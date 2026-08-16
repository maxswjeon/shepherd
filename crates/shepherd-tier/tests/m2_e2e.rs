//! **M2's end-to-end round trip** (§6 Phase 2, T11).
//!
//! ```text
//! scan → rule dry-run → tier to MinIO → hash-verify → destroy → restore → byte-identical
//! ```
//!
//! `#[ignore]`d behind MinIO, like `shepherd-storage`'s suite, so a plain
//! `cargo test --workspace` stays meaningful on a machine with no Docker. A
//! test that silently passes when its dependency is absent is worse than one
//! that is visibly skipped.
//!
//! ```text
//! docker compose -f tests/docker-compose.yml up -d --wait
//! SHEPHERD_MINIO_ENDPOINT=http://127.0.0.1:9000 \
//!   cargo test -p shepherd-tier --test m2_e2e -- --ignored --nocapture
//! docker compose -f tests/docker-compose.yml down -v
//! ```
//!
//! # WHAT IS REAL HERE AND WHAT IS STUBBED
//!
//! Stated up front, because a harness that *appears* complete is worse than an
//! obviously partial one — and because §9 rule 1 forbids satisfying a gate with
//! a skip.
//!
//! | leg | status |
//! |---|---|
//! | scan + floors | **real** — `shepherd-scan` |
//! | rule match + dry-run preview | **real** — `shepherd-rules` |
//! | plan | **STUBBED** — `shepherd-tier::plan` is not landed (worker-4). [`stub_plan`] selects candidates directly from the walk, which is what `plan.rs` will do. |
//! | upload | **STUBBED** — `shepherd-tier::upload` is not landed. [`stub_upload`] performs a single-shot `create` through the real adapter against real MinIO. The **transfer/resume state machine is therefore not exercised here**; `shepherd-storage`'s own MinIO suite covers multipart and `ListParts` resume. |
//! | hash-verify | **real** — `verify_full_content`, AC-1's mandatory full re-read |
//! | attestation probe | **real** — `probe_attestation_mode` against both buckets |
//! | destroy | **real** — `execute_local_destruction`, the whole §4.10 ordering |
//! | restore | **real** — `restore_file`, exclusive-create |
//! | fidelity | **real** — `verify_restore` against a manifest |
//!
//! When `plan.rs` and `upload.rs` land, the two `stub_*` functions are the only
//! things that change; every assertion below is written against the real
//! outcome and stays.
//!
//! # Both attestation modes, not just the convenient one
//!
//! Every round trip runs **twice** — once against `shepherd-versioned`
//! (mechanism A) and once against `shepherd-plain` (mechanism B). B is the
//! NAS / non-versioned-S3 path the user explicitly accepted, with its ~50 s
//! window and a closing HEAD that **cannot** detect a same-size replacement.
//! Testing only A would leave the weaker mechanism — the one most targets
//! actually land on — unexercised while the suite reported green.
//!
//! # Assert the quantity, not the exit code
//!
//! Every assertion here compares a *value*: bytes, hashes, paths, counts. Not
//! "did it return Ok". Four separate green-signal-measuring-nothing defects
//! surfaced during this build, and the e2e is the last place one could hide and
//! the most expensive place to have one.

#![allow(clippy::items_after_test_module)]

use std::path::{Path, PathBuf};
use std::time::Duration;

use bytes::Bytes;
use shepherd_catalog::AtimeMode;
use shepherd_catalog::file_repo::{Availability, ScanRoot};
use shepherd_catalog::identity::{PathCasePolicy, PathNormPolicy, content_key};
use shepherd_core::{Blake3Hash, FileStat, IntentId, ObjectKey, RootId, StubMode, Timestamp};
use shepherd_placeholder::DeleteModeProvider;
use shepherd_placeholder::provider::FileIdentity;
use shepherd_rules::{MatchContext, Matcher};
use shepherd_scan::{DenyList, FloorContext, FloorInput, FloorPolicy, IgnoreSet, floors, walk};
use shepherd_storage::adapter::{
    AttestationMode, CreatePrecondition, StorageAdapter, verify_full_content,
};
use shepherd_storage::s3::{S3Adapter, S3Config, StaticCredentials};
use shepherd_tier::fidelity::{CoreAttrs, FidelityManifest};
use shepherd_tier::revalidate::{Location, LocationState};
use shepherd_tier::{
    AuditLog, FileLocks, LocalDestroyRequest, execute_local_destruction, read_back, restore_file,
    verify_restore,
};

const VERSIONED_BUCKET: &str = "shepherd-versioned";
const PLAIN_BUCKET: &str = "shepherd-plain";

fn endpoint() -> String {
    std::env::var("SHEPHERD_MINIO_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9000".to_string())
}

async fn adapter(bucket: &str) -> S3Adapter {
    let mut cfg = S3Config::minio(bucket, endpoint());
    cfg.credentials = Some(StaticCredentials {
        access_key_id: "shepherdtest".into(),
        secret_access_key: "shepherdtest".into(),
    });
    S3Adapter::new(cfg).await.expect("build S3 adapter")
}

/// Deterministic but high-entropy, so a size comparison cannot accidentally
/// stand in for a hash comparison.
fn body(len: usize, salt: u8) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = 0x2545_F491_4F6C_DD1Du64 ^ u64::from(salt);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    v
}

/// A corpus root with one tierable file and several that must NOT be touched.
///
/// The negatives are the point. A round trip that only proves "the one file we
/// aimed at came back" would pass just as happily if the rule had matched
/// everything.
struct Corpus {
    dir: PathBuf,
    target: PathBuf,
    payload: Vec<u8>,
}

impl Corpus {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("shepherd-m2-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Photos/2024")).unwrap();
        std::fs::create_dir_all(dir.join("Photos/2024/raw-backups")).unwrap();
        std::fs::create_dir_all(dir.join("Docs")).unwrap();
        std::fs::create_dir_all(dir.join(".git/objects")).unwrap();

        let payload = body(3 * 1024 * 1024, 7);
        let target = dir.join("Photos/2024/shoot.raw");
        std::fs::write(&target, &payload).unwrap();

        // Negatives, each for a specific reason:
        //  - wrong extension
        std::fs::write(dir.join("Docs/notes.txt"), body(2 * 1024 * 1024, 1)).unwrap();
        //  - right extension, but deeper than a single-star glob reaches
        std::fs::write(
            dir.join("Photos/2024/raw-backups/old.raw"),
            body(2 * 1024 * 1024, 2),
        )
        .unwrap();
        //  - right extension, but under the built-in deny-list
        std::fs::write(dir.join(".git/objects/pack.raw"), body(1024 * 1024, 3)).unwrap();
        //  - right extension, but below the size floor
        std::fs::write(dir.join("Photos/2024/thumb.raw"), body(1024, 4)).unwrap();

        Self {
            dir,
            target,
            payload,
        }
    }

    fn root(&self) -> ScanRoot {
        ScanRoot {
            id: RootId::new(1),
            path: self.dir.display().to_string(),
            stub_mode: StubMode::Delete,
            case_policy: PathCasePolicy::Sensitive,
            norm_policy: PathNormPolicy::Preserve,
            atime_mode: AtimeMode::Relatime,
            volume_id: Some("uuid:m2-test".into()),
            resync_required: false,
            availability: Availability::Available,
            destruction_ineligible: false,
            destruction_ineligible_reason: None,
        }
    }
}

impl Drop for Corpus {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// **STUB for `shepherd-tier::plan`.** Selects tiering candidates by running
/// the real matcher and the real floors over the real walk. When `plan.rs`
/// lands it does this against the catalog instead; the selection *criteria* are
/// already what the plan specifies.
fn stub_plan(corpus: &Corpus, now: Timestamp) -> Vec<FileStat> {
    let ignores = IgnoreSet::new(&corpus.dir, &["*.tmp".to_string()]).unwrap();
    let out = walk(
        RootId::new(1),
        &corpus.dir,
        &DenyList::builtin(),
        &ignores,
        now,
    )
    .expect("walk");

    let rule = serde_json::json!({
        "ext": ["raw"],
        "path_glob": "Photos/*/*.raw",
        "min_size": 1024 * 1024,
    });
    let matcher = Matcher::compile(
        "tier-raws",
        &rule,
        &shepherd_rules::preview::RuleAction::Tier {
            destinations: vec![],
        },
        AtimeMode::Relatime,
    )
    .expect("rule compiles");

    let policy = FloorPolicy {
        min_size: 1024 * 1024,
        min_age: Duration::from_secs(0),
    };

    out.files
        .into_iter()
        .filter(|f| {
            let ctx = MatchContext {
                now,
                atime_mode: AtimeMode::Relatime,
                last_observed_access: None,
                tags: &[],
            };
            if !matcher.matches(f, &ctx).matched {
                return false;
            }
            let abs = corpus.dir.join(&f.rel_path);
            let md = std::fs::symlink_metadata(&abs).unwrap();
            use std::os::unix::fs::MetadataExt;
            floors::evaluate(
                &policy,
                &FloorInput {
                    path: abs,
                    size: md.len(),
                    age: Duration::from_secs(3600),
                    nlink: md.nlink(),
                    is_symlink: md.is_symlink(),
                    allocated_bytes: Some(md.blocks() * 512),
                    fs_id: None,
                    observed_at: now,
                },
                FloorContext::ScanTime,
            )
            .is_eligible()
        })
        .collect()
}

/// **STUB for `shepherd-tier::upload`.** Single-shot `create` through the real
/// adapter against real MinIO.
///
/// The transfer/resume state machine is **not** exercised by this — no
/// multipart, no checkpointing, no `ListParts` reconciliation. AC-2's resume is
/// covered by `shepherd-storage`'s own MinIO suite, and this stub deliberately
/// does not pretend otherwise.
async fn stub_upload(a: &S3Adapter, key: &ObjectKey, bytes: Vec<u8>) -> AttestationMode {
    a.create(key, Bytes::from(bytes), CreatePrecondition::Unconditional)
        .await
        .expect("upload");
    a.probe_attestation_mode().await.expect("probe attestation")
}

fn hash_of(b: &[u8]) -> Blake3Hash {
    Blake3Hash::from_bytes(*blake3::hash(b).as_bytes())
}

fn identity_of(p: &Path) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p).unwrap();
    FileIdentity {
        dev: md.dev(),
        ino: md.ino(),
        nlink: md.nlink(),
    }
}

/// The whole M2 round trip against one bucket.
async fn round_trip(bucket: &str, expect_mode: AttestationMode, tag: &str) {
    let now = Timestamp::from_nanos(1_000_000_000_000);
    let corpus = Corpus::new(tag);
    let a = adapter(bucket).await;

    // --- scan + dry-run selection ------------------------------------------
    let candidates = stub_plan(&corpus, now);

    // ASSERT THE QUANTITY. Exactly one file, and exactly the right one — not
    // "at least one", which would pass if the rule matched the whole corpus.
    assert_eq!(
        candidates.len(),
        1,
        "expected exactly one candidate, got {:?}",
        candidates.iter().map(|f| &f.rel_path).collect::<Vec<_>>()
    );
    assert_eq!(candidates[0].rel_path, "Photos/2024/shoot.raw");

    let hash = hash_of(&corpus.payload);
    let key = content_key(&format!("m2-{}-{tag}", std::process::id()), hash);

    // --- tier ---------------------------------------------------------------
    let mode = stub_upload(&a, &key, corpus.payload.clone()).await;
    assert_eq!(
        mode, expect_mode,
        "bucket `{bucket}` reported {mode:?}; the compose file says it should be \
         {expect_mode:?}. Landing on B while believing A is how a safety claim decays \
         into a slogan (§4.10.2)."
    );

    // --- hash-verify: AC-1's mandatory full re-read --------------------------
    verify_full_content(&a, &key, hash, corpus.payload.len() as u64, 1024 * 1024)
        .await
        .expect("remote copy must hash to the expected value before anything is destroyed");

    // --- destroy ------------------------------------------------------------
    let meta = a.head(&key).await.unwrap().expect("object present");
    let custodian = Location {
        target: shepherd_core::TargetId::new(1),
        state: LocationState::Verified,
        attestation: mode,
        custody_eligible: true,
        last_full_hash_verified_at: Some(now),
        publication_receipt_ok: true,
        object_version: meta.version.clone(),
        expected_hash: hash,
    };
    let root = corpus.root();
    let audit = AuditLog::open(&corpus.dir.join("audit/destroy.jsonl")).unwrap();
    let locks = FileLocks::new();

    // `& 0o7777`, because `CoreAttrs::mode` is documented as "Unix permission
    // bits" and `read_back` masks the same way. `permissions().mode()` returns
    // the FULL st_mode on Linux — 0o100664, including the S_IFREG file-type
    // bits — so passing it unmasked builds a manifest that can never be
    // satisfied.
    //
    // This test did exactly that, and the first real MinIO run failed with
    // `Mode { expected: 33204, actual: 436 }` — 0o100664 vs 0o664. Kept as a
    // comment rather than a silent fix: `metadata().permissions().mode()` is
    // the obvious way to fill this field, and it is wrong.
    let mode_bits = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(&corpus.target)
            .unwrap()
            .permissions()
            .mode()
            & 0o7777
    };
    let mtime = Timestamp::from_nanos(1);

    execute_local_destruction(
        &LocalDestroyRequest {
            intent: IntentId::new(1),
            path: &corpus.target,
            root: &root,
            expected_hash: hash,
            expected_size: corpus.payload.len() as u64,
            verified_identity: identity_of(&corpus.target),
            age: Duration::from_secs(3600),
            floor_policy: FloorPolicy {
                min_size: 1024 * 1024,
                min_age: Duration::from_secs(0),
            },
            custodian: &custodian,
            remote_key: &key,
        },
        &DeleteModeProvider::new(),
        &(&a as &dyn StorageAdapter),
        &audit,
        &locks,
        now,
    )
    .await
    .expect("destroy");

    assert!(!corpus.target.exists(), "the original is gone");

    // The negatives are still there. A rule that matched everything would have
    // destroyed these too, and a round trip asserting only the happy path would
    // not notice.
    for survivor in [
        "Docs/notes.txt",
        "Photos/2024/raw-backups/old.raw",
        ".git/objects/pack.raw",
        "Photos/2024/thumb.raw",
    ] {
        assert!(
            corpus.dir.join(survivor).exists(),
            "`{survivor}` must not have been touched"
        );
    }

    // Exactly one audit record, naming the mechanism that authorized it.
    let records = audit.read_all();
    assert_eq!(records.len(), 1, "one destruction, one record");
    let expect_label = match expect_mode {
        AttestationMode::Version => "version",
        AttestationMode::Content => "content",
        AttestationMode::None => unreachable!("None cannot authorize a destruction"),
    };
    assert!(
        records[0].contains(expect_label),
        "audit record must name the attestation mode: {}",
        records[0]
    );

    // --- restore ------------------------------------------------------------
    let fetched = {
        use shepherd_storage::adapter::ByteRange;
        let mut buf = Vec::new();
        let size = corpus.payload.len() as u64;
        let mut off = 0u64;
        while off < size {
            let len = (1024 * 1024).min(size - off);
            let b = a
                .get_range(&key, ByteRange { offset: off, len })
                .await
                .expect("get_range");
            buf.extend_from_slice(&b);
            off += len;
        }
        buf
    };

    let manifest = FidelityManifest::new(CoreAttrs {
        blake3: hash,
        size: corpus.payload.len() as u64,
        mtime,
        mode: mode_bits,
    });
    let outcome = restore_file(&corpus.target, &fetched, &manifest).expect("restore");

    // --- byte-identical, by CONTENT and by PATH ------------------------------
    let restored = std::fs::read(&corpus.target).expect("restored at the original path");
    assert_eq!(
        hash_of(&restored),
        hash,
        "restored content must hash to the original — a size check is not this assertion"
    );
    assert_eq!(restored, corpus.payload, "byte-for-byte");
    assert_eq!(
        Path::new(outcome.path()),
        corpus.target.as_path(),
        "restored to the ORIGINAL path, not a conflict name"
    );

    let attrs = read_back(&corpus.target).expect("read back");
    verify_restore(&manifest, &attrs).expect("fidelity contract holds");
}

/// Mechanism A — versioning on. The closing HEAD genuinely re-attests.
#[tokio::test]
#[ignore = "requires MinIO: see the module docs"]
async fn m2_round_trip_mechanism_a_versioned() {
    round_trip(VERSIONED_BUCKET, AttestationMode::Version, "verA").await;
}

/// Mechanism B — versioning off, which is S3's **default** and therefore the
/// path most real targets land on. Its closing HEAD proves existence and size
/// only; content addressing is what bounds it.
#[tokio::test]
#[ignore = "requires MinIO: see the module docs"]
async fn m2_round_trip_mechanism_b_content_addressed() {
    round_trip(PLAIN_BUCKET, AttestationMode::Content, "verB").await;
}

/// The corpus selection itself, without MinIO — so the part of M2 that needs no
/// network is checkable by `cargo test --workspace`.
///
/// This is the leg that would silently rot if the whole file were `#[ignore]`d:
/// a rule that quietly began matching every file would still pass an
/// ignored-by-default e2e, because nobody ran it.
#[test]
fn the_dry_run_selects_exactly_one_candidate_out_of_five() {
    let corpus = Corpus::new("select");
    let picked = stub_plan(&corpus, Timestamp::from_nanos(1_000_000_000_000));
    assert_eq!(
        picked.len(),
        1,
        "expected exactly one, got {:?}",
        picked.iter().map(|f| &f.rel_path).collect::<Vec<_>>()
    );
    assert_eq!(picked[0].rel_path, "Photos/2024/shoot.raw");
}

/// Each negative is excluded for its OWN reason, asserted separately.
///
/// A single "only one matched" assertion would still pass if four files were
/// excluded by one over-broad rule and the fifth by luck.
#[test]
fn each_negative_is_excluded_for_its_own_stated_reason() {
    let corpus = Corpus::new("reasons");
    let now = Timestamp::from_nanos(1_000_000_000_000);

    // 1. Deny-list: `.git` is pruned by the walker, so it never reaches a rule.
    let ignores = IgnoreSet::empty(&corpus.dir).unwrap();
    let out = walk(
        RootId::new(1),
        &corpus.dir,
        &DenyList::builtin(),
        &ignores,
        now,
    )
    .unwrap();
    assert!(
        !out.files.iter().any(|f| f.rel_path.contains(".git")),
        "the deny-list must prune .git before any rule sees it"
    );

    // 2. Extension: notes.txt is not a raw.
    let m = Matcher::compile_readonly(&serde_json::json!({ "ext": ["raw"] })).unwrap();
    let ctx = MatchContext {
        now,
        atime_mode: AtimeMode::Relatime,
        last_observed_access: None,
        tags: &[],
    };
    let notes = out
        .files
        .iter()
        .find(|f| f.rel_path.ends_with("notes.txt"))
        .unwrap();
    assert!(!m.matches(notes, &ctx).matched);

    // 3. Glob depth: `Photos/*/*.raw` must not reach raw-backups/old.raw.
    let m =
        Matcher::compile_readonly(&serde_json::json!({ "path_glob": "Photos/*/*.raw" })).unwrap();
    let deep = out
        .files
        .iter()
        .find(|f| f.rel_path.ends_with("raw-backups/old.raw"))
        .unwrap();
    assert!(
        !m.matches(deep, &ctx).matched,
        "a single `*` must not cross a separator"
    );

    // 4. Size floor: thumb.raw is 1 KiB.
    let thumb = out
        .files
        .iter()
        .find(|f| f.rel_path.ends_with("thumb.raw"))
        .unwrap();
    assert!(thumb.size < 1024 * 1024);
}
