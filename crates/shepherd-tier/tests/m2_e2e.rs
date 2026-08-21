//! POSIX-only: this file asserts POSIX modes and link counts across the tiering round trip, via `std::os::unix`'s `MetadataExt`
//! and `PermissionsExt`. Gated at file level rather than per-item so
//! Windows COMPILES the crate and runs everything else, instead of the
//! whole workspace failing to build on one leg — §9 wants a platform
//! break found on the commit that caused it, which needs the other
//! platforms to still build.
//!
//! This is a real coverage gap on Windows and is meant to read as one.
#![cfg(unix)]

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
//! # WHAT IS REAL HERE, AND WHAT IS COVERED ELSEWHERE
//!
//! Stated up front, because a harness that *appears* complete is worse than an
//! obviously partial one — and because §9 rule 1 forbids satisfying a gate with
//! a skip.
//!
//! | leg | status |
//! |---|---|
//! | scan + floors | **real** — `shepherd-scan` |
//! | rule match + dry-run preview | **real** — `shepherd-rules` |
//! | plan | **real** — `shepherd-tier::plan_tier`. [`tier_plan_for`] feeds it the walk's selections; the §4.9 content-addressed key comes from `derive_object_key` and nowhere else, so the object this test uploads to is named by the production code path. |
//! | upload | **real** — `shepherd-tier::upload_item` driving `shepherd-storage`'s `TransferDriver`: a genuine **multipart** upload against real MinIO, with the part size taken from the transfer config ([`PART_SIZE`]) and the resulting part count asserted ([`EXPECTED_PARTS`]). |
//! | hash-verify | **real** — `verify_full_content`, AC-1's mandatory full re-read |
//! | attestation probe | **real** — recorded on the session by the driver, against both buckets |
//! | destroy | **real** — `execute_local_destruction`, the whole §4.10 ordering |
//! | restore | **real** — `restore_file`, exclusive-create |
//! | fidelity | **real** — `verify_restore` against a manifest |
//!
//! Two things are deliberately **not** this file's subject, named so nobody
//! reads their absence as coverage:
//!
//! * **Crash windows and resume.** `TransferDriver`'s four windows and its
//!   `ListParts` reconciliation are `shepherd-storage`'s own suite; AC-2's
//!   cross-process leg is `session_store_tests.rs`. This test runs one
//!   uninterrupted transfer and asserts it as such (`bytes_skipped == 0`).
//! * **Durable session persistence.** The store here is `shepherd-storage`'s
//!   `MemStore`. The production `CatalogSessionStore` is exactly what
//!   `session_store_tests.rs` exists to exercise, and duplicating it here would
//!   add a catalog-seeding apparatus without adding evidence.
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

use shepherd_catalog::AtimeMode;
use shepherd_catalog::file_repo::{Availability, ScanRoot};
use shepherd_catalog::identity::{PathCasePolicy, PathNormPolicy};
use shepherd_core::{
    Blake3Hash, FileId, FileStat, FsId, IntentId, JobId, RootId, StubMode, TargetId, Timestamp,
};
use shepherd_placeholder::DeleteModeProvider;
use shepherd_placeholder::provider::FileIdentity;
use shepherd_rules::{MatchContext, Matcher};
use shepherd_scan::{DenyList, FloorContext, FloorInput, FloorPolicy, IgnoreSet, floors, walk};
use shepherd_storage::adapter::{AttestationMode, StorageAdapter, verify_full_content};
use shepherd_storage::multipart::DEFAULT_PART_SIZE;
use shepherd_storage::s3::{S3Adapter, S3Config, StaticCredentials};
use shepherd_storage::testing::MemStore;
use shepherd_storage::transfer_session::{TransferSessionStore, TransferState};
use shepherd_tier::fidelity::{CoreAttrs, FidelityManifest};
use shepherd_tier::revalidate::{Location, LocationState};
use shepherd_tier::{
    AuditLog, FileLocks, LocalDestroyRequest, SelectedFile, TierPlan, execute_local_destruction,
    hash_file, plan_tier, read_back, restore_file, upload_item, verify_restore,
};

const VERSIONED_BUCKET: &str = "shepherd-versioned";
const PLAIN_BUCKET: &str = "shepherd-plain";

/// The part size handed to the transfer, and the count it must produce.
///
/// **Deliberately not [`DEFAULT_PART_SIZE`].** Passing a constant where the
/// transfer config belongs is this project's instance-#6 defect: the plan
/// collapses to a single part, the multipart path is never entered, and the
/// round trip goes green having proven nothing about it. Because 5 MiB is S3's
/// own floor — `PartPlan::new` clamps anything smaller *up* to it — it is also
/// the smallest value that can cut an object into more than one part at all.
const PART_SIZE: u64 = 5 * 1024 * 1024;

/// 12 MiB in 5 MiB parts is 5 + 5 + 2: three parts, the last one short.
///
/// A literal rather than a `div_ceil` recomputation of the planner's own
/// arithmetic, so a change in `PartPlan::new` cannot quietly agree with itself
/// here.
const EXPECTED_PARTS: u32 = 3;

/// Large enough that [`PART_SIZE`] genuinely splits it.
const PAYLOAD_LEN: usize = 12 * 1024 * 1024;

// Both properties the two constants above exist to hold, checked at compile
// time so an edit to either cannot silently turn this suite back into a
// single-shot upload that measures nothing.
const _: () = assert!(PART_SIZE != DEFAULT_PART_SIZE);
const _: () = assert!(PAYLOAD_LEN as u64 > PART_SIZE);

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
        // `CARGO_TARGET_TMPDIR`, not `std::env::temp_dir()`: this corpus is handed
        // to `walk` with `DenyList::builtin()`, and on macOS `$TMPDIR` is
        // `/var/folders/…` whose canonical form is `/private/var/…` — denied as
        // a `SystemPath`, correctly. A fixture inside a denied system tree
        // makes the walk answer about the runner's temp directory rather than
        // about the corpus.
        let dir = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("shepherd-m2-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("Photos/2024")).unwrap();
        std::fs::create_dir_all(dir.join("Photos/2024/raw-backups")).unwrap();
        std::fs::create_dir_all(dir.join("Docs")).unwrap();
        std::fs::create_dir_all(dir.join(".git/objects")).unwrap();

        let payload = body(PAYLOAD_LEN, 7);
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

/// Tiering candidates, by the real matcher and the real floors over the real
/// walk.
///
/// This is the **input** to `shepherd-tier::plan_tier`, not a substitute for
/// it: `plan.rs` is deliberately thin and takes selections as values, knowing
/// nothing about walking or matching. See [`tier_plan_for`] for the planning
/// step itself.
fn select_candidates(corpus: &Corpus, now: Timestamp) -> Vec<FileStat> {
    select_candidates_ignoring(corpus, now, &["*.tmp".to_string()])
}

/// The same selection, with the user ignore patterns supplied by the caller.
///
/// Split out for AC-9's tier leg. The `*.tmp` list the default passes has never
/// been load-bearing — this corpus contains no `.tmp` file, so that pattern
/// excludes nothing and the whole selection would behave identically with an
/// empty set. See `a_user_ignore_pattern_excludes_a_file_the_rule_would_tier`,
/// which supplies a pattern that actually hits.
fn select_candidates_ignoring(
    corpus: &Corpus,
    now: Timestamp,
    patterns: &[String],
) -> Vec<FileStat> {
    let ignores = IgnoreSet::new(&corpus.dir, patterns).unwrap();
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

/// The real `shepherd-tier::plan`, over the real selection.
///
/// The remote key is `plan_tier`'s and nowhere else's. A key the test built for
/// itself would pass happily while the production key differed — which is the
/// §4.9 mistake (path-derived keys) reproduced inside the test that exists to
/// catch it.
fn tier_plan_for(corpus: &Corpus, now: Timestamp, prefix: &str) -> TierPlan {
    plan_over(corpus, now, prefix, &["*.tmp".to_string()])
}

/// The same planning step over a caller-supplied ignore list. See
/// [`select_candidates_ignoring`].
fn plan_over(corpus: &Corpus, now: Timestamp, prefix: &str, patterns: &[String]) -> TierPlan {
    let selected: Vec<SelectedFile> = select_candidates_ignoring(corpus, now, patterns)
        .into_iter()
        .enumerate()
        .map(|(i, f)| {
            let abs = corpus.dir.join(&f.rel_path);
            SelectedFile {
                file: FileId::new(i as i64 + 1),
                // ABSOLUTE. `upload_item` opens this path directly, so a
                // relative one would fail at read time rather than at plan time.
                path: abs.display().to_string(),
                size: f.size,
                // The real streamed planning hasher, not a convenience re-hash
                // of the buffer the test already holds in memory. Cross-checked
                // against that buffer in `round_trip`.
                blake3: Some(hash_file(&abs).expect("hash the source")),
            }
        })
        .collect();
    plan_tier(&selected, &[TargetId::new(1)], prefix)
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

    // --- scan + dry-run selection + plan -------------------------------------
    let plan = tier_plan_for(&corpus, now, &format!("m2-{}-{tag}", std::process::id()));

    // ASSERT THE QUANTITY. Exactly one item, and exactly the right one — not
    // "at least one", which would pass if the rule matched the whole corpus.
    assert!(
        plan.refused.is_empty(),
        "nothing may be silently unplannable here: {:?}",
        plan.refused
    );
    assert_eq!(
        plan.items.len(),
        1,
        "expected exactly one planned item, got {:?}",
        plan.items.iter().map(|i| &i.path).collect::<Vec<_>>()
    );
    assert_eq!(plan.distinct_objects(), 1);
    let item = &plan.items[0];
    assert_eq!(Path::new(&item.path), corpus.target.as_path());
    assert_eq!(item.size, corpus.payload.len() as u64);

    let hash = hash_of(&corpus.payload);
    assert_eq!(
        item.blake3, hash,
        "the streamed planning hash must equal the in-memory one — the key is \
         derived from it, so a divergence names the object after bytes it does \
         not hold"
    );
    let key = item.remote_key.clone();

    // --- tier: the real multipart uploader -----------------------------------
    let store = MemStore::new();
    let locks = FileLocks::new();
    let job = JobId::new(1);
    let outcome = upload_item(
        job,
        item,
        &a,
        &store,
        &locks,
        FsId::new("uuid:m2-test"),
        PART_SIZE,
    )
    .await
    .expect("upload");

    // ASSERT THE QUANTITY, again — and specifically the part count. An upload
    // that quietly collapsed to a single part would still commit, still verify
    // and still restore, so every downstream assertion here would pass while
    // the multipart path this leg exists to cover went unexercised.
    assert_eq!(outcome.state, TransferState::Committed);
    assert_eq!(
        outcome.parts_sent,
        EXPECTED_PARTS,
        "{} B at a {PART_SIZE} B part size is {EXPECTED_PARTS} parts; {} were sent",
        corpus.payload.len(),
        outcome.parts_sent
    );
    assert_eq!(
        outcome.bytes_uploaded,
        corpus.payload.len() as u64,
        "every byte goes over the wire exactly once on a fresh session"
    );
    assert_eq!(
        outcome.bytes_skipped, 0,
        "a fresh session has no acknowledged parts to skip"
    );
    assert!(
        !outcome.resolved_ambiguous_completion,
        "the driver found an object already at `{}` and skipped \
         CompleteMultipartUpload entirely — verify would still pass on identical \
         content, so this run would prove nothing about multipart completion",
        key.as_str()
    );

    // The persisted plan, not just the outcome: this is what proves `PART_SIZE`
    // reached `PartPlan::new` instead of a hardcoded default being used behind
    // the parameter's back.
    let session = store
        .load(job)
        .await
        .expect("load session")
        .expect("a committed transfer leaves its session behind");
    assert_eq!(
        session.plan.part_size, PART_SIZE,
        "the part size must come from the transfer config, not a constant"
    );
    assert_eq!(session.plan.part_count, EXPECTED_PARTS);
    assert_eq!(session.parts.len(), EXPECTED_PARTS as usize);
    assert_eq!(session.remote_key, key);

    let mode = session
        .attestation_mode
        .expect("the driver records the mechanism that will authorize destruction");
    assert_eq!(
        mode, expect_mode,
        "bucket `{bucket}` reported {mode:?}; the compose file says it should be \
         {expect_mode:?}. Landing on B while believing A is how a safety claim decays \
         into a slogan (§4.10.2)."
    );

    // Printed because `--nocapture` is the documented way to run this suite and
    // because whoever reads a gate report should be able to SEE the quantities
    // rather than take a green "ok" for them.
    eprintln!(
        "[{tag}] {bucket}: uploaded {} B as {} part(s) of {} B ({} skipped), \
         attestation {mode:?}, key {}",
        outcome.bytes_uploaded,
        outcome.parts_sent,
        session.plan.part_size,
        outcome.bytes_skipped,
        key.as_str()
    );

    // --- hash-verify: AC-1's mandatory full re-read --------------------------
    //
    // Kept even though `TransferDriver::verify` already did one internally. This
    // is AC-1's *cited* evidence, and delegating it to the code under test would
    // make the citation circular: the driver deciding it verified itself is not
    // the same fact as the object hashing correctly.
    verify_full_content(&a, &key, hash, corpus.payload.len() as u64, 1024 * 1024)
        .await
        .expect("remote copy must hash to the expected value before anything is destroyed");

    // --- destroy ------------------------------------------------------------
    let meta = a.head(&key).await.unwrap().expect("object present");
    let custodian = Location {
        target: item.target,
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

    // The catalog's identity, from the catalog's own function — the destroy
    // path locks on this value, and it must be the one an upload of this same
    // file would be handed.
    let fs_id = shepherd_catalog::volume::fs_id(
        &corpus.target,
        root.volume_id.as_deref().expect("the corpus root has one"),
    )
    .expect("fs_id");

    execute_local_destruction(
        &LocalDestroyRequest {
            root_gate: &OpenGate,
            intent: shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
                IntentId::new(1),
                shepherd_catalog::intent::IntentKind::Local,
                &corpus.target.to_string_lossy(),
                corpus.payload.len() as i64,
                Some(hash),
            ),
            path: &corpus.target,
            root: &root,
            expected_hash: hash,
            expected_size: corpus.payload.len() as u64,
            verified_identity: identity_of(&corpus.target),
            fs_id: &fs_id,
            age: Duration::from_secs(3600),
            floor_policy: FloorPolicy {
                min_size: 1024 * 1024,
                min_age: Duration::from_secs(0),
            },
            custodian: &custodian,
            remote_key: &key,
        },
        &DeleteModeProvider::new(),
        &shepherd_tier::destroy::TargetGate::new(shepherd_core::TargetId::new(1), &a),
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
    let survivors = [
        "Docs/notes.txt",
        "Photos/2024/raw-backups/old.raw",
        ".git/objects/pack.raw",
        "Photos/2024/thumb.raw",
    ];
    for survivor in survivors {
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

    eprintln!(
        "[{tag}] {bucket}: restored {} B to {} — hash {} matches, {} negative(s) untouched",
        restored.len(),
        corpus.target.display(),
        hash.to_hex(),
        survivors.len()
    );
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
    let now = Timestamp::from_nanos(1_000_000_000_000);
    let picked = select_candidates(&corpus, now);
    assert_eq!(
        picked.len(),
        1,
        "expected exactly one, got {:?}",
        picked.iter().map(|f| &f.rel_path).collect::<Vec<_>>()
    );
    assert_eq!(picked[0].rel_path, "Photos/2024/shoot.raw");

    // …and the real planner turns that one selection into one work item at one
    // content-addressed key. Network-free, so `plan.rs`'s integration with the
    // selection above is checked by a plain `cargo test`, not only by the
    // `#[ignore]`d round trip nobody runs by accident.
    let plan = tier_plan_for(&corpus, now, "m2-dry-run");
    assert!(plan.refused.is_empty(), "{:?}", plan.refused);
    assert_eq!(plan.items.len(), 1);
    assert_eq!(plan.distinct_objects(), 1);
    let hash = hash_of(&corpus.payload);
    assert_eq!(plan.items[0].blake3, hash);

    // §4.9: content-addressed, never path-derived. Asserted on the key's own
    // text rather than by re-calling `derive_object_key` — comparing the
    // producer against itself would hold just as well if it were named after
    // the path.
    let k = plan.items[0].remote_key.as_str();
    assert_eq!(
        k,
        format!(
            "m2-dry-run/objects/{}/{}/{}",
            &hash.to_hex()[0..2],
            &hash.to_hex()[2..4],
            hash.to_hex()
        )
    );
    assert!(
        !k.contains("shoot") && !k.contains("Photos"),
        "no part of the local path may appear in the key: {k}"
    );
}

/// **AC-9's tier leg**: a user ignore pattern removes a file the tiering rule
/// would otherwise have selected.
///
/// AC-9 reads "ignore patterns are honored on both scan and tier". The scan
/// leg is cited to `shepherd-scan`'s walker; this is the other one, and it was
/// missing. `shepherd-tier` has no `IgnoreSet` of its own — it honours ignores
/// by consuming what the walk produced — so the only way to prove the tier leg
/// is to show a file disappearing from a **tier plan**, not from a walk.
///
/// Both directions are asserted on the same file, which is the point. An
/// "excluded.raw is not in the plan" assertion on its own passes just as
/// happily when the rule never matched it, when the size floor rejected it, or
/// when the walk crashed — so the first half proves the file IS a candidate
/// with no pattern in force, and only then does the second half attribute its
/// disappearance to the pattern.
#[test]
fn a_user_ignore_pattern_excludes_a_file_the_rule_would_tier() {
    let corpus = Corpus::new("ac9-tier");
    let now = Timestamp::from_nanos(1_000_000_000_000);

    // A second file that satisfies every positive condition `select_candidates`
    // applies: `.raw`, directly under `Photos/<year>/`, and over the 1 MiB
    // floor. Nothing but an ignore pattern can remove it.
    std::fs::write(
        corpus.dir.join("Photos/2024/scratch.raw"),
        body(2 * 1024 * 1024, 11),
    )
    .unwrap();

    // 1. With no user patterns, the rule genuinely selects it.
    let without = select_candidates_ignoring(&corpus, now, &[]);
    let paths = |v: &[FileStat]| v.iter().map(|f| f.rel_path.clone()).collect::<Vec<_>>();
    assert!(
        paths(&without).contains(&"Photos/2024/scratch.raw".to_string()),
        "the fixture is wrong if the rule does not pick this file up: {:?}",
        paths(&without)
    );
    assert!(
        paths(&without).contains(&"Photos/2024/shoot.raw".to_string()),
        "{:?}",
        paths(&without)
    );

    // 2. With the user's pattern, it is gone — and the sibling is not.
    let with = select_candidates_ignoring(&corpus, now, &["scratch.raw".to_string()]);
    assert!(
        !paths(&with).contains(&"Photos/2024/scratch.raw".to_string()),
        "the user's ignore pattern did not reach tier selection: {:?}",
        paths(&with)
    );
    assert!(
        paths(&with).contains(&"Photos/2024/shoot.raw".to_string()),
        "the pattern excluded more than it named — a rule that matched nothing \
         would pass the assertion above: {:?}",
        paths(&with)
    );

    // 3. And it is absent from the real plan, not merely from the selection.
    // `plan_tier` is what turns selections into work items; a file excluded by
    // the selection but re-admitted by the planner would still be uploaded.
    let ignored_plan = plan_over(&corpus, now, "ac9-with", &["scratch.raw".to_string()]);
    assert_eq!(ignored_plan.items.len(), 1, "{:?}", ignored_plan.items);
    let open_plan = plan_over(&corpus, now, "ac9-without", &[]);
    assert_eq!(
        open_plan.items.len(),
        2,
        "the paired non-zero: with no pattern the planner must produce TWO items, \
         or the assertion above is satisfied by a planner that produces one \
         regardless: {:?}",
        open_plan.items
    );
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

/// A root whose PM-3 gates stay open, which is what this test is about.
///
/// Defined here rather than exported from `shepherd-tier`: a public
/// always-permits `RootGate` is a footgun on the irreversible path, and the
/// only callers that should ever have one are tests that say so.
struct OpenGate;

#[async_trait::async_trait]
impl shepherd_tier::destroy::RootGate for OpenGate {
    async fn hold_open(
        &self,
        _root: shepherd_core::RootId,
    ) -> shepherd_tier::destroy::Result<Result<shepherd_tier::destroy::RootHold, String>> {
        Ok(Ok(
            shepherd_tier::destroy::RootHold::nothing_can_change_this_root(),
        ))
    }
}
