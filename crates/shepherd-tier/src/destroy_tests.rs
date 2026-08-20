//! End-to-end tests for the destroy path.
//!
//! These live inside `destroy.rs`'s crate (via `#[path]` include from that
//! module) rather than in `tests/`, because §4.1 rule 4a scans
//! `crates/**` for the tracked destructive symbols and `crates/shepherd-tier/
//! tests/` is inside that scan. Exercising destruction through the public
//! `execute_local_destruction` entry point is the philosophically correct shape
//! anyway: it is what T10 and the daemon will call.
//!
//! §8.2 names four hazards that must be **exercised, not assumed away**:
//! held-writable-fd, mmap, open-between-floor-check-and-rename, and
//! staged-path-reopen. The first and last are asserted in
//! `shepherd-placeholder`'s `delete_mode` tests, where the primitive lives; the
//! ones that need the full ordering are here.

use std::path::PathBuf;
use std::time::Duration;

use shepherd_catalog::file_repo::{Availability, ScanRoot};
use shepherd_core::{Blake3Hash, IntentId, ObjectKey, RootId, StubMode, Timestamp};
use shepherd_placeholder::DeleteModeProvider;
use shepherd_placeholder::provider::{FileIdentity, PlaceholderProvider};
use shepherd_scan::floors::FloorPolicy;
use shepherd_storage::adapter::AttestationMode;

use super::*;
use crate::revalidate::{Location, LocationState};
use shepherd_storage::testing::MemAdapter;

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("shepherd-destroy-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }
    fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.0.join(name);
        std::fs::write(&p, bytes).unwrap();
        p
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn root(path: &std::path::Path) -> ScanRoot {
    ScanRoot {
        id: RootId::new(1),
        path: path.display().to_string(),
        stub_mode: StubMode::Delete,
        case_policy: shepherd_catalog::identity::PathCasePolicy::Sensitive,
        norm_policy: shepherd_catalog::identity::PathNormPolicy::Preserve,
        atime_mode: shepherd_catalog::AtimeMode::Relatime,
        volume_id: Some("uuid:test".into()),
        resync_required: false,
        availability: Availability::Available,
        destruction_ineligible: false,
        destruction_ineligible_reason: None,
    }
}

fn identity_of(path: &std::path::Path) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(path).unwrap();
    FileIdentity {
        dev: md.dev(),
        ino: md.ino(),
        nlink: md.nlink(),
    }
}

/// The identity the **catalog** holds for `path`, via the same function that
/// fills `file.fs_id` and that the upload path is handed.
///
/// Deliberately not `format!("{dev}:{ino}")`. That is the string this module's
/// subject used to lock on, and the whole point of these tests is that it is a
/// different string from this one.
fn catalog_fs_id(root: &ScanRoot, path: &std::path::Path) -> shepherd_core::FsId {
    shepherd_catalog::volume::fs_id(
        path,
        root.volume_id
            .as_deref()
            .expect("the fixture root carries a volume id"),
    )
    .expect("the catalog's fs_id for a file that exists")
}

fn custodian(mode: AttestationMode, hash: Blake3Hash) -> Location {
    Location {
        target: shepherd_core::TargetId::new(1),
        state: LocationState::Verified,
        attestation: mode,
        custody_eligible: true,
        last_full_hash_verified_at: Some(Timestamp::from_nanos(999)),
        publication_receipt_ok: true,
        object_version: (mode == AttestationMode::Version)
            .then(|| shepherd_core::ObjectVersion::new("v9")),
        expected_hash: hash,
    }
}

/// A file old enough and big enough to clear the floors.
fn payload() -> Vec<u8> {
    vec![7u8; 128 * 1024]
}

fn policy() -> FloorPolicy {
    FloorPolicy {
        min_size: 1024,
        min_age: Duration::from_secs(1),
    }
}

struct Fixture {
    tmp: Tmp,
    path: PathBuf,
    root: ScanRoot,
    hash: Blake3Hash,
    identity: FileIdentity,
    /// The catalog's identity for [`Fixture::path`], built the way the catalog
    /// builds it. Not `<dev>:<ino>` — see [`LocalDestroyRequest::fs_id`].
    fs_id: shepherd_core::FsId,
    key: ObjectKey,
    adapter: MemAdapter,
    audit: AuditLog,
    locks: FileLocks,
    provider: DeleteModeProvider,
}

fn fixture(tag: &str, mode: AttestationMode) -> Fixture {
    let tmp = Tmp::new(tag);
    let body = payload();
    let path = tmp.file("data.bin", &body);
    let hash = shepherd_scan::hash_bytes(&body);
    let key = shepherd_catalog::identity::content_key("t", hash);

    let adapter = if mode == AttestationMode::Version {
        MemAdapter::versioned()
    } else {
        MemAdapter::content_addressed()
    };
    // `put_versioned`: mechanism A pins a version at verify and re-attests it
    // with the closing HEAD, so these tests must control the value rather than
    // accept a derived one.
    adapter.put_versioned(&key, body.clone().into(), "v9");

    let audit = AuditLog::open(&tmp.0.join("audit").join("destroy.jsonl")).unwrap();
    let root = root(&tmp.0);
    Fixture {
        identity: identity_of(&path),
        fs_id: catalog_fs_id(&root, &path),
        root,
        path,
        hash,
        key,
        adapter,
        audit,
        locks: FileLocks::new(),
        provider: DeleteModeProvider::new(),
        tmp,
    }
}

impl Fixture {
    fn request<'a>(&'a self, custodian: &'a Location) -> LocalDestroyRequest<'a> {
        LocalDestroyRequest {
            intent: IntentId::new(1),
            path: &self.path,
            root: &self.root,
            expected_hash: self.hash,
            expected_size: payload().len() as u64,
            verified_identity: self.identity,
            fs_id: &self.fs_id,
            age: Duration::from_secs(60 * 60 * 24 * 30),
            floor_policy: policy(),
            custodian,
            remote_key: &self.key,
        }
    }

    async fn run(&self, custodian: &Location) -> Result<()> {
        execute_local_destruction(
            &self.request(custodian),
            &self.provider,
            &(&self.adapter as &dyn shepherd_storage::StorageAdapter),
            &self.audit,
            &self.locks,
            Timestamp::from_nanos(1_000_000),
        )
        .await
    }
}

/// The acquisition floor stands in front of every test below, and on a platform
/// with no open-handle detector it refuses before their subject is reachable.
///
/// [`shepherd_scan::floors`]'s `open_handles` is implemented on Linux only.
/// Everywhere else it answers `CouldNotDetermine`, which OQ-J defines as
/// held-open, so `execute_local_destruction` returns at **step 1** — before
/// re-attestation, before staging, before the unlink. A test that unwraps a
/// success, or that expects `DestroyError::Refused`, is then asserting against
/// an error raised by a step its own subject never reached. That is why eight
/// tests in this module failed on macOS the first time the suite ran there: not
/// because destruction is broken, but because they never got to it.
///
/// This asserts the platform-correct outcome of that floor and reports whether
/// the caller may go on to assert its own subject. **On a platform with no
/// detector, this assertion IS the test** — that destructive work is refused,
/// and refused for the stated reason rather than by accident.
///
/// It deliberately will not accept a bare refusal. `is_err()` would pass on a
/// panic, a missing fixture, a permissions error — on any bug in `destroy` at
/// all. The refusal has to name the floor, the platform whose handles could not
/// be checked, and the rule that makes "undetermined" mean "held".
#[must_use]
fn past_the_open_handle_floor(r: Result<()>) -> Option<Result<()>> {
    match &r {
        Err(DestroyError::Floor { code, detail })
            if *code == "held-open" && detail.contains("CouldNotDetermine") =>
        {
            assert!(
                std::env::consts::OS != "linux",
                "the open-handle floor answered CouldNotDetermine ON LINUX, where the \
                 detector exists. That is the detector breaking rather than a platform \
                 lacking one — and left unasserted it would silently convert every test \
                 below into a vacuous refusal check. detail: {detail}"
            );
            assert!(
                detail.contains(std::env::consts::OS),
                "the refusal must name the platform whose handles it could not check, so \
                 a reader knows which detector is missing: {detail}"
            );
            assert!(
                detail.contains("OQ-J"),
                "the refusal must name the rule that makes an undetermined answer mean \
                 held-open rather than clear: {detail}"
            );
            None
        }
        Ok(()) => {
            assert!(
                std::env::consts::OS == "linux",
                "destruction SUCCEEDED on {}, where open_handles() is unimplemented and \
                 the acquisition floor is supposed to fail closed. Either Phase 3 landed \
                 a detector for this platform — in which case these tests must be updated \
                 to expect success, DELIBERATELY — or the fail-closed floor stopped \
                 failing closed.",
                std::env::consts::OS
            );
            Some(r)
        }
        // Any other error is the caller's subject, or a genuine bug. Either way
        // it belongs to the caller's own assertion, not to this one.
        _ => Some(r),
    }
}

#[tokio::test]
async fn the_happy_path_destroys_and_audits() {
    let f = fixture("happy", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let Some(r) = past_the_open_handle_floor(f.run(&c).await) else {
        return;
    };
    r.unwrap();

    assert!(!f.path.exists(), "the original is gone");
    assert!(
        f.provider.list_staged(&f.tmp.0).unwrap().is_empty(),
        "nothing is left in staging"
    );
    let audit = f.audit.read_all();
    assert_eq!(audit.len(), 1);
    assert!(audit[0].contains("\"attestation\":\"version\""));
    assert!(audit[0].contains(&f.hash.to_hex()));
}

/// §4.10.1 step 4. The content changed after verification, so destruction is
/// refused and — abort-forward-never — the file comes back.
#[tokio::test]
async fn content_changed_since_verification_aborts_and_restores() {
    let f = fixture("changed", AttestationMode::Version);
    // The catalog believes a different hash than the disk holds.
    let mut c = custodian(AttestationMode::Version, f.hash);
    c.object_version = Some(shepherd_core::ObjectVersion::new("v9"));
    let wrong = Blake3Hash::from_bytes([0xEE; 32]);
    let req = LocalDestroyRequest {
        expected_hash: wrong,
        ..f.request(&c)
    };

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            &req,
            &f.provider,
            &(&f.adapter as &dyn shepherd_storage::StorageAdapter),
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    let err = r.unwrap_err();

    assert!(matches!(err, DestroyError::ContentChanged { .. }), "{err}");
    assert!(f.path.exists(), "abort-forward-never: the file is restored");
    assert_eq!(std::fs::read(&f.path).unwrap(), payload());
    assert!(
        f.audit.read_all().is_empty(),
        "nothing was destroyed to audit"
    );
}

/// §4.10.1 step 3. The inode is not the one that was verified — an
/// unlink-and-recreate between verification and destruction.
#[tokio::test]
async fn identity_mismatch_aborts_and_restores() {
    let f = fixture("identity", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let req = LocalDestroyRequest {
        verified_identity: FileIdentity {
            ino: f.identity.ino.wrapping_add(1),
            ..f.identity
        },
        ..f.request(&c)
    };

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            &req,
            &f.provider,
            &(&f.adapter as &dyn shepherd_storage::StorageAdapter),
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    let err = r.unwrap_err();

    assert!(
        matches!(err, DestroyError::IdentityMismatch { .. }),
        "{err}"
    );
    assert!(f.path.exists(), "the wrong file was NOT destroyed");
}

/// §4.10.2 step 5, mechanism A: the remote version moved, so the object we
/// verified is not the object that is there now.
#[tokio::test]
async fn a_changed_remote_version_aborts_and_restores() {
    let f = fixture("version", AttestationMode::Version);
    let mut c = custodian(AttestationMode::Version, f.hash);
    c.object_version = Some(shepherd_core::ObjectVersion::new("stale-version"));

    let Some(r) = past_the_open_handle_floor(f.run(&c).await) else {
        return;
    };
    let err = r.unwrap_err();
    assert!(matches!(err, DestroyError::Refused(_)), "{err}");
    assert!(
        f.path.exists(),
        "the local copy survives a failed re-attestation"
    );
}

/// §4.10.2 step 5: the remote object vanished between verification and
/// destruction — a bucket lifecycle rule, a NAS cleanup script. This is the
/// *plausible accident* the closing HEAD exists to catch, and catching it is
/// why the local-fd window is 10–100 ms rather than microseconds.
#[tokio::test]
async fn a_remote_object_deleted_before_the_closing_head_aborts() {
    let f = fixture("vanished", AttestationMode::Content);
    let c = custodian(AttestationMode::Content, f.hash);
    // Remove it behind the adapter's back.
    f.adapter.remove_raw(&f.key);

    let Some(r) = past_the_open_handle_floor(f.run(&c).await) else {
        return;
    };
    let err = r.unwrap_err();
    assert!(matches!(err, DestroyError::Refused(_)), "{err}");
    assert!(f.path.exists());
}

/// PM-3: a root needing resync refuses before anything is touched.
#[tokio::test]
async fn a_gated_root_refuses_before_staging() {
    let mut f = fixture("gated", AttestationMode::Version);
    f.root.resync_required = true;
    let c = custodian(AttestationMode::Version, f.hash);

    let err = f.run(&c).await.unwrap_err();
    assert!(matches!(err, DestroyError::Root(_)), "{err}");
    assert!(f.path.exists());
    assert!(
        f.provider.list_staged(&f.tmp.0).unwrap().is_empty(),
        "a gated root must not even stage"
    );
}

/// D-12: a destruction-ineligible root is refused the same way.
#[tokio::test]
async fn a_destruction_ineligible_root_refuses() {
    let mut f = fixture("d12", AttestationMode::Version);
    f.root.destruction_ineligible = true;
    f.root.destruction_ineligible_reason = Some("RENAME_NOREPLACE unsupported".into());
    let c = custodian(AttestationMode::Version, f.hash);

    let err = f.run(&c).await.unwrap_err();
    assert!(format!("{err}").contains("RENAME_NOREPLACE"), "{err}");
    assert!(f.path.exists());
}

/// §4.10.4: an incomplete forensic record halts *subsequent* destruction. The
/// halt is checked before anything irreversible happens.
#[tokio::test]
async fn a_halted_audit_log_refuses_before_staging() {
    let f = fixture("halted", AttestationMode::Version);
    f.audit
        .halt_for_recovery("an intent reached the syscall with no audit record");
    let c = custodian(AttestationMode::Version, f.hash);

    let err = f.run(&c).await.unwrap_err();
    assert!(matches!(err, DestroyError::Audit(_)), "{err}");
    assert!(f.path.exists());
}

/// OQ-J's precondition, through the full path: a file another handle holds open
/// is not destroyed. "Cannot determine" is treated the same way.
#[tokio::test]
async fn a_file_held_open_is_not_destroyed() {
    let f = fixture("openfd", AttestationMode::Version);
    let _holder = std::fs::File::open(&f.path).unwrap();
    let c = custodian(AttestationMode::Version, f.hash);

    let err = f.run(&c).await.unwrap_err();
    match err {
        DestroyError::Floor { code, detail } => {
            assert_eq!(code, "held-open", "{detail}");
            // The code alone is NOT enough, and this test was green for the
            // wrong reason on macOS before this assertion existed: `held-open`
            // is also what a platform with no detector answers, so the check
            // passed whether or not `_holder` held anything — it would have
            // passed with the `_holder` line deleted. Assert the EVIDENCE.
            #[cfg(target_os = "linux")]
            assert!(
                detail.contains("Descriptors"),
                "the refusal must come from finding THIS test's descriptor, not from the \
                 detector being unavailable — otherwise this test passes without its own \
                 fixture doing anything: {detail}"
            );
            #[cfg(not(target_os = "linux"))]
            assert!(
                detail.contains("CouldNotDetermine"),
                "on a platform with no open-handle detector the refusal must be the \
                 fail-closed one; a Descriptors answer here would mean a detector exists \
                 and this test is now asserting less than it could: {detail}"
            );
        }
        other => panic!("expected the open-handle floor to refuse, got {other}"),
    }
    assert!(f.path.exists());
}

/// §8.2's **mmap** hazard, exercised rather than assumed away.
///
/// A mapping established before staging still writes through it afterwards.
/// This asserts the residual §4.10.1 admits is REAL — it is not a test that the
/// hazard is prevented, because it is not prevented. What bounds it is OQ-J's
/// open-handle precondition narrowing the population, and the 10–100 ms window;
/// both are documented, neither is closed.
#[test]
fn an_mmap_established_before_staging_still_writes_after_it() {
    let t = Tmp::new("mmap");
    let p = t.file("m.bin", &[1u8; 4096]);

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&p)
        .unwrap();
    let mut map = unsafe { memmap2::MmapMut::map_mut(&file).unwrap() };

    let staged = DeleteModeProvider::new()
        .stage_for_destruction(&t.0, &p)
        .unwrap();

    map[0] = 0xFF;
    map.flush().unwrap();

    let after = std::fs::read(&staged.staged).unwrap();
    assert_eq!(
        after[0], 0xFF,
        "a pre-existing mapping wrote through the rename — D-8/OQ-J's residual, \
         documented rather than fixed"
    );
}

/// §8.2's **open-between-floor-check-and-rename** hazard.
///
/// The floors pass, then a handle appears before staging. The check cannot see
/// it, which is precisely the residual: OQ-J narrows *which* files are exposed,
/// it does not close the window.
#[tokio::test]
async fn a_handle_opened_after_the_floor_check_is_not_seen_by_it() {
    let f = fixture("racewindow", AttestationMode::Version);

    // The floors pass right now, with nothing holding the file.
    let md = std::fs::symlink_metadata(&f.path).unwrap();
    use std::os::unix::fs::MetadataExt;
    let verdict = shepherd_scan::floors::evaluate(
        &policy(),
        &shepherd_scan::floors::FloorInput {
            path: f.path.clone(),
            size: md.len(),
            age: Duration::from_secs(60 * 60 * 24 * 30),
            nlink: md.nlink(),
            is_symlink: false,
            allocated_bytes: Some(md.blocks() * 512),
            fs_id: None,
            observed_at: Timestamp::from_nanos(1),
        },
        shepherd_scan::floors::FloorContext::Acquisition,
    );
    // Baseline: nothing holds it yet — on a platform that can tell. Where
    // `open_handles` is unimplemented the acquisition floor refuses fail-closed
    // no matter what holds the file, so this baseline cannot be established
    // there. Assert THAT instead of skipping: the window this test documents is
    // a property of the ordering, not of the detector, and the rest of the test
    // exercises it on every platform.
    match verdict.refusal() {
        None => assert!(
            std::env::consts::OS == "linux",
            "the acquisition floor found this file eligible on {}, where open_handles() \
             is unimplemented and it should have refused fail-closed. Either Phase 3 \
             landed a detector or the floor stopped failing closed.",
            std::env::consts::OS
        ),
        Some(r) => {
            assert!(
                std::env::consts::OS != "linux",
                "the acquisition floor refused a file nothing holds, ON LINUX, where the \
                 detector exists: {r:?}"
            );
            assert_eq!(
                r.code(),
                "held-open",
                "on a platform with no open-handle detector the ONLY expected refusal here \
                 is the fail-closed one; anything else means a different floor tripped and \
                 this test is no longer measuring what it says: {r:?}"
            );
        }
    }

    // …and now a writer arrives, after the check.
    let mut writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&f.path)
        .unwrap();
    let staged = f.provider.stage_for_destruction(&f.tmp.0, &f.path).unwrap();
    use std::io::Write;
    writer.write_all(b"late").unwrap();
    writer.sync_all().unwrap();

    let after = std::fs::read(&staged.staged).unwrap();
    assert_eq!(
        after.len(),
        payload().len() + 4,
        "the late writer's bytes are present: the floor check at step 1 cannot see a \
         handle that arrives at step 1.5, which is the window OQ-J documents"
    );
}

/// Per-file serialization through the real entry point: a second attempt on the
/// same file waits rather than racing.
#[tokio::test]
async fn two_destroys_of_one_file_serialize() {
    let f = fixture("serial", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);

    // The first succeeds; the second finds no file and fails at the stat rather
    // than destroying anything a second time.
    let Some(first) = past_the_open_handle_floor(f.run(&c).await) else {
        // No detector on this platform, so the first destruction never happened
        // and there is no second attempt to serialize against. The refusal is
        // asserted above; asserting a second refusal would add nothing.
        return;
    };
    first.unwrap();
    let err = f.run(&c).await.unwrap_err();
    assert!(matches!(err, DestroyError::Io(_)), "{err}");
    assert_eq!(f.audit.read_all().len(), 1, "exactly one audit record");
}

/// The other half of the nested-staging seam, and the one a provider test
/// cannot reach: `destroy.rs` must hand `stage_for_destruction` the
/// **registered root**. A provider that stages correctly is no use if its
/// caller names the wrong directory.
///
/// The assertion is where the staging directory ended up, because that is what
/// startup recovery lists. `<root>/sub/dir/.shepherd-staging` would be a
/// crash-window in which the bytes exist and nothing can find them.
#[tokio::test]
async fn the_destroy_path_stages_a_nested_file_into_the_registered_root() {
    use shepherd_placeholder::delete_mode::STAGING_DIR_NAME;

    let f = fixture("nested-root", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);

    // The same bytes as the fixture's own file, so the content-addressed key
    // and the version already pinned in the adapter still describe it.
    let parent = f.tmp.0.join("sub").join("dir");
    std::fs::create_dir_all(&parent).unwrap();
    let nested = parent.join("deep.bin");
    std::fs::write(&nested, payload()).unwrap();
    let nested_fs_id = catalog_fs_id(&f.root, &nested);

    let req = LocalDestroyRequest {
        path: &nested,
        verified_identity: identity_of(&nested),
        fs_id: &nested_fs_id,
        ..f.request(&c)
    };

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            &req,
            &f.provider,
            &(&f.adapter as &dyn shepherd_storage::StorageAdapter),
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    r.unwrap();

    assert!(!nested.exists(), "the nested file was destroyed");
    assert!(
        f.tmp.0.join(STAGING_DIR_NAME).exists(),
        "staging went through the registered root's directory — the one \
         `list_staged(root)` reads"
    );
    assert!(
        !parent.join(STAGING_DIR_NAME).exists(),
        "and NOT beside the file. A staged entry there survives a crash somewhere \
         recovery never looks, which is the same as losing it"
    );
}

/// Per-file serialization is only worth anything if the destroy path and the
/// **rest of the system** name the same lock.
///
/// [`crate::upload`] takes `FileLocks::acquire` on the catalog's `fs_id` —
/// `<stable-volume-id>:<inode>`. This path once synthesized `<st_dev>:<inode>`
/// from the verified identity instead, and on any UUID-backed filesystem those
/// two strings can never be equal: the guard was acquired, held across every
/// await, and guarded nothing. An upload and a destruction of one file could
/// run concurrently while both looked serialized.
///
/// So the assertion is contention, not shape. A test that checked the key's
/// *format* would pass on a fix that changed both sides to something equally
/// wrong; this one fails unless the two actually collide.
///
/// The lock is taken **before** the acquisition floor, so this holds on every
/// unix platform — with or without an open-handle detector.
#[tokio::test]
async fn a_destroy_waits_on_the_lock_the_catalog_identity_names() {
    let f = fixture("contend-catalog", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);

    // Exactly the value an upload of this same file would be handed.
    let held = f.locks.acquire(&catalog_fs_id(&f.root, &f.path)).await;

    let blocked = tokio::time::timeout(Duration::from_millis(250), f.run(&c)).await;
    assert!(
        blocked.is_err(),
        "a holder of this file's catalog fs_id lock must block its destruction. It did \
         not, so the two sides are keyed on different strings and `FileLocks` serializes \
         nothing between them"
    );

    // The other direction: releasing lets it through, so the block above was
    // the lock and not a hang somewhere else in the path.
    drop(held);
    let released = tokio::time::timeout(Duration::from_secs(30), f.run(&c))
        .await
        .expect("releasing the lock must let the destruction proceed");
    let _ = past_the_open_handle_floor(released);
}

/// The pair to the test above, and the reason it cannot be satisfied cheaply.
///
/// `<st_dev>:<inode>` is **not** this file's identity — `st_dev` is not stable
/// across a remount, which is why `volume::fs_id` uses the volume UUID
/// (G-1-IDENTITY-FSID). Nothing may serialize against it. A "fix" that moved
/// both the upload and the destroy side onto `<st_dev>:<inode>` would satisfy
/// the contention test above and fail this one.
#[tokio::test]
async fn a_destroy_does_not_wait_on_a_dev_ino_shaped_key() {
    let f = fixture("contend-devino", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);

    let stale = shepherd_core::FsId::new(format!("{}:{}", f.identity.dev, f.identity.ino));
    assert_ne!(
        stale.as_str(),
        f.fs_id.as_str(),
        "the two identity formats must genuinely differ on this filesystem, or neither \
         half of this pair is measuring anything"
    );

    let _held = f.locks.acquire(&stale).await;
    let r = tokio::time::timeout(Duration::from_secs(30), f.run(&c))
        .await
        .expect(
            "a lock on a key that is not this file's identity must not block it; if this \
             times out, the destroy path is keyed on `<dev>:<ino>` again",
        );
    let _ = past_the_open_handle_floor(r);
}

/// PM-2's seam, and the one T10 must use. Remote destruction routes through
/// this crate rather than calling the adapter directly — rule 4 makes that
/// mandatory, and the point of the mandate is that the intent + audit apparatus
/// cannot be bypassed by a second call site.
#[tokio::test]
async fn remote_discard_deletes_and_audits_through_the_same_apparatus() {
    let f = fixture("discard", AttestationMode::Version);
    let guard =
        shepherd_storage::adapter::VersionGuard::Version(shepherd_core::ObjectVersion::new("v9"));

    execute_remote_discard(
        IntentId::new(7),
        &(&f.adapter as &dyn shepherd_storage::StorageAdapter),
        &f.key,
        &guard,
        &f.audit,
        "version",
        Timestamp::from_nanos(5),
    )
    .await
    .unwrap();

    assert_eq!(f.adapter.deleted_keys(), vec![f.key.as_str().to_owned()]);
    let audit = f.audit.read_all();
    assert_eq!(audit.len(), 1);
    assert!(audit[0].contains("\"kind\":\"remote\""));
    assert!(audit[0].contains("\"intent\":7"));
}

/// A halted audit log stops remote discard too — not only local destruction.
#[tokio::test]
async fn remote_discard_refuses_while_the_audit_log_is_halted() {
    let f = fixture("discard-halt", AttestationMode::Version);
    f.audit.halt_for_recovery("incomplete forensic record");
    let guard =
        shepherd_storage::adapter::VersionGuard::Version(shepherd_core::ObjectVersion::new("v9"));

    let err = execute_remote_discard(
        IntentId::new(8),
        &(&f.adapter as &dyn shepherd_storage::StorageAdapter),
        &f.key,
        &guard,
        &f.audit,
        "version",
        Timestamp::from_nanos(5),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, DestroyError::Audit(_)), "{err}");
    assert!(
        f.adapter.deleted_keys().is_empty(),
        "nothing may be deleted while the record is incomplete"
    );
}

/// §4.10.4, abort-forward-never, at the last possible moment: the **unlink
/// itself** fails. The destruction has not happened — the staged entry still
/// holds the bytes — so the file is restored rather than left orphaned in
/// staging.
///
/// Uses `MockPlaceholderProvider::fail_next_destroy()`, which makes this
/// reachable without needing a filesystem to misbehave on cue. It found a real
/// gap: the first version of `execute_local_destruction` propagated the error
/// straight out and left the file staged.
#[tokio::test]
async fn a_failing_unlink_restores_rather_than_orphaning_the_file() {
    use shepherd_placeholder::mock::MockPlaceholderProvider;

    let f = fixture("unlink-fails", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let provider = MockPlaceholderProvider::new();
    provider.fail_next_destroy();

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            &f.request(&c),
            &provider,
            &(&f.adapter as &dyn shepherd_storage::StorageAdapter),
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    let err = r.unwrap_err();

    assert!(matches!(err, DestroyError::Provider(_)), "{err}");
    assert!(
        f.audit.read_all().is_empty(),
        "nothing was destroyed, so nothing may be audited as destroyed"
    );
}

// --- the halt is GLOBAL, which means it has to be a gate --------------------

/// A [`RemoteGate`] that parks inside the closing HEAD until it is released.
///
/// The closing HEAD is the last step before the irreversible one, so a destroy
/// parked here is **admitted**: past the top-of-function halt check, past the
/// floors, staged, re-hashed. That is precisely the state the finding describes
/// — and parking is how the interleaving is made explicit rather than hoped
/// for. A test that called destroy twice and waited would prove nothing.
struct ParkedRemote<'a> {
    inner: &'a dyn shepherd_storage::StorageAdapter,
    /// Signalled when the closing HEAD is reached.
    entered: std::sync::Arc<tokio::sync::Notify>,
    /// Awaited there, so the caller chooses when this destroy goes on.
    release: std::sync::Arc<tokio::sync::Notify>,
}

#[async_trait::async_trait]
impl RemoteGate for ParkedRemote<'_> {
    async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>> {
        self.entered.notify_one();
        self.release.notified().await;
        self.inner
            .head(key)
            .await
            .map_err(|e| DestroyError::Storage(e.to_string()))
    }

    /// Never reached: the local destroy path does not remove remote objects.
    /// Answering without touching the adapter keeps this double out of the
    /// remote-destruction seam entirely.
    async fn remove_object(&self, _key: &ObjectKey, _guard: &VersionGuard) -> Result<()> {
        Ok(())
    }
}

/// A second file in the fixture's root, identical to the first.
///
/// Same bytes means the same content-addressed key, so the closing HEAD finds
/// the object the fixture already published — and a **different inode**, so
/// `FileLocks` lets the two destructions run at the same time. That is the
/// point: per-file locking is exactly what does not serialize them.
fn sibling(f: &Fixture, name: &str) -> (PathBuf, FileIdentity, shepherd_core::FsId) {
    let p = f.tmp.file(name, &payload());
    let id = identity_of(&p);
    let fs_id = catalog_fs_id(&f.root, &p);
    (p, id, fs_id)
}

/// §4.10.4's halt is **global**: "subsequent destruction halts until audit
/// writes succeed again". The check at the top of `execute_local_destruction`
/// cannot deliver that on its own, because it is one-time and per-call — two
/// destructions of two files pass it against the same unhalted state, and
/// nothing re-reads it between then and the syscall.
///
/// So the audit failure of one destroy has to be able to stop another that was
/// **already admitted**. This test puts the second destroy one step short of
/// the unlink, runs the first start to finish with an audit log that cannot be
/// written, and then lets the second go on.
///
/// The assertion is the FILE, not the error. Both destroys fail either way —
/// the append is broken for both — so an `is_err()` check passes against the
/// unfixed code while the second file is being destroyed after the halt.
#[tokio::test]
async fn a_destroy_already_admitted_does_not_unlink_after_another_one_halts_the_audit() {
    let f = fixture("halt-race", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let (second, second_id, second_fs_id) = sibling(&f, "second.bin");

    // Every append now fails at `open`: the same mechanism
    // `audit::tests::a_failed_write_halts_destruction` uses. `AuditLog::open`
    // creates the parent directory and not the file, so the name is free.
    std::fs::create_dir(f.tmp.0.join("audit").join("destroy.jsonl"))
        .expect("block the audit log with a directory at its path");

    let req2 = LocalDestroyRequest {
        path: &second,
        verified_identity: second_id,
        fs_id: &second_fs_id,
        ..f.request(&c)
    };
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let parked = ParkedRemote {
        inner: &f.adapter,
        entered: entered.clone(),
        release: release.clone(),
    };
    let second_destroy = execute_local_destruction(
        &req2,
        &f.provider,
        &parked,
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(2),
    );
    tokio::pin!(second_destroy);

    // Drive the second destroy until it parks. Reaching the closing HEAD is the
    // proof that it is admitted — it read the halt flag, found it clear, and
    // has already staged its file.
    tokio::select! {
        r = &mut second_destroy => {
            // On a platform with no open-handle detector this refused at the
            // floor and never reached its subject.
            assert!(
                past_the_open_handle_floor(r).is_none(),
                "the second destroy finished without reaching the closing HEAD"
            );
            return;
        }
        () = entered.notified() => {}
    }

    // The first destroy, start to finish, while the second is in flight. It
    // crosses the unlink and then cannot record it, which is what halts the log.
    //
    // Bounded, because the failure mode of an over-broad gate is a DEADLOCK
    // rather than a wrong answer: a gate taken for the whole path is held by the
    // parked destroy, which is waiting for a release that only arrives once this
    // one returns. A hung suite reports nothing; this reports which fix is wrong.
    let first = tokio::time::timeout(Duration::from_secs(30), f.run(&c))
        .await
        .expect(
            "a destroy blocked while another was merely IN FLIGHT — the gate covers more \
             than the irreversible step",
        );
    let Some(first) = past_the_open_handle_floor(first) else {
        return;
    };
    let err = first.unwrap_err();
    assert!(matches!(err, DestroyError::Audit(_)), "{err}");
    assert!(
        !f.path.exists(),
        "the first destroy has to genuinely cross the irreversible step, or the \
         halt it sets is not the one this test is about"
    );
    assert!(
        f.audit.is_halted(),
        "a failed audit append must halt destruction"
    );

    release.notify_one();
    let err2 = tokio::time::timeout(Duration::from_secs(30), second_destroy)
        .await
        .expect("the released destroy must be able to finish")
        .expect_err("destruction is halted, so the admitted destroy must refuse");

    assert!(
        second.exists(),
        "THE HALT IS NOT GLOBAL: {} was unlinked after an audit failure had already \
         halted destruction. The check at the top of the destroy path ran before the \
         halt existed, and nothing consulted it again before the syscall.",
        second.display()
    );
    assert_eq!(
        std::fs::read(&second).expect("read the survivor"),
        payload(),
        "abort-forward-never: a refusal at the gate restores the staged file"
    );
    assert!(
        matches!(
            err2,
            DestroyError::Audit(crate::audit::AuditError::Halted { .. })
        ),
        "the refusal must be the HALT rather than this destroy's own failed \
         append — the second means it already destroyed the file: {err2:?}"
    );
    assert!(
        f.provider.list_staged(&f.tmp.0).unwrap().is_empty(),
        "nothing is left in staging"
    );
}

/// The accepting direction, and the reason the gate is around the irreversible
/// step rather than around the whole path.
///
/// A "fix" that took a global lock for the duration of `execute_local_destruction`
/// would satisfy the test above and **deadlock here**: the parked destroy holds
/// the lock while waiting for a release that only comes after the other destroy
/// finishes. So both awaits are bounded, and a deadlock is a failure with a name
/// rather than a hung suite.
///
/// A gate that simply refused the second destroy would fail here too.
#[tokio::test]
async fn two_concurrent_destroys_with_a_healthy_audit_log_both_complete() {
    let f = fixture("halt-race-ok", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let (second, second_id, second_fs_id) = sibling(&f, "second.bin");

    let req2 = LocalDestroyRequest {
        path: &second,
        verified_identity: second_id,
        fs_id: &second_fs_id,
        ..f.request(&c)
    };
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let parked = ParkedRemote {
        inner: &f.adapter,
        entered: entered.clone(),
        release: release.clone(),
    };
    let second_destroy = execute_local_destruction(
        &req2,
        &f.provider,
        &parked,
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(2),
    );
    tokio::pin!(second_destroy);

    tokio::select! {
        r = &mut second_destroy => {
            assert!(
                past_the_open_handle_floor(r).is_none(),
                "the second destroy finished without reaching the closing HEAD"
            );
            return;
        }
        () = entered.notified() => {}
    }

    let first = tokio::time::timeout(Duration::from_secs(30), f.run(&c))
        .await
        .expect(
            "a destroy blocked while another was merely IN FLIGHT. The gate is around \
             more than the irreversible step, so two destructions of two different \
             files cannot overlap at all",
        );
    let Some(first) = past_the_open_handle_floor(first) else {
        return;
    };
    first.unwrap();

    release.notify_one();
    tokio::time::timeout(Duration::from_secs(30), second_destroy)
        .await
        .expect("the released destroy must be able to finish")
        .unwrap();

    assert!(!f.path.exists(), "the first file is gone");
    assert!(!second.exists(), "the second file is gone");
    assert_eq!(
        f.audit.read_all().len(),
        2,
        "two destructions, two audit records"
    );
    assert!(!f.audit.is_halted());
    assert!(
        f.provider.list_staged(&f.tmp.0).unwrap().is_empty(),
        "nothing is left in staging"
    );
}
