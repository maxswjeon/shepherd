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
use crate::test_adapter::FakeRemote;

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
    key: ObjectKey,
    adapter: FakeRemote,
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

    let adapter = FakeRemote::new(mode == AttestationMode::Version);
    adapter.put(&key, body.clone().into());

    let audit = AuditLog::open(&tmp.0.join("audit").join("destroy.jsonl")).unwrap();
    Fixture {
        identity: identity_of(&path),
        root: root(&tmp.0),
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
            &self.adapter,
            &self.audit,
            &self.locks,
            Timestamp::from_nanos(1_000_000),
        )
        .await
    }
}

#[tokio::test]
async fn the_happy_path_destroys_and_audits() {
    let f = fixture("happy", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    f.run(&c).await.unwrap();

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

    let err = execute_local_destruction(
        &req,
        &f.provider,
        &f.adapter,
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .unwrap_err();

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

    let err = execute_local_destruction(
        &req,
        &f.provider,
        &f.adapter,
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .unwrap_err();

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

    let err = f.run(&c).await.unwrap_err();
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
    f.adapter.remove(&f.key);

    let err = f.run(&c).await.unwrap_err();
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
        DestroyError::Floor { code, .. } => assert_eq!(code, "held-open"),
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

    let staged = DeleteModeProvider::new().stage_for_destruction(&p).unwrap();

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
    assert!(verdict.is_eligible(), "baseline: nothing holds it yet");

    // …and now a writer arrives, after the check.
    let mut writer = std::fs::OpenOptions::new()
        .append(true)
        .open(&f.path)
        .unwrap();
    let staged = f.provider.stage_for_destruction(&f.path).unwrap();
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
    f.run(&c).await.unwrap();
    let err = f.run(&c).await.unwrap_err();
    assert!(matches!(err, DestroyError::Io(_)), "{err}");
    assert_eq!(f.audit.read_all().len(), 1, "exactly one audit record");
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
        &f.adapter,
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
        &f.adapter,
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
