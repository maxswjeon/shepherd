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

/// A root gate a test can flip mid-destruction.
///
/// PM-3's gates are mutable, so what this exercises is the WINDOW: the request
/// is assembled while the root permits destruction and the gate closes while
/// the destroy path is staging, hashing and HEADing.
#[derive(Default)]
struct Gate(std::sync::Mutex<Option<String>>);

impl Gate {
    fn open() -> Self {
        Self(std::sync::Mutex::new(None))
    }
    /// The live gate closes while the snapshot in the request still permits.
    fn close(&self, reason: &str) {
        *self.0.lock().unwrap() = Some(reason.to_owned());
    }
}

#[async_trait::async_trait]
impl crate::destroy::RootGate for Gate {
    async fn hold_open(
        &self,
        root: shepherd_core::RootId,
    ) -> Result<std::result::Result<crate::destroy::RootHold, String>> {
        // The root is checked, because a gate that ignores it is a gate that
        // can be asked the wrong question — which is the other half of what
        // this port exists for.
        if root != shepherd_core::RootId::new(1) {
            return Ok(Err(format!(
                "this gate is for root 1 and was asked about root {}",
                root.get()
            )));
        }
        match self.0.lock().unwrap().clone() {
            Some(reason) => Ok(Err(reason)),
            None => Ok(Ok(crate::destroy::RootHold::nothing_can_change_this_root())),
        }
    }
}

/// Records the §4.4 transitions a destruction asks for.
///
/// A `Vec`, because the ORDER is the property: `syscall-issued` must precede
/// the unlink and `audited` must follow the record, and a set could not tell
/// those apart from the same states in the wrong sequence.
#[derive(Default)]
struct Journal(std::sync::Mutex<Vec<shepherd_catalog::intent::IntentState>>);

impl Journal {
    fn seen(&self) -> Vec<shepherd_catalog::intent::IntentState> {
        self.0.lock().unwrap().clone()
    }
}

#[async_trait::async_trait]
impl crate::destroy::IntentGate for Journal {
    async fn advance(
        &self,
        _id: shepherd_core::IntentId,
        to: shepherd_catalog::intent::IntentState,
    ) -> Result<()> {
        self.0.lock().unwrap().push(to);
        Ok(())
    }
}

/// An intent bound to exactly what a request destroys.
///
/// Every request that overrides `path` or `expected_hash` must rebind, because
/// the destroy path now refuses a token prepared for something else. That is
/// the point of the check, so the fixtures state the binding rather than
/// working around it.
fn bound_intent(id: i64, path: &Path, size: i64, hash: Blake3Hash) -> PreparedIntent {
    PreparedIntent::fabricated_for_tests(
        IntentId::new(id),
        shepherd_catalog::intent::IntentKind::Local,
        &path.to_string_lossy(),
        size,
        Some(hash),
    )
}

/// A prepared intent authorizes ONE destruction, not any destruction.
///
/// `PreparedIntent` proved a row reached `prepared` and nothing about which
/// row, so an intent prepared for one file authorized unlinking another and
/// the sole forensic record — which is what §4.10.4's recovery reads — named a
/// file that still exists. Being `Copy`, one row could back any number of
/// them; that half is now a compile error rather than a test.
#[tokio::test]
async fn an_intent_prepared_for_another_file_does_not_authorize_this_one() {
    let f = fixture("wrong-intent", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let elsewhere = f.tmp.0.join("someone-else.bin");
    let req = LocalDestroyRequest {
        intent: bound_intent(1, &elsewhere, payload().len() as i64, f.hash),
        ..f.request(&c)
    };

    let err = execute_local_destruction(
        req,
        &f.provider,
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("an intent prepared for another path must not authorize this unlink");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains("someone-else.bin")),
        "the refusal must name the disagreement: {err}"
    );
    assert!(f.path.exists(), "and the file is still there");
    assert!(
        f.audit.read_all().is_empty(),
        "refused before the syscall, so there is nothing to record"
    );
}

/// Custody must be about the bytes being destroyed.
///
/// The closing check imported the custodian's attestation mode and version but
/// never required its hash to be this file's. Under `AttestationMode::Content`
/// that let a recently-verified location holding different same-sized content
/// stand as custody: the local re-hash passes against the request's own hash,
/// the closing HEAD proves only that an object of the right size exists, and
/// the last local copy of unrelated bytes is unlinked.
#[tokio::test]
async fn custody_verified_against_other_bytes_does_not_authorize_this_destroy() {
    let f = fixture("wrong-custody", AttestationMode::Content);
    let other = Blake3Hash::from_bytes([0xAB; 32]);
    let c = custodian(AttestationMode::Content, other);
    let req = f.request(&c);

    let err = execute_local_destruction(
        req,
        &f.provider,
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("a custodian verified against other bytes must not authorize this destroy");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains(&other.to_hex())),
        "the refusal must name the hash custody was verified against: {err}"
    );
    assert!(f.path.exists(), "and the file is still there");
}

/// The remote key must name the bytes, whatever §4.9 layout built it.
#[tokio::test]
async fn a_remote_key_naming_other_bytes_does_not_authorize_this_destroy() {
    let f = fixture("wrong-key", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let other = shepherd_catalog::identity::content_key("t", Blake3Hash::from_bytes([0xCD; 32]));
    let req = LocalDestroyRequest {
        remote_key: &other,
        ..f.request(&c)
    };

    let err = execute_local_destruction(
        req,
        &f.provider,
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("a key naming other bytes must not authorize this destroy");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains("does not name")),
        "the refusal must say the key is about something else: {err}"
    );
    assert!(f.path.exists(), "and the file is still there");
}

/// The closing HEAD must ask the target that authorized the destruction.
///
/// The binding round 30 added checked the hash and the key and never checked
/// WHICH target answered. A custody proof from target A paired with a gate
/// reaching target B satisfies the closing HEAD under content attestation from
/// any same-sized object at a hash-named key on B — while A's replica, the one
/// that authorized this, is never rechecked and may have vanished.
#[tokio::test]
async fn a_closing_head_sent_to_another_target_does_not_authorize_this_destroy() {
    let f = fixture("wrong-target", AttestationMode::Content);
    let mut c = custodian(AttestationMode::Content, f.hash);
    c.target = shepherd_core::TargetId::new(7);
    let req = f.request(&c);

    let err = execute_local_destruction(
        req,
        &f.provider,
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("a HEAD against another target must not authorize this destroy");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains("target 7")),
        "the refusal must name the target custody was proven against: {err}"
    );
    assert!(f.path.exists(), "and the file is still there");
}

/// A gate that cannot name its target is refused, not waved through.
///
/// This is the arm that decides whether the check above is a check: `None` is
/// "I do not know which target answered", which is not a weaker proof than a
/// mismatch — it is the same one. A bare adapter genuinely cannot know, since
/// the target is a catalog fact rather than a property of the connection.
#[tokio::test]
async fn a_gate_that_cannot_name_its_target_does_not_authorize_this_destroy() {
    let f = fixture("no-target", AttestationMode::Content);
    let c = custodian(AttestationMode::Content, f.hash);
    let req = f.request(&c);

    let err = execute_local_destruction(
        req,
        &f.provider,
        &(&f.adapter as &dyn shepherd_storage::StorageAdapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("a gate with no target must not authorize a destroy");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains("TargetGate")),
        "the refusal must say how to fix it: {err}"
    );
    assert!(f.path.exists(), "and the file is still there");
}

/// The remote path validates its intent too.
///
/// `authorizes` was wired to the local path alone, so an intent prepared for
/// remote object A could accompany a DELETE of object B — the audit record then
/// cites A's intent id while the durable recovery row describes A rather than
/// the object that was irreversibly removed. A forensic record pointing at the
/// wrong object is worse than none, because recovery trusts it.
#[tokio::test]
async fn a_remote_intent_prepared_for_another_object_does_not_authorize_this_delete() {
    let f = fixture("wrong-remote-intent", AttestationMode::Version);
    let guard =
        shepherd_storage::adapter::VersionGuard::Version(shepherd_core::ObjectVersion::new("v9"));
    let elsewhere =
        shepherd_catalog::identity::content_key("t", Blake3Hash::from_bytes([0x5A; 32]));

    let err = execute_remote_discard(
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(31),
            shepherd_catalog::intent::IntentKind::Remote,
            elsewhere.as_str(),
            0,
            None,
        ),
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.key,
        &guard,
        &f.audit,
        &f.journal,
        "version",
        Timestamp::from_nanos(5),
    )
    .await
    .expect_err("an intent prepared for another object must not authorize this delete");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains(elsewhere.as_str())),
        "the refusal must name what the intent was prepared for: {err}"
    );
    assert!(
        f.adapter.deleted_keys().is_empty(),
        "and nothing was deleted"
    );
    assert!(
        f.audit.read_all().is_empty(),
        "refused before `admit`, so the audit gate is not even charged"
    );
}

/// A PM-3 gate that closes mid-destruction stops the unlink.
///
/// The gate was read once, from the caller's snapshot, at the top of
/// `execute_local_destruction` — before waiting for the file lock and before
/// staging, hashing through the handle, and the remote HEAD. Every one of those
/// takes time, and PM-3's gates are mutable: a watcher journal overflow sets
/// `resync_required` and a volume going away changes `availability`. PM-3 says
/// destruction stops while the gate is SET, not while it was set when the
/// request was assembled.
///
/// The gate here closes while the destroy path is working, which is the window
/// itself rather than a stand-in for it.
#[tokio::test]
async fn a_root_gate_that_closes_during_a_destroy_stops_it_before_the_unlink() {
    let f = fixture("gate-closes", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let req = f.request(&c);

    // The SNAPSHOT still permits destruction — `f.root` is untouched, so the
    // check at the top of the function passes — and the live gate refuses.
    // Nothing but a re-read can produce a refusal from this arrangement, which
    // is the property under test, and it needs no timing to provoke.
    f.gate.close("watcher journal overflowed");
    assert!(
        req.root.destroy_refusal().is_none(),
        "the snapshot must still permit, or this would pass on the stale check"
    );

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            req,
            &f.provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    let err = r.expect_err("a gate set during the destroy must stop it");
    assert!(
        matches!(&err, DestroyError::Root(reason) if reason.contains("overflowed")),
        "the refusal must carry the gate's own reason: {err}"
    );
    assert!(
        f.path.exists(),
        "and the file is still there, restored from staging"
    );
    assert!(
        f.audit.read_all().is_empty(),
        "nothing irreversible happened, so nothing is owed a record"
    );
}

/// A gate for another root does not speak for this destruction.
///
/// The request carried `root` and `root_gate` independently and the gate was
/// asked no question at all — so a gate belonging to root B could be attached
/// to a destruction under root A and answer "open" while A required resync.
/// `hold_open` takes the root now, so an implementation that looks it up
/// cannot be asked about the wrong one.
#[tokio::test]
async fn a_gate_for_another_root_does_not_authorize_this_destroy() {
    let f = fixture("wrong-root", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let mut root = f.root.clone();
    root.id = shepherd_core::RootId::new(2);
    // The request AGREES WITH ITSELF — the catalog records the file under the
    // root the request supplies — so only the gate disagrees. Without this the
    // (earlier, cheaper) owning-root check fires first and this test would pass
    // without ever reaching the gate.
    let req = LocalDestroyRequest {
        root: &root,
        file_root: shepherd_core::RootId::new(2),
        ..f.request(&c)
    };

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            req,
            &f.provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    let err = r.expect_err("a gate for another root must not authorize this destroy");
    assert!(
        matches!(&err, DestroyError::Root(reason) if reason.contains("root 2")),
        "the refusal must name the root it was asked about: {err}"
    );
    assert!(f.path.exists(), "and the file is still there");
}

/// A replica that vanishes while the destroy waits does not authorize it.
///
/// `destroy_staged` asks the closing HEAD, and TWO unbounded waits then sit
/// between that answer and the unlink: `audit.admit()` takes a process-wide
/// gate `AuditLog` documents as held across another destruction's network
/// DELETE, and `hold_open` is another await on top of it. Under contention the
/// replica that authorised this can disappear inside that gap after its own
/// HEAD said it was there, and the last local copy would still be unlinked —
/// the one outcome §4.10.2 exists to prevent.
///
/// So the HEAD is asked again immediately before the syscall. This double
/// answers the first one and loses the object before the second, which is the
/// gap itself rather than a stand-in for it.
#[tokio::test]
async fn a_replica_that_disappears_while_the_destroy_waits_stops_the_unlink() {
    struct VanishesAfterTheFirstHead<'a> {
        inner: &'a dyn shepherd_storage::StorageAdapter,
        asked: std::sync::atomic::AtomicUsize,
    }

    #[async_trait::async_trait]
    impl RemoteGate for VanishesAfterTheFirstHead<'_> {
        fn target(&self) -> Option<shepherd_core::TargetId> {
            Some(shepherd_core::TargetId::new(1))
        }

        fn prefix(&self) -> Option<&str> {
            Some("t")
        }

        async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>> {
            if self.asked.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                return self
                    .inner
                    .head(key)
                    .await
                    .map_err(|e| DestroyError::Storage(e.to_string()));
            }
            // Gone by the second ask.
            Ok(None)
        }

        async fn remove_object(&self, _key: &ObjectKey, _guard: &VersionGuard) -> Result<()> {
            unreachable!("the local destroy path removes no remote object")
        }
    }

    let f = fixture("vanishes", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let req = f.request(&c);
    let remote = VanishesAfterTheFirstHead {
        inner: &f.adapter,
        asked: std::sync::atomic::AtomicUsize::new(0),
    };

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            req,
            &f.provider,
            &remote,
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    let err = r.expect_err("a replica that vanished must not authorize the unlink");
    assert!(
        matches!(&err, DestroyError::Refused(_)),
        "the closing check is what must refuse: {err}"
    );
    assert!(
        f.path.exists(),
        "and the file is restored from staging, not left in it"
    );
    assert!(
        f.audit.read_all().is_empty(),
        "nothing irreversible happened, so nothing is owed a record"
    );
}

/// A key in another target's namespace does not authorize this destroy.
///
/// The leaf check says the key names these bytes and the target check says the
/// HEAD reaches the custodian's target; neither says the key is under that
/// target's PREFIX. Two logical targets can share one adapter and one bucket,
/// so a request with a custodian and gate for A can name a hash-suffixed key
/// under B's namespace — and under content attestation a same-sized object
/// there satisfies both closing HEADs while A's catalogued replica is gone.
/// The local original is then unlinked with no reachable location recorded for
/// the surviving bytes.
#[tokio::test]
async fn a_remote_key_outside_the_gates_prefix_does_not_authorize_this_destroy() {
    let f = fixture("wrong-prefix", AttestationMode::Content);
    let c = custodian(AttestationMode::Content, f.hash);
    // The same content hash — so the leaf check passes — under another
    // target's prefix, which is exactly the shape a shared bucket produces.
    let elsewhere = shepherd_catalog::identity::content_key("other-target", f.hash);
    let req = LocalDestroyRequest {
        remote_key: &elsewhere,
        ..f.request(&c)
    };

    let err = execute_local_destruction(
        req,
        &f.provider,
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("a key in another namespace must not authorize this destroy");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains("prefix")),
        "the refusal must name what is wrong with the key: {err}"
    );
    assert!(f.path.exists(), "and the file is still there");

    // A NEIGHBOUR SHARING LEADING BYTES is the same hazard, and `starts_with`
    // accepted it: a gate for `tenant/a` took `tenant/archive/...`, which in a
    // shared bucket is another tenant rather than a hypothetical.
    let neighbour = shepherd_catalog::identity::content_key("tenant/archive", f.hash);
    let req = LocalDestroyRequest {
        remote_key: &neighbour,
        ..f.request(&c)
    };
    let err = execute_local_destruction(
        req,
        &f.provider,
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "tenant/a", &f.adapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("a neighbouring namespace must not authorize this destroy");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains("prefix")),
        "the refusal must name what is wrong with the key: {err}"
    );

    // AND THE ACCEPTING DIRECTION, including the trailing slash a config may
    // carry: `derive_object_key` trims it, so both spellings name the same
    // objects and both must be accepted.
    let own = shepherd_catalog::identity::content_key("tenant/a", f.hash);
    for configured in ["tenant/a", "tenant/a/"] {
        let req = LocalDestroyRequest {
            remote_key: &own,
            ..f.request(&c)
        };
        let Some(r) = past_the_open_handle_floor(
            execute_local_destruction(
                req,
                &f.provider,
                &crate::destroy::TargetGate::new(
                    shepherd_core::TargetId::new(1),
                    configured,
                    &f.adapter,
                ),
                &f.audit,
                &f.locks,
                Timestamp::from_nanos(1),
            )
            .await,
        ) else {
            return;
        };
        // It gets past the binding checks; whether it completes depends on the
        // fixture's remote holding that key, which is not what this asserts.
        assert!(
            !matches!(&r, Err(DestroyError::Unbound { detail }) if detail.contains("prefix")),
            "a key under the gate's own prefix (`{configured}`) was refused: {r:?}"
        );
    }
}

/// The root that governs a destruction is the one the CATALOG says owns the
/// file.
///
/// `root` and `path` arrive independently, and §4.9 allows roots to overlap —
/// so pathname containment cannot decide which root owns a file, and nothing
/// checked. A caller could hand root A's file to root B's open snapshot and
/// gate: the floors, the refusal check and the held gate would all run against
/// B's authority while A required resync or was unavailable, and the unlink
/// would proceed on the strength of the wrong root's answer.
#[tokio::test]
async fn a_root_that_does_not_own_the_file_does_not_authorize_this_destroy() {
    let f = fixture("wrong-owner", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let req = LocalDestroyRequest {
        file_root: shepherd_core::RootId::new(9),
        ..f.request(&c)
    };

    let err = execute_local_destruction(
        req,
        &f.provider,
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("a root that does not own the file must not authorize its destruction");
    assert!(
        matches!(&err, DestroyError::Unbound { detail } if detail.contains("under root 9")),
        "the refusal must name the root the catalog records: {err}"
    );
    assert!(f.path.exists(), "and the file is still there");
}

/// A destruction advances its intent through §4.4's lifecycle.
///
/// `IntentState` has a full successor machine and NOTHING called
/// `IntentJournal::transition` — so a destruction that ran start to finish left
/// its row in `prepared`, which `unresolved()` reports as needing recovery.
/// Every successful destroy looked, to recovery, exactly like a crash; and a
/// crash immediately after the unlink was indistinguishable from one before it,
/// which is the distinction §4.10.4's ordering exists to make.
///
/// The ORDER is the property, not the set. `syscall-issued` must precede the
/// unlink so a crash between them is readable, and `audited` must FOLLOW the
/// record — claiming a record that does not exist is the lie that state is
/// supposed to rule out.
#[tokio::test]
async fn a_successful_destroy_walks_its_intent_to_audited() {
    use shepherd_catalog::intent::IntentState;

    let f = fixture("lifecycle", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            f.request(&c),
            &f.provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    r.expect("the destruction succeeds");

    assert_eq!(
        f.journal.seen(),
        vec![
            IntentState::SyscallIssued,
            IntentState::OutcomeKnown,
            IntentState::Audited,
        ],
        "the journal must trace §4.4's sequence, in order — and STOP at \
         `audited`, because this function changes no catalog row and the \
         transaction that records the destruction is the only place the final \
         state can be made atomic with it"
    );
    assert!(!f.path.exists(), "and the file really was destroyed");
}

/// A destruction that refuses before the syscall records nothing.
///
/// The lifecycle is about an operation that STARTED. A refusal at a binding
/// check has issued nothing, so writing `syscall-issued` for it would tell
/// recovery to go looking for an unlink that never happened.
#[tokio::test]
async fn a_destroy_refused_before_the_syscall_advances_nothing() {
    let f = fixture("lifecycle-refused", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let req = LocalDestroyRequest {
        file_root: shepherd_core::RootId::new(9),
        ..f.request(&c)
    };

    execute_local_destruction(
        req,
        &f.provider,
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.audit,
        &f.locks,
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("the request is not bound to its proof");

    assert!(
        f.journal.seen().is_empty(),
        "a refusal before the syscall recorded {:?}",
        f.journal.seen()
    );
}

/// A journal that cannot record `syscall-issued` stops the destruction.
///
/// Everything after the unlink is recorded best-effort, because there is
/// nothing left to abort to. THIS one is different and treating it the same way
/// was the defect: if `syscall-issued` is not durable, a crash leaves deleted
/// bytes behind an intent that still says `prepared`, and recovery cannot tell
/// an unissued operation from a completed one — which is the distinction the
/// state exists to make.
#[tokio::test]
async fn a_destroy_whose_intent_cannot_be_advanced_does_not_unlink() {
    struct Refuses;

    #[async_trait::async_trait]
    impl crate::destroy::IntentGate for Refuses {
        async fn advance(
            &self,
            _id: shepherd_core::IntentId,
            _to: shepherd_catalog::intent::IntentState,
        ) -> Result<()> {
            Err(DestroyError::Storage("the writer is unavailable".into()))
        }
    }

    let f = fixture("journal-down", AttestationMode::Version);
    let c = custodian(AttestationMode::Version, f.hash);
    let req = LocalDestroyRequest {
        intent_gate: &Refuses,
        ..f.request(&c)
    };

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            req,
            &f.provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
            &f.audit,
            &f.locks,
            Timestamp::from_nanos(1),
        )
        .await,
    ) else {
        return;
    };
    r.expect_err("an unrecordable `syscall-issued` must stop the destruction");
    assert!(
        f.path.exists(),
        "the file is restored from staging: this refusal is BEFORE the syscall, \
         so abort-forward-never applies exactly as it does to every other one"
    );
    assert!(
        f.audit.read_all().is_empty(),
        "nothing irreversible happened, so nothing is owed a record"
    );
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
    gate: Gate,
    journal: Journal,
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

    let audit =
        AuditLog::open_with_no_unresolved_intents(&tmp.0.join("audit").join("destroy.jsonl"))
            .unwrap();
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
        gate: Gate::open(),
        journal: Journal::default(),
        provider: DeleteModeProvider::new(),
        tmp,
    }
}

impl Fixture {
    fn request<'a>(&'a self, custodian: &'a Location) -> LocalDestroyRequest<'a> {
        LocalDestroyRequest {
            // Bound to what this request destroys — the token is checked
            // against the request now, so a fixture that fabricates a
            // mismatched one is testing the refusal, not the happy path.
            intent: shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
                IntentId::new(1),
                shepherd_catalog::intent::IntentKind::Local,
                &self.path.to_string_lossy(),
                payload().len() as i64,
                Some(self.hash),
            ),
            path: &self.path,
            root: &self.root,
            expected_hash: self.hash,
            expected_size: payload().len() as u64,
            verified_identity: self.identity,
            fs_id: &self.fs_id,
            age: Duration::from_secs(60 * 60 * 24 * 30),
            floor_policy: policy(),
            // Through the PREDICATE, not fabricated. A fixture that invented a
            // `PermittedCustodian` would be exercising the binding checks and
            // not the precondition — which is exactly the gap that made the
            // bare `&Location` unsafe.
            custodian: crate::revalidate::destroy_permitted(
                std::slice::from_ref(custodian),
                &[],
                Timestamp::from_nanos(1_000),
                std::time::Duration::from_secs(3600),
            )
            .expect("the fixture's custodian must satisfy §4.10.2"),
            remote_key: &self.key,
            root_gate: &self.gate,
            // No rule in these fixtures asks for a specific target, so the
            // policy requires none — and the token is issued against the same
            // empty set, which is what makes them agree.
            policy_required: &[],
            intent_gate: &self.journal,
            // The catalog's answer for this fixture's file, which is the
            // fixture's own root.
            file_root: self.root.id,
        }
    }

    async fn run(&self, custodian: &Location) -> Result<()> {
        execute_local_destruction(
            self.request(custodian),
            &self.provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &self.adapter),
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
    // The catalog believes a different hash than the disk holds. Every PROOF in
    // the request agrees on that belief — the intent, the custody record and
    // the remote key are all for `wrong` — because a request whose own proofs
    // disagree is refused at the door now, and this test is about the other
    // failure: the disk not matching what everything else agrees on. Step 4's
    // re-hash through the staged handle is what has to catch it.
    let wrong = Blake3Hash::from_bytes([0xEE; 32]);
    let mut c = custodian(AttestationMode::Version, wrong);
    c.object_version = Some(shepherd_core::ObjectVersion::new("v9"));
    let wrong_key = shepherd_catalog::identity::content_key("t", wrong);
    let req = LocalDestroyRequest {
        expected_hash: wrong,
        intent: bound_intent(1, &f.path, payload().len() as i64, wrong),
        remote_key: &wrong_key,
        ..f.request(&c)
    };

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            req,
            &f.provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
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
            req,
            &f.provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
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
        intent: bound_intent(1, &nested, payload().len() as i64, f.hash),
        ..f.request(&c)
    };

    let Some(r) = past_the_open_handle_floor(
        execute_local_destruction(
            req,
            &f.provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
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
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(7),
            shepherd_catalog::intent::IntentKind::Remote,
            f.key.as_str(),
            payload().len() as i64,
            Some(f.hash),
        ),
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.key,
        &guard,
        &f.audit,
        &f.journal,
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
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(8),
            shepherd_catalog::intent::IntentKind::Remote,
            f.key.as_str(),
            payload().len() as i64,
            Some(f.hash),
        ),
        &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
        &f.key,
        &guard,
        &f.audit,
        &f.journal,
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
            f.request(&c),
            &provider,
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), "t", &f.adapter),
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

// --- an ambiguous remote DELETE ---------------------------------------------

/// A [`RemoteGate`] whose DELETE errors without saying whether it landed.
///
/// This is the ordinary S3 failure, not an exotic one: the request is sent, the
/// provider applies it, and the acknowledgement is lost to a reset or a
/// gateway timeout. The SDK surfaces an error either way, so the error alone
/// cannot tell a caller which side of the irreversible step it is on.
struct AmbiguousDelete {
    /// What the DELETE actually did, as the provider sees it afterwards.
    gone: bool,
    /// Whether the resolving HEAD can answer at all.
    head_answers: bool,
    /// The version the key answers with when it is still there.
    version: &'static str,
    /// When set, the DELETE is refused rather than being ambiguous — the
    /// provider stating that it did not act.
    precondition_failed: bool,
    heads: std::sync::atomic::AtomicUsize,
}

impl AmbiguousDelete {
    fn new(gone: bool, head_answers: bool) -> Self {
        Self {
            gone,
            head_answers,
            version: "v9",
            precondition_failed: false,
            heads: std::sync::atomic::AtomicUsize::new(0),
        }
    }
    /// Still there, but as a version the guard did not name.
    fn replaced(version: &'static str) -> Self {
        Self {
            version,
            ..Self::new(false, true)
        }
    }
    fn refused() -> Self {
        Self {
            precondition_failed: true,
            ..Self::new(false, true)
        }
    }
    fn heads(&self) -> usize {
        self.heads.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[async_trait::async_trait]
impl RemoteGate for AmbiguousDelete {
    // The target `custodian()` names, so these doubles exercise the path
    // rather than the refusal. The refusal has its own test.
    fn target(&self) -> Option<shepherd_core::TargetId> {
        Some(shepherd_core::TargetId::new(1))
    }

    fn prefix(&self) -> Option<&str> {
        Some("t")
    }

    async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>> {
        self.heads.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if !self.head_answers {
            return Err(DestroyError::Storage("the provider is unreachable".into()));
        }
        Ok((!self.gone).then(|| ObjectMeta {
            key: key.clone(),
            size: 4,
            version: Some(shepherd_core::ObjectVersion::new(self.version)),
            etag: None,
            whole_object_checksum: None,
        }))
    }

    async fn remove_object(&self, key: &ObjectKey, _guard: &VersionGuard) -> Result<()> {
        if self.precondition_failed {
            return Err(DestroyError::PreconditionFailed {
                key: key.as_str().to_owned(),
                detail: "the object is not the version this was authorised against".into(),
            });
        }
        Err(DestroyError::Storage(
            "connection reset after the request was sent".into(),
        ))
    }
}

fn v9() -> VersionGuard {
    VersionGuard::Version(shepherd_core::ObjectVersion::new("v9"))
}

/// The DELETE landed and the acknowledgement did not come back.
///
/// The bytes are gone — irreversibly — so §4.10.4 owes a record. Asserting on
/// the **audit log** rather than on the return value is the point: propagating
/// the provider error was already what this did, and it left no evidence that
/// the object had been destroyed at all.
///
/// Under a CONTENT-ADDRESSED guard, deliberately. The key is the identity
/// there, so an absent key is an absent object and the outcome really is
/// resolved. This used to run under a version guard, where a plain HEAD cannot
/// establish that at all — see
/// `an_absent_key_under_a_version_guard_is_not_a_resolved_delete`.
#[tokio::test]
async fn a_lost_delete_acknowledgement_is_still_audited() {
    let f = fixture("discard-lost-ack", AttestationMode::Version);
    let remote = AmbiguousDelete::new(true, true);

    execute_remote_discard(
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(11),
            shepherd_catalog::intent::IntentKind::Remote,
            f.key.as_str(),
            payload().len() as i64,
            Some(f.hash),
        ),
        &remote,
        &f.key,
        &VersionGuard::ContentAddressed { expect: f.hash },
        &f.audit,
        &f.journal,
        "content",
        Timestamp::from_nanos(5),
    )
    .await
    .expect("the object is gone and the record is written; that is the operation succeeding");

    assert_eq!(remote.heads(), 1, "the outcome must actually be resolved");
    let audit = f.audit.read_all();
    assert_eq!(
        audit.len(),
        1,
        "an object was destroyed with no surviving evidence"
    );
    assert!(audit[0].contains("\"intent\":11"), "{}", audit[0]);
    assert!(
        !f.audit.is_halted(),
        "the outcome was resolved, so there is nothing to halt for"
    );
}

/// The DELETE did not land: the object is still there.
///
/// A pre-operation failure — a refused connection, a 403 — is not ambiguous.
/// Nothing irreversible happened, so nothing is owed a record and halting every
/// other destruction would be an outage manufactured from a retryable error.
#[tokio::test]
async fn a_delete_that_never_landed_is_neither_audited_nor_halting() {
    let f = fixture("discard-no-op", AttestationMode::Version);
    let remote = AmbiguousDelete::new(false, true);

    let err = execute_remote_discard(
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(12),
            shepherd_catalog::intent::IntentKind::Remote,
            f.key.as_str(),
            payload().len() as i64,
            Some(f.hash),
        ),
        &remote,
        &f.key,
        &v9(),
        &f.audit,
        &f.journal,
        "version",
        Timestamp::from_nanos(5),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, DestroyError::Storage(_)), "{err}");
    assert!(
        f.audit.read_all().is_empty(),
        "nothing was destroyed, so nothing may be audited as destroyed"
    );
    assert!(!f.audit.is_halted(), "a retryable failure is not a halt");
}

/// The DELETE is ambiguous and the outcome **cannot** be resolved.
///
/// This is the case the global halt exists for: an irreversible operation may
/// have happened and the record cannot be completed. Letting the next
/// destruction proceed is exactly what §4.10.4 forbids.
#[tokio::test]
async fn an_unresolvable_delete_halts_subsequent_destruction() {
    let f = fixture("discard-unresolved", AttestationMode::Version);
    let remote = AmbiguousDelete::new(true, false);

    let err = execute_remote_discard(
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(13),
            shepherd_catalog::intent::IntentKind::Remote,
            f.key.as_str(),
            payload().len() as i64,
            Some(f.hash),
        ),
        &remote,
        &f.key,
        &v9(),
        &f.audit,
        &f.journal,
        "version",
        Timestamp::from_nanos(5),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, DestroyError::Storage(_)), "{err}");
    assert!(
        f.audit.is_halted(),
        "destruction may not continue past an unresolved irreversible step"
    );
    assert!(
        f.audit.check_not_halted().is_err(),
        "and the halt has to be the one every other destruction reads"
    );
}

/// A HEAD that answers with a DIFFERENT version settles nothing.
///
/// `head` reports the CURRENT version only. Under `VersionGuard::Version` a
/// mismatch is consistent with two opposite histories: the guarded version was
/// deleted and an older one is now current, or another writer replaced the
/// object before the DELETE was ever applied. Reading it as "the delete landed"
/// forges a record for a destruction that may not have happened; reading it as
/// "it did not" drops an irreversible one. Neither is available, so this is the
/// halt.
#[tokio::test]
async fn a_head_that_answers_with_another_version_is_not_a_resolution() {
    let f = fixture("discard-replaced", AttestationMode::Version);
    let remote = AmbiguousDelete::replaced("v10");

    let err = execute_remote_discard(
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(14),
            shepherd_catalog::intent::IntentKind::Remote,
            f.key.as_str(),
            payload().len() as i64,
            Some(f.hash),
        ),
        &remote,
        &f.key,
        &v9(),
        &f.audit,
        &f.journal,
        "version",
        Timestamp::from_nanos(5),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, DestroyError::Storage(_)), "{err}");
    assert!(
        f.audit.read_all().is_empty(),
        "a destruction that cannot be established must not be recorded as one"
    );
    assert!(
        f.audit.is_halted(),
        "and an unresolved irreversible step halts subsequent destruction"
    );
}

/// A refused precondition is not ambiguous, and must not halt.
///
/// The provider refusing on the guard is the provider stating that it did not
/// act — the one thing a lost acknowledgement can never state. Flattened into
/// the generic storage error it became indistinguishable from ambiguity, and
/// the resolver would then either forge a record or halt every other
/// destruction because a guard did its job.
#[tokio::test]
async fn a_refused_precondition_neither_records_nor_halts() {
    let f = fixture("discard-precondition", AttestationMode::Version);
    let remote = AmbiguousDelete::refused();

    let err = execute_remote_discard(
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(15),
            shepherd_catalog::intent::IntentKind::Remote,
            f.key.as_str(),
            payload().len() as i64,
            Some(f.hash),
        ),
        &remote,
        &f.key,
        &v9(),
        &f.audit,
        &f.journal,
        "version",
        Timestamp::from_nanos(5),
    )
    .await
    .unwrap_err();

    assert!(
        matches!(err, DestroyError::PreconditionFailed { .. }),
        "the refusal must reach the caller as itself: {err}"
    );
    assert_eq!(
        remote.heads(),
        0,
        "there is nothing to resolve, so nothing may be asked"
    );
    assert!(f.audit.read_all().is_empty());
    assert!(!f.audit.is_halted(), "a working guard is not an incident");
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
    /// Parks the FIRST closing HEAD only.
    ///
    /// There are two now: `destroy_staged` asks one, and the unlink is
    /// preceded by another after the audit permit and the root hold, because
    /// both of those waits are unbounded and a replica can vanish inside them.
    /// Parking the second as well would park a destroy that has already been
    /// released, which is not the interleaving this fixture is describing.
    parked: std::sync::atomic::AtomicBool,
}

#[async_trait::async_trait]
impl RemoteGate for ParkedRemote<'_> {
    // The target `custodian()` names, so these doubles exercise the path
    // rather than the refusal. The refusal has its own test.
    fn target(&self) -> Option<shepherd_core::TargetId> {
        Some(shepherd_core::TargetId::new(1))
    }

    fn prefix(&self) -> Option<&str> {
        Some("t")
    }

    async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>> {
        if !self.parked.swap(true, std::sync::atomic::Ordering::SeqCst) {
            self.entered.notify_one();
            self.release.notified().await;
        }
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

    // Every append now fails: the same mechanism
    // `audit::tests::a_failed_write_halts_destruction` uses. `AuditLog::open`
    // creates the file and fsyncs its parent, so the file is REPLACED by a
    // directory here rather than the name being left free — an audit log that
    // becomes unwritable after the daemon started, which is the case that can
    // still surprise an admitted destruction.
    let log_path = f.tmp.0.join("audit").join("destroy.jsonl");
    std::fs::remove_file(&log_path).expect("the log was created at open");
    std::fs::create_dir(&log_path).expect("block the audit log with a directory at its path");

    let req2 = LocalDestroyRequest {
        path: &second,
        verified_identity: second_id,
        fs_id: &second_fs_id,
        intent: bound_intent(2, &second, payload().len() as i64, f.hash),
        ..f.request(&c)
    };
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let parked = ParkedRemote {
        inner: &f.adapter,
        entered: entered.clone(),
        release: release.clone(),
        parked: std::sync::atomic::AtomicBool::new(false),
    };
    let second_destroy = execute_local_destruction(
        req2,
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
        intent: bound_intent(2, &second, payload().len() as i64, f.hash),
        ..f.request(&c)
    };
    let entered = std::sync::Arc::new(tokio::sync::Notify::new());
    let release = std::sync::Arc::new(tokio::sync::Notify::new());
    let parked = ParkedRemote {
        inner: &f.adapter,
        entered: entered.clone(),
        release: release.clone(),
        parked: std::sync::atomic::AtomicBool::new(false),
    };
    let second_destroy = execute_local_destruction(
        req2,
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

/// An absent key under a VERSION guard is not a resolved delete.
///
/// `head_meta` answers about the CURRENT version, and a delete marker — one
/// that was already there, or one another writer added — makes it answer
/// "absent" while the guarded version is still present as a noncurrent one. So
/// `Ok(None)` is equally consistent with the ambiguous DELETE never having
/// reached the provider, and appending a destruction record for it would
/// describe an object that still exists. That is the record §4.10.4's recovery
/// trusts.
///
/// The version-mismatch arm already reasoned this way; this is the same
/// argument reached from the other direction, and the arm that had it backwards.
#[tokio::test]
async fn an_absent_key_under_a_version_guard_is_not_a_resolved_delete() {
    let f = fixture("discard-version-absent", AttestationMode::Version);
    let remote = AmbiguousDelete::new(true, true);

    let err = execute_remote_discard(
        shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
            IntentId::new(12),
            shepherd_catalog::intent::IntentKind::Remote,
            f.key.as_str(),
            payload().len() as i64,
            Some(f.hash),
        ),
        &remote,
        &f.key,
        &v9(),
        &f.audit,
        &f.journal,
        "version",
        Timestamp::from_nanos(5),
    )
    .await
    .expect_err("an unresolvable outcome must not be reported as a destruction");
    assert!(
        matches!(&err, DestroyError::Storage(d) if d.contains("delete marker")),
        "the failure must say why the answer settles nothing: {err}"
    );
    assert!(
        f.audit.is_halted(),
        "an irreversible step may have happened and its record cannot be completed; that is \
         what the global halt is for"
    );
    assert!(
        f.audit.read_all().is_empty(),
        "and no destruction record is written for something that may still exist"
    );
}
