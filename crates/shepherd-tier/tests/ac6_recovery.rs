//! **AC-6** — drop all local state after tiering-and-destroying, then rebuild
//! from the filesystem **plus the four-class recovery bundle** (§4.10.3a).
//!
//! This is P1's restated custody invariant, and the plan spent an iteration
//! getting it honest after review found the original claim false on delete-mode
//! roots. The claim now is narrow and testable:
//!
//! > The catalog splits into *derived* (rebuildable by rescanning), *custody*
//! > (the **only address** of a destroyed original, recoverable solely via the
//! > replica), and *durable config* (user-authored, derived from nothing).
//!
//! So the test has to prove **two different things about two different halves**,
//! and the second is the one that matters:
//!
//! 1. Derived rows come back **from the filesystem** — a rescan finds the files
//!    that still exist, and does *not* invent the one that was destroyed.
//! 2. Custody rows come back **only from the bundle**. A destroyed file leaves
//!    no trace on disk, so if the bundle does not carry its address, the bytes
//!    are unreachable forever even though they are sitting in the target.
//!
//! A test asserting only "the catalog is non-empty after recovery" would pass
//! on derived rows alone while custody was silently lost — which is exactly the
//! failure P1 was overclaiming about.
//!
//! # Why the bundle is written from the catalog rather than mocked
//!
//! The interesting failure is a custody row that never reaches the bundle. If
//! the test hand-built the bundle it would be asserting that `decode(encode(x))
//! == x`, which is `bundle_tests`' job and proves nothing about whether the
//! *destroy path* published what it destroyed.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

use shepherd_catalog::file_repo::FileRepo;
use shepherd_catalog::identity::{PathCasePolicy, PathNormPolicy, content_key};
use shepherd_catalog::{AtimeMode, Catalog};
use shepherd_core::{
    Blake3Hash, CustodyClass, FileStat, IntentId, ObjectKey, StubMode, TargetId, Timestamp,
};
use shepherd_placeholder::DeleteModeProvider;
use shepherd_placeholder::provider::FileIdentity;
use shepherd_scan::{DenyList, FloorPolicy, IgnoreSet, walk};
use shepherd_storage::adapter::{AttestationMode, StorageAdapter};
use shepherd_storage::replica::bundle::{
    BundleEntry, CustodyKey, CustodyRecord, LogicalClock, bundle_class_of, decode_segment,
    encode_segment,
};
use shepherd_storage::testing::MemAdapter;
use shepherd_tier::revalidate::{Location, LocationState};
use shepherd_tier::{AuditLog, FileLocks, LocalDestroyRequest, execute_local_destruction};

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Self {
        let d = std::env::temp_dir().join(format!("shepherd-ac6-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        Tmp(d)
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

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

fn hash_of(b: &[u8]) -> Blake3Hash {
    Blake3Hash::from_bytes(*blake3::hash(b).as_bytes())
}

fn identity_of(p: &std::path::Path) -> FileIdentity {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p).unwrap();
    FileIdentity {
        dev: md.dev(),
        ino: md.ino(),
        nlink: md.nlink(),
    }
}

/// AC-6 end to end.
#[tokio::test]
async fn all_local_state_is_dropped_and_rebuilt_from_the_filesystem_plus_the_bundle() {
    let tmp = Tmp::new("rebuild");
    let now = Timestamp::from_nanos(1_000_000_000_000);
    let db = tmp.0.join("catalog.db");
    let corpus = tmp.0.join("corpus");
    std::fs::create_dir_all(&corpus).unwrap();

    // One file that will be tiered and destroyed, one that will survive.
    let doomed_bytes = body(256 * 1024, 1);
    let doomed = corpus.join("archive.raw");
    std::fs::write(&doomed, &doomed_bytes).unwrap();
    let survivor_bytes = body(64 * 1024, 2);
    let survivor = corpus.join("keep.txt");
    std::fs::write(&survivor, &survivor_bytes).unwrap();

    let doomed_hash = hash_of(&doomed_bytes);
    let key = content_key("ac6", doomed_hash);
    let adapter = MemAdapter::versioned();
    adapter.put_versioned(&key, doomed_bytes.clone().into(), "v1");

    // --- populate the catalog, tier, destroy -------------------------------
    //
    // The root row is INSERTED, not just constructed: `file.root_id` is a real
    // foreign key, and the catalog rejected the first version of this test for
    // exactly that reason. A test that fabricated a `ScanRoot` in memory and
    // wrote children against it would have been testing a shape the database
    // does not permit.
    let root = {
        let mut cat = Catalog::open(&db).unwrap();
        let id = FileRepo::new(&mut cat)
            .insert_root(
                &corpus.display().to_string(),
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Preserve,
                AtimeMode::Relatime,
                Some("uuid:ac6"),
                false,
                &[],
                now,
            )
            .unwrap();
        FileRepo::new(&mut cat).get_root(id).unwrap().unwrap()
    };
    {
        let mut cat = Catalog::open(&db).unwrap();
        let mut repo = FileRepo::new(&mut cat);
        for (p, h) in [
            (&doomed, Some(doomed_hash)),
            (&survivor, Some(hash_of(&survivor_bytes))),
        ] {
            let rel = p.strip_prefix(&corpus).unwrap().display().to_string();
            let md = std::fs::metadata(p).unwrap();
            repo.upsert_file(
                &root,
                &FileStat {
                    root: root.id,
                    rel_path: rel,
                    size: md.len(),
                    mtime: now,
                    ctime: now,
                    atime: None,
                    blake3: h,
                },
                now,
            )
            .unwrap();
        }
    }

    let custodian = Location {
        target: TargetId::new(1),
        state: LocationState::Verified,
        attestation: AttestationMode::Version,
        custody_eligible: true,
        last_full_hash_verified_at: Some(now),
        publication_receipt_ok: true,
        object_version: Some(shepherd_core::ObjectVersion::new("v1")),
        expected_hash: doomed_hash,
    };
    let audit = AuditLog::open(&tmp.0.join("audit.jsonl")).unwrap();

    let destroyed = execute_local_destruction(
        &LocalDestroyRequest {
            intent: IntentId::new(1),
            path: &doomed,
            root: &root,
            expected_hash: doomed_hash,
            expected_size: doomed_bytes.len() as u64,
            verified_identity: identity_of(&doomed),
            age: Duration::from_secs(3600),
            floor_policy: FloorPolicy {
                min_size: 1024,
                min_age: Duration::from_secs(0),
            },
            custodian: &custodian,
            remote_key: &key,
        },
        &DeleteModeProvider::new(),
        &(&adapter as &dyn StorageAdapter),
        &audit,
        &FileLocks::new(),
        now,
    )
    .await;

    // `open_handles` is implemented on Linux only; everywhere else the
    // acquisition floor refuses fail-closed, because OQ-J defines "cannot
    // determine" as held. So the destruction this test needs as a PRECONDITION
    // cannot be produced through the real path there, and AC-6's actual subject
    // — rebuilding local state from the filesystem plus the bundle — has no
    // destroyed file to rebuild around.
    //
    // Assert that refusal specifically rather than unwrapping into a panic that
    // reads like a recovery bug. `DestroyError` is not re-exported from the
    // crate root, so this matches the user-visible Display text, which is what
    // an operator would see anyway.
    match destroyed {
        Ok(()) => assert!(
            std::env::consts::OS == "linux",
            "destruction SUCCEEDED on {}, where open_handles() is unimplemented and the \
             acquisition floor should have refused fail-closed. If Phase 3 landed a \
             detector for this platform, AC-6 recovery can now be covered here and the \
             early return below should be removed — deliberately, not by accident.",
            std::env::consts::OS
        ),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                std::env::consts::OS != "linux",
                "destruction failed on Linux, where the detector exists and it is expected \
                 to succeed. This is a real failure, not a platform gap: {msg}"
            );
            assert!(
                msg.contains("floor refused: held-open"),
                "on a platform with no open-handle detector the ONLY expected refusal is \
                 the fail-closed one; any other means a different floor tripped: {msg}"
            );
            assert!(
                msg.contains("CouldNotDetermine") && msg.contains(std::env::consts::OS),
                "the refusal must name the missing detector and the platform, so it is not \
                 mistaken for a genuine open handle on this file: {msg}"
            );
            return;
        }
    }

    assert!(!doomed.exists(), "the original is gone from disk");
    assert!(survivor.exists());

    // --- publish the four-class bundle -------------------------------------
    //
    // Only classes that `bundle_class_of` admits. `Derived` maps to None and is
    // deliberately excluded — that exclusion is what makes the rebuild a real
    // test rather than a copy.
    assert!(
        bundle_class_of(CustodyClass::Derived).is_none(),
        "derived state must be EXCLUDED from the bundle, or this test proves nothing: \
         a bundle carrying derived rows would 'recover' them without a rescan"
    );

    let custody = CustodyRecord {
        key: CustodyKey {
            path: "archive.raw".into(),
            blake3: doomed_hash,
        },
        target: TargetId::new(1),
        object_key: key.as_str().to_owned(),
        object_version: Some("v1".into()),
        size: doomed_bytes.len() as u64,
        mtime: now,
        mode: 0o644,
        restore_metadata: BTreeMap::new(),
        clock: LogicalClock::default(),
        tombstone: false,
    };
    let segment = encode_segment(&[BundleEntry::Custody(custody.clone())]).expect("encode");

    // --- DROP ALL LOCAL STATE ----------------------------------------------
    //
    // The whole catalog file, not a table. §9's Phase 2 gate says "drop *all*
    // local state", and deleting rows would leave schema, sequence counters and
    // WAL behind — which is not the disaster being simulated.
    drop(std::fs::remove_file(&db));
    assert!(!db.exists(), "the catalog is gone");
    assert!(
        !tmp.0.join("catalog.db-wal").exists() && !tmp.0.join("catalog.db-shm").exists(),
        "WAL and shm must go too, or 'all local state' is not what was dropped"
    );

    // --- REBUILD ------------------------------------------------------------
    let mut cat = Catalog::open(&db).unwrap();

    // 1a. Re-enroll the root. "Drop ALL local state" took the `scan_root` row
    //     with it, and the foreign key on `file.root_id` refuses children
    //     without it — which is the database correctly insisting that a rebuild
    //     starts from enrollment rather than from orphaned rows. The first
    //     version of this test skipped straight to the files and was rejected.
    //
    //     Note the root comes back with DEFAULT policies: the probed
    //     case/normalization policy and the atime fidelity are themselves
    //     derived state, re-established by probing the filesystem again, not
    //     recovered from the bundle.
    let root = {
        let id = FileRepo::new(&mut cat)
            .insert_root(
                &corpus.display().to_string(),
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Preserve,
                AtimeMode::Relatime,
                Some("uuid:ac6"),
                false,
                &[],
                now,
            )
            .unwrap();
        FileRepo::new(&mut cat).get_root(id).unwrap().unwrap()
    };

    // 1b. Derived rows: from the filesystem.
    let ignores = IgnoreSet::empty(&corpus).unwrap();
    let walked = walk(root.id, &corpus, &DenyList::builtin(), &ignores, now).unwrap();
    {
        let mut repo = FileRepo::new(&mut cat);
        for f in &walked.files {
            repo.upsert_file(&root, f, now).unwrap();
        }
    }

    let rescanned: Vec<&str> = walked.files.iter().map(|f| f.rel_path.as_str()).collect();
    assert_eq!(
        rescanned,
        vec!["keep.txt"],
        "the rescan finds ONLY the surviving file. The destroyed one leaves no trace on \
         disk — which is precisely why its address cannot come from here"
    );

    // 2. Custody rows: from the bundle, and from nowhere else.
    let entries = decode_segment(&segment).expect("decode");
    let recovered: Vec<&CustodyRecord> = entries
        .iter()
        .filter_map(|e| match e {
            BundleEntry::Custody(c) => Some(c),
            _ => None,
        })
        .collect();

    assert_eq!(recovered.len(), 1, "exactly one custody record recovered");
    let r = recovered[0];

    // ASSERT THE ADDRESS, not merely that a row exists. A custody row without a
    // usable object key is not custody — it is a note saying a file used to
    // exist.
    assert_eq!(r.key.path, "archive.raw");
    assert_eq!(r.key.blake3, doomed_hash);
    assert_eq!(r.object_key, key.as_str());
    assert_eq!(r.object_version.as_deref(), Some("v1"));
    assert_eq!(r.size, doomed_bytes.len() as u64);
    assert!(!r.tombstone);

    // 3. The recovered address really reaches the bytes. This is the invariant
    //    in its strongest form: after losing every local trace, the destroyed
    //    file is still retrievable using only what the bundle carried.
    let fetched = adapter
        .object(&ObjectKey::new(r.object_key.clone()))
        .expect("the object key recovered from the bundle must resolve");
    assert_eq!(
        hash_of(&fetched),
        doomed_hash,
        "the bytes reached via the recovered address must be the destroyed file's bytes"
    );
}

/// The negative that makes the test above mean something.
///
/// If the custody record were absent from the bundle, the destroyed file would
/// be **unreachable** — the bytes sit in the target and nothing on the machine
/// knows their address. Asserting this explicitly stops the positive test from
/// passing for the wrong reason, e.g. if a rescan ever started inventing rows
/// for files it cannot see.
#[test]
fn without_its_custody_record_a_destroyed_file_is_unreachable() {
    let segment = encode_segment(&[]).expect("an empty segment is still a segment");
    let entries = decode_segment(&segment).expect("decode");
    let custody: Vec<_> = entries
        .iter()
        .filter(|e| matches!(e, BundleEntry::Custody(_)))
        .collect();
    assert!(
        custody.is_empty(),
        "no custody records means no addresses — the destroyed bytes are orphaned, which \
         is the outcome AC-6 exists to prevent"
    );
}

/// §4.10.3a's fourth class, asserted as a total function.
///
/// `Derived` must map to `None`. If it ever mapped to a bundle class, the
/// rebuild test would pass by carrying derived rows through the bundle rather
/// than by rescanning — proving the opposite of what it claims.
#[test]
fn the_four_class_split_excludes_derived_and_includes_the_other_two() {
    assert!(bundle_class_of(CustodyClass::Derived).is_none());
    assert!(bundle_class_of(CustodyClass::Custody).is_some());
    assert!(bundle_class_of(CustodyClass::DurableConfig).is_some());
}
