//! Upload tests. The state machine itself is `shepherd-storage`'s to test; what
//! is checked here is the two things this module adds — reading a real file,
//! and holding the remote-key lock.

use super::*;
use crate::plan::derive_object_key;
use shepherd_core::{FileId, ObjectKey, TargetId};
use shepherd_storage::testing::{MemAdapter, MemStore};

struct TempFile(PathBuf);

impl TempFile {
    fn new(tag: &str, bytes: &[u8]) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!("shepherd-upload-{tag}-{}", std::process::id()));
        std::fs::write(&p, bytes).expect("write temp");
        Self(p)
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.0);
    }
}

const BODY: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz-tiered-content";

fn item(path: &str, hash: Blake3Hash) -> TierItem {
    TierItem {
        file: FileId::new(1),
        path: path.into(),
        size: BODY.len() as u64,
        blake3: hash,
        target: TargetId::new(1),
        remote_key: derive_object_key("shepherd", hash),
    }
}

#[test]
fn hashing_a_file_streams_and_matches_an_in_memory_hash() {
    let f = TempFile::new("hash", BODY);
    let got = hash_file(&f.0).expect("hash");
    assert_eq!(got, Blake3Hash::from_bytes(*blake3::hash(BODY).as_bytes()));
}

#[tokio::test]
async fn the_file_source_reads_the_ranges_the_driver_asks_for() {
    // The driver re-reads arbitrary parts on resume, in any order.
    let f = TempFile::new("ranges", BODY);
    let src = FileSource::new(&f.0, FsId::new("vol:1"));

    let tail = src
        .read_range(ByteRange { offset: 10, len: 5 })
        .await
        .expect("read");
    assert_eq!(&tail[..], &BODY[10..15]);

    // Out of order, and the whole thing.
    let head = src
        .read_range(ByteRange { offset: 0, len: 4 })
        .await
        .expect("read");
    assert_eq!(&head[..], &BODY[0..4]);

    let fp = src.fingerprint().await.expect("fingerprint");
    assert_eq!(fp.size, BODY.len() as u64);
}

#[tokio::test]
async fn an_upload_runs_end_to_end_and_the_object_is_byte_identical() {
    let f = TempFile::new("e2e", BODY);
    let hash = hash_file(&f.0).expect("hash");
    let it = item(&f.0.to_string_lossy(), hash);

    let adapter = MemAdapter::content_addressed();
    let store = MemStore::new();
    let locks = FileLocks::new();

    let outcome = upload_item(
        JobId::new(1),
        &it,
        &adapter,
        &store,
        &locks,
        FsId::new("vol:1"),
        shepherd_storage::multipart::DEFAULT_PART_SIZE,
    )
    .await
    .expect("upload");

    assert_eq!(
        outcome.state,
        shepherd_storage::transfer_session::TransferState::Committed
    );
    assert_eq!(
        adapter.object(&it.remote_key).expect("object").as_ref(),
        BODY
    );
}

/// The plan-to-upload window, partially closed.
#[tokio::test]
async fn a_file_that_changed_size_since_planning_is_refused_rather_than_uploaded() {
    // The driver's PM-1 guard starts at session creation, so an edit between
    // planning and here would otherwise go unnoticed until `Verifying` — after
    // the whole object was uploaded, and leaving residue at a content-addressed
    // key whose name does not describe its bytes.
    let f = TempFile::new("grew", BODY);
    let hash = hash_file(&f.0).expect("hash");
    let mut it = item(&f.0.to_string_lossy(), hash);
    it.size = BODY.len() as u64 + 100; // planned against a larger file

    let adapter = MemAdapter::content_addressed();
    let store = MemStore::new();
    let locks = FileLocks::new();

    let err = upload_item(
        JobId::new(2),
        &it,
        &adapter,
        &store,
        &locks,
        FsId::new("vol:1"),
        shepherd_storage::multipart::DEFAULT_PART_SIZE,
    )
    .await
    .expect_err("a changed source must be re-planned, not uploaded");
    assert!(
        err.to_string().contains("re-plan"),
        "the error must say what to do about it: {err}"
    );
    assert!(
        adapter.object(&it.remote_key).is_none(),
        "nothing may reach the target"
    );
}

/// The reason this module holds `acquire_key` and not only `acquire`.
#[tokio::test]
async fn the_remote_key_lock_is_held_because_dedup_makes_the_mapping_many_to_one() {
    // Two DIFFERENT files with IDENTICAL content share one remote key — that is
    // AC-47's dedup. An `fs_id` lock would not serialize them, and the driver's
    // window-1 recovery aborts every live session at the key it is working on.
    let hash = Blake3Hash::from_bytes(*blake3::hash(BODY).as_bytes());
    let a = item("/root/a.raw", hash);
    let mut b = item("/root/copies/a.raw", hash);
    b.file = FileId::new(2);

    assert_eq!(
        a.remote_key, b.remote_key,
        "precondition: dedup gives these one key"
    );

    let locks = FileLocks::new();
    let held = locks.acquire_key(&a.remote_key).await;
    // A second acquisition of the SAME key must block while the first is held.
    let second = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        locks.acquire_key(&b.remote_key),
    )
    .await;
    assert!(
        second.is_err(),
        "two uploads at one key must not run concurrently"
    );
    drop(held);

    // A different key is unaffected.
    let other = ObjectKey::new("objects/zz/zz/other");
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(100),
        locks.acquire_key(&other),
    )
    .await
    .expect("a different key must not block");
}

// --- the source's identity is READ, not remembered -------------------------
//
// POSIX-only, and stated rather than papered over. `shepherd_catalog::volume::
// fs_id` is `cfg(unix)` and these tests assert on `st_ino` through
// `MetadataExt`, exactly as `destroy_tests.rs` does. Windows has an equivalent
// (`FILE_ID_INFO`) and nobody has written it, so the pair is gated rather than
// half-ported — see `volume.rs`'s Phase 3 note.
#[cfg(unix)]
mod identity {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    /// Deliberately the SAME LENGTH as `BODY`: the size half of the fingerprint
    /// must not be what notices the swap, or the test proves nothing about the
    /// identity half.
    const IMPOSTOR: &[u8] = b"ZZZZZZZZZZ-different-bytes-same-length-abcdefghijkl";

    fn ino_of(p: &std::path::Path) -> u64 {
        std::fs::metadata(p).expect("stat").ino()
    }

    /// Replace `path` with a DIFFERENT inode holding `bytes`, preserving the
    /// original mtime exactly. This is the case the caller-copied `fs_id` could
    /// not see: size matches, mtime matches, and only the identity differs.
    fn replace_inode_preserving_size_and_mtime(path: &std::path::Path, bytes: &[u8]) {
        let md = std::fs::metadata(path).expect("stat original");
        assert_eq!(
            md.len(),
            bytes.len() as u64,
            "the impostor must be the same size, or size catches it and identity is untested"
        );
        let mtime = md.modified().expect("mtime");

        let tmp = path.with_extension("impostor");
        std::fs::write(&tmp, bytes).expect("write impostor");
        let f = std::fs::File::options()
            .write(true)
            .open(&tmp)
            .expect("open impostor");
        f.set_modified(mtime).expect("set impostor mtime");
        drop(f);
        std::fs::rename(&tmp, path).expect("swap in the impostor");

        let after = std::fs::metadata(path).expect("stat replacement");
        assert_eq!(after.len(), md.len(), "precondition: size is unchanged");
        assert_eq!(
            after.modified().expect("mtime"),
            mtime,
            "precondition: mtime is unchanged"
        );
    }

    /// The defect, at its smallest: a fingerprint that copies the planned
    /// `fs_id` compares a value with itself and can never disagree.
    #[tokio::test]
    async fn a_fresh_fingerprint_reports_the_statted_inode_not_the_planned_one() {
        let f = TempFile::new("fp-identity", BODY);
        let before_ino = ino_of(&f.0);
        let src = FileSource::new(&f.0, FsId::new("vol:1"));
        let planned = src.fingerprint().await.expect("fingerprint");

        replace_inode_preserving_size_and_mtime(&f.0, IMPOSTOR);
        assert_ne!(
            ino_of(&f.0),
            before_ino,
            "precondition: the swap really did change the inode"
        );

        let fresh = src.fingerprint().await.expect("fingerprint");

        // The two cheap halves are blind to this, by construction.
        assert_eq!(fresh.size, planned.size);
        assert_eq!(fresh.mtime, planned.mtime);

        assert_ne!(
            fresh.fs_id, planned.fs_id,
            "the fingerprint must report the identity of the file it just statted; \
             reporting the caller's planned `fs_id` makes the driver's guard compare \
             a value with itself"
        );
    }

    /// The accepting direction. A `fingerprint` that returned something fresh
    /// every call — a counter, a timestamp — would satisfy the test above while
    /// refusing every legitimate resume.
    #[tokio::test]
    async fn an_untouched_file_fingerprints_identically_twice() {
        let f = TempFile::new("fp-stable", BODY);
        let src = FileSource::new(&f.0, FsId::new("vol:1"));
        let a = src.fingerprint().await.expect("fingerprint");
        let b = src.fingerprint().await.expect("fingerprint");
        assert_eq!(a, b, "an unchanged file must fingerprint the same twice");
    }

    /// The consequence, and the reason the fingerprint has to be right: a
    /// resume whose source was swapped must be refused **before** anything is
    /// written, not caught by verification after a wrong object is already
    /// immutable at a content-addressed key.
    #[tokio::test]
    async fn a_resume_whose_source_was_swapped_writes_nothing_to_the_target() {
        let f = TempFile::new("swap-resume", BODY);
        let hash = hash_file(&f.0).expect("hash");
        let it = item(&f.0.to_string_lossy(), hash);

        let adapter = MemAdapter::content_addressed();
        let store = MemStore::new();
        let locks = FileLocks::new();
        let job = JobId::new(77);

        // A session that survived a crash, planned against the file as it was.
        let src = FileSource::new(&f.0, FsId::new("vol:1"));
        let fp = src.fingerprint().await.expect("fingerprint");
        let session = TransferSession::plan(
            job,
            it.target,
            it.remote_key.clone(),
            SourceIdentity {
                file_id: it.file,
                rel_path: it.path.clone(),
                size: fp.size,
                mtime: fp.mtime,
                fs_id: fp.fs_id.clone(),
                blake3: it.blake3,
            },
            &adapter,
            shepherd_storage::multipart::DEFAULT_PART_SIZE,
        )
        .expect("plan");
        store.save(&session).await.expect("save");

        replace_inode_preserving_size_and_mtime(&f.0, IMPOSTOR);

        let err = upload_item(
            job,
            &it,
            &adapter,
            &store,
            &locks,
            FsId::new("vol:1"),
            shepherd_storage::multipart::DEFAULT_PART_SIZE,
        )
        .await
        .expect_err("a source replaced under the session must not be uploaded");

        // The FACT, not the error: an object at a content-addressed key whose
        // name does not describe its bytes is immutable and unreapable (D-10),
        // so "we noticed afterwards" is not the same as "we refused".
        assert!(
            adapter.object(&it.remote_key).is_none(),
            "nothing may reach the target: the wrong bytes would sit forever under a \
             key that names the RIGHT hash, and every retry would rediscover it — got \
             an object anyway, with err {err}"
        );
    }

    /// The accepting twin of the test above: the identical resume, with no
    /// swap, must still complete. A guard that refused every resume would pass
    /// the refusal test and silently break AC-2.
    #[tokio::test]
    async fn an_untouched_resume_still_completes() {
        let f = TempFile::new("no-swap-resume", BODY);
        let hash = hash_file(&f.0).expect("hash");
        let it = item(&f.0.to_string_lossy(), hash);

        let adapter = MemAdapter::content_addressed();
        let store = MemStore::new();
        let locks = FileLocks::new();
        let job = JobId::new(78);

        let src = FileSource::new(&f.0, FsId::new("vol:1"));
        let fp = src.fingerprint().await.expect("fingerprint");
        let session = TransferSession::plan(
            job,
            it.target,
            it.remote_key.clone(),
            SourceIdentity {
                file_id: it.file,
                rel_path: it.path.clone(),
                size: fp.size,
                mtime: fp.mtime,
                fs_id: fp.fs_id.clone(),
                blake3: it.blake3,
            },
            &adapter,
            shepherd_storage::multipart::DEFAULT_PART_SIZE,
        )
        .expect("plan");
        store.save(&session).await.expect("save");

        let outcome = upload_item(
            job,
            &it,
            &adapter,
            &store,
            &locks,
            FsId::new("vol:1"),
            shepherd_storage::multipart::DEFAULT_PART_SIZE,
        )
        .await
        .expect("an untouched source must still resume to completion");

        assert_eq!(
            outcome.state,
            shepherd_storage::transfer_session::TransferState::Committed
        );
        assert_eq!(
            adapter.object(&it.remote_key).expect("object").as_ref(),
            BODY
        );
    }
}
