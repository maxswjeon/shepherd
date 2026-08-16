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
