//! **AC-2's cross-process leg**, against a real SQLite file.
//!
//! The headline is `a_killed_upload_resumes_from_disk_without_resending_verified_parts`.
//! It is the test that could not exist while `MemStore` was the only
//! implementation: an in-memory store has no process to survive, so a
//! restart-resume assertion against it passes without exercising the property —
//! the same shape as a test filter matching zero tests and exiting 0.
//!
//! Every "process" here is a scope that opens its own `CatalogSessionStore`
//! against the same file and drops it. Nothing is carried across in memory, so
//! whatever the second scope sees came off disk.

use super::*;
use crate::plan::{TierItem, derive_object_key};
use crate::serialize::FileLocks;
use crate::upload::{hash_file, upload_item};
use shepherd_catalog::Catalog;
use shepherd_storage::multipart::PartAction;
use shepherd_storage::testing::MemAdapter;

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        p.push(format!(
            "shepherd-session-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("temp dir");
        Self(p)
    }
    fn join(&self, n: &str) -> std::path::PathBuf {
        self.0.join(n)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Create the rows `transfer_session`'s foreign keys point at.
///
/// The FKs are real — `job_id`, `target_id` and `file_id` all reference live
/// tables — and a test that invented ids failed with `FOREIGN KEY constraint
/// failed` on the first save. Seeding properly is also the more honest test:
/// a session in production always hangs off a real job, target and file, and a
/// store that only worked against orphan ids would not be exercising that.
fn seed(db: &std::path::Path, job: JobId, target: TargetId, file: FileId) {
    let cat = Catalog::open(db).expect("open for seeding");
    let c = cat.conn();
    c.execute(
        "INSERT INTO scan_root (id, path, stub_mode, created_at)
         VALUES (1, ?1, 'delete', 0)",
        [db.to_string_lossy().to_string()],
    )
    .expect("scan_root");
    c.execute(
        "INSERT INTO file (id, root_id, rel_path, name, size, mtime, ctime,
                           norm_key, first_seen_at, updated_at)
         VALUES (?1, 1, 'a.bin', 'a.bin', 0, 0, 0, 'a.bin', 0, 0)",
        [file.get()],
    )
    .expect("file");
    c.execute(
        "INSERT INTO target (id, name, adapter) VALUES (?1, 'test-target', 's3')",
        [target.get()],
    )
    .expect("target");
    c.execute(
        "INSERT INTO job (id, class, state, created_at, updated_at)
         VALUES (?1, 'upload', 'running', 0, 0)",
        [job.get()],
    )
    .expect("job");
}

/// 3 parts at the `MemAdapter`'s 8-byte minimum.
const BODY: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";

fn item_for(path: &std::path::Path) -> TierItem {
    let hash = hash_file(path).expect("hash");
    TierItem {
        file: FileId::new(1),
        path: path.to_string_lossy().into_owned(),
        size: BODY.len() as u64,
        blake3: hash,
        target: TargetId::new(1),
        remote_key: derive_object_key("shepherd", hash),
    }
}

#[tokio::test]
async fn a_session_round_trips_through_a_real_file() {
    let dir = TempDir::new("roundtrip");
    let db = dir.join("catalog.db");
    let src = dir.join("a.bin");
    std::fs::write(&src, BODY).expect("write source");
    let item = item_for(&src);

    let job = JobId::new(42);
    seed(&db, job, item.target, item.file);
    let saved = {
        let store = CatalogSessionStore::open(&db).expect("open");
        let adapter = MemAdapter::content_addressed();
        let mut s = TransferSession::plan(
            job,
            item.target,
            item.remote_key.clone(),
            SourceIdentity {
                file_id: item.file,
                rel_path: item.path.clone(),
                size: item.size,
                mtime: Timestamp::from_nanos(7),
                fs_id: FsId::new("vol-1:ino-9"),
                blake3: item.blake3,
            },
            &adapter,
            16,
        )
        .expect("plan");
        s.state = TransferState::Uploading;
        s.upload_id = Some(OpaqueToken::new("upload-abc"));
        s.parts.push(PartCheckpoint {
            part_no: 1,
            offset: 0,
            len: 16,
            local_blake3: Blake3Hash::from_bytes([9u8; 32]),
            etag: Some(OpaqueToken::new("etag-1")),
        });
        store.save(&s).await.expect("save");
        s
    }; // <- the store, and its connection, are gone

    let store = CatalogSessionStore::open(&db).expect("reopen");
    let back = store
        .load(job)
        .await
        .expect("load")
        .expect("a row survived");

    assert_eq!(back.state, TransferState::Uploading);
    assert_eq!(back.upload_id, saved.upload_id);
    assert_eq!(back.source.blake3, saved.source.blake3);
    assert_eq!(back.source.size, saved.source.size);
    assert_eq!(back.plan.part_size, saved.plan.part_size);
    assert_eq!(back.plan.part_count, saved.plan.part_count);
    assert_eq!(back.parts.len(), 1);
    assert_eq!(back.parts[0].etag, saved.parts[0].etag);
    assert_eq!(back.parts[0].len, 16);
    // Derived from the immutable part size rather than stored.
    assert_eq!(back.parts[0].offset, 0);
}

#[tokio::test]
async fn an_absent_session_loads_as_none_rather_than_an_error() {
    let dir = TempDir::new("absent");
    let store = CatalogSessionStore::open(&dir.join("catalog.db")).expect("open");
    assert_eq!(store.load(JobId::new(1)).await.expect("load"), None);
}

/// **AC-2's cross-process leg.** This is the test `MemStore` could not support.
#[tokio::test]
async fn a_killed_upload_resumes_from_disk_without_resending_verified_parts() {
    let dir = TempDir::new("ac2");
    let db = dir.join("catalog.db");
    let src = dir.join("big.bin");
    std::fs::write(&src, BODY).expect("write source");
    let item = item_for(&src);
    let job = JobId::new(7);
    seed(&db, job, item.target, item.file);

    // --- process 1: upload, then die between two parts -------------------
    let (acked_before, part_count) = {
        let store = CatalogSessionStore::open(&db).expect("open");
        let adapter = MemAdapter::content_addressed();
        let locks = FileLocks::new();

        // Kill the store's durability after the second part checkpoint, the way
        // a process death would: the provider keeps what it received, the
        // database keeps only what was committed before the kill.
        let err = {
            // Saves in order: 1 initial plan, 2 Initiating, 3 Uploading,
            // then one per part checkpoint. Dying at 6 leaves parts 1 and 2
            // durable and part 3 uploaded-but-uncheckpointed — the window that
            // makes the resume decision interesting rather than trivial.
            let killer = KillAfter::new(&store, 6);
            upload_item(
                job,
                &item,
                &adapter,
                &killer,
                &locks,
                FsId::new("vol-1:ino-9"),
                // 16-byte parts over a 51-byte body: 4 parts, so "skip the
                // verified ones" is a claim with something to measure.
                16,
            )
            .await
            .expect_err("the process must die mid-upload")
        };
        assert!(err.is_retryable(), "a lost write is transient: {err}");

        let s = store
            .load(job)
            .await
            .expect("load")
            .expect("something was durable before the kill");
        let acked = s.parts.iter().filter(|p| p.is_acknowledged()).count();
        assert!(
            acked > 0,
            "precondition: at least one part must have been durably acknowledged"
        );
        assert!(
            acked < s.plan.part_count as usize,
            "precondition: the upload must NOT have finished"
        );
        (acked, s.plan.part_count)
    }; // <- process 1 is gone: store, connection, adapter, locks all dropped

    // --- process 2: reopen ONLY the database and resume ------------------
    let store = CatalogSessionStore::open(&db).expect("reopen");
    let resumed = store
        .load(job)
        .await
        .expect("load")
        .expect("the session must survive the process");

    assert_eq!(
        resumed.parts.iter().filter(|p| p.is_acknowledged()).count(),
        acked_before,
        "the acknowledged parts must come back off disk, not be recomputed"
    );
    assert_eq!(resumed.plan.part_count, part_count);
    assert_eq!(resumed.state, TransferState::Uploading);

    // And the resume decision really skips them. This is the property AC-2
    // measures — asserted as a QUANTITY, not as "a resume code path ran".
    let remote: Vec<_> = resumed
        .parts
        .iter()
        .filter_map(|p| {
            p.etag
                .as_ref()
                .map(|e| shepherd_storage::adapter::PartReceipt {
                    part_no: p.part_no,
                    size: p.len,
                    etag: e.clone(),
                    checksum: None,
                })
        })
        .collect();
    let recon =
        shepherd_storage::multipart::reconcile_parts(&resumed.plan, &resumed.parts, &remote);
    assert_eq!(
        recon
            .actions
            .iter()
            .filter(|a| **a == PartAction::Skip)
            .count(),
        acked_before,
        "every durably acknowledged part must be skipped on resume"
    );
    assert!(
        recon.bytes_skipped > 0,
        "AC-2 measures bytes NOT re-sent; got {}",
        recon.bytes_skipped
    );
}

/// A store wrapper that stops persisting after `n` saves, modelling a process
/// death: the provider keeps what it received, the database keeps only what was
/// committed before the kill.
#[derive(Debug)]
struct KillAfter<'a> {
    inner: &'a CatalogSessionStore,
    saves: Mutex<usize>,
    die_at: usize,
}

impl<'a> KillAfter<'a> {
    fn new(inner: &'a CatalogSessionStore, die_at: usize) -> Self {
        Self {
            inner,
            saves: Mutex::new(0),
            die_at,
        }
    }
}

#[async_trait::async_trait]
impl TransferSessionStore for KillAfter<'_> {
    async fn save(&self, session: &TransferSession) -> StorageResult<()> {
        {
            let mut n = self.saves.lock().unwrap_or_else(|e| e.into_inner());
            *n += 1;
            if *n >= self.die_at {
                return Err(StorageError::Transient {
                    op: "session save".into(),
                    detail: "injected process death".into(),
                });
            }
        }
        self.inner.save(session).await
    }

    async fn load(&self, job_id: JobId) -> StorageResult<Option<TransferSession>> {
        self.inner.load(job_id).await
    }
}
