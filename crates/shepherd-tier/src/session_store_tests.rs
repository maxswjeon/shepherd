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

use std::sync::Arc;
use std::sync::Barrier;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use super::*;
use crate::plan::{TierItem, derive_object_key};
use crate::serialize::FileLocks;
use crate::upload::{hash_file, upload_item};
use shepherd_catalog::Catalog;
use shepherd_catalog::file_repo::FileRepo;
use shepherd_catalog::writer::CatalogActor;
use shepherd_core::{FileStat, RootId};
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
            checksum: None,
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

/// A per-part checkpoint writes ONE row, and the accumulated set survives it.
///
/// `save` replaces the whole part set on every call, and `upload_pending` calls
/// the store once per acknowledged part — so recording N events cost N(N+1)/2
/// part inserts. On the 3,200-part 50 GB upload the plan sizes for, that is
/// about 5.1 million inserts under `synchronous = FULL`, and the checkpointing
/// can cost more than the transfer.
///
/// Both halves are asserted, because the cheap version of this fix is the
/// dangerous one: writing only the changed part is worthless if the earlier
/// receipts stop being readable, since resume reads exactly those to decide
/// what it may skip. So the parts are checkpointed one at a time and the whole
/// set is then loaded back from a REOPENED store.
#[tokio::test]
async fn checkpointing_a_part_writes_only_that_part_and_keeps_the_rest() {
    let dir = TempDir::new("save-part");
    let db = dir.join("catalog.db");
    let src = dir.join("a.bin");
    std::fs::write(&src, BODY).expect("write source");
    let item = item_for(&src);

    let job = JobId::new(77);
    seed(&db, job, item.target, item.file);

    {
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
            4,
        )
        .expect("plan");
        s.state = TransferState::Uploading;
        s.upload_id = Some(OpaqueToken::new("upload-abc"));
        store.save(&s).await.expect("save the planned session");

        // Four parts, checkpointed one at a time exactly as `upload_pending`
        // does — each `save_part` call after the part before it is already
        // durable.
        for part_no in 1..=4u32 {
            s.parts.push(PartCheckpoint {
                part_no,
                offset: u64::from(part_no - 1) * 4,
                len: 4,
                local_blake3: Blake3Hash::from_bytes([part_no as u8; 32]),
                etag: Some(OpaqueToken::new(format!("etag-{part_no}"))),
                checksum: None,
            });
            store.save_part(&s, part_no).await.expect("save_part");

            // The rows written so far are exactly the parts checkpointed so
            // far — no more, and none lost.
            let conn = rusqlite::Connection::open(&db).expect("open for count");
            let rows: i64 = conn
                .query_row("SELECT COUNT(*) FROM transfer_part", [], |r| r.get(0))
                .expect("count");
            assert_eq!(
                rows,
                i64::from(part_no),
                "checkpointing part {part_no} must leave one row per checkpointed part"
            );
        }
    } // <- the store and its connection are gone

    let store = CatalogSessionStore::open(&db).expect("reopen");
    let back = store
        .load(job)
        .await
        .expect("load")
        .expect("a row survived");

    assert_eq!(
        back.parts.len(),
        4,
        "resume reads these to decide what it may skip; a lost receipt re-sends \
         a part, and a wrong one skips a part that never landed"
    );
    for (i, p) in back.parts.iter().enumerate() {
        let n = i as u32 + 1;
        assert_eq!(p.part_no, n);
        assert_eq!(p.etag, Some(OpaqueToken::new(format!("etag-{n}"))));
        assert_eq!(p.local_blake3, Blake3Hash::from_bytes([n as u8; 32]));
        assert_eq!(p.len, 4);
    }

    // And re-checkpointing a part already on disk updates it rather than
    // adding a second row — the PRIMARY KEY the upsert targets.
    let mut again = back;
    again.parts[0].etag = Some(OpaqueToken::new("etag-1-retried"));
    store.save_part(&again, 1).await.expect("re-checkpoint");
    let reloaded = store.load(job).await.expect("load").expect("still there");
    assert_eq!(reloaded.parts.len(), 4);
    assert_eq!(
        reloaded.parts[0].etag,
        Some(OpaqueToken::new("etag-1-retried"))
    );
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

/// Both backends must be interchangeable, and one of them is what the daemon
/// will actually run.
///
/// If `with_writer` ever diverged from the owned path — a different
/// transaction shape, a dropped column — the daemon would persist something
/// subtly different from what every test in this file exercises, and nothing
/// would say so. Both run the same `save_blocking` / `load_blocking`, and this
/// asserts the round trip is identical through either.
#[tokio::test]
async fn the_actor_backend_round_trips_identically_to_the_owned_one() {
    let dir = TempDir::new("actor");
    let db = dir.join("catalog.db");
    let src = dir.join("a.bin");
    std::fs::write(&src, BODY).expect("write source");
    let item = item_for(&src);
    let job = JobId::new(11);
    seed(&db, job, item.target, item.file);

    let session = {
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
        s.upload_id = Some(OpaqueToken::new("upload-actor"));
        s.parts.push(PartCheckpoint {
            part_no: 1,
            offset: 0,
            len: 16,
            local_blake3: Blake3Hash::from_bytes([3u8; 32]),
            etag: Some(OpaqueToken::new("etag-actor")),
            checksum: None,
        });
        s
    };

    // Write through the ACTOR, on its own thread.
    {
        let actor = CatalogActor::start(Catalog::open(&db).expect("open"), None);
        let store = CatalogSessionStore::with_writer(actor.handle());
        store.save(&session).await.expect("save via actor");
    } // actor stopped, thread joined

    // Read back through the OWNED path, from a fresh connection.
    let owned = CatalogSessionStore::open(&db).expect("reopen");
    let back = owned.load(job).await.expect("load").expect("row survived");
    assert_eq!(back.state, session.state);
    assert_eq!(back.upload_id, session.upload_id);
    assert_eq!(back.parts.len(), 1);
    assert_eq!(back.parts[0].etag, session.parts[0].etag);

    // And through the actor again, to prove the read side matches too.
    let actor = CatalogActor::start(Catalog::open(&db).expect("open"), None);
    let via_actor = CatalogSessionStore::with_writer(actor.handle());
    assert_eq!(
        via_actor.load(job).await.expect("load via actor"),
        Some(back),
        "both backends must return the same session"
    );
}

// ---------------------------------------------------------------------------
// Contention: two writers on one WAL file
// ---------------------------------------------------------------------------

/// A session with one acknowledged part, ready to persist.
fn session_for(job: JobId, item: &TierItem, tag: &str) -> TransferSession {
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
    s.upload_id = Some(OpaqueToken::new(format!("upload-{tag}")));
    s.parts.push(PartCheckpoint {
        part_no: 1,
        offset: 0,
        len: 16,
        local_blake3: Blake3Hash::from_bytes([5u8; 32]),
        etag: Some(OpaqueToken::new(format!("etag-{tag}"))),
        checksum: None,
    });
    s
}

/// One row of the shape `shepherd-daemon`'s scan executor writes.
fn scan_stat(i: usize) -> FileStat {
    FileStat {
        root: RootId::new(1),
        rel_path: format!("scan/{i}.bin"),
        size: 1,
        mtime: Timestamp::from_nanos(1),
        ctime: Timestamp::from_nanos(1),
        atime: None,
        blake3: None,
        ino: shepherd_core::InodeSighting::Unknown,
    }
}

/// **The contention measurement, on the failing arrangement.**
///
/// `Backend::Owned` holds its own connection. Put it on the same file as a scan
/// and the two are a second writer on one WAL database — many readers, one
/// WRITER — so this measures what actually happens rather than reasoning about
/// it.
///
/// # Why the overlap is proven rather than hoped for
///
/// `SQLITE_BUSY` **cannot** be produced without a live concurrent holder of the
/// write lock: the error *is* the overlap. A free-running pair of threads would
/// not do — both `save_blocking` and the scan's `upsert_batch` are write-first,
/// and `busy_timeout = 5000` absorbs a 500-row batch commit without complaint,
/// so the contention would show up as invisible latency and an assertion on it
/// would measure nothing. That is instance #5's shape. So the scan side holds
/// its transaction open across a barrier pair, and the session save is issued
/// strictly inside that window with `holding` asserted first.
///
/// # What the elapsed-time assertion is for — the ADR-001 discriminator
///
/// SQLite has two failure modes here and they are **not** interchangeable:
///
/// * plain `SQLITE_BUSY` — the write lock is held by someone else. The busy
///   handler runs, so the call blocks for the whole `busy_timeout` and the
///   operation is retryable. `waited >= TEST_BUSY_TIMEOUT` is what identifies
///   this one.
/// * `SQLITE_BUSY_SNAPSHOT` (extended code 517) — a DEFERRED transaction took a
///   read snapshot and *then* tried to write, and someone committed in between.
///   It returns **immediately**; no `busy_timeout` can cure it, and the only
///   recovery is to roll back and re-run the whole transaction. This is the
///   shape ADR-001 rejected `sqlx` for.
///
/// Asserting that the call waited out the timeout is therefore the empirical
/// proof that our write paths are write-first and have not reintroduced the
/// read-then-write upgrade by hand.
#[test]
fn a_second_connection_writing_during_a_scan_batch_gets_sqlite_busy() {
    let dir = TempDir::new("busy");
    let db = dir.join("catalog.db");
    let src = dir.join("a.bin");
    std::fs::write(&src, BODY).expect("write source");
    let item = item_for(&src);
    let job = JobId::new(21);
    seed(&db, job, item.target, item.file);
    let session = session_for(job, &item, "busy");

    // Opened before the scan side takes the lock: `Catalog::open` applies
    // pragmas, and `journal_mode` is not something to negotiate mid-conflict.
    let mut cat = Catalog::open(&db).expect("session connection");

    /// The production budget is 5000ms (`shepherd_catalog::PRAGMAS`). Lowered
    /// here only to bound the test — the mechanism is what is under
    /// measurement, not the tuning. A test that waited out the real budget
    /// would prove the same thing five seconds more slowly.
    const TEST_BUSY_TIMEOUT: Duration = Duration::from_millis(200);
    cat.conn()
        .pragma_update(None, "busy_timeout", TEST_BUSY_TIMEOUT.as_millis() as i64)
        .expect("lower busy_timeout");

    let gate = Arc::new(Barrier::new(2));
    let release = Arc::new(Barrier::new(2));
    let holding = Arc::new(AtomicBool::new(false));

    let scan = {
        let db = db.clone();
        let gate = Arc::clone(&gate);
        let release = Arc::clone(&release);
        let holding = Arc::clone(&holding);
        std::thread::spawn(move || {
            let mut cat = Catalog::open(&db).expect("scan connection");
            let root = FileRepo::new(&mut cat)
                .get_root(RootId::new(1))
                .expect("get_root")
                .expect("the seeded root");
            // Exactly `shepherd-daemon::scan_exec::upsert_batch`'s shape:
            // BEGIN, N x FileRepo::upsert_file, COMMIT. The first write takes
            // the WAL writer lock and holds it until the commit.
            cat.conn().execute_batch("BEGIN").expect("begin");
            for i in 0..50 {
                FileRepo::new(&mut cat)
                    .upsert_file(&root, &scan_stat(i), 1, Timestamp::from_nanos(1))
                    .expect("upsert");
            }
            holding.store(true, Ordering::SeqCst);
            gate.wait(); // the write lock is held from here...
            release.wait(); // ...to here
            cat.conn().execute_batch("COMMIT").expect("commit");
            holding.store(false, Ordering::SeqCst);
        })
    };

    gate.wait();
    assert!(
        holding.load(Ordering::SeqCst),
        "precondition: the scan side must be inside its write transaction, \
         or this test measures an uncontended write"
    );

    // The extended code, captured DIRECTLY rather than inferred from timing.
    // `save_blocking` maps every `rusqlite::Error` to a `StorageError` string,
    // so the discriminator has to be read off a raw statement on the same
    // connection, inside the same held window.
    let probe = cat
        .conn()
        .execute(
            "UPDATE transfer_session SET updated_at = updated_at WHERE job_id = ?1",
            [job.get()],
        )
        .expect_err("a raw write is refused for the same reason the store's is");
    let extended = match &probe {
        rusqlite::Error::SqliteFailure(e, _) => e.extended_code,
        other => panic!("expected a SQLite failure, got {other:?}"),
    };
    assert_eq!(
        extended,
        rusqlite::ffi::SQLITE_BUSY,
        "expected SQLITE_BUSY (5) — retryable, the busy handler ran. \
         SQLITE_BUSY_SNAPSHOT (517) would mean a DEFERRED transaction read before it wrote, \
         which returns immediately, no `busy_timeout` can cure, and ADR-001 rejected sqlx for"
    );

    let started = Instant::now();
    let err = save_blocking(&mut cat, &session)
        .expect_err("a second connection cannot write while the scan holds the WAL writer lock");
    let waited = started.elapsed();

    release.wait();
    scan.join().expect("scan thread");

    let detail = err.to_string();
    assert!(
        detail.to_lowercase().contains("locked"),
        "expected SQLITE_BUSY (`database is locked`), got: {detail}"
    );
    assert!(
        waited >= TEST_BUSY_TIMEOUT,
        "the call returned after {waited:?}, short of the {TEST_BUSY_TIMEOUT:?} busy_timeout. \
         An immediate return is SQLITE_BUSY_SNAPSHOT (517) — a DEFERRED transaction that read \
         before it wrote — which no timeout can cure and which ADR-001 rejected sqlx for"
    );

    // And the failure is transient, not terminal: once the scan commits, the
    // identical save lands. A store that had corrupted its own transaction on
    // the way out would fail here too.
    save_blocking(&mut cat, &session).expect("the retry must succeed once the lock is free");
    let parts: i64 = cat
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM transfer_part p
               JOIN transfer_session s ON s.id = p.session_id
              WHERE s.job_id = ?1",
            [job.get()],
            |r| r.get(0),
        )
        .expect("count parts");
    assert_eq!(parts, 1, "the retried save must have landed its part row");
    let scanned: i64 = cat
        .conn()
        .query_row(
            "SELECT COUNT(*) FROM file WHERE rel_path LIKE 'scan/%'",
            [],
            |r| r.get(0),
        )
        .expect("count scanned files");
    assert_eq!(
        scanned, 50,
        "the scan batch must have committed all 50 rows"
    );
}

/// **The same contention, routed through the one writer the daemon runs.**
///
/// This is the arrangement `CatalogSessionStore::with_writer` exists for, and
/// the question it has to answer is not "does it work" but "does serialising
/// the transfer path behind the scan path stall uploads".
///
/// # The overlap is a handshake, not a hope
///
/// The scan batch signals from **inside** the actor closure that it is running,
/// waits for the test to say it has started timing, and only then holds the
/// actor for a known `HOLD`. So the save is issued while a scan batch is
/// demonstrably executing on the single writer, and the measured latency has
/// exactly one explanation.
///
/// # What the number means
///
/// The save waits, it does not fail — no `SQLITE_BUSY` is reachable, because
/// there is only ever one connection. The cost is queueing, and its bound is
/// **one batch**, not one scan: `shepherd-daemon::scan_exec` submits 500 rows
/// per blocking `try_with` and never holds a transaction across them
/// (`UPSERT_BATCH`, scan_exec.rs). There is no long scan transaction for a
/// transfer to stall behind.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_writer_actor_queues_a_session_save_behind_a_scan_batch_instead_of_failing() {
    let dir = TempDir::new("queued");
    let db = dir.join("catalog.db");
    let src = dir.join("a.bin");
    std::fs::write(&src, BODY).expect("write source");
    let item = item_for(&src);
    let job = JobId::new(23);
    seed(&db, job, item.target, item.file);
    let session = session_for(job, &item, "queued");

    /// How long the scan batch occupies the actor once the save is timing.
    const HOLD: Duration = Duration::from_millis(250);
    /// The scan closure polls at 1ms; a few of those plus scheduling is the
    /// only slack between the test's clock and the closure's sleep.
    const SLACK: Duration = Duration::from_millis(25);
    const BATCHES: usize = 4;
    const PER_BATCH: usize = 50;

    let actor = CatalogActor::start(Catalog::open(&db).expect("open"), Some(db.clone()));
    let store = CatalogSessionStore::with_writer(actor.handle());

    let running = Arc::new(AtomicBool::new(false));
    let timing = Arc::new(AtomicBool::new(false));

    let scan = {
        let writer = actor.handle();
        let running = Arc::clone(&running);
        let timing = Arc::clone(&timing);
        std::thread::spawn(move || {
            for batch in 0..BATCHES {
                let running = Arc::clone(&running);
                let timing = Arc::clone(&timing);
                writer
                    .try_with(move |cat| {
                        if batch == 0 {
                            running.store(true, Ordering::SeqCst);
                            // Waiting on a flag the TEST sets, never on the
                            // actor: a closure that waited for actor work would
                            // wedge the catalog permanently.
                            let start = Instant::now();
                            while !timing.load(Ordering::SeqCst)
                                && start.elapsed() < Duration::from_secs(5)
                            {
                                std::thread::sleep(Duration::from_millis(1));
                            }
                            std::thread::sleep(HOLD);
                        }
                        let root = FileRepo::new(cat)
                            .get_root(RootId::new(1))?
                            .expect("the seeded root");
                        cat.conn().execute_batch("BEGIN")?;
                        for i in 0..PER_BATCH {
                            FileRepo::new(cat).upsert_file(
                                &root,
                                &scan_stat(batch * PER_BATCH + i),
                                1,
                                Timestamp::from_nanos(1),
                            )?;
                        }
                        cat.conn().execute_batch("COMMIT")?;
                        Ok(())
                    })
                    .expect("every scan batch must reach the actor");
            }
        })
    };

    let start = Instant::now();
    while !running.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(5) {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert!(
        running.load(Ordering::SeqCst),
        "precondition: a scan batch must be executing on the actor, or this test \
         measures an uncontended save"
    );

    timing.store(true, Ordering::SeqCst);
    let t0 = Instant::now();
    let saved = store.save(&session).await;
    let waited = t0.elapsed();

    scan.join().expect("scan thread");

    saved.expect("the actor serialises rather than colliding: a save must not fail here");
    assert!(
        waited + SLACK >= HOLD,
        "the save returned after {waited:?}, so it did NOT queue behind the {HOLD:?} scan \
         batch and this test proved nothing about contention"
    );

    // Both writers' work is present. A lost row on either side would mean the
    // actor was not the only writer after all.
    let writer = actor.handle();
    let (files, parts) = writer
        .try_with(move |cat| {
            let files: i64 = cat.conn().query_row(
                "SELECT COUNT(*) FROM file WHERE rel_path LIKE 'scan/%'",
                [],
                |r| r.get(0),
            )?;
            let parts: i64 = cat.conn().query_row(
                "SELECT COUNT(*) FROM transfer_part p
                   JOIN transfer_session s ON s.id = p.session_id
                  WHERE s.job_id = ?1",
                [job.get()],
                |r| r.get(0),
            )?;
            Ok((files, parts))
        })
        .expect("count through the actor");
    assert_eq!(
        files,
        (BATCHES * PER_BATCH) as i64,
        "every scan row must have landed"
    );
    assert_eq!(parts, 1, "the session's part row must have landed");

    // The session is readable through the same writer that wrote it.
    let back = store.load(job).await.expect("load").expect("row survived");
    assert_eq!(back.upload_id, session.upload_id);
}

/// **The deadlock, proven rather than argued.**
///
/// [`CatalogWriter::with`] blocks on a rendezvous channel until the actor
/// replies, so a store call made from *inside* another `with` closure wedges
/// the catalog permanently: the actor is busy running the outer closure and can
/// never dequeue the inner one. A hang, not a slow path — it does not recover
/// and it does not time out.
///
/// # The audit this guards
///
/// `with_writer`'s docs argue the shape cannot arise. Reading every `with` /
/// `try_with` call site in the workspace agrees, and for a stronger reason than
/// the one recorded there:
///
/// * no production closure body can reach a store — they are
///   `save_blocking` / `load_blocking` (session_store.rs:215,228), `Queue::*`
///   and `JobRepo::*` (worker.rs), `load_scan_input` / `upsert_batch`
///   (scan_exec.rs:107,161) and one `COUNT(*)` (state.rs:163), all pure SQL;
/// * `run_one` calls `executor.run(&ctx)` **outside** the closure (worker.rs),
///   so no executor — present or future — inherits an open actor frame;
/// * `upload_item` is the only constructor of a `TransferDriver`
///   (upload.rs:189) and is reached only from test bodies today.
///
/// So the hazard is unreachable. But a structural safety argument with no test
/// is a comment, and comments scroll out of view. This fails the moment someone
/// makes the nesting reachable and then reasons that it is fine.
#[test]
fn a_store_call_nested_inside_a_writer_closure_deadlocks() {
    let dir = TempDir::new("nested");
    let db = dir.join("catalog.db");
    let src = dir.join("a.bin");
    std::fs::write(&src, BODY).expect("write source");
    let item = item_for(&src);
    let job = JobId::new(29);
    seed(&db, job, item.target, item.file);

    /// Long enough that a working call is not merely slow: a top-level save
    /// through the actor is sub-millisecond, and the control below asserts it.
    const NEST_TIMEOUT: Duration = Duration::from_secs(2);

    // LEAKED DELIBERATELY. `CatalogActor::drop` joins the writer thread, and
    // wedging that thread is the whole point of this test — so letting the
    // actor drop would hang the suite instead of proving anything. The wedged
    // thread and its connection live until the test process exits.
    let actor: &'static CatalogActor = Box::leak(Box::new(CatalogActor::start(
        Catalog::open(&db).expect("open"),
        None,
    )));

    // --- positive control, FIRST -------------------------------------------
    // The identical call at the top level must succeed, and fast. Without this
    // the test could pass because the save was broken rather than because it
    // was nested — the timeout cannot tell those apart on its own.
    {
        let store = CatalogSessionStore::with_writer(actor.handle());
        let session = session_for(job, &item, "control");
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        let started = Instant::now();
        rt.block_on(store.save(&session))
            .expect("a top-level save through the actor must succeed");
        let took = started.elapsed();
        assert!(
            took < NEST_TIMEOUT,
            "the control save took {took:?}, so the {NEST_TIMEOUT:?} timeout below could not \
             distinguish a deadlock from ordinary slowness"
        );
    }

    // --- the forbidden shape ------------------------------------------------
    let (done_tx, done_rx) = std::sync::mpsc::channel::<()>();
    let writer = actor.handle();
    let session = session_for(job, &item, "nested");
    std::thread::Builder::new()
        .name("nested-store-call".into())
        .spawn(move || {
            let store = CatalogSessionStore::with_writer(writer.clone());
            // A store call from INSIDE a `with` closure. The actor is running
            // this closure, so it can never dequeue the save the closure makes.
            let _ = writer.with(move |_cat| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("runtime");
                rt.block_on(store.save(&session))
            });
            // Unreachable while the invariant holds.
            let _ = done_tx.send(());
        })
        .expect("spawn the nesting thread");

    let outcome = done_rx.recv_timeout(NEST_TIMEOUT);
    // `Timeout` specifically, NOT merely `is_err()`. A panicking thread drops
    // its sender and yields `Disconnected` immediately, which would satisfy a
    // bare `is_err()` and pass this test for entirely the wrong reason.
    assert!(
        matches!(outcome, Err(std::sync::mpsc::RecvTimeoutError::Timeout)),
        "expected the nested call to HANG (Timeout); got {outcome:?}. `Disconnected` means the \
         thread panicked or unwound, which is not a deadlock. `Ok` means the nesting completed — \
         either `with` stopped being a blocking rendezvous or the store stopped routing through \
         the actor, and in both cases `with_writer`'s safety argument no longer describes this \
         code"
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

/// A session reloaded in `completing` still knows each part's checksum.
///
/// The value lived only in memory. A crash after the session was durably
/// advanced to `completing` — the state whose whole point is that the parts are
/// already up — lost every provider-issued per-part checksum, and the reloaded
/// driver starts AT completion: it never runs `upload_pending`, so it never
/// runs the `list_parts` healing loop that would have re-fetched them. It
/// completes with `checksum: None` for every part, and a provider that required
/// the probed checksum answers `InvalidPart`. The one state that could not
/// re-fetch the value was the one state that needed it.
#[tokio::test]
async fn a_completing_session_reloads_the_part_checksums_it_must_echo() {
    let dir = TempDir::new("completing-checksums");
    let db = dir.join("catalog.db");
    let src = dir.join("a.bin");
    std::fs::write(&src, BODY).expect("write source");
    let item = item_for(&src);

    let job = JobId::new(77);
    seed(&db, job, item.target, item.file);
    {
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
        s.state = TransferState::Completing;
        s.upload_id = Some(OpaqueToken::new("upload-xyz"));
        for (part_no, checksum) in [(1u32, Some("crc32c-part-1")), (2, None)] {
            s.parts.push(PartCheckpoint {
                part_no,
                offset: u64::from(part_no - 1) * 16,
                len: 16,
                local_blake3: Blake3Hash::from_bytes([9u8; 32]),
                etag: Some(OpaqueToken::new(format!("etag-{part_no}"))),
                checksum: checksum.map(str::to_owned),
            });
        }
        store.save(&s).await.expect("save");
    }

    let store = CatalogSessionStore::open(&db).expect("reopen");
    let back = store
        .load(job)
        .await
        .expect("load")
        .expect("the session is there");
    assert_eq!(back.state, TransferState::Completing);
    assert_eq!(
        back.parts
            .iter()
            .map(|p| p.checksum.clone())
            .collect::<Vec<_>>(),
        vec![Some("crc32c-part-1".to_owned()), None],
        "a completing session that cannot echo its part checksums is refused \
         with `InvalidPart` by every provider that required them"
    );
}
