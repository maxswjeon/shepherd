//! The catalog writer actor: one thread owns the connection.
//!
//! # Why this lives here rather than in whichever crate needed it first
//!
//! This crate already enforces single-writer discipline **within** a thread:
//! every mutating method takes `&mut self`, so the borrow checker refuses a
//! second concurrent writer. [`CatalogActor`] is the same invariant extended
//! **across** threads — exactly one thread owns the [`Catalog`], and everyone
//! else sends it a closure. One invariant, two enforcement mechanisms, one
//! crate.
//!
//! It began in `shepherd-jobs`, because the worker pool was its only consumer.
//! That stopped being true when `shepherd-tier` needed it too (a durable
//! transfer-session store must not open a second `Catalog` on one WAL file), at
//! which point obtaining it from the queue crate would have drawn a
//! `shepherd-tier -> shepherd-jobs` edge for a type with nothing to do with
//! queues — into the crate where §4.1 rules 2 and 4 make every edge
//! load-bearing. Moving it here costs **zero** new edges: both consumers
//! already depend on this crate.
//!
//! There is deliberately no `Mutex<Catalog>` anywhere. A mutex serialises
//! access but still hands `&mut` to arbitrary threads, so "who may write"
//! reverts to being a convention rather than a structure.
//!
//! # Reads go through the actor too, for now
//!
//! SQLite's WAL model would allow concurrent readers on separate connections,
//! and the eventual design has them.
//! ponytail: reads are serialised behind writes; give readers their own
//! connections when a search-during-scan profile shows the queueing.
//!
//! # The dedicated PASSIVE-checkpoint connection
//!
//! WAL grows until something checkpoints it. Letting the *writer* do it means
//! the checkpoint competes with the work; letting SQLite's automatic checkpoint
//! do it means it fires on a random unlucky commit — potentially one on the
//! destroy path. So a second connection runs `wal_checkpoint(PASSIVE)` on a
//! timer. PASSIVE specifically: it never blocks a reader or a writer. TRUNCATE
//! or RESTART would stall whoever is mid-transaction.
//!
//! # Threads, not an async runtime
//!
//! `rusqlite` is synchronous and the catalog is `&mut`-serialised, so a runtime
//! would spend its time in `spawn_blocking` wrappers around blocking calls. The
//! channels are `std::sync::mpsc`. A consumer that needs an async client inside
//! a closure builds a runtime in its own thread and blocks on it there.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use crate::{Catalog, CatalogError};

/// How often the WAL checkpoint thread runs.
pub const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, thiserror::Error)]
pub enum WriterError {
    #[error("the catalog writer actor has stopped")]
    Gone,
    #[error(transparent)]
    Catalog(#[from] CatalogError),
}

type Task = Box<dyn FnOnce(&mut Catalog) + Send>;

/// What the writer thread receives.
///
/// `Stop` exists because "the channel closed" is not a usable shutdown signal
/// here: [`CatalogWriter`] is cloneable by design, so any live clone — one held
/// by a worker, or one a caller kept — keeps the channel open and the writer
/// thread alive. An earlier version relied on dropping the actor's own sender
/// and deadlocked in `Drop`, joining a thread that was still waiting on a
/// channel somebody else held open.
enum Msg {
    Run(Task),
    Stop,
}

/// A handle to the one thread permitted to touch the catalog.
///
/// Cloneable and `Send`: hand it to workers, the IPC server, anything. Cloning
/// the handle does not clone the connection — there is still exactly one.
#[derive(Clone)]
pub struct CatalogWriter {
    tx: Sender<Msg>,
}

impl CatalogWriter {
    /// Run `f` on the catalog thread and wait for its result.
    ///
    /// The closure returns through a rendezvous channel, so a caller cannot
    /// proceed on the assumption that a write landed when it has not.
    ///
    /// # Deadlock: never call this from inside another `with`
    ///
    /// This **blocks** until the actor replies. If `f` — or anything `f` calls —
    /// itself calls [`CatalogWriter::with`], the actor is busy running the outer
    /// closure, can never dequeue the inner one, and every catalog access in the
    /// process wedges permanently. It does not recover and it does not time out.
    ///
    /// Safe: from a worker thread, a connection thread, a job executor — any
    /// thread that is not the actor's.
    /// Unsafe: from inside a closure already running on the actor.
    ///
    /// The shape that walks into it is "open a transaction on the actor, then
    /// ask some collaborator for a record" — the collaborator's lookup is the
    /// nested call. The fix is to invert it: gather what you need in one
    /// closure, or make the collaborator's access the outer one.
    ///
    /// A `Mutex<CatalogWriter>` makes this *worse*, not safer: a thread parked
    /// on the mutex holds nothing the actor can drain, which widens the window
    /// rather than closing it. The handle is already `Send + Sync`; it needs no
    /// lock.
    pub fn with<T, F>(&self, f: F) -> Result<T, WriterError>
    where
        F: FnOnce(&mut Catalog) -> T + Send + 'static,
        T: Send + 'static,
    {
        let (reply_tx, reply_rx) = sync_channel::<T>(0);
        self.tx
            .send(Msg::Run(Box::new(move |cat| {
                let out = f(cat);
                // A receiver that hung up means the caller gave up waiting. The
                // write still happened; dropping the reply is correct.
                let _ = reply_tx.send(out);
            })))
            .map_err(|_| WriterError::Gone)?;
        reply_rx.recv().map_err(|_| WriterError::Gone)
    }

    /// Convenience for the common fallible case.
    pub fn try_with<T, F>(&self, f: F) -> Result<T, WriterError>
    where
        F: FnOnce(&mut Catalog) -> Result<T, CatalogError> + Send + 'static,
        T: Send + 'static,
    {
        self.with(f)?.map_err(WriterError::from)
    }
}

/// Owns the catalog thread and the WAL checkpoint thread.
pub struct CatalogActor {
    handle: CatalogWriter,
    writer_thread: Option<JoinHandle<()>>,
    checkpoint_thread: Option<JoinHandle<()>>,
    stop: Arc<AtomicBool>,
}

impl CatalogActor {
    /// Take ownership of `catalog` and start the actor.
    ///
    /// `checkpoint_path` is the database file for the dedicated PASSIVE
    /// checkpoint connection. `None` skips that thread, which is what an
    /// in-memory catalog needs — a second connection to `:memory:` would open a
    /// *different, empty* database, so checkpointing it would be theatre.
    pub fn start(catalog: Catalog, checkpoint_path: Option<std::path::PathBuf>) -> Self {
        let (tx, rx): (Sender<Msg>, Receiver<Msg>) = channel();
        let stop = Arc::new(AtomicBool::new(false));

        let writer_thread = std::thread::Builder::new()
            .name("shepherd-catalog-writer".into())
            .spawn(move || {
                let mut catalog = catalog;
                // Ends on `Stop`, or if every sender is gone. Tasks already
                // queued ahead of `Stop` still run, so a write submitted before
                // shutdown is not silently discarded.
                for msg in rx {
                    match msg {
                        Msg::Run(task) => task(&mut catalog),
                        Msg::Stop => break,
                    }
                }
            })
            .expect("spawning the catalog writer thread");

        let checkpoint_thread = checkpoint_path.map(|path| {
            let stop = Arc::clone(&stop);
            std::thread::Builder::new()
                .name("shepherd-wal-checkpoint".into())
                .spawn(move || checkpoint_loop(&path, &stop))
                .expect("spawning the WAL checkpoint thread")
        });

        Self {
            handle: CatalogWriter { tx },
            writer_thread: Some(writer_thread),
            checkpoint_thread,
            stop,
        }
    }

    pub fn handle(&self) -> CatalogWriter {
        self.handle.clone()
    }
}

impl Drop for CatalogActor {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        // Queued tasks run first; `Stop` is behind them. Outstanding
        // `CatalogWriter` clones stay valid to *call* and will get
        // `WriterGone`, because once the thread returns the receiver drops and
        // the send fails.
        let _ = self.handle.tx.send(Msg::Stop);
        if let Some(t) = self.writer_thread.take() {
            let _ = t.join();
        }
        if let Some(t) = self.checkpoint_thread.take() {
            let _ = t.join();
        }
    }
}

/// The dedicated PASSIVE-checkpoint connection.
///
/// Failures are logged, never propagated: a checkpoint that could not run is a
/// WAL that stays large for another interval, which is a performance condition,
/// not a correctness one. Turning it into an error would take the daemon down
/// over housekeeping.
fn checkpoint_loop(path: &std::path::Path, stop: &AtomicBool) {
    let conn = match rusqlite::Connection::open(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "WAL checkpoint connection unavailable; \
                                        the WAL will be checkpointed by SQLite's own policy");
            return;
        }
    };
    // Sleep in short slices so shutdown is prompt without a condvar.
    let slice = Duration::from_millis(100);
    let mut waited = Duration::ZERO;
    while !stop.load(Ordering::SeqCst) {
        if waited >= CHECKPOINT_INTERVAL {
            waited = Duration::ZERO;
            if let Err(e) = conn.pragma_update(None, "wal_checkpoint", "PASSIVE") {
                tracing::warn!(error = %e, "PASSIVE WAL checkpoint failed");
            }
        }
        std::thread::sleep(slice);
        waited += slice;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "shepherd-writer-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn count(w: &CatalogWriter) -> i64 {
        w.try_with(|cat| {
            cat.conn()
                .query_row("SELECT COUNT(*) FROM scan_root", [], |r| r.get::<_, i64>(0))
                .map_err(CatalogError::from)
        })
        .unwrap()
    }

    /// **The cross-thread half of the single-writer invariant, on a real file.**
    ///
    /// `&mut self` makes the borrow checker refuse two writers inside one
    /// thread. Nothing in the type system says anything about two threads —
    /// that is the actor's job, and this is the test that it does it. On a
    /// file-backed catalog rather than `:memory:`, because a WAL database on
    /// disk is where a second writer would actually collide.
    ///
    /// Every insert must land. A lost one means two threads reached the
    /// connection; a `SQLITE_BUSY` failure means they reached it concurrently.
    #[test]
    fn concurrent_writers_over_one_file_serialize() {
        let dir = tmpdir("serialize");
        let db = dir.join("catalog.db");
        let actor = CatalogActor::start(Catalog::open(&db).unwrap(), Some(db.clone()));
        let w = actor.handle();

        const THREADS: usize = 8;
        const EACH: usize = 25;
        let threads: Vec<_> = (0..THREADS)
            .map(|n| {
                let w = w.clone();
                std::thread::spawn(move || {
                    for i in 0..EACH {
                        w.try_with(move |cat| {
                            cat.conn_mut()
                                .execute(
                                    "INSERT INTO scan_root (path, stub_mode, created_at)
                                     VALUES (?1, 'delete', 0)",
                                    rusqlite::params![format!("/t{n}/{i}")],
                                )
                                .map(|_| ())
                                .map_err(CatalogError::from)
                        })
                        .expect("every write must reach the actor");
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }

        assert_eq!(
            count(&w),
            (THREADS * EACH) as i64,
            "a lost row means two threads reached the connection"
        );
        drop(actor);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Writes queued before shutdown still land; the actor drains before it
    /// stops. A `Stop` that jumped the queue would silently discard them.
    #[test]
    fn shutdown_drains_what_was_already_submitted() {
        let dir = tmpdir("drain");
        let db = dir.join("catalog.db");
        let n = {
            let actor = CatalogActor::start(Catalog::open(&db).unwrap(), Some(db.clone()));
            let w = actor.handle();
            for i in 0..50 {
                w.try_with(move |cat| {
                    cat.conn_mut()
                        .execute(
                            "INSERT INTO scan_root (path, stub_mode, created_at)
                             VALUES (?1, 'delete', 0)",
                            rusqlite::params![format!("/d/{i}")],
                        )
                        .map(|_| ())
                        .map_err(CatalogError::from)
                })
                .unwrap();
            }
            count(&w)
        };
        assert_eq!(n, 50);

        // Reopening proves they were durable, not merely acknowledged.
        let actor = CatalogActor::start(Catalog::open(&db).unwrap(), None);
        assert_eq!(count(&actor.handle()), 50);
        drop(actor);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// A handle outliving its actor reports `Gone` rather than blocking
    /// forever. The handle is cloneable, so shutdown cannot depend on sender
    /// counts — an earlier version deadlocked in `Drop` for exactly that reason.
    #[test]
    fn a_handle_that_outlives_its_actor_reports_gone() {
        let w = {
            let actor = CatalogActor::start(Catalog::open_in_memory().unwrap(), None);
            actor.handle()
        };
        let err = w
            .try_with(|cat| {
                cat.conn()
                    .query_row("SELECT 1", [], |r| r.get::<_, i64>(0))
                    .map_err(CatalogError::from)
            })
            .unwrap_err();
        assert!(matches!(err, WriterError::Gone), "{err:?}");
    }

    /// The handle must be `Send + Sync` — `shepherd-tier`'s session store needs
    /// it behind a `Send + Sync` trait object, and `shepherd-daemon` shares it
    /// across connection threads inside an `Arc`.
    #[test]
    fn the_handle_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<CatalogWriter>();
        assert_send_sync::<Arc<CatalogWriter>>();
    }
}
