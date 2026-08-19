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
        Self::start_with_interval(catalog, checkpoint_path, CHECKPOINT_INTERVAL)
    }

    /// [`CatalogActor::start`] with the checkpoint period as a parameter.
    ///
    /// Private, and it exists for one reason: the test that shows the
    /// checkpoint runs on a connection the writer thread does not own has to
    /// observe a checkpoint land inside a window during which the writer is
    /// provably occupied, and a thirty-second window is a thirty-second test.
    /// Nothing outside this module may choose the period — [`CHECKPOINT_INTERVAL`]
    /// is the daemon's, and a caller that could shorten it could turn the
    /// PASSIVE checkpoint into a busy loop against the writer.
    fn start_with_interval(
        catalog: Catalog,
        checkpoint_path: Option<std::path::PathBuf>,
        interval: Duration,
    ) -> Self {
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
                .spawn(move || checkpoint_loop(&path, &stop, interval))
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
fn checkpoint_loop(path: &std::path::Path, stop: &AtomicBool, interval: Duration) {
    let conn = match rusqlite::Connection::open(path) {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "WAL checkpoint connection unavailable; \
                                        the WAL will be checkpointed by SQLite's own policy");
            return;
        }
    };
    // Sleep in short slices so shutdown is prompt without a condvar.
    let slice = Duration::from_millis(100).min(interval);
    let mut waited = Duration::ZERO;
    while !stop.load(Ordering::SeqCst) {
        if waited >= interval {
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

    /// **§9's `dedicated PASSIVE-checkpoint connection`, as a claim about
    /// *which connection*, not about whether the call appears.**
    ///
    /// A bounded WAL is evidence that *something* checkpoints. It is not
    /// evidence that the something is a second connection: a
    /// `wal_checkpoint(PASSIVE)` issued on the writer's own connection bounds
    /// the log just as well, and SQLite's built-in `wal_autocheckpoint` — which
    /// this crate's [`PRAGMAS`](crate::PRAGMAS) never disables — bounds it
    /// without any of our code running at all. All three produce the same
    /// graph. They are different mechanisms with different blocking behaviour,
    /// and §9 names one of them.
    ///
    /// So this does not grep for `wal_checkpoint`, and it does not count
    /// checkpoint calls; a call that is present, is issued, and never bounds
    /// anything would satisfy both. It measures an **outcome that only a
    /// separate connection can produce**:
    ///
    /// 1. The actor's whole invariant is that exactly one thread ever holds the
    ///    `Catalog`. Anything executed on the writer's connection therefore
    ///    runs on the writer thread — that is what
    ///    [`concurrent_writers_over_one_file_serialize`] establishes.
    /// 2. The writer thread is put to sleep *inside* a closure, and a probe
    ///    task submitted afterwards is shown not to have completed. The writer's
    ///    connection is provably idle for the whole window.
    /// 3. `wal_autocheckpoint` is turned off **on the writer's connection**
    ///    (it is connection-scoped, so the checkpoint thread's own connection
    ///    keeps its default). SQLite's automatic checkpoint fires on commit,
    ///    and no commit happens in the window regardless.
    /// 4. In WAL mode the main database file grows only when frames are
    ///    backfilled into it. Growth during that window is a checkpoint that
    ///    ran on a connection nothing on the writer thread was touching.
    ///
    /// And the same window with `checkpoint_path: None` is run as the control.
    /// Without it, "the file grew" would be a number with nothing to compare it
    /// against; with it, the difference between the two runs *is* the dedicated
    /// connection.
    #[test]
    fn the_checkpoint_lands_on_a_connection_the_writer_thread_does_not_own() {
        let dedicated = backfilled_while_the_writer_slept("dedicated", true);
        let none = backfilled_while_the_writer_slept("no-checkpoint-thread", false);

        assert!(
            dedicated > 0,
            "no WAL frame reached the database file while the writer thread sat \
             inside a sleeping closure. Every checkpoint this project could be \
             performing on the writer's own connection is impossible in that \
             window, so a zero here means §9's `dedicated` connection is not \
             checkpointing — whatever else is keeping the WAL small"
        );
        assert_eq!(
            none, 0,
            "the database file grew by {none} bytes during the same window with \
             NO checkpoint thread running. Something other than the dedicated \
             connection backfills the WAL here, so the {dedicated} bytes measured \
             with the thread running are not attributable to it and this test \
             proves nothing"
        );
    }

    /// One window: block the writer thread, and report how many bytes the main
    /// database file grew while it was blocked.
    ///
    /// `dedicated` chooses whether [`CatalogActor`] gets a checkpoint
    /// connection at all, which is the only difference between the measurement
    /// and its control.
    fn backfilled_while_the_writer_slept(tag: &str, dedicated: bool) -> u64 {
        /// Short enough that the window is seconds rather than the daemon's
        /// half-minute; long enough that the checkpoint is still a timer.
        const TICK: Duration = Duration::from_millis(250);
        /// The window the writer thread spends asleep. Many `TICK`s, so a
        /// missed checkpoint is a missing mechanism and not a missed deadline.
        const WINDOW: Duration = Duration::from_secs(4);
        /// Enough rows that backfilling them must ALLOCATE pages, which is what
        /// makes the checkpoint visible as file *growth*. Overwriting pages the
        /// database already has would leave its length unchanged.
        const ROWS: usize = 20_000;

        let dir = tmpdir(tag);
        let db = dir.join("catalog.db");
        let actor = CatalogActor::start_with_interval(
            Catalog::open(&db).unwrap(),
            dedicated.then(|| db.clone()),
            TICK,
        );
        let w = actor.handle();

        // Take SQLite's own checkpointer off the writer's connection, and
        // CHECK that it went: `wal_autocheckpoint` defaults to 1000 pages, so
        // left alone the writer's commits backfill their own frames and the
        // growth this function measures would be the writer's work rather than
        // the checkpoint thread's. `pragma_update` cannot set the pragmas that
        // answer with a row, hence the fallback — the same shape
        // `crate::apply_pragmas` uses.
        let autock = w
            .with(|cat| {
                let c = cat.conn();
                let _ = c
                    .pragma_update(None, "wal_autocheckpoint", 0)
                    .or_else(|_| c.query_row("PRAGMA wal_autocheckpoint = 0", [], |_| Ok(())));
                c.query_row("PRAGMA wal_autocheckpoint", [], |r| r.get::<_, i64>(0))
                    .unwrap_or(-1)
            })
            .unwrap();
        assert_eq!(
            autock, 0,
            "SQLite's automatic checkpoint is still armed on the writer's \
             connection, so any backfill measured below could be the writer's own"
        );

        let occupied = Arc::new(AtomicBool::new(false));
        let baseline = Arc::new(std::sync::atomic::AtomicU64::new(0));
        {
            let occupied = Arc::clone(&occupied);
            let baseline = Arc::clone(&baseline);
            let path = db.clone();
            let w = w.clone();
            std::thread::spawn(move || {
                w.with(move |cat| {
                    // One committed transaction. Its pages live only in the WAL:
                    // autocheckpoint is off and this connection issues nothing
                    // else for the rest of the window.
                    let tx = cat.conn_mut().transaction().unwrap();
                    {
                        let mut st = tx
                            .prepare(
                                "INSERT INTO scan_root (path, stub_mode, created_at)
                                 VALUES (?1, 'delete', 0)",
                            )
                            .unwrap();
                        for i in 0..ROWS {
                            st.execute(rusqlite::params![format!("/ck/{i}")]).unwrap();
                        }
                    }
                    tx.commit().unwrap();
                    // Taken here, on the writer thread, after the commit: every
                    // byte counted against it arrived while this thread slept.
                    baseline.store(
                        std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0),
                        Ordering::SeqCst,
                    );
                    occupied.store(true, Ordering::SeqCst);
                    std::thread::sleep(WINDOW);
                    occupied.store(false, Ordering::SeqCst);
                })
                .expect("the blocking closure must reach the actor");
            });
        }

        let waiting = std::time::Instant::now();
        while !occupied.load(Ordering::SeqCst) {
            assert!(
                waiting.elapsed() < Duration::from_secs(120),
                "the blocking closure never started, so no window was ever opened"
            );
            std::thread::sleep(Duration::from_millis(10));
        }

        // The control for step 2: a task submitted now cannot be served until
        // the sleeping closure returns. If it completes, the writer thread was
        // not blocked and nothing below can be attributed to a second
        // connection.
        let probe_done = Arc::new(AtomicBool::new(false));
        {
            let probe_done = Arc::clone(&probe_done);
            let w = w.clone();
            std::thread::spawn(move || {
                let _ = w.with(|_| ());
                probe_done.store(true, Ordering::SeqCst);
            });
        }

        let base = baseline.load(Ordering::SeqCst);
        assert!(base > 0, "the database file was never readable");
        let mut grew = 0;
        let deadline = std::time::Instant::now() + WINDOW - Duration::from_millis(500);
        while std::time::Instant::now() < deadline {
            let now = std::fs::metadata(&db).map(|m| m.len()).unwrap_or(0);
            if now > base {
                assert!(
                    occupied.load(Ordering::SeqCst),
                    "the window had already closed when the growth was seen"
                );
                assert!(
                    !probe_done.load(Ordering::SeqCst),
                    "a task submitted after the window opened completed inside \
                     it, so the writer thread was not blocked and the growth \
                     cannot be attributed to another connection"
                );
                grew = now - base;
                break;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        while occupied.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(25));
        }
        drop(actor);
        std::fs::remove_dir_all(&dir).ok();
        grew
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
