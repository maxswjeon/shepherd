//! The catalog writer actor and the fixed worker pool.
//!
//! # The writer actor
//!
//! §9's Phase 1 gate names it directly: *"Catalog write discipline:
//! single-writer actor, dedicated PASSIVE-checkpoint connection."*
//! [`CatalogWriter`] is that actor.
//!
//! `shepherd-catalog` carries the single-writer rule in its types — every
//! mutating method takes `&mut Catalog`, so the borrow checker refuses two
//! writers. That works inside one thread and says nothing about several. The
//! actor extends it across threads by construction: **exactly one thread ever
//! owns the `Catalog`**, and everyone else sends it a closure. There is no
//! `Mutex<Catalog>` anywhere, and that is deliberate — a mutex serialises
//! access but still hands a `&mut` to arbitrary threads, so "who may write" is
//! back to being a convention.
//!
//! Reads go through the actor too at Phase 1. SQLite's WAL model would allow
//! concurrent readers on separate connections, and the eventual design has
//! them.
//! ponytail: reads are serialised behind the writer; give readers their own
//! connections when a search-during-scan profile shows the queueing.
//!
//! # The PASSIVE checkpoint connection
//!
//! WAL grows until something checkpoints it. Letting the *writer* do it means
//! the checkpoint competes with the work, and letting SQLite's automatic
//! checkpoint do it means it happens on a random unlucky commit — including,
//! potentially, one on the destroy path. So a second connection runs
//! `wal_checkpoint(PASSIVE)` on a timer. PASSIVE specifically: it never blocks
//! a reader or a writer, and does as much as it can without waiting. A
//! TRUNCATE or RESTART checkpoint would stall whoever is mid-transaction.
//!
//! # Threads, not tokio
//!
//! `rusqlite` is synchronous and the catalog is `&mut`-serialised, so an async
//! runtime would spend its time in `spawn_blocking` wrappers around blocking
//! calls. The pool is a fixed, small number of OS threads and the channels are
//! `std::sync::mpsc`. A Phase 2 executor that needs an async storage adapter
//! creates a runtime inside its own worker thread and blocks on it there; that
//! is a per-executor concern and does not push a runtime into the queue.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel, sync_channel};
use std::thread::JoinHandle;
use std::time::Duration;

use shepherd_catalog::job_repo::{Job, JobClass};
use shepherd_catalog::{Catalog, CatalogError};
use shepherd_core::{JobId, Timestamp};

use crate::queue::{Disposition, Queue, Recovery};

/// Worker threads in the pool.
///
/// Fixed and conservative, per §6 Phase 1's split — adaptive concurrency with
/// user hard caps is Phase 4 and explicitly not here. Four is chosen to be
/// obviously safe on a laptop rather than tuned: the jobs that matter at Phase 1
/// are I/O-bound, and every one of them serialises on the writer actor anyway,
/// so a larger pool would mostly grow the queue in front of that actor.
/// ponytail: fixed 4; Phase 4 owns adaptive sizing and the hard caps that
/// always win.
pub const POOL_SIZE: usize = 4;

/// How often the WAL checkpoint thread runs.
pub const CHECKPOINT_INTERVAL: Duration = Duration::from_secs(30);

/// How long a worker sleeps when the queue is empty.
///
/// Polling rather than notifying: at Phase 1 the queue is low-rate and a poll
/// is a single indexed query. A condvar wake-up would be woken by the enqueuing
/// thread, which is the same actor the worker then has to queue behind, so the
/// latency win is smaller than it looks.
/// ponytail: 250ms poll; notify on enqueue if job latency ever shows up.
pub const IDLE_POLL: Duration = Duration::from_millis(250);

#[derive(Debug, thiserror::Error)]
pub enum WorkerError {
    #[error("the catalog writer actor has stopped")]
    WriterGone,
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
    pub fn with<T, F>(&self, f: F) -> Result<T, WorkerError>
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
            .map_err(|_| WorkerError::WriterGone)?;
        reply_rx.recv().map_err(|_| WorkerError::WriterGone)
    }

    /// Convenience for the common fallible case.
    pub fn try_with<T, F>(&self, f: F) -> Result<T, WorkerError>
    where
        F: FnOnce(&mut Catalog) -> Result<T, CatalogError> + Send + 'static,
        T: Send + 'static,
    {
        self.with(f)?.map_err(WorkerError::from)
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

// ---------------------------------------------------------------------------
// Executors and the pool
// ---------------------------------------------------------------------------

/// What a worker gives an executor.
pub struct JobContext {
    pub job: Job,
    writer: CatalogWriter,
}

impl JobContext {
    pub fn id(&self) -> JobId {
        self.job.id
    }

    /// The resume point this attempt should start from, if any.
    pub fn checkpoint(&self) -> Option<&str> {
        self.job.checkpoint_json.as_deref()
    }

    /// Persist a resume point mid-run.
    ///
    /// AC-2 is only satisfiable if an executor can do this *while working*, so
    /// it is on the context rather than being something the pool does at the
    /// end.
    pub fn save_checkpoint(&self, checkpoint_json: &str) -> Result<(), WorkerError> {
        let id = self.job.id;
        let json = checkpoint_json.to_string();
        let now = now();
        self.writer
            .try_with(move |cat| Queue::checkpoint(cat, id, &json, now))
    }
}

/// Runs one job. Registered per [`JobClass`].
pub trait Executor: Send + Sync + 'static {
    /// `Ok(())` completes the job; `Err` records the message and lets the
    /// queue's retry policy decide what happens next.
    fn run(&self, ctx: &JobContext) -> Result<(), String>;
}

impl<F> Executor for F
where
    F: Fn(&JobContext) -> Result<(), String> + Send + Sync + 'static,
{
    fn run(&self, ctx: &JobContext) -> Result<(), String> {
        self(ctx)
    }
}

/// Class → executor.
///
/// A class with no executor is **not** claimed-and-failed: the pool leaves it
/// queued. At Phase 1 most classes have no executor yet, and failing them would
/// burn their attempts budget against a daemon that was never going to run
/// them, so that a Phase 2 build would find them already exhausted.
#[derive(Default)]
pub struct Registry {
    executors: HashMap<&'static str, Arc<dyn Executor>>,
}

impl Registry {
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, class: JobClass, executor: impl Executor) -> Self {
        self.executors.insert(class.as_str(), Arc::new(executor));
        self
    }

    pub fn get(&self, class: JobClass) -> Option<Arc<dyn Executor>> {
        self.executors.get(class.as_str()).cloned()
    }

    pub fn classes(&self) -> Vec<&'static str> {
        let mut v: Vec<&'static str> = self.executors.keys().copied().collect();
        v.sort_unstable();
        v
    }

    /// The classes a worker may claim. Passed straight to the claim query.
    pub fn runnable_classes(&self) -> Vec<JobClass> {
        let mut v: Vec<JobClass> = self
            .executors
            .keys()
            .filter_map(|name| JobClass::parse(name))
            .collect();
        v.sort_by_key(|c| c.as_str());
        v
    }
}

/// A fixed pool of worker threads.
pub struct Pool {
    stop: Arc<AtomicBool>,
    threads: Vec<JoinHandle<()>>,
}

impl Pool {
    /// Start `size` workers against `writer`, running the executors in
    /// `registry`.
    pub fn start(writer: CatalogWriter, registry: Arc<Registry>, size: usize) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let threads = (0..size)
            .map(|n| {
                let writer = writer.clone();
                let registry = Arc::clone(&registry);
                let stop = Arc::clone(&stop);
                std::thread::Builder::new()
                    .name(format!("shepherd-worker-{n}"))
                    .spawn(move || worker_loop(&writer, &registry, &stop))
                    .expect("spawning a worker thread")
            })
            .collect();
        Self { stop, threads }
    }

    /// Ask the workers to stop and wait for them.
    ///
    /// A worker finishes the job in its hand first. That is what makes shutdown
    /// leave the queue in a state recovery can reason about: a job is either
    /// finished, or `running` and therefore visible to
    /// [`Queue::recover_interrupted`].
    pub fn shutdown(mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

impl Drop for Pool {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }
}

fn worker_loop(writer: &CatalogWriter, registry: &Registry, stop: &AtomicBool) {
    while !stop.load(Ordering::SeqCst) {
        match run_one(writer, registry) {
            Ok(true) => {}
            Ok(false) => std::thread::sleep(IDLE_POLL),
            Err(WorkerError::WriterGone) => return,
            Err(e) => {
                tracing::warn!(error = %e, "worker could not reach the catalog");
                std::thread::sleep(IDLE_POLL);
            }
        }
    }
}

/// Claim and run at most one job. `Ok(false)` means nothing was ready.
///
/// Exposed so tests can drive the pool's logic deterministically, without
/// threads or sleeps.
pub fn run_one(writer: &CatalogWriter, registry: &Registry) -> Result<bool, WorkerError> {
    // Ask only for classes this build can actually run. Claiming counts an
    // attempt, so claiming-then-returning an unrunnable job burns its retry
    // budget — measured at 12 attempts in 3 seconds from one thread before this
    // was a filter rather than a check.
    let runnable = registry.runnable_classes();
    let claimed = writer.try_with(move |cat| Queue::claim_of(cat, now(), Some(&runnable)))?;
    let Some(job) = claimed else {
        return Ok(false);
    };

    let Some(executor) = registry.get(job.class) else {
        // Unreachable: the claim filtered on exactly this registry's classes.
        // Kept as a typed outcome rather than an `unwrap` — a future caller
        // passing a wider allowlist should get a job back in the queue, not a
        // panic in a worker thread.
        let id = job.id;
        writer.try_with(move |cat| {
            shepherd_catalog::job_repo::JobRepo::new(cat).requeue(
                id,
                Timestamp::from_nanos(now().as_nanos() + IDLE_POLL.as_nanos() as i64),
                Some("claimed a class this worker has no executor for"),
                now(),
            )
        })?;
        return Ok(false);
    };

    let ctx = JobContext {
        job: job.clone(),
        writer: writer.clone(),
    };
    let outcome = executor.run(&ctx);

    match outcome {
        Ok(()) => {
            let id = job.id;
            writer.try_with(move |cat| Queue::complete(cat, id, now()))?;
        }
        Err(message) => {
            let disposition =
                writer.try_with(move |cat| Queue::fail(cat, &job, &message, now()))?;
            match disposition {
                Disposition::Retry { at, attempt } => {
                    tracing::info!(attempt, retry_at = at.as_nanos(), "job will be retried");
                }
                Disposition::Failed { reason } => tracing::warn!(reason, "job failed terminally"),
                Disposition::Done => unreachable!("fail() never returns Done"),
            }
        }
    }
    Ok(true)
}

/// Resolve crash-interrupted jobs. Call before starting the pool.
pub fn recover(writer: &CatalogWriter) -> Result<Vec<Recovery>, WorkerError> {
    writer.try_with(move |cat| Queue::recover_interrupted(cat, now()))
}

/// Wall-clock now, in nanoseconds since the epoch.
pub fn now() -> Timestamp {
    Timestamp::from_nanos(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as i64)
            .unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn actor_in_memory() -> CatalogActor {
        CatalogActor::start(Catalog::open_in_memory().unwrap(), None)
    }

    #[test]
    fn the_writer_actor_serialises_writes_from_many_threads() {
        // The property the gate names. Without a single owner this races on the
        // connection; with it, every increment lands.
        let actor = actor_in_memory();
        let w = actor.handle();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let w = w.clone();
                std::thread::spawn(move || {
                    for _ in 0..25 {
                        w.try_with(|cat| {
                            Queue::enqueue(cat, JobClass::Hash, 0, "{}", now()).map(|_| ())
                        })
                        .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
        let depth = w.try_with(|cat| Queue::depth(cat)).unwrap();
        let hash = depth.iter().find(|d| d.class == "hash").unwrap();
        assert_eq!(hash.pending, 200);
    }

    #[test]
    fn a_write_is_visible_to_the_caller_when_with_returns() {
        let actor = actor_in_memory();
        let w = actor.handle();
        let id = w
            .try_with(|cat| Queue::enqueue(cat, JobClass::Scan, 0, "{}", now()))
            .unwrap();
        let found = w
            .try_with(move |cat| shepherd_catalog::job_repo::JobRepo::new(cat).get(id))
            .unwrap();
        assert!(
            found.is_some(),
            "with() must not return before the write lands"
        );
    }

    #[test]
    fn a_registered_executor_runs_and_the_job_completes() {
        let actor = actor_in_memory();
        let w = actor.handle();
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let sink = Arc::clone(&seen);

        let registry = Arc::new(
            Registry::new().with(JobClass::Scan, move |ctx: &JobContext| {
                sink.lock().unwrap().push(ctx.job.payload_json.clone());
                Ok(())
            }),
        );

        w.try_with(|cat| Queue::enqueue(cat, JobClass::Scan, 0, r#"{"root":1}"#, now()))
            .unwrap();
        assert!(run_one(&w, &registry).unwrap());
        assert_eq!(&*seen.lock().unwrap(), &[r#"{"root":1}"#.to_string()]);

        let depth = w.try_with(|cat| Queue::depth(cat)).unwrap();
        let scan = depth.iter().find(|d| d.class == "scan").unwrap();
        assert_eq!((scan.pending, scan.running, scan.failed), (0, 0, 0));
        assert!(!run_one(&w, &registry).unwrap(), "queue is drained");
    }

    /// A class nobody can execute must cost it **nothing**.
    ///
    /// The first version of this test polled once and asserted `attempts <= 1`,
    /// which passed while the real behaviour was one attempt per claim: a
    /// requeue with a 250ms deadline, re-claimed forever. Measured at 12
    /// attempts in 3 seconds from a single thread — `MAX_ATTEMPTS` is 5, so a
    /// four-worker pool exhausted an untouched job's whole retry budget in
    /// under two seconds, and the phase that later registered its executor
    /// would have seen it fail terminally on the first transient error.
    ///
    /// So this polls hard and asserts **zero**, which only a claim-time filter
    /// can satisfy.
    #[test]
    fn a_job_with_no_executor_costs_no_attempts_however_often_it_is_polled() {
        let actor = actor_in_memory();
        let w = actor.handle();
        let registry = Arc::new(Registry::new()); // empty
        let id = w
            .try_with(|cat| Queue::enqueue(cat, JobClass::Embed, 0, "{}", now()))
            .unwrap();

        for _ in 0..200 {
            assert!(!run_one(&w, &registry).unwrap(), "nothing is runnable");
        }
        let job = w
            .try_with(move |cat| shepherd_catalog::job_repo::JobRepo::new(cat).get(id))
            .unwrap()
            .unwrap();
        assert_eq!(job.state, shepherd_catalog::job_repo::JobState::Queued);
        assert_eq!(
            job.attempts, 0,
            "an unrunnable class must accumulate no attempts at all"
        );
        assert!(
            job.last_error.is_none(),
            "and must not have its last_error stomped: {:?}",
            job.last_error
        );
    }

    /// A runnable job must not be starved by an unrunnable higher-priority one.
    #[test]
    fn an_unrunnable_job_does_not_block_a_runnable_one_behind_it() {
        let actor = actor_in_memory();
        let w = actor.handle();
        let registry = Arc::new(Registry::new().with(JobClass::Hash, |_: &JobContext| Ok(())));
        w.try_with(|cat| Queue::enqueue(cat, JobClass::Embed, 100, "{}", now()))
            .unwrap();
        let hash = w
            .try_with(|cat| Queue::enqueue(cat, JobClass::Hash, 0, "{}", now()))
            .unwrap();

        assert!(run_one(&w, &registry).unwrap());
        let job = w
            .try_with(move |cat| shepherd_catalog::job_repo::JobRepo::new(cat).get(hash))
            .unwrap()
            .unwrap();
        assert_eq!(job.state, shepherd_catalog::job_repo::JobState::Done);
    }

    #[test]
    fn a_failing_executor_records_the_error_and_schedules_a_retry() {
        let actor = actor_in_memory();
        let w = actor.handle();
        let registry = Arc::new(
            Registry::new().with(JobClass::Upload, |_: &JobContext| Err("503 from s3".into())),
        );
        let id = w
            .try_with(|cat| Queue::enqueue(cat, JobClass::Upload, 0, "{}", now()))
            .unwrap();

        assert!(run_one(&w, &registry).unwrap());
        let job = w
            .try_with(move |cat| shepherd_catalog::job_repo::JobRepo::new(cat).get(id))
            .unwrap()
            .unwrap();
        assert_eq!(job.state, shepherd_catalog::job_repo::JobState::Queued);
        assert_eq!(job.last_error.as_deref(), Some("503 from s3"));
        assert!(
            job.run_after > 0,
            "a retry must be scheduled into the future"
        );
    }

    /// **The §9 Phase 1 gate item: "Job-queue core: kill-and-resume of a
    /// checkpointed job."**
    ///
    /// An executor writes a checkpoint and then the process is torn down. On
    /// restart, against the same on-disk catalog, the job comes back with its
    /// resume point and finishes from there rather than from the start.
    ///
    /// Honest about what it simulates: the teardown is dropping the actor and
    /// reopening the database, not `kill -9`. What it therefore proves is that
    /// the durable state — the row left in `running`, and its
    /// `checkpoint_json` — is sufficient to resume. It does not prove
    /// crash-consistency of the SQLite file itself, which is `synchronous =
    /// FULL`'s job and is asserted by the catalog crate's own pragmas.
    ///
    /// Run 1 deliberately does **not** go through an executor returning `Err`.
    /// That is the *retry* path: it finishes the attempt, marks the row
    /// `queued` and sets a backoff, so recovery would correctly find nothing to
    /// do. A crash leaves the row `running` with nobody coming back for it,
    /// which is what run 1 reproduces by claiming and checkpointing and then
    /// simply ceasing to exist. Getting this distinction wrong is why the first
    /// version of this test passed for the wrong reason.
    #[test]
    fn kill_and_resume_of_a_checkpointed_job() {
        let dir = std::env::temp_dir().join(format!(
            "shepherd-jobs-resume-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("catalog.db");

        // --- run 1: claim, checkpoint, then vanish mid-job ----------------
        let id = {
            let actor = CatalogActor::start(Catalog::open(&db).unwrap(), Some(db.clone()));
            let w = actor.handle();
            let id = w
                .try_with(|cat| Queue::enqueue(cat, JobClass::Upload, 0, r#"{"parts":10}"#, now()))
                .unwrap();

            let claimed = w.try_with(|cat| Queue::claim(cat, now())).unwrap().unwrap();
            assert_eq!(claimed.id, id);
            assert!(claimed.checkpoint_json.is_none(), "first run starts clean");
            w.try_with(move |cat| Queue::checkpoint(cat, id, r#"{"parts_done":7}"#, now()))
                .unwrap();

            // No complete(), no fail(): the process is gone. The row stays
            // `running`, which is exactly what a crash leaves behind.
            let left = w
                .try_with(move |cat| shepherd_catalog::job_repo::JobRepo::new(cat).get(id))
                .unwrap()
                .unwrap();
            assert_eq!(left.state, shepherd_catalog::job_repo::JobState::Running);
            id
        };

        // --- run 2: reopen and resume -------------------------------------
        {
            let actor = CatalogActor::start(Catalog::open(&db).unwrap(), Some(db.clone()));
            let w = actor.handle();
            let recovered = recover(&w).unwrap();
            assert_eq!(
                recovered,
                vec![Recovery::Requeued(id)],
                "the interrupted upload must be recognised and requeued"
            );

            let resumed_from = Arc::new(Mutex::new(None::<String>));
            let sink = Arc::clone(&resumed_from);
            let registry = Arc::new(Registry::new().with(
                JobClass::Upload,
                move |ctx: &JobContext| {
                    *sink.lock().unwrap() = ctx.checkpoint().map(str::to_string);
                    Ok(())
                },
            ));

            assert!(run_one(&w, &registry).unwrap(), "the job must be claimable");
            assert_eq!(
                resumed_from.lock().unwrap().as_deref(),
                Some(r#"{"parts_done":7}"#),
                "the second run must start from the checkpoint, not from scratch"
            );

            let job = w
                .try_with(move |cat| shepherd_catalog::job_repo::JobRepo::new(cat).get(id))
                .unwrap()
                .unwrap();
            assert_eq!(job.state, shepherd_catalog::job_repo::JobState::Done);
            assert_eq!(job.attempts, 2, "one claim per run");
        }

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_pool_drains_the_queue_and_shuts_down_cleanly() {
        let actor = actor_in_memory();
        let w = actor.handle();
        let done = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter = Arc::clone(&done);
        let registry = Arc::new(Registry::new().with(JobClass::Hash, move |_: &JobContext| {
            counter.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }));

        for _ in 0..20 {
            w.try_with(|cat| Queue::enqueue(cat, JobClass::Hash, 0, "{}", now()))
                .unwrap();
        }
        let pool = Pool::start(w.clone(), registry, POOL_SIZE);

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while done.load(Ordering::SeqCst) < 20 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        pool.shutdown();

        assert_eq!(done.load(Ordering::SeqCst), 20);
        let depth = w.try_with(|cat| Queue::depth(cat)).unwrap();
        let hash = depth.iter().find(|d| d.class == "hash").unwrap();
        assert_eq!((hash.pending, hash.running), (0, 0));
    }

    #[test]
    fn the_registry_reports_what_it_can_run() {
        let r = Registry::new()
            .with(JobClass::Scan, |_: &JobContext| Ok(()))
            .with(JobClass::Hash, |_: &JobContext| Ok(()));
        assert_eq!(r.classes(), vec!["hash", "scan"]);
        assert!(r.get(JobClass::Scan).is_some());
        assert!(r.get(JobClass::Upload).is_none());
    }

    #[test]
    fn a_dropped_actor_reports_writer_gone_rather_than_hanging() {
        let w = {
            let actor = actor_in_memory();
            actor.handle()
        };
        let err = w.try_with(|cat| Queue::depth(cat)).unwrap_err();
        assert!(matches!(err, WorkerError::WriterGone), "{err:?}");
    }
}
