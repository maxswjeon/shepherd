//! The worker pool and the class-to-executor registry.
//!
//! # The writer actor is next door
//!
//! §9's Phase 1 gate names it directly: *"Catalog write discipline:
//! single-writer actor, dedicated PASSIVE-checkpoint connection."* That is
//! `shepherd_catalog::writer::CatalogActor`, and it lives in the catalog crate
//! because it is the same single-writer invariant `&mut self` already enforces
//! within a thread, extended across them. It started here, when the pool was
//! its only consumer; it moved when `shepherd-tier` needed it too and taking it
//! from the queue crate would have meant a `tier -> jobs` edge for a type with
//! nothing to do with queues.
//!
//! What is left here is the part that really is about jobs: the pool, the
//! registry, and the claim-run-complete loop.
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
use std::thread::JoinHandle;
use std::time::Duration;

use shepherd_catalog::job_repo::{Job, JobClass};
use shepherd_catalog::writer::{CatalogWriter, WriterError};
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
    pub fn save_checkpoint(&self, checkpoint_json: &str) -> Result<(), WriterError> {
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
                // The mixed idiom below is deliberate and load-bearing to read
                // correctly. `registry` and `stop` are `Arc`s, so `Arc::clone`
                // says "refcount bump" at the call site. `CatalogWriter` is NOT
                // an `Arc` — it is a `Sender<Msg>` newtype (see its definition:
                // "cloning the handle does not clone the connection"), so
                // `Arc::clone(&writer)` does not compile.
                //
                // Two independent `.clone()` audits both read this loop as an
                // inconsistency to harmonise. It is not. If you are here to make
                // these three lines match, check the type first.
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
            Err(WriterError::Gone) => return,
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
pub fn run_one(writer: &CatalogWriter, registry: &Registry) -> Result<bool, WriterError> {
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
pub fn recover(writer: &CatalogWriter) -> Result<Vec<Recovery>, WriterError> {
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
    use shepherd_catalog::Catalog;
    use shepherd_catalog::writer::CatalogActor;
    use std::sync::Mutex;

    fn actor_in_memory() -> CatalogActor {
        CatalogActor::start(Catalog::open_in_memory().unwrap(), None)
    }

    /// The pool's own use of the actor. The actor's *invariant* is tested where
    /// it now lives — `shepherd_catalog::writer::tests` — on a file-backed
    /// catalog; this is the in-memory version that the queue depends on.
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
}
