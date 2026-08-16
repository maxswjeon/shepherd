//! The durable job queue and its worker pool.
//!
//! # What is here, and what is Phase 4's
//!
//! §6 Phase 1 moves the queue *core* up from Phase 4, because Phase 2's AC-2
//! (kill the daemon mid-upload, restart, resume without re-sending verified
//! parts) and the M2 pipeline are not expressible without durable job
//! persistence, checkpointing and resume. The split is deliberate:
//!
//! | Phase 1 — this crate today | Phase 4 — not yet |
//! |---|---|
//! | durable enqueue/dequeue, job states, priority | `croner` schedules, anacron-style catch-up |
//! | `checkpoint_json` persistence and resume-on-restart | per-job-class power + network gating (OQ-2) |
//! | retry with backoff, `attempts`, `last_error` | adaptive concurrency + user hard caps |
//! | a fixed, conservative worker pool | bandwidth / metered caps, `scrub` cadence |
//!
//! # Layering
//!
//! ```text
//!   shepherd-catalog::job_repo   rows + the transitions that must be atomic
//!            ▲
//!   queue.rs                     policy: backoff curve, attempt ceiling,
//!            ▲                   which classes may retry, crash recovery
//!   worker.rs                    the single-writer actor, the fixed pool,
//!                                the class → executor registry
//! ```
//!
//! [`worker::CatalogWriter`] is the §9 Phase 1 gate's "single-writer actor":
//! exactly one thread owns the `Catalog`, everyone else sends it a closure.
//!
//! # The one safety rule in this crate
//!
//! **A `destroy` job is never retried and never auto-requeued after a crash.**
//! §4.10.4 specifies abort-forward-never recovery for the destroy path, and the
//! queue is the wrong layer to decide a partially-completed destruction is safe
//! to re-enter. [`queue::is_retryable`] and
//! [`queue::Queue::recover_interrupted`] both encode it, and both have a test
//! that fails if someone "simplifies" the special case away.

#![forbid(unsafe_code)]

pub mod queue;
pub mod worker;

pub use queue::{
    BASE_BACKOFF, Disposition, MAX_ATTEMPTS, MAX_BACKOFF, Queue, Recovery, backoff_for,
    is_retryable,
};
pub use worker::{
    CatalogActor, CatalogWriter, Executor, JobContext, POOL_SIZE, Pool, Registry, WorkerError,
    recover, run_one,
};
