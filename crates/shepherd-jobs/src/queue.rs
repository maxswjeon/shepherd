//! The durable job queue: enqueue, claim, complete, retry with backoff, and
//! crash recovery.
//!
//! # Where the line between this and `shepherd-catalog` falls
//!
//! `shepherd_catalog::job_repo` owns the **row transitions that must be
//! atomic** — claiming a job in one statement so it cannot be handed out twice,
//! requeueing it in one statement so the state change and its deadline are not
//! separately observable. This module owns the **policy**: how long a backoff
//! is, how many attempts a class gets, whether a class may be retried at all,
//! and what happens to a job a crash left mid-flight.
//!
//! That split is why the backoff curve is testable without a database and why
//! changing it is not a migration.
//!
//! # Scope: the queue *core* only
//!
//! §6 Phase 1 splits the queue deliberately, and the right-hand column is
//! **not** in this crate yet:
//!
//! | Phase 1 — here | Phase 4 — not here |
//! |---|---|
//! | durable enqueue/dequeue, job states, priority | `croner` schedules, anacron-style catch-up |
//! | `checkpoint_json` persistence and resume-on-restart | per-job-class power + network gating (OQ-2) |
//! | retry with backoff, `attempts`, `last_error` | adaptive concurrency + user hard caps |
//! | a fixed, conservative worker pool | bandwidth / metered caps, `scrub` cadence |
//!
//! Nothing here consults battery state, network metering or a clock schedule.
//! A job is ready when it is `queued` and its `run_after` has passed, and that
//! is the whole readiness predicate at Phase 1.

use shepherd_catalog::job_repo::{Job, JobClass, JobRepo, JobState};
use shepherd_catalog::{Catalog, CatalogError};
use shepherd_core::{JobId, Timestamp};

/// How many times a job is handed out before it is failed for good.
///
/// Counted as *attempts*, not retries: `attempts == MAX_ATTEMPTS` means the job
/// has run that many times and will not run again.
pub const MAX_ATTEMPTS: i64 = 5;

/// First retry delay. Doubles per attempt up to [`MAX_BACKOFF`].
pub const BASE_BACKOFF: std::time::Duration = std::time::Duration::from_secs(2);

/// Ceiling on the backoff delay.
///
/// Without a ceiling, attempt 5 of an exponential curve is far enough out that
/// a transient outage turns into a job that looks abandoned. Five minutes is
/// short enough that a user watching `shepctl status` sees movement.
pub const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(300);

/// What the queue decided to do with a finished attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    /// Succeeded; the row is `done`.
    Done,
    /// Failed, and will be retried at this time.
    Retry { at: Timestamp, attempt: i64 },
    /// Failed and out of attempts, or failed in a way that is not retryable;
    /// the row is `failed` and nothing will pick it up again.
    Failed { reason: String },
}

/// What recovery decided about a job a crash left in `running`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recovery {
    /// Returned to the queue with its checkpoint intact.
    Requeued(JobId),
    /// Left exactly as it was, for a human or a later phase to resolve.
    Quarantined { id: JobId, why: String },
}

/// Whether a failed job of this class may be handed out again.
///
/// **`Destroy` is not retryable, and this is a safety property, not a tuning
/// choice.** §4.10.4 specifies abort-forward-never recovery for the destroy
/// path: a destroy that failed partway has already moved through states that a
/// naive re-run would re-enter with stale preconditions — a revalidated remote
/// version, an exclusive-access window, an fsync'd intent journal entry. The
/// queue is the wrong layer to decide it is safe to try again, so it does not.
///
/// Phase 1 cannot execute a destroy job at all. This is written now because the
/// plan's own addendum warns that this class of decision gets "simplified" back
/// in by a later contributor who sees a retry policy with a hole in it.
pub const fn is_retryable(class: JobClass) -> bool {
    !matches!(class, JobClass::Destroy)
}

/// Delay before attempt `attempts + 1`, given that `attempts` have been made.
///
/// Exponential, doubling, capped. Deliberately **not** jittered: Shepherd's
/// queue is single-process with a fixed small pool, so there is no thundering
/// herd to spread — jitter would only make the backoff untestable in exchange
/// for solving a problem this design does not have. A future multi-node or
/// server-fanout deployment is when to add it.
pub fn backoff_for(attempts: i64) -> std::time::Duration {
    let exponent = attempts.saturating_sub(1).clamp(0, 16) as u32;
    BASE_BACKOFF
        .saturating_mul(1u32 << exponent)
        .min(MAX_BACKOFF)
}

/// The durable queue, over a catalog the caller owns.
///
/// Takes `&mut Catalog` per call rather than holding it, so the single-writer
/// actor in [`crate::worker`] stays the only thing that owns the connection.
pub struct Queue;

impl Queue {
    /// Enqueue a job. `payload_json` is opaque here and interpreted by the
    /// executor registered for `class`.
    pub fn enqueue(
        cat: &mut Catalog,
        class: JobClass,
        priority: i64,
        payload_json: &str,
        now: Timestamp,
    ) -> Result<JobId, CatalogError> {
        JobRepo::new(cat).enqueue(class, priority, payload_json, now)
    }

    /// Claim the highest-priority ready job, if any, and return it whole.
    ///
    /// Two statements — claim, then read — but only the claim needs to be
    /// atomic. Once a row is `running` nothing else will touch it, so reading
    /// it afterwards cannot race.
    pub fn claim(cat: &mut Catalog, now: Timestamp) -> Result<Option<Job>, CatalogError> {
        Self::claim_of(cat, now, None)
    }

    /// Claim the highest-priority ready job whose class is in `classes`.
    ///
    /// The pool passes what it has executors for. A job of any other class is
    /// **never claimed**, rather than claimed and handed back: claiming counts
    /// an attempt, so polling for a class this build cannot run would exhaust
    /// that job's retry budget before the phase that implements it ever sees
    /// it. See `JobRepo::claim_next_of`.
    pub fn claim_of(
        cat: &mut Catalog,
        now: Timestamp,
        classes: Option<&[JobClass]>,
    ) -> Result<Option<Job>, CatalogError> {
        let Some(id) = JobRepo::new(cat).claim_next_of(now, classes)? else {
            return Ok(None);
        };
        JobRepo::new(cat).get(id)
    }

    /// Persist a resume point for a running job.
    pub fn checkpoint(
        cat: &mut Catalog,
        id: JobId,
        checkpoint_json: &str,
        now: Timestamp,
    ) -> Result<(), CatalogError> {
        JobRepo::new(cat).checkpoint(id, checkpoint_json, now)
    }

    /// Mark a claimed job successful.
    pub fn complete(
        cat: &mut Catalog,
        id: JobId,
        now: Timestamp,
    ) -> Result<Disposition, CatalogError> {
        JobRepo::new(cat).finish(id, JobState::Done, None, now)?;
        Ok(Disposition::Done)
    }

    /// Record a failed attempt and decide whether it gets another.
    ///
    /// The decision is made here, in one place, so "why did this job stop
    /// retrying" has a single answer: it exhausted [`MAX_ATTEMPTS`], or its
    /// class is not retryable.
    pub fn fail(
        cat: &mut Catalog,
        job: &Job,
        error: &str,
        now: Timestamp,
    ) -> Result<Disposition, CatalogError> {
        if !is_retryable(job.class) {
            let reason = format!(
                "{} jobs are never retried automatically (§4.10.4 abort-forward-never): {error}",
                job.class.as_str()
            );
            JobRepo::new(cat).finish(job.id, JobState::Failed, Some(&reason), now)?;
            return Ok(Disposition::Failed { reason });
        }

        if job.attempts >= MAX_ATTEMPTS {
            let reason = format!("giving up after {} attempts: {error}", job.attempts);
            JobRepo::new(cat).finish(job.id, JobState::Failed, Some(&reason), now)?;
            return Ok(Disposition::Failed { reason });
        }

        let delay = backoff_for(job.attempts);
        let at = Timestamp::from_nanos(now.as_nanos().saturating_add(delay.as_nanos() as i64));
        JobRepo::new(cat).requeue(job.id, at, Some(error), now)?;
        Ok(Disposition::Retry {
            at,
            attempt: job.attempts + 1,
        })
    }

    /// Resolve every job a crash left in `running`. Call once at startup,
    /// before the worker pool starts.
    ///
    /// **Class-aware, deliberately.** A blanket "requeue everything still
    /// running" loop is the obvious implementation and it is wrong: it would
    /// re-run an interrupted `destroy`, which §4.10.4 forbids. Non-destructive
    /// classes come back with their checkpoint intact — that is what makes AC-2
    /// (kill mid-upload, restart, resume without re-sending verified parts)
    /// work. `destroy` is left untouched and reported, so it surfaces in
    /// `doctor` rather than being silently resumed or silently dropped.
    ///
    /// Recovered jobs are made ready immediately (`run_after = 0`): the process
    /// has just restarted, so whatever transient condition justified a backoff
    /// is no longer the current state of the world.
    pub fn recover_interrupted(
        cat: &mut Catalog,
        now: Timestamp,
    ) -> Result<Vec<Recovery>, CatalogError> {
        let stranded = JobRepo::new(cat).interrupted()?;
        let mut out = Vec::with_capacity(stranded.len());
        for job in stranded {
            if is_retryable(job.class) {
                JobRepo::new(cat).requeue(
                    job.id,
                    Timestamp::EPOCH,
                    Some("requeued after an unclean shutdown"),
                    now,
                )?;
                out.push(Recovery::Requeued(job.id));
            } else {
                out.push(Recovery::Quarantined {
                    id: job.id,
                    why: format!(
                        "a `{}` job was interrupted mid-flight. §4.10.4 requires \
                         abort-forward-never recovery, which the queue must not attempt \
                         automatically. Left in `running` for inspection.",
                        job.class.as_str()
                    ),
                });
            }
        }
        Ok(out)
    }

    /// Queue depth per class, for `status` (AC-49) and `doctor`.
    pub fn depth(cat: &Catalog) -> Result<Vec<ClassDepth>, CatalogError> {
        let mut stmt = cat.conn().prepare(
            "SELECT class,
                    SUM(state = 'queued')  AS pending,
                    SUM(state = 'running') AS running,
                    SUM(state = 'failed')  AS failed
             FROM job GROUP BY class ORDER BY class",
        )?;
        let rows = stmt
            .query_map([], |r| {
                Ok(ClassDepth {
                    class: r.get::<_, String>(0)?,
                    pending: r.get::<_, i64>(1)? as u64,
                    running: r.get::<_, i64>(2)? as u64,
                    failed: r.get::<_, i64>(3)? as u64,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(rows)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassDepth {
    pub class: String,
    pub pending: u64,
    pub running: u64,
    pub failed: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat() -> Catalog {
        Catalog::open_in_memory().unwrap()
    }
    fn t(n: i64) -> Timestamp {
        Timestamp::from_nanos(n)
    }

    #[test]
    fn backoff_doubles_then_saturates() {
        assert_eq!(backoff_for(1), BASE_BACKOFF);
        assert_eq!(backoff_for(2), BASE_BACKOFF * 2);
        assert_eq!(backoff_for(3), BASE_BACKOFF * 4);
        assert_eq!(backoff_for(4), BASE_BACKOFF * 8);
        assert_eq!(
            backoff_for(50),
            MAX_BACKOFF,
            "must saturate, never overflow"
        );
        // attempts = 0 should not underflow into a huge shift.
        assert_eq!(backoff_for(0), BASE_BACKOFF);
    }

    #[test]
    fn a_transient_failure_is_retried_with_a_growing_delay() {
        let mut c = cat();
        let id = Queue::enqueue(&mut c, JobClass::Upload, 0, "{}", t(0)).unwrap();

        let job = Queue::claim(&mut c, t(0)).unwrap().unwrap();
        assert_eq!(job.id, id);
        assert_eq!(job.attempts, 1);

        let d = Queue::fail(&mut c, &job, "connection reset", t(0)).unwrap();
        let Disposition::Retry { at, attempt } = d else {
            panic!("expected a retry, got {d:?}");
        };
        assert_eq!(attempt, 2);
        assert_eq!(at.as_nanos(), BASE_BACKOFF.as_nanos() as i64);

        // Not claimable before the deadline; claimable at it.
        assert!(
            Queue::claim(&mut c, t(at.as_nanos() - 1))
                .unwrap()
                .is_none()
        );
        let again = Queue::claim(&mut c, at).unwrap().unwrap();
        assert_eq!(again.attempts, 2);
    }

    #[test]
    fn a_job_is_failed_for_good_once_it_runs_out_of_attempts() {
        let mut c = cat();
        Queue::enqueue(&mut c, JobClass::Hash, 0, "{}", t(0)).unwrap();

        let mut now = 0i64;
        let mut last = None;
        for _ in 0..MAX_ATTEMPTS {
            let job = Queue::claim(&mut c, t(now))
                .unwrap()
                .expect("still retryable");
            last = Some(Queue::fail(&mut c, &job, "boom", t(now)).unwrap());
            now += MAX_BACKOFF.as_nanos() as i64;
        }

        let Some(Disposition::Failed { reason }) = last else {
            panic!("expected a terminal failure, got {last:?}");
        };
        assert!(reason.contains("5 attempts"), "{reason}");
        assert!(
            Queue::claim(&mut c, t(now)).unwrap().is_none(),
            "a failed job must never be handed out again"
        );
    }

    /// The safety property. A `destroy` job that fails is not retried, ever,
    /// regardless of attempts remaining.
    #[test]
    fn a_destroy_job_is_never_retried() {
        let mut c = cat();
        Queue::enqueue(&mut c, JobClass::Destroy, 0, "{}", t(0)).unwrap();
        let job = Queue::claim(&mut c, t(0)).unwrap().unwrap();
        assert_eq!(job.attempts, 1, "attempts remain, so exhaustion is not why");

        let d = Queue::fail(&mut c, &job, "remote version changed", t(0)).unwrap();
        let Disposition::Failed { reason } = d else {
            panic!("a destroy failure must be terminal, got {d:?}");
        };
        assert!(reason.contains("abort-forward-never"), "{reason}");
        assert!(
            Queue::claim(&mut c, t(i64::MAX / 2)).unwrap().is_none(),
            "no amount of waiting may make a failed destroy claimable"
        );
    }

    #[test]
    fn retryability_is_a_property_of_the_class() {
        assert!(!is_retryable(JobClass::Destroy));
        for c in [
            JobClass::Scan,
            JobClass::Hash,
            JobClass::Extract,
            JobClass::Tag,
            JobClass::Embed,
            JobClass::Upload,
            JobClass::Verify,
            JobClass::Restore,
            JobClass::Replicate,
            JobClass::Scrub,
        ] {
            assert!(is_retryable(c), "{c:?}");
        }
    }

    /// AC-2's shape at the queue layer: an interrupted upload comes back with
    /// its resume point, so the work already done is not repeated.
    #[test]
    fn recovery_requeues_a_non_destructive_job_with_its_checkpoint() {
        let mut c = cat();
        let id = Queue::enqueue(&mut c, JobClass::Upload, 0, "{}", t(0)).unwrap();
        Queue::claim(&mut c, t(0)).unwrap();
        Queue::checkpoint(&mut c, id, r#"{"parts_done":7}"#, t(0)).unwrap();
        // ... daemon dies here ...

        let recovered = Queue::recover_interrupted(&mut c, t(10)).unwrap();
        assert_eq!(recovered, vec![Recovery::Requeued(id)]);

        let job = Queue::claim(&mut c, t(10))
            .unwrap()
            .expect("claimable again");
        assert_eq!(job.id, id);
        assert_eq!(
            job.checkpoint_json.as_deref(),
            Some(r#"{"parts_done":7}"#),
            "the resume point is the whole point of AC-2"
        );
    }

    /// The blanket-requeue regression, pinned. A crash-interrupted destroy must
    /// not come back as an ordinary queued job.
    #[test]
    fn recovery_quarantines_an_interrupted_destroy_instead_of_requeueing_it() {
        let mut c = cat();
        let id = Queue::enqueue(&mut c, JobClass::Destroy, 0, "{}", t(0)).unwrap();
        Queue::claim(&mut c, t(0)).unwrap();

        let recovered = Queue::recover_interrupted(&mut c, t(10)).unwrap();
        match &recovered[..] {
            [Recovery::Quarantined { id: got, why }] => {
                assert_eq!(*got, id);
                assert!(why.contains("abort-forward-never"), "{why}");
            }
            other => panic!("expected quarantine, got {other:?}"),
        }
        assert!(
            Queue::claim(&mut c, t(10)).unwrap().is_none(),
            "a quarantined destroy must not be claimable"
        );
    }

    #[test]
    fn recovery_handles_a_mixed_batch_and_is_idempotent() {
        let mut c = cat();
        let up = Queue::enqueue(&mut c, JobClass::Upload, 10, "{}", t(0)).unwrap();
        let de = Queue::enqueue(&mut c, JobClass::Destroy, 5, "{}", t(0)).unwrap();
        Queue::claim(&mut c, t(0)).unwrap();
        Queue::claim(&mut c, t(0)).unwrap();

        let first = Queue::recover_interrupted(&mut c, t(1)).unwrap();
        assert_eq!(first.len(), 2);
        assert!(first.contains(&Recovery::Requeued(up)));

        // Running it again must not re-report the upload (it is queued now) and
        // must still report the quarantined destroy.
        let second = Queue::recover_interrupted(&mut c, t(2)).unwrap();
        assert_eq!(second.len(), 1);
        assert!(matches!(&second[0], Recovery::Quarantined { id, .. } if *id == de));
    }

    #[test]
    fn recovery_clears_any_backoff_the_crash_interrupted() {
        // A job that was backing off, then got claimed, then the process died.
        // On restart the transient condition is no longer current, so it should
        // be ready immediately rather than waiting out a stale deadline.
        let mut c = cat();
        let id = Queue::enqueue(&mut c, JobClass::Hash, 0, "{}", t(0)).unwrap();
        let job = Queue::claim(&mut c, t(0)).unwrap().unwrap();
        Queue::fail(&mut c, &job, "transient", t(0)).unwrap();
        let resumed_at = t(BASE_BACKOFF.as_nanos() as i64);
        Queue::claim(&mut c, resumed_at).unwrap();

        Queue::recover_interrupted(&mut c, t(1)).unwrap();
        let job = Queue::claim(&mut c, t(1)).unwrap().expect("ready now");
        assert_eq!(job.id, id);
    }

    #[test]
    fn depth_reports_per_class_counts() {
        let mut c = cat();
        Queue::enqueue(&mut c, JobClass::Scan, 0, "{}", t(0)).unwrap();
        Queue::enqueue(&mut c, JobClass::Scan, 0, "{}", t(0)).unwrap();
        Queue::enqueue(&mut c, JobClass::Hash, 0, "{}", t(0)).unwrap();
        Queue::claim(&mut c, t(0)).unwrap();

        let d = Queue::depth(&c).unwrap();
        let scan = d.iter().find(|x| x.class == "scan").unwrap();
        assert_eq!((scan.pending, scan.running), (1, 1));
        let hash = d.iter().find(|x| x.class == "hash").unwrap();
        assert_eq!((hash.pending, hash.running), (1, 0));
    }

    #[test]
    fn priority_then_insertion_order_survives_the_queue_layer() {
        let mut c = cat();
        let low = Queue::enqueue(&mut c, JobClass::Scan, 0, "{}", t(0)).unwrap();
        let high = Queue::enqueue(&mut c, JobClass::Upload, 10, "{}", t(0)).unwrap();
        assert_eq!(Queue::claim(&mut c, t(0)).unwrap().unwrap().id, high);
        assert_eq!(Queue::claim(&mut c, t(0)).unwrap().unwrap().id, low);
    }
}
