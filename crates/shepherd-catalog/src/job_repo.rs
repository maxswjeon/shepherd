//! Reads and writes over `job`.
//!
//! **Scope.** This is storage for the job queue, not the queue. Durable
//! enqueue/dequeue semantics, the worker pool, checkpoint-and-resume and retry
//! backoff are T6's `shepherd-jobs::queue`/`::worker`. What lives here is the
//! row shape and the transitions that must be atomic against it, so that the
//! queue T6 builds has something correct to build on.

use rusqlite::{OptionalExtension, params};
use shepherd_core::{JobId, Timestamp};

use crate::{Catalog, CatalogError, Result};

/// Job classes, from §4.4.
///
/// `Scrub` is a first-class class rather than a background chore so it inherits
/// per-class power and network gating (OQ-2) and never runs on battery or a
/// metered link under the default preset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobClass {
    Scan,
    Hash,
    Extract,
    Tag,
    Embed,
    Upload,
    Verify,
    Destroy,
    Restore,
    Replicate,
    Scrub,
}

impl JobClass {
    pub fn as_str(self) -> &'static str {
        match self {
            JobClass::Scan => "scan",
            JobClass::Hash => "hash",
            JobClass::Extract => "extract",
            JobClass::Tag => "tag",
            JobClass::Embed => "embed",
            JobClass::Upload => "upload",
            JobClass::Verify => "verify",
            JobClass::Destroy => "destroy",
            JobClass::Restore => "restore",
            JobClass::Replicate => "replicate",
            JobClass::Scrub => "scrub",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "scan" => JobClass::Scan,
            "hash" => JobClass::Hash,
            "extract" => JobClass::Extract,
            "tag" => JobClass::Tag,
            "embed" => JobClass::Embed,
            "upload" => JobClass::Upload,
            "verify" => JobClass::Verify,
            "destroy" => JobClass::Destroy,
            "restore" => JobClass::Restore,
            "replicate" => JobClass::Replicate,
            "scrub" => JobClass::Scrub,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JobState {
    Queued,
    Running,
    Done,
    Failed,
}

impl JobState {
    pub fn as_str(self) -> &'static str {
        match self {
            JobState::Queued => "queued",
            JobState::Running => "running",
            JobState::Done => "done",
            JobState::Failed => "failed",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "queued" => JobState::Queued,
            "running" => JobState::Running,
            "done" => JobState::Done,
            "failed" => JobState::Failed,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Job {
    pub id: JobId,
    pub class: JobClass,
    pub state: JobState,
    pub priority: i64,
    pub payload_json: String,
    pub checkpoint_json: Option<String>,
    pub attempts: i64,
    pub last_error: Option<String>,
    /// Nanoseconds since the epoch before which this job is not claimable.
    /// `0` means "ready now". Written by the retry backoff in
    /// `shepherd-jobs::queue`; enforced here by [`JobRepo::claim_next`].
    pub run_after: i64,
}

pub struct JobRepo<'a>(pub &'a mut Catalog);

impl<'a> JobRepo<'a> {
    pub fn new(cat: &'a mut Catalog) -> Self {
        Self(cat)
    }

    pub fn enqueue(
        &mut self,
        class: JobClass,
        priority: i64,
        payload_json: &str,
        now: Timestamp,
    ) -> Result<JobId> {
        self.0.conn_mut().execute(
            "INSERT INTO job (class, state, priority, payload_json, created_at, updated_at)
             VALUES (?1, 'queued', ?2, ?3, ?4, ?4)",
            params![class.as_str(), priority, payload_json, now.as_nanos()],
        )?;
        Ok(JobId::new(self.0.conn().last_insert_rowid()))
    }

    pub fn get(&self, id: JobId) -> Result<Option<Job>> {
        self.0
            .conn()
            .query_row(
                "SELECT id, class, state, priority, payload_json, checkpoint_json,
                        attempts, last_error, run_after
                 FROM job WHERE id = ?1",
                params![id.get()],
                row_to_job,
            )
            .optional()
            .map_err(CatalogError::from)?
            .transpose()
    }

    /// Claim the highest-priority *ready* queued job atomically.
    ///
    /// The `UPDATE … WHERE state = 'queued'` with a subquery is one statement on
    /// purpose: a select-then-update would let two workers read the same row
    /// before either wrote. Single-writer discipline makes that unlikely, not
    /// impossible — the catalog is also opened by tests and by `shepctl
    /// doctor` — and a job claimed twice is a duplicated upload or, for the
    /// `destroy` class, a duplicated destruction attempt.
    ///
    /// "Ready" means `run_after <= now`. A job serving out a retry backoff is
    /// invisible here rather than being claimed and immediately re-failed,
    /// which would burn its `attempts` budget without ever waiting.
    pub fn claim_next(&mut self, now: Timestamp) -> Result<Option<JobId>> {
        self.claim_next_of(now, None)
    }

    /// Claim the highest-priority ready job **of one of `classes`**.
    ///
    /// `None` means any class, which is what [`JobRepo::claim_next`] passes.
    ///
    /// # Why the filter is here and not in the caller
    ///
    /// The obvious shape is to claim whatever is next and put it back if the
    /// caller cannot run it. That is what T6's worker pool did first, and it is
    /// wrong for a measurable reason: `claim_next` increments `attempts`, so a
    /// job of a class this build has no executor for accumulates attempts every
    /// time a worker looks at it. Measured at **12 attempts in 3 seconds** from
    /// a single polling thread; with a four-worker pool `MAX_ATTEMPTS` is
    /// exhausted in under two seconds. The job would then fail terminally on
    /// the *first* real failure once a later phase registered its executor.
    ///
    /// Filtering inside the claim means an unrunnable job is never claimed at
    /// all: no attempts inflation, no `last_error` stomped with a message about
    /// a missing executor, and no claim/requeue churn through the writer actor.
    pub fn claim_next_of(
        &mut self,
        now: Timestamp,
        classes: Option<&[JobClass]>,
    ) -> Result<Option<JobId>> {
        // An empty allowlist means "this build can run nothing", which must
        // claim nothing rather than degrading to "anything".
        if classes.is_some_and(<[JobClass]>::is_empty) {
            return Ok(None);
        }
        // Bound parameters, not interpolation.
        //
        // Interpolating `JobClass::as_str()` would be safe TODAY — it returns
        // one of a closed set of `&'static str` and never user input — and the
        // first version did exactly that with a comment saying so. The comment
        // was accurate; the shape was still wrong, because the safety rests on
        // an invariant held by nothing but the body of `as_str`, and the blast
        // radius is THIS statement: the single-statement claim whose atomicity
        // is what stops a `destroy` job being handed to two workers.
        //
        // A later variant carrying a runtime `String`, or a refactor letting a
        // plugin-supplied class through, would turn a correct comment into an
        // injection into the destroy claim — and would not look like a change
        // touching SQL. Placeholders cannot fail that way whatever `as_str`
        // becomes.
        //
        // `?1` is `now`, referenced twice; classes start at `?2`. Numbered
        // parameters handle the repeat, which positional `?` would not.
        let now_nanos = now.as_nanos();
        let class_names: Vec<&'static str> = classes
            .map(|cs| cs.iter().map(|c| c.as_str()).collect())
            .unwrap_or_default();
        let filter = if class_names.is_empty() {
            String::new()
        } else {
            let holes: Vec<String> = (0..class_names.len())
                .map(|i| format!("?{}", i + 2))
                .collect();
            format!(" AND class IN ({})", holes.join(", "))
        };
        let mut binds: Vec<&dyn rusqlite::ToSql> = Vec::with_capacity(class_names.len() + 1);
        binds.push(&now_nanos);
        for name in &class_names {
            binds.push(name);
        }
        let sql = format!(
            "UPDATE job SET state = 'running', attempts = attempts + 1, updated_at = ?1
             WHERE id = (
                 SELECT id FROM job
                 WHERE state = 'queued' AND run_after <= ?1{filter}
                 ORDER BY priority DESC, id ASC LIMIT 1
             )
             RETURNING id"
        );
        let tx = self.0.conn_mut().transaction()?;
        let claimed: Option<i64> = tx
            .query_row(&sql, rusqlite::params_from_iter(binds), |r| r.get(0))
            .optional()?;
        tx.commit()?;
        Ok(claimed.map(JobId::new))
    }

    /// Return a job to the queue, not claimable again until `run_after`.
    ///
    /// One statement, for the same reason `claim_next` is: the transition out of
    /// `running` and the deadline that governs the next claim must not be
    /// separately observable.
    ///
    /// `attempts` is deliberately **not** touched — `claim_next` already counted
    /// this attempt when it handed the job out. Incrementing here too would
    /// double-count and halve the effective retry budget.
    ///
    /// The backoff curve, the attempt ceiling, and the decision that a class is
    /// retryable at all belong to `shepherd-jobs::queue`. This is only the
    /// transition.
    pub fn requeue(
        &mut self,
        id: JobId,
        run_after: Timestamp,
        last_error: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE job
             SET state = 'queued', run_after = ?2, last_error = ?3, updated_at = ?4
             WHERE id = ?1",
            params![id.get(), run_after.as_nanos(), last_error, now.as_nanos()],
        )?;
        Ok(())
    }

    /// Persist a resume point. T6's worker calls this; the row shape is what
    /// makes "kill the daemon mid-upload, restart, resume without re-sending
    /// verified parts" (AC-2) expressible at all.
    pub fn checkpoint(&mut self, id: JobId, checkpoint_json: &str, now: Timestamp) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE job SET checkpoint_json = ?2, updated_at = ?3 WHERE id = ?1",
            params![id.get(), checkpoint_json, now.as_nanos()],
        )?;
        Ok(())
    }

    pub fn finish(
        &mut self,
        id: JobId,
        state: JobState,
        last_error: Option<&str>,
        now: Timestamp,
    ) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE job SET state = ?2, last_error = ?3, updated_at = ?4 WHERE id = ?1",
            params![id.get(), state.as_str(), last_error, now.as_nanos()],
        )?;
        Ok(())
    }

    /// Jobs left `running` by a crash.
    ///
    /// Requeueing is T6's decision, not this layer's: a `destroy` job found
    /// mid-flight must go through §4.10.4's abort-forward-never recovery, not be
    /// naively retried. This only reports them.
    pub fn interrupted(&self) -> Result<Vec<Job>> {
        let mut stmt = self.0.conn().prepare(
            "SELECT id, class, state, priority, payload_json, checkpoint_json,
                    attempts, last_error, run_after
             FROM job WHERE state = 'running' ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], row_to_job)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }
}

fn row_to_job(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<Job>> {
    let class: String = row.get(1)?;
    let state: String = row.get(2)?;
    Ok((|| {
        Ok(Job {
            id: JobId::new(row.get(0)?),
            class: JobClass::parse(&class)
                .ok_or_else(|| CatalogError::Invalid(format!("job class `{class}`")))?,
            state: JobState::parse(&state)
                .ok_or_else(|| CatalogError::Invalid(format!("job state `{state}`")))?,
            priority: row.get(3)?,
            payload_json: row.get(4)?,
            checkpoint_json: row.get(5)?,
            attempts: row.get(6)?,
            last_error: row.get(7)?,
            run_after: row.get(8)?,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cat() -> Catalog {
        Catalog::open_in_memory().unwrap()
    }

    #[test]
    fn claim_order_is_priority_then_insertion() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        let mut r = JobRepo::new(&mut c);
        let low = r.enqueue(JobClass::Scan, 0, "{}", t).unwrap();
        let high = r.enqueue(JobClass::Upload, 10, "{}", t).unwrap();
        let low2 = r.enqueue(JobClass::Scan, 0, "{}", t).unwrap();

        assert_eq!(JobRepo::new(&mut c).claim_next(t).unwrap(), Some(high));
        assert_eq!(JobRepo::new(&mut c).claim_next(t).unwrap(), Some(low));
        assert_eq!(JobRepo::new(&mut c).claim_next(t).unwrap(), Some(low2));
        assert_eq!(JobRepo::new(&mut c).claim_next(t).unwrap(), None);
    }

    /// A claimed job must not be claimable again. For the `destroy` class this
    /// is the difference between one destruction attempt and two.
    #[test]
    fn a_claimed_job_is_not_handed_out_twice() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        JobRepo::new(&mut c)
            .enqueue(JobClass::Destroy, 0, "{}", t)
            .unwrap();
        assert!(JobRepo::new(&mut c).claim_next(t).unwrap().is_some());
        assert!(
            JobRepo::new(&mut c).claim_next(t).unwrap().is_none(),
            "a running job must not be re-claimed"
        );
    }

    #[test]
    fn claiming_counts_the_attempt() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        let id = JobRepo::new(&mut c)
            .enqueue(JobClass::Hash, 0, "{}", t)
            .unwrap();
        JobRepo::new(&mut c).claim_next(t).unwrap();
        assert_eq!(JobRepo::new(&mut c).get(id).unwrap().unwrap().attempts, 1);
    }

    #[test]
    fn checkpoints_round_trip() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        let id = JobRepo::new(&mut c)
            .enqueue(JobClass::Upload, 0, "{}", t)
            .unwrap();
        JobRepo::new(&mut c)
            .checkpoint(id, r#"{"parts_done":7}"#, t)
            .unwrap();
        let j = JobRepo::new(&mut c).get(id).unwrap().unwrap();
        assert_eq!(j.checkpoint_json.as_deref(), Some(r#"{"parts_done":7}"#));
    }

    /// A crash leaves `running` rows. They are REPORTED, not auto-requeued: a
    /// destroy job mid-flight needs §4.10.4's recovery, not a naive retry.
    #[test]
    fn interrupted_jobs_are_reported_not_requeued() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        JobRepo::new(&mut c)
            .enqueue(JobClass::Destroy, 0, "{}", t)
            .unwrap();
        JobRepo::new(&mut c).claim_next(t).unwrap();

        let stranded = JobRepo::new(&mut c).interrupted().unwrap();
        assert_eq!(stranded.len(), 1);
        assert_eq!(stranded[0].class, JobClass::Destroy);
        assert_eq!(stranded[0].state, JobState::Running);
        // Still running: nothing put it back in the queue behind our back.
        assert!(JobRepo::new(&mut c).claim_next(t).unwrap().is_none());
    }

    /// The point of the column: a job inside its backoff window is invisible to
    /// `claim_next`, and becomes claimable the instant the deadline passes.
    #[test]
    fn a_job_in_backoff_is_not_claimable_until_its_deadline() {
        let mut c = cat();
        let t0 = Timestamp::from_nanos(1_000);
        let id = JobRepo::new(&mut c)
            .enqueue(JobClass::Upload, 0, "{}", t0)
            .unwrap();
        assert_eq!(JobRepo::new(&mut c).claim_next(t0).unwrap(), Some(id));

        // Failed, retry in 500ns.
        let deadline = Timestamp::from_nanos(1_500);
        JobRepo::new(&mut c)
            .requeue(id, deadline, Some("connection reset"), t0)
            .unwrap();

        for too_early in [1_000, 1_499] {
            assert_eq!(
                JobRepo::new(&mut c)
                    .claim_next(Timestamp::from_nanos(too_early))
                    .unwrap(),
                None,
                "claimable at {too_early}, before its run_after of 1500"
            );
        }
        assert_eq!(
            JobRepo::new(&mut c).claim_next(deadline).unwrap(),
            Some(id),
            "the deadline is inclusive: at run_after the job is ready"
        );
    }

    /// A backed-off job must not block a ready one behind it. Without the
    /// `run_after` filter in the subquery the head-of-line job would be picked,
    /// re-failed and the queue would stall on it.
    #[test]
    fn backoff_does_not_block_the_rest_of_the_queue() {
        let mut c = cat();
        let t = Timestamp::from_nanos(100);
        let stalled = JobRepo::new(&mut c)
            .enqueue(JobClass::Upload, 10, "{}", t)
            .unwrap();
        let ready = JobRepo::new(&mut c)
            .enqueue(JobClass::Hash, 0, "{}", t)
            .unwrap();

        JobRepo::new(&mut c).claim_next(t).unwrap(); // takes `stalled`, higher priority
        JobRepo::new(&mut c)
            .requeue(stalled, Timestamp::from_nanos(9_999), Some("429"), t)
            .unwrap();

        assert_eq!(
            JobRepo::new(&mut c).claim_next(t).unwrap(),
            Some(ready),
            "the lower-priority ready job must be served while the other waits"
        );
    }

    /// `claim_next` already counted the attempt. If `requeue` counted it too,
    /// a 5-attempt budget would be spent in 3 failures.
    #[test]
    fn requeue_does_not_double_count_the_attempt() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        let id = JobRepo::new(&mut c)
            .enqueue(JobClass::Hash, 0, "{}", t)
            .unwrap();
        JobRepo::new(&mut c).claim_next(t).unwrap();
        JobRepo::new(&mut c)
            .requeue(id, t, Some("boom"), t)
            .unwrap();
        assert_eq!(JobRepo::new(&mut c).get(id).unwrap().unwrap().attempts, 1);

        JobRepo::new(&mut c).claim_next(t).unwrap();
        assert_eq!(JobRepo::new(&mut c).get(id).unwrap().unwrap().attempts, 2);
    }

    /// Requeue preserves the resume point. AC-2 is "resume without re-sending
    /// verified parts"; a retry that cleared the checkpoint would re-send them.
    #[test]
    fn requeue_preserves_the_checkpoint_and_records_the_error() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        let id = JobRepo::new(&mut c)
            .enqueue(JobClass::Upload, 0, "{}", t)
            .unwrap();
        JobRepo::new(&mut c).claim_next(t).unwrap();
        JobRepo::new(&mut c)
            .checkpoint(id, r#"{"parts_done":7}"#, t)
            .unwrap();
        JobRepo::new(&mut c)
            .requeue(id, t, Some("connection reset"), t)
            .unwrap();

        let j = JobRepo::new(&mut c).get(id).unwrap().unwrap();
        assert_eq!(j.state, JobState::Queued);
        assert_eq!(j.checkpoint_json.as_deref(), Some(r#"{"parts_done":7}"#));
        assert_eq!(j.last_error.as_deref(), Some("connection reset"));
    }

    /// Rows written before migration 0002 must be claimable immediately rather
    /// than stranded behind a NULL or a bogus deadline.
    #[test]
    fn rows_predating_the_migration_default_to_ready() {
        let mut c = cat();
        let t = Timestamp::from_nanos(42);
        let id = JobRepo::new(&mut c)
            .enqueue(JobClass::Scan, 0, "{}", t)
            .unwrap();
        assert_eq!(JobRepo::new(&mut c).get(id).unwrap().unwrap().run_after, 0);
        assert_eq!(JobRepo::new(&mut c).claim_next(t).unwrap(), Some(id));
    }

    /// A requeued job is invisible until its backoff elapses. Without the
    /// `run_after <= now` clause, a failing job would be re-claimed instantly
    /// and spin.
    #[test]
    fn a_requeued_job_is_not_claimable_before_its_deadline() {
        let mut c = cat();
        let t0 = Timestamp::from_nanos(1_000);
        let id = JobRepo::new(&mut c)
            .enqueue(JobClass::Upload, 0, "{}", t0)
            .unwrap();
        JobRepo::new(&mut c).claim_next(t0).unwrap();

        JobRepo::new(&mut c)
            .requeue(id, Timestamp::from_nanos(5_000), Some("transient"), t0)
            .unwrap();

        assert_eq!(
            JobRepo::new(&mut c)
                .claim_next(Timestamp::from_nanos(4_999))
                .unwrap(),
            None,
            "still backing off"
        );
        assert_eq!(
            JobRepo::new(&mut c)
                .claim_next(Timestamp::from_nanos(5_000))
                .unwrap(),
            Some(id),
            "claimable once the deadline is reached"
        );
        let j = JobRepo::new(&mut c).get(id).unwrap().unwrap();
        assert_eq!(j.attempts, 2, "each claim counts an attempt");
        assert_eq!(j.last_error.as_deref(), Some("transient"));
    }

    /// A job with no backoff is claimable immediately — `run_after` defaults to
    /// 0, so the new clause must not gate ordinary work.
    #[test]
    fn a_fresh_job_is_claimable_at_any_time() {
        let mut c = cat();
        let id = JobRepo::new(&mut c)
            .enqueue(JobClass::Scan, 0, "{}", Timestamp::from_nanos(1))
            .unwrap();
        assert_eq!(
            JobRepo::new(&mut c)
                .claim_next(Timestamp::from_nanos(1))
                .unwrap(),
            Some(id)
        );
    }

    /// The defect this exists to prevent, pinned: a class the caller cannot run
    /// must not be claimed, because claiming counts an attempt.
    #[test]
    fn a_class_outside_the_allowlist_is_never_claimed() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        let embed = JobRepo::new(&mut c)
            .enqueue(JobClass::Embed, 10, "{}", t)
            .unwrap();
        let hash = JobRepo::new(&mut c)
            .enqueue(JobClass::Hash, 0, "{}", t)
            .unwrap();

        // Repeatedly poll for only what we can run. The higher-priority Embed
        // job must be skipped entirely, not claimed and returned.
        for _ in 0..50 {
            let got = JobRepo::new(&mut c)
                .claim_next_of(t, Some(&[JobClass::Hash]))
                .unwrap();
            if let Some(id) = got {
                assert_eq!(id, hash);
                JobRepo::new(&mut c)
                    .finish(id, JobState::Done, None, t)
                    .unwrap();
            }
        }
        let j = JobRepo::new(&mut c).get(embed).unwrap().unwrap();
        assert_eq!(
            j.attempts, 0,
            "an unrunnable job must accumulate no attempts, saw {}",
            j.attempts
        );
        assert_eq!(j.state, JobState::Queued);
        assert!(
            j.last_error.is_none(),
            "and its last_error must be untouched"
        );
    }

    #[test]
    fn an_empty_allowlist_claims_nothing_rather_than_everything() {
        let mut c = cat();
        let t = Timestamp::from_nanos(1);
        JobRepo::new(&mut c)
            .enqueue(JobClass::Scan, 0, "{}", t)
            .unwrap();
        assert_eq!(
            JobRepo::new(&mut c).claim_next_of(t, Some(&[])).unwrap(),
            None
        );
        // And `None` still means "any", so the old behaviour is intact.
        assert!(
            JobRepo::new(&mut c)
                .claim_next_of(t, None)
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn the_allowlist_still_honours_priority_and_backoff() {
        let mut c = cat();
        let t = Timestamp::from_nanos(100);
        let low = JobRepo::new(&mut c)
            .enqueue(JobClass::Hash, 0, "{}", t)
            .unwrap();
        let high = JobRepo::new(&mut c)
            .enqueue(JobClass::Hash, 10, "{}", t)
            .unwrap();
        let allow = [JobClass::Hash, JobClass::Scan];
        assert_eq!(
            JobRepo::new(&mut c).claim_next_of(t, Some(&allow)).unwrap(),
            Some(high)
        );
        JobRepo::new(&mut c)
            .requeue(high, Timestamp::from_nanos(9_999), Some("x"), t)
            .unwrap();
        assert_eq!(
            JobRepo::new(&mut c).claim_next_of(t, Some(&allow)).unwrap(),
            Some(low),
            "backoff still applies inside the allowlist"
        );
    }

    #[test]
    fn an_unknown_class_is_refused_by_the_schema() {
        let mut c = cat();
        let err = c.conn_mut().execute(
            "INSERT INTO job (class, state, payload_json, created_at, updated_at)
             VALUES ('mine-bitcoin', 'queued', '{}', 1, 1)",
            [],
        );
        assert!(
            err.is_err(),
            "job.class is CHECK-constrained to §4.4's list"
        );
    }

    #[test]
    fn class_strings_round_trip_with_the_check_constraint() {
        for c in [
            JobClass::Scan,
            JobClass::Hash,
            JobClass::Extract,
            JobClass::Tag,
            JobClass::Embed,
            JobClass::Upload,
            JobClass::Verify,
            JobClass::Destroy,
            JobClass::Restore,
            JobClass::Replicate,
            JobClass::Scrub,
        ] {
            assert_eq!(JobClass::parse(c.as_str()), Some(c));
        }
    }
}
