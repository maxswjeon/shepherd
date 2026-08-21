//! §4.10.5 — blast-radius controls.
//!
//! Three mechanisms, and each exists because a specific cheaper version of it
//! was shown not to hold.
//!
//! # 1. The rate breaker is a persisted ROLLING window, not a per-batch cap
//!
//! A per-`batch_id` cap alone is evadable by arithmetic: run the pass twice
//! with half the candidates, or wait for the process to restart. So the window
//! is keyed by `(target, root)` and **persisted** — `discard_rate_window` in
//! §4.4 — so repeated sub-threshold passes accumulate against the same budget
//! and a restart does not reset it. The per-batch cap is retained *in addition*,
//! not replaced.
//!
//! # 2. Confirmation binds to an immutable candidate-set hash
//!
//! Iteration 1 claimed "a 200-item pass destroys nothing before confirmation"
//! without requiring the preflight that makes the claim true. So:
//!
//! * the **complete** candidate set is enumerated and durably held **before the
//!   first delete** — [`Episode::enumerate`];
//! * confirmation binds to `candidate_set_blake3`, and **expires when the set
//!   changes** ([`Episode::confirm`] / [`Episode::may_execute`]).
//!
//! A confirmation that survived a changed set would authorize destroying files
//! the human never saw, which is the entire failure this guards.
//!
//! # 3. A hold escalates; it does not time out into action
//!
//! §4.10.5 is explicit: a held discard queue blocks only the `destroy` and
//! `discard` classes **for that target** — every other job class continues —
//! and it "does **not** time out into action — it escalates". [`HoldScope`]
//! encodes the first half and [`Episode::may_execute`] the second: an expired
//! confirmation returns to [`EpisodeState::Held`], never to
//! [`EpisodeState::Confirmed`].

use serde::{Deserialize, Serialize};
use shepherd_catalog::job_repo::JobClass;
use shepherd_core::{Blake3Hash, FileId, RootId, TargetId, Timestamp};

/// Default rolling window: 24 hours.
pub const DEFAULT_WINDOW_NANOS: i64 = 24 * 3_600 * 1_000_000_000;

/// How long a human confirmation stays good.
pub const DEFAULT_CONFIRMATION_TTL_NANOS: i64 = 3_600 * 1_000_000_000;

/// Breaker limits, per `(target, root)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BreakerLimits {
    /// Most discards permitted inside one rolling window.
    pub max_in_window: u32,
    /// The rolling window's length. **Must be positive** — see
    /// [`BreakerLimits::validate`].
    pub window_nanos: i64,
    /// Per-episode cap, retained alongside the rolling window.
    pub max_per_episode: u32,
}

impl BreakerLimits {
    /// Refuse limits that would disable the breaker instead of enforcing it.
    ///
    /// `BreakerLimits` is `Deserialize`, so these arrive from a config file and
    /// nothing rejected a nonpositive window. With `window_nanos == 0` the
    /// floor is `now` and `count_within`'s strict `>` excludes even the bucket
    /// just recorded at `now`, so every call sees `used == 0` and an unbounded
    /// sequence of individually sub-limit episodes is permitted — the rolling
    /// budget silently switched off, in the direction that destroys data. A
    /// negative window moves the floor into the future and does the same.
    ///
    /// Checked where the budget is EVALUATED and where it is CONSUMED, not once
    /// at load: a value that can be deserialized anywhere has no single door to
    /// guard, and the two call sites that matter are the two that spend.
    pub fn validate(&self) -> Result<(), BreakerRefusal> {
        if self.window_nanos <= 0 {
            return Err(BreakerRefusal::InvalidWindow {
                window_nanos: self.window_nanos,
            });
        }
        Ok(())
    }
}

impl Default for BreakerLimits {
    fn default() -> Self {
        Self {
            max_in_window: 1_000,
            window_nanos: DEFAULT_WINDOW_NANOS,
            max_per_episode: 500,
        }
    }
}

/// One persisted bucket of `discard_rate_window`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RateBucket {
    pub bucket_start: Timestamp,
    pub count: u32,
}

/// The rolling counter for one `(target, root)`.
///
/// Persisted, so it survives a restart. An in-memory counter would make the
/// breaker trivially evadable by restarting the daemon, which is the failure
/// mode a rate limit most needs to survive.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RateWindow {
    pub target: Option<TargetId>,
    pub root: Option<RootId>,
    pub buckets: Vec<RateBucket>,
}

impl RateWindow {
    /// Discards counted inside the window ending at `now`.
    pub fn count_within(&self, now: Timestamp, window_nanos: i64) -> u32 {
        // A nonpositive window is not a small window, it is no window — see
        // `BreakerLimits::validate`. Counting EVERYTHING is the only safe
        // reading here: this function has no way to refuse, and the callers
        // that can (`try_charge`, `may_execute`) do. Returning 0 would be the
        // answer that disables the budget.
        if window_nanos <= 0 {
            return self
                .buckets
                .iter()
                .map(|b| b.count)
                .fold(0u32, |a, b| a.saturating_add(b));
        }
        let floor = now.as_nanos().saturating_sub(window_nanos);
        self.buckets
            .iter()
            .filter(|b| b.bucket_start.as_nanos() > floor)
            .map(|b| b.count)
            .fold(0u32, |a, b| a.saturating_add(b))
    }

    /// Test the budget and consume it **in one step**, refusing rather than
    /// overshooting.
    ///
    /// This is the operation the discard path must use, and [`Self::record`] is
    /// not. A caller that checks [`Self::count_within`] and then calls `record`
    /// has published a window between the two in which a second episode reads
    /// the same unused budget and also passes — so two passes that are each
    /// under the limit jointly exceed it. That is the arithmetic evasion the
    /// rolling window exists to stop, reintroduced one layer up.
    ///
    /// Atomicity here is only as wide as the `&mut` borrow, which is the whole
    /// point: within a process the borrow checker makes concurrent charges
    /// impossible, and across processes it is the [`RateLedger`] implementation
    /// that must carry the same guarantee down to its storage.
    pub fn try_charge(
        &mut self,
        now: Timestamp,
        n: u32,
        limits: &BreakerLimits,
    ) -> Result<(), BreakerRefusal> {
        limits.validate()?;
        let used = self.count_within(now, limits.window_nanos);
        if used.saturating_add(n) > limits.max_in_window {
            return Err(BreakerRefusal::RateWindowExhausted {
                used,
                limit: limits.max_in_window,
                window_nanos: limits.window_nanos,
            });
        }
        self.record(now, n);
        Ok(())
    }

    /// Record `n` discards at `now`.
    ///
    /// Unconditional. [`Self::try_charge`] is what the discard path calls;
    /// this is the raw recorder underneath it and a recovery/replay hook.
    pub fn record(&mut self, now: Timestamp, n: u32) {
        match self.buckets.iter_mut().find(|b| b.bucket_start == now) {
            Some(b) => b.count = b.count.saturating_add(n),
            None => self.buckets.push(RateBucket {
                bucket_start: now,
                count: n,
            }),
        }
    }

    /// Drop buckets that can no longer affect any decision.
    ///
    /// Deliberately **not** called automatically anywhere in this module:
    /// pruning is a durability decision for the catalog, and a breaker that
    /// quietly forgets its own history is the thing this design is guarding
    /// against.
    pub fn prune(&mut self, now: Timestamp, window_nanos: i64) {
        let floor = now.as_nanos().saturating_sub(window_nanos);
        self.buckets.retain(|b| b.bucket_start.as_nanos() > floor);
    }
}

/// What a hold blocks.
///
/// §4.10.5: "a held discard queue blocks only the `destroy`/`discard` classes
/// for that target; all other job classes continue."
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HoldScope {
    pub target: TargetId,
}

impl HoldScope {
    /// Whether a job of `class` against `target` is blocked by this hold.
    ///
    /// Scan, hash, extract, tag, embed, upload, verify, restore, replicate and
    /// scrub all continue — a hold is not a pause button for the product.
    ///
    /// Takes the catalog's [`JobClass`] rather than a `&str`. An earlier version
    /// string-matched `"destroy" | "discard"`, which is a second vocabulary that
    /// can drift from the enum §4.4 actually defines: renaming a variant would
    /// still compile and would silently stop blocking the class it was meant to
    /// block. Same defect shape as two crates re-deriving an `atime` predicate.
    ///
    /// §4.10.5 names the blocked classes as "destroy/discard", but `JobClass`
    /// has **no `Discard` variant** — discard is the remote side of `destroy`,
    /// which is why PM-2 routes it through the same intent + audit apparatus
    /// rather than treating it as a separate operation.
    pub fn blocks(&self, class: JobClass, target: TargetId) -> bool {
        self.target == target && matches!(class, JobClass::Destroy)
    }
}

/// `discard_episode.state`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EpisodeState {
    Enumerating,
    Held,
    Confirmed,
    Executing,
    Completed,
    Expired,
    Cancelled,
}

/// One candidate, as durably held in `discard_candidate`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Candidate {
    pub file: FileId,
    pub path: String,
    pub blake3: Option<Blake3Hash>,
}

/// A bulk-discard episode.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Episode {
    pub root: RootId,
    pub target: TargetId,
    pub state: EpisodeState,
    pub opened_at: Timestamp,
    /// The COMPLETE set, enumerated before the first delete.
    pub candidates: Vec<Candidate>,
    /// Hash of the enumerated set. Confirmation binds to this exact value.
    pub candidate_set_blake3: Option<Blake3Hash>,
    pub confirmed_at: Option<Timestamp>,
    pub confirmed_by: Option<String>,
    /// The hash that was confirmed. Compared against the current set at
    /// execution time — this pair is what makes "expires when the set changes"
    /// a mechanism rather than a promise.
    pub confirmed_set_blake3: Option<Blake3Hash>,
    pub expires_at: Option<Timestamp>,
}

/// Hash a candidate set, order-independently.
///
/// Sorted by `file_id` before hashing, so a set enumerated in a different
/// order — a different SQL plan, a different index — is the *same* set. Making
/// this order-sensitive would expire confirmations at random and train people
/// to re-confirm without reading, which is worse than not confirming at all.
pub fn candidate_set_hash(candidates: &[Candidate]) -> Blake3Hash {
    let mut ids: Vec<&Candidate> = candidates.iter().collect();
    ids.sort_by_key(|c| c.file.get());
    let mut hasher = blake3::Hasher::new();
    for c in ids {
        hasher.update(&c.file.get().to_le_bytes());
        hasher.update(c.path.as_bytes());
        hasher.update(&[0u8]); // separator: "ab"+"c" must not hash as "a"+"bc"
        if let Some(h) = c.blake3 {
            hasher.update(h.as_bytes());
        }
        hasher.update(&[0xffu8]);
    }
    Blake3Hash::from_bytes(*hasher.finalize().as_bytes())
}

/// Why execution was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BreakerRefusal {
    /// The configured rolling window is nonpositive, which disables the budget
    /// rather than narrowing it.
    InvalidWindow {
        window_nanos: i64,
    },
    /// Enumeration never completed, so the "complete set held before the first
    /// delete" precondition does not hold.
    SetNotEnumerated,
    NotConfirmed {
        state: EpisodeState,
    },
    /// The candidate set changed after confirmation.
    ConfirmationStale {
        confirmed: Blake3Hash,
        current: Blake3Hash,
    },
    ConfirmationExpired {
        at: Timestamp,
    },
    /// Rolling window budget exhausted.
    RateWindowExhausted {
        used: u32,
        limit: u32,
        window_nanos: i64,
    },
    /// Per-episode cap.
    EpisodeTooLarge {
        count: u32,
        limit: u32,
    },
    /// The charge was reserved against a different target.
    ///
    /// Its own variant rather than a field of a combined one, so a test that
    /// varies **only** the target names what it caught. The pair below is the
    /// same shape for the root.
    WrongTarget {
        charged: TargetId,
        attempted: TargetId,
    },
    /// The charge was reserved against a different root.
    WrongRoot {
        charged: RootId,
        attempted: RootId,
    },
    /// The object is not one of the candidates whose set the operator
    /// confirmed.
    ///
    /// **This variant replaced `ChargeExhausted`, and the replacement is the
    /// point.** A count-only charge answered "has this episode deleted more
    /// than it paid for?" — a question about arithmetic, which a deletion of
    /// the wrong object passes trivially. The question that matters is "was
    /// *this* object confirmed?", and only a charge that knows its candidates
    /// can answer it. Over-deletion is no longer reachable either: a set of `n`
    /// candidates yields exactly `n` spendable units by construction, so there
    /// is nothing left for a separate exhaustion refusal to catch.
    NotACandidate {
        file: FileId,
    },
    /// This candidate's unit has already been spent.
    ///
    /// Distinct from [`Self::NotACandidate`] because they are different bugs:
    /// one is a wiring error reaching outside the confirmed set, the other is
    /// an iteration error inside it that would delete one object twice while
    /// leaving another alive.
    AlreadySpent {
        file: FileId,
    },
    /// The candidate carries no BLAKE3, so no content-addressed key names it.
    ///
    /// §4.9 keys are `<prefix>/objects/…/<b3>` and nothing else, so a candidate
    /// without a hash cannot name a remote object at all. `plan_tier` already
    /// refuses unhashed files ([`crate::plan::PlanRefusal::Unhashed`]), which
    /// makes this a consistency check rather than a new restriction — and
    /// exactly the kind of "cannot happen" that becomes reachable the day
    /// `plan_tier` changes. It fails loudly instead of deriving a key from
    /// nothing.
    Unhashed {
        file: FileId,
    },
    Cancelled,
}

/// The durable rolling window, as the discard path reaches it.
///
/// Implemented by whatever owns §4.4's `discard_rate_window` table. The port
/// exists for the same reason [`crate::destroy::RemoteGate`] does: the thing
/// that must happen lives in another crate, and the rule about *when* it
/// happens lives here.
///
/// **Contract, and the whole point of the mechanism:**
///
/// * `charge` must test the budget and consume it **atomically** — one
///   transaction, not a read followed by a write. Two episodes evaluating
///   concurrently both observe the same free budget, and only the atomicity of
///   this call decides which of them gets it.
/// * The charge must be **durable before it returns**. A charge that is still
///   in memory when the process dies restores exactly the budget the deletions
///   already spent, which is the restart evasion the persisted window exists
///   to close.
/// * It must be called **before** the deletions it pays for, never after. A
///   post-delete update leaves every concurrent episode reading a stale window
///   for the whole duration of the delete.
///
/// [`RateWindow::try_charge`] is the reference implementation of the test-and-
/// consume step; an implementation backed by SQLite should perform the same
/// arithmetic inside a single immediate transaction.
#[async_trait::async_trait]
pub trait RateLedger: Send + Sync {
    /// Reserve `n` discards against the persisted window for `(target, root)`.
    async fn charge(
        &self,
        target: TargetId,
        root: RootId,
        at: Timestamp,
        n: u32,
        limits: &BreakerLimits,
    ) -> Result<(), BreakerRefusal>;

    /// Return `n` discards to the window, for a reservation that will not
    /// happen.
    ///
    /// Only ever called BEFORE any deletion — a refusal between the charge and
    /// the episode's durable transition — so it cannot mask work that occurred.
    /// Infallible by signature and best-effort by contract: a ledger that
    /// cannot be reached leaves the budget spent, which is the conservative
    /// direction for a blast-radius control and is what the window rolling
    /// forward eventually resolves anyway.
    async fn refund(&self, target: TargetId, root: RootId, at: Timestamp, n: u32);
}

impl Episode {
    pub fn open(root: RootId, target: TargetId, now: Timestamp) -> Self {
        Self {
            root,
            target,
            state: EpisodeState::Enumerating,
            opened_at: now,
            candidates: Vec::new(),
            candidate_set_blake3: None,
            confirmed_at: None,
            confirmed_by: None,
            confirmed_set_blake3: None,
            expires_at: None,
        }
    }

    /// Durably hold the **complete** candidate set and move to `Held`.
    ///
    /// This is the preflight iteration 1 asserted but never required. Until it
    /// has run there is no set to confirm, and [`Episode::may_execute`] refuses.
    /// Enumerate a candidate set, moving the episode to `Held`.
    ///
    /// **Terminal episodes are not revived.** `Cancelled` and `Completed` are
    /// decisions that have already been made — one by a human, one by the
    /// destructions that ran — and re-enumerating over either turns a finished
    /// episode back into a live one carrying its old confirmation fields. A
    /// caller that wants another bulk discard opens another episode; that is
    /// what makes each one's audit trail its own.
    pub fn enumerate(&mut self, candidates: Vec<Candidate>) -> bool {
        if matches!(
            self.state,
            EpisodeState::Cancelled | EpisodeState::Completed
        ) {
            return false;
        }
        self.candidate_set_blake3 = Some(candidate_set_hash(&candidates));
        self.candidates = candidates;
        self.state = EpisodeState::Held;
        true
    }

    /// A human confirmed the set. Binds to the hash as it stands now.
    ///
    /// Only from `Held`, and returns whether it took. Confirming a `Cancelled`
    /// or `Completed` episode would resurrect it with a fresh deadline, and
    /// confirming one already `Executing` would re-arm a run in progress.
    pub fn confirm(&mut self, by: impl Into<String>, now: Timestamp, ttl_nanos: i64) -> bool {
        if self.state != EpisodeState::Held {
            return false;
        }
        self.confirmed_set_blake3 = self.candidate_set_blake3;
        self.confirmed_at = Some(now);
        self.confirmed_by = Some(by.into());
        self.expires_at = Some(Timestamp::from_nanos(
            now.as_nanos().saturating_add(ttl_nanos),
        ));
        self.state = EpisodeState::Confirmed;
        true
    }

    /// Re-enumerate. **Invalidates any confirmation**, because the set a human
    /// approved is no longer the set that would be destroyed.
    pub fn re_enumerate(&mut self, candidates: Vec<Candidate>) -> bool {
        if !self.enumerate(candidates) {
            return false;
        }
        self.confirmed_set_blake3 = None;
        self.confirmed_at = None;
        self.confirmed_by = None;
        self.expires_at = None;
        // Back to Held, never to Confirmed. A hold escalates; it never times
        // out into action.
        self.state = EpisodeState::Held;
        true
    }

    pub fn cancel(&mut self) {
        self.state = EpisodeState::Cancelled;
    }

    /// Whether this episode may start destroying, and why not if it may not.
    ///
    /// Every failing check is reported, for the same reason the discard
    /// predicate reports all of them: a held bulk discard is operator-facing.
    pub fn may_execute(
        &self,
        window: &RateWindow,
        limits: &BreakerLimits,
        now: Timestamp,
    ) -> Result<(), Vec<BreakerRefusal>> {
        let mut refusals = Vec::new();

        // Limits that would disable the budget rather than narrow it. Reported
        // alongside everything else because this predicate reports every
        // failing conjunct; `try_charge` refuses outright, since it is the one
        // that spends.
        if let Err(e) = limits.validate() {
            refusals.push(e);
        }

        // The STATE must be `Confirmed`, not merely "not cancelled".
        //
        // Rejecting `Cancelled` alone let every other state through on the
        // strength of leftover fields: an episode in `Completed`, `Executing`,
        // `Expired` or even `Held` still carries the `confirmed_set_blake3` and
        // deadline it was given, so a retry could reserve a fresh charge and
        // run the whole candidate set again — and if an object had been
        // recreated at one of those keys in between, delete the replacement
        // under a confirmation that never saw it.
        //
        // An exhaustive match rather than `!=`: a state added later must be
        // classified deliberately rather than default into "close enough to
        // confirmed", which is the same convention the destroy predicate and
        // `governs_this_discard` use.
        match self.state {
            EpisodeState::Confirmed => {}
            EpisodeState::Cancelled => refusals.push(BreakerRefusal::Cancelled),
            state @ (EpisodeState::Enumerating
            | EpisodeState::Held
            | EpisodeState::Executing
            | EpisodeState::Completed
            | EpisodeState::Expired) => {
                refusals.push(BreakerRefusal::NotConfirmed { state });
            }
        }

        let Some(current) = self.candidate_set_blake3 else {
            refusals.push(BreakerRefusal::SetNotEnumerated);
            return Err(refusals);
        };

        match self.confirmed_set_blake3 {
            None => refusals.push(BreakerRefusal::NotConfirmed { state: self.state }),
            Some(confirmed) if confirmed != current => {
                refusals.push(BreakerRefusal::ConfirmationStale { confirmed, current });
            }
            Some(_) => {
                if let Some(exp) = self.expires_at
                    && now.as_nanos() >= exp.as_nanos()
                {
                    refusals.push(BreakerRefusal::ConfirmationExpired { at: exp });
                }
            }
        }

        let count = u32::try_from(self.candidates.len()).unwrap_or(u32::MAX);
        if count > limits.max_per_episode {
            refusals.push(BreakerRefusal::EpisodeTooLarge {
                count,
                limit: limits.max_per_episode,
            });
        }

        // The rolling window counts what has ALREADY happened plus what this
        // episode would add: authorizing a pass that would itself breach the
        // limit is the arithmetic the per-batch cap alone missed.
        let used = window.count_within(now, limits.window_nanos);
        if used.saturating_add(count) > limits.max_in_window {
            refusals.push(BreakerRefusal::RateWindowExhausted {
                used,
                limit: limits.max_in_window,
                window_nanos: limits.window_nanos,
            });
        }

        if refusals.is_empty() {
            Ok(())
        } else {
            Err(refusals)
        }
    }
}

#[cfg(test)]
#[path = "breaker_tests.rs"]
mod tests;
