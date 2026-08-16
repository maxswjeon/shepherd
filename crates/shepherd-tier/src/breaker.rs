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
    pub window_nanos: i64,
    /// Per-episode cap, retained alongside the rolling window.
    pub max_per_episode: u32,
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
        let floor = now.as_nanos().saturating_sub(window_nanos);
        self.buckets
            .iter()
            .filter(|b| b.bucket_start.as_nanos() > floor)
            .map(|b| b.count)
            .fold(0u32, |a, b| a.saturating_add(b))
    }

    /// Record `n` discards at `now`.
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
    pub fn blocks(&self, class: &str, target: TargetId) -> bool {
        self.target == target && matches!(class, "destroy" | "discard")
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
    Cancelled,
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
    pub fn enumerate(&mut self, candidates: Vec<Candidate>) {
        self.candidate_set_blake3 = Some(candidate_set_hash(&candidates));
        self.candidates = candidates;
        self.state = EpisodeState::Held;
    }

    /// A human confirmed the set. Binds to the hash as it stands now.
    pub fn confirm(&mut self, by: impl Into<String>, now: Timestamp, ttl_nanos: i64) {
        self.confirmed_set_blake3 = self.candidate_set_blake3;
        self.confirmed_at = Some(now);
        self.confirmed_by = Some(by.into());
        self.expires_at = Some(Timestamp::from_nanos(
            now.as_nanos().saturating_add(ttl_nanos),
        ));
        self.state = EpisodeState::Confirmed;
    }

    /// Re-enumerate. **Invalidates any confirmation**, because the set a human
    /// approved is no longer the set that would be destroyed.
    pub fn re_enumerate(&mut self, candidates: Vec<Candidate>) {
        self.enumerate(candidates);
        self.confirmed_set_blake3 = None;
        self.confirmed_at = None;
        self.confirmed_by = None;
        self.expires_at = None;
        // Back to Held, never to Confirmed. A hold escalates; it never times
        // out into action.
        self.state = EpisodeState::Held;
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

        if self.state == EpisodeState::Cancelled {
            refusals.push(BreakerRefusal::Cancelled);
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
