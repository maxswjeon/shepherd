//! The discard branch (AC-3, PM-2) — where the three gates meet.
//!
//! # This module is the seam that makes §4.1 rule 2 hold
//!
//! `shepherd-rules` holds the discard predicate and `shepherd-placeholder`
//! holds the platform events, and **rule 2 forbids an edge between them**. That
//! is workable only because something translates one into the other, and this
//! is that something: `shepherd-tier` is the single crate permitted to see both.
//!
//! [`confirmation_from_stub`] is the translation. Without it the rule-2
//! resolution recorded in `delete_policy.rs` would be an argument rather than a
//! mechanism — the policy engine would need the provider after all, and the
//! `rule2.dev_exemptions` entry the gate anticipated would be unavoidable.
//!
//! # One source of truth for the breaker
//!
//! `discard_permitted` takes a `BreakerState { charged, candidate_set_bound }`,
//! while [`Episode::may_execute`] *computes* the real thing. Supplying those
//! booleans independently would let the two gates disagree, and the
//! disagreement would be invisible — the same drift class as two crates
//! re-deriving an `atime` predicate. So [`evaluate_discard`] derives the
//! booleans **from** `may_execute`'s outcome and never accepts them from a
//! caller.
//!
//! # Nothing here calls the adapter
//!
//! §4.1 rule 4 makes `shepherd-tier::destroy` the sole caller of
//! `StorageAdapter::delete_object`. The remote deletion routes through
//! [`crate::destroy::execute_remote_discard`], which deletes **and** writes the
//! audit record and refuses if the audit log is halted. PM-2 requires the
//! discard branch to run through the same intent + audit apparatus as local
//! destruction, and a second call site would be a second place to forget it.

use shepherd_catalog::job_repo::JobClass;
use shepherd_core::{IntentId, ObjectKey, RootId, TargetId, Timestamp};
use shepherd_placeholder::mock::StubState;
use shepherd_rules::delete_policy::{
    BreakerState, DiscardDecision, DiscardInputs, PermanentDeleteConfirmation, discard_permitted,
};
use shepherd_storage::adapter::VersionGuard;

use crate::audit::AuditLog;
use crate::breaker::{BreakerLimits, BreakerRefusal, Candidate, Episode, RateLedger, RateWindow};
use crate::destroy::{DestroyError, RemoteGate, execute_remote_discard};
use crate::plan::derive_object_key;
use crate::serialize::FileLocks;

/// Translate a platform stub state into the fact the policy engine consumes.
///
/// **`TrashedPending` yields `None`, and that is the entire point.** A trash
/// reparent is reversible; treating it as a permanent delete is the
/// misclassification the whole deferral window insures against. `Restored` is
/// likewise `None` — the user took it back.
///
/// `Present` is `None` for a different reason worth stating: on Linux
/// delete-mode, absence is the *steady state* of every tiered file, so no
/// absence-derived signal may ever fire a discard (§4.10.3). Linux's
/// confirmation comes from an operator, via
/// [`confirmation_from_operator`], never from an observed state.
pub fn confirmation_from_stub(
    state: StubState,
    platform: StubPlatform,
) -> Option<PermanentDeleteConfirmation> {
    match state {
        StubState::PermanentlyDeleted => Some(match platform {
            StubPlatform::WindowsCfApi => PermanentDeleteConfirmation::WindowsCfApi,
            StubPlatform::MacosFileProvider => PermanentDeleteConfirmation::MacosFileProvider,
        }),
        // Reversible, or reversed. Not a confirmation.
        StubState::TrashedPending | StubState::Restored | StubState::Present => None,
    }
}

/// Which provider produced a stub event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubPlatform {
    /// CFAPI `NOTIFY_DELETE` without `CF_CALLBACK_DELETE_FLAG_IS_UNDELETE`.
    WindowsCfApi,
    /// File Provider `deleteItem` — "delete an item forever".
    MacosFileProvider,
}

/// Linux delete-mode's confirmation: an explicit operator action.
///
/// §4.10.3's table gives Linux **no automatic trigger**, so the operator *is*
/// the confirmation and the deferral window is the interval in which they may
/// change their mind.
pub fn confirmation_from_operator(at: Timestamp) -> PermanentDeleteConfirmation {
    PermanentDeleteConfirmation::OperatorExplicit { at }
}

/// Why a discard was refused, across both gates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscardRefusals {
    /// From `shepherd-rules`' predicate.
    pub policy: Vec<shepherd_rules::delete_policy::DiscardRefusal>,
    /// From the blast-radius controls.
    pub breaker: Vec<BreakerRefusal>,
}

impl DiscardRefusals {
    pub fn is_empty(&self) -> bool {
        self.policy.is_empty() && self.breaker.is_empty()
    }
}

/// Evaluate both gates, with the breaker as the single source of truth for its
/// own booleans.
///
/// `inputs.breaker` is **overwritten** from `episode.may_execute`, deliberately:
/// a caller cannot assert the breaker is charged, because the breaker decides
/// that.
pub fn evaluate_discard(
    mut inputs: DiscardInputs<'_>,
    episode: &Episode,
    window: &RateWindow,
    limits: &BreakerLimits,
    now: Timestamp,
) -> Result<(), DiscardRefusals> {
    let breaker_refusals = episode
        .may_execute(window, limits, now)
        .err()
        .unwrap_or_default();

    // Derived, never supplied. `charged` is false if the rate window or the
    // per-episode cap refused; `candidate_set_bound` is false if the set was
    // never enumerated or the confirmation no longer matches it.
    inputs.breaker = BreakerState {
        charged: !breaker_refusals.iter().any(|r| {
            matches!(
                r,
                BreakerRefusal::RateWindowExhausted { .. } | BreakerRefusal::EpisodeTooLarge { .. }
            )
        }),
        candidate_set_bound: !breaker_refusals.iter().any(|r| {
            matches!(
                r,
                BreakerRefusal::SetNotEnumerated
                    | BreakerRefusal::ConfirmationStale { .. }
                    | BreakerRefusal::NotConfirmed { .. }
                    | BreakerRefusal::ConfirmationExpired { .. }
            )
        }),
    };

    let policy_refusals = match discard_permitted(&inputs) {
        DiscardDecision::Permitted => Vec::new(),
        DiscardDecision::Refused(r) => r,
    };

    let refusals = DiscardRefusals {
        policy: policy_refusals,
        breaker: breaker_refusals,
    };
    if refusals.is_empty() {
        Ok(())
    } else {
        Err(refusals)
    }
}

/// Proof that the rolling breaker was charged **for these specific objects**.
///
/// **This type is the fix for "the breaker is a check with no subject", and it
/// took two rounds to get the subject right.** [`evaluate_discard`] first
/// observed available budget that nothing ever consumed, so repeated
/// sub-threshold episodes kept reading the same unused window; the charge is
/// minted only by [`reserve_discard`], which persists it before returning, and
/// [`execute_discard`] cannot be called without one. That made "forgot to
/// charge the breaker" unreachable.
///
/// It did **not** make "charged for the wrong object" unreachable. A charge
/// that only counted authorised any `n` deletions, so a key from another
/// episode, another target, or an item omitted from [`Episode::candidates`]
/// spent a unit and destroyed an object no operator ever reviewed — on the one
/// path that cannot be undone. So the charge now carries the confirmed set
/// itself, and every unit is drawn against **one named candidate**.
///
/// # The key is derived, never accepted
///
/// [`Self::spend`] returns the [`ObjectKey`] it authorised, computed from the
/// candidate's hash and the target's prefix through
/// [`crate::plan::derive_object_key`] — the single place §4.9 keys are built.
/// [`execute_discard`] therefore takes no key at all: a caller with no way to
/// supply one cannot supply a wrong one. Taking a key *and* checking it against
/// the derivation would have been a second copy of a computed value, which is
/// the drift shape this crate keeps finding rather than a defence against it.
///
/// A `key.ends_with(<hash hex>)` suffix test would be that same mistake twice
/// over: a second reading of the key's structure, and one that leaves the
/// prefix non-load-bearing, so an object under a **foreign prefix** with the
/// right hash would pass. Do not reintroduce it.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "an unspent charge has already consumed breaker budget; spend it or drop the episode"]
pub struct DiscardCharge {
    target: TargetId,
    root: RootId,
    at: Timestamp,
    /// The COMPLETE set the operator confirmed, copied at reservation time.
    /// Not a count: a count cannot answer "was *this* object confirmed?".
    confirmed: Vec<Candidate>,
    /// Indices into `confirmed` whose unit has been drawn.
    spent: Vec<usize>,
}

impl DiscardCharge {
    pub fn target(&self) -> TargetId {
        self.target
    }

    pub fn root(&self) -> RootId {
        self.root
    }

    /// When the charge was persisted.
    pub fn charged_at(&self) -> Timestamp {
        self.at
    }

    pub fn reserved(&self) -> u32 {
        u32::try_from(self.confirmed.len()).unwrap_or(u32::MAX)
    }

    pub fn remaining(&self) -> u32 {
        self.reserved()
            .saturating_sub(u32::try_from(self.spent.len()).unwrap_or(u32::MAX))
    }

    /// Draw this charge's unit for **one named candidate**, and return the key
    /// that deletion is authorised to name.
    ///
    /// Called by [`execute_discard`] **before** the deletion, never after.
    ///
    /// Every component is compared, and each is independently load-bearing: the
    /// target and the root because a charge is scoped to one `(target, root)`
    /// pair and the ledger's budget is keyed on exactly that; the whole
    /// candidate because a set membership test on `file` alone would accept a
    /// row whose path or hash had drifted from the one the operator read.
    ///
    /// A refused spend consumes nothing. Nothing was deleted, so there is
    /// nothing to have paid for.
    fn spend(
        &mut self,
        candidate: &Candidate,
        target: TargetId,
        root: RootId,
        prefix: &str,
    ) -> Result<ObjectKey, BreakerRefusal> {
        if target != self.target {
            return Err(BreakerRefusal::WrongTarget {
                charged: self.target,
                attempted: target,
            });
        }
        if root != self.root {
            return Err(BreakerRefusal::WrongRoot {
                charged: self.root,
                attempted: root,
            });
        }

        // Linear, and deliberately so: `BreakerLimits::max_per_episode` caps a
        // set at 500, so the scan is bounded by a limit the breaker already
        // enforces. An index keyed on the candidate is the upgrade if that cap
        // ever rises.
        let mut seen = false;
        let mut free = None;
        for (i, c) in self.confirmed.iter().enumerate() {
            if c != candidate {
                continue;
            }
            seen = true;
            if !self.spent.contains(&i) {
                free = Some(i);
                break;
            }
        }
        let Some(idx) = free else {
            return Err(if seen {
                BreakerRefusal::AlreadySpent {
                    file: candidate.file,
                }
            } else {
                BreakerRefusal::NotACandidate {
                    file: candidate.file,
                }
            });
        };

        // §4.9: a key is `<prefix>/objects/<b3[0:2]>/<b3[2:4]>/<b3>` and nothing
        // else, so a candidate with no hash names no object. Refusing is a
        // consistency check today — `plan_tier` will not plan an unhashed file —
        // and a loud failure the day that changes.
        let Some(hash) = candidate.blake3 else {
            return Err(BreakerRefusal::Unhashed {
                file: candidate.file,
            });
        };

        self.spent.push(idx);
        Ok(derive_object_key(prefix, hash))
    }
}

/// Evaluate both gates and **reserve** the breaker budget the episode needs.
///
/// The two steps answer different questions and only the second one is
/// authoritative:
///
/// 1. [`evaluate_discard`] reports **every** refusal, because a held bulk
///    discard is operator-facing and a list of one reason at a time is a bad
///    conversation. Its view of the rate window is a snapshot, so it is
///    advisory: two episodes racing each other both pass this step.
/// 2. `ledger.charge` is the authority. It tests and consumes the budget in
///    one durable step, so of two racing episodes exactly one gets it and the
///    other is refused here — which is the check-then-act window the previous
///    shape left open.
///
/// # Why nothing is refunded when a deletion fails
///
/// A failed remote deletion is **not** the same fact as a deletion that did not
/// happen: a timeout, a dropped connection or an ambiguous provider response
/// leaves the object's fate unknown, which is precisely why §4.4's
/// `destroy_intent` carries an `outcome-ambiguous` state. Returning budget on
/// error would therefore hand back capacity that may well have been spent on a
/// real deletion, and it would do so on the one path that cannot be undone.
///
/// An un-refunded charge only ever makes the breaker **stricter**, and a
/// breaker that is occasionally too conservative after an error is the correct
/// failure direction for a blast-radius control. The budget it holds is
/// released by the window rolling forward, which is the same mechanism that
/// releases every other charge.
pub async fn reserve_discard(
    inputs: DiscardInputs<'_>,
    episode: &Episode,
    window: &RateWindow,
    limits: &BreakerLimits,
    now: Timestamp,
    ledger: &impl RateLedger,
) -> Result<DiscardCharge, DiscardRefusals> {
    evaluate_discard(inputs, episode, window, limits, now)?;

    let count = u32::try_from(episode.candidates.len()).unwrap_or(u32::MAX);
    ledger
        .charge(episode.target, episode.root, now, count, limits)
        .await
        .map_err(|r| DiscardRefusals {
            policy: Vec::new(),
            breaker: vec![r],
        })?;

    Ok(DiscardCharge {
        target: episode.target,
        root: episode.root,
        at: now,
        // The set itself, not its size. What was charged and what may be
        // deleted are then one fact rather than two that can disagree.
        confirmed: episode.candidates.clone(),
        spent: Vec::new(),
    })
}

/// Whether a discard hold blocks a job class, ignoring target scope.
///
/// Thin on purpose: [`crate::breaker::HoldScope::blocks`] is the real answer
/// and is target-scoped. This exists for callers that have already established
/// they are looking at the held target, and both now take the catalog's
/// [`JobClass`] so there is one vocabulary rather than two.
pub fn hold_blocks(class: JobClass) -> bool {
    // Delegates rather than repeating the match. Two typed copies of one
    // predicate is the same drift shape as the string-vs-enum version this
    // replaced — it just fails more quietly, because both compile.
    crate::breaker::HoldScope { target: SENTINEL }.blocks(class, SENTINEL)
}

/// Any target: [`hold_blocks`] answers the class question only, so the target
/// comparison is made trivially true rather than duplicated.
const SENTINEL: TargetId = TargetId::new(0);

/// Execute a discard that both gates have already permitted.
///
/// Deliberately takes `RemoteGate` rather than `StorageAdapter`: rule 4a
/// permits `delete_object` to be *named* only inside `shepherd-storage` and
/// `destroy.rs`, so a double implemented against the adapter trait would fail
/// the gate. Implement `RemoteGate` instead.
/// Takes `&mut DiscardCharge` rather than a bare go-ahead, because the charge
/// is the only evidence that the rolling breaker was actually paid. The unit is
/// spent **before** the deletion is authorised: charging afterwards would leave
/// every concurrent episode reading a stale window for the duration of the
/// delete, and charging not at all was the defect this pair of types replaced.
///
/// **It takes no `ObjectKey`.** The key is derived by [`DiscardCharge::spend`]
/// from the candidate the charge authorised and the target's `prefix`, so a
/// caller has no way to name an object other than the one it is spending for.
/// The wrong key is not something this function refuses; it is something no
/// caller can express. See [`DiscardCharge`] for why that is stronger than
/// accepting a key and checking it.
/// # NOT YET SAFE UNDER AC-47 DEDUP — the last-referent check is missing
///
/// Keys here are content-addressed, so two files with identical bytes on the
/// same target and prefix resolve to **one object**. This function deletes that
/// object on the strength of one file's candidate, without asking whether any
/// other file still points at it — so discarding either sibling would destroy
/// the remote bytes the other one still needs, and the survivor's
/// `object_location` row would name a key that is gone.
///
/// It is not a live defect and it is not fixed here, for the same reason D-12's
/// enrollment probe is deferred at `dispatch::root_add`: the consuming path does
/// not exist. `object_location` is schema-only — nothing in this repository
/// writes a binding, `tier.plan` and `tier.run` answer `MethodNotImplemented`,
/// and `execute_discard` has no caller outside its own tests. There is
/// therefore no referent to count, and inventing the count now would mean
/// designing T10's binding lifecycle inside a review round.
///
/// **What T10 must do here, in this order:** remove *this* file's
/// `object_location` row, then count the rows still naming the same
/// `remote_object`, then delete the object only if that count is zero — all in
/// ONE catalog transaction, because a count and a delete in two writer
/// operations is the race `dispatch::root_remove` already had to close. The
/// remote-key lock this function now takes is the other half: it serializes
/// against a concurrent upload republishing the same key.
#[allow(clippy::too_many_arguments)]
pub async fn execute_discard(
    charge: &mut DiscardCharge,
    intent: IntentId,
    remote: &impl RemoteGate,
    candidate: &Candidate,
    target: TargetId,
    root: RootId,
    prefix: &str,
    guard: &VersionGuard,
    locks: &FileLocks,
    audit: &AuditLog,
    attestation: &str,
    now: Timestamp,
) -> Result<(), DestroyError> {
    // Before the deletion, never after. The budget was already persisted by
    // `reserve_discard`; this is the per-object draw against it, and it both
    // authorises the deletion and names what may be deleted.
    let key = charge
        .spend(candidate, target, root, prefix)
        .map_err(DestroyError::Breaker)?;

    // The SAME process-wide remote-key lock `upload::upload_item` takes through
    // `acquire_both`. Without it the two operations interleave on one key:
    // a delete landing between an upload's completion and its verification
    // makes that upload fail after it has already published, and a completion
    // landing after the delete recreates an object this discard has already
    // audited as gone — a live object with a forensic record saying it was
    // destroyed.
    //
    // Held across the audit resolution, not just the DELETE: it is
    // `execute_remote_discard`'s closing HEAD that decides whether an ambiguous
    // failure gets a record or a halt, and a republish underneath that HEAD is
    // exactly what would make it decide wrongly.
    let _key_lock = locks.acquire_key(&key).await;

    // One call site. PM-2's requirement is that the discard branch runs through
    // the same intent + audit apparatus as local destruction; a second path
    // here would be a second place to forget the audit record.
    execute_remote_discard(intent, remote, &key, guard, audit, attestation, now).await
}

#[cfg(test)]
#[path = "discard_tests.rs"]
mod tests;
