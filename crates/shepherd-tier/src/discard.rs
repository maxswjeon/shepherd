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
use shepherd_core::{IntentId, ObjectKey, TargetId, Timestamp};
use shepherd_placeholder::mock::StubState;
use shepherd_rules::delete_policy::{
    BreakerState, DiscardDecision, DiscardInputs, PermanentDeleteConfirmation, discard_permitted,
};
use shepherd_storage::adapter::VersionGuard;

use crate::audit::AuditLog;
use crate::breaker::{BreakerLimits, BreakerRefusal, Episode, RateLedger, RateWindow};
use crate::destroy::{DestroyError, RemoteGate, execute_remote_discard};

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

/// Proof that the rolling breaker was charged for an episode's deletions.
///
/// **This type is the fix for "the breaker is a check with no subject".**
/// [`evaluate_discard`] observed available budget and nothing ever consumed it,
/// so repeated sub-threshold episodes kept reading the same unused window. The
/// charge is now minted only by [`reserve_discard`], which persists it before
/// returning, and [`execute_discard`] cannot be called without one — so
/// "forgot to charge the breaker" is not a reachable state rather than a
/// convention someone has to remember.
///
/// One unit is spent per object deleted, so a single reservation authorises
/// exactly the number of deletions it paid for and not one more.
#[derive(Debug, PartialEq, Eq)]
#[must_use = "an unspent charge has already consumed breaker budget; spend it or drop the episode"]
pub struct DiscardCharge {
    target: TargetId,
    root: shepherd_core::RootId,
    at: Timestamp,
    reserved: u32,
    spent: u32,
}

impl DiscardCharge {
    pub fn target(&self) -> TargetId {
        self.target
    }

    pub fn root(&self) -> shepherd_core::RootId {
        self.root
    }

    /// When the charge was persisted.
    pub fn charged_at(&self) -> Timestamp {
        self.at
    }

    pub fn reserved(&self) -> u32 {
        self.reserved
    }

    pub fn remaining(&self) -> u32 {
        self.reserved.saturating_sub(self.spent)
    }

    /// Consume one unit, for one object about to be deleted.
    ///
    /// Called by [`execute_discard`] **before** the deletion, never after.
    fn spend(&mut self) -> Result<(), BreakerRefusal> {
        if self.remaining() == 0 {
            return Err(BreakerRefusal::ChargeExhausted {
                reserved: self.reserved,
            });
        }
        self.spent += 1;
        Ok(())
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
        reserved: count,
        spent: 0,
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
#[allow(clippy::too_many_arguments)]
pub async fn execute_discard(
    charge: &mut DiscardCharge,
    intent: IntentId,
    remote: &impl RemoteGate,
    key: &ObjectKey,
    guard: &VersionGuard,
    audit: &AuditLog,
    attestation: &str,
    now: Timestamp,
) -> Result<(), DestroyError> {
    // Before the deletion, never after. The budget was already persisted by
    // `reserve_discard`; this is the per-object draw against it.
    charge.spend().map_err(DestroyError::Breaker)?;

    // One call site. PM-2's requirement is that the discard branch runs through
    // the same intent + audit apparatus as local destruction; a second path
    // here would be a second place to forget the audit record.
    execute_remote_discard(intent, remote, key, guard, audit, attestation, now).await
}

#[cfg(test)]
#[path = "discard_tests.rs"]
mod tests;
