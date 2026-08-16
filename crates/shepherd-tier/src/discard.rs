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
use crate::breaker::{BreakerLimits, BreakerRefusal, Episode, RateWindow};
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
#[allow(clippy::too_many_arguments)]
pub async fn execute_discard(
    intent: IntentId,
    remote: &impl RemoteGate,
    key: &ObjectKey,
    guard: &VersionGuard,
    audit: &AuditLog,
    attestation: &str,
    now: Timestamp,
) -> Result<(), DestroyError> {
    // One call site. PM-2's requirement is that the discard branch runs through
    // the same intent + audit apparatus as local destruction; a second path
    // here would be a second place to forget the audit record.
    execute_remote_discard(intent, remote, key, guard, audit, attestation, now).await
}

#[cfg(test)]
#[path = "discard_tests.rs"]
mod tests;
