//! Delete policies and the discard predicate (§4.10.3, OQ-G, OQ-H).
//!
//! # The predicate is a conjunction, and iteration 3 got that wrong
//!
//! Iteration 3 wrote `provider_confirmed **OR** deferral_expired`. Windows and
//! macOS *do* supply provider confirmation, so that branch fires immediately —
//! **every nonzero window would have behaved exactly like zero**, and the user
//! was about to be offered a choice between 7, 14 and 30 days that were
//! behaviourally identical. The corrected predicate is:
//!
//! ```text
//! discard_permitted(file, target) =
//!       permanent_delete_confirmed(file)
//!   AND (effective_window(policy) == 0 OR deferral_expired(file))
//!   AND NOT deferral_cancelled(file)
//!   AND resync_ok(root) AND available(root)
//!   AND breaker_charged_and_candidate_bound(episode)
//! ```
//!
//! Every conjunct is evaluated and every failing one is reported, rather than
//! short-circuiting on the first. A discard refusal is something a human has to
//! act on, and "blocked by one of six things" is not actionable.
//!
//! # What the window means differs per platform, and both are stated
//!
//! | Platform | What starts the clock | What the window buys |
//! |---|---|---|
//! | Windows / macOS | provider-confirmed **permanent** deletion | insurance against a **misclassified** trash/undelete — we read "permanently deleted" when the user only trashed it |
//! | Linux (delete-mode) | an explicit operator `shepctl file discard` | time for the operator to **change their mind**; nothing classifies here, so there is nothing to misclassify |
//!
//! # Why this module has no dependency on `shepherd-placeholder`
//!
//! §4.1 rule 2 forbids the edge, and that turns out to be right rather than
//! merely restrictive: **every input above is a value, not a provider call.**
//! Platform events (CFAPI `NOTIFY_DELETE`, a File Provider `deleteItem`, an
//! operator's explicit discard) are translated into
//! [`PermanentDeleteConfirmation`] by `shepherd-tier`, which is permitted the
//! edge. The policy engine consumes the distilled fact. See the note on
//! `rule2.dev_exemptions` in `xtask/deps-policy.toml`: the exemption is not
//! needed, because the dependency is not needed.

use serde::{Deserialize, Serialize};
use shepherd_core::{FileId, RootId, TargetId, Timestamp};

/// OQ-H, settled by user decision 2026-08-16.
pub const DEFAULT_DEFERRAL_WINDOW_DAYS: u32 = 14;

const NANOS_PER_DAY: i64 = 86_400 * 1_000_000_000;

/// What a delete policy does when it matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum DeleteAction {
    /// Copy to `destination`, verify, **then** delete from the origin target.
    /// That origin deletion is itself a remote destroy and routes through the
    /// full intent + audit apparatus.
    Archive { destination: TargetId },
    /// Delete from **all** targets. Sole-copy destruction — the irreversible
    /// one, and the only action the deferral window exists for.
    Discard,
    /// Destroy nothing. Drop the file→location binding to `orphaned`; the file
    /// stays listable and restorable.
    Orphan,
}

impl DeleteAction {
    /// Whether this action can irreversibly destroy the last copy.
    ///
    /// `Archive` deletes from the *origin* only after a verified copy exists
    /// elsewhere, so it is not sole-copy destruction; `Orphan` destroys
    /// nothing. Only `Discard` is.
    pub fn is_sole_copy_destruction(&self) -> bool {
        matches!(self, DeleteAction::Discard)
    }
}

/// How trustworthy the wall clock was when a deferral was created.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockProvenance {
    NtpSynced,
    Local,
    Unknown,
}

/// Which side of the system a deferral is protecting.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeferralKind {
    /// unlink / dehydrate of a local original (PM-1).
    Local,
    /// The `discard` branch of a delete policy (AC-3, PM-2).
    Remote,
}

/// How the platform confirmed a *permanent* deletion.
///
/// The distinction this type exists to preserve is trashed-vs-permanent.
/// A trash reparent is **not** a permanent delete, and treating it as one is
/// the misclassification the whole deferral window insures against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "source")]
pub enum PermanentDeleteConfirmation {
    /// CFAPI `NOTIFY_DELETE` **without** `CF_CALLBACK_DELETE_FLAG_IS_UNDELETE`.
    WindowsCfApi,
    /// File Provider `deleteItem`, documented as "delete an item forever" —
    /// **not** a `.trashContainer` reparent.
    MacosFileProvider,
    /// Linux delete-mode has no automatic trigger (§4.10.3): absence is the
    /// steady state of every tiered file, so no absence-based event may fire
    /// discard. The confirmation here is the operator.
    OperatorExplicit { at: Timestamp },
}

/// A clock reading, taken together so the fields are consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClockReading {
    pub wall: Timestamp,
    /// Monotonic nanoseconds since boot. Meaningful only within `boot_id`.
    pub monotonic_nanos: u64,
    pub boot_id: String,
    /// How trustworthy `wall` is **right now**.
    ///
    /// Part of the reading rather than a separate argument because it is a
    /// property of this sample: the same machine answers differently ten
    /// seconds before and ten seconds after `chronyd` steps the clock, and a
    /// caller holding a reading must not have to remember which side of that it
    /// took. [`Deferral::status`] refuses to expire a cross-boot window on an
    /// untrusted one.
    pub provenance: ClockProvenance,
}

/// The durable deferral record (§4.4's `deferral` table).
///
/// Four clock fields, because **a monotonic instant alone does not survive a
/// reboot**. Within one boot the monotonic deadline is authoritative and immune
/// to wall-clock adjustment; across a reboot the monotonic reading is
/// meaningless and the wall clock governs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deferral {
    pub file: FileId,
    pub target: TargetId,
    pub kind: DeferralKind,
    pub deferred_at: Timestamp,
    pub window_days: u32,
    /// Authoritative across reboots.
    pub wall_clock_deadline: Timestamp,
    /// Valid only while `boot_id` matches the current boot.
    pub monotonic_deadline_nanos: u64,
    pub boot_id: String,
    pub clock_provenance: ClockProvenance,
    pub confirmed_permanent_at: Option<Timestamp>,
    /// An undelete or restore before expiry. Destroys **nothing**.
    pub cancelled_at: Option<Timestamp>,
}

impl Deferral {
    /// Open a deferral window of `window_days` from `now`.
    /// `provenance` comes from `now` rather than from a separate argument:
    /// two ways to say how good the clock was are two chances to disagree, and
    /// [`Deferral::status`] compares them.
    pub fn open(
        file: FileId,
        target: TargetId,
        kind: DeferralKind,
        window_days: u32,
        now: &ClockReading,
    ) -> Self {
        let span = i64::from(window_days).saturating_mul(NANOS_PER_DAY);
        Self {
            file,
            target,
            kind,
            deferred_at: now.wall,
            window_days,
            wall_clock_deadline: Timestamp::from_nanos(now.wall.as_nanos().saturating_add(span)),
            monotonic_deadline_nanos: now
                .monotonic_nanos
                .saturating_add(u64::try_from(span).unwrap_or(u64::MAX)),
            boot_id: now.boot_id.clone(),
            clock_provenance: now.provenance,
            confirmed_permanent_at: None,
            cancelled_at: None,
        }
    }
}

/// Where a deferral stands right now.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeferralStatus {
    /// An undelete or restore landed before expiry. Terminal: destroy nothing.
    Cancelled,
    /// Still running.
    Pending { remaining_nanos: i64 },
    /// The window has elapsed.
    Expired,
    /// The wall clock moved **backwards** since the deferral was opened.
    ///
    /// The window **holds and alerts; it never shortens**. A backwards clock is
    /// the one condition under which "expired" could be manufactured, and the
    /// cost asymmetry is total: holding too long delays a deletion, shortening
    /// destroys a file the user could still have recovered.
    HeldClockWentBackwards { by_nanos: i64 },
    /// A cross-boot window whose wall clock nobody can vouch for.
    ///
    /// Across a reboot the monotonic reading is meaningless and the wall clock
    /// is the only judge — so the window can only be ended by a clock that is
    /// actually right. An RTC that comes up ahead of real time (a dead battery,
    /// a dual-boot machine that wrote local time into it, a VM restored from a
    /// snapshot) reports the deadline passed the instant the daemon starts, and
    /// on the `discard` path that is an irreversible deletion of the last copy
    /// during a window the user still had.
    ///
    /// FORWARD jumps are the ones that matter here and the backwards check
    /// cannot see them: `HeldClockWentBackwards` fires when time appears to
    /// have gone the wrong way, and a clock that is wrongly ahead looks exactly
    /// like time having passed.
    ///
    /// Both provenances are reported because either can shorten the window: the
    /// reading that CREATED the deadline (too early a `deferred_at` makes the
    /// deadline too early) and the reading now being compared against it.
    HeldClockUntrusted {
        stored: ClockProvenance,
        current: ClockProvenance,
    },
}

impl DeferralStatus {
    /// Only [`DeferralStatus::Expired`] satisfies the window conjunct.
    pub fn is_expired(&self) -> bool {
        matches!(self, DeferralStatus::Expired)
    }
}

impl Deferral {
    /// Evaluate against a clock reading.
    ///
    /// Pure, and takes the reading as an argument rather than sampling one, so
    /// reboot and clock-skew cases are reproducible instead of being whatever
    /// the test machine happened to do.
    pub fn status(&self, now: &ClockReading) -> DeferralStatus {
        if self.cancelled_at.is_some() {
            return DeferralStatus::Cancelled;
        }

        // Same boot: the monotonic deadline is authoritative and cannot be
        // moved by an NTP step or a user changing the clock.
        if now.boot_id == self.boot_id {
            return if now.monotonic_nanos >= self.monotonic_deadline_nanos {
                DeferralStatus::Expired
            } else {
                DeferralStatus::Pending {
                    remaining_nanos: i64::try_from(
                        self.monotonic_deadline_nanos - now.monotonic_nanos,
                    )
                    .unwrap_or(i64::MAX),
                }
            };
        }

        // Different boot: the stored monotonic reading is meaningless. Wall
        // clock governs — so the window may only be ended by wall-clock
        // readings that can actually be vouched for. Checked BEFORE the
        // comparison, not after, because the comparison is the thing that could
        // manufacture an expiry.
        //
        // Only `NtpSynced` counts. `Local` is the RTC as it came up and
        // `Unknown` is nobody having asked, and both of those are the very
        // states in which a machine reports a time it has no basis for.
        if self.clock_provenance != ClockProvenance::NtpSynced
            || now.provenance != ClockProvenance::NtpSynced
        {
            return DeferralStatus::HeldClockUntrusted {
                stored: self.clock_provenance,
                current: now.provenance,
            };
        }

        // And refuse to shorten on a backwards clock.
        let drift = now.wall.as_nanos() - self.deferred_at.as_nanos();
        if drift < 0 {
            return DeferralStatus::HeldClockWentBackwards { by_nanos: -drift };
        }
        if now.wall.as_nanos() >= self.wall_clock_deadline.as_nanos() {
            DeferralStatus::Expired
        } else {
            DeferralStatus::Pending {
                remaining_nanos: self.wall_clock_deadline.as_nanos() - now.wall.as_nanos(),
            }
        }
    }
}

/// The effective window for a policy: `None` inherits the 14-day default.
pub fn effective_window_days(policy_override: Option<u32>) -> u32 {
    policy_override.unwrap_or(DEFAULT_DEFERRAL_WINDOW_DAYS)
}

/// Root-level gates that block every destructive decision (PM-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RootGates {
    pub root: RootId,
    /// `scan_root.resync_required` — a desynchronized catalog turns "absent"
    /// into "the user deleted it", so this gates everything.
    pub resync_required: bool,
    /// `scan_root.availability == available`.
    pub available: bool,
}

/// Blast-radius state for the episode this discard belongs to (§4.10.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerState {
    /// The rolling rate window still has budget.
    pub charged: bool,
    /// The confirmation is bound to the immutable candidate-set hash, and the
    /// complete set was durably enumerated **before the first delete**.
    pub candidate_set_bound: bool,
}

/// Everything the predicate reads. Assembled by the caller so the predicate
/// itself performs no I/O and is exhaustively testable.
#[derive(Debug, Clone)]
pub struct DiscardInputs<'a> {
    pub file: FileId,
    pub target: TargetId,
    pub action: DeleteAction,
    pub confirmation: Option<PermanentDeleteConfirmation>,
    pub policy_window_override: Option<u32>,
    pub deferral: Option<&'a Deferral>,
    pub now: &'a ClockReading,
    pub gates: RootGates,
    pub breaker: BreakerState,
}

/// Why a discard was refused. Every failing conjunct is reported.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum DiscardRefusal {
    /// The action was not `discard` at all.
    NotADiscard,
    /// No platform or operator confirmation of a **permanent** delete.
    NoPermanentDeleteConfirmation,
    /// A nonzero window is configured but no deferral record exists. Fails
    /// closed: a missing record is not an elapsed one.
    WindowConfiguredButNoDeferral {
        window_days: u32,
    },
    /// The supplied deferral is some *other* deferral: a different file, a
    /// different target, or the local-unlink side rather than the remote
    /// discard side.
    ///
    /// Reported before its status is read at all. An elapsed window belonging
    /// to one file says nothing whatsoever about another file, and a lookup
    /// that returns the wrong row must not be able to authorize a destruction
    /// on the strength of it. The offending record's own identity is carried
    /// here because that, not this file's identity, is what names the wiring
    /// mistake.
    DeferralForAnotherKey {
        deferral_file: FileId,
        deferral_target: TargetId,
        deferral_kind: DeferralKind,
    },
    DeferralStillRunning {
        remaining_nanos: i64,
    },
    /// An undelete or restore landed before expiry.
    DeferralCancelled,
    ClockWentBackwards {
        by_nanos: i64,
    },
    /// A cross-boot window whose wall clock is not trustworthy enough to end
    /// it. See [`DeferralStatus::HeldClockUntrusted`].
    ClockUntrusted {
        stored: ClockProvenance,
        current: ClockProvenance,
    },
    /// A candidate in the batch has no policy proof of its own, or its proof
    /// was refused.
    ///
    /// A charge covers every candidate in an episode, so every candidate needs
    /// its own confirmation, its own expired deferral and its own root gates.
    /// One file's proof authorizing the batch is the whole finding.
    CandidateUnproven {
        file: FileId,
    },
    /// A proof was supplied for a file this episode does not contain. Refused
    /// rather than ignored: a proof set that does not match the batch is not a
    /// proof of the batch.
    ProofForAnotherCandidate {
        file: FileId,
    },
    ResyncRequired,
    RootUnavailable,
    BreakerOpen,
    CandidateSetNotBound,
}

/// The decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscardDecision {
    Permitted,
    /// Non-empty by construction — see [`DiscardDecision::refused`].
    Refused(Vec<DiscardRefusal>),
}

impl DiscardDecision {
    pub fn is_permitted(&self) -> bool {
        matches!(self, DiscardDecision::Permitted)
    }

    pub fn refusals(&self) -> &[DiscardRefusal] {
        match self {
            DiscardDecision::Permitted => &[],
            DiscardDecision::Refused(r) => r,
        }
    }
}

/// Whether this deferral is the one that governs *this* discard.
///
/// The complete key — file, target and side of the system — compared before the
/// deferral's status is read at all. A status is only evidence about the thing
/// it belongs to, so "expired" from the wrong row is not a weaker authority, it
/// is no authority. `DiscardInputs` carries no kind field because the discard
/// branch *is* PM-2's remote side; that expectation is written here rather than
/// left to the caller to supply correctly.
fn governs_this_discard(deferral: &Deferral, inputs: &DiscardInputs<'_>) -> bool {
    // An exhaustive match rather than `== DeferralKind::Remote`: a variant added
    // later must be classified deliberately, not default into "close enough to
    // a discard" — nor silently widen this check by matching a wildcard.
    let kind_governs = match deferral.kind {
        DeferralKind::Remote => true,
        DeferralKind::Local => false,
    };
    deferral.file == inputs.file && deferral.target == inputs.target && kind_governs
}

/// §4.10.3's `discard_permitted`, as a conjunction.
///
/// Returns **every** failing conjunct rather than the first, because a held
/// discard is an operator-facing condition and "blocked, try again" is not
/// something a human can act on.
pub fn discard_permitted(inputs: &DiscardInputs<'_>) -> DiscardDecision {
    let mut refusals = Vec::new();

    if !inputs.action.is_sole_copy_destruction() {
        // Not a refusal of a legitimate discard so much as a category error,
        // but it must never return `Permitted` for an archive or an orphan.
        refusals.push(DiscardRefusal::NotADiscard);
    }

    if inputs.confirmation.is_none() {
        refusals.push(DiscardRefusal::NoPermanentDeleteConfirmation);
    }

    // The window conjunct. `window == 0` satisfies it outright; otherwise a
    // deferral must exist AND have expired.
    let window = effective_window_days(inputs.policy_window_override);
    if window > 0 {
        match inputs.deferral {
            None => refusals.push(DiscardRefusal::WindowConfiguredButNoDeferral {
                window_days: window,
            }),
            // Identity before status, in both branches below. Whose window it
            // is decides whether its state means anything here.
            Some(d) if !governs_this_discard(d, inputs) => {
                refusals.push(DiscardRefusal::DeferralForAnotherKey {
                    deferral_file: d.file,
                    deferral_target: d.target,
                    deferral_kind: d.kind,
                });
            }
            Some(d) => match d.status(inputs.now) {
                DeferralStatus::Expired => {}
                DeferralStatus::Cancelled => refusals.push(DiscardRefusal::DeferralCancelled),
                DeferralStatus::Pending { remaining_nanos } => {
                    refusals.push(DiscardRefusal::DeferralStillRunning { remaining_nanos });
                }
                DeferralStatus::HeldClockWentBackwards { by_nanos } => {
                    refusals.push(DiscardRefusal::ClockWentBackwards { by_nanos });
                }
                DeferralStatus::HeldClockUntrusted { stored, current } => {
                    refusals.push(DiscardRefusal::ClockUntrusted { stored, current });
                }
            },
        }
    } else if let Some(d) = inputs.deferral {
        if !governs_this_discard(d, inputs) {
            // `cancelled_at` is a status too, and reading another row's is the
            // same mistake pointed the other way.
            refusals.push(DiscardRefusal::DeferralForAnotherKey {
                deferral_file: d.file,
                deferral_target: d.target,
                deferral_kind: d.kind,
            });
        } else if d.cancelled_at.is_some() {
            // A zero window still cannot destroy something the user undeleted.
            refusals.push(DiscardRefusal::DeferralCancelled);
        }
    }

    if inputs.gates.resync_required {
        refusals.push(DiscardRefusal::ResyncRequired);
    }
    if !inputs.gates.available {
        refusals.push(DiscardRefusal::RootUnavailable);
    }
    if !inputs.breaker.charged {
        refusals.push(DiscardRefusal::BreakerOpen);
    }
    if !inputs.breaker.candidate_set_bound {
        refusals.push(DiscardRefusal::CandidateSetNotBound);
    }

    if refusals.is_empty() {
        DiscardDecision::Permitted
    } else {
        DiscardDecision::Refused(refusals)
    }
}

#[cfg(test)]
#[path = "delete_policy_tests.rs"]
mod tests;
