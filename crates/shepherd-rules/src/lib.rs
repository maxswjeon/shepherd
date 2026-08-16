//! Rule matching, the rule engine, dry-run previews and delete policies.
//!
//! # What this crate is not allowed to do
//!
//! §4.1 rule 2 forbids any crate but `shepherd-tier` from depending on
//! `shepherd-placeholder`, so **nothing here can reach a destructive syscall**.
//! That is not an inconvenience to route around: every input to the discard
//! predicate is a *value* — a confirmation, a clock reading, a breaker state —
//! not a provider call. Platform events are translated into those values by
//! `shepherd-tier`, which is permitted the edge. See the module docs of
//! [`delete_policy`].
//!
//! # The rules are inert until a dry-run says otherwise
//!
//! AC-14: a rule cannot be enabled without a preview, and editing a rule
//! re-blocks it. OQ-G settled that delete policies are a Rule variant and
//! **inherit** that requirement rather than merely defaulting to it. The
//! enforcement lives in [`preview`] and is asserted by the daemon, not by the
//! UI — a UI-only check is a suggestion.

#![forbid(unsafe_code)]

pub mod delete_policy;
pub mod engine;
/// AC-13's matcher. `match` is a keyword, hence the raw identifier.
pub mod r#match;
pub mod preview;

pub use delete_policy::{
    BreakerState, ClockProvenance, ClockReading, DEFAULT_DEFERRAL_WINDOW_DAYS, Deferral,
    DeferralKind, DeferralStatus, DeleteAction, DiscardDecision, DiscardInputs, DiscardRefusal,
    PermanentDeleteConfirmation, RootGates, discard_permitted, effective_window_days,
};
pub use engine::{Candidate, Engine, EngineRefusal, PlannedAction, RunMode, RunReport};
pub use r#match::{MatchContext, MatchError, MatchOutcome, Matcher, Predicate, TimeField};
pub use preview::{
    AccessSignalSource, EnableDecision, EnableRefusal, PreviewRecord, RuleBody, preview_hash,
};
