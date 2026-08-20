//! AC-14 — a rule is inert until a dry-run says otherwise.
//!
//! # The requirement, and where it is enforced
//!
//! > Enabling a rule with no dry-run record is rejected **by the daemon**, not
//! > just the UI.
//!
//! A UI-only check is a suggestion. `shepctl`, the IPC surface and the Tauri
//! app all route through [`may_enable`], so there is one answer rather than
//! three implementations of it.
//!
//! OQ-G (settled 2026-08-16) makes this apply to **delete policies too**: a
//! `DeletePolicy` is a Rule variant and *inherits* AC-14 rather than defaulting
//! to it. `rule` and `delete_policy` carry the same `last_preview_at` /
//! `last_preview_hash` pair for that reason.
//!
//! # Why the hash covers the body but NOT `enabled`
//!
//! `last_preview_hash` binds a dry-run to the exact rule body previewed, so
//! **editing a rule re-blocks enablement**. If the hash covered the `enabled`
//! flag, then flipping that flag would change the hash — the act of enabling
//! would invalidate the very preview that authorized it, and no rule could ever
//! be enabled. The hash covers what the rule *does*, never its lifecycle state.
//!
//! # §4.12's signal-provenance rule is a rejection, not a warning
//!
//! A preview must state **which signal actually drove each match**, and a
//! **destructive rule resting solely on `atime` where fidelity is `relatime`,
//! `disabled` or `unknown` is rejected** — not warned about. `unknown` is
//! treated exactly as `disabled`: an undetermined signal is not a permissive
//! one. That the preview records a signal per match is structural here —
//! [`PreviewedMatch::signal`] is not optional — rather than a check that could
//! be forgotten.

use serde::{Deserialize, Serialize};
use shepherd_catalog::atime::AtimeMode;
use shepherd_core::{Blake3Hash, FileId, TargetId, Timestamp};

use crate::delete_policy::DeleteAction;

/// Which signal actually drove an age match (§4.12's `file.access_signal_src`).
///
/// The *access* fallback order is `Observed → Atime (only where reliable) →
/// Mtime`. [`AccessSignalSource::Ctime`] is not part of that chain and is never
/// fallen back to — it appears only when a rule names `ctime_older_than_days`,
/// which reads a timestamp of its own.
///
/// # This is NOT `shepherd_catalog::AccessSignal`
///
/// That enum is persisted into `file.access_signal_src`, whose schema CHECK
/// admits `observed | atime | mtime` and nothing else. The two have never been
/// converted into one another and must not start being converted casually: this
/// one carries a fourth value, and writing it through would fail the CHECK at
/// runtime. Widening the column is a schema change, not a cast.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessSignalSource {
    /// `file.last_observed_access` — Shepherd-owned, uniform across platforms
    /// and strictly better than OS atime.
    Observed,
    /// OS `atime`. Only trustworthy where `AtimeMode::Reliable`.
    Atime,
    /// Last resort.
    Mtime,
    /// Inode change time, read only by an explicit `ctime_older_than_days`
    /// predicate.
    ///
    /// It exists because reporting these matches as `Mtime` told the operator
    /// that an mtime rule selected the file when ctime authorized the action —
    /// and [`crate::engine::Engine::run`] refuses on exactly this difference,
    /// so a wrong label is a refusal that does not fire.
    Ctime,
}

/// What a rule does when it matches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum RuleAction {
    /// Copy to targets and — under a delete-mode root — destroy the local
    /// original afterwards.
    Tier { destinations: Vec<TargetId> },
    /// A delete policy. OQ-G: still a Rule, still bound by AC-14.
    Delete(DeleteAction),
}

impl RuleAction {
    /// Whether enabling this rule can lead to destroying user data.
    ///
    /// Deliberately generous. `Tier` counts because on a delete-mode root
    /// tiering *is* the path to unlinking the original, and `Archive` counts
    /// because its origin-side deletion is a real remote destroy. Only `Orphan`
    /// is non-destructive — it drops a binding and destroys nothing. Guessing
    /// wrong in the permissive direction here would let §4.12's rejection be
    /// bypassed by choosing a different action verb.
    pub fn is_destructive(&self) -> bool {
        match self {
            RuleAction::Tier { .. } => true,
            RuleAction::Delete(DeleteAction::Orphan) => false,
            RuleAction::Delete(_) => true,
        }
    }
}

/// The part of a rule that a preview is bound to.
///
/// `enabled` is deliberately **absent** — see the module docs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleBody {
    pub name: String,
    /// The match predicate exactly as stored in `rule.match_json`.
    pub match_json: serde_json::Value,
    pub action: RuleAction,
    /// Which signal the rule's **age** predicate rests on, or `None` if it has
    /// no age predicate.
    ///
    /// Computed by the matcher (`match.rs`), not parsed here — this crate does
    /// not need a second, divergent reading of `match_json`.
    pub age_signal: Option<AccessSignalSource>,
}

/// Canonical hash of a rule body.
///
/// Routed through `serde_json::Value`, whose object type is a `BTreeMap`, so
/// the bytes are alphabetically ordered and whitespace-free regardless of field
/// declaration order. Same discipline as the replica pointer records, for the
/// same reason: a hash that depended on field order would silently invalidate
/// every stored preview the moment a field was added.
pub fn preview_hash(body: &RuleBody) -> Blake3Hash {
    let canonical = serde_json::to_value(body).and_then(|v| serde_json::to_vec(&v));
    match canonical {
        Ok(bytes) => Blake3Hash::from_bytes(*blake3::hash(&bytes).as_bytes()),
        // A rule body that will not serialize cannot be previewed, and must not
        // collide with any real hash. Hash the error text instead so the value
        // is deterministic and enablement fails on the mismatch.
        Err(e) => Blake3Hash::from_bytes(
            *blake3::hash(format!("unserializable-rule-body:{e}").as_bytes()).as_bytes(),
        ),
    }
}

/// One file the dry-run matched, and the signal that drove it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewedMatch {
    pub file: FileId,
    /// Not optional: AC-14 requires the preview to state which signal drove
    /// each match, so a preview that omits it is not representable.
    pub signal: AccessSignalSource,
}

/// A stored dry-run (`rule.last_preview_at` / `last_preview_hash`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreviewRecord {
    /// The hash of the body this preview was taken against.
    pub rule_hash: Blake3Hash,
    pub previewed_at: Timestamp,
    /// The complete match set. AC-14 requires this to be *exactly* the set a
    /// real run would act on.
    pub matches: Vec<PreviewedMatch>,
}

/// Why enablement was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EnableRefusal {
    /// No dry-run has ever been run for this rule.
    NoPreview,
    /// The rule was edited after its last preview.
    PreviewStale {
        previewed: Blake3Hash,
        current: Blake3Hash,
    },
    /// §4.12: a destructive rule resting solely on an untrustworthy `atime`.
    DestructiveRuleOnUntrustedAtime { mode: AtimeMode },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EnableDecision {
    Permitted,
    Refused(Vec<EnableRefusal>),
}

impl EnableDecision {
    pub fn is_permitted(&self) -> bool {
        matches!(self, EnableDecision::Permitted)
    }

    pub fn refusals(&self) -> &[EnableRefusal] {
        match self {
            EnableDecision::Permitted => &[],
            EnableDecision::Refused(r) => r,
        }
    }
}

/// AC-14's gate. Every failing condition is reported, not just the first.
///
/// `atime_mode` is the fidelity of the root the rule targets. Where a rule
/// spans roots the caller passes the **least** trustworthy of them, because a
/// rule that would be rejected on one root must not be enabled by averaging it
/// against another.
pub fn may_enable(
    body: &RuleBody,
    preview: Option<&PreviewRecord>,
    atime_mode: AtimeMode,
) -> EnableDecision {
    let mut refusals = Vec::new();

    let current = preview_hash(body);
    match preview {
        None => refusals.push(EnableRefusal::NoPreview),
        Some(p) if p.rule_hash != current => refusals.push(EnableRefusal::PreviewStale {
            previewed: p.rule_hash,
            current,
        }),
        Some(_) => {}
    }

    // §4.12: rejected, not warned — and the line is drawn at `disabled`/
    // `unknown`, NOT at "anything short of reliable".
    //
    // `Relatime` is PERMITTED. It is Linux's default mount option, so rejecting
    // it would refuse destructive age rules on very nearly every Linux root,
    // which §4.12 does not ask for: relatime rules warn and must state their
    // signal per match, they do not fail. `Unknown` groups with `Disabled`
    // because "we could not tell" and "it never updates" have the same
    // consequence for a rule that would otherwise match every file on the
    // volume.
    //
    // The predicate is `AtimeMode::supports_destructive_age_rule` rather than a
    // local re-derivation, so this crate and `shepherd-catalog` cannot drift
    // into disagreeing about which roots are safe.
    if body.action.is_destructive()
        && body.age_signal == Some(AccessSignalSource::Atime)
        && !atime_mode.supports_destructive_age_rule()
    {
        refusals.push(EnableRefusal::DestructiveRuleOnUntrustedAtime { mode: atime_mode });
    }

    if refusals.is_empty() {
        EnableDecision::Permitted
    } else {
        EnableDecision::Refused(refusals)
    }
}

#[cfg(test)]
#[path = "preview_tests.rs"]
mod tests;
