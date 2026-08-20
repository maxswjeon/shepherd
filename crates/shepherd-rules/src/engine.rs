//! The rule engine — evaluate matched rules into actions, dry-run first.
//!
//! # The engine's job is composition, not matching
//!
//! `match.rs` decides whether one file satisfies one predicate, and
//! `preview.rs` decides whether a rule may be enabled at all. This module puts
//! them together: run a rule over candidates, produce a preview, and — only
//! against a preview that still binds — produce the actions a run would take.
//!
//! It deliberately re-derives nothing. The age signal comes from
//! [`MatchOutcome::age_signal`] rather than from a second reading of
//! `match_json`, because two readings of one predicate is the drift that
//! §4.12's rejection already caught once.
//!
//! # A dry run and a real run share one code path
//!
//! AC-14 requires that "dry-run enumerates *exactly* the real run's set". The
//! only way to hold that is for them to be the same traversal, so
//! [`Engine::run`] takes a [`RunMode`] and the mode changes **what is done
//! with** the matches, never **which files match**. Two functions that agree
//! today are two functions that can disagree after the next edit.
//!
//! # Enablement is re-checked at execution, not just at the API
//!
//! A rule can be enabled, then edited, then executed. `preview.rs` blocks the
//! *enable*; [`Engine::run`] in [`RunMode::Execute`] re-checks that the preview
//! still binds the current body, so an edit between enable and run cannot slip
//! a changed rule into a real pass. AC-51 asks for the daemon to enforce this,
//! and "the daemon" includes the moment it acts, not only the moment it is
//! asked.
//!
//! # …and the body is not the only thing that moves
//!
//! The rule can hold perfectly still while the corpus does not. Files are
//! created, deleted, retagged and touched between the dry run an operator read
//! and the run they authorized, and a hash over the rule body cannot see any of
//! it. So [`RunMode::Execute`] also compares the set it just matched against
//! [`PreviewRecord::matches`], and refuses on any difference.
//!
//! Refuses, rather than intersecting down to the previewed set. The friendlier
//! reading — act on the overlap — still acts on a list nobody approved in that
//! shape, and does it quietly. The operator gets a [`MatchSetDrift`] naming
//! what appeared, what left and what changed signal, and re-previews.

use std::collections::BTreeMap;

use shepherd_catalog::atime::AtimeMode;
use shepherd_core::{FileId, FileStat, Timestamp};

use crate::r#match::{MatchContext, MatchError, Matcher};
use crate::preview::{
    AccessSignalSource, EnableDecision, EnableRefusal, PreviewRecord, PreviewedMatch, RuleAction,
    RuleBody, may_enable, preview_hash,
};

/// One file the engine may act on, with the context its predicates need.
#[derive(Debug, Clone)]
pub struct Candidate {
    pub file: FileId,
    pub stat: FileStat,
    /// §4.12's Shepherd-owned access signal, where one exists.
    pub last_observed_access: Option<Timestamp>,
    pub tags: Vec<String>,
}

/// Whether this pass may act.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunMode {
    /// Enumerate and report. Touches nothing.
    DryRun,
    /// Produce actions. Requires a preview that still binds the current body.
    Execute,
}

/// What the engine decided to do with one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedAction {
    pub file: FileId,
    pub action: RuleAction,
    /// Which signal drove the age predicate, if the rule had one. AC-14
    /// requires the preview to state this per match.
    pub age_signal: Option<AccessSignalSource>,
}

/// One previewed match whose record no longer reads the same.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchDrifted {
    pub previewed: PreviewedMatch,
    pub current: PreviewedMatch,
}

/// How the set this pass matched differs from the set a preview enumerated.
///
/// Whole [`PreviewedMatch`] records are compared rather than file ids alone, so
/// a field added to that struct joins this comparison automatically instead of
/// having to be remembered here. That includes the signal: AC-14 makes the
/// preview state which signal drove each match, so a match driven by a
/// different signal is not the match that was approved.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct MatchSetDrift {
    /// Matching now, absent from the preview — files the operator never saw.
    pub added: Vec<PreviewedMatch>,
    /// Previewed, no longer matching.
    pub removed: Vec<PreviewedMatch>,
    /// Same file, different record.
    pub changed: Vec<MatchDrifted>,
}

impl MatchSetDrift {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty() && self.removed.is_empty() && self.changed.is_empty()
    }
}

/// Compare a pass's matches against the set a preview recorded.
///
/// Keyed by file and ordered, so the refusal an operator reads is the same on
/// every run rather than whatever a hash map happened to iterate.
fn drift_against(previewed: &[PreviewedMatch], current: &[PreviewedMatch]) -> MatchSetDrift {
    let mut outstanding: BTreeMap<FileId, &PreviewedMatch> =
        previewed.iter().map(|m| (m.file, m)).collect();
    let mut drift = MatchSetDrift::default();
    for c in current {
        match outstanding.remove(&c.file) {
            // A file id repeated inside one pass consumes its previewed entry
            // once and lands in `added` on the second sighting. That is a
            // caller bug either way, and it fails closed.
            None => drift.added.push(c.clone()),
            Some(p) if p != c => drift.changed.push(MatchDrifted {
                previewed: p.clone(),
                current: c.clone(),
            }),
            Some(_) => {}
        }
    }
    drift.removed = outstanding.into_values().cloned().collect();
    drift
}

/// Why a run refused to proceed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EngineRefusal {
    /// The rule body would not compile — an unknown key, an empty predicate.
    /// Refused rather than ignored: a typo'd key silently dropped turns
    /// `{"ext":["raw"],"older_thn_days":365}` into "every raw file ever".
    InvalidRule { detail: String },
    /// §4.12: a destructive rule resting solely on untrustworthy `atime`.
    Untrustworthy { detail: String },
    /// `Execute` without a preview, or against a stale one.
    NotEnabled { decision: EnableDecision },
    /// The set this pass matches is not the set the preview enumerated.
    ///
    /// Refused rather than intersected down to the previewed set. Intersecting
    /// looks friendlier and would still act — on a list the operator approved
    /// in a different shape. AC-14 says the dry run enumerates *exactly* the
    /// real run's set, and the honest answer to a corpus that moved underneath
    /// it is a fresh preview, not a quiet subset.
    ///
    /// **Callers must surface this as *re-preview required*, not as an error
    /// string.** It is a routine, expected outcome — the corpus moved, which it
    /// does constantly — and the operator's next step is a new dry run, not a
    /// retry and not a support ticket. A wildcard arm rendering every refusal
    /// as "refused" compiles perfectly well and throws the `drift` away, which
    /// is the whole content of the answer.
    PreviewDrifted { drift: MatchSetDrift },
}

/// The result of a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunReport {
    pub mode: RunMode,
    /// Every match, with its driving signal. In `DryRun` this *is* the preview.
    pub matches: Vec<PreviewedMatch>,
    /// Populated only in [`RunMode::Execute`]. A dry run plans nothing, so
    /// there is no shape in which it can act by accident.
    pub actions: Vec<PlannedAction>,
    /// Files considered. Reported so "0 matches" is distinguishable from
    /// "nothing was looked at" — they are very different answers to
    /// "is my rule working?".
    pub considered: usize,
}

impl RunReport {
    /// The preview record a dry run produces, ready to store against the rule.
    pub fn into_preview(self, body: &RuleBody, at: Timestamp) -> PreviewRecord {
        PreviewRecord {
            rule_hash: preview_hash(body),
            previewed_at: at,
            matches: self.matches,
        }
    }
}

/// Runs one rule over a set of candidates.
pub struct Engine<'a> {
    pub body: &'a RuleBody,
    pub atime_mode: AtimeMode,
}

impl<'a> Engine<'a> {
    pub fn new(body: &'a RuleBody, atime_mode: AtimeMode) -> Self {
        Self { body, atime_mode }
    }

    /// Evaluate the rule over `candidates`.
    ///
    /// One traversal for both modes, so AC-14's "the dry run enumerates exactly
    /// the real run's set" is a property of there being a single code path
    /// rather than a claim about two.
    pub fn run(
        &self,
        candidates: &[Candidate],
        mode: RunMode,
        preview: Option<&PreviewRecord>,
        now: Timestamp,
    ) -> Result<RunReport, EngineRefusal> {
        // Compiling performs §4.12's destructive-atime rejection once, as a
        // property of the rule on this root, rather than per file.
        let matcher = Matcher::compile(
            &self.body.name,
            &self.body.match_json,
            &self.body.action,
            self.atime_mode,
        )
        .map_err(|e| match e {
            MatchError::AtimeUntrustworthy { .. } => EngineRefusal::Untrustworthy {
                detail: e.to_string(),
            },
            other => EngineRefusal::InvalidRule {
                detail: other.to_string(),
            },
        })?;

        // Re-checked HERE, not only when the rule was enabled. A rule can be
        // enabled, edited, then run; `may_enable` guards the first of those and
        // this guards the third.
        let previewed = if mode == RunMode::Execute {
            let decision = may_enable(self.body, preview, self.atime_mode);
            if !decision.is_permitted() {
                return Err(EngineRefusal::NotEnabled { decision });
            }
            // Bound here rather than reached for at the comparison below. An
            // absent preview would otherwise compare equal to an empty match
            // set, and "nothing drifted" is not an answer a run that was never
            // previewed is entitled to. `may_enable` already refuses `None`;
            // this makes that a property of this function rather than a
            // second-hand one.
            //
            // Deliberately un-killable by test: deleting it leaves the suite
            // green, because `may_enable` catches the case today. It is here
            // against a future edit to `may_enable`, not against a bug that
            // exists — redundant on purpose rather than dead.
            let Some(p) = preview else {
                return Err(EngineRefusal::NotEnabled {
                    decision: EnableDecision::Refused(vec![EnableRefusal::NoPreview]),
                });
            };
            Some(p)
        } else {
            None
        };

        let mut matches = Vec::new();
        let mut actions = Vec::new();
        for c in candidates {
            let out = matcher.matches(
                &c.stat,
                &MatchContext {
                    now,
                    atime_mode: self.atime_mode,
                    last_observed_access: c.last_observed_access,
                    tags: &c.tags,
                },
            );
            if !out.matched {
                continue;
            }
            // The signal the matcher actually resolved, which under `relatime`
            // is legitimately `Mtime` even for an `atime_older_than_days`
            // predicate. The preview must print what drove the match, not what
            // the rule asked for — that difference is the point of the field.
            //
            // Carried through as-is, `None` included. `unwrap_or(Mtime)` here
            // undid the matcher's own correction one line after it was made: a
            // match selected by extension or by a negated age predicate has no
            // driving timestamp, and naming one is the mislabel this field
            // exists to prevent.
            matches.push(PreviewedMatch {
                file: c.file,
                signal: out.age_signal,
            });
            if mode == RunMode::Execute {
                actions.push(PlannedAction {
                    file: c.file,
                    action: self.body.action.clone(),
                    age_signal: out.age_signal,
                });
            }
        }

        // `may_enable` proves the rule *body* is the one that was previewed. It
        // cannot prove anything about the corpus, which moves on its own:
        // files are created, deleted, retagged and touched between the dry run
        // an operator read and the run they authorized. AC-14's "exactly the
        // real run's set" is a claim about the set, so the set is compared —
        // before any of these actions reach the caller.
        if let Some(p) = previewed {
            let drift = drift_against(&p.matches, &matches);
            if !drift.is_empty() {
                return Err(EngineRefusal::PreviewDrifted { drift });
            }
        }

        Ok(RunReport {
            mode,
            matches,
            actions,
            considered: candidates.len(),
        })
    }

    /// Convenience: a dry run, and the preview record it produces.
    pub fn preview(
        &self,
        candidates: &[Candidate],
        now: Timestamp,
    ) -> Result<PreviewRecord, EngineRefusal> {
        let report = self.run(candidates, RunMode::DryRun, None, now)?;
        Ok(report.into_preview(self.body, now))
    }
}

#[cfg(test)]
#[path = "engine_tests.rs"]
mod tests;
