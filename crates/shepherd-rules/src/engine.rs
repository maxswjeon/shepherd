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

use shepherd_catalog::atime::AtimeMode;
use shepherd_core::{FileId, FileStat, Timestamp};

use crate::r#match::{MatchContext, MatchError, Matcher};
use crate::preview::{
    AccessSignalSource, EnableDecision, PreviewRecord, PreviewedMatch, RuleAction, RuleBody,
    may_enable, preview_hash,
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
        if mode == RunMode::Execute {
            let decision = may_enable(self.body, preview, self.atime_mode);
            if !decision.is_permitted() {
                return Err(EngineRefusal::NotEnabled { decision });
            }
        }

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
            matches.push(PreviewedMatch {
                file: c.file,
                signal: out.age_signal.unwrap_or(AccessSignalSource::Mtime),
            });
            if mode == RunMode::Execute {
                actions.push(PlannedAction {
                    file: c.file,
                    action: self.body.action.clone(),
                    age_signal: out.age_signal,
                });
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
