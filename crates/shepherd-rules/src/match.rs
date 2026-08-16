//! The rule **matcher** (AC-13) — a pure predicate, and nothing else.
//!
//! AC-13: "rules match on extension, mtime, ctime, atime, size, path glob, and
//! tag." All seven, over a [`FileStat`] plus a tag set. No engine, no preview,
//! no destructive action — those are [`crate::preview`] and worker-4's engine.
//! §6 moved this into Phase 1 precisely so AC-13's gate became *passable*:
//! iteration 1 gated it at Phase 1 while creating the crate in Phase 2.
//!
//! # §4.12 lives here, and it is the reason this file is safety work
//!
//! An age predicate needs an answer to "accessed when?", and last-access is
//! unreliable on two of three platforms. §4.12 fixes the fallback order —
//! `last_observed_access` → `atime` (**only** where fidelity is `reliable`) →
//! `mtime` — and requires the matcher to record *which signal actually drove
//! each match*, so a dry-run preview can say so rather than implying `atime`
//! did.
//!
//! The consequence if this is wrong is not a mis-sorted list. On a volume where
//! last-access never advances, `atime` never moves, so "not accessed in 1 year"
//! does not under-match — it eventually matches **everything**, including files
//! in daily use. Under a `discard` policy that is a mass-destruction trigger.
//!
//! So [`Matcher::compile`] **rejects** a destructive rule whose age predicate
//! rests on `atime` where the root's fidelity is `disabled` or `unknown`. It
//! calls [`AtimeMode::supports_destructive_age_rule`] rather than re-deriving
//! the test — that method exists so both sides agree, and re-deriving it is how
//! `Relatime` (Linux's *default* mount option) nearly got rejected, which would
//! have refused destructive age rules on very nearly every Linux root.

use globset::{GlobBuilder, GlobMatcher};
use serde::{Deserialize, Serialize};
use shepherd_catalog::AtimeMode;
use shepherd_core::{FileStat, Timestamp};

use crate::preview::{AccessSignalSource, RuleAction};

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum MatchError {
    #[error("invalid match predicate: {0}")]
    Invalid(String),
    #[error("invalid path glob `{glob}`: {detail}")]
    Glob { glob: String, detail: String },
    /// §4.12 rule 4. Not a warning — a rejection.
    #[error(
        "destructive rule `{rule}` rests on an `atime` age predicate, but root fidelity is \
         `{mode}`. Where last-access never advances, an age predicate eventually matches EVERY \
         file, including ones in daily use — so this is refused rather than warned about (§4.12)"
    )]
    AtimeUntrustworthy { rule: String, mode: &'static str },
}

pub type Result<T> = std::result::Result<T, MatchError>;

/// Which timestamp an age predicate reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimeField {
    /// §4.12's resolved access signal, with the documented fallback order. The
    /// default, and what a user means by "not accessed in a year".
    Accessed,
    Mtime,
    Ctime,
    /// Raw OS `atime`, requested explicitly. Subject to the same fidelity
    /// rejection — asking for it by name does not make it trustworthy.
    Atime,
}

/// One compiled predicate.
#[derive(Debug)]
pub enum Predicate {
    /// Case-insensitive extension match. `ext` is stored lowercase by the
    /// scanner, and users type `RAW` as often as `raw`.
    Ext(Vec<String>),
    PathGlob(Box<GlobMatcher>),
    MinSize(u64),
    MaxSize(u64),
    OlderThan {
        field: TimeField,
        days: u64,
    },
    Tag(String),
    All(Vec<Predicate>),
    Any(Vec<Predicate>),
    Not(Box<Predicate>),
}

/// Everything a match needs beyond the file itself.
#[derive(Debug, Clone)]
pub struct MatchContext<'a> {
    pub now: Timestamp,
    /// The root's probed `atime` fidelity (§4.12).
    pub atime_mode: AtimeMode,
    /// Shepherd's own access signal, where one exists.
    pub last_observed_access: Option<Timestamp>,
    pub tags: &'a [String],
}

/// Why a file matched, or did not — plus which signal drove the age test.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MatchOutcome {
    pub matched: bool,
    /// The signal that actually drove the age predicate, `None` if the rule has
    /// no age predicate. AC-14's preview must state this per match.
    pub age_signal: Option<AccessSignalSource>,
}

/// A compiled rule predicate.
#[derive(Debug)]
pub struct Matcher {
    root: Predicate,
    /// Present when the rule has an age predicate at all.
    age_field: Option<TimeField>,
}

impl Matcher {
    /// Compile `match_json`, refusing a destructive rule that cannot be trusted.
    ///
    /// `action` and `atime_mode` are taken here rather than at evaluation time
    /// on purpose: §4.12's rejection is a property of the *rule on this root*,
    /// so it belongs at compile time where it is answered once and cannot be
    /// skipped by a caller who forgets to ask.
    pub fn compile(
        rule_name: &str,
        match_json: &serde_json::Value,
        action: &RuleAction,
        atime_mode: AtimeMode,
    ) -> Result<Self> {
        let root = compile_predicate(match_json)?;
        let age_field = first_age_field(&root);

        // §4.12 rule 4, and the one line in this file that refuses rather than
        // reports. `Accessed` is included: its fallback order ends at `atime`
        // when there is no observed signal, so it inherits the same problem.
        let rests_on_atime = matches!(age_field, Some(TimeField::Atime | TimeField::Accessed));
        if action.is_destructive() && rests_on_atime && !atime_mode.supports_destructive_age_rule()
        {
            return Err(MatchError::AtimeUntrustworthy {
                rule: rule_name.to_owned(),
                mode: atime_mode.as_str(),
            });
        }

        Ok(Self { root, age_field })
    }

    /// Compile without the destructive-rule check. For non-destructive uses —
    /// search filters, suggestions — where §4.12's rejection does not apply.
    pub fn compile_readonly(match_json: &serde_json::Value) -> Result<Self> {
        let root = compile_predicate(match_json)?;
        let age_field = first_age_field(&root);
        Ok(Self { root, age_field })
    }

    pub fn matches(&self, file: &FileStat, ctx: &MatchContext<'_>) -> MatchOutcome {
        let matched = eval_predicate(&self.root, file, ctx);
        MatchOutcome {
            matched,
            age_signal: self.age_field.map(|f| resolve_signal(f, file, ctx).1),
        }
    }

    /// Which signal this rule's age predicate rests on, for
    /// `RuleBody::age_signal`. `None` when the rule has no age predicate.
    pub fn age_signal_for(
        &self,
        file: &FileStat,
        ctx: &MatchContext<'_>,
    ) -> Option<AccessSignalSource> {
        self.age_field.map(|f| resolve_signal(f, file, ctx).1)
    }
}

/// §4.12's fallback order, and the single place it is written down.
///
/// `last_observed_access` → `atime` (only where fidelity is `reliable`) →
/// `mtime`. Returns the timestamp *and* which signal supplied it, because the
/// preview has to name it.
fn resolve_signal(
    field: TimeField,
    file: &FileStat,
    ctx: &MatchContext<'_>,
) -> (Timestamp, AccessSignalSource) {
    match field {
        TimeField::Mtime => (file.mtime, AccessSignalSource::Mtime),
        TimeField::Ctime => (file.ctime, AccessSignalSource::Mtime),
        TimeField::Atime => match file.atime {
            // Requested by name, but still only trusted where fidelity is.
            Some(t) if ctx.atime_mode.may_fold_into_observed_access() => {
                (t, AccessSignalSource::Atime)
            }
            _ => (file.mtime, AccessSignalSource::Mtime),
        },
        TimeField::Accessed => {
            if let Some(t) = ctx.last_observed_access {
                return (t, AccessSignalSource::Observed);
            }
            match file.atime {
                Some(t) if ctx.atime_mode.may_fold_into_observed_access() => {
                    (t, AccessSignalSource::Atime)
                }
                _ => (file.mtime, AccessSignalSource::Mtime),
            }
        }
    }
}

fn eval_predicate(p: &Predicate, file: &FileStat, ctx: &MatchContext<'_>) -> bool {
    match p {
        Predicate::Ext(exts) => {
            let name = file.rel_path.rsplit(['/', '\\']).next().unwrap_or("");
            // A leading dot is not an extension separator — `.gitignore` has
            // none. Same rule the scanner applies, deliberately.
            match name.rfind('.').filter(|&i| i > 0) {
                Some(i) => {
                    let got = name[i + 1..].to_ascii_lowercase();
                    exts.contains(&got)
                }
                None => false,
            }
        }
        Predicate::PathGlob(g) => g.is_match(file.rel_path.replace('\\', "/")),
        Predicate::MinSize(n) => file.size >= *n,
        Predicate::MaxSize(n) => file.size <= *n,
        Predicate::OlderThan { field, days } => {
            let (at, _) = resolve_signal(*field, file, ctx);
            let age_nanos = ctx.now.as_nanos().saturating_sub(at.as_nanos());
            // A file whose timestamp is in the FUTURE has a negative age and
            // must not read as ancient. §4.12's `first_seen_at` is the real
            // remedy; refusing to match here is the fail-safe direction.
            age_nanos > 0 && (age_nanos as u128) >= (*days as u128) * 86_400_000_000_000u128
        }
        Predicate::Tag(t) => ctx.tags.iter().any(|x| x == t),
        Predicate::All(ps) => ps.iter().all(|p| eval_predicate(p, file, ctx)),
        Predicate::Any(ps) => ps.iter().any(|p| eval_predicate(p, file, ctx)),
        Predicate::Not(p) => !eval_predicate(p, file, ctx),
    }
}

/// The first age predicate in the tree, which is what `age_signal` reports.
fn first_age_field(p: &Predicate) -> Option<TimeField> {
    match p {
        Predicate::OlderThan { field, .. } => Some(*field),
        Predicate::All(ps) | Predicate::Any(ps) => ps.iter().find_map(first_age_field),
        Predicate::Not(inner) => first_age_field(inner),
        _ => None,
    }
}

fn compile_predicate(v: &serde_json::Value) -> Result<Predicate> {
    let obj = v
        .as_object()
        .ok_or_else(|| MatchError::Invalid("match predicate must be an object".into()))?;

    // Explicit combinators first.
    if let Some(list) = obj.get("all") {
        return Ok(Predicate::All(compile_list(list)?));
    }
    if let Some(list) = obj.get("any") {
        return Ok(Predicate::Any(compile_list(list)?));
    }
    if let Some(inner) = obj.get("not") {
        return Ok(Predicate::Not(Box::new(compile_predicate(inner)?)));
    }

    // A flat object is an AND of its keys — the shape the stored rules use.
    let mut parts = Vec::new();
    for (k, val) in obj {
        let p = match k.as_str() {
            "ext" => Predicate::Ext(
                as_str_list(val, "ext")?
                    .into_iter()
                    .map(|s| s.trim_start_matches('.').to_ascii_lowercase())
                    .collect(),
            ),
            "path_glob" => {
                let s = val
                    .as_str()
                    .ok_or_else(|| MatchError::Invalid("path_glob must be a string".into()))?;
                // `literal_separator(true)` is NOT the default, and the
                // default is the dangerous direction: without it `*` crosses
                // `/`, so `Photos/*.raw` also matches `Photos/2024/a.raw` —
                // selecting files the user did not name, for an action that may
                // destroy them. `**` still spans directories, which is the
                // whole point of having two syntaxes.
                let g = GlobBuilder::new(s)
                    .literal_separator(true)
                    .build()
                    .map_err(|e| MatchError::Glob {
                        glob: s.to_owned(),
                        detail: e.to_string(),
                    })?;
                Predicate::PathGlob(Box::new(g.compile_matcher()))
            }
            "min_size" => Predicate::MinSize(as_u64(val, "min_size")?),
            "max_size" => Predicate::MaxSize(as_u64(val, "max_size")?),
            "older_than_days" => Predicate::OlderThan {
                field: TimeField::Accessed,
                days: as_u64(val, "older_than_days")?,
            },
            "mtime_older_than_days" => Predicate::OlderThan {
                field: TimeField::Mtime,
                days: as_u64(val, "mtime_older_than_days")?,
            },
            "ctime_older_than_days" => Predicate::OlderThan {
                field: TimeField::Ctime,
                days: as_u64(val, "ctime_older_than_days")?,
            },
            "atime_older_than_days" => Predicate::OlderThan {
                field: TimeField::Atime,
                days: as_u64(val, "atime_older_than_days")?,
            },
            "tag" => Predicate::Tag(
                val.as_str()
                    .ok_or_else(|| MatchError::Invalid("tag must be a string".into()))?
                    .to_owned(),
            ),
            "tags" => Predicate::All(
                as_str_list(val, "tags")?
                    .into_iter()
                    .map(Predicate::Tag)
                    .collect(),
            ),
            // An unknown key is REFUSED, never ignored. A typo'd predicate that
            // is silently dropped widens the rule — `{"ext":["raw"],
            // "older_thn_days":365}` would match every raw file ever, and the
            // action may be destructive.
            other => {
                return Err(MatchError::Invalid(format!(
                    "unknown predicate `{other}`. Refusing rather than ignoring it: a dropped \
                     predicate WIDENS the rule, and the action may destroy files"
                )));
            }
        };
        parts.push(p);
    }

    match parts.len() {
        0 => Err(MatchError::Invalid(
            "empty predicate would match every file".into(),
        )),
        1 => Ok(parts.pop().expect("len checked")),
        _ => Ok(Predicate::All(parts)),
    }
}

fn compile_list(v: &serde_json::Value) -> Result<Vec<Predicate>> {
    let arr = v
        .as_array()
        .ok_or_else(|| MatchError::Invalid("all/any takes an array".into()))?;
    if arr.is_empty() {
        return Err(MatchError::Invalid(
            "an empty all/any list is ambiguous; state the predicate".into(),
        ));
    }
    arr.iter().map(compile_predicate).collect()
}

fn as_u64(v: &serde_json::Value, what: &str) -> Result<u64> {
    v.as_u64()
        .ok_or_else(|| MatchError::Invalid(format!("{what} must be a non-negative integer")))
}

fn as_str_list(v: &serde_json::Value, what: &str) -> Result<Vec<String>> {
    let arr = v
        .as_array()
        .ok_or_else(|| MatchError::Invalid(format!("{what} must be an array of strings")))?;
    arr.iter()
        .map(|x| {
            x.as_str()
                .map(str::to_owned)
                .ok_or_else(|| MatchError::Invalid(format!("{what} entries must be strings")))
        })
        .collect()
}

#[cfg(test)]
#[path = "match_tests.rs"]
mod tests;
