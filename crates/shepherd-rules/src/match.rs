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
//! So [`Matcher::compile`] **rejects** a destructive rule where *any* of its
//! age predicates rests on `atime` and the root's fidelity is `disabled` or
//! `unknown` — *any*, because a rule that reaches for `atime` in its second
//! predicate is exactly as dangerous as one that reaches for it in its first,
//! and inspecting only the first is how `all: [mtime_older_than_days,
//! atime_older_than_days]` used to compile on a root where atime is dead. It
//! calls [`AtimeMode::supports_destructive_age_rule`] rather than re-deriving
//! the test — that method exists so both sides agree, and re-deriving it is how
//! `Relatime` (Linux's *default* mount option) nearly got rejected, which would
//! have refused destructive age rules on very nearly every Linux root.
//!
//! # Write the assertion from the requirement, not from the library
//!
//! `a_single_star_does_not_cross_directory_separators` was written from what a
//! path glob *should* do, before checking what `globset` actually does. It then
//! failed: `*` crosses `/` by default, so `Photos/*.raw` also matched
//! `Photos/2024/a.raw` — files the user never named, for an action that
//! destroys on a delete-mode root. `literal_separator(true)` had to be asked
//! for.
//!
//! Had the test been written *after* observing the library, it would have
//! encoded the over-matching as expected and passed forever. **A test written
//! from observed behaviour can only ever confirm it; only one written from the
//! requirement can disagree with the code.** That generalises well past globs,
//! and it is the reason this module's tests assert refusals — unknown keys,
//! empty predicates, untrustworthy `atime` — rather than only successes.

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
        //
        // EVERY age predicate is inspected, not the one `age_field` happens to
        // report. Those are different questions, and answering this one with
        // `first_age_field` let a compound rule walk straight past the refusal:
        // in `all: [mtime_older_than_days, atime_older_than_days]` the first age
        // field is `Mtime`, so the rule compiled — and its atime condition was
        // then evaluated by the fallback, selecting files on `mtime` under a
        // rule the user wrote in terms of last access.
        let rests_on_atime = any_age_field_rests_on_atime(&root);
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
        let (matched, signal) = eval_predicate(&self.root, file, ctx);
        MatchOutcome {
            matched,
            // The fallback applies ONLY to a non-match. A successful match that
            // returned no signal returned it deliberately: `any: [{ext}, {age}]`
            // selected by extension, or a `not` around an age predicate, are
            // both matches that no timestamp authorized. Overriding that with
            // the rule's first age predicate made the preview claim a
            // timestamp had — and, worse, made `age_signal` depend on a value
            // the match never read, so a change in the fallback source can
            // raise `PreviewDrifted` while the matched set and the authorizing
            // branch are both unchanged.
            age_signal: if matched {
                signal
            } else {
                self.fallback_signal(file, ctx)
            },
        }
    }

    /// Which signal this rule's age predicate rests on, for
    /// `RuleBody::age_signal`. `None` when the rule has no age predicate.
    ///
    /// Answers through the same evaluation as [`Self::matches`], because
    /// `Engine::run` refuses on a preview/run signal difference and two paths
    /// that resolve it differently would be a refusal that fires on nothing.
    pub fn age_signal_for(
        &self,
        file: &FileStat,
        ctx: &MatchContext<'_>,
    ) -> Option<AccessSignalSource> {
        let (matched, signal) = eval_predicate(&self.root, file, ctx);
        if matched {
            signal
        } else {
            self.fallback_signal(file, ctx)
        }
    }

    /// The rule-level answer, for a file that matched **nothing**.
    ///
    /// No branch authorized the match, so no branch can name the signal — but
    /// `None` would read as "this rule has no age predicate", which is a
    /// different statement. Nothing is acted on for a non-match, so naming the
    /// rule's first age predicate is the honest remainder.
    ///
    /// Never applied to a MATCH. A matching branch that carries no age
    /// predicate reports `None` because none authorized it, and substituting a
    /// signal there is the mislabel this whole apparatus exists to prevent —
    /// in the same shape as the `Mtime`-for-`Ctime` one, one layer up.
    fn fallback_signal(
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
        // Reads `file.ctime`, so it reports `Ctime`. Naming `Mtime` here made
        // every ctime match tell the operator that an mtime rule selected the
        // file, which is the signal-provenance contract §4.12 requires the
        // preview to state — and `Engine::run` refuses execution on exactly a
        // preview/run signal difference, so the wrong label is a refusal that
        // never fires. Not part of the access fallback chain below: `ctime` is
        // asked for by name and always answers for itself.
        TimeField::Ctime => (file.ctime, AccessSignalSource::Ctime),
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

/// Evaluate, and report the age signal of the branch that **authorized** the
/// match.
///
/// The second half is the point. `age_field` was resolved once at compile time
/// as the first age predicate in the tree, which answers "which one is written
/// first" — a different question from "which one selected this file". In
/// `any: [mtime…, ctime…]` where only the ctime branch is true, that named a
/// timestamp that provably could not have driven the match, and `Engine::run`'s
/// refusal on a preview/run signal difference compares exactly these labels.
///
/// * `Any` — the branch that matched, so the first `Some` among the matching
///   ones.
/// * `All` — every branch contributed; the first age signal among them is the
///   one the rule rests on, and there is no narrower true answer.
/// * `Not` — an age predicate inside a negation did not authorize anything by
///   being old, so it names nothing.
fn eval_predicate(
    p: &Predicate,
    file: &FileStat,
    ctx: &MatchContext<'_>,
) -> (bool, Option<AccessSignalSource>) {
    match p {
        Predicate::All(ps) => {
            let mut signal = None;
            for sub in ps {
                let (ok, s) = eval_predicate(sub, file, ctx);
                if !ok {
                    return (false, None);
                }
                signal = signal.or(s);
            }
            (true, signal)
        }
        Predicate::Any(ps) => {
            for sub in ps {
                let (ok, s) = eval_predicate(sub, file, ctx);
                if ok {
                    return (true, s);
                }
            }
            (false, None)
        }
        Predicate::Not(inner) => (!eval_predicate(inner, file, ctx).0, None),
        Predicate::OlderThan { field, days } => {
            let (at, signal) = resolve_signal(*field, file, ctx);
            let age_nanos = ctx.now.as_nanos().saturating_sub(at.as_nanos());
            // A file whose timestamp is in the FUTURE has a negative age and
            // must not read as ancient. §4.12's `first_seen_at` is the real
            // remedy; refusing to match here is the fail-safe direction.
            let matched =
                age_nanos > 0 && (age_nanos as u128) >= (*days as u128) * 86_400_000_000_000u128;
            (matched, matched.then_some(signal))
        }
        other => (eval_simple(other, file, ctx), None),
    }
}

/// The predicates that carry no age signal.
fn eval_simple(p: &Predicate, file: &FileStat, ctx: &MatchContext<'_>) -> bool {
    match p {
        Predicate::Ext(exts) => {
            let name = file
                .rel_path
                .rsplit(|c: char| is_component_boundary(c))
                .next()
                .unwrap_or("");
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
        Predicate::PathGlob(g) => g.is_match(glob_subject(&file.rel_path).as_ref()),
        Predicate::MinSize(n) => file.size >= *n,
        Predicate::MaxSize(n) => file.size <= *n,
        Predicate::Tag(t) => ctx.tags.iter().any(|x| x == t),
        // Handled by `eval_predicate`, which is the only caller.
        Predicate::OlderThan { .. } | Predicate::All(_) | Predicate::Any(_) | Predicate::Not(_) => {
            eval_predicate(p, file, ctx).0
        }
    }
}

/// Whether this character separates path components on the host.
///
/// **`\` is an ordinary character in a Unix filename**, and this is the
/// destructive side of that fact. A root-level file literally named
/// `cache\private.txt` was rewritten to `cache/private.txt` before matching, so
/// `path_glob: "cache/**"` selected a file that is not inside the directory the
/// operator named — and a rule's action can destroy it. Selecting a file the
/// operator did not name is the one thing the glob predicate exists to prevent;
/// `literal_separator(true)` is set on every glob for the same reason.
///
/// The catalog stores `rel_path` "with separators left exactly as the OS gave
/// them", so on Windows both characters really are boundaries and both are
/// treated as such there.
#[inline]
fn is_component_boundary(c: char) -> bool {
    c == '/' || (cfg!(windows) && c == '\\')
}

/// The path a glob is matched against.
///
/// Globs are written with `/` — that is what `globset` parses and what a user
/// types — so a Windows path's `\` separators are rewritten to match. On Unix
/// nothing is rewritten, because there is nothing there that is a separator.
fn glob_subject(rel_path: &str) -> std::borrow::Cow<'_, str> {
    if cfg!(windows) && rel_path.contains('\\') {
        std::borrow::Cow::Owned(rel_path.replace('\\', "/"))
    } else {
        std::borrow::Cow::Borrowed(rel_path)
    }
}

/// Whether **any** age predicate in the tree reads a signal that can fall back
/// to `atime` — the question §4.12's destructive refusal asks.
///
/// Deliberately not [`first_age_field`]: that answers "which signal does the
/// preview name", and one predicate cannot speak for a rule whose refusal is a
/// property of all of them.
fn any_age_field_rests_on_atime(p: &Predicate) -> bool {
    match p {
        Predicate::OlderThan { field, .. } => {
            matches!(field, TimeField::Atime | TimeField::Accessed)
        }
        Predicate::All(ps) | Predicate::Any(ps) => ps.iter().any(any_age_field_rests_on_atime),
        Predicate::Not(inner) => any_age_field_rests_on_atime(inner),
        // EXHAUSTIVE ON PURPOSE — no `_` arm. This drives a destructive-rule
        // REFUSAL, so a wildcard would answer `false` for any variant added
        // later, and a new predicate carrying a `TimeField` would silently
        // reopen exactly the bypass this function was written to close. Listing
        // them makes the next person decide instead of inheriting an answer.
        Predicate::Ext(_)
        | Predicate::PathGlob(_)
        | Predicate::MinSize(_)
        | Predicate::MaxSize(_)
        | Predicate::Tag(_) => false,
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

    // Explicit combinators first — and ALONE in their object. Returning the
    // moment the key is seen drops every sibling key unread: `max_size` is
    // discarded, WIDENING a rule whose action may destroy, and a typo'd
    // predicate slips past the unknown-key refusal below that exists to catch
    // exactly that.
    //
    // Refused rather than folded into a conjunction, because
    // `{"any":[A,B],"max_size":N}` reads equally well as `(A|B) AND N` or as an
    // `N` the author meant to put INSIDE the list. Guessing between two honest
    // readings for a destructive rule is what the empty-list refusal already
    // declines to do; say so, and let the author write the one they meant.
    for combinator in ["all", "any", "not"] {
        if obj.contains_key(combinator) && obj.len() > 1 {
            let siblings = obj
                .keys()
                .filter(|k| k.as_str() != combinator)
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join("`, `");
            // The rewrite depends on the combinator: `all` already IS the
            // conjunction, so the siblings belong in its list; `any` and `not`
            // have to be wrapped in one.
            let rewrite = if combinator == "all" {
                "move them into the `all` list".to_owned()
            } else {
                format!("wrap both in one: `{{\"all\": [ {{\"{combinator}\": ...}}, ... ]}}`")
            };
            return Err(MatchError::Invalid(format!(
                "`{combinator}` must be the only key in its object, but it stands beside \
                 `{siblings}`. Refusing rather than dropping them: a dropped predicate WIDENS \
                 the rule, and the action may destroy files. If you meant a conjunction, \
                 {rewrite}"
            )));
        }
    }

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
    // Refused HERE, at the one place list predicates are parsed, rather than in
    // each arm — the hazard is the same for every list and the arms are where a
    // future one would forget.
    //
    // It is not merely meaningless, it is dangerous in one direction. `tags: []`
    // compiled to `Predicate::All([])`, and an `all` over nothing is vacuously
    // TRUE: the rule matched every candidate in the corpus, and rule actions
    // destroy files. (`ext: []` fails the other way, matching nothing — still
    // not something a user meant to write.) The compiler already refuses an
    // empty `all`/`any` list and an empty predicate object for exactly this
    // reason; a list predicate is the third door into the same room.
    if arr.is_empty() {
        return Err(MatchError::Invalid(format!(
            "`{what}` is an empty list. An empty `tags` list matches EVERY file — an `all` \
             over no conditions is vacuously true — and the action may destroy them. State \
             the values, or remove the predicate"
        )));
    }
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
