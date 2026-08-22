//! `cargo xtask claim-ledger` — §9 rule 5.
//!
//! > Every `[U]` or untagged load-bearing claim is promoted by a spike or
//! > escalated before the phase depending on it may close — enforced by
//! > `xtask claim-ledger`, **which treats untagged as `[U]`**.
//!
//! # The grammar
//!
//! The plan tags load-bearing claims inline:
//!
//! | tag | meaning |
//! |---|---|
//! | `[V]` | verified, source unnamed |
//! | `[V: learn.microsoft.com]` | verified, source named |
//! | `[U]` | unverified |
//! | `[U — architectural inference]` | unverified, with a stated reason |
//! | `[U at method level]` | unverified, scoped |
//!
//! "Untagged" is the harder half, because in prose it is not decidable. This
//! implementation restricts it to the case that *is* decidable: a body cell of
//! a markdown table whose header names an **Evidence** column. Those cells are
//! load-bearing by construction — the column exists to carry the evidence — so
//! an empty or tagless one is an untagged claim and is classified `U`.
//!
//! Prose claims with no tag are **not** detected. That is a real limit and it
//! is reported in the output rather than left for a reader to assume away.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Verdict {
    Verified,
    Unverified,
    /// An Evidence cell carrying no tag. §9 rule 5: treated as `[U]`.
    UntaggedTreatedAsU,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Verdict::Verified => "V",
            Verdict::Unverified => "U",
            Verdict::UntaggedTreatedAsU => "U(untagged)",
        }
    }

    fn is_unverified(self) -> bool {
        !matches!(self, Verdict::Verified)
    }
}

/// A byte range on one line of the plan, 1-based line, 0-based columns.
///
/// Spans rather than bare line numbers because both checks below point at *part*
/// of a line — the tag, or the phrase inside it — and "line 2104" in a 400-column
/// markdown table row is not a location anyone can act on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub line: usize,
    pub col: usize,
    pub end: usize,
}

impl std::fmt::Display for Span {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}-{}", self.line, self.col, self.end)
    }
}

#[derive(Debug, Clone)]
pub struct Claim {
    pub span: Span,
    pub line: usize,
    pub verdict: Verdict,
    /// The text inside the tag after `V`/`U`, e.g. `learn.microsoft.com`.
    pub source: String,
    /// Trimmed context, for locating the claim by eye.
    pub context: String,
    /// Escalation ids (`OQ-A`, `D-8`, `R-21`, …) named on the same line.
    pub escalations: Vec<String>,
}

pub struct Ledger {
    pub plan: String,
    pub claims: Vec<Claim>,
    /// Escalation ids found in the escalations register, if one was supplied.
    pub known_escalations: Option<BTreeSet<String>>,
    /// Check A. Report-only; never blocks.
    pub narrow: Vec<NarrowEvidence>,
    /// Check B. Report-only; never blocks.
    pub withdrawals: Vec<Withdrawal>,
}

impl Ledger {
    pub fn counts(&self) -> (usize, usize, usize) {
        let v = self
            .claims
            .iter()
            .filter(|c| c.verdict == Verdict::Verified)
            .count();
        let u = self
            .claims
            .iter()
            .filter(|c| c.verdict == Verdict::Unverified)
            .count();
        let untagged = self
            .claims
            .iter()
            .filter(|c| c.verdict == Verdict::UntaggedTreatedAsU)
            .count();
        (v, u, untagged)
    }

    /// Unverified claims naming no escalation id that the register knows.
    pub fn unescalated(&self) -> Vec<&Claim> {
        let Some(known) = &self.known_escalations else {
            return self
                .claims
                .iter()
                .filter(|c| c.verdict.is_unverified())
                .collect();
        };
        self.claims
            .iter()
            .filter(|c| c.verdict.is_unverified())
            .filter(|c| !c.escalations.iter().any(|e| known.contains(e)))
            .collect()
    }

    /// Whether `--require-escalation` should fail the build.
    pub fn blocking(&self) -> bool {
        !self.unescalated().is_empty()
    }

    pub fn render(&self, require_escalation: bool) -> String {
        let (v, u, untagged) = self.counts();
        let mut s = String::new();
        let _ = writeln!(s, "cargo xtask claim-ledger — §9 rule 5 evidence ledger");
        let _ = writeln!(s, "{}", "=".repeat(72));
        let _ = writeln!(s, "plan: {}", self.plan);
        let _ = writeln!(
            s,
            "claims: {} total — {v} verified [V], {u} unverified [U], {untagged} untagged \
             evidence cells (treated as [U] per rule 5)",
            self.claims.len()
        );
        match &self.known_escalations {
            Some(k) => {
                let _ = writeln!(s, "escalation register: {} known ids", k.len());
            }
            None => {
                let _ = writeln!(
                    s,
                    "escalation register: ABSENT — every unverified claim counts as unescalated"
                );
            }
        }
        let _ = writeln!(s, "{}", "-".repeat(72));

        for c in self.claims.iter().filter(|c| c.verdict.is_unverified()) {
            let _ = writeln!(
                s,
                "  [{}] {}: {}{}",
                c.verdict.label(),
                c.span,
                truncate(&c.context, 120),
                if c.escalations.is_empty() {
                    String::new()
                } else {
                    format!("  (escalations: {})", c.escalations.join(", "))
                }
            );
        }

        let unescalated = self.unescalated();
        let _ = writeln!(s, "{}", "-".repeat(72));
        let _ = writeln!(
            s,
            "unverified and unescalated: {} of {}",
            unescalated.len(),
            u + untagged
        );
        if require_escalation {
            if unescalated.is_empty() {
                let _ = writeln!(
                    s,
                    "RESULT: PASS — every unverified claim names a known escalation"
                );
            } else {
                let _ = writeln!(
                    s,
                    "RESULT: FAIL — {} unverified claim(s) name no escalation the register knows. \
                     §9 rule 5 requires promotion by a spike or escalation before the depending \
                     phase may close.",
                    unescalated.len()
                );
            }
        } else {
            let _ = writeln!(
                s,
                "RESULT: REPORT ONLY (pass `--require-escalation` to make this a gate)"
            );
        }
        s.push_str(&self.render_narrow());
        s.push_str(&self.render_withdrawals());

        let _ = writeln!(s, "{}", "-".repeat(72));
        let _ = writeln!(
            s,
            "LIMIT 1: untagged detection covers Evidence-column table cells only. Untagged prose \
             claims are NOT detected and this ledger does not assert otherwise."
        );
        let _ = writeln!(
            s,
            "LIMIT 2: lines where the plan DESCRIBES the tag notation (\"claims are marked [V] \
             or [U]\") are counted as claims. Text grammar cannot separate use from mention; \
             they are left in rather than filtered by a heuristic that could also hide a real one."
        );
        let _ = writeln!(
            s,
            "LIMIT 3: the narrow-evidence and withdrawn-phrase sections are REPORT-ONLY. Neither \
             affects the exit status, including under --require-escalation. The withdrawn-phrase \
             section enumerates candidate sites for a human to confirm; it does not classify them."
        );
        s
    }

    fn render_narrow(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "{}", "-".repeat(72));
        let _ = writeln!(
            s,
            "NARROW EVIDENCE — a self-reported command/pattern that does not mention every \
             specific the claim asserts ({} found)",
            self.narrow.len()
        );
        if self.narrow.is_empty() {
            let _ = writeln!(
                s,
                "  none. This check runs only on self-reported evidence (a grep, a quoted or \
                 backticked pattern); external source pointers such as [V: crates.io] are \
                 excluded, because nothing in the text says how much of a claim they cover."
            );
        }
        for n in &self.narrow {
            let _ = writeln!(
                s,
                "  {} claims [{}] but its evidence `{}` never mentions it\n      claim: {}",
                n.span,
                n.uncovered.join(", "),
                n.evidence,
                n.claim
            );
        }
        s
    }

    fn render_withdrawals(&self) -> String {
        let total: usize = self.withdrawals.iter().map(|w| w.sites.len()).sum();
        let mut s = String::new();
        let _ = writeln!(s, "{}", "-".repeat(72));
        let _ = writeln!(
            s,
            "WITHDRAWN MECHANISMS — {} declared dead, {} other site(s) where their distinguishing \
             tokens co-occur. Each site is a CANDIDATE for a human to confirm is a withdrawal \
             context and not a live assertion; this section classifies nothing.",
            self.withdrawals.len(),
            total
        );
        for w in &self.withdrawals {
            let _ = writeln!(
                s,
                "  {} withdrew \"{}\"  [tokens: {}]",
                w.declared_at,
                truncate(&w.phrase, 70),
                w.tokens.join(" + ")
            );
            for (span, text) in &w.sites {
                let _ = writeln!(s, "      also at {span}: {text}");
            }
            if w.sites.is_empty() {
                let _ = writeln!(s, "      no other site mentions it");
            }
        }
        s
    }

    pub fn to_json(&self) -> String {
        let (v, u, untagged) = self.counts();
        serde_json::to_string_pretty(&serde_json::json!({
            "command": "claim-ledger",
            "plan": self.plan,
            "verified": v,
            "unverified": u,
            "untagged_treated_as_u": untagged,
            "escalation_register_present": self.known_escalations.is_some(),
            "unescalated": self.unescalated().len(),
            "narrow_evidence": self.narrow.iter().map(|n| serde_json::json!({
                "line": n.span.line, "col": n.span.col, "end": n.span.end,
                "uncovered": n.uncovered, "evidence": n.evidence, "claim": n.claim,
            })).collect::<Vec<_>>(),
            "withdrawals": self.withdrawals.iter().map(|w| serde_json::json!({
                "line": w.declared_at.line, "col": w.declared_at.col,
                "phrase": w.phrase, "tokens": w.tokens,
                "sites": w.sites.iter().map(|(sp, t)| serde_json::json!({
                    "line": sp.line, "col": sp.col, "end": sp.end, "text": t,
                })).collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "claims": self.claims.iter().map(|c| serde_json::json!({
                "line": c.span.line,
                "col": c.span.col,
                "end": c.span.end,
                "verdict": c.verdict.label(),
                "source": c.source,
                "context": c.context,
                "escalations": c.escalations,
            })).collect::<Vec<_>>(),
        }))
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

pub fn run(plan: &Path, escalations: Option<&Path>) -> Result<Ledger, String> {
    let text = std::fs::read_to_string(plan).map_err(|e| {
        format!(
            "cannot read plan {}: {e}\n\
             The plan lives under .omc/, which is not committed, so this command is a local \
             gate rather than a CI step. Pass --plan <path> to point at it.",
            plan.display()
        )
    })?;
    let known = match escalations {
        Some(p) => {
            let t = std::fs::read_to_string(p)
                .map_err(|e| format!("cannot read escalations {}: {e}", p.display()))?;
            Some(escalation_ids(&t))
        }
        None => None,
    };
    let claims = parse_claims(&text);
    Ok(Ledger {
        plan: plan.display().to_string(),
        narrow: check_narrow_evidence(&claims),
        withdrawals: find_withdrawals(&text),
        claims,
        known_escalations: known,
    })
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

pub fn parse_claims(text: &str) -> Vec<Claim> {
    let mut claims = Vec::new();
    // Header cells of the table currently being read, if any.
    let mut header: Option<Vec<String>> = None;
    let mut prev_row: Option<Vec<String>> = None;

    for (i, raw) in text.lines().enumerate() {
        let lineno = i + 1;
        let line = raw.trim_end();

        // --- inline tags, anywhere ---
        for (verdict, source, col, end) in scan_tags(line) {
            claims.push(Claim {
                span: Span {
                    line: lineno,
                    col,
                    end,
                },
                line: lineno,
                verdict,
                source,
                context: line.trim().to_string(),
                escalations: escalation_ids_in(line),
            });
        }

        // --- table state machine, for untagged Evidence cells ---
        if !line.trim_start().starts_with('|') {
            header = None;
            prev_row = None;
            continue;
        }
        let cells = split_row(line);
        if is_separator_row(&cells) {
            header = prev_row.take();
            continue;
        }
        if let Some(h) = &header {
            if let Some(idx) = evidence_column(h)
                && let Some(cell) = cells.get(idx)
                && scan_tags(cell.trim()).next().is_none()
            {
                let c = cell.trim();
                let col = line.find(cell.as_str()).unwrap_or(0);
                claims.push(Claim {
                    span: Span {
                        line: lineno,
                        col,
                        end: col + cell.len(),
                    },
                    line: lineno,
                    verdict: Verdict::UntaggedTreatedAsU,
                    source: String::new(),
                    context: format!(
                        "[{}] evidence cell: {}",
                        cells.first().map(|s| s.trim()).unwrap_or(""),
                        if c.is_empty() { "(empty)" } else { c }
                    ),
                    escalations: escalation_ids_in(line),
                });
            }
        } else {
            prev_row = Some(cells);
        }
    }
    claims
}

/// Yield every `[V…]` / `[U…]` tag on a line as
/// `(verdict, source, col_start, col_end)` with byte columns into `line`.
fn scan_tags(line: &str) -> impl Iterator<Item = (Verdict, String, usize, usize)> + '_ {
    let b = line.as_bytes();
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i < b.len() {
            if b[i] != b'[' {
                i += 1;
                continue;
            }
            let verdict = match b.get(i + 1) {
                Some(b'V') => Verdict::Verified,
                Some(b'U') => Verdict::Unverified,
                _ => {
                    i += 1;
                    continue;
                }
            };
            // The character after V/U must end the tag or open its body, so
            // `[Various]` and `[Unix]` are not mistaken for evidence tags.
            match b.get(i + 2) {
                Some(b']') | Some(b':') | Some(b' ') => {}
                _ => {
                    i += 1;
                    continue;
                }
            }
            let Some(end) = line[i..].find(']').map(|e| i + e) else {
                i += 1;
                continue;
            };
            let source = line[i + 2..end]
                .trim_start_matches([':', ' '])
                .trim()
                .to_string();
            let (start, stop) = (i, end + 1);
            i = end + 1;
            return Some((verdict, source, start, stop));
        }
        None
    })
}

// ---------------------------------------------------------------------------
// Check A — evidence narrower than the claim it is attached to
// ---------------------------------------------------------------------------
//
// The concrete defect: a sweep reported clean having run `grep "1% deep hash"`
// while claiming to have cleared "the 1%/90-day scrub policy". The pattern was
// narrower than the assertion attached to it, and the report read as green.
//
// Only *self-reported* evidence is checkable this way. `[V: crates.io]` names an
// external source; nothing in the text says how much of the claim it covers, and
// pretending otherwise would flag all 129 of them. So the check runs only when
// the evidence text carries a command-ish marker — a `grep`, a quoted string, or
// a backticked pattern — and then asks one question: does every distinguishing
// token in the claim appear in the evidence?
//
// Distinguishing tokens are numbers and quoted/backticked literals ONLY. Ordinary
// words are excluded deliberately: an English word appearing in a claim but not
// in a grep pattern is the normal case, not a defect, and a check that fires on
// the normal case gets switched off.

#[derive(Debug, Clone)]
pub struct NarrowEvidence {
    pub span: Span,
    pub claim: String,
    pub evidence: String,
    /// Tokens the claim asserts that its own evidence does not mention.
    pub uncovered: Vec<String>,
}

/// Verbs that make an evidence string a *self-report of work done* rather than a
/// pointer at an external source.
///
/// Matched as whole identifiers. Substring matching was tried first and was
/// wrong in both directions on the real plan: `"rg "` matched inside
/// `man7.o`**`rg f`**`anotify`, and a bare `"` matched a citation that quotes a
/// paper title. A source pointer is not checkable for coverage from its text, so
/// misclassifying one produces exactly the noise that gets a check switched off.
const SELF_REPORT_VERBS: &[&str] = &[
    "grep",
    "rg",
    "ripgrep",
    "ran",
    "swept",
    "sweep",
    "scanned",
    "searched",
    "checked",
    "verified",
    "confirmed",
];

fn is_self_reported_evidence(evidence: &str) -> bool {
    let lower = evidence.to_ascii_lowercase();
    SELF_REPORT_VERBS
        .iter()
        .any(|v| crate::check_deps::contains_ident(&lower, v))
}

/// Numbers and quoted/backticked literals — the tokens that make a claim
/// specific. Digit runs are compared as whole tokens, so `1` never matches
/// inside `100`.
pub fn distinguishing_tokens(s: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let b = s.as_bytes();

    // Pass 1 — every digit run, including digits inside a quoted literal. The
    // two passes are independent on purpose: consuming `"1% deep hash"` as one
    // literal token would hide the `1` it contains, and the whole point of the
    // check is comparing the numbers a claim asserts against the numbers its
    // evidence actually mentions.
    let mut i = 0usize;
    while i < b.len() {
        if b[i].is_ascii_digit() {
            let start = i;
            while i < b.len() && b[i].is_ascii_digit() {
                i += 1;
            }
            let t = s[start..i].to_string();
            if !out.contains(&t) {
                out.push(t);
            }
            continue;
        }
        i += 1;
    }

    // Pass 2 — quoted and backticked literals.
    for quote in ['"', '`'] {
        let mut rest = s;
        while let Some(open) = rest.find(quote) {
            let after = &rest[open + quote.len_utf8()..];
            let Some(close) = after.find(quote) else {
                break;
            };
            let lit = after[..close].trim().to_ascii_lowercase();
            if !lit.is_empty() && !out.contains(&lit) {
                out.push(lit);
            }
            rest = &after[close + quote.len_utf8()..];
        }
    }
    out
}

/// Remove every `[V…]`/`[U…]` tag from a line, together with the backticks that
/// wrap it. Backticks elsewhere are kept: a backticked identifier in the claim
/// is one of the distinguishing tokens the coverage check looks for.
pub fn strip_tags(line: &str) -> String {
    let b = line.as_bytes();
    let mut out = String::with_capacity(line.len());
    let mut last = 0usize;
    for (_, _, col, end) in scan_tags(line) {
        let open = if col > 0 && b[col - 1] == b'`' {
            col - 1
        } else {
            col
        };
        let close = if end < b.len() && b[end] == b'`' {
            end + 1
        } else {
            end
        };
        if open >= last {
            out.push_str(&line[last..open]);
            out.push(' ');
        }
        last = close;
    }
    out.push_str(&line[last..]);
    out
}

/// The span of text one tag is answerable for: its own table cell if the line is
/// a markdown row, otherwise the whole line.
fn claim_scope<'a>(context: &'a str, source: &str) -> &'a str {
    if !context.trim_start().starts_with('|') {
        return context;
    }
    let Some(cell) = context
        .split('|')
        .find(|cell| !source.is_empty() && cell.contains(source))
    else {
        return context;
    };
    // Both table shapes occur in the plan: some rows put the tag in the same
    // cell as the assertion it backs, others give Evidence its own column. When
    // the tag's cell is nothing but the tag, the claim it answers for is
    // elsewhere in the row, so widen back to the row.
    let bare = strip_tags(cell);
    if bare.trim().chars().filter(|c| !c.is_whitespace()).count() < 12 {
        context
    } else {
        cell
    }
}

fn check_narrow_evidence(claims: &[Claim]) -> Vec<NarrowEvidence> {
    let mut out = Vec::new();
    for c in claims {
        if c.verdict != Verdict::Verified || !is_self_reported_evidence(&c.source) {
            continue;
        }
        // The claim is the *cell* the tag sits in, not the whole markdown row.
        // An evidence table row carries several independent claims; charging one
        // tag with the version numbers from its neighbours' cells produces an
        // uncovered-token list nobody can act on.
        let scope = claim_scope(&c.context, &c.source);
        // Compare the claim minus its own tag against the evidence. The whole
        // tag goes, not just the source text: leaving the `[V: ]` husk behind
        // makes its own delimiters look like quoted literals in the claim.
        let claim_text = strip_tags(scope);
        let ev = distinguishing_tokens(&c.source);
        let uncovered: Vec<String> = distinguishing_tokens(&claim_text)
            .into_iter()
            .filter(|t| !ev.contains(t))
            .collect();
        if !uncovered.is_empty() {
            out.push(NarrowEvidence {
                span: c.span,
                claim: truncate(scope.trim(), 140),
                evidence: c.source.clone(),
                uncovered,
            });
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Check B — a withdrawn mechanism still asserted somewhere else
// ---------------------------------------------------------------------------
//
// The recurring defect across all five planning iterations: a fix lands in one
// place while its consequences stay stale elsewhere. Twice that produced tests
// that would have PASSED while asserting behaviour the plan had already ruled
// out. Four review passes missed it; a human-scale grep caught it each time.
//
// This makes that grep systematic and leaves the judgement where it was. It is
// deliberately an ENUMERATION, not a classification, for two reasons found by
// running it on the real plan:
//
//   * the declaration and its discussion are 16 lines apart, so "inside the
//     withdrawal sentence" would be an arbitrary proximity window; and
//   * the withdrawn phrase is paraphrased at every site — "1% per 90-day sweep",
//     "1%-per-90-day deep sample", "1% deep sample per 90-day sweep" — so exact
//     phrase matching finds only the declaration itself.
//
// So it matches on numeric-token CO-OCCURRENCE and prints every hit with a span.
// There is no pass/fail: the correct output on a healthy plan is a short list a
// human confirms are all withdrawal contexts.

#[derive(Debug, Clone)]
pub struct Withdrawal {
    pub declared_at: Span,
    pub phrase: String,
    pub tokens: Vec<String>,
    /// Other lines where all the phrase's tokens co-occur.
    pub sites: Vec<(Span, String)>,
}

/// Markers that declare a mechanism dead. These are the forms the plan actually
/// uses; an unlisted form is invisible to this check.
const WITHDRAWAL_MARKERS: &[&str] = &[
    "is withdrawn",
    "are withdrawn",
    "was withdrawn",
    "were withdrawn",
    "that asserted",
    "is obsolete",
    "the obsolete shape",
];

fn stem(w: &str) -> String {
    let w: String = w
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .collect::<String>()
        .to_ascii_lowercase();
    w.chars().take(5).collect()
}

const STOPWORDS: &[&str] = &[
    "the", "a", "an", "of", "per", "and", "or", "that", "this", "it", "its", "to", "in", "on",
    "for", "with", "by", "at", "is", "was", "be", "as",
];

/// The phrase a withdrawal marker refers to: the quoted or backticked literal
/// nearest before it, else the words following `that asserted`.
fn withdrawn_phrase(line: &str, marker: &str, marker_at: usize) -> Option<String> {
    if marker == "that asserted" {
        let rest = &line[marker_at + marker.len()..];
        let cut = rest
            .find(['—', '.', ';', ',', '*'])
            .unwrap_or(rest.len().min(80));
        let p = rest[..cut].trim();
        return (!p.is_empty()).then(|| p.to_string());
    }
    let before = &line[..marker_at];
    for q in ['"', '`', '\u{201d}'] {
        if let Some(close) = before.rfind(q) {
            let opener = if q == '\u{201d}' { '\u{201c}' } else { q };
            if let Some(open) = before[..close].rfind(opener) {
                let p = before[open + opener.len_utf8()..close].trim();
                if !p.is_empty() {
                    return Some(p.to_string());
                }
            }
        }
    }
    None
}

pub fn find_withdrawals(text: &str) -> Vec<Withdrawal> {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<Withdrawal> = Vec::new();

    for (i, line) in lines.iter().enumerate() {
        for marker in WITHDRAWAL_MARKERS {
            let Some(at) = line.find(marker) else {
                continue;
            };
            let Some(phrase) = withdrawn_phrase(line, marker, at) else {
                continue;
            };
            // "Both citations are withdrawn" withdraws an evidence tag, not a
            // mechanism. Tracking it would list every line citing that source.
            if phrase.starts_with("[V") || phrase.starts_with("[U") {
                continue;
            }

            // Numeric tokens are the match key. Where a phrase has fewer than
            // two of them, the longest content word is added, so a phrase like
            // "90 days" does not match every line mentioning 90.
            let mut tokens = distinguishing_tokens(&phrase)
                .into_iter()
                .filter(|t| t.chars().all(|c| c.is_ascii_digit()))
                .collect::<Vec<_>>();
            if tokens.len() < 2 {
                let mut words: Vec<&str> = phrase
                    .split_whitespace()
                    .filter(|w| {
                        let s = stem(w);
                        s.len() >= 4 && !STOPWORDS.contains(&w.to_ascii_lowercase().as_str())
                    })
                    .collect();
                words.sort_by_key(|w| std::cmp::Reverse(w.len()));
                tokens.extend(words.into_iter().take(2).map(stem));
            }
            if tokens.is_empty() {
                continue;
            }
            if out.iter().any(|w| w.tokens == tokens) {
                continue; // same mechanism declared dead twice
            }

            let declared_at = Span {
                line: i + 1,
                col: at,
                end: at + marker.len(),
            };
            let sites = lines
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .filter(|(_, l)| {
                    let stems: Vec<String> = l.split_whitespace().map(stem).collect();
                    let nums = distinguishing_tokens(l);
                    tokens.iter().all(|t| {
                        if t.chars().all(|c| c.is_ascii_digit()) {
                            nums.contains(t)
                        } else {
                            stems.iter().any(|s| s == t)
                        }
                    })
                })
                .map(|(j, l)| {
                    (
                        Span {
                            line: j + 1,
                            col: 0,
                            end: l.len(),
                        },
                        truncate(l.trim(), 120),
                    )
                })
                .collect::<Vec<_>>();

            out.push(Withdrawal {
                declared_at,
                phrase,
                tokens,
                sites,
            });
        }
    }
    out
}

fn split_row(line: &str) -> Vec<String> {
    line.trim()
        .trim_start_matches('|')
        .trim_end_matches('|')
        .split('|')
        .map(|c| c.trim().to_string())
        .collect()
}

fn is_separator_row(cells: &[String]) -> bool {
    !cells.is_empty()
        && cells
            .iter()
            .all(|c| !c.is_empty() && c.chars().all(|ch| ch == '-' || ch == ':'))
}

fn evidence_column(header: &[String]) -> Option<usize> {
    header.iter().position(|h| {
        let h = h.trim().trim_matches('*').to_ascii_lowercase();
        h == "evidence" || h == "evidence / source" || h == "source"
    })
}

/// Escalation identifiers: `OQ-A`…`OQ-J` (with optional `-spike`), `D-8`, `R-21`, `PM-2`.
pub fn escalation_ids_in(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let b = line.as_bytes();
    for (i, _) in line.char_indices() {
        let rest = &line[i..];
        for prefix in ["OQ-", "PM-", "D-", "R-"] {
            if !rest.starts_with(prefix) {
                continue;
            }
            // Not preceded by an identifier character (avoids `AD-`, `xR-`).
            if i > 0 && (b[i - 1].is_ascii_alphanumeric() || b[i - 1] == b'_') {
                continue;
            }
            let tail = &rest[prefix.len()..];
            let n: String = tail
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric())
                .collect();
            if n.is_empty() {
                continue;
            }
            let id = format!("{prefix}{n}");
            if !out.contains(&id) {
                out.push(id);
            }
        }
    }
    out
}

fn escalation_ids(text: &str) -> BTreeSet<String> {
    text.lines().flat_map(escalation_ids_in).collect()
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let head: String = s.chars().take(n).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_grammar() {
        let tags: Vec<_> =
            scan_tags("GA `[V: AWS blog]`; resumable `[V]`; method `[U at method level]`")
                .collect();
        assert_eq!(tags.len(), 3);
        assert_eq!(tags[0].0, Verdict::Verified);
        assert_eq!(tags[0].1, "AWS blog");
        assert_eq!(tags[1].0, Verdict::Verified);
        assert_eq!(tags[2].0, Verdict::Unverified);
        assert_eq!(tags[2].1, "at method level");
    }

    #[test]
    fn em_dash_note_form() {
        let tags: Vec<_> = scan_tags("`[U — architectural inference]`").collect();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0].0, Verdict::Unverified);
        assert!(tags[0].1.contains("architectural inference"));
    }

    #[test]
    fn ordinary_brackets_are_not_tags() {
        assert_eq!(scan_tags("[Various options]").count(), 0);
        assert_eq!(scan_tags("[Unix sockets]").count(), 0);
        assert_eq!(scan_tags("see [4.1](#4-1)").count(), 0);
    }

    #[test]
    fn untagged_evidence_cell_is_u() {
        let md = "\
| Need | Choice | Evidence |
|---|---|---|
| S3 | `aws-sdk-s3` | GA `[V: AWS blog]` |
| Azure | `azure_storage_blob` |  |
";
        let claims = parse_claims(md);
        let untagged: Vec<_> = claims
            .iter()
            .filter(|c| c.verdict == Verdict::UntaggedTreatedAsU)
            .collect();
        assert_eq!(untagged.len(), 1, "claims: {claims:?}");
        assert!(untagged[0].context.contains("Azure"));
    }

    // --- check A: evidence narrower than the claim ---

    /// The named defect, as a fixture: a sweep reported clean having run
    /// `grep "1% deep hash"` while claiming to have cleared the 1%/90-day
    /// policy. The pattern never mentions 90.
    #[test]
    fn narrow_evidence_catches_the_sweep_that_grepped_less_than_it_claimed() {
        let md = "The 1%/90-day scrub policy is cleared \
                  `[V: ran grep \"1% deep hash\", swept clean]`.";
        let hits = check_narrow_evidence(&parse_claims(md));
        assert_eq!(hits.len(), 1, "{hits:#?}");
        assert_eq!(hits[0].uncovered, vec!["90".to_string()]);
    }

    #[test]
    fn evidence_covering_the_whole_claim_does_not_fire() {
        let md = "The 1%/90-day scrub policy is cleared \
                  `[V: ran grep \"1%\" and grep \"90-day\", swept clean]`.";
        assert!(check_narrow_evidence(&parse_claims(md)).is_empty());
    }

    /// External source pointers are excluded by construction. They dominate the
    /// plan (129 of 154 tags), and nothing in their text says how much of a
    /// claim they cover, so checking them would flag all of them.
    #[test]
    fn external_source_pointers_are_not_coverage_checked() {
        let md = "GA since 1.141.0 with 90-day support `[V: crates.io]`.";
        assert!(check_narrow_evidence(&parse_claims(md)).is_empty());
    }

    /// `man7.org fanotify(7)` contains the substring "rg " inside "o**rg f**".
    /// Substring matching classified it as a self-report; identifier matching
    /// does not.
    #[test]
    fn a_source_pointer_containing_a_verb_substring_is_still_a_pointer() {
        assert!(!is_self_reported_evidence("man7.org fanotify(7)"));
        assert!(!is_self_reported_evidence(
            "emschwartz.me \"Write Transactions are a Footgun\""
        ));
        assert!(is_self_reported_evidence("ran grep \"1% deep hash\""));
        assert!(is_self_reported_evidence("trust audit confirmed"));
    }

    #[test]
    fn a_claim_is_scoped_to_its_own_table_cell() {
        let md = "\
| Need | Choice | Notes |
|---|---|---|
| PDF | `pdfium-render` 0.9.3 permissive stack `[V: trust audit confirmed]` | unrelated 256 and 21 |
";
        let hits = check_narrow_evidence(&parse_claims(md));
        assert_eq!(hits.len(), 1, "{hits:#?}");
        // The neighbouring cell's numbers are not this tag's problem.
        assert!(!hits[0].uncovered.contains(&"256".to_string()));
        assert!(hits[0].uncovered.contains(&"9".to_string()));
    }

    // --- check B: a withdrawn mechanism still asserted elsewhere ---

    /// Enumeration, not classification: the declaration site plus every other
    /// line where the phrase's distinguishing tokens co-occur, paraphrases
    /// included. Exact-phrase matching would find only the declaration.
    #[test]
    fn withdrawn_mechanism_lists_paraphrased_sites() {
        let md = "\
Iteration 2's \"1% per 90-day sweep\" is withdrawn: it implied too much.
Filler line with no numbers at all.
A 1%-per-90-day deep sample implies a ~25-year full-verification interval.
The max_full_verification_age is 90 days for sole copies, 365 for replicated.
";
        let w = find_withdrawals(md);
        assert_eq!(w.len(), 1, "{w:#?}");
        assert_eq!(w[0].tokens, vec!["1".to_string(), "90".to_string()]);
        let lines: Vec<usize> = w[0].sites.iter().map(|(s, _)| s.line).collect();
        assert_eq!(lines, vec![3], "paraphrase found, 90-only line excluded");
    }

    /// The `that asserted` form, from the E2E row that asserted the installer
    /// force-enables lingering — behaviour OQ-F forbids.
    #[test]
    fn withdrawn_mechanism_reads_the_that_asserted_form() {
        let md = "\
This test replaces an iteration-2 row that asserted the installer enables lingering — OQ-F forbids it.
Shepherd checks lingering and warns; it never enables it.
";
        let w = find_withdrawals(md);
        assert_eq!(w.len(), 1, "{w:#?}");
        assert!(w[0].phrase.contains("installer"));
    }

    /// "Both citations are withdrawn" withdraws an evidence tag, not a
    /// mechanism. Tracking it would list every line citing that source.
    #[test]
    fn a_withdrawn_citation_is_not_a_withdrawn_mechanism() {
        let md = "`[V: dependency trust audit, repo + source read]`. Both citations are withdrawn.";
        assert!(find_withdrawals(md).is_empty());
    }

    // --- spans ---

    #[test]
    fn spans_point_at_the_tag_not_the_line() {
        let md = "resumable transfers `[V: docs.rs]` per AC-2";
        let c = &parse_claims(md)[0];
        assert_eq!(c.span.line, 1);
        assert_eq!(&md[c.span.col..c.span.end], "[V: docs.rs]");
        assert_eq!(c.span.to_string(), "1:21-33");
    }

    #[test]
    fn escalation_ids_parse() {
        let ids = escalation_ids_in("narrowed by OQ-J, D-8 and R-21; see OQ-C-spike");
        assert!(ids.contains(&"OQ-J".to_string()));
        assert!(ids.contains(&"D-8".to_string()));
        assert!(ids.contains(&"R-21".to_string()));
    }
}
