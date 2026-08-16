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

#[derive(Debug, Clone)]
pub struct Claim {
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
                "  [{}] line {}: {}{}",
                c.verdict.label(),
                c.line,
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
            "claims": self.claims.iter().map(|c| serde_json::json!({
                "line": c.line,
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
    Ok(Ledger {
        plan: plan.display().to_string(),
        claims: parse_claims(&text),
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
        for (verdict, source) in scan_tags(line) {
            claims.push(Claim {
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
                claims.push(Claim {
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

/// Yield every `[V…]` / `[U…]` tag on a line as `(verdict, source)`.
fn scan_tags(line: &str) -> impl Iterator<Item = (Verdict, String)> + '_ {
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
            i = end + 1;
            return Some((verdict, source));
        }
        None
    })
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

    #[test]
    fn escalation_ids_parse() {
        let ids = escalation_ids_in("narrowed by OQ-J, D-8 and R-21; see OQ-C-spike");
        assert!(ids.contains(&"OQ-J".to_string()));
        assert!(ids.contains(&"D-8".to_string()));
        assert!(ids.contains(&"R-21".to_string()));
    }
}
