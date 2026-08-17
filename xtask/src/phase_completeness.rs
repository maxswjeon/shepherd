//! `cargo xtask gate --audit` (second section) — the **phase-completeness**
//! check: does `ac-map.toml` actually ask for what §9's row for each phase
//! demands?
//!
//! # The defect this exists to make impossible
//!
//! `gate --phase 1` returned **PASS** while Phase 1 was not done. Nothing was
//! broken: AC-13 and AC-56 are the only two ACs carrying `owning_gate = "1"`,
//! both are backed by tests that run, so the gate reported what it was asked to
//! report. §9's Phase 1 row additionally demands the M1 legs, the identity
//! layer, `atime_mode` detection, the job-queue core, catalog write discipline
//! and daemon installation — **none of which was encoded as a phase-1-owned
//! row, so the gate could not ask for it.**
//!
//! `gate --audit`'s own closing NOTE predicted this: it catches *owned too
//! early* and states that a vacuous pass "stays a human review property". A
//! phase whose gate demands a proper subset of its §9 row is precisely that
//! vacuous pass, and it is mechanically detectable — so it is checked here
//! rather than left to review.
//!
//! # What it does
//!
//! §9's gate table is the specification; `ac-map.toml` is the encoding. This
//! module parses the table **out of the plan** and reconciles the two:
//!
//! 1. **Every gate command §9 names must be runnable.** §9 names
//!    `xtask gate --phase 0ab`, which matched no id in the map — so Phase 0 had
//!    no gate at all and `--phase 0a` exited 2. A command that cannot be run is
//!    not a gate.
//! 2. **Every phase must be covered by exactly one §9 row**, checked against
//!    `phase_order`. This is the check on the *parser*: a renamed heading or a
//!    reformatted table would otherwise yield zero rows and a clean pass over
//!    nothing — this file's own version of the empty-filter defect.
//! 3. **AC ids reconcile in both directions.** An AC named in §9's row for a
//!    phase must be owned by that phase, and an AC owned by a phase must be
//!    named in its row. Where §9 deliberately names an AC it does *not* own —
//!    the leg pattern, "AC-3, AC-4 and AC-10 mock legs only" — the map must
//!    declare it and **quote the sentence from §9 that says so**, so the
//!    exception cannot be asserted, only cited.
//! 4. **Every clause of the row must be claimed.** The row is split into
//!    clauses and each must be covered by a `[[phase.requirement]]` whose
//!    `quote` appears **verbatim** in that clause. A requirement names either
//!    the ids that carry it (`covered_by`) or, honestly, that nothing does
//!    (`unencoded`).
//!
//! Rule 4 is the one that would have caught Phase 1, and `gate --phase P`
//! **fails on any uncovered or unencoded clause** in P's row. That is
//! deliberate: it is what stops this checker having the same vacuous mode as
//! the gap it audits. A lazy encoder — one requirement per clause, all
//! `unencoded` — does not buy a green gate; it produces a red one that lists
//! exactly what is unbacked.
//!
//! # What it still cannot catch, stated as plainly as §9 rule 6 states its own
//!
//! * **Weak evidence behind a claimed clause.** It verifies that a clause is
//!   claimed by an id that exists and is owned by that phase; it cannot judge
//!   whether that id's tests are strong enough to be worth the claim. A guard
//!   citing one trivial test satisfies this check.
//! * **A quote that does not capture its clause's meaning.** The quote is
//!   verified to be present, not to be the load-bearing part of the sentence.
//! * **A clause splitter that merges two requirements into one clause** hides
//!   under-coverage without ever reporting it. `--show-clauses` dumps the split
//!   with its covering ids for exactly this reason: the splitter is auditable
//!   rather than trusted.
//!
//! The first two stay human review properties. The difference from before is
//! their size: review now starts from a list of claims with quoted sources,
//! instead of from the question "what did §9 ask for that nobody encoded?"

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// The map side
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AcMap {
    phase_order: Vec<String>,
    /// §9 names compound gate commands (`--phase 0ab`) over phases the map
    /// keeps atomic (`0a`, `0b`), because the ownership invariant in
    /// `gate --audit` needs a total order and `0ab` has no place in one.
    /// The alias is the join, declared rather than guessed.
    #[serde(default)]
    alias: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    ac: Vec<Entry>,
    #[serde(default)]
    guard: Vec<Entry>,
    #[serde(default)]
    phase: Vec<PhaseSpec>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    id: String,
    owning_gate: String,
}

/// The encoding of one §9 row.
#[derive(Debug, Deserialize)]
struct PhaseSpec {
    /// The gate id as §9's command writes it — `0ab`, `1`, `release`.
    gate: String,
    #[serde(default)]
    requirement: Vec<Requirement>,
    /// ACs §9's row names without owning: the "mock legs only" pattern.
    #[serde(default)]
    leg: Vec<Leg>,
}

#[derive(Debug, Deserialize)]
struct Requirement {
    /// Verbatim substring of one clause of the row. Verbatim so that editing
    /// §9 breaks the check loudly instead of leaving a stale encoding that
    /// still reads as current.
    quote: String,
    /// AC/guard ids that carry this requirement. Each must exist and be owned
    /// by one of the row's phases.
    #[serde(default)]
    covered_by: Vec<String>,
    /// Stated when nothing carries it. Keeps the clause visible and the gate
    /// red rather than letting silence read as coverage.
    #[serde(default)]
    unencoded: Option<String>,
    /// This clause demands no evidence: it records scope, reasoning, or what
    /// the phase explicitly does **not** have to do ("Windows startup task
    /// defers to Phase 3").
    ///
    /// A necessary category — without it a gate could never go green, because
    /// §9's rows carry parentheticals — and the most abusable one in this file:
    /// marking a real demand `rationale` waves it away. Three things bound
    /// that. It cannot be applied without quoting the sentence; every
    /// rationale clause is printed by `--show-clauses` and counted separately
    /// in the summary rather than folded into "carried"; and the reason must be
    /// written out, so waving a demand away leaves a signed sentence saying why
    /// it was not one.
    #[serde(default)]
    rationale: Option<String>,
}

#[derive(Debug, Deserialize)]
struct Leg {
    /// The AC named but not owned.
    ac: String,
    /// Verbatim quote from the row that says so. Without it the exception is a
    /// bare assertion, which is the thing §9 rule 6 refuses.
    quote: String,
    #[serde(default)]
    owned_by: String,
}

// ---------------------------------------------------------------------------
// The plan side
// ---------------------------------------------------------------------------

/// One row of §9's gate table.
#[derive(Debug, Clone)]
pub struct PlanRow {
    /// First cell, markdown stripped — `0a/0b`, `1`, `9`.
    pub label: String,
    /// The gate command verbatim.
    pub command: String,
    /// The id the command names: `0ab`, `1`, `release`.
    pub gate_id: String,
    /// Third cell, continuation lines joined.
    pub evidence: String,
    /// [`split_clauses`] of `evidence`.
    pub clauses: Vec<String>,
}

/// Pull §9's gate table out of the plan.
///
/// Returns an error rather than an empty vector when the table cannot be
/// found: "no rows" and "no table" are the same fact here, and a checker that
/// silently reconciles nothing is the defect it exists to catch.
pub fn parse_gate_table(plan: &str) -> Result<Vec<PlanRow>, String> {
    let mut in_section = false;
    let mut raw: Vec<String> = Vec::new();
    let mut current: Option<String> = None;

    for line in plan.lines() {
        if line.starts_with("## ") {
            if in_section {
                break;
            }
            in_section = line.starts_with("## 9.");
            continue;
        }
        if !in_section {
            continue;
        }
        let trimmed = line.trim_end();
        if trimmed.starts_with('|') {
            if let Some(row) = current.take() {
                raw.push(row);
            }
            // The header and the `|---|` separator are not rows.
            let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
            if compact.starts_with("|---") || trimmed.starts_with("| Phase |") {
                continue;
            }
            current = Some(trimmed.to_string());
        } else if trimmed.trim().is_empty() {
            if let Some(row) = current.take() {
                raw.push(row);
            }
        } else if let Some(row) = current.as_mut() {
            // A wrapped cell: markdown joins it with a space.
            row.push(' ');
            row.push_str(trimmed.trim());
        }
    }
    if let Some(row) = current.take() {
        raw.push(row);
    }

    if raw.is_empty() {
        return Err(
            "§9's gate table produced NO rows. Either the `## 9.` heading moved, the \
                    table was reformatted, or this parser broke — in every case reconciling \
                    zero rows would be a pass over nothing"
                .into(),
        );
    }

    let mut rows = Vec::new();
    for row in raw {
        let cells: Vec<&str> = row.trim().trim_matches('|').split('|').collect();
        if cells.len() != 3 {
            return Err(format!(
                "a §9 table row split into {} cells, not 3 — the table shape changed and this \
                 parser must be updated rather than left reporting on a shape that no longer \
                 exists. Row: {}",
                cells.len(),
                truncate(row.trim(), 120)
            ));
        }
        let label = strip_markdown(cells[0]);
        let command = strip_markdown(cells[1]);
        let gate_id = gate_id_of(&command).ok_or_else(|| {
            format!("§9 row `{label}` names no runnable gate command (cell: `{command}`)")
        })?;
        let evidence = cells[2].trim().to_string();
        let clauses = split_clauses(&evidence);
        rows.push(PlanRow {
            label,
            command,
            gate_id,
            evidence,
            clauses,
        });
    }
    Ok(rows)
}

/// `xtask gate --phase 0ab` -> `0ab`; `xtask gate --release` -> `release`.
fn gate_id_of(command: &str) -> Option<String> {
    let toks: Vec<&str> = command.split_whitespace().collect();
    if let Some(i) = toks.iter().position(|t| *t == "--phase") {
        return toks.get(i + 1).map(|t| t.trim().to_string());
    }
    // A flag-form gate: §9's Phase 9 row is `xtask gate --release`.
    toks.iter()
        .skip_while(|t| **t != "gate")
        .find(|t| t.starts_with("--"))
        .map(|t| t.trim_start_matches("--").to_string())
}

fn strip_markdown(cell: &str) -> String {
    let mut s = cell.trim().to_string();
    for pat in ["**", "*", "`"] {
        s = s.replace(pat, "");
    }
    s.trim().to_string()
}

/// Split a row's evidence cell into the clauses that must each be claimed.
///
/// Sentence boundaries plus **top-level** semicolons: a semicolon inside
/// parentheses or backticks belongs to its sentence ("systemd user unit;
/// lingering *checked and warned*") while one between them separates two
/// independent demands ("...on the 1M on-disk corpus; < 50 ms p95 over a
/// 10M-row injected catalog").
///
/// Kept deliberately simple, and dumped by `--show-clauses`, because the
/// splitter is the one part of this checker whose failure is silent: two
/// requirements merged into one clause are covered by a quote for either.
pub fn split_clauses(text: &str) -> Vec<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut depth = 0i32;
    let mut in_code = false;
    let mut out = Vec::new();
    let mut start = 0usize;

    for i in 0..chars.len() {
        let c = chars[i];
        match c {
            '`' => in_code = !in_code,
            '(' | '[' if !in_code => depth += 1,
            ')' | ']' if !in_code => depth -= 1,
            _ => {}
        }
        if in_code || depth > 0 {
            continue;
        }
        // Markdown closes *after* the full stop — "…rejected iteration 1.*
        // Spike sources are preserved…" — so the space that ends the sentence
        // is one emphasis run away from the period. Skipping that run is what
        // separates §9's commentary from the demand it is glued to.
        let next_ws = chars[i + 1..]
            .iter()
            .find(|n| !matches!(n, '*' | '`' | '_'))
            .is_some_and(|n| n.is_whitespace());
        let boundary = match c {
            ';' => next_ws,
            // No digit guard: `0.90` and `§4.10.3a` are already excluded by
            // `next_ws`, since a decimal point is never followed by a space.
            // Guarding on the preceding digit as well looks harmless and is
            // not — it swallowed "…that rejected iteration 1.* Spike sources
            // are preserved as non-production fixtures", merging §9's
            // commentary with the demand that follows it, where one quote
            // would have claimed both.
            '.' => next_ws && starts_a_sentence(&chars[i + 1..]),
            _ => false,
        };
        if boundary {
            push_clause(&mut out, &chars[start..=i]);
            start = i + 1;
        }
    }
    if start < chars.len() {
        push_clause(&mut out, &chars[start..]);
    }
    out
}

/// Is what follows a new sentence, rather than the tail of an abbreviation?
///
/// Markdown emphasis is skipped, so `. **AC-13**` counts. A **code span opens a
/// sentence** even though identifiers are lowercase: `` . `atime_mode`
/// detection correct on all three platforms `` is a §9 Phase 1 demand of its
/// own, and skipping the backtick to find a lowercase letter merged it into the
/// `fs_id` sentence before it — where a single quote would have claimed both.
/// That is the silent under-coverage this splitter is most prone to, so it is
/// fixed here and asserted below.
fn starts_a_sentence(rest: &[char]) -> bool {
    for c in rest {
        // `(` too: §9's parenthetical asides open sentences — "…AC-47** green.
        // *(AC-4 is deliberately absent from this list…" is a separate
        // statement from the list of ACs before it, and merging the two put a
        // deliberate exclusion inside the clause that claims the inclusions.
        if c.is_whitespace() || *c == '*' || *c == '_' || *c == '(' {
            continue;
        }
        if *c == '`' {
            return true;
        }
        return c.is_uppercase() || c.is_ascii_digit() || *c == '§' || *c == '✅' || *c == '⚠';
    }
    false
}

fn push_clause(out: &mut Vec<String>, chars: &[char]) {
    let s: String = chars.iter().collect();
    let mut s = s.trim();
    // An emphasis run that CLOSED on the previous sentence leaves its marker at
    // the head of this one ("…iteration 1.* Spike sources are…"). Strip the
    // orphan, not the "**" that opens a bolded clause.
    while let Some(rest) = s.strip_prefix("* ") {
        s = rest.trim_start();
    }
    let s = s.to_string();
    // A fragment this short carries no requirement; it is punctuation debris.
    if s.chars().filter(|c| c.is_alphanumeric()).count() >= 3 {
        out.push(s);
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let head: String = s.chars().take(n).collect();
    format!("{head}…")
}

// ---------------------------------------------------------------------------
// Reconciliation
// ---------------------------------------------------------------------------

/// The shortest quote that can claim a clause. A three-character quote would
/// technically "appear verbatim" while claiming nothing.
const MIN_QUOTE_CHARS: usize = 16;

/// One clause and what claims it.
#[derive(Debug, Clone)]
pub struct ClauseCoverage {
    pub clause: String,
    /// Requirement ids (`covered_by` entries) claiming this clause.
    pub covered_by: Vec<String>,
    /// Stated gaps recorded against this clause.
    pub unencoded: Vec<String>,
    /// Reasons this clause demands no evidence.
    pub rationale: Vec<String>,
}

impl ClauseCoverage {
    /// A clause is settled when something carries it, or when it demands
    /// nothing. A clause claimed only by an `unencoded` reason is *accounted
    /// for* but not carried, and fails the phase gate — a stated gap is
    /// honest, not satisfied.
    pub fn carried(&self) -> bool {
        !self.covered_by.is_empty() || !self.rationale.is_empty()
    }
    pub fn claimed(&self) -> bool {
        self.carried() || !self.unencoded.is_empty()
    }
    pub fn is_rationale(&self) -> bool {
        self.covered_by.is_empty() && !self.rationale.is_empty()
    }
}

#[derive(Debug)]
pub struct PhaseCoverage {
    pub gate_id: String,
    pub label: String,
    pub command: String,
    /// Phases from the map that this §9 row gates.
    pub phases: Vec<String>,
    pub clauses: Vec<ClauseCoverage>,
    /// Ids owned by `phases`, for the report.
    pub owned: Vec<String>,
}

impl PhaseCoverage {
    pub fn unclaimed(&self) -> Vec<&ClauseCoverage> {
        self.clauses.iter().filter(|c| !c.claimed()).collect()
    }
    pub fn uncarried(&self) -> Vec<&ClauseCoverage> {
        self.clauses.iter().filter(|c| !c.carried()).collect()
    }
}

pub struct Report {
    pub violations: Vec<String>,
    pub coverage: Vec<PhaseCoverage>,
    pub row_count: usize,
    pub phase_count: usize,
}

impl Report {
    pub fn failed(&self) -> bool {
        !self.violations.is_empty()
    }

    /// Coverage for the §9 row that gates `phase`, if any.
    pub fn for_phase(&self, phase: &str) -> Option<&PhaseCoverage> {
        self.coverage
            .iter()
            .find(|c| c.phases.iter().any(|p| p == phase))
    }

    pub fn render(&self, show_clauses: bool) -> String {
        let mut s = String::new();
        let _ = writeln!(
            s,
            "cargo xtask gate --audit — §9 phase-completeness reconciliation"
        );
        let _ = writeln!(s, "{}", "=".repeat(72));
        let _ = writeln!(
            s,
            "§9 gate rows parsed: {}   phases in phase_order: {}",
            self.row_count, self.phase_count
        );
        let _ = writeln!(
            s,
            "invariant: every clause of a phase's §9 row is claimed by a row in ac-map.toml"
        );
        let _ = writeln!(s, "{}", "-".repeat(72));

        for cov in &self.coverage {
            let rationale = cov.clauses.iter().filter(|c| c.is_rationale()).count();
            let carried = cov.clauses.iter().filter(|c| c.carried()).count() - rationale;
            let stated = cov
                .clauses
                .iter()
                .filter(|c| !c.carried() && c.claimed())
                .count();
            let open = cov.clauses.len() - carried - stated - rationale;
            let _ = writeln!(
                s,
                "  {:<8} `{}`\n      {}/{} clauses carried, {} stated-gap, {} rationale-only, \
                 {} UNENCODED   [{} AC/guard owned]",
                cov.label,
                cov.command,
                carried,
                cov.clauses.len(),
                stated,
                rationale,
                open,
                cov.owned.len()
            );
            if show_clauses {
                for c in &cov.clauses {
                    let who = if !c.covered_by.is_empty() {
                        c.covered_by.join(", ")
                    } else if c.is_rationale() {
                        "RATIONALE ".to_string()
                    } else if !c.unencoded.is_empty() {
                        "STATED GAP".to_string()
                    } else {
                        "UNENCODED ".to_string()
                    };
                    let _ = writeln!(s, "        [{who}] {}", truncate(&c.clause, 150));
                }
            }
        }

        let _ = writeln!(s, "{}", "-".repeat(72));
        for v in &self.violations {
            let _ = writeln!(s, "  ✗ {v}");
        }
        if self.violations.is_empty() {
            let _ = writeln!(
                s,
                "RESULT: PASS — {} §9 rows reconciled against ac-map.toml, 0 structural violations",
                self.row_count
            );
        } else {
            let _ = writeln!(
                s,
                "RESULT: FAIL — {} structural violation(s) over {} §9 rows",
                self.violations.len(),
                self.row_count
            );
        }
        let _ = writeln!(
            s,
            "NOTE: an UNENCODED clause is not a violation HERE — a phase whose gate has not been \
             written yet is not a defect — but `gate --phase <id>` FAILS on every unencoded or \
             stated-gap clause in its own row, which is where under-specification is caught. \
             What this check still cannot catch: whether the evidence behind a claimed clause is \
             strong enough to be worth the claim, and whether a quote captures its clause's \
             meaning. Both stay human review properties; `--show-clauses` prints the split so the \
             splitter itself is auditable."
        );
        s
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "command": "gate --audit (phase completeness)",
            "pass": !self.failed(),
            "rows": self.row_count,
            "violations": self.violations,
            "coverage": self.coverage.iter().map(|c| serde_json::json!({
                "gate": c.gate_id,
                "command": c.command,
                "phases": c.phases,
                "clauses": c.clauses.len(),
                "carried": c.clauses.iter().filter(|x| x.carried()).count(),
                "stated_gap": c.clauses.iter().filter(|x| !x.carried() && x.claimed()).count(),
                "unencoded": c.clauses.iter().filter(|x| !x.claimed()).count(),
                "owned": c.owned,
            })).collect::<Vec<_>>(),
        })
    }
}

pub fn run(map_path: &Path, plan_path: &Path) -> Result<Report, String> {
    let map_text = std::fs::read_to_string(map_path)
        .map_err(|e| format!("cannot read {}: {e}", map_path.display()))?;
    let map: AcMap = toml::from_str(&map_text)
        .map_err(|e| format!("cannot parse {}: {e}", map_path.display()))?;
    // Absent evidence fails; it never skips. A missing plan makes this check
    // unable to run, which is not the same as it having passed.
    let plan_text = std::fs::read_to_string(plan_path).map_err(|e| {
        format!(
            "cannot read the plan at {}: {e}. §9's table IS the specification this reconciles \
             against; without it there is nothing to check and a pass would be over nothing",
            plan_path.display()
        )
    })?;

    let rows = parse_gate_table(&plan_text)?;
    Ok(reconcile(&map, &rows))
}

fn reconcile(map: &AcMap, rows: &[PlanRow]) -> Report {
    let mut violations = Vec::new();

    // owning phase -> ids, from the map.
    let mut owned_by_phase: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for e in map.ac.iter().chain(map.guard.iter()) {
        owned_by_phase
            .entry(e.owning_gate.as_str())
            .or_default()
            .push(e.id.as_str());
    }
    let known_ids: BTreeSet<&str> = map
        .ac
        .iter()
        .chain(map.guard.iter())
        .map(|e| e.id.as_str())
        .collect();
    let id_owner: BTreeMap<&str, &str> = map
        .ac
        .iter()
        .chain(map.guard.iter())
        .map(|e| (e.id.as_str(), e.owning_gate.as_str()))
        .collect();

    // --- 1. every gate command §9 names must resolve and be runnable --------
    let mut covered_phases: BTreeMap<String, String> = BTreeMap::new();
    let mut coverage = Vec::new();

    for row in rows {
        let phases: Vec<String> = match map.alias.get(&row.gate_id) {
            Some(list) => list.clone(),
            None => vec![row.gate_id.clone()],
        };
        let mut resolved = Vec::new();
        for p in &phases {
            if !map.phase_order.iter().any(|x| x == p) {
                violations.push(format!(
                    "§9 row `{}` names `{}`, which resolves to phase `{p}` — not in \
                     phase_order. Either §9's command is wrong or the map is; a gate command \
                     that cannot be run is not a gate",
                    row.label, row.command
                ));
                continue;
            }
            if let Some(prev) = covered_phases.insert(p.clone(), row.label.clone()) {
                violations.push(format!(
                    "phase `{p}` is gated by two §9 rows (`{prev}` and `{}`) — exactly one gate \
                     must own a phase or its evidence is ambiguous",
                    row.label
                ));
            }
            let owned = owned_by_phase.get(p.as_str()).map(Vec::len).unwrap_or(0);
            if owned == 0 {
                violations.push(format!(
                    "§9 row `{}` names `{}`, but NO acceptance criterion or guard in \
                     ac-map.toml carries `owning_gate = \"{p}\"`. The gate would refuse to run \
                     rather than report a vacuous pass over an empty set — which is correct, and \
                     means this phase has no gate",
                    row.label, row.command
                ));
            }
            resolved.push(p.clone());
        }

        let spec = map.phase.iter().find(|p| p.gate == row.gate_id);
        let owned: Vec<String> = resolved
            .iter()
            .flat_map(|p| {
                owned_by_phase
                    .get(p.as_str())
                    .into_iter()
                    .flatten()
                    .map(|s| s.to_string())
            })
            .collect();

        // --- 2. AC ids reconcile in both directions ------------------------
        let named: BTreeSet<String> = ac_ids_in(&row.evidence);
        let legs: BTreeMap<&str, &Leg> = spec
            .map(|s| s.leg.iter().map(|l| (l.ac.as_str(), l)).collect())
            .unwrap_or_default();

        for ac in &named {
            let owner = id_owner.get(ac.as_str()).copied();
            if owner.is_some_and(|o| resolved.iter().any(|p| p == o)) {
                continue;
            }
            match legs.get(ac.as_str()) {
                Some(leg) => {
                    if !row.evidence.contains(&leg.quote) {
                        violations.push(format!(
                            "§9 row `{}`: the leg declaration for {ac} quotes text that is NOT \
                             in the row — the encoding is stale, or the exception was asserted \
                             rather than cited. Quote: \"{}\"",
                            row.label,
                            truncate(&leg.quote, 90)
                        ));
                    }
                    if !leg.owned_by.is_empty() && owner.is_some_and(|o| o != leg.owned_by) {
                        violations.push(format!(
                            "§9 row `{}`: {ac}'s leg says it is owned by phase `{}`, but the map \
                             owns it at `{}`",
                            row.label,
                            leg.owned_by,
                            owner.unwrap_or("<nothing>")
                        ));
                    }
                }
                None => violations.push(format!(
                    "§9 row `{}` names {ac}, which the map owns at phase `{}` — declare it as a \
                     [[phase.leg]] with the sentence from §9 that says so, or fix the ownership. \
                     An AC named by a gate it does not belong to is how a leg becomes a claim",
                    row.label,
                    owner.unwrap_or("<nothing: it is in no phase at all>")
                )),
            }
        }
        for id in &owned {
            if !id.starts_with("AC-") {
                continue; // guards are not named in §9 by id
            }
            if !named.contains(id) {
                violations.push(format!(
                    "{id} is owned by phase `{}` in ac-map.toml, but §9's row `{}` never names \
                     it. A gate asserting an AC its own §9 row does not ask for is unreviewable",
                    id_owner.get(id.as_str()).copied().unwrap_or("?"),
                    row.label
                ));
            }
        }

        // --- 3. clause coverage --------------------------------------------
        let mut clauses: Vec<ClauseCoverage> = row
            .clauses
            .iter()
            .map(|c| ClauseCoverage {
                clause: c.clone(),
                covered_by: Vec::new(),
                unencoded: Vec::new(),
                rationale: Vec::new(),
            })
            .collect();

        if let Some(spec) = spec {
            for req in &spec.requirement {
                let quote_len = req.quote.chars().count();
                let hits: Vec<usize> = clauses
                    .iter()
                    .enumerate()
                    .filter(|(_, c)| c.clause.contains(&req.quote))
                    .map(|(i, _)| i)
                    .collect();
                if hits.is_empty() {
                    violations.push(format!(
                        "§9 row `{}`: requirement quote is not in any clause of the row — §9 was \
                         edited and this encoding is stale, or the quote spans a clause boundary. \
                         Quote: \"{}\"",
                        row.label,
                        truncate(&req.quote, 90)
                    ));
                    continue;
                }
                if quote_len < MIN_QUOTE_CHARS
                    && hits
                        .iter()
                        .any(|i| clauses[*i].clause.chars().count() > MIN_QUOTE_CHARS)
                {
                    violations.push(format!(
                        "§9 row `{}`: requirement quote is {quote_len} chars, under the \
                         {MIN_QUOTE_CHARS}-char floor. A quote that short claims a clause \
                         without naming what it claims. Quote: \"{}\"",
                        row.label, req.quote
                    ));
                }
                let says_nothing = req.covered_by.is_empty()
                    && req.unencoded.as_deref().unwrap_or("").is_empty()
                    && req.rationale.as_deref().unwrap_or("").is_empty();
                if says_nothing {
                    violations.push(format!(
                        "§9 row `{}`: requirement \"{}\" names none of `covered_by`, `unencoded` \
                         or `rationale`. Silence is the one thing it may not say — that is the \
                         defect this whole check exists for",
                        row.label,
                        truncate(&req.quote, 70)
                    ));
                }
                if req.rationale.is_some() && !req.covered_by.is_empty() {
                    violations.push(format!(
                        "§9 row `{}`: requirement \"{}\" is marked `rationale` AND cites \
                         evidence. A clause either demands something or it does not; claiming \
                         both lets a demand be carried by the half that asks for nothing",
                        row.label,
                        truncate(&req.quote, 70)
                    ));
                }
                for id in &req.covered_by {
                    if !known_ids.contains(id.as_str()) {
                        violations.push(format!(
                            "§9 row `{}`: requirement cites `{id}`, which is not an AC or guard \
                             in ac-map.toml",
                            row.label
                        ));
                        continue;
                    }
                    let owner = id_owner.get(id.as_str()).copied().unwrap_or("?");
                    if !resolved.iter().any(|p| p == owner) {
                        violations.push(format!(
                            "§9 row `{}`: requirement cites `{id}`, which is owned by phase \
                             `{owner}` — a clause of this row must be carried by something THIS \
                             gate runs",
                            row.label
                        ));
                    }
                }
                for i in hits {
                    clauses[i].covered_by.extend(req.covered_by.iter().cloned());
                    if let Some(u) = &req.unencoded {
                        clauses[i].unencoded.push(u.clone());
                    }
                    if let Some(r) = &req.rationale {
                        clauses[i].rationale.push(r.clone());
                    }
                }
            }
        }

        coverage.push(PhaseCoverage {
            gate_id: row.gate_id.clone(),
            label: row.label.clone(),
            command: row.command.clone(),
            phases: resolved,
            clauses,
            owned,
        });
    }

    // --- 4. the check on the parser ----------------------------------------
    //
    // Every phase the map knows must be gated by some §9 row. This is what
    // stops a reformatted table, a renamed heading or a broken splitter from
    // producing a clean pass over nothing: the same empty-filter defect this
    // gate was built to refuse, one level up.
    for p in &map.phase_order {
        if !covered_phases.contains_key(p.as_str()) {
            violations.push(format!(
                "phase `{p}` is in phase_order but NO §9 gate row resolves to it. Either §9 \
                 names no command for it, or the parser failed to see the row — a phase with no \
                 gate cannot be completed, and a checker that reconciled zero rows would pass \
                 over nothing"
            ));
        }
    }
    for spec in &map.phase {
        if !rows.iter().any(|r| r.gate_id == spec.gate) {
            violations.push(format!(
                "ac-map.toml declares requirements for gate `{}`, which §9 names nowhere",
                spec.gate
            ));
        }
    }

    Report {
        violations,
        coverage,
        row_count: rows.len(),
        phase_count: map.phase_order.len(),
    }
}

/// Every `AC-<n>` a row names, including possessives (`AC-54's`) and **ranges**
/// (`AC-20…AC-27`).
///
/// The range form is not a nicety: §9 writes Phase 5's nine tag ACs and Phase
/// 8's six UI ACs as ranges, so a reader that took only the endpoints would
/// report AC-21…AC-26 as "owned but never named" and the reconciliation would
/// drown in twelve false violations — which is how a check gets an exception
/// list bolted on and stops meaning anything.
fn ac_ids_in(text: &str) -> BTreeSet<String> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = BTreeSet::new();
    let mut spans: Vec<(usize, usize, u32)> = Vec::new(); // start, end, n

    let mut i = 0;
    while i + 3 < chars.len() {
        if chars[i] == 'A' && chars[i + 1] == 'C' && chars[i + 2] == '-' {
            let mut j = i + 3;
            let mut num = String::new();
            while j < chars.len() && chars[j].is_ascii_digit() {
                num.push(chars[j]);
                j += 1;
            }
            if let Ok(n) = num.parse::<u32>() {
                out.insert(format!("AC-{n}"));
                spans.push((i, j, n));
                i = j;
                continue;
            }
        }
        i += 1;
    }

    for pair in spans.windows(2) {
        let (_, end_a, a) = pair[0];
        let (start_b, _, b) = pair[1];
        let between: String = chars[end_a..start_b].iter().collect();
        let joiner = between.trim();
        let is_range = matches!(joiner, "…" | "..." | "–" | "—") && b > a;
        if is_range {
            for n in a..=b {
                out.insert(format!("AC-{n}"));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `ac-map.toml` is committed, so it can be compiled in.
    const MAP: &str = include_str!("../ac-map.toml");

    /// **The plan is NOT committed** — `.gitignore` excludes all of `/.omc/` —
    /// so it cannot be `include_str!`d: that would make every checkout without
    /// it fail to *compile*, on all three CI platforms, for a file-location
    /// policy. It is read at runtime instead, and its absence is handled
    /// explicitly by each test rather than silently.
    ///
    /// This is the same constraint that keeps `xtask claim-ledger` out of CI,
    /// documented in `ci.yml`: a step that cannot see the plan can only skip or
    /// fail always, and both are worse than not being a step.
    fn plan_text() -> Option<String> {
        std::fs::read_to_string(
            crate::evidence_artifacts::repo_root().join(".omc/plans/shepherd-consensus-plan.md"),
        )
        .ok()
    }

    /// The plan, or a skip that says so. Every use is inside a test that
    /// asserts something else in the `None` branch — a bare early return would
    /// be the silent-skip defect, one level up from the empty test filter this
    /// gate exists to refuse.
    macro_rules! plan_or_bail {
        () => {
            match plan_text() {
                Some(t) => t,
                None => {
                    // The one thing this branch must not be is a bare early
                    // return. It asserts the REASON the plan is absent — that
                    // the repository deliberately does not track it — so that
                    // deleting the plan cannot turn a red reconciliation green.
                    let ignores = std::fs::read_to_string(
                        crate::evidence_artifacts::repo_root().join(".gitignore"),
                    )
                    .expect(".gitignore is committed");
                    assert!(
                        ignores.lines().any(|l| l.trim() == "/.omc/"),
                        "the plan is missing from this checkout and .gitignore does NOT exclude \
                         /.omc/ — so it was deleted rather than never tracked, and this test \
                         would otherwise pass by losing its own subject"
                    );
                    eprintln!(
                        "SKIPPED the §9 reconciliation: the plan is not tracked by git \
                         (/.omc/ is gitignored) and is not in this checkout. Asserted that \
                         .gitignore still says so."
                    );
                    return;
                }
            }
        };
    }

    /// §9's rows, or a documented skip. Every plan-dependent test starts
    /// here, so none of them can silently reconcile nothing.
    macro_rules! rows_or_bail {
        () => {{
            let plan = plan_or_bail!();
            parse_gate_table(&plan).expect("§9's table must parse")
        }};
    }

    /// The parser runs against the real plan, not a fixture, because a fixture
    /// proves the parser handles the fixture. Ten rows: 0ab, 0cd, 1..9.
    #[test]
    fn the_real_section_9_table_parses_into_every_gate_row() {
        let rows = rows_or_bail!();
        assert_eq!(
            rows.len(),
            11,
            "§9 has eleven gate rows; got {}: {:?}",
            rows.len(),
            rows.iter().map(|r| &r.label).collect::<Vec<_>>()
        );
        let ids: Vec<&str> = rows.iter().map(|r| r.gate_id.as_str()).collect();
        assert_eq!(
            ids,
            [
                "0ab", "0cd", "1", "2", "3", "4", "5", "6", "7", "8", "release"
            ]
        );
    }

    /// §9 writes nine of Phase 5's ACs as `AC-20…AC-27`. Reading only the
    /// endpoints reports six ACs as owned-but-never-named — six false
    /// violations, which is how a real check acquires an exception list and
    /// stops being one.
    #[test]
    fn an_ac_range_expands_rather_than_reporting_its_endpoints() {
        let ids = ac_ids_in("**AC-19 (≥ 2 distinct persisted tags per file), AC-20…AC-27, AC-17**");
        for n in 20..=27 {
            assert!(
                ids.contains(&format!("AC-{n}")),
                "AC-{n} missing from {ids:?}"
            );
        }
        assert!(ids.contains("AC-19") && ids.contains("AC-17"));
    }

    /// And a comma-separated pair is NOT a range — expanding `AC-13, AC-56`
    /// into forty-four ACs would make the reconciliation pass by covering
    /// everything.
    #[test]
    fn a_comma_separated_pair_is_not_a_range() {
        let ids = ac_ids_in("**AC-13** and **AC-56** hold.");
        assert_eq!(ids.len(), 2, "got {ids:?}");
    }

    /// A header row or separator misread as a gate row would silently add a
    /// phase nobody gates.
    #[test]
    fn the_header_and_separator_are_not_rows() {
        let rows = rows_or_bail!();
        assert!(rows.iter().all(|r| r.label != "Phase"));
        assert!(rows.iter().all(|r| !r.label.contains("---")));
    }

    /// Wrapped cells: §9's 0a/0b row spans sixteen physical lines, and a
    /// parser that took only the first would reconcile a fraction of the row
    /// while reporting on all of it.
    #[test]
    fn a_wrapped_row_is_joined_rather_than_truncated() {
        let r = rows_or_bail!();
        let zero = r.iter().find(|r| r.gate_id == "0ab").unwrap();
        assert!(
            zero.evidence.contains("bench-contract.toml"),
            "first line only"
        );
        assert!(
            zero.evidence.contains("Spike sources are"),
            "the row's LAST line must be present, not just its first: {}",
            truncate(&zero.evidence, 200)
        );
    }

    /// §9's Phase 9 gate is `xtask gate --release`, not `--phase 9`. A parser
    /// that understood only `--phase` would leave phase 9 ungated and say
    /// nothing.
    #[test]
    fn the_flag_form_gate_command_is_recognised() {
        assert_eq!(
            gate_id_of("xtask gate --release").as_deref(),
            Some("release")
        );
        assert_eq!(gate_id_of("xtask gate --phase 0ab").as_deref(), Some("0ab"));
    }

    /// The Phase 1 row is the defect this module exists for: it must split
    /// into the distinct demands that were dropped, not into one blob.
    #[test]
    fn the_phase_1_row_splits_into_its_separate_demands() {
        let r = rows_or_bail!();
        let one = r.iter().find(|r| r.gate_id == "1").unwrap();
        let joined = one.clauses.join(" ¶ ");
        for demand in [
            "1M on-disk corpus",
            "50 ms p95",
            "fs_id",
            "atime_mode",
            "kill-and-resume",
            "single-writer actor",
            "LaunchAgent",
        ] {
            assert!(
                one.clauses.iter().any(|c| c.contains(demand)),
                "§9 demands `{demand}` and no clause carries it. Clauses: {joined}"
            );
        }
        // Each of those is a demand of its own; if the splitter merged them all
        // into one clause, one quote would claim the lot.
        assert!(
            one.clauses.len() >= 8,
            "the Phase 1 row carries at least eight separable demands, got {}: {joined}",
            one.clauses.len()
        );
    }

    /// The two M1 legs sit in ONE sentence separated by a semicolon, and they
    /// have genuinely different status — the perf leg is measured, the
    /// functional leg is not. A splitter that kept them together would let the
    /// measured one cover for the missing one.
    #[test]
    fn the_two_m1_legs_are_separate_clauses() {
        let r = rows_or_bail!();
        let one = r.iter().find(|r| r.gate_id == "1").unwrap();
        let functional = one
            .clauses
            .iter()
            .position(|c| c.contains("1M on-disk corpus"))
            .expect("functional leg");
        let perf = one
            .clauses
            .iter()
            .position(|c| c.contains("50 ms p95"))
            .expect("perf leg");
        assert_ne!(
            functional, perf,
            "both M1 legs landed in one clause, so one quote claims both: {}",
            one.clauses[functional]
        );
    }

    /// A semicolon *inside* parentheses is punctuation, not a boundary —
    /// "(systemd user unit; lingering checked and warned...)" is one demand.
    #[test]
    fn a_semicolon_inside_parentheses_does_not_split() {
        let out = split_clauses(
            "Daemon installs on Linux (systemd user unit; lingering); Windows defers",
        );
        assert_eq!(out.len(), 2, "got {out:?}");
        assert!(out[0].contains("lingering"));
    }

    /// A decimal point is not a sentence end — and the thing that decides
    /// that is the *following* space, not the preceding digit.
    #[test]
    fn a_decimal_is_not_a_sentence_boundary() {
        let out = split_clauses("The bar is 0.90 recall and it holds. Next demand here");
        assert_eq!(out.len(), 2, "got {out:?}");
        assert!(out[0].contains("0.90"), "the decimal was split: {out:?}");
    }

    /// …and a sentence that *ends* on a digit still ends. Guarding on the
    /// preceding digit as well as the following space is the plausible version
    /// of the rule above, and it merged §9's Phase-0 commentary into the demand
    /// that follows it — where one quote would have claimed both.
    #[test]
    fn a_sentence_ending_in_a_number_still_ends() {
        let out = split_clauses(
            "the class that rejected iteration 1.* Spike sources are **preserved**, not deleted",
        );
        assert_eq!(out.len(), 2, "got {out:?}");
        assert!(out[1].starts_with("Spike sources"), "got {out:?}");
    }

    #[test]
    fn possessive_ac_ids_are_found() {
        let ids = ac_ids_in("**AC-54's `CLI == registered_methods`** and AC-13, plus AC-9.");
        assert!(ids.contains("AC-54"), "got {ids:?}");
        assert!(ids.contains("AC-13"));
        assert!(ids.contains("AC-9"));
    }

    /// **The end-to-end assertion, against the real map and the real plan.**
    /// Everything above tests a part; this tests the verdict the command
    /// prints, and it is the row that fails if someone adds a §9 demand
    /// without encoding it.
    #[test]
    fn the_committed_map_reconciles_against_the_committed_plan() {
        let map: AcMap = toml::from_str(MAP).expect("ac-map.toml parses");
        let report = reconcile(&map, &rows_or_bail!());
        assert!(
            report.violations.is_empty(),
            "structural violations against the committed plan:\n  {}",
            report.violations.join("\n  ")
        );
    }

    /// **The Phase 0 half of the task, end to end against the committed
    /// files.** §9 names `xtask gate --phase 0ab`; the map keeps `0a` and `0b`
    /// separate. Both constituents must resolve to that one row, or
    /// `gate --phase 0a` has no specification to check itself against and the
    /// gate silently loses its coverage section for Phase 0.
    #[test]
    fn both_constituents_of_a_compound_gate_resolve_to_its_section_9_row() {
        let map: AcMap = toml::from_str(MAP).unwrap();
        let report = reconcile(&map, &rows_or_bail!());
        for phase in ["0a", "0b"] {
            let cov = report
                .for_phase(phase)
                .unwrap_or_else(|| panic!("no §9 row covers phase {phase}"));
            assert_eq!(cov.gate_id, "0ab");
            assert_eq!(cov.phases, ["0a", "0b"]);
        }
        // And the row is runnable: something is owned by each constituent, or
        // the gate would exit 2 rather than report.
        assert!(
            !report.for_phase("0a").unwrap().owned.is_empty(),
            "phase 0a owns nothing, so `gate --phase 0ab` cannot assert anything"
        );
    }

    /// §9's Phase 9 gate is `--release`. Phase 9 must still resolve, or four
    /// release-blocking ACs sit behind a command the tool does not answer to.
    #[test]
    fn the_release_gate_resolves_to_phase_nine() {
        let map: AcMap = toml::from_str(MAP).unwrap();
        let report = reconcile(&map, &rows_or_bail!());
        let cov = report.for_phase("9").expect("phase 9 must be gated");
        assert_eq!(cov.gate_id, "release");
        assert!(cov.owned.iter().any(|id| id == "AC-63"));
    }

    /// **The regression this whole module is for.** Every clause of §9's Phase
    /// 1 row must be claimed by something in the map. If a future edit adds a
    /// demand to that row and nobody encodes it, this fails — which is the
    /// property that was missing when `gate --phase 1` returned PASS over two
    /// of ten demands.
    #[test]
    fn every_clause_of_the_phase_1_row_is_claimed() {
        let map: AcMap = toml::from_str(MAP).unwrap();
        let report = reconcile(&map, &rows_or_bail!());
        let cov = report.for_phase("1").unwrap();
        let unclaimed: Vec<&str> = cov.unclaimed().iter().map(|c| c.clause.as_str()).collect();
        assert!(
            unclaimed.is_empty(),
            "§9 demands these of Phase 1 and ac-map.toml claims none of them:\n  - {}",
            unclaimed.join("\n  - ")
        );
        // The count guard: a row that parsed into one clause would satisfy the
        // assertion above with a single quote.
        assert!(
            cov.clauses.len() >= 10,
            "the Phase 1 row split into {} clauses; §9 makes at least ten separate demands \
             there, so a smaller number means the splitter merged them",
            cov.clauses.len()
        );
    }

    /// The defect, reproduced: a phase §9 names with nothing owning it must be
    /// a violation. Driven through `reconcile`, not asserted about a literal.
    #[test]
    fn a_phase_with_no_owned_criteria_is_a_violation() {
        let map: AcMap = toml::from_str(
            r#"
phase_order = ["1"]
[alias]
[[ac]]
id = "AC-1"
owning_gate = "1"
"#,
        )
        .unwrap();
        let rows = vec![PlanRow {
            label: "0a/0b".into(),
            command: "xtask gate --phase 0ab".into(),
            gate_id: "0ab".into(),
            evidence: "some evidence".into(),
            clauses: vec!["some evidence".into()],
        }];
        let report = reconcile(&map, &rows);
        assert!(
            report.violations.iter().any(|v| v.contains("0ab")),
            "an unresolvable gate id must be reported: {:?}",
            report.violations
        );
        assert!(
            report.violations.iter().any(|v| v.contains("phase_order")),
            "and phase 1 being ungated must be reported: {:?}",
            report.violations
        );
    }

    /// A stale quote — §9 edited, the encoding not — must fail loudly rather
    /// than keep claiming a clause that no longer says what it said.
    #[test]
    fn a_quote_that_no_longer_appears_in_the_row_is_a_violation() {
        let map: AcMap = toml::from_str(
            r#"
phase_order = ["1"]
[[ac]]
id = "AC-1"
owning_gate = "1"
[[phase]]
gate = "1"
[[phase.requirement]]
quote = "a demand that section 9 no longer makes"
covered_by = ["AC-1"]
"#,
        )
        .unwrap();
        let rows = vec![PlanRow {
            label: "1".into(),
            command: "xtask gate --phase 1".into(),
            gate_id: "1".into(),
            evidence: "AC-1 holds.".into(),
            clauses: vec!["AC-1 holds.".into()],
        }];
        let report = reconcile(&map, &rows);
        assert!(
            report.violations.iter().any(|v| v.contains("stale")),
            "got {:?}",
            report.violations
        );
    }

    /// An unencoded clause is NOT a structural violation — a future phase is
    /// not a defect — but it must be visible, because `gate --phase` fails on
    /// it. If this ever became a violation, phases 3-9 would block CI for
    /// being in the future.
    #[test]
    fn an_unencoded_clause_is_reported_but_is_not_a_structural_violation() {
        let map: AcMap = toml::from_str(
            r#"
phase_order = ["1"]
[[ac]]
id = "AC-1"
owning_gate = "1"
"#,
        )
        .unwrap();
        let rows = vec![PlanRow {
            label: "1".into(),
            command: "xtask gate --phase 1".into(),
            gate_id: "1".into(),
            evidence: "AC-1 holds. And a second demand nobody encoded".into(),
            clauses: split_clauses("AC-1 holds. And a second demand nobody encoded"),
        }];
        let report = reconcile(&map, &rows);
        assert!(report.violations.is_empty(), "{:?}", report.violations);
        let cov = report.for_phase("1").unwrap();
        assert_eq!(cov.unclaimed().len(), 2, "both clauses are unclaimed");
    }
}
