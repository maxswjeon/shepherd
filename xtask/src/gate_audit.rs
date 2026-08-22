//! `cargo xtask gate --audit` — §9 rule 6.
//!
//! The invariant, quoted from §9 rule 6: *an AC may be owned no **earlier**
//! than the phase that creates the machinery it exercises.* Machinery is
//! cumulative — Phase 3 may own an AC whose engine Phase 2 built, which is
//! exactly how AC-3, AC-4 and AC-10 split. What is forbidden is gating AC-13 at
//! Phase 1 while the rules crate first appears in Phase 2.
//!
//! The mapping it consumes is `xtask/ac-map.toml`, the machine-readable form of
//! the Appendix's `Exercises` column. §9 is explicit that "without that column
//! the tool is just a name attached to a self-report".
//!
//! **Known limit, restated from §9 rule 6:** this catches *owned-too-early*. It
//! does **not** catch *vacuous pass* — an AC owned late enough to compile but
//! too early to be non-trivial. That remains a human review property.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct AcMap {
    /// Phases in execution order. An AC's owning phase must not precede any
    /// phase that creates machinery it exercises.
    phase_order: Vec<String>,
    expected_ac_count: u32,
    /// machinery key -> phase that creates it, from §6's creates-lists.
    machinery: BTreeMap<String, String>,
    #[serde(default)]
    ac: Vec<Entry>,
    /// Release-blocking guards that are not numbered spec ACs (PM-1/2/3).
    /// Audited by the same invariant but excluded from the AC-count check.
    #[serde(default)]
    guard: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    id: String,
    owning_gate: String,
    exercises: Vec<String>,
    #[serde(default)]
    note: String,
}

pub struct Report {
    violations: Vec<String>,
    ac_count: usize,
    guard_count: usize,
    machinery_count: usize,
    /// (id, owning phase, latest machinery phase) for each audited row.
    rows: Vec<(String, String, String)>,
}

impl Report {
    pub fn failed(&self) -> bool {
        !self.violations.is_empty()
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "cargo xtask gate --audit — §9 rule 6 AC-ownership audit");
        let _ = writeln!(s, "{}", "=".repeat(72));
        let _ = writeln!(
            s,
            "machinery entries: {}   acceptance criteria: {}   guards: {}",
            self.machinery_count, self.ac_count, self.guard_count
        );
        let _ = writeln!(
            s,
            "invariant: owning phase >= latest phase creating any exercised machinery"
        );
        let _ = writeln!(s, "{}", "-".repeat(72));
        for v in &self.violations {
            let _ = writeln!(s, "  ✗ {v}");
        }
        if self.violations.is_empty() {
            let _ = writeln!(
                s,
                "RESULT: PASS — {} rows audited, 0 owned-too-early violations",
                self.rows.len()
            );
            let _ = writeln!(
                s,
                "NOTE: this audit catches owned-too-early only. It does NOT catch a vacuous \
                 pass (an AC owned late enough to compile but too early to be non-trivial). \
                 §9 rule 6 states that limit; it stays a human review property."
            );
        } else {
            let _ = writeln!(
                s,
                "RESULT: FAIL — {} violation(s) over {} rows",
                self.violations.len(),
                self.rows.len()
            );
        }
        s
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(&serde_json::json!({
            "command": "gate --audit",
            "pass": !self.failed(),
            "ac_count": self.ac_count,
            "guard_count": self.guard_count,
            "machinery_count": self.machinery_count,
            "violations": self.violations,
            "rows": self.rows.iter().map(|(id, own, mach)| serde_json::json!({
                "id": id, "owning_gate": own, "latest_machinery_phase": mach,
            })).collect::<Vec<_>>(),
        }))
        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
    }
}

pub fn run(map_path: &Path) -> Result<Report, String> {
    let text = std::fs::read_to_string(map_path)
        .map_err(|e| format!("cannot read {}: {e}", map_path.display()))?;
    let map: AcMap =
        toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", map_path.display()))?;

    let phase_index = |p: &str| map.phase_order.iter().position(|x| x == p);

    let mut violations = Vec::new();
    let mut rows = Vec::new();

    // Machinery phases must be known phases.
    for (key, phase) in &map.machinery {
        if phase_index(phase).is_none() {
            violations.push(format!(
                "machinery `{key}` names phase `{phase}`, which is not in phase_order"
            ));
        }
    }

    for entry in map.ac.iter().chain(map.guard.iter()) {
        let Some(own_idx) = phase_index(&entry.owning_gate) else {
            violations.push(format!(
                "{}: owning_gate `{}` is not in phase_order",
                entry.id, entry.owning_gate
            ));
            continue;
        };
        if entry.exercises.is_empty() {
            violations.push(format!(
                "{}: `exercises` is empty. Without it the audit is a name attached to a \
                 self-report (§9 rule 6)",
                entry.id
            ));
            continue;
        }

        let mut latest: Option<(usize, &str, &str)> = None;
        for m in &entry.exercises {
            let Some(phase) = map.machinery.get(m) else {
                violations.push(format!(
                    "{}: exercises unknown machinery `{m}` — add it to [machinery] with the \
                     phase whose §6 creates-list produces it",
                    entry.id
                ));
                continue;
            };
            let Some(idx) = phase_index(phase) else {
                continue; // already reported above
            };
            if latest.is_none_or(|(cur, _, _)| idx > cur) {
                latest = Some((idx, m.as_str(), phase.as_str()));
            }
        }

        if let Some((idx, key, phase)) = latest {
            if own_idx < idx {
                violations.push(format!(
                    "{}: owned by phase {} but exercises `{key}`, which phase {phase} creates \
                     — owned too early (§9 rule 6){}",
                    entry.id,
                    entry.owning_gate,
                    if entry.note.is_empty() {
                        String::new()
                    } else {
                        format!(". note: {}", entry.note)
                    }
                ));
            }
            rows.push((
                entry.id.clone(),
                entry.owning_gate.clone(),
                phase.to_string(),
            ));
        }
    }

    // Completeness: exactly AC-1 .. AC-<expected_ac_count>, each once.
    let mut seen: BTreeMap<u32, usize> = BTreeMap::new();
    for entry in &map.ac {
        match entry
            .id
            .strip_prefix("AC-")
            .and_then(|n| n.parse::<u32>().ok())
        {
            Some(n) => *seen.entry(n).or_insert(0) += 1,
            None => violations.push(format!(
                "`{}` is in [[ac]] but is not of the form AC-<n>; guards belong in [[guard]]",
                entry.id
            )),
        }
    }
    for n in 1..=map.expected_ac_count {
        match seen.get(&n) {
            None => violations.push(format!("AC-{n} is missing from ac-map.toml")),
            Some(&c) if c > 1 => violations.push(format!(
                "AC-{n} appears {c} times — every AC names exactly one owning gate (Appendix)"
            )),
            _ => {}
        }
    }
    for n in seen.keys().filter(|&&n| n > map.expected_ac_count) {
        violations.push(format!(
            "AC-{n} exceeds expected_ac_count = {}",
            map.expected_ac_count
        ));
    }

    Ok(Report {
        violations,
        ac_count: map.ac.len(),
        guard_count: map.guard.len(),
        machinery_count: map.machinery.len(),
        rows,
    })
}
