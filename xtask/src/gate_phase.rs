//! `cargo xtask gate --phase <id>` — a phase gate that **asserts** rather than
//! reports.
//!
//! §9: "A phase is done when its gate command produces the stated evidence, not
//! when its code is written." Until now this command exited 3 for every phase,
//! which was the correct Phase-0a scaffold — a gate returning 0 without
//! evidence is exactly the §9 rule 6 defect — but it left the gates
//! hand-checked.
//!
//! # The four rules this is built to, each from a defect that actually happened
//!
//! **1. Assert counts, never exit codes.** `cargo test --exact does_not_exist`
//! exits **0** and prints `0 passed; 0 filtered out`. A filter that matches
//! nothing is not an error to cargo. That is how a CI step can run zero tests
//! and report green, which happened on this project today. Every check here
//! parses `N passed` and **requires N >= 1**.
//!
//! **2. Absent evidence FAILS; it never skips.** A MinIO leg that cannot run
//! because the endpoint is unset is not a pass — skipping is how "not run"
//! becomes "passed". [`Evidence::requires_env`] turns a missing variable into a
//! failure that names the variable.
//!
//! **3. Every AC the phase owns must be accounted for.** The owned set is read
//! from `ac-map.toml`, not from a list in this file, so an AC cannot be
//! silently dropped from the gate by being forgotten here. An AC with no
//! evidence entry is reported `NO EVIDENCE` and fails the gate.
//!
//! **4. Report which AC failed and why.** A bare exit code sends someone back
//! to re-run everything by hand, which is where a claim gets substituted for a
//! measurement.
//!
//! # What a failing gate means
//!
//! It means the phase is not done. §9 rule 1 is explicit that no gate may be
//! satisfied by a skipped or ignored test, and a gate that cannot pass because
//! machinery is missing is a **useful result** — it says what is missing and
//! stops, rather than letting a hand-assembled claim stand in.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use serde::Deserialize;

// ---------------------------------------------------------------------------
// Evidence declarations, read from ac-map.toml
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct AcMap {
    #[serde(default)]
    ac: Vec<Entry>,
    #[serde(default)]
    guard: Vec<Entry>,
}

#[derive(Debug, Deserialize)]
struct Entry {
    id: String,
    owning_gate: String,
    #[serde(default)]
    evidence: Vec<Evidence>,
    /// A remaining gap that keeps this AC red **regardless of whether its
    /// evidence passed**.
    ///
    /// This is what lets the gate say "here is what IS proven, and here is what
    /// is still missing" instead of choosing between a bare NO EVIDENCE and a
    /// green it has not earned. AC-2 is the case that forced it: the durable
    /// store and cross-process resume are genuinely proven, on a 51-byte body,
    /// while §9 demands a 50 GB artifact. Citing the passing tests without this
    /// field would turn the gate green without the thing it exists to check
    /// having happened.
    ///
    /// It is deliberately a hard override rather than a warning. An AC that can
    /// be argued green while a stated gap stands is an AC that will be.
    #[serde(default)]
    evidence_missing: Option<String>,
}

/// One runnable proof.
#[derive(Debug, Deserialize, Clone)]
pub struct Evidence {
    /// Cargo package to test.
    pub package: String,
    /// Exact test name, passed with `--exact`.
    pub test: String,
    /// `true` for `#[ignore]`d tests, which need `--ignored`.
    #[serde(default)]
    pub ignored: bool,
    /// Environment variable this evidence needs. Absent variable => the check
    /// FAILS naming it, rather than skipping.
    #[serde(default)]
    pub requires_env: Option<String>,
    /// What this proves, for the report.
    #[serde(default)]
    pub proves: String,
}

// ---------------------------------------------------------------------------
// Results
// ---------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum CheckOutcome {
    /// The test ran and passed. Carries the count, because the count is the
    /// assertion.
    Passed {
        count: u32,
    },
    Failed {
        detail: String,
    },
    /// The filter matched nothing. Distinguished from `Failed` because it means
    /// something different: the evidence does not exist under that name.
    MatchedNothing,
    /// A required variable was not set. NOT a skip.
    MissingEnv {
        var: String,
    },
}

impl CheckOutcome {
    fn ok(&self) -> bool {
        matches!(self, CheckOutcome::Passed { .. })
    }
    fn label(&self) -> String {
        match self {
            CheckOutcome::Passed { count } => format!("PASS ({count} test(s) ran)"),
            CheckOutcome::Failed { detail } => format!("FAIL — {detail}"),
            CheckOutcome::MatchedNothing => {
                "FAIL — the filter matched NO tests. `cargo test` exits 0 on this, which is \
                 why the count is asserted rather than the exit code"
                    .into()
            }
            CheckOutcome::MissingEnv { var } => format!(
                "FAIL — ${var} is not set, so this evidence could not be produced. Absent \
                 evidence fails; skipping is how \"not run\" becomes \"passed\""
            ),
        }
    }
}

#[derive(Debug)]
pub struct AcResult {
    pub id: String,
    pub outcomes: Vec<(Evidence, CheckOutcome)>,
    pub missing_reason: Option<String>,
}

impl AcResult {
    fn ok(&self) -> bool {
        // A stated gap overrides passing evidence. See `Entry::evidence_missing`.
        self.missing_reason.is_none()
            && !self.outcomes.is_empty()
            && self.outcomes.iter().all(|(_, o)| o.ok())
    }

    /// Evidence that ran and passed, while the AC as a whole stays red on a
    /// stated gap. Reported so the partial result is visible rather than buried.
    fn is_partial(&self) -> bool {
        self.missing_reason.is_some()
            && !self.outcomes.is_empty()
            && self.outcomes.iter().all(|(_, o)| o.ok())
    }
}

pub struct PhaseReport {
    pub phase: String,
    pub results: Vec<AcResult>,
}

impl PhaseReport {
    pub fn failed(&self) -> bool {
        self.results.iter().any(|r| !r.ok())
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "cargo xtask gate --phase {} — §9 phase gate", self.phase);
        let _ = writeln!(s, "{}", "=".repeat(78));

        let mut total_tests = 0u32;
        for r in &self.results {
            let status = if r.ok() {
                "PASS"
            } else if r.is_partial() {
                "PARTIAL"
            } else {
                "FAIL"
            };
            let _ = writeln!(s, "[{status}] {}", r.id);
            if r.outcomes.is_empty() {
                let why = r.missing_reason.as_deref().unwrap_or(
                    "no evidence declared in ac-map.toml. An AC the phase OWNS with nothing \
                     to run cannot be asserted, so the gate fails rather than assuming it",
                );
                let _ = writeln!(s, "         NO EVIDENCE — {why}");
                continue;
            }
            for (e, o) in &r.outcomes {
                if let CheckOutcome::Passed { count } = o {
                    total_tests += count;
                }
                let _ = writeln!(s, "         {} :: {} — {}", e.package, e.test, o.label());
                if !e.proves.is_empty() {
                    let _ = writeln!(s, "             proves: {}", e.proves);
                }
            }
            if let Some(why) = &r.missing_reason {
                let _ = writeln!(s, "         STILL MISSING — {why}");
            }
        }

        let _ = writeln!(s, "{}", "=".repeat(78));
        let failed: Vec<&AcResult> = self.results.iter().filter(|r| !r.ok()).collect();
        let unbacked = failed.iter().filter(|r| r.outcomes.is_empty()).count();
        let partial = failed.iter().filter(|r| r.is_partial()).count();
        if failed.is_empty() {
            let _ = writeln!(
                s,
                "RESULT: PASS — {} acceptance criteria asserted by {} test(s) that actually ran",
                self.results.len(),
                total_tests
            );
        } else {
            let _ = writeln!(
                s,
                "RESULT: FAIL — {} of {} criteria unmet ({} with no evidence at all, {} \
                 partial: evidence passed but a stated gap remains): {}",
                failed.len(),
                self.results.len(),
                unbacked,
                partial,
                failed
                    .iter()
                    .map(|r| r.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
            let _ = writeln!(
                s,
                "\nA failing gate means the phase is NOT done. §9 rule 1: no gate may be \
                 satisfied by a skipped or ignored test. Reporting what is missing is the \
                 correct outcome — a hand-assembled claim is not."
            );
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Running
// ---------------------------------------------------------------------------

pub fn run(root: &Path, map_path: &Path, phase: &str) -> Result<PhaseReport, String> {
    let text = std::fs::read_to_string(map_path)
        .map_err(|e| format!("cannot read {}: {e}", map_path.display()))?;
    let map: AcMap =
        toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", map_path.display()))?;

    // The owned set comes from the map, never from a list in this file, so an
    // AC cannot be dropped from the gate by being forgotten here.
    let owned: Vec<&Entry> = map
        .ac
        .iter()
        .chain(map.guard.iter())
        .filter(|e| e.owning_gate == phase)
        .collect();

    if owned.is_empty() {
        return Err(format!(
            "no acceptance criteria are owned by phase `{phase}` in {}. Either the phase id \
             is wrong or the map is — refusing to report a vacuous pass over an empty set",
            map_path.display()
        ));
    }

    let mut results = Vec::new();
    // One test binary can back several ACs; run each distinct check once.
    let mut cache: BTreeMap<(String, String, bool), CheckOutcome> = BTreeMap::new();

    for entry in owned {
        let mut outcomes = Vec::new();
        for ev in &entry.evidence {
            let key = (ev.package.clone(), ev.test.clone(), ev.ignored);
            let outcome = match cache.get(&key) {
                Some(o) => clone_outcome(o),
                None => {
                    let o = run_evidence(root, ev);
                    cache.insert(key, clone_outcome(&o));
                    o
                }
            };
            outcomes.push((ev.clone(), outcome));
        }
        results.push(AcResult {
            id: entry.id.clone(),
            outcomes,
            missing_reason: entry.evidence_missing.clone(),
        });
    }

    Ok(PhaseReport {
        phase: phase.to_string(),
        results,
    })
}

fn clone_outcome(o: &CheckOutcome) -> CheckOutcome {
    match o {
        CheckOutcome::Passed { count } => CheckOutcome::Passed { count: *count },
        CheckOutcome::Failed { detail } => CheckOutcome::Failed {
            detail: detail.clone(),
        },
        CheckOutcome::MatchedNothing => CheckOutcome::MatchedNothing,
        CheckOutcome::MissingEnv { var } => CheckOutcome::MissingEnv { var: var.clone() },
    }
}

fn run_evidence(root: &Path, ev: &Evidence) -> CheckOutcome {
    if let Some(var) = &ev.requires_env
        && std::env::var(var).is_err()
    {
        return CheckOutcome::MissingEnv { var: var.clone() };
    }

    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".to_string());
    let mut cmd = Command::new(cargo);
    cmd.current_dir(root)
        .args(["test", "-p", &ev.package, "--", &ev.test, "--exact"]);
    if ev.ignored {
        cmd.arg("--ignored");
    }

    let out = match cmd.output() {
        Ok(o) => o,
        Err(e) => {
            return CheckOutcome::Failed {
                detail: format!("cannot run cargo test: {e}"),
            };
        }
    };
    let stdout = String::from_utf8_lossy(&out.stdout);
    let (passed, failed) = parse_counts(&stdout);

    // The count IS the assertion. A filter matching nothing exits 0.
    if passed == 0 && failed == 0 {
        return CheckOutcome::MatchedNothing;
    }
    if failed > 0 || !out.status.success() {
        return CheckOutcome::Failed {
            detail: format!("{failed} test(s) failed, {passed} passed"),
        };
    }
    CheckOutcome::Passed { count: passed }
}

/// Sum `test result:` lines. Summing rather than taking the first, because a
/// package with several test binaries prints one line each and only one of them
/// holds the test being filtered for.
pub fn parse_counts(stdout: &str) -> (u32, u32) {
    let (mut passed, mut failed) = (0u32, 0u32);
    for line in stdout.lines() {
        let Some(rest) = line.trim().strip_prefix("test result:") else {
            continue;
        };
        let toks: Vec<&str> = rest.split_whitespace().collect();
        for w in toks.windows(2) {
            let n: u32 = match w[0].trim_end_matches(';').parse() {
                Ok(n) => n,
                Err(_) => continue,
            };
            match w[1].trim_end_matches(';') {
                "passed" => passed += n,
                "failed" => failed += n,
                _ => {}
            }
        }
    }
    (passed, failed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The defect this whole module is shaped around.** A filter that matches
    /// nothing prints zeroes and exits 0; only the count distinguishes it from
    /// a real pass.
    #[test]
    fn a_filter_that_matched_nothing_is_all_zeroes() {
        let out = "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 41 filtered out; finished in 0.00s\n";
        assert_eq!(parse_counts(out), (0, 0));
    }

    #[test]
    fn counts_are_summed_across_test_binaries() {
        let out = "\
test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.01s
test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 12 filtered out; finished in 0.00s
test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
";
        assert_eq!(parse_counts(out), (4, 0));
    }

    #[test]
    fn failures_are_counted() {
        let out =
            "test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; 0 filtered out;\n";
        assert_eq!(parse_counts(out), (2, 1));
    }

    #[test]
    fn a_missing_env_var_reads_as_a_failure_not_a_skip() {
        let o = CheckOutcome::MissingEnv {
            var: "SHEPHERD_MINIO_ENDPOINT".into(),
        };
        assert!(!o.ok());
        assert!(o.label().contains("SHEPHERD_MINIO_ENDPOINT"));
        assert!(o.label().contains("not run"));
    }

    /// An AC with no evidence declared must FAIL, not pass vacuously.
    #[test]
    fn an_ac_with_no_evidence_does_not_pass() {
        let r = AcResult {
            id: "AC-99".into(),
            outcomes: vec![],
            missing_reason: None,
        };
        assert!(!r.ok());
    }

    #[test]
    fn an_ac_passes_only_when_every_piece_of_evidence_passed() {
        let ev = Evidence {
            package: "p".into(),
            test: "t".into(),
            ignored: false,
            requires_env: None,
            proves: String::new(),
        };
        let all_good = AcResult {
            id: "AC-1".into(),
            outcomes: vec![
                (ev.clone(), CheckOutcome::Passed { count: 1 }),
                (ev.clone(), CheckOutcome::Passed { count: 2 }),
            ],
            missing_reason: None,
        };
        assert!(all_good.ok());

        let one_bad = AcResult {
            id: "AC-1".into(),
            outcomes: vec![
                (ev.clone(), CheckOutcome::Passed { count: 1 }),
                (ev, CheckOutcome::MatchedNothing),
            ],
            missing_reason: None,
        };
        assert!(!one_bad.ok());
    }
}
