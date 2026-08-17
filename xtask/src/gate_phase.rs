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
    /// §9's compound gate ids (`0ab`) over the map's atomic phases (`0a`,
    /// `0b`). See [`resolve_phase`].
    #[serde(default)]
    alias: BTreeMap<String, Vec<String>>,
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
    ///
    /// §9 rule 1 forbids a gate being *satisfied by* a skipped or ignored test.
    /// Naming one here is the opposite of skipping it: the gate runs it
    /// explicitly and asserts its count, which is the only way an expensive
    /// measurement can back a gate at all.
    #[serde(default)]
    pub ignored: bool,
    /// `true` for evidence that is only meaningful in `--release`.
    ///
    /// Added for the 10M metadata bar, whose test *panics* under
    /// `debug_assertions` rather than report a debug-build number as if it
    /// meant something. Without this the gate would run it in debug and record
    /// a FAIL that says nothing about the index.
    #[serde(default)]
    pub release: bool,
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
    /// The test harness itself could not run — a build failure, a lock on the
    /// target directory, a toolchain problem. **Not** a statement about the
    /// evidence.
    ///
    /// Distinguished because it fails for a different reason and wants a
    /// different response. A gate that reports "AC-1 failed" when the truth is
    /// "cargo could not build" sends someone to debug the wrong thing — and if
    /// it happens intermittently it teaches people to re-run until green, which
    /// corrodes the gate faster than a wrong answer would.
    ///
    /// It still fails the gate. "Could not determine" is not a pass here for
    /// the same reason it is not one in the acquisition floors.
    CouldNotRun {
        detail: String,
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
            CheckOutcome::CouldNotRun { detail } => format!(
                "FAIL — the test harness could not run ({detail}). This is NOT a verdict on \
                 the evidence: re-run once the build is clean. It still fails the gate, \
                 because \"could not determine\" is not a pass"
            ),
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
    /// Clauses of this phase's §9 row that **nothing in `ac-map.toml` claims**.
    ///
    /// The Phase 1 defect in one field: the gate reported PASS over the two ACs
    /// it had been given while §9's row asked for eight more things, and it had
    /// no way to know. Each entry here fails the gate on its own, separately
    /// from the AC tally, because "the criteria I was given all pass" and "the
    /// phase is done" are different claims and only the second one is what a
    /// gate is read as saying.
    pub uncovered: Vec<String>,
    /// Clauses claimed only by a stated gap — accounted for, not carried.
    pub stated_gaps: Vec<String>,
    /// Set when the requested phase is one constituent of a larger §9 gate, so
    /// a pass here cannot be read as closing that gate.
    pub scope_note: Option<String>,
    /// Why coverage could not be established, when it could not. Never a skip:
    /// this fails the gate.
    pub coverage_error: Option<String>,
    /// The daemon-reachability line for this phase, and whether it fails.
    ///
    /// A phase can land every library it owns, test them, and wire none of them
    /// to anything a user can invoke. Phase 2 did: eleven of twelve criteria
    /// PASS while `tier.run` answers `MethodNotImplemented`. Per-AC evidence
    /// cannot see that, because each AC is true.
    pub reachability: Option<(String, bool)>,
}

impl PhaseReport {
    pub fn failed(&self) -> bool {
        self.results.iter().any(|r| !r.ok())
            || !self.uncovered.is_empty()
            || !self.stated_gaps.is_empty()
            || self.coverage_error.is_some()
            || self
                .reachability
                .as_ref()
                .is_some_and(|(_, failed)| *failed)
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "cargo xtask gate --phase {} — §9 phase gate", self.phase);
        let _ = writeln!(s, "{}", "=".repeat(78));
        if let Some(note) = &self.scope_note {
            let _ = writeln!(s, "{note}\n");
        }

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

        // §9 coverage, printed as its own section: "every criterion I was given
        // passed" and "§9's row for this phase is satisfied" are different
        // claims, and collapsing them is the defect this section exists for.
        if let Some(err) = &self.coverage_error {
            let _ = writeln!(
                s,
                "§9 COVERAGE: COULD NOT BE ESTABLISHED — {err}\n  This fails the gate. A gate \
                 that cannot read the specification it gates against has not checked it."
            );
        } else if self.uncovered.is_empty() && self.stated_gaps.is_empty() {
            let _ = writeln!(
                s,
                "§9 COVERAGE: every clause of this phase's §9 row is claimed by a row in \
                 ac-map.toml."
            );
        } else {
            let _ = writeln!(
                s,
                "§9 COVERAGE: {} clause(s) of this phase's §9 row are NOT carried:",
                self.uncovered.len() + self.stated_gaps.len()
            );
            for c in &self.stated_gaps {
                let _ = writeln!(s, "  [STATED GAP] {c}");
            }
            for c in &self.uncovered {
                let _ = writeln!(s, "  [UNENCODED ] {c}");
            }
            let _ = writeln!(
                s,
                "  An UNENCODED clause is a §9 demand that ac-map.toml does not ask for, so no \
                 verdict above speaks to it. A STATED GAP is a demand encoded honestly as \
                 unmet. Both fail the gate: this is how a phase reports being under-specified \
                 instead of passing over the part of §9 nobody wrote down."
            );
        }
        if let Some((line, _)) = &self.reachability {
            let _ = writeln!(s, "{}", "-".repeat(78));
            let _ = writeln!(s, "{line}");
        }
        let _ = writeln!(s, "{}", "=".repeat(78));

        let failed: Vec<&AcResult> = self.results.iter().filter(|r| !r.ok()).collect();
        let unbacked = failed.iter().filter(|r| r.outcomes.is_empty()).count();
        let partial = failed.iter().filter(|r| r.is_partial()).count();
        if failed.is_empty() {
            let _ = writeln!(
                s,
                "RESULT: {} — {} acceptance criteria asserted by {} test(s) that actually ran",
                match (
                    self.failed(),
                    self.reachability.as_ref().is_some_and(|(_, f)| *f),
                ) {
                    (false, _) => "PASS".to_string(),
                    // Naming which of the two it is, because "every criterion
                    // passed" and "the phase is done" failing apart is the
                    // whole point of these sections existing.
                    (true, true) => format!(
                        "FAIL (every criterion green — the phase is NOT REACHABLE{})",
                        if self.uncovered.is_empty() && self.stated_gaps.is_empty() {
                            ""
                        } else {
                            ", and its §9 row is not covered"
                        }
                    ),
                    (true, false) => "FAIL (criteria green, §9 row NOT covered)".to_string(),
                },
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

/// Which map phases a requested gate id covers.
///
/// §9 names `xtask gate --phase 0ab`; the map keeps `0a` and `0b` separate
/// because `gate --audit`'s owned-no-earlier-than invariant needs a total order
/// and `0ab` has no position in one. The join is declared in the map's
/// `[alias]` table rather than guessed from the string, so `--phase 0ab` runs
/// exactly the phases someone wrote down.
fn resolve_phase(map: &AcMap, requested: &str) -> Vec<String> {
    match map.alias.get(requested) {
        Some(list) => list.clone(),
        None => vec![requested.to_string()],
    }
}

pub fn run(
    root: &Path,
    map_path: &Path,
    plan_path: &Path,
    phase: &str,
) -> Result<PhaseReport, String> {
    let text = std::fs::read_to_string(map_path)
        .map_err(|e| format!("cannot read {}: {e}", map_path.display()))?;
    let map: AcMap =
        toml::from_str(&text).map_err(|e| format!("cannot parse {}: {e}", map_path.display()))?;

    let phases = resolve_phase(&map, phase);

    // The owned set comes from the map, never from a list in this file, so an
    // AC cannot be dropped from the gate by being forgotten here.
    let owned: Vec<&Entry> = map
        .ac
        .iter()
        .chain(map.guard.iter())
        .filter(|e| phases.contains(&e.owning_gate))
        .collect();

    if owned.is_empty() {
        return Err(format!(
            "no acceptance criteria are owned by phase `{phase}` in {}. Either the phase id \
             is wrong or the map is — refusing to report a vacuous pass over an empty set",
            map_path.display()
        ));
    }

    // §9's row for this phase, reconciled against the map. Not optional: the
    // criteria below are a claim ABOUT that row, and checking them without it
    // is what returned PASS over a proper subset of Phase 1.
    let (uncovered, stated_gaps, scope_note, coverage_error) =
        match crate::phase_completeness::run(map_path, plan_path) {
            Ok(report) => {
                let cov = phases.iter().find_map(|p| report.for_phase(p));
                match cov {
                    Some(cov) => {
                        let note = (cov.phases.len() > phases.len()).then(|| {
                            format!(
                                "PARTIAL SCOPE — `{phase}` is {} of the {} phases gated by §9's \
                                 `{}`. Whatever this run reports, it does NOT close that gate; \
                                 the other phase(s) ({}) are not asserted here.",
                                phases.len(),
                                cov.phases.len(),
                                cov.command,
                                cov.phases
                                    .iter()
                                    .filter(|p| !phases.contains(p))
                                    .cloned()
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            )
                        });
                        (
                            cov.unclaimed()
                                .iter()
                                .map(|c| truncate(&c.clause, 150))
                                .collect(),
                            cov.clauses
                                .iter()
                                .filter(|c| !c.carried() && c.claimed())
                                .map(|c| truncate(&c.clause, 150))
                                .collect(),
                            note,
                            None,
                        )
                    }
                    None => (
                        Vec::new(),
                        Vec::new(),
                        None,
                        Some(format!(
                            "no §9 gate row covers phase `{phase}`, so there is no specification \
                             to check these criteria against"
                        )),
                    ),
                }
            }
            Err(e) => (Vec::new(), Vec::new(), None, Some(e)),
        };

    let mut results = Vec::new();
    // One test binary can back several ACs; run each distinct check once.
    let mut cache: BTreeMap<(String, String, bool, bool), CheckOutcome> = BTreeMap::new();

    for entry in owned {
        let mut outcomes = Vec::new();
        for ev in &entry.evidence {
            let key = (ev.package.clone(), ev.test.clone(), ev.ignored, ev.release);
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

    // Reachability is per-phase and derived from two committed files, so it
    // needs neither the plan nor the map. A phase that owns no refusal still
    // gets the line, because "no refusal names this phase" is a weaker
    // statement than "this phase is reachable" and the difference is worth
    // printing every time.
    let reachability = match crate::reachability::run(root) {
        Ok(r) => {
            let failed = phases.iter().any(|p| r.failed_for(p));
            let line = phases
                .iter()
                .map(|p| r.phase_line(p))
                .collect::<Vec<_>>()
                .join("\n");
            Some((line, failed))
        }
        Err(e) => Some((
            format!(
                "REACHABILITY: COULD NOT BE ESTABLISHED — {e}\n  This fails the gate. Absent \
                 evidence fails; it never skips."
            ),
            true,
        )),
    };

    Ok(PhaseReport {
        phase: phase.to_string(),
        results,
        uncovered,
        stated_gaps,
        scope_note,
        coverage_error,
        reachability,
    })
}

/// Keep a clause readable in a report without letting one sentence of §9 take
/// eight lines.
fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        return s.to_string();
    }
    let head: String = s.chars().take(n).collect();
    format!("{head}…")
}

fn clone_outcome(o: &CheckOutcome) -> CheckOutcome {
    match o {
        CheckOutcome::Passed { count } => CheckOutcome::Passed { count: *count },
        CheckOutcome::Failed { detail } => CheckOutcome::Failed {
            detail: detail.clone(),
        },
        CheckOutcome::MatchedNothing => CheckOutcome::MatchedNothing,
        CheckOutcome::MissingEnv { var } => CheckOutcome::MissingEnv { var: var.clone() },
        CheckOutcome::CouldNotRun { detail } => CheckOutcome::CouldNotRun {
            detail: detail.clone(),
        },
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
    cmd.current_dir(root).args(["test", "-p", &ev.package]);
    if ev.release {
        cmd.arg("--release");
    }
    cmd.args(["--", &ev.test, "--exact"]);
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
    let stderr = String::from_utf8_lossy(&out.stderr);
    let (passed, failed) = parse_counts(&stdout);
    classify(
        passed,
        failed,
        saw_result_line(&stdout),
        out.status.success(),
        &stderr,
    )
}

/// Did the harness print a `test result:` line *at all*?
///
/// Deliberately separate from [`parse_counts`], because "no line" and "a line
/// summing to zero" are different facts and only one of them survives a
/// `(u32, u32)` return. Collapsing them is what made a build failure and a
/// misnamed test indistinguishable.
fn saw_result_line(stdout: &str) -> bool {
    stdout.lines().any(|l| l.trim().starts_with("test result:"))
}

/// The outcome decision, split out from the process so it is testable without
/// spawning cargo.
///
/// Zero counts have two causes that mean opposite things — the filter matched
/// nothing (go rename a test) and the harness never ran (go fix a crate) — and
/// **the discriminator is the presence of a `test result:` line, not the exit
/// code.** A filter matching nothing still prints one, with zeroes. A compile
/// error, a link error, or a blocked build-directory lock prints none.
///
/// The exit code is the wrong discriminator in both directions. Cargo exits
/// **0** for an empty filter, which is the original defect; and an
/// infrastructure failure can also exit 0, which an exit-code test reports as
/// `MatchedNothing` — sending a reader to rename a test that exists. That
/// second case is the one an earlier version of this function got wrong, and it
/// is the reason the signal moved off the exit code.
///
/// The exit code survives only as corroboration: zeroes on a line we did see,
/// with a non-zero exit, means one binary matched nothing while something else
/// broke — indeterminate, not empty.
///
/// This is not hypothetical in either direction. A green workspace produced a
/// gate reporting ten missing tests that all existed and passed; separately, a
/// concurrent `cargo test --workspace` contending for the build directory
/// produced a one-off "AC-1 failed" between two clean runs.
pub fn classify(
    passed: u32,
    failed: u32,
    saw_result_line: bool,
    success: bool,
    stderr: &str,
) -> CheckOutcome {
    if !saw_result_line {
        return CheckOutcome::CouldNotRun {
            detail: format!(
                "no `test result:` line at all, so the harness never reached the tests. \
                 Last lines of stderr:\n{}",
                stderr_tail(stderr)
            ),
        };
    }
    if passed == 0 && failed == 0 {
        if success {
            return CheckOutcome::MatchedNothing;
        }
        return CheckOutcome::CouldNotRun {
            detail: format!(
                "a `test result:` line summing to zero, but cargo exited non-zero — one \
                 binary matched nothing while another failed to run. Indeterminate, not \
                 empty. Last lines of stderr:\n{}",
                stderr_tail(stderr)
            ),
        };
    }
    if failed > 0 || !success {
        return CheckOutcome::Failed {
            detail: format!("{failed} test(s) failed, {passed} passed"),
        };
    }
    CheckOutcome::Passed { count: passed }
}

/// The last few non-blank stderr lines, indented. Enough to name the crate and
/// the error; not so much that one broken build buries the other eleven rows.
fn stderr_tail(stderr: &str) -> String {
    let lines: Vec<&str> = stderr.lines().filter(|l| !l.trim().is_empty()).collect();
    let start = lines.len().saturating_sub(8);
    lines[start..]
        .iter()
        .map(|l| format!("             | {l}"))
        .collect::<Vec<_>>()
        .join("\n")
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

    /// The mirror defect, and the one that actually bit: a build failure
    /// reported as an empty filter says the test is missing when the test is
    /// fine — the most expensive possible wrong answer, because it points the
    /// reader at the wrong file.
    ///
    /// Kept, but rewritten: this originally asserted `Failed { "BUILD failure" }`
    /// because the first fix keyed on the exit code. The outcome is now
    /// `CouldNotRun`, which is a better answer to the same question — the
    /// distinction it draws is the one the reader needs, and it no longer
    /// depends on the failure having exited non-zero. Deleted the old
    /// expectation deliberately rather than leaving it asserting something
    /// weaker than it reads.
    #[test]
    fn a_build_failure_is_not_an_empty_filter() {
        let stderr = "error[E0432]: unresolved import `foo::Bar`";
        match classify(0, 0, false, false, stderr) {
            CheckOutcome::CouldNotRun { detail } => {
                assert!(
                    detail.contains("E0432"),
                    "stderr must be surfaced: {detail}"
                );
            }
            other => panic!("a build failure must not read as a missing test, got {other:?}"),
        }
    }

    /// The two zero-count cases must not be collapsed in either direction: a
    /// filter that matched nothing still prints its result line and exits 0,
    /// and must stay `MatchedNothing`, or the fix above would relabel every
    /// missing test as infrastructure and lose the original signal.
    #[test]
    fn an_empty_filter_still_reports_as_an_empty_filter() {
        assert_eq!(classify(0, 0, true, true, ""), CheckOutcome::MatchedNothing);
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

    fn passing_report() -> PhaseReport {
        PhaseReport {
            phase: "1".into(),
            results: vec![AcResult {
                id: "AC-13".into(),
                outcomes: vec![(
                    Evidence {
                        package: "p".into(),
                        test: "t".into(),
                        ignored: false,
                        release: false,
                        requires_env: None,
                        proves: String::new(),
                    },
                    CheckOutcome::Passed { count: 1 },
                )],
                missing_reason: None,
            }],
            uncovered: vec![],
            stated_gaps: vec![],
            scope_note: None,
            coverage_error: None,
            reachability: None,
        }
    }

    /// **The Phase 1 defect, as a unit test.** Every criterion the gate was
    /// given passes — and the phase is not done, because §9's row asks for
    /// things nothing in the map claims. The gate must fail, and must not
    /// print PASS while doing it.
    #[test]
    fn a_gate_whose_every_criterion_passes_still_fails_on_a_clause_nothing_claims() {
        let mut r = passing_report();
        assert!(
            !r.failed(),
            "the control: with the row covered, this passes"
        );
        r.uncovered = vec!["`atime_mode` detection correct on all three platforms.".into()];
        assert!(r.failed(), "an unclaimed §9 clause must fail the gate");
        let out = r.render();
        assert!(out.contains("UNENCODED"), "{out}");
        assert!(
            !out.contains("RESULT: PASS"),
            "a gate that fails must not print PASS anywhere in its verdict: {out}"
        );
    }

    /// **The Phase 2 defect, as a unit test.** Every criterion passes, the §9
    /// row is fully covered, and the phase still fails — because its own daemon
    /// answers `MethodNotImplemented` for the work it delivered. This is the
    /// case per-AC evidence structurally cannot see: each AC is true.
    #[test]
    fn a_gate_with_green_criteria_and_a_covered_row_still_fails_when_nothing_is_reachable() {
        let mut r = passing_report();
        assert!(!r.failed(), "the control");
        r.reachability = Some((
            "REACHABILITY: 9 of the daemon's 17 protocol methods/capabilities are REFUSED"
                .to_string(),
            true,
        ));
        assert!(r.failed(), "an unreachable phase must fail its gate");
        let out = r.render();
        assert!(out.contains("NOT REACHABLE"), "{out}");
        assert!(!out.contains("RESULT: PASS"), "{out}");
    }

    /// And a reported-but-not-failing reachability line must not fail the gate,
    /// or every phase with no recorded refusal would go red for the absence of
    /// a fact rather than the presence of one.
    #[test]
    fn a_reachability_line_that_does_not_fail_leaves_the_gate_alone() {
        let mut r = passing_report();
        r.reachability = Some(("REACHABILITY: no method … is refused".to_string(), false));
        assert!(!r.failed());
        assert!(r.render().contains("RESULT: PASS"));
    }

    /// A stated gap is honest, not satisfied. It fails for the same reason
    /// `evidence_missing` overrides passing evidence one level down.
    #[test]
    fn a_clause_claimed_only_by_a_stated_gap_fails_too() {
        let mut r = passing_report();
        r.stated_gaps = vec!["the 1M on-disk corpus".into()];
        assert!(r.failed());
        assert!(r.render().contains("STATED GAP"));
    }

    /// If the specification cannot be read, the gate has not checked it.
    /// "Could not determine" is not a pass here either.
    #[test]
    fn coverage_that_could_not_be_established_fails_rather_than_skipping() {
        let mut r = passing_report();
        r.coverage_error = Some("cannot read the plan".into());
        assert!(r.failed());
        assert!(r.render().contains("COULD NOT BE ESTABLISHED"));
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
            release: false,
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

#[cfg(test)]
mod harness_tests {
    use super::*;

    /// Drive the real decision, not a property of the fixture.
    ///
    /// An earlier version of these tests asserted `out.contains("test result:")`
    /// on a string literal written two lines above, which cannot fail whatever
    /// the gate does. `CouldNotRun` was declared, labelled, cloned and
    /// "tested" while **no production path could emit it** — the module's own
    /// defect, inside the fix for that defect. Every case below therefore goes
    /// through [`classify`] and asserts the outcome.
    fn classify_out(stdout: &str, success: bool, stderr: &str) -> CheckOutcome {
        let (p, f) = parse_counts(stdout);
        classify(p, f, saw_result_line(stdout), success, stderr)
    }

    /// A filter that matched nothing DOES print a result line, and must stay
    /// `MatchedNothing` — otherwise the fix relabels every missing test as
    /// infrastructure and the original signal is lost.
    #[test]
    fn a_zero_result_line_is_matched_nothing_not_a_harness_failure() {
        let out = "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 41 filtered out;\n";
        assert_eq!(classify_out(out, true, ""), CheckOutcome::MatchedNothing);
    }

    /// Real harness output for the two infrastructure failures actually
    /// observed on this branch.
    #[test]
    fn output_with_no_result_line_at_all_is_a_harness_failure() {
        for out in [
            "error: could not compile `shepherd-tier`\n",
            "Blocking waiting for file lock on build directory\n",
            "",
        ] {
            match classify_out(out, false, out) {
                CheckOutcome::CouldNotRun { .. } => {}
                other => panic!("no result line must be CouldNotRun, got {other:?} for {out:?}"),
            }
        }
    }

    /// **The case an exit-code discriminator gets wrong, and the reason the
    /// signal moved off the exit code.** An infrastructure failure that exits
    /// 0 has no result line; reading the exit code alone calls that
    /// `MatchedNothing` and sends someone to rename a test that exists.
    #[test]
    fn a_harness_failure_that_exits_zero_is_still_not_an_empty_filter() {
        match classify_out(
            "Blocking waiting for file lock on build directory\n",
            true,
            "",
        ) {
            CheckOutcome::CouldNotRun { .. } => {}
            other => {
                panic!("exit 0 with no result line must NOT read as an empty filter: {other:?}")
            }
        }
    }

    /// Zeroes on a line we did see, with a non-zero exit: one binary matched
    /// nothing while another failed to run. Indeterminate, not empty.
    #[test]
    fn a_zero_line_with_a_failing_exit_is_indeterminate_not_empty() {
        let out = "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 41 filtered out;\n";
        match classify_out(out, false, "error: could not compile `shepherd-scan`") {
            CheckOutcome::CouldNotRun { detail } => {
                assert!(detail.contains("Indeterminate"), "got: {detail}");
            }
            other => panic!("expected CouldNotRun, got {other:?}"),
        }
    }

    /// It still fails the gate. "Could not determine" is not a pass — the same
    /// posture as the acquisition floors treating an indeterminate open-handle
    /// check as held-open.
    #[test]
    fn could_not_run_fails_and_says_it_is_not_a_verdict_on_the_evidence() {
        let o = classify_out(
            "error: could not compile\n",
            false,
            "error: could not compile",
        );
        assert!(!o.ok());
        assert!(o.label().contains("NOT a verdict"));
        assert!(o.label().contains("could not determine"));
    }
}
