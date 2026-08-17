//! Is a phase's work **reachable**, or only tested?
//!
//! # The defect
//!
//! `gate --phase 2` reported 11 of 12 criteria PASS while a user could not tier
//! a file. Every criterion was honestly evidenced: `shepherd-tier`,
//! `shepherd-storage` and the rules engine all exist and their tests all pass.
//! And `crates/shepherd-daemon/src/dispatch.rs` answers `MethodNotImplemented`
//! to `target.add`, `target.list`, `target.test`, `rule.list`, `rule.preview`,
//! `tier.plan`, `tier.run` and `restore` — every one of them Phase 2 machinery
//! — under a section header reading `registered, not served at Phase 1`.
//! `shepherd-daemon/Cargo.toml` does not depend on `shepherd-tier` at all.
//!
//! AC-14's cited evidence is `preview::tests::a_rule_with_no_preview_cannot_be_enabled`:
//! true, passing, and `rule.preview` answers `MethodNotImplemented` to anyone
//! who asks.
//!
//! **This is a sharper defect than the one that prompted this work.** Phase 1's
//! gate was *under-specified* and reported PASS over a subset. Phase 2's gate is
//! fully specified against twelve criteria, every one is real, and the phase is
//! still unusable. Under-specification is caught by
//! [`crate::phase_completeness`]. This one passes every check we had: a library
//! can land, be tested, close its gate, and never be wired to anything a user
//! can invoke.
//!
//! # What is checked
//!
//! The tree already states the fact in machine-readable form, in two committed
//! files and nothing else:
//!
//! * `schemas/ipc-inventory.json` — generated from `shepherd_proto::MethodKind::ALL`,
//!   the authority for what the protocol offers.
//! * `crates/shepherd-daemon/src/dispatch.rs` — where each method is either
//!   served or refused, and **the refusal names its owning phase in prose**
//!   ("tiering lands in Phase 2").
//!
//! So: a refusal naming Phase N is a Phase-N deliverable that cannot be
//! reached. `gate --phase N` fails on it. Not owning a refusal is *not*
//! evidence of reachability, and this module never says it is — see
//! [`Report::phase_line`].
//!
//! Capability-level refusals count too. `search` is served, and refuses its
//! `path_glob` filter naming Phase 2. That is Phase 2 functionality a user
//! cannot reach, in a method that reports as served.
//!
//! # What it cannot catch, stated plainly
//!
//! This reads what `dispatch.rs` **says**, not what the daemon **does**. A
//! method that is served and returns an empty result, or one wired to a stub,
//! reads as reachable here. The stronger form is a live probe — start a daemon,
//! call every method in the inventory, record which answer
//! `MethodNotImplemented` — and it belongs with the daemon's own e2e suite
//! rather than here.
//!
//! The scan's own blind spot is a refusal produced **without** the
//! `not_implemented` helper this module reads. That is guarded rather than
//! hoped away: `dispatch.rs` must construct `ErrorCode::MethodNotImplemented`
//! in exactly one place, and a second construction site is reported as the scan
//! having gone partially blind — the count is the assertion, as everywhere else
//! in this binary.

use std::fmt::Write as _;
use std::path::Path;

/// One `not_implemented(...)` call site.
#[derive(Debug, Clone)]
pub struct Refusal {
    /// First argument: a method name (`tier.run`) or a capability path within
    /// one (`search.filters.path_glob`).
    pub subject: String,
    /// Second argument, verbatim — the sentence naming who owns it.
    pub owner: String,
    /// The phase parsed out of `owner`, e.g. `2`.
    pub phase: Option<String>,
    /// `true` when `subject` is a whole method in the inventory.
    pub whole_method: bool,
}

pub struct Report {
    /// Method names from `ipc-inventory.json`.
    pub methods: Vec<String>,
    pub refusals: Vec<Refusal>,
    /// Failures **of the scan itself** — a refusal naming no phase, a subject
    /// the method table does not know, a second way to produce a refusal. These
    /// mean the answer below is not trustworthy, which is a different and worse
    /// thing than the answer being bad.
    pub violations: Vec<String>,
}

impl Report {
    /// Refusals attributed to `phase`.
    pub fn for_phase(&self, phase: &str) -> Vec<&Refusal> {
        self.refusals
            .iter()
            .filter(|r| r.phase.as_deref() == Some(phase))
            .collect()
    }

    pub fn unserved_methods(&self) -> usize {
        self.refusals.iter().filter(|r| r.whole_method).count()
    }

    /// The line `gate --phase` prints. Deliberately worded so that the clean
    /// case does not overclaim: no refusal naming this phase is not the same
    /// fact as this phase being reachable, and a gate that said the second
    /// while checking the first would be the defect this file is about,
    /// re-committed in its own fix.
    pub fn phase_line(&self, phase: &str) -> String {
        let mine = self.for_phase(phase);
        if mine.is_empty() {
            return format!(
                "REACHABILITY: no method or capability in the daemon is refused with Phase \
                 {phase} named as its owner.\n  This is NOT a statement that the phase is \
                 reachable — it is the absence of a recorded refusal. A method wired to a stub, \
                 or served and returning nothing, reads as served here."
            );
        }
        let mut s = format!(
            "REACHABILITY: {} of the daemon's {} protocol methods/capabilities are REFUSED, \
             naming Phase {phase} as their owner:\n",
            mine.len(),
            self.methods.len()
        );
        for r in &mine {
            let _ = writeln!(
                s,
                "  [{}] {} — \"{}\"",
                if r.whole_method {
                    "UNSERVED METHOD"
                } else {
                    "REFUSED CAPABILITY"
                },
                r.subject,
                truncate(&r.owner, 100)
            );
        }
        let _ = write!(
            s,
            "  The libraries this phase owns can pass every test they have while nothing a user \
             types reaches them. A phase whose own daemon answers MethodNotImplemented for the \
             work it delivered is not done, whatever its per-criterion evidence says."
        );
        s
    }

    pub fn failed_for(&self, phase: &str) -> bool {
        !self.for_phase(phase).is_empty() || !self.violations.is_empty()
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let _ = writeln!(s, "cargo xtask gate --audit — daemon reachability");
        let _ = writeln!(s, "{}", "=".repeat(72));
        let _ = writeln!(
            s,
            "protocol methods: {}   unserved: {}   capability refusals: {}",
            self.methods.len(),
            self.unserved_methods(),
            self.refusals.len() - self.unserved_methods()
        );
        let mut phases: Vec<&str> = self
            .refusals
            .iter()
            .filter_map(|r| r.phase.as_deref())
            .collect();
        phases.sort_unstable();
        phases.dedup();
        for p in &phases {
            let mine = self.for_phase(p);
            let _ = writeln!(
                s,
                "  Phase {p}: {} refused — {}",
                mine.len(),
                mine.iter()
                    .map(|r| r.subject.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        for v in &self.violations {
            let _ = writeln!(s, "  ✗ {v}");
        }

        // A banner, not a count among counts.
        //
        // This step does not fail: the daemon surface is unscheduled feature
        // work, and a CI that is red for months over something nobody can act
        // on today is the never-green-gate condition — everyone learns to read
        // past the colour and the next real failure hides behind it. The cost
        // of not failing is that this has to carry its weight in TEXT, which is
        // the one thing a reader skips. Hence the shape.
        if !self.refusals.is_empty() {
            let _ = writeln!(s, "{}", "!".repeat(72));
            let _ = writeln!(
                s,
                "!! {} of {} PROTOCOL METHODS ARE NOT SERVED BY THE DAEMON.",
                self.unserved_methods(),
                self.methods.len()
            );
            for p in &phases {
                let n = self.for_phase(p).len();
                let _ = writeln!(
                    s,
                    "!! {n} refusal(s) name PHASE {p} as their owner — that phase's libraries \
                     can pass\n!! every test they have while nothing a user types reaches them."
                );
            }
            let _ = writeln!(
                s,
                "!! This step PASSES. It is not a verdict that the product works — it is a \
                 count.\n!! `xtask gate --phase <id>` FAILS on these; read this banner as \
                 \"unreachable\",\n!! never as \"clean\"."
            );
            let _ = writeln!(s, "{}", "!".repeat(72));
        }

        let _ = writeln!(
            s,
            "NOTE: reported here, FATAL in `gate --phase <id>` for the phase a refusal names. \
             This reads what dispatch.rs says, not what the daemon does: a method wired to a \
             stub reads as served — the false-GREEN direction, and the reason \
             `every_registry_method_is_probed_and_exactly_the_recorded_ones_are_refused` in \
             shepherd-daemon's e2e suite probes all {} methods over the real IPC surface and \
             asserts the refused set by identity.",
            self.methods.len()
        );
        s
    }

    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "methods": self.methods.len(),
            "unserved_methods": self.unserved_methods(),
            "violations": self.violations,
            "refusals": self.refusals.iter().map(|r| serde_json::json!({
                "subject": r.subject,
                "phase": r.phase,
                "whole_method": r.whole_method,
            })).collect::<Vec<_>>(),
        })
    }
}

pub fn run(root: &Path) -> Result<Report, String> {
    let inv_path = root.join("schemas/ipc-inventory.json");
    let inv_text = std::fs::read_to_string(&inv_path)
        .map_err(|e| format!("cannot read {}: {e}", inv_path.display()))?;
    let inv: serde_json::Value =
        serde_json::from_str(&inv_text).map_err(|e| format!("cannot parse the inventory: {e}"))?;

    let methods: Vec<String> = inv["methods"]
        .as_array()
        .ok_or("ipc-inventory.json has no `methods` array")?
        .iter()
        .filter_map(|m| m["name"].as_str().map(str::to_string))
        .collect();

    let mut violations = Vec::new();
    // The inventory states its own count. Checking it costs one line and turns
    // a truncated or half-written artifact into a loud failure rather than a
    // smaller method set that everything downstream silently agrees with.
    if let Some(n) = inv["method_count"].as_u64()
        && n as usize != methods.len()
    {
        violations.push(format!(
            "ipc-inventory.json declares method_count = {n} but lists {} methods — the artifact \
             disagrees with itself, so every count below is derived from an unknown quantity",
            methods.len()
        ));
    }
    if methods.is_empty() {
        violations.push(
            "the inventory lists NO methods, so every method trivially reads as served. A scan \
             over an empty set is the empty-filter defect one file over"
                .into(),
        );
    }

    let dispatch_path = root.join("crates/shepherd-daemon/src/dispatch.rs");
    let src = std::fs::read_to_string(&dispatch_path)
        .map_err(|e| format!("cannot read {}: {e}", dispatch_path.display()))?;

    let (refusals, mut scan_violations) = scan(&src, &methods);
    violations.append(&mut scan_violations);

    Ok(Report {
        methods,
        refusals,
        violations,
    })
}

/// Pull every `not_implemented("subject", "owner …")` out of `dispatch.rs`.
///
/// Split from [`run`] so it is testable without the repository, and because the
/// interesting failures are all in here.
pub fn scan(src: &str, methods: &[String]) -> (Vec<Refusal>, Vec<String>) {
    let mut refusals = Vec::new();
    let mut violations = Vec::new();

    // The guard on the scan itself. If a refusal can be produced without the
    // helper, this scan is blind to it and must say so rather than report a
    // smaller number confidently.
    //
    // Counted over code, not over comments: `dispatch.rs`'s module doc names
    // `ErrorCode::MethodNotImplemented` while explaining the convention, and a
    // raw string count read that as a second construction site. Reusing
    // `check_deps::strip_comment` rather than writing a second stripper —
    // rule 4's scanner already learned this exact lesson, and its
    // `a_comment_naming_the_method_is_not_a_call` test is the record of it.
    let construction_sites = src
        .lines()
        .map(crate::check_deps::strip_comment)
        .map(|l| l.matches("ErrorCode::MethodNotImplemented").count())
        .sum::<usize>();
    if construction_sites != 1 {
        violations.push(format!(
            "dispatch.rs constructs ErrorCode::MethodNotImplemented in {construction_sites} \
             places, not 1. This scan only reads `not_implemented(...)` call sites, so any other \
             route to a refusal is invisible to it — the count below may be an undercount, which \
             is worse than a wrong one because it reads as good news"
        ));
    }

    let mut rest = src;
    let mut consumed = 0usize;
    while let Some(idx) = rest.find("not_implemented(") {
        let at = consumed + idx;
        let open = at + "not_implemented".len();
        consumed = open;
        rest = &src[open..];

        // The helper's own definition is not a call site.
        if src[..at].ends_with("fn ") {
            continue;
        }
        let Some(args) = balanced(&src[open..]) else {
            violations.push(format!(
                "a `not_implemented(` call at byte {at} has no matching close paren — the file \
                 could not be parsed and this scan is incomplete"
            ));
            continue;
        };
        let Some(subject) = first_string_literal(args) else {
            violations.push(format!(
                "a `not_implemented(` call at byte {at} does not name its subject as a string \
                 literal, so the scan cannot attribute it to a method"
            ));
            continue;
        };
        let owner = args[subject.1..]
            .trim_start_matches([',', ' ', '\n'])
            .trim();
        let owner = owner
            .trim_start_matches('"')
            .trim_end_matches([')', ' ', '\n', ','])
            .trim_end_matches('"')
            .replace("\\\n", " ")
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");

        let subject = subject.0;
        let whole_method = methods.contains(&subject);
        if !whole_method {
            // A capability path: its method prefix must still exist, or the
            // string is a typo and the refusal names nothing real.
            let known_prefix = methods
                .iter()
                .any(|m| subject.starts_with(&format!("{m}.")));
            if !known_prefix {
                violations.push(format!(
                    "dispatch.rs refuses `{subject}`, which is neither a method in \
                     ipc-inventory.json nor a capability of one. Either the protocol dropped it \
                     and the refusal is dead, or the string is a typo — in both cases the \
                     refusal names nothing a user can call"
                ));
            }
        }

        let phase = phase_in(&owner);
        if phase.is_none() {
            violations.push(format!(
                "the refusal for `{subject}` names no phase (\"{}\"), so no gate can be made to \
                 fail on it. A refusal that names its owner is a promise; one that does not is a \
                 permanent hole",
                truncate(&owner, 80)
            ));
        }

        refusals.push(Refusal {
            subject,
            owner,
            phase,
            whole_method,
        });
    }

    (refusals, violations)
}

/// The text between the parens starting at `s[0] == '('`, ignoring parens that
/// sit inside string literals.
fn balanced(s: &str) -> Option<&str> {
    let bytes: Vec<char> = s.chars().collect();
    if bytes.first() != Some(&'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut in_str = false;
    let mut escaped = false;
    for (i, c) in bytes.iter().enumerate() {
        if in_str {
            if escaped {
                escaped = false;
            } else if *c == '\\' {
                escaped = true;
            } else if *c == '"' {
                in_str = false;
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    let end: usize = bytes[..=i].iter().map(|c| c.len_utf8()).sum();
                    return Some(&s[1..end - 1]);
                }
            }
            _ => {}
        }
    }
    None
}

/// The first `"…"` in `args`, and the byte offset just past it.
fn first_string_literal(args: &str) -> Option<(String, usize)> {
    let start = args.find('"')?;
    let mut escaped = false;
    for (i, c) in args[start + 1..].char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match c {
            '\\' => escaped = true,
            '"' => {
                return Some((args[start + 1..start + 1 + i].to_string(), start + 2 + i));
            }
            _ => {}
        }
    }
    None
}

/// `"tiering lands in Phase 2"` -> `Some("2")`.
fn phase_in(owner: &str) -> Option<String> {
    let at = owner.find("Phase ")?;
    let digits: String = owner[at + "Phase ".len()..]
        .chars()
        .take_while(char::is_ascii_digit)
        .collect();
    (!digits.is_empty()).then_some(digits)
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

    fn repo() -> std::path::PathBuf {
        crate::evidence_artifacts::repo_root()
    }

    /// **The scan against the real tree.** Not an assertion that the tree is
    /// reachable — it is not — but that every refusal in it is *classified*.
    /// An unclassified refusal is the scan failing quietly, which is the only
    /// outcome here worse than a bad answer.
    #[test]
    fn every_refusal_in_the_real_dispatch_is_attributed_to_a_phase_and_a_known_subject() {
        let r = run(&repo()).expect("the inventory and dispatch.rs are both committed");
        assert!(
            r.violations.is_empty(),
            "the scan could not account for something:\n  {}",
            r.violations.join("\n  ")
        );
        assert_eq!(
            r.methods.len(),
            17,
            "the method table changed size; if that is intended, update this count — it exists \
             so a scan over an empty or truncated inventory cannot read as `all served`"
        );
        assert!(
            !r.refusals.is_empty(),
            "the scan found NO refusals at all. dispatch.rs refuses eight methods today, so \
             zero means the scan stopped working, not that the daemon started serving them"
        );
    }

    /// The defect itself, asserted as a fact about the tree rather than as a
    /// failure: Phase 2's own methods are refused. When they are served this
    /// test fails and is deleted — and the day it fails is the day the gate can
    /// go green, so it is worth the noise.
    #[test]
    fn phase_2_methods_are_currently_unserved_and_the_gate_must_see_it() {
        let r = run(&repo()).unwrap();
        let two = r.for_phase("2");
        assert!(
            !two.is_empty(),
            "no refusal names Phase 2. Either the daemon now serves tiering — in which case \
             delete this test and the gate goes green honestly — or the scan broke"
        );
        for expected in ["tier.run", "restore", "rule.preview", "target.add"] {
            assert!(
                two.iter().any(|r| r.subject == expected),
                "`{expected}` is Phase 2 machinery and the scan did not find it refused; got {:?}",
                two.iter().map(|r| &r.subject).collect::<Vec<_>>()
            );
        }
        assert!(r.failed_for("2"), "the gate must fail phase 2 on this");
    }

    /// A capability refusal inside a served method counts. `search` is served
    /// and refuses its glob filter, naming Phase 2 — Phase 2 functionality a
    /// user cannot reach, in a method that reports as served.
    #[test]
    fn a_capability_refused_inside_a_served_method_is_still_unreachable() {
        let r = run(&repo()).unwrap();
        let glob = r
            .refusals
            .iter()
            .find(|x| x.subject == "search.filters.path_glob")
            .expect("search refuses its path_glob filter");
        assert!(
            !glob.whole_method,
            "it is a capability of `search`, not a method"
        );
        assert_eq!(glob.phase.as_deref(), Some("2"));
    }

    /// The clean case must not overclaim. "No refusal names this phase" is not
    /// "this phase is reachable", and the gate prints the difference.
    #[test]
    fn a_phase_with_no_refusals_is_reported_as_unrecorded_not_as_reachable() {
        let r = run(&repo()).unwrap();
        let line = r.phase_line("7");
        assert!(
            line.contains("NOT a statement that the phase is reachable"),
            "{line}"
        );
        assert!(!r.failed_for("7"), "an absent refusal must not fail a gate");
    }

    /// A doc comment naming the error code is not a construction site. The
    /// real `dispatch.rs` names it in its module doc while explaining the
    /// convention, and counting raw occurrences reported the scan as blind
    /// when it was not — a false alarm that fails every gate is as corrosive
    /// as a false pass, because the response to both is to stop reading it.
    #[test]
    fn a_comment_naming_the_error_code_is_not_a_second_construction_site() {
        let methods = vec!["tier.run".to_string()];
        let src = r#"
            //! The unimplemented ones return [`ErrorCode::MethodNotImplemented`] rather
            fn not_implemented(m: &str, o: &str) -> RpcError {
                RpcError::new(ErrorCode::MethodNotImplemented, format!("{m} {o}"))
            }
            fn f() { Err(not_implemented("tier.run", "tiering lands in Phase 2")) }
        "#;
        let (refusals, violations) = scan(src, &methods);
        assert!(violations.is_empty(), "got {violations:?}");
        assert_eq!(refusals.len(), 1);
    }

    /// A second route to a refusal blinds this scan, so the count of
    /// construction sites is asserted rather than assumed.
    #[test]
    fn a_second_way_to_produce_a_refusal_is_reported_as_the_scan_going_blind() {
        let methods = vec!["tier.run".to_string()];
        let src = r#"
            fn not_implemented(m: &str, o: &str) -> RpcError {
                RpcError::new(ErrorCode::MethodNotImplemented, format!("{m} {o}"))
            }
            fn tier_run() -> Result<(), RpcError> {
                Err(RpcError::new(ErrorCode::MethodNotImplemented, "hand-rolled".into()))
            }
        "#;
        let (_, violations) = scan(src, &methods);
        assert!(
            violations.iter().any(|v| v.contains("undercount")),
            "got {violations:?}"
        );
    }

    /// A refusal that names no phase can never be made to fail a gate. It must
    /// be reported rather than quietly attributed to nothing.
    #[test]
    fn a_refusal_that_names_no_phase_is_a_violation() {
        let methods = vec!["tier.run".to_string()];
        let src = r#"
            fn not_implemented(m: &str, o: &str) -> RpcError {
                RpcError::new(ErrorCode::MethodNotImplemented, format!("{m} {o}"))
            }
            fn f() { Err(not_implemented("tier.run", "not done yet")) }
        "#;
        let (refusals, violations) = scan(src, &methods);
        assert_eq!(refusals.len(), 1);
        assert!(refusals[0].phase.is_none());
        assert!(
            violations.iter().any(|v| v.contains("permanent hole")),
            "got {violations:?}"
        );
    }

    /// A refusal for a subject the method table does not know names nothing a
    /// user can call — a dead refusal, or a typo.
    #[test]
    fn a_refusal_for_an_unknown_subject_is_a_violation() {
        let methods = vec!["tier.run".to_string()];
        let src = r#"
            fn not_implemented(m: &str, o: &str) -> RpcError {
                RpcError::new(ErrorCode::MethodNotImplemented, format!("{m} {o}"))
            }
            fn f() { Err(not_implemented("teir.run", "tiering lands in Phase 2")) }
        "#;
        let (_, violations) = scan(src, &methods);
        assert!(
            violations.iter().any(|v| v.contains("teir.run")),
            "got {violations:?}"
        );
    }

    /// Multi-line calls are the majority form in the real file; a scanner that
    /// only read single-line ones would miss `rule.list` and `rule.preview` and
    /// report a smaller, cleaner, wrong number.
    #[test]
    fn a_multi_line_call_is_read_the_same_as_a_single_line_one() {
        let methods = vec!["rule.list".to_string()];
        let src = r#"
            fn not_implemented(m: &str, o: &str) -> RpcError {
                RpcError::new(ErrorCode::MethodNotImplemented, format!("{m} {o}"))
            }
            fn f() {
                Err(not_implemented(
                    "rule.list",
                    "the rule engine lands in Phase 2; only the matcher exists at Phase 1",
                ))
            }
        "#;
        let (refusals, violations) = scan(src, &methods);
        assert!(violations.is_empty(), "got {violations:?}");
        assert_eq!(refusals.len(), 1);
        assert_eq!(refusals[0].subject, "rule.list");
        assert_eq!(refusals[0].phase.as_deref(), Some("2"));
        assert!(refusals[0].whole_method);
    }
}
