//! Shepherd workspace tasks.
//!
//! Run as `cargo xtask <command>` (see `.cargo/config.toml`).
//!
//! | command | status |
//! |---|---|
//! | `check-deps`   | implemented — §4.1 dependency rules, required in CI |
//! | `gate --audit` | implemented — §9 rule 6 AC-ownership audit **and** the §9 phase-completeness reconciliation |
//! | `claim-ledger` | implemented — §9 rule 5 evidence-tag ledger |
//! | `gate --phase` | implemented — runs each owned AC's evidence and checks §9's row for the phase |
//! | `codegen`      | implemented — §4.3 IPC artifacts; `--check` is required in CI |
//!
//! Commands that are not implemented exit with a distinct non-zero status. A
//! gate command that exited 0 without producing evidence is precisely the
//! defect §9 rule 6 records ("a tool credited with running that did not
//! exist"), so it is a deliberate design point that this binary never does so.
//!
//! *(The row for `gate --phase` said "NOT implemented; exits non-zero" until
//! this change, three commits after it was implemented. A status table is
//! documentation of the same kind as an evidence artifact, and a stale one
//! reads as current — so it is corrected here rather than left to be believed.)*

use xtask::{
    check_deps, claim_ledger, codegen, gate_audit, gate_phase, phase_completeness, reachability,
};

use std::path::{Path, PathBuf};
use std::process::ExitCode;

// The `EXIT_UNIMPLEMENTED = 3` status lived here for "this command exists but
// is not implemented yet". Every command is now implemented, so keeping it
// would be a reserved code nothing can return — and `.omc/artifacts/phase-0a/`
// still records `gate --phase` exiting 3, which is now a description of code
// that does not exist. Flagged rather than silently left agreeing with itself.

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match dispatch(&args) {
        Ok(code) => code,
        Err(msg) => {
            eprintln!("xtask: {msg}");
            ExitCode::from(2)
        }
    }
}

fn dispatch(args: &[String]) -> Result<ExitCode, String> {
    let Some(cmd) = args.first().map(String::as_str) else {
        print_usage();
        return Ok(ExitCode::from(2));
    };
    let rest = &args[1..];
    let root = workspace_root()?;

    match cmd {
        "check-deps" => cmd_check_deps(&root, rest),
        "gate" => cmd_gate(&root, rest),
        "claim-ledger" => cmd_claim_ledger(&root, rest),
        "codegen" => cmd_codegen(&root, rest),
        "-h" | "--help" | "help" => {
            print_usage();
            Ok(ExitCode::SUCCESS)
        }
        other => Err(format!(
            "unknown command `{other}`. Try `cargo xtask help`."
        )),
    }
}

fn print_usage() {
    eprintln!(
        "\
usage: cargo xtask <command>

  check-deps [--json]
        Enforce §4.1's dependency rules. Non-zero on any violation.

  gate --audit [--map <ac-map.toml>] [--plan <plan.md>] [--json] [--show-clauses]
        Two static checks over the map, both required in CI:
          * §9 rule 6: reject any AC owned by a phase earlier than the one
            whose §6 creates-list supplies the machinery that AC exercises.
          * §9 phase completeness: reconcile the map against §9's gate table —
            every gate command §9 names must be runnable, every AC must
            reconcile in both directions, and every clause of every row must
            be claimed. `--show-clauses` prints the clause split with its
            covering ids.

  gate --phase <id> | gate --release
        Run the evidence for every AC and guard the phase owns, asserting the
        test COUNT rather than the exit status, and fail on any clause of the
        phase's §9 row that nothing in the map claims. `<id>` accepts the
        compound ids §9 uses (`0ab`, `0cd`) via the map's [alias] table.

  claim-ledger [--plan <path>] [--escalations <path>] [--json] [--require-escalation]
        §9 rule 5: ledger of every [V]/[U] evidence tag in the plan, with
        untagged evidence cells treated as [U].

  codegen [--check] [--json]
        Emit the committed IPC artifacts under `schemas/` from
        `shepherd_proto::MethodKind::ALL`. `--check` writes nothing and exits
        non-zero when the tree disagrees with the method table.
"
    );
}

// ---------------------------------------------------------------------------

fn cmd_check_deps(root: &Path, args: &[String]) -> Result<ExitCode, String> {
    let json = args.iter().any(|a| a == "--json");
    let policy_path = root.join("xtask/deps-policy.toml");
    let policy = check_deps::load_policy(&policy_path)?;
    let report = check_deps::run(root, &policy)?;
    if json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.render());
    }
    Ok(if report.failed() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_codegen(root: &Path, args: &[String]) -> Result<ExitCode, String> {
    let json = args.iter().any(|a| a == "--json");
    let checking = args.iter().any(|a| a == "--check");
    let report = if checking {
        codegen::check(root)?
    } else {
        codegen::write(root)?
    };
    if json {
        println!("{}", report.to_json());
    } else {
        print!("{}", report.render());
    }
    Ok(if report.failed() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

fn cmd_gate(root: &Path, args: &[String]) -> Result<ExitCode, String> {
    let map_path = flag_value(args, "--map")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("xtask/ac-map.toml"));
    let plan_path = flag_value(args, "--plan")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".omc/plans/shepherd-consensus-plan.md"));

    // §9 names Phase 9's gate `xtask gate --release`, not `--phase 9`. Both
    // forms reach the same place; a command §9 names that this binary does not
    // answer to is a gate nobody can run.
    let phase = flag_value(args, "--phase").or_else(|| {
        args.iter()
            .any(|a| a == "--release")
            .then(|| "release".to_string())
    });

    if let Some(phase) = phase {
        let report = gate_phase::run(root, &map_path, &plan_path, &phase)?;
        print!("{}", report.render());
        return Ok(if report.failed() {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        });
    }

    if !args.iter().any(|a| a == "--audit") {
        return Err("gate: expected `--audit`, `--phase <id>` or `--release`".into());
    }
    let json = args.iter().any(|a| a == "--json");
    let show_clauses = args.iter().any(|a| a == "--show-clauses");

    let audit = gate_audit::run(&map_path)?;

    // Deliberately the same command: a completeness check nobody runs is the
    // problem it was written to fix, and `gate --audit` is already required in
    // CI.
    //
    // But the plan is **not committed** — `.gitignore` excludes all of
    // `/.omc/` — so a CI checkout cannot see §9 at all. That is the same
    // constraint that keeps `claim-ledger` out of CI, and it leaves three
    // options, all bad: fail every CI run over a file-location policy, skip
    // silently, or say so. This says so, loudly, and does not count as a pass.
    // Wherever the plan IS present — every developer machine, and every
    // `gate --phase` invocation, which fails outright without it — the
    // reconciliation runs.
    //
    // The real fix is a decision about where the specification lives, and that
    // is not this file's to make.
    let completeness = if plan_path.exists() {
        Some(phase_completeness::run(&map_path, &plan_path)?)
    } else {
        None
    };

    // Reachability reads only committed files, so unlike the completeness
    // check it works in CI. It is REPORTED here and fatal in `gate --phase`:
    // an unserved method is a statement about a phase's readiness, not about
    // the map's structure, and `--audit` is the map's check.
    let reach = reachability::run(root)?;

    let not_run = format!(
        "cargo xtask gate --audit — §9 phase-completeness reconciliation\n\
         {}\n\
         NOT RUN — {} is not present in this checkout.\n\
         This is NOT a pass. §9's gate table is the specification this reconciles against, and\n\
         the plan is gitignored (`/.omc/`), so no CI checkout can see it — the same reason\n\
         `xtask claim-ledger` is not a CI step. The check runs wherever the plan is: on every\n\
         developer machine, and inside `xtask gate --phase <id>`, which FAILS rather than\n\
         reports when the plan is missing.\n\
         Nothing here has been checked. Read this line as \"unknown\", never as \"clean\".\n",
        "=".repeat(72),
        plan_path.display()
    );

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ownership": serde_json::from_str::<serde_json::Value>(&audit.to_json())
                    .unwrap_or(serde_json::Value::Null),
                "completeness": match &completeness {
                    Some(c) => c.to_json(),
                    None => serde_json::json!({
                        "ran": false,
                        "why": "the plan is not in this checkout; /.omc/ is gitignored",
                    }),
                },
                "reachability": reach.to_json(),
                "pass": !audit.failed() && !completeness.as_ref().is_some_and(|c| c.failed()),
            }))
            .unwrap_or_default()
        );
    } else {
        print!("{}", audit.render());
        println!();
        match &completeness {
            Some(c) => print!("{}", c.render(show_clauses)),
            None => print!("{not_run}"),
        }
        println!();
        print!("{}", reach.render());
    }
    Ok(
        if audit.failed() || completeness.as_ref().is_some_and(|c| c.failed()) {
            ExitCode::FAILURE
        } else {
            ExitCode::SUCCESS
        },
    )
}

fn cmd_claim_ledger(root: &Path, args: &[String]) -> Result<ExitCode, String> {
    let json = args.iter().any(|a| a == "--json");
    let require_escalation = args.iter().any(|a| a == "--require-escalation");
    let plan = flag_value(args, "--plan")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".omc/plans/shepherd-consensus-plan.md"));
    let escalations = flag_value(args, "--escalations")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join(".omc/plans/open-questions.md"));

    let ledger = claim_ledger::run(&plan, escalations.exists().then_some(&escalations))?;
    if json {
        println!("{}", ledger.to_json());
    } else {
        print!("{}", ledger.render(require_escalation));
    }
    Ok(if require_escalation && ledger.blocking() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
}

// ---------------------------------------------------------------------------

fn flag_value(args: &[String], flag: &str) -> Option<String> {
    let i = args.iter().position(|a| a == flag)?;
    args.get(i + 1).cloned()
}

/// Walk up from the current directory to the nearest `Cargo.toml` declaring a
/// `[workspace]`, so `cargo xtask` works from any subdirectory.
fn workspace_root() -> Result<PathBuf, String> {
    let mut dir = std::env::current_dir().map_err(|e| format!("cannot read cwd: {e}"))?;
    loop {
        let manifest = dir.join("Cargo.toml");
        if manifest.is_file()
            && std::fs::read_to_string(&manifest)
                .map(|t| t.contains("[workspace]"))
                .unwrap_or(false)
        {
            return Ok(dir);
        }
        if !dir.pop() {
            return Err("no workspace root found above the current directory".into());
        }
    }
}
