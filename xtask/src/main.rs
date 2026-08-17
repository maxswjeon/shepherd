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

        SCHEDULE THESE TWO; they are not casual commands, and neither says so
        until you are already inside it:
          --phase 1   a 1M-file scan plus a 10M index build in --release.
                      Needs $SHEPHERD_M1_CORPUS and FAILS without it.
          --phase 2   a real 50 GB upload against MinIO, 45+ minutes.
                      Needs $SHEPHERD_MINIO_ENDPOINT and FAILS without it.
                      IT GOES SILENT FOR ~32 MINUTES during the resume leg —
                      it has NOT hung. Killing it there destroys a 53-minute
                      run and the failure looks environmental. Check
                      /proc/<pid>/io for progress instead of the output.
        Both hold the build-directory lock across many `cargo test` runs, so a
        concurrent build turns one evidence row into CouldNotRun and costs the
        whole run. See .omc/handoffs/shared-worktree-hazards.md §2.

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
    let table_path = root.join(phase_completeness::TABLE_PATH);

    // Regenerating §9's tracked table is the one mutating gate operation, so it
    // is an explicit verb rather than a side effect of auditing. `gate --audit`
    // that silently rewrote the artifact it checks could never report drift.
    if args.iter().any(|a| a == "--regen-table") {
        let plan = std::fs::read_to_string(&plan_path).map_err(|e| {
            format!(
                "cannot read the plan at {}: {e}. Regenerating requires a checkout that has it",
                plan_path.display()
            )
        })?;
        let rows = phase_completeness::parse_gate_table(&plan)?;
        let rendered = phase_completeness::render_table(&rows);
        std::fs::write(&table_path, &rendered)
            .map_err(|e| format!("cannot write {}: {e}", table_path.display()))?;
        println!(
            "wrote {} — {} §9 gate rows, {} bytes",
            table_path.display(),
            rows.len(),
            rendered.len()
        );
        return Ok(ExitCode::SUCCESS);
    }

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
    // This used to be unable to run there at all: the plan is gitignored, so a
    // CI checkout could not see §9. It now reconciles against the tracked
    // `xtask/section9-gate-table.json`, generated from §9 by
    // `gate --regen-table`, and reports whether that artifact is still known to
    // match its source. Absent plan (CI) is NOT a failure; a drifted artifact
    // (local) is.
    let completeness = phase_completeness::run(&map_path, &plan_path, &table_path)?;

    // Reachability reads only committed files, so unlike the completeness
    // check it works in CI. It is REPORTED here and fatal in `gate --phase`:
    // an unserved method is a statement about a phase's readiness, not about
    // the map's structure, and `--audit` is the map's check.
    let reach = reachability::run(root)?;

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "ownership": serde_json::from_str::<serde_json::Value>(&audit.to_json())
                    .unwrap_or(serde_json::Value::Null),
                "completeness": completeness.to_json(),
                "reachability": reach.to_json(),
                "pass": !audit.failed() && !completeness.failed(),
            }))
            .unwrap_or_default()
        );
    } else {
        print!("{}", audit.render());
        println!();
        print!("{}", completeness.render(show_clauses));
        println!();
        print!("{}", reach.render());
    }
    Ok(if audit.failed() || completeness.failed() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    })
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
