//! Shepherd workspace tasks.
//!
//! Run as `cargo xtask <command>` (see `.cargo/config.toml`).
//!
//! | command | status |
//! |---|---|
//! | `check-deps`   | implemented — §4.1 dependency rules, required in CI |
//! | `gate --audit` | implemented — §9 rule 6 AC-ownership audit |
//! | `claim-ledger` | implemented — §9 rule 5 evidence-tag ledger |
//! | `gate --phase` | NOT implemented; exits non-zero rather than pass vacuously |
//! | `codegen`      | NOT implemented (Phase 1) |
//!
//! Commands that are not implemented exit with a distinct non-zero status. A
//! gate command that exited 0 without producing evidence is precisely the
//! defect §9 rule 6 records ("a tool credited with running that did not
//! exist"), so it is a deliberate design point that this binary never does so.

use xtask::{check_deps, claim_ledger, gate_audit};

use std::path::{Path, PathBuf};
use std::process::ExitCode;

/// Exit status for "this command exists but is not implemented yet".
const EXIT_UNIMPLEMENTED: u8 = 3;

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
        "codegen" => {
            eprintln!(
                "xtask codegen: NOT IMPLEMENTED. It is a Phase 1 deliverable \
                 (`xtask/src/codegen.rs`, §6 Phase 1). Exiting {EXIT_UNIMPLEMENTED}."
            );
            Ok(ExitCode::from(EXIT_UNIMPLEMENTED))
        }
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

  gate --audit [--map <ac-map.toml>] [--json]
        §9 rule 6: reject any AC owned by a phase earlier than the one whose
        §6 creates-list supplies the machinery that AC exercises.

  gate --phase <id>
        NOT IMPLEMENTED. Exits {EXIT_UNIMPLEMENTED}.

  claim-ledger [--plan <path>] [--escalations <path>] [--json] [--require-escalation]
        §9 rule 5: ledger of every [V]/[U] evidence tag in the plan, with
        untagged evidence cells treated as [U].

  codegen
        NOT IMPLEMENTED (Phase 1).
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

fn cmd_gate(root: &Path, args: &[String]) -> Result<ExitCode, String> {
    if let Some(phase) = flag_value(args, "--phase") {
        eprintln!(
            "xtask gate --phase {phase}: NOT IMPLEMENTED.\n\
             The phase gates in §9 require evidence this repository cannot yet produce \
             (bench baselines, MinIO E2E runs, signed packages). This command deliberately \
             exits {EXIT_UNIMPLEMENTED} instead of returning success, because a gate that \
             passes without evidence is the exact defect §9 rule 6 records."
        );
        return Ok(ExitCode::from(EXIT_UNIMPLEMENTED));
    }
    if !args.iter().any(|a| a == "--audit") {
        return Err("gate: expected `--audit` or `--phase <id>`".into());
    }
    let json = args.iter().any(|a| a == "--json");
    let map_path = flag_value(args, "--map")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("xtask/ac-map.toml"));
    let report = gate_audit::run(&map_path)?;
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
