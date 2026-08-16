//! `shepherdd` — the always-on daemon.
//!
//! # Argv is an installer surface, not the method table
//!
//! `run`, `install`, `uninstall`, `doctor`. These are deliberately **not**
//! IPC methods: installing a service cannot be done by the daemon being
//! installed, and adding them to the table would add `shepctl install`
//! commands that AC-54's `CLI == registered_methods` would then require the UI
//! to offer too. The registry stays exactly the product surface; the installer
//! lives here.
//!
//! `shepherdd doctor` overlaps the `doctor` *method* on purpose: the method is
//! what a running daemon answers, this is what you run when it is not running.
//! Both call the same checks.
//!
//! # Startup order
//!
//! 1. resolve paths, open the catalog, start the writer actor;
//! 2. **recover crash-interrupted jobs before any worker starts** — otherwise a
//!    worker could claim a fresh job while a stranded one is still `running`
//!    and never be resolved;
//! 3. warn about lingering (never change it — OQ-F);
//! 4. bind the socket, start the pool, serve.

use std::sync::Arc;
use std::sync::atomic::AtomicBool;

use shepherd_catalog::writer::CatalogActor;
use shepherd_daemon::events::EventHub;
use shepherd_daemon::paths::Paths;
use shepherd_daemon::scan_exec::ScanExecutor;
use shepherd_daemon::state::Daemon;
use shepherd_daemon::{EVENT_BUFFER, server, service};
use shepherd_jobs::worker::{Pool, Registry};
use shepherd_jobs::{POOL_SIZE, Recovery, recover};

fn main() -> std::process::ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let command = args.first().map(String::as_str).unwrap_or("run");

    let result = match command {
        "run" => cmd_run(),
        "install" => cmd_install(),
        "uninstall" => cmd_uninstall(),
        "doctor" => cmd_doctor(),
        "-h" | "--help" | "help" => {
            print_usage();
            return std::process::ExitCode::SUCCESS;
        }
        "--version" | "-V" => {
            println!("shepherdd {}", env!("CARGO_PKG_VERSION"));
            return std::process::ExitCode::SUCCESS;
        }
        other => Err(format!("unknown command `{other}`. Try `shepherdd help`.")),
    };

    match result {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("shepherdd: {message}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn print_usage() {
    println!(
        "\
usage: shepherdd <command>

  run                Run the daemon in the foreground (the default).
  install            Install the per-user service unit for this platform.
  uninstall          Remove it. Never touches the catalog or secrets.
  doctor             Run the self-checks locally, without a running daemon.

Clients talk to this process over the socket; see `shepctl --help`.
Service installation is intentionally not an IPC method — see the module docs."
    );
}

// ---------------------------------------------------------------------------

fn cmd_run() -> Result<(), String> {
    shepherd_obs::tracing_setup::init_tracing("info");
    let paths = Paths::from_process()?;
    std::fs::create_dir_all(&paths.state_dir)
        .map_err(|e| format!("cannot create {}: {e}", paths.state_dir.display()))?;

    let catalog = shepherd_catalog::Catalog::open(&paths.catalog())
        .map_err(|e| format!("cannot open {}: {e}", paths.catalog().display()))?;
    let actor = CatalogActor::start(catalog, Some(paths.catalog()));
    let hub = EventHub::new_for_run(EVENT_BUFFER);
    let daemon = Daemon::new(actor, hub, paths.clone());

    // Before any worker runs: a job left `running` by a crash must be resolved
    // while nothing else is claiming, and a `destroy` job must be quarantined
    // rather than requeued (§4.10.4).
    match recover(&daemon.writer) {
        Ok(recovered) => report_recovery(&recovered),
        Err(e) => tracing::warn!(error = %e, "could not run crash recovery"),
    }

    warn_about_lingering();

    let listener = server::bind(&paths.socket).map_err(|e| e.to_string())?;
    tracing::info!(
        socket = %paths.socket.display(),
        catalog = %paths.catalog().display(),
        proto = %shepherd_proto::PROTO_VERSION,
        "shepherdd listening"
    );

    // The `scan` executor is registered; every other class is still
    // unregistered, and a worker never claims a class it cannot run, so those
    // jobs wait at zero attempts rather than burning their retry budget.
    let registry = Arc::new(Registry::new().with(
        shepherd_catalog::job_repo::JobClass::Scan,
        ScanExecutor::new(Arc::clone(&daemon)),
    ));
    let pool = Pool::start(daemon.writer.clone(), registry, POOL_SIZE);

    let stop = shutdown_flag();
    server::serve(listener, Arc::clone(&daemon), Arc::clone(&stop));

    tracing::info!("shutting down");
    pool.shutdown();
    let _ = std::fs::remove_file(&paths.socket);
    Ok(())
}

fn report_recovery(recovered: &[Recovery]) {
    for r in recovered {
        match r {
            Recovery::Requeued(id) => {
                tracing::info!(job = %id, "requeued a job interrupted by an unclean shutdown");
            }
            Recovery::Quarantined { id, why } => {
                // Deliberately `warn`: this needs a human, and it is the one
                // recovery outcome the daemon will not resolve on its own.
                tracing::warn!(job = %id, why, "quarantined an interrupted job");
            }
        }
    }
}

/// OQ-F: state the consequence, change nothing.
fn warn_about_lingering() {
    let user = shepherd_obs::lingering::current_user();
    let state = shepherd_obs::lingering::probe(&user);
    let check =
        shepherd_obs::lingering::check(&state, shepherd_obs::lingering::looks_seated(), &user);
    if let shepherd_obs::doctor::CheckStatus::Warn {
        detail,
        remediation,
    } = &check.status
    {
        match remediation {
            Some(cmd) => tracing::warn!(remediation = %cmd, "{detail}"),
            None => tracing::warn!("{detail}"),
        }
    }
}

/// Shutdown, and the honest account of what happens on a signal.
///
/// There is **no signal handler**, and that is a decision rather than an
/// omission. `std` has no portable signal API, so catching SIGTERM means
/// `signal-hook` or raw `libc` — a new workspace dependency for the daemon to
/// exit slightly more tidily.
///
/// It buys very little here, because the daemon is designed to survive being
/// killed outright:
///
/// * the catalog runs at `synchronous = FULL`, so a committed write is durable
///   before the call returns;
/// * a job caught mid-flight is left `running`, which is precisely what
///   `Queue::recover_interrupted` looks for at the next start;
/// * `kill_and_resume_of_a_checkpointed_job` in `shepherd-jobs` is the test
///   that this path works.
///
/// What is lost to a SIGTERM is the socket file, which the next start clears
/// as stale ([`server::bind`]), and the chance to finish the job in hand, which
/// recovery re-queues. Both are already handled.
///
/// `stop` therefore exists for in-process shutdown — the integration tests, and
/// any future IPC `shutdown` method — and the flag is honoured by the accept
/// loop.
/// ponytail: no signal handling; add `signal-hook` if a shutdown ever needs to
/// flush something SQLite is not already making durable.
fn shutdown_flag() -> Arc<AtomicBool> {
    Arc::new(AtomicBool::new(false))
}

// ---------------------------------------------------------------------------

fn cmd_install() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("cannot find this binary: {e}"))?;
    let outcome = service::install(&exe).map_err(|e| e.to_string())?;
    print_outcome("installed", &outcome);
    Ok(())
}

fn cmd_uninstall() -> Result<(), String> {
    let outcome = service::uninstall().map_err(|e| e.to_string())?;
    print_outcome("removed", &outcome);
    Ok(())
}

fn print_outcome(verb: &str, outcome: &service::Outcome) {
    for p in &outcome.paths {
        println!("{verb}: {}", p.display());
    }
    for c in &outcome.commands {
        println!("ran: {c}");
    }
    for n in &outcome.notes {
        if !n.is_empty() {
            println!("\n{n}");
        }
    }
}

/// `shepherdd doctor` — the offline half.
///
/// Runs the checks a client process can run without a daemon. The §9 gate's
/// seatless-VM row needs exactly this: on a headless node with lingering
/// disabled the daemon does **not** start, so the lingering report has to come
/// from somewhere that is not the daemon.
fn cmd_doctor() -> Result<(), String> {
    let user = shepherd_obs::lingering::current_user();
    let state = shepherd_obs::lingering::probe(&user);

    let mut doctor = shepherd_obs::doctor::Doctor::new();
    doctor.push(shepherd_obs::lingering::check(
        &state,
        shepherd_obs::lingering::looks_seated(),
        &user,
    ));

    match Paths::from_process() {
        Ok(paths) => {
            let running = std::os::unix::net::UnixStream::connect(&paths.socket).is_ok();
            doctor.push(shepherd_obs::doctor::Check::new(
                "daemon",
                if running {
                    shepherd_obs::doctor::CheckStatus::Ok
                } else {
                    shepherd_obs::doctor::CheckStatus::warn(
                        format!("no daemon is listening on {}", paths.socket.display()),
                        "shepherdd run",
                    )
                },
            ));
            doctor.push(shepherd_obs::doctor::Check::new(
                "catalog",
                if paths.catalog().exists() {
                    shepherd_obs::doctor::CheckStatus::Ok
                } else {
                    shepherd_obs::doctor::CheckStatus::NotApplicable {
                        reason: format!("{} does not exist yet", paths.catalog().display()),
                    }
                },
            ));
        }
        Err(e) => {
            doctor.push(shepherd_obs::doctor::Check::new(
                "paths",
                shepherd_obs::doctor::CheckStatus::fail(e),
            ));
        }
    }

    print!("{}", doctor.render());
    println!(
        "\nThese are the checks a client can run on its own. A running daemon answers \
         `shepctl doctor` with more."
    );
    if doctor.is_clean() {
        Ok(())
    } else {
        Err("one or more checks failed".into())
    }
}
