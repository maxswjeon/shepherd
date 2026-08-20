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
use shepherd_daemon::Paths;
use shepherd_daemon::events::EventHub;
use shepherd_daemon::scan_exec::ScanExecutor;
#[cfg(unix)]
use shepherd_daemon::server;
use shepherd_daemon::state::Daemon;
use shepherd_daemon::{EVENT_BUFFER, service};
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

/// Create the state directory — or tighten one that already exists — to `0700`.
///
/// # This is the same control as the socket's, on the half that holds the data
///
/// §4.3 makes filesystem permissions the *entire* authorization model: "same
/// user, same machine, not network-exposed", no token and no per-caller check.
/// [`server::bind`] therefore sets the socket to `0600` under a `0700`
/// directory. The state directory holds `catalog.db` — the user's complete file
/// inventory, and the custody rows that are a tiered file's only remote address
/// — so leaving it world-readable hands over by another route exactly what the
/// socket's mode exists to withhold.
///
/// The per-user assumption is already load-bearing elsewhere:
/// `targets::resolve_credentials` lets `target.add` fall back to ambient cloud
/// credentials *only* because the caller's uid is the daemon's uid. This is that
/// same invariant, seen from the filesystem.
///
/// # Why it was `0755` in practice
///
/// `create_dir_all` obeys the umask, which is `022` on an ordinary login. On the
/// normal Linux layout nothing later tightens it either: §4.3 puts the socket in
/// `$XDG_RUNTIME_DIR`, so `bind`'s `0700` lands on a different directory
/// entirely. Only the fallback layout — no runtime dir, socket inside the state
/// directory — ever got it right, and by accident.
///
/// # Refusing rather than warning
///
/// The mode is **asserted after being set** rather than merely requested, which
/// is what makes this a check instead of an intention, and a mismatch stops the
/// daemon. Ownership is checked first so the failure names the actual cause:
/// `chmod` on someone else's directory fails with `EPERM`, which reads as a
/// permissions bug rather than as "something other than you owns your catalog".
#[cfg(unix)]
fn secure_state_dir(dir: &std::path::Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    std::fs::create_dir_all(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    // SAFETY: `geteuid` is always successful per POSIX — it cannot fail, has no
    // error return, and touches no memory we own.
    let me = unsafe { libc::geteuid() };
    let owner = std::fs::metadata(dir)
        .map_err(|e| format!("cannot inspect {}: {e}", dir.display()))?
        .uid();
    if owner != me {
        return Err(format!(
            "{} is owned by uid {owner}, but this daemon runs as uid {me}. shepherdd is a \
             per-user agent (§4.2) and its catalog is the only address of tiered files; it \
             will not open one under a directory it does not own",
            dir.display()
        ));
    }

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| format!("cannot restrict {} to 0700: {e}", dir.display()))?;

    let mode = std::fs::metadata(dir)
        .map_err(|e| format!("cannot inspect {}: {e}", dir.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(format!(
            "{} is mode {mode:04o} after being set to 0700. The catalog will not be opened \
             under a directory whose permissions the filesystem does not enforce",
            dir.display()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------

/// Serve, on a platform that has a transport.
///
/// The IPC surface is a Unix domain socket (§4.2), and `server` is
/// `#[cfg(unix)]` for that reason. Windows needs a named pipe and a startup
/// task, which §6 defers to Phase 3 alongside package identity.
///
/// This refuses rather than being absent: the whole workspace must BUILD and
/// TEST on all three platforms from Phase 0a so a platform break is found on
/// the commit that caused it, and a `run` that silently does not exist on
/// Windows would leave the binary compiling while doing nothing — the same
/// shape as a check that passes without its subject. `cargo test` on Windows
/// now reaches every other command.
#[cfg(not(unix))]
fn cmd_run() -> Result<(), String> {
    Err(format!(
        "the daemon's IPC transport is not implemented on {} yet (Phase 3): \
         it is a Unix domain socket, and Windows needs a named pipe and a \
         startup task with package identity. Every other subcommand works here",
        std::env::consts::OS
    ))
}

#[cfg(unix)]
fn cmd_run() -> Result<(), String> {
    shepherd_obs::tracing_setup::init_tracing("info");
    let paths = Paths::from_process()?;
    // Before the catalog exists, not after: SQLite creates `catalog.db` with
    // whatever the directory and the umask allow, and a file created readable
    // stays readable.
    secure_state_dir(&paths.state_dir)?;

    let catalog = shepherd_catalog::Catalog::open(&paths.catalog())
        .map_err(|e| format!("cannot open {}: {e}", paths.catalog().display()))?;
    let actor = CatalogActor::start(catalog, Some(paths.catalog()));
    let hub = EventHub::new_for_run(EVENT_BUFFER);
    // Moved in: `Daemon` owns `Paths` for the process lifetime, and the
    // start-up path below reads the daemon's copy rather than keeping a second.
    let daemon = Daemon::new(actor, hub, paths);

    // Before any worker runs: a job left `running` by a crash must be resolved
    // while nothing else is claiming, and a `destroy` job must be quarantined
    // rather than requeued (§4.10.4).
    match recover(&daemon.writer) {
        Ok(recovered) => report_recovery(&recovered),
        Err(e) => tracing::warn!(error = %e, "could not run crash recovery"),
    }

    warn_about_lingering();

    // §4.6's winning candidate has no persisted form, so the arena is rebuilt at
    // every start. A failure here is logged and NOT fatal: an unsearchable
    // daemon still scans, still tiers and still restores, and refusing to boot
    // would take the safety-critical paths down with the convenience one.
    // `search` answers `Precondition` in the meantime rather than answering
    // "no hits", and `doctor` reports it — an index that is absent must never be
    // indistinguishable from an index that found nothing.
    match daemon.rebuild_index() {
        Ok(entries) => tracing::info!(entries, "metadata index ready"),
        Err(e) => tracing::error!(error = %e, "the metadata index could not be built; \
                                               `search` will be refused until a restart"),
    }

    let listener = server::bind(&daemon.paths.socket).map_err(|e| e.to_string())?;
    tracing::info!(
        socket = %daemon.paths.socket.display(),
        catalog = %daemon.paths.catalog().display(),
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
    let _ = std::fs::remove_file(&daemon.paths.socket);
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
            // `Some(false)` means "asked, nothing listening". `None` means
            // "could not ask" — there is no transport to try on this platform,
            // so reporting `not running` would be a claim the check never
            // made. Same fail-closed distinction as `floors::open_handles`.
            #[cfg(unix)]
            let running = Some(std::os::unix::net::UnixStream::connect(&paths.socket).is_ok());
            #[cfg(not(unix))]
            let running: Option<bool> = None;
            if running.is_none() {
                doctor.push(shepherd_obs::doctor::Check::new(
                    "daemon",
                    shepherd_obs::doctor::CheckStatus::Warn {
                        detail: format!(
                            "cannot tell whether a daemon is running on {}: the IPC \
                             transport is a Unix domain socket and is not implemented \
                             here yet (Phase 3). This is `could not determine`, not \
                             `not running`",
                            std::env::consts::OS
                        ),
                        remediation: None,
                    },
                ));
            }
            if let Some(running) = running {
                doctor.push(shepherd_obs::doctor::Check::new(
                    "daemon",
                    if running {
                        shepherd_obs::doctor::CheckStatus::Ok
                    } else {
                        let (unit_path, registered) = service::registration();
                        let registration = if registered {
                            format!("registered: service unit exists at {unit_path}")
                        } else {
                            format!("not registered: no service unit at {unit_path}")
                        };
                        shepherd_obs::doctor::CheckStatus::warn(
                            format!(
                                "no daemon is listening on {}; {registration}",
                                paths.socket.display()
                            ),
                            service::start_command(registered),
                        )
                    },
                ));
            }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "shepherdd-statedir-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn mode_of(p: &std::path::Path) -> u32 {
        std::fs::metadata(p).unwrap().permissions().mode() & 0o777
    }

    /// A first run creates it, and the ambient umask does not get a vote.
    #[test]
    fn a_new_state_directory_is_owner_only() {
        let d = tmp("new");
        secure_state_dir(&d).unwrap();
        assert_eq!(mode_of(&d), 0o700, "state directory is {:04o}", mode_of(&d));
        std::fs::remove_dir_all(&d).ok();
    }

    /// The case that actually shipped: the directory already exists, created by
    /// an earlier run under a `022` umask. Accepting it as found is what leaves
    /// the catalog readable to every account on the host, so it is tightened
    /// rather than tolerated.
    ///
    /// The foreign-ownership refusal above it has no test: a directory owned by
    /// another uid cannot be created without privileges a test suite must not
    /// have. It is stated here rather than left as an apparent oversight.
    #[test]
    fn an_existing_group_and_world_readable_state_directory_is_tightened() {
        let d = tmp("loose");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            mode_of(&d),
            0o755,
            "the fixture itself has to be loose, or this test asserts nothing"
        );

        secure_state_dir(&d).unwrap();

        assert_eq!(mode_of(&d), 0o700, "state directory is {:04o}", mode_of(&d));
        std::fs::remove_dir_all(&d).ok();
    }
}
