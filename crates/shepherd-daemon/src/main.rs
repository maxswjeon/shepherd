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

    // CREATE owner-only, or VERIFY — never seize. The socket directory learned
    // this one round earlier and the state directory is the same hazard through
    // a different environment variable: `SHEPHERD_STATE_DIR=/tmp` as root
    // passes the ownership check below (root owns `/tmp`) and the chmod then
    // makes the mode check pass too, locking every other user and service out.
    //
    // `create_dir_all_tracked` already reports which levels it made, which is
    // exactly the distinction needed: those are ours by construction and may be
    // tightened; anything that was already there is checked and refused.
    // The ANCESTRY, before anything is created — the same walk the socket path
    // takes, and for the same reason one level up. `metadata` below follows a
    // symlinked ancestor and describes whatever it resolves to at that instant,
    // while `daemon.lock`, `catalog.db` and `secrets.json` are opened through
    // the ORIGINAL pathname afterwards. A link another account can repoint in
    // between therefore passes every check here and still lands the daemon's
    // state — including its secrets — inside a directory that account controls.
    //
    // Shared rather than copied: two spellings of one rule drift, and this one
    // already arrived a round after the socket's. Both walks run, configured
    // and resolved, so a writable directory ABOVE a link's target is refused
    // too. See `server::check_ancestry`.
    //
    // Residual unchanged and still #3: a component this daemon itself owns can
    // move between the check and the open. Nobody else can move it.
    let me = unsafe { libc::geteuid() };
    shepherd_daemon::server::check_path_ancestry(dir, me, "the state directory")?;

    // ABSOLUTE from here down, not only for the walk. A relative override made
    // `created`'s parents run out at the first component, so `parent()` was
    // `""` and the durability fsync failed with a bare "No such file or
    // directory" naming nothing — a working directory is a property of the
    // process, not of the path, and every operation below is about a place on
    // disk rather than about what the operator typed.
    let dir = &std::path::absolute(dir).map_err(|e| {
        format!(
            "cannot resolve {} against the working directory: {e}",
            dir.display()
        )
    })?;

    let created =
        create_dir_all_tracked(dir).map_err(|e| format!("cannot create {}: {e}", dir.display()))?;

    // AND AGAIN, after creating. The walk above described the path as it was
    // found; `create_dir_all_tracked` can lose a race for a missing component
    // to another account under a sticky ancestor such as `/tmp`, and that
    // account's directory would then sit above the leaf every check below
    // looks at. Re-walking is what turns "it was safe a moment ago" into "it
    // is safe now", and it costs one `lstat` per component.
    shepherd_daemon::server::check_path_ancestry(dir, me, "the state directory")?;
    let we_made_it = created.iter().any(|p| p == dir);

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

    // Only a directory THIS call created is tightened.
    if we_made_it {
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
            .map_err(|e| format!("cannot restrict {} to 0700: {e}", dir.display()))?;
    }

    let mode = std::fs::metadata(dir)
        .map_err(|e| format!("cannot inspect {}: {e}", dir.display()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(format!(
            "{} is mode {mode:04o}, and the catalog will not be opened under a directory \
             other accounts can read — it holds the user's complete file inventory and the \
             custody rows that are a tiered file's only remote address. This daemon will NOT \
             chmod a directory it did not create: doing that to `/run` or `/tmp` locks out \
             every other user on the machine. Point `SHEPHERD_STATE_DIR` at a dedicated \
             directory, which will be created `0700`, or tighten this one yourself",
            dir.display()
        ));
    }

    // --- and now make all of that survive a power cut ---------------------
    //
    // `create_dir_all` returns once the entries exist in the page cache. On a
    // filesystem that needs a directory fsync for crash durability — ext4 in
    // its default `data=ordered`, among others — the directory NAMING a new
    // entry is not on disk until it is synced, and neither is a mode change,
    // which lives in the directory's own inode. So a first start could open the
    // catalog, report writes durable, and lose the whole state directory to a
    // power cut moments later — or bring it back at the umask's `0755`, which
    // is the mode this function exists to refuse.
    //
    // Two syncs, and both are needed for different reasons: `dir` itself,
    // because the chmod above changed its inode and because it names whatever
    // the catalog is about to create inside it; and the parent of every
    // directory just created, because that is what makes the new name real.
    // Ordered before the catalog is opened, so nothing is ever reported durable
    // on top of a directory that is not.
    sync_dir(dir).map_err(|e| format!("cannot fsync {}: {e}", dir.display()))?;
    for made in &created {
        if let Some(parent) = made.parent() {
            sync_dir(parent).map_err(|e| format!("cannot fsync {}: {e}", parent.display()))?;
        }
    }
    Ok(())
}

/// `create_dir_all`, reporting which directories it actually created.
///
/// The list is what [`secure_state_dir`] needs to know which parents to fsync:
/// syncing every ancestor up to `/` would be wasteful and syncing none is the
/// defect. Deepest last, which is also creation order.
///
/// An `AlreadyExists` from the create is not an error — another process may
/// have made the same directory between the probe and the call — but it does
/// mean this process did not create it, so it is dropped from the list rather
/// than counted.
#[cfg(unix)]
fn create_dir_all_tracked(dir: &std::path::Path) -> std::io::Result<Vec<std::path::PathBuf>> {
    let mut missing: Vec<std::path::PathBuf> = Vec::new();
    let mut cursor = Some(dir);
    while let Some(p) = cursor {
        // `try_exists`, not `exists`: a permission error on an ancestor is a
        // real failure and must not read as "absent", which would send this
        // into a `create_dir` that fails with a more confusing message.
        if p.try_exists()? {
            break;
        }
        missing.push(p.to_path_buf());
        cursor = p.parent().filter(|q| !q.as_os_str().is_empty());
    }

    // OWNER-ONLY at creation, every level, not only the leaf.
    //
    // `create_dir` obeys the ambient umask, and `secure_state_dir` chmods the
    // final directory alone — so with a permissive umask an intermediate this
    // daemon made was left world-writable, and an account that can write it can
    // rename or replace the checked `0700` leaf before `daemon.lock`,
    // `catalog.db` and `secrets.json` are opened through the pathname. The mode
    // has to be applied by the call that creates the entry rather than after
    // it, or the window is simply narrower.
    //
    // `DirBuilder::mode` is `mkdir(2)`'s mode argument, so the directory is
    // never briefly anything else — the same reason `secure_socket_dir` builds
    // with it rather than creating and tightening.
    use std::os::unix::fs::DirBuilderExt;
    let mut created = Vec::with_capacity(missing.len());
    for p in missing.iter().rev() {
        match std::fs::DirBuilder::new().mode(0o700).create(p) {
            Ok(()) => created.push(p.clone()),
            // Somebody else made it between the probe and the call. NOT ours,
            // so it is not chmodded — and not trusted either: the caller
            // re-walks the whole ancestry after this returns, which is what
            // catches an account that won the race and installed a writable
            // intermediate under a sticky ancestor like `/tmp`.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    }
    Ok(created)
}

/// fsync a directory, so an entry created in it survives a crash.
///
/// Unix-only by construction: this whole function lives under the same gate as
/// [`secure_state_dir`], because opening a directory as a file is not something
/// the Windows API permits. Windows durability is Phase 3's, with the rest of
/// the platform.
#[cfg(unix)]
fn sync_dir(dir: &std::path::Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
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

    // THE SINGLETON LOCK, before the catalog is opened.
    //
    // It used to be taken inside `server::bind` at the end of start-up, which
    // is after crash recovery has already rewritten job rows. A second
    // `shepherdd` started while this one had a live scan read that legitimate
    // `running` row as crash-stranded, requeued it, and only then reached
    // `bind` and lost the lock — leaving the first daemon's workers free to
    // claim a second copy of a job whose executor was still running.
    //
    // Everything below this line touches the shared catalog, so everything
    // below this line is underneath the lock.
    let state_lock =
        server::lock_state_dir(&paths.state_dir.join("daemon.lock")).map_err(|e| e.to_string())?;

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
    //
    // A failure here is FATAL, unlike the index rebuild below. This was a
    // warning followed by an ordinary start, which is the one outcome the
    // ordering exists to prevent: the pool comes up and accepts new work while
    // crash-stranded jobs are still `running` — destroy jobs among them, the
    // ones §4.10.4 requires to be quarantined before anything else claims.
    // Every invariant this call establishes would then be unestablished for the
    // whole life of the daemon, and nothing would try again.
    let recovered = recover(&daemon.writer)
        .map_err(|e| format!("crash recovery failed, refusing to start workers: {e}"))?;
    report_recovery(&recovered);

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

    // The state lock taken at the top is handed over here, which is what keeps
    // it held for the daemon's life: `Bound` owns it from now on.
    let bound = server::bind(&daemon.paths.socket, state_lock).map_err(|e| e.to_string())?;
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
    let pool = Pool::start(
        daemon.writer.clone(),
        registry,
        POOL_SIZE,
        Arc::new(HubJobObserver(Arc::clone(&daemon))),
    );

    let stop = shutdown_flag();
    // `bound` is held to the end of `run`, which is what keeps the startup lock
    // held for the daemon's life: dropping it before `serve` returns would let
    // a second daemon take the socket out from under this one.
    server::serve(bound.listener, Arc::clone(&daemon), Arc::clone(&stop));

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
            Recovery::Exhausted { id, why } => {
                // `warn`, not `info`: work the user asked for has stopped
                // permanently, and nothing will pick it up again.
                tracing::warn!(job = %id, why, "an interrupted job was out of attempts");
            }
            Recovery::Quarantined { id, why } => {
                // Deliberately `warn`: this needs a human, and it is the one
                // recovery outcome the daemon will not resolve on its own.
                tracing::warn!(job = %id, why, "quarantined an interrupted job");
            }
        }
    }
}

/// The queue's transitions, on the `job` event stream.
///
/// `events.subscribe` advertises that stream and nothing published to it: a
/// client could subscribe successfully and watch an entire queue drain without
/// receiving a frame. This is the join — `shepherd-jobs` reports plain data
/// about its own queue and stays free of a protocol dependency, and the mapping
/// onto the wire type lives here, where the two already meet.
struct HubJobObserver(Arc<Daemon>);

impl shepherd_jobs::worker::JobObserver for HubJobObserver {
    fn transition(&self, t: shepherd_jobs::worker::Transition) {
        self.0.events.publish(
            shepherd_proto::event::EventStream::Job,
            shepherd_proto::event::EventPayload::JobTransition {
                job_id: t.id.get(),
                class: t.class.as_str().to_owned(),
                from: t.from.as_str().to_owned(),
                to: t.to.as_str().to_owned(),
                // The wire field is `u32` and the catalog's is `i64`. A
                // saturating cast rather than a wrapping one: an attempts count
                // that wrapped to 0 would read as "this is the first try".
                attempts: u32::try_from(t.attempts).unwrap_or(u32::MAX),
                last_error: t.last_error,
            },
        );
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

    /// A replaceable ancestor of the state directory is refused, and refusing
    /// creates nothing.
    ///
    /// The ownership and mode checks below describe what the pathname resolves
    /// to at the instant they run, and `daemon.lock`, `catalog.db` and
    /// `secrets.json` are opened through the ORIGINAL pathname afterwards — so
    /// a component another account can repoint in between passes every one of
    /// them and still lands the daemon's secrets inside a directory that
    /// account controls. The socket path grew this walk a round earlier and
    /// this one is the same hazard through `SHEPHERD_STATE_DIR`; it is the
    /// SAME walk rather than a second spelling of it.
    #[test]
    fn a_replaceable_ancestor_of_the_state_directory_is_refused() {
        let base = tmp("anc");
        let open = base.join("open");
        std::fs::create_dir_all(&open).unwrap();
        // Explicit, not umask-derived. `create_dir_all` takes whatever umask
        // the process has, and this binary now has a test that sets it to 0 —
        // so a fixture that leaned on the ambient value picked up `0777` on
        // `base` and was refused by the ancestry walk for a reason that had
        // nothing to do with what it was testing.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();

        let under = open.join("state");
        let err = secure_state_dir(&under)
            .expect_err("a state directory anyone may rename must be refused");
        assert!(
            err.contains("not sticky") && err.contains("the state directory"),
            "the refusal must name what is wrong and which destination: {err}"
        );
        assert!(
            !under.exists(),
            "and a refused path must be left exactly as it was found"
        );

        // THE ACCEPTING DIRECTION, and the one the old rule would have failed:
        // a symlinked ancestor this account owns is not a hazard, because only
        // this account or root can repoint it. `$TMPDIR` under macOS is exactly
        // this shape.
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        let real = base.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();
        secure_state_dir(&base.join("link").join("state"))
            .expect("a link this daemon owns must not block startup");
        assert_eq!(mode_of(&real.join("state")), 0o700);
        std::fs::remove_dir_all(&base).ok();
    }

    /// A RELATIVE override is walked from the working directory, not from its
    /// own first component.
    ///
    /// `Path::components` on a relative path yields only what is written in it,
    /// so `SHEPHERD_STATE_DIR=state` was checked as `state` alone and the
    /// process's working directory — and everything above it — was never
    /// examined. Start shepherdd in a directory another account owns and that
    /// account can rename the `0700` child this creates and substitute its own.
    /// The deepest-existing search did not save it either: it walks `parent()`,
    /// and a relative path's parents run out at the first component.
    #[test]
    fn a_relative_state_directory_is_walked_from_the_working_directory() {
        let base = tmp("rel");
        let open = base.join("open");
        std::fs::create_dir_all(&open).unwrap();
        // Explicit for the same reason as the ancestry fixture above.
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();

        // The refusal must come from the ancestor, reached only by resolving
        // the relative path against the working directory.
        let guard = WorkingDir::set(&open);
        let err = secure_state_dir(std::path::Path::new("state"))
            .expect_err("a relative path under a world-writable directory must be refused");
        assert!(
            err.contains("not sticky") && err.contains(open.to_string_lossy().as_ref()),
            "the refusal must name the ancestor the working directory supplied: {err}"
        );
        assert!(
            !open.join("state").exists(),
            "and a refused path must be left exactly as it was found"
        );

        // THE ACCEPTING DIRECTION: the same relative name under a working
        // directory that is fine.
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o700)).unwrap();
        secure_state_dir(std::path::Path::new("state"))
            .expect("a relative path under an owner-only directory is ordinary");
        assert_eq!(mode_of(&open.join("state")), 0o700);
        drop(guard);
        std::fs::remove_dir_all(&base).ok();
    }

    /// Serialises the process-wide working directory for the test above.
    ///
    /// `set_current_dir` is process-global and the test harness is threaded, so
    /// a bare call would move the ground under every other test in this binary.
    struct WorkingDir {
        previous: std::path::PathBuf,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    /// The one lock both process-global guards take.
    ///
    /// Two locks would not serialise them against each other, and a test that
    /// moved the working directory while another changed the umask would make a
    /// third fail for a reason nobody could find.
    fn process_state_lock() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    impl WorkingDir {
        fn set(to: &std::path::Path) -> Self {
            let lock = process_state_lock();
            let previous = std::env::current_dir().unwrap();
            std::env::set_current_dir(to).unwrap();
            Self {
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for WorkingDir {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.previous);
        }
    }

    /// EVERY level this daemon creates is owner-only, not only the leaf.
    ///
    /// `create_dir` obeys the ambient umask and `secure_state_dir` chmodded the
    /// final directory alone, so with a permissive umask an intermediate this
    /// daemon made was left group- or world-writable. An account that can write
    /// it can rename or replace the checked `0700` leaf before `daemon.lock`,
    /// `catalog.db` and `secrets.json` are opened through the pathname — the
    /// leaf's own mode says nothing about who can swap the leaf.
    ///
    /// The umask is set for the duration, because the defect is invisible under
    /// the ordinary `022`: the old code produced `0755` intermediates there and
    /// nobody would have called that world-writable.
    #[test]
    fn every_level_of_a_created_state_path_is_owner_only() {
        let base = tmp("levels");
        let deep = base.join("a").join("b").join("state");

        let _umask = Umask::set(0o000);
        secure_state_dir(&deep).unwrap();
        drop(_umask);

        for level in [base.join("a"), base.join("a").join("b"), deep.clone()] {
            assert_eq!(
                mode_of(&level),
                0o700,
                "{} was created {:04o} under a permissive umask",
                level.display(),
                mode_of(&level)
            );
        }
        std::fs::remove_dir_all(&base).ok();
    }

    /// Sets the process umask for a scope, and puts it back.
    ///
    /// Process-global like the working directory, and the harness is threaded,
    /// so it takes the same lock the working-directory guard does — a test that
    /// changed the umask underneath another would make an unrelated one fail
    /// for a reason nobody could find.
    struct Umask {
        previous: libc::mode_t,
        _lock: std::sync::MutexGuard<'static, ()>,
    }

    impl Umask {
        fn set(to: libc::mode_t) -> Self {
            let lock = process_state_lock();
            // SAFETY: `umask` is infallible per POSIX — it returns the previous
            // value and cannot fail. It is process-global, which is what the
            // lock above is for.
            let previous = unsafe { libc::umask(to) };
            Self {
                previous,
                _lock: lock,
            }
        }
    }

    impl Drop for Umask {
        fn drop(&mut self) {
            unsafe { libc::umask(self.previous) };
        }
    }

    /// A first run creates it, and the ambient umask does not get a vote.
    #[test]
    fn a_new_state_directory_is_owner_only() {
        let d = tmp("new");
        secure_state_dir(&d).unwrap();
        assert_eq!(mode_of(&d), 0o700, "state directory is {:04o}", mode_of(&d));
        std::fs::remove_dir_all(&d).ok();
    }

    /// An existing world-readable state directory is REFUSED — not tightened,
    /// and not tolerated.
    ///
    /// ORACLE CHANGED, and the change is the remedy rather than the property.
    /// This asserted that such a directory was chmodded to `0700`, because
    /// accepting it as found leaves the catalog readable to every account on
    /// the host. That half still holds. What does not is doing it by force:
    /// `SHEPHERD_STATE_DIR=/tmp` as root passes the ownership check — root owns
    /// `/tmp` — and the chmod then makes the mode check pass too, locking every
    /// other user and service out of the machine's shared directory. The socket
    /// directory learned this one round earlier through the same reasoning.
    ///
    /// So a directory this daemon did not create is checked and refused with
    /// the remedy named. A directory an earlier RUN created is unaffected: this
    /// daemon makes them `0700`.
    ///
    /// The foreign-ownership refusal above it has no test: a directory owned by
    /// another uid cannot be created without privileges a test suite must not
    /// have. It is stated here rather than left as an apparent oversight.
    #[test]
    fn an_existing_world_readable_state_directory_is_refused() {
        let d = tmp("loose");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::set_permissions(&d, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(
            mode_of(&d),
            0o755,
            "the fixture itself has to be loose, or this test asserts nothing"
        );

        let err = secure_state_dir(&d).expect_err("a shared directory must not be seized");
        assert!(
            err.contains("did not create"),
            "the refusal must explain why it will not just fix the mode: {err}"
        );
        assert_eq!(
            mode_of(&d),
            0o755,
            "and it must not have been chmodded on the way to refusing"
        );

        // THE ACCEPTING DIRECTION: a dedicated child, which the daemon creates
        // owner-only. This is what an operator does after reading the refusal.
        let child = d.join("shepherd");
        secure_state_dir(&child).expect("a dedicated child is created and secured");
        assert_eq!(mode_of(&child), 0o700);

        std::fs::remove_dir_all(&d).ok();
    }

    /// A custom `SHEPHERD_STATE_DIR` several levels deep still comes up, and
    /// every level this process made is reported.
    ///
    /// The report is what decides which directories get fsynced, so a level
    /// missing from it is a level whose *name* is not durable. The fsync
    /// ordering itself cannot be asserted here — proving it needs a power cut,
    /// or a filesystem fault injector this suite does not have — so what is
    /// checked is the input that ordering depends on.
    #[test]
    fn every_directory_level_this_process_creates_is_reported() {
        let root = tmp("deep");
        let leaf = root.join("a/b/c");

        let created = create_dir_all_tracked(&leaf).unwrap();
        assert_eq!(
            created,
            vec![
                root.clone(),
                root.join("a"),
                root.join("a/b"),
                root.join("a/b/c"),
            ],
            "shallowest first, which is creation order, and none skipped"
        );
        assert!(leaf.is_dir());

        // Second call: everything is already there, so this process created
        // nothing and there is nothing whose name it must publish.
        assert!(
            create_dir_all_tracked(&leaf).unwrap().is_empty(),
            "a directory that already existed was reported as newly created; \
             its parent would then be fsynced on every single start"
        );

        // And the whole path through `secure_state_dir`, which is what actually
        // runs at start-up: nested creation, then the mode, then the syncs.
        let other_root = tmp("deep2");
        let other = other_root.join("x/y");
        secure_state_dir(&other).unwrap();
        assert_eq!(mode_of(&other), 0o700);

        std::fs::remove_dir_all(&root).ok();
        std::fs::remove_dir_all(&other_root).ok();
    }
}
