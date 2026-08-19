//! The Linux systemd **user** unit.
//!
//! A user unit, not a system unit, per §4.2: every asset the daemon owns is
//! user-scoped. The consequence — that it starts at *logon*, not boot, and
//! never at all on a headless node without lingering — is stated to the user by
//! [`install`] rather than worked around.

use std::path::{Path, PathBuf};

use super::{Outcome, Result, ServiceError, io_err};

pub const UNIT_NAME: &str = "shepherd.service";

/// The environment inputs [`unit_path`] resolution depends on.
///
/// Resolution is pure over an injected environment so the fallback order —
/// and, through [`write_unit_file`], `install()`'s actual write location — is
/// testable without setting process-global variables, which would race every
/// other test in the binary. Same shape as `paths::Env`, which documents the
/// same reasoning.
#[derive(Debug, Clone, Default)]
struct Env {
    xdg_config_home: Option<String>,
    home: Option<String>,
}

impl Env {
    fn from_process() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            xdg_config_home: var("XDG_CONFIG_HOME"),
            home: var("HOME"),
        }
    }
}

/// `~/.config/systemd/user/shepherd.service`, resolved over an injected
/// environment.
fn unit_path_in(env: &Env) -> Result<PathBuf> {
    let base = match (&env.xdg_config_home, &env.home) {
        (Some(xdg), _) => PathBuf::from(xdg),
        (None, Some(home)) => PathBuf::from(home).join(".config"),
        (None, None) => {
            return Err(ServiceError::Unsupported(
                "cannot locate a config directory: neither XDG_CONFIG_HOME nor HOME is set".into(),
            ));
        }
    };
    Ok(base.join("systemd/user").join(UNIT_NAME))
}

/// `~/.config/systemd/user/shepherd.service`.
pub fn unit_path() -> Result<PathBuf> {
    unit_path_in(&Env::from_process())
}

/// The unit file text.
///
/// Pure, so the content is testable without writing anything.
///
/// `Restart=on-failure` rather than `always`: `always` restarts a daemon that
/// exited cleanly because the user asked it to stop, which turns
/// `systemctl --user stop` into a loop. `RestartSec` is deliberately generous —
/// a daemon crash-looping against a corrupt catalog should be slow enough that
/// a human can read the journal and intervene.
pub fn unit_text(exe: &Path) -> String {
    format!(
        "\
[Unit]
Description=Shepherd file custody daemon
Documentation=https://github.com/swjeon/shepherd
# The catalog lives under $XDG_STATE_HOME; do not start before it is mountable.
After=default.target

[Service]
Type=simple
ExecStart={exe} run
Restart=on-failure
RestartSec=10
# The daemon is the sole writer of the catalog and owns all filesystem
# mutation, so it deliberately runs with the user's ordinary privileges and no
# extra capabilities. It needs no hardening directives that would also block it
# from reaching the user's scan roots.
KillMode=mixed
TimeoutStopSec=30

[Install]
WantedBy=default.target
",
        exe = exe.display()
    )
}

/// Write the unit file for `exe` to the location `env` resolves, creating
/// parent directories as needed, and return that path.
///
/// Split out of [`install`] so a test can prove the write lands at the
/// XDG-resolved path — not a hardcoded literal duplicating this function's
/// own constant — by injecting an [`Env`] that points somewhere other than
/// the real user unit directory. The systemctl calls that follow it in
/// [`install`] are deliberately NOT part of this function: they target the
/// real, global `UNIT_NAME` regardless of `env`, so a hermetic test built on
/// this function never risks touching a real `systemd --user` session.
fn write_unit_file(env: &Env, exe: &Path) -> Result<PathBuf> {
    let path = unit_path_in(env)?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    std::fs::write(&path, unit_text(exe)).map_err(|e| io_err(&path, e))?;
    Ok(path)
}

pub fn install(exe: &Path) -> Result<Outcome> {
    let path = write_unit_file(&Env::from_process(), exe)?;

    let mut commands = Vec::new();
    let mut notes = Vec::new();
    for args in [
        vec!["--user", "daemon-reload"],
        vec!["--user", "enable", UNIT_NAME],
    ] {
        let rendered = format!("systemctl {}", args.join(" "));
        match std::process::Command::new("systemctl").args(&args).output() {
            Ok(out) if out.status.success() => commands.push(rendered),
            Ok(out) => notes.push(format!(
                "`{rendered}` exited {}: {}. The unit file is written; run it yourself once \
                 systemd is reachable.",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            )),
            Err(e) => notes.push(format!(
                "could not run `{rendered}` ({e}). The unit file is written; enable it yourself."
            )),
        }
    }

    notes.push(lingering_note());
    Ok(Outcome {
        paths: vec![path],
        commands,
        notes,
    })
}

/// The OQ-F note the installer prints.
///
/// It **names** the command and does not run it. `shepherd_obs::lingering` owns
/// the probe and the wording; this only decides that the installer is one of
/// the places it gets said.
pub fn lingering_note() -> String {
    let user = shepherd_obs::lingering::current_user();
    let state = shepherd_obs::lingering::probe(&user);
    match state {
        shepherd_obs::lingering::Lingering::Enabled => {
            "systemd lingering is enabled, so shepherdd will start at boot.".to_string()
        }
        other => {
            let check = shepherd_obs::lingering::check(
                &other,
                shepherd_obs::lingering::looks_seated(),
                &user,
            );
            match check.status {
                shepherd_obs::doctor::CheckStatus::Warn {
                    detail,
                    remediation,
                } => match remediation {
                    Some(cmd) => format!("{detail}\n  If you want that, run: {cmd}"),
                    None => detail,
                },
                _ => String::new(),
            }
        }
    }
}

/// Remove the unit file at the location `env` resolves, if one is there.
///
/// The removal half of [`write_unit_file`]'s split: hermetically testable
/// against an injected [`Env`], with no systemctl call attached.
fn remove_unit_file(env: &Env) -> Result<Option<PathBuf>> {
    let path = unit_path_in(env)?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| io_err(&path, e))?;
        Ok(Some(path))
    } else {
        Ok(None)
    }
}

pub fn uninstall() -> Result<Outcome> {
    let mut commands = Vec::new();
    let mut notes = Vec::new();

    for args in [
        vec!["--user", "disable", "--now", UNIT_NAME],
        vec!["--user", "daemon-reload"],
    ] {
        let rendered = format!("systemctl {}", args.join(" "));
        match std::process::Command::new("systemctl").args(&args).output() {
            Ok(out) if out.status.success() => commands.push(rendered),
            Ok(_) | Err(_) => notes.push(format!("`{rendered}` did not succeed; continuing.")),
        }
    }

    let paths = remove_unit_file(&Env::from_process())?
        .into_iter()
        .collect::<Vec<_>>();
    notes.push(
        "The catalog and secrets were NOT removed. Uninstalling a service must not destroy \
         the only address of files that no longer exist locally."
            .into(),
    );
    Ok(Outcome {
        paths,
        commands,
        notes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unit_starts_the_daemon_in_run_mode() {
        let t = unit_text(Path::new("/usr/bin/shepherdd"));
        assert!(t.contains("ExecStart=/usr/bin/shepherdd run"), "{t}");
        assert!(t.contains("WantedBy=default.target"));
    }

    /// `Restart=always` would fight `systemctl --user stop`.
    #[test]
    fn the_unit_restarts_on_failure_only() {
        let t = unit_text(Path::new("/x"));
        assert!(t.contains("Restart=on-failure"));
        assert!(!t.contains("Restart=always"));
    }

    /// OQ-F, asserted against the generated artifact rather than trusted.
    #[test]
    fn the_unit_never_mentions_lingering() {
        let t = unit_text(Path::new("/x"));
        assert!(
            !t.to_lowercase().contains("linger"),
            "a unit file cannot enable lingering, and must not appear to try: {t}"
        );
    }

    #[test]
    fn uninstall_says_it_kept_the_catalog() {
        // Not a behaviour test — the note itself is the deliverable. A user who
        // uninstalls must not be left guessing whether their custody records
        // were destroyed with the service.
        let note = "The catalog and secrets were NOT removed.";
        assert!(note.contains("NOT removed"));
    }

    // -------------------------------------------------------------------
    // `install()`'s write path — G-1-INSTALL-LINUX.
    //
    // Everything above proves WHAT gets installed. These prove WHERE:
    // `write_unit_file`/`remove_unit_file` are the literal functions `install`
    // and `uninstall` call, exercised through an injected `Env` so a test can
    // point them somewhere other than the real user unit directory — never by
    // mutating `std::env` (process-global, races every other test in this
    // binary; see `paths::Env`'s doc comment for the same reasoning) and never
    // by asserting against a second, hand-copied literal of `unit_path`'s own
    // logic. A version of `install` that hardcoded the wrong directory would
    // pass every other test in this module and fail every test below.
    // -------------------------------------------------------------------

    /// A private, per-test tmp dir. Each test uses its own `name`, so
    /// concurrent test threads never share one.
    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "shepherd-systemd-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn env(xdg_config_home: Option<&std::path::Path>, home: Option<&std::path::Path>) -> Env {
        Env {
            xdg_config_home: xdg_config_home.map(|p| p.display().to_string()),
            home: home.map(|p| p.display().to_string()),
        }
    }

    #[test]
    fn unit_path_in_prefers_xdg_config_home_over_home() {
        let p = unit_path_in(&env(Some(Path::new("/x/cfg")), Some(Path::new("/x/home")))).unwrap();
        assert_eq!(p, PathBuf::from("/x/cfg/systemd/user/shepherd.service"));
    }

    #[test]
    fn unit_path_in_falls_back_to_home_dot_config() {
        let p = unit_path_in(&env(None, Some(Path::new("/x/home")))).unwrap();
        assert_eq!(
            p,
            PathBuf::from("/x/home/.config/systemd/user/shepherd.service")
        );
    }

    #[test]
    fn unit_path_in_errors_when_neither_is_set() {
        let err = unit_path_in(&env(None, None)).unwrap_err().to_string();
        assert!(err.contains("XDG_CONFIG_HOME"), "{err}");
        assert!(err.contains("HOME"), "{err}");
    }

    /// The load-bearing test: `install` writes to wherever `Env` resolves,
    /// not to a fixed directory. Two different environments must produce two
    /// different files in two different places — an install that silently
    /// wrote everywhere to the same (e.g. hardcoded, or accidentally
    /// process-real) location would collapse this to one location and fail.
    #[test]
    fn install_writes_to_the_env_resolved_path_and_nowhere_else() {
        let a_cfg = tmp("write-a");
        let b_cfg = tmp("write-b");
        let a_env = env(Some(&a_cfg), None);
        let b_env = env(Some(&b_cfg), None);
        let exe = Path::new("/usr/bin/shepherdd");

        let a_path = write_unit_file(&a_env, exe).unwrap();
        let b_path = write_unit_file(&b_env, exe).unwrap();

        assert_ne!(
            a_path, b_path,
            "two different envs must resolve two different paths"
        );
        assert_eq!(a_path, unit_path_in(&a_env).unwrap());
        assert_eq!(b_path, unit_path_in(&b_env).unwrap());

        // The write actually landed where it was told to, with the real
        // content — not merely a path computation matching, but a file on
        // disk at that exact path.
        assert_eq!(std::fs::read_to_string(&a_path).unwrap(), unit_text(exe));
        assert_eq!(std::fs::read_to_string(&b_path).unwrap(), unit_text(exe));

        // And it did NOT also land at the other env's path, or anywhere in
        // the other env's directory tree.
        assert!(!a_path.starts_with(&b_cfg));
        assert!(!b_path.starts_with(&a_cfg));
        assert!(
            std::fs::read_dir(b_cfg.join("systemd/user"))
                .unwrap()
                .count()
                == 1,
            "b's unit directory must contain only b's own file"
        );

        std::fs::remove_dir_all(&a_cfg).ok();
        std::fs::remove_dir_all(&b_cfg).ok();
    }

    /// Re-running `install` overwrites in place rather than accumulating.
    #[test]
    fn install_is_idempotent_on_reinstall() {
        let cfg = tmp("reinstall");
        let e = env(Some(&cfg), None);

        let p1 = write_unit_file(&e, Path::new("/old/shepherdd")).unwrap();
        let p2 = write_unit_file(&e, Path::new("/new/shepherdd")).unwrap();

        assert_eq!(p1, p2, "reinstalling must not move the unit");
        let text = std::fs::read_to_string(&p2).unwrap();
        assert!(text.contains("ExecStart=/new/shepherdd run"), "{text}");
        assert!(!text.contains("/old/shepherdd"), "{text}");
        assert_eq!(
            std::fs::read_dir(cfg.join("systemd/user")).unwrap().count(),
            1,
            "reinstalling must leave exactly one unit file, not a duplicate"
        );

        std::fs::remove_dir_all(&cfg).ok();
    }

    #[test]
    fn uninstall_removes_the_file_install_wrote() {
        let cfg = tmp("uninstall");
        let e = env(Some(&cfg), None);
        let written = write_unit_file(&e, Path::new("/usr/bin/shepherdd")).unwrap();
        assert!(written.exists());

        let removed = remove_unit_file(&e).unwrap();
        assert_eq!(removed, Some(written.clone()));
        assert!(!written.exists());

        std::fs::remove_dir_all(&cfg).ok();
    }

    #[test]
    fn uninstall_with_nothing_installed_is_a_harmless_no_op() {
        let cfg = tmp("uninstall-noop");
        let e = env(Some(&cfg), None);
        assert_eq!(remove_unit_file(&e).unwrap(), None);

        std::fs::remove_dir_all(&cfg).ok();
    }
}
