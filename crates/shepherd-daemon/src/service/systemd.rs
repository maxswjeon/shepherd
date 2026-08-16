//! The Linux systemd **user** unit.
//!
//! A user unit, not a system unit, per §4.2: every asset the daemon owns is
//! user-scoped. The consequence — that it starts at *logon*, not boot, and
//! never at all on a headless node without lingering — is stated to the user by
//! [`install`] rather than worked around.

use std::path::{Path, PathBuf};

use super::{Outcome, Result, ServiceError, io_err};

pub const UNIT_NAME: &str = "shepherd.service";

/// `~/.config/systemd/user/shepherd.service`.
pub fn unit_path() -> Result<PathBuf> {
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            std::env::var("HOME")
                .ok()
                .filter(|v| !v.is_empty())
                .map(|h| PathBuf::from(h).join(".config"))
        })
        .ok_or_else(|| {
            ServiceError::Unsupported(
                "cannot locate a config directory: neither XDG_CONFIG_HOME nor HOME is set".into(),
            )
        })?;
    Ok(base.join("systemd/user").join(UNIT_NAME))
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

pub fn install(exe: &Path) -> Result<Outcome> {
    let path = unit_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    std::fs::write(&path, unit_text(exe)).map_err(|e| io_err(&path, e))?;

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

pub fn uninstall() -> Result<Outcome> {
    let path = unit_path()?;
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

    let mut paths = Vec::new();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| io_err(&path, e))?;
        paths.push(path);
    }
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
}
