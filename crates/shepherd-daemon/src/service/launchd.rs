//! The macOS LaunchAgent.
//!
//! Per-user (`~/Library/LaunchAgents`), not a system LaunchDaemon, for the same
//! §4.2 reason as the Linux user unit: Keychain items, the File Provider domain
//! and `$HOME` scan roots are all user-scoped.

use std::path::{Path, PathBuf};

use super::{Outcome, Result, ServiceError, io_err};

pub const LABEL: &str = "kr.swjeon.shepherd";

pub fn plist_path() -> Result<PathBuf> {
    let home = std::env::var("HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .ok_or_else(|| ServiceError::Unsupported("HOME is not set".into()))?;
    Ok(PathBuf::from(home).join(format!("Library/LaunchAgents/{LABEL}.plist")))
}

/// The plist text. Pure, so it is testable without writing anything.
///
/// `RunAtLoad` starts it at logon. There is deliberately no `KeepAlive`:
/// combined with `RunAtLoad` it restarts a daemon the user just stopped, which
/// is the launchd equivalent of systemd's `Restart=always` problem.
pub fn plist_text(exe: &Path) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{LABEL}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{exe}</string>
        <string>run</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>ProcessType</key>
    <string>Background</string>
</dict>
</plist>
"#,
        exe = exe.display()
    )
}

pub fn install(exe: &Path) -> Result<Outcome> {
    let path = plist_path()?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| io_err(parent, e))?;
    }
    std::fs::write(&path, plist_text(exe)).map_err(|e| io_err(&path, e))?;

    let mut commands = Vec::new();
    let mut notes = Vec::new();
    let target = format!("gui/{}", uid());
    let args = vec!["bootstrap".to_string(), target, path.display().to_string()];
    let rendered = format!("launchctl {}", args.join(" "));
    match std::process::Command::new("launchctl").args(&args).output() {
        Ok(out) if out.status.success() => commands.push(rendered),
        Ok(out) => notes.push(format!(
            "`{rendered}` exited {}: {}. The plist is written; load it yourself.",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => notes.push(format!(
            "could not run `{rendered}` ({e}); the plist is written."
        )),
    }
    notes.push(
        "macOS starts a LaunchAgent at logon, not at boot. §4.2 records that as the honest \
         equivalent for a per-user agent: hydration, Keychain access and the File Provider \
         domain are all meaningless outside a logged-in session."
            .into(),
    );
    Ok(Outcome {
        paths: vec![path],
        commands,
        notes,
    })
}

pub fn uninstall() -> Result<Outcome> {
    let path = plist_path()?;
    let mut commands = Vec::new();
    let args = vec!["bootout".to_string(), format!("gui/{}/{LABEL}", uid())];
    let rendered = format!("launchctl {}", args.join(" "));
    if let Ok(out) = std::process::Command::new("launchctl").args(&args).output()
        && out.status.success()
    {
        commands.push(rendered);
    }
    let mut paths = Vec::new();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| io_err(&path, e))?;
        paths.push(path);
    }
    Ok(Outcome {
        paths,
        commands,
        notes: vec![
            "The catalog and secrets were NOT removed. Uninstalling a service must not \
             destroy the only address of files that no longer exist locally."
                .into(),
        ],
    })
}

fn uid() -> String {
    std::env::var("UID").unwrap_or_else(|_| "$(id -u)".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_plist_is_well_formed_and_starts_the_daemon_in_run_mode() {
        let t = plist_text(Path::new("/opt/shepherd/shepherdd"));
        assert!(t.starts_with("<?xml"));
        assert!(t.contains("<string>/opt/shepherd/shepherdd</string>"));
        assert!(t.contains("<string>run</string>"));
        assert!(t.contains(&format!("<string>{LABEL}</string>")));
        assert_eq!(
            t.matches("<dict>").count(),
            t.matches("</dict>").count(),
            "unbalanced dict tags"
        );
        assert_eq!(t.matches("<array>").count(), t.matches("</array>").count());
    }

    /// `KeepAlive` plus `RunAtLoad` restarts a daemon the user just stopped.
    #[test]
    fn the_plist_does_not_fight_the_user() {
        let t = plist_text(Path::new("/x"));
        assert!(t.contains("<key>RunAtLoad</key>"));
        assert!(!t.contains("KeepAlive"));
    }
}
