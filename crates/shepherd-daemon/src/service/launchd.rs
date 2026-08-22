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
        exe = xml_escape(&exe.display().to_string())
    )
}

/// XML-escape a value going into a plist `<string>`.
///
/// A path is not a safe literal: an installation under a directory containing
/// `&` or `<` produced a plist that does not parse, `launchctl bootstrap` then
/// failed, and `install` recorded that failure as a NOTE while still returning
/// success — so the user was left with an agent that looks installed and never
/// starts. Escaping is the fix; the note-not-failure half is a separate
/// judgement the install path already makes deliberately for the bootstrap
/// step, since the plist itself is written.
///
/// All five predefined entities, not only the three that break `<string>`:
/// the cost is nil and a partial escaper is the kind that gets copied.
fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
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
    let mut notes = Vec::new();
    let args = vec!["bootout".to_string(), format!("gui/{}/{LABEL}", uid())];
    let rendered = format!("launchctl {}", args.join(" "));
    // A failed `bootout` is REPORTED, on both arms — the install path five
    // functions up already does this for `bootstrap`, and only the uninstall
    // arm dropped it. Deleting the plist stops the agent starting at the next
    // logon; it does nothing to an agent that is loaded and running right now.
    // Silently succeeding there told the user the service was gone while it
    // went on running and mutating the catalog until they logged out.
    //
    // Not fatal: the plist still has to go, or the next logon starts the
    // daemon again and the uninstall achieved nothing at all. So the removal
    // proceeds and the note carries the part that did not.
    match std::process::Command::new("launchctl").args(&args).output() {
        Ok(out) if out.status.success() => commands.push(rendered),
        Ok(out) => notes.push(format!(
            "`{rendered}` failed ({}): {}. The plist is removed, so the agent will not \
             start again — but if it is running now it keeps running until you log out. \
             Run that command yourself to stop it immediately.",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        Err(e) => notes.push(format!(
            "could not run `{rendered}` ({e}). The plist is removed, so the agent will not \
             start again — but if it is running now it keeps running until you log out."
        )),
    }
    let mut paths = Vec::new();
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| io_err(&path, e))?;
        paths.push(path);
    }
    notes.push(
        "The catalog and secrets were NOT removed. Uninstalling a service must not \
         destroy the only address of files that no longer exist locally."
            .into(),
    );
    Ok(Outcome {
        paths,
        commands,
        notes,
    })
}

/// The real uid, for the `gui/<uid>` domain target `bootstrap` and `bootout`
/// both take.
///
/// This read `std::env::var("UID")` and fell back to the literal string
/// `"$(id -u)"`. `Command::new` never invokes a shell, so nothing expanded it —
/// and `UID` is a shell *parameter*, not an exported environment variable
/// (`env | grep -c '^UID='` is `0` on a normal login), so the fallback was the
/// live path rather than the rare one. Measured on macOS 26.5.2: `launchctl`
/// received `gui/$(id -u)`, answered `Unrecognized target specifier` and exited
/// 64, the agent never loaded — and `shepherdd install` still exited 0, because
/// a failed bootstrap is recorded as a note. Exporting `UID=501` and changing
/// nothing else made the identical binary load the agent.
///
/// The exit-0-on-bootstrap-failure behaviour is left alone deliberately: on a
/// headless Mac there is no GUI session and that bootstrap *should* fail
/// without failing the install. It was not the defect; this was.
fn uid() -> String {
    #[cfg(unix)]
    {
        // SAFETY: `getuid` is always successful per POSIX — it cannot fail, has
        // no error return, and touches no memory we own.
        unsafe { libc::getuid() }.to_string()
    }
    #[cfg(not(unix))]
    {
        // `service::launchd` compiles everywhere; only macOS dispatches to it.
        String::new()
    }
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

    /// An XML metacharacter in the path must not produce a plist that will not
    /// parse.
    ///
    /// `launchctl bootstrap` then fails — and `install` records that as a NOTE
    /// while still returning success, so the user is left with an agent that
    /// looks installed and never starts. The malformed file is the cause, so
    /// the file is where this is fixed.
    #[test]
    fn an_executable_path_with_xml_metacharacters_is_escaped() {
        let t = plist_text(Path::new("/opt/A & B/<shepherdd>"));
        assert!(
            t.contains("<string>/opt/A &amp; B/&lt;shepherdd&gt;</string>"),
            "{t}"
        );
        assert!(
            !t.contains("/opt/A & B/<shepherdd>"),
            "the raw path must not survive into the document: {t}"
        );
        // Still one `<string>` per argument, so the escaping did not disturb
        // the element structure.
        assert!(t.contains("<string>run</string>"));
    }

    /// `KeepAlive` plus `RunAtLoad` restarts a daemon the user just stopped.
    #[test]
    fn the_plist_does_not_fight_the_user() {
        let t = plist_text(Path::new("/x"));
        assert!(t.contains("<key>RunAtLoad</key>"));
        assert!(!t.contains("KeepAlive"));
    }

    /// `uid()` fed `gui/$(id -u)` to `launchctl` for as long as this file has
    /// existed, and nothing caught it because the only assertions here were
    /// about the plist's *text*. A well-formed plist that launchd never loads
    /// passes every other test in this module.
    ///
    /// Checked against `id -u` rather than against `libc::getuid()`, which is
    /// what the implementation already calls — comparing a function to itself
    /// would pass just as happily on the broken version.
    #[test]
    #[cfg(unix)]
    fn the_domain_target_is_a_real_uid_and_never_a_shell_substitution() {
        let u = uid();

        assert!(
            !u.contains('$'),
            "a shell substitution reached the launchctl domain target: {u:?}. \
             Command::new invokes no shell, so launchctl receives this \
             literally and answers `Unrecognized target specifier` (exit 64)"
        );
        assert!(
            !u.is_empty() && u.chars().all(|c| c.is_ascii_digit()),
            "launchctl's domain target is gui/<uid>; uid() produced {u:?}"
        );

        // Independent source: `id -u` is a different mechanism from getuid(),
        // so this compares two answers rather than one answer to itself.
        let out = std::process::Command::new("id")
            .arg("-u")
            .output()
            .expect("`id -u` is POSIX and must exist wherever this test runs");
        let from_id = String::from_utf8(out.stdout).expect("`id -u` prints ASCII");
        assert_eq!(
            u,
            from_id.trim(),
            "uid() disagrees with `id -u` — the shell substitution this \
             function used to emit was literally spelling out that command"
        );
    }
}
