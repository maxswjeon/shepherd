//! systemd user-lingering detection (OQ-F).
//!
//! # The one rule
//!
//! **Nothing in this module ever enables lingering.** Not at install, not at
//! startup, not from `doctor`, not from a test. OQ-F is a recorded user
//! decision: running in the background while logged out is the user's choice,
//! and Shepherd's obligation is to *state the consequence plainly* rather than
//! silently doing nothing on a headless box — or silently changing a system
//! setting on their behalf. [`enable_command`] returns the command as **text,
//! for a human to run**; there is deliberately no function in this crate that
//! executes it.
//!
//! An earlier plan revision had the installer force lingering on, and shipped
//! an E2E row asserting that behaviour — so a correctly-implemented daemon
//! would have failed its own test. That row was replaced; this module is the
//! implementation side of the replacement.
//!
//! # Why it lives in `shepherd-obs` and not in the daemon
//!
//! Three callers need the same answer:
//!
//! 1. `shepherdd` at startup, which warns and carries on;
//! 2. the `doctor` IPC method, answered by the running daemon;
//! 3. `shepctl doctor` **when the daemon is not running** — which is precisely
//!    the headless-with-lingering-disabled case, where there is no daemon to
//!    ask, and is the case the §9 gate row exercises on a seatless VM.
//!
//! Three implementations of a rule about not touching a system setting is three
//! chances to get it wrong, so there is one.
//!
//! # Purity
//!
//! [`parse`] is a pure function over the text `loginctl` prints. [`probe`] is
//! the only thing that runs a subprocess, and every test drives [`parse`] with
//! injected output. A test that shelled out to `loginctl` would pass or fail
//! based on the machine it ran on, which is the opposite of what a test of this
//! rule is for.

use crate::doctor::{Check, CheckStatus};

/// What the platform reports about lingering for the current user.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Lingering {
    /// The user manager runs while nobody is logged in. A user unit starts at
    /// boot.
    Enabled,
    /// The user manager runs only during a login session. On a headless node
    /// where nobody logs in, the daemon does not start — **which is correct
    /// behaviour**, not a defect (§4.2).
    Disabled,
    /// Not a systemd platform, so the question does not arise.
    NotApplicable,
    /// systemd is present but the answer could not be obtained.
    Unknown(String),
}

/// The command a **user** may run. Shepherd never runs it.
///
/// Takes the account name rather than reading it, so the string is testable and
/// so the caller decides what identity to name.
pub fn enable_command(user: &str) -> String {
    format!("loginctl enable-linger {user}")
}

/// The command that reports the current state, named in diagnostics so an
/// operator can confirm what Shepherd saw.
pub fn query_command(user: &str) -> String {
    format!("loginctl show-user {user} --property=Linger")
}

/// Parse `loginctl show-user --property=Linger` output.
///
/// Accepts the `Linger=yes` / `Linger=no` line anywhere in the output and
/// ignores everything else, because `--property` is not the only way a caller
/// might have produced this and a future systemd may add lines.
pub fn parse(output: &str) -> Lingering {
    for line in output.lines() {
        let line = line.trim();
        let Some(value) = line.strip_prefix("Linger=") else {
            continue;
        };
        return match value.trim().to_ascii_lowercase().as_str() {
            "yes" | "true" | "1" => Lingering::Enabled,
            "no" | "false" | "0" => Lingering::Disabled,
            other => Lingering::Unknown(format!("unrecognised Linger value `{other}`")),
        };
    }
    Lingering::Unknown(format!(
        "no `Linger=` line in loginctl output ({} byte(s))",
        output.len()
    ))
}

/// Ask the platform. The only impure function here.
///
/// Non-Linux targets return [`Lingering::NotApplicable`] without running
/// anything: launchd and the Windows startup task have no equivalent setting,
/// and §4.2 assigns lingering specifically to the Linux systemd user unit.
#[cfg(target_os = "linux")]
pub fn probe(user: &str) -> Lingering {
    match std::process::Command::new("loginctl")
        .args(["show-user", user, "--property=Linger"])
        .output()
    {
        Ok(out) if out.status.success() => parse(&String::from_utf8_lossy(&out.stdout)),
        Ok(out) => Lingering::Unknown(format!(
            "`{}` exited {}: {}",
            query_command(user),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )),
        // Not an error worth failing on: a container without systemd, or a
        // distro that does not ship loginctl, is a legitimate deployment.
        Err(e) => Lingering::Unknown(format!("could not run loginctl: {e}")),
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe(_user: &str) -> Lingering {
    Lingering::NotApplicable
}

/// The current account name, for the probe and the remediation text.
pub fn current_user() -> String {
    std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| String::from("$USER"))
}

/// Render the doctor check.
///
/// `has_seat` is whether this looks like an interactive session. It changes the
/// *wording*, never the verdict: on a desktop, lingering-off means "the daemon
/// stops when you log out"; on a headless node it means "the daemon never
/// starts at all", which is a materially different thing for the operator to
/// read, and the second one is the case the §9 gate exercises on a seatless VM.
///
/// The status is [`CheckStatus::Warn`] and never `Fail`. `Doctor::is_clean`
/// treats warnings as clean specifically so that nothing in this codebase ever
/// acquires a reason to make `doctor` green by enabling lingering.
pub fn check(state: &Lingering, has_seat: bool, user: &str) -> Check {
    let status = match state {
        Lingering::Enabled => CheckStatus::Ok,
        Lingering::NotApplicable => CheckStatus::NotApplicable {
            reason: "lingering is a systemd concept; this platform starts the daemon another way"
                .into(),
        },
        Lingering::Unknown(why) => CheckStatus::Warn {
            detail: format!(
                "could not determine whether systemd lingering is enabled: {why}. \
                 If this is a headless node, the daemon will not start unless lingering is on."
            ),
            remediation: Some(query_command(user)),
        },
        Lingering::Disabled if has_seat => CheckStatus::warn(
            "systemd lingering is disabled, so shepherdd stops when you log out and \
             starts again when you log back in. On a desktop that is usually what you want. \
             Shepherd will not change this setting for you.",
            enable_command(user),
        ),
        Lingering::Disabled => CheckStatus::warn(
            "systemd lingering is disabled and this looks like a headless session, so the \
             user manager does not run when nobody is logged in and shepherdd will NOT start \
             at boot. This is expected behaviour, not a fault. Shepherd will not change this \
             setting for you — running while logged out is your decision.",
            enable_command(user),
        ),
    };
    Check::new("systemd lingering", status)
}

/// Whether this process looks like it has an interactive seat.
///
/// A heuristic, and labelled as one: it only selects between two wordings of
/// the same warning, so being wrong costs a slightly-off sentence rather than a
/// wrong verdict. Nothing branches on it except message text.
pub fn looks_seated() -> bool {
    ["DISPLAY", "WAYLAND_DISPLAY", "XDG_SESSION_ID"]
        .iter()
        .any(|k| std::env::var_os(k).is_some_and(|v| !v.is_empty()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_both_answers() {
        assert_eq!(parse("Linger=yes\n"), Lingering::Enabled);
        assert_eq!(parse("Linger=no\n"), Lingering::Disabled);
        assert_eq!(parse("  Linger=yes  "), Lingering::Enabled);
        // Tolerate other spellings and extra properties.
        assert_eq!(parse("Linger=true"), Lingering::Enabled);
        assert_eq!(
            parse("UID=1000\nGID=1000\nLinger=no\nState=active\n"),
            Lingering::Disabled
        );
    }

    #[test]
    fn unparseable_output_is_unknown_not_assumed_enabled() {
        // Assuming "enabled" would silence the warning on exactly the machine
        // that needs it. Assuming "disabled" would warn on machines that are
        // fine. Neither is honest, so it is its own state.
        assert!(matches!(parse(""), Lingering::Unknown(_)));
        assert!(matches!(
            parse("Failed to get user: no such user"),
            Lingering::Unknown(_)
        ));
        assert!(matches!(parse("Linger=maybe"), Lingering::Unknown(_)));
    }

    #[test]
    fn the_remediation_names_the_command_but_nothing_runs_it() {
        // OQ-F, asserted as text. The grep in the second half is the real test:
        // this module must contain no execution of enable-linger anywhere.
        assert_eq!(enable_command("sam"), "loginctl enable-linger sam");
        let source = include_str!("lingering.rs");
        for line in source.lines() {
            let is_command_construction = line.contains("Command::new") || line.contains(".args(");
            assert!(
                !(is_command_construction && line.contains("enable-linger")),
                "this module must never execute enable-linger: {line}"
            );
        }
        // The only subprocess this module builds is the read-only query.
        assert!(source.contains("\"show-user\""));
    }

    #[test]
    fn a_headless_disabled_node_warns_and_says_it_is_expected() {
        let c = check(&Lingering::Disabled, false, "sam");
        let CheckStatus::Warn {
            detail,
            remediation,
        } = &c.status
        else {
            panic!("must warn, got {:?}", c.status);
        };
        assert!(detail.contains("will NOT start"), "{detail}");
        assert!(
            detail.contains("expected behaviour"),
            "the operator must be told this is not a fault: {detail}"
        );
        assert!(
            detail.contains("will not change this setting"),
            "OQ-F requires saying so out loud: {detail}"
        );
        assert_eq!(remediation.as_deref(), Some("loginctl enable-linger sam"));
    }

    #[test]
    fn a_seated_disabled_node_warns_differently() {
        let c = check(&Lingering::Disabled, true, "sam");
        let CheckStatus::Warn { detail, .. } = &c.status else {
            panic!("must warn");
        };
        assert!(detail.contains("log out"), "{detail}");
        assert!(
            !detail.contains("will NOT start"),
            "a desktop does start; that wording is the headless case: {detail}"
        );
    }

    #[test]
    fn enabled_is_ok_and_a_non_systemd_platform_is_not_applicable() {
        assert_eq!(
            check(&Lingering::Enabled, false, "sam").status,
            CheckStatus::Ok
        );
        assert!(matches!(
            check(&Lingering::NotApplicable, true, "sam").status,
            CheckStatus::NotApplicable { .. }
        ));
    }

    #[test]
    fn an_unknown_state_still_warns_with_the_query_command() {
        let c = check(&Lingering::Unknown("no loginctl".into()), false, "sam");
        let CheckStatus::Warn { remediation, .. } = &c.status else {
            panic!("must warn");
        };
        assert_eq!(
            remediation.as_deref(),
            Some("loginctl show-user sam --property=Linger"),
            "an unknown state should tell the operator how to look, not how to change"
        );
    }

    /// Warnings must not fail the doctor. If they did, the pressure to get a
    /// green `doctor` would become pressure to enable lingering for the user —
    /// the exact thing OQ-F declines.
    #[test]
    fn a_lingering_warning_leaves_the_doctor_clean() {
        let mut d = crate::doctor::Doctor::new();
        d.push(check(&Lingering::Disabled, false, "sam"));
        assert!(d.is_clean());
        assert_eq!(d.warnings().count(), 1);
        assert_eq!(d.failures().count(), 0);
    }

    #[test]
    fn probe_never_panics_whatever_the_platform() {
        // Runs the real subprocess (or returns NotApplicable off Linux). It
        // asserts nothing about the answer — that depends on the machine — only
        // that probing is safe to call. The behaviour is tested through `parse`.
        let _ = probe(&current_user());
        let _ = looks_seated();
    }
}
