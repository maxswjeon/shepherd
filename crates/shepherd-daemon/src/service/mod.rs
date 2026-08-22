//! Service installation: systemd user unit, launchd LaunchAgent.
//!
//! # `shepherdd install`, not `shepctl install`
//!
//! Installing a service is an *installer* action, not a product capability, and
//! it is deliberately not in the method table. Two reasons, and the second is
//! the load-bearing one:
//!
//! 1. It is not something a running daemon can do for itself — the daemon that
//!    would serve the method is the thing being installed.
//! 2. Adding it to the table would add a `shepctl install` command, and AC-54's
//!    `CLI == registered_methods` check would then require the UI to be able to
//!    install a service too. The check has no exemption list, on purpose.
//!
//! So the installer surface lives on the `shepherdd` binary's own argv, where
//! it touches neither the registry nor the AC-54 bijection.
//!
//! # Never lingering (OQ-F)
//!
//! The Linux installer writes a **user** unit and enables it. It does not run
//! `loginctl enable-linger` and never will — see `shepherd_obs::lingering`. On
//! a headless node with lingering off, the consequence is that the daemon does
//! not start, which §4.2 calls correct behaviour accompanied by a warning. The
//! installer prints that warning; it does not act on it.
//!
//! # Windows
//!
//! §4.2 puts the Windows startup task **inside the MSIX package**, so that it
//! inherits the package identity that sync-root registration depends on. That
//! is Phase 3 packaging work and cannot be done by writing a file from here;
//! §9's Phase 1 gate says as much ("Windows startup task defers to Phase 3 with
//! package identity"). [`install`] therefore returns a named error on Windows
//! rather than doing something that half works.

use std::path::{Path, PathBuf};

pub mod launchd;
pub mod systemd;

/// What an install/uninstall did, so the caller can print it and a test can
/// assert on it without reading the filesystem.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Files written or removed.
    pub paths: Vec<PathBuf>,
    /// Commands that were run, in order. Empty when nothing was run.
    pub commands: Vec<String>,
    /// Lines to show the user, including any OQ-F lingering warning.
    pub notes: Vec<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceError {
    #[error("{0}")]
    Unsupported(String),
    #[error("service file {path}: {detail}")]
    Io { path: String, detail: String },
}

pub type Result<T> = std::result::Result<T, ServiceError>;

pub(crate) fn io_err(path: &Path, e: std::io::Error) -> ServiceError {
    ServiceError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    }
}

/// The platform's service manager, or an explanation of why there is not one.
pub fn install(exe: &Path) -> Result<Outcome> {
    #[cfg(target_os = "linux")]
    {
        systemd::install(exe)
    }
    #[cfg(target_os = "macos")]
    {
        launchd::install(exe)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = exe;
        Err(ServiceError::Unsupported(WINDOWS_NOTE.into()))
    }
}

pub fn uninstall() -> Result<Outcome> {
    #[cfg(target_os = "linux")]
    {
        systemd::uninstall()
    }
    #[cfg(target_os = "macos")]
    {
        launchd::uninstall()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(ServiceError::Unsupported(WINDOWS_NOTE.into()))
    }
}

/// Where this platform's service unit would live, and whether it exists.
///
/// This is a filesystem check, not a query to systemd/launchd — it answers
/// "has `install` ever been run" (AC-61's "registration state"), not "is the
/// unit currently enabled or running". Claiming more than the file check
/// supports would be a confident wrong answer, which is worse than the honest
/// gap `shepherd-cli::client::not_running_message` already declines to close.
pub fn registration() -> (String, bool) {
    let path = if cfg!(target_os = "macos") {
        launchd::plist_path()
    } else {
        systemd::unit_path()
    };
    match path {
        Ok(p) => (p.display().to_string(), p.exists()),
        Err(e) => (format!("(could not determine: {e})"), false),
    }
}

/// The command that starts the daemon, given whether it is registered as a
/// service.
///
/// A registered-but-stopped service is started through the service manager —
/// `shepherdd run` in the foreground would fight `Restart=on-failure` /
/// `RunAtLoad` the next time the service manager tries to start it. An
/// unregistered daemon has no service to start, so the foreground command is
/// the honest answer.
pub fn start_command(registered: bool) -> &'static str {
    if !registered {
        "shepherdd run"
    } else if cfg!(target_os = "macos") {
        "launchctl kickstart -k gui/$UID/kr.swjeon.shepherd"
    } else {
        "systemctl --user start shepherd"
    }
}

/// Stated once, used by both arms and by the tests.
pub const WINDOWS_NOTE: &str = "\
`shepherdd install` is not available on Windows. §4.2 puts the Windows startup \
task inside the MSIX package so it inherits the package identity that sync-root \
registration depends on, which means it is created by the installer at package \
install time and not by this binary. It is a Phase 3 deliverable; the §9 Phase 1 \
gate defers it explicitly. Run `shepherdd run` in the foreground meanwhile.";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_windows_path_explains_itself_rather_than_failing_blankly() {
        assert!(WINDOWS_NOTE.contains("MSIX"));
        assert!(WINDOWS_NOTE.contains("Phase 3"));
        assert!(
            WINDOWS_NOTE.contains("shepherdd run"),
            "an unsupported install must still tell the user what they CAN do"
        );
    }

    /// An unregistered daemon has no service to start through, regardless of
    /// platform — AC-61's remediation must be something that actually exists.
    #[test]
    fn start_command_is_the_foreground_run_when_unregistered() {
        assert_eq!(start_command(false), "shepherdd run");
    }

    /// A registered-but-stopped daemon must be started through the service
    /// manager, not `shepherdd run` in the foreground — see [`start_command`]'s
    /// doc comment for why running it by hand would fight the manager's own
    /// restart policy.
    #[test]
    fn start_command_is_never_the_foreground_run_when_registered() {
        assert_ne!(start_command(true), "shepherdd run");
    }
}
