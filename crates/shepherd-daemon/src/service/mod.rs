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
}
