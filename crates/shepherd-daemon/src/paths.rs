//! Where the daemon keeps its socket and its state.
//!
//! Every path is user-scoped, because §4.2 makes `shepherdd` a **per-user
//! agent**: Keychain items, OAuth tokens, `$HOME` scan roots, the macOS File
//! Provider domain and the Windows package identity are all user-scoped, so a
//! system-wide daemon could not reach any of them.
//!
//! Resolution is pure over an injected environment ([`Env`]) so the fallback
//! order is testable without setting process-global variables — which would
//! race every other test in the binary.

use std::path::PathBuf;

/// The environment inputs path resolution depends on.
#[derive(Debug, Clone, Default)]
pub struct Env {
    pub xdg_runtime_dir: Option<String>,
    pub xdg_state_home: Option<String>,
    pub home: Option<String>,
    /// Overrides everything, for tests and for running two daemons side by side.
    pub shepherd_state_dir: Option<String>,
    pub shepherd_socket: Option<String>,
}

impl Env {
    pub fn from_process() -> Self {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        Self {
            xdg_runtime_dir: var("XDG_RUNTIME_DIR"),
            xdg_state_home: var("XDG_STATE_HOME"),
            home: var("HOME"),
            shepherd_state_dir: var("SHEPHERD_STATE_DIR"),
            shepherd_socket: var("SHEPHERD_SOCKET"),
        }
    }
}

/// Resolved locations for one daemon instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Paths {
    pub state_dir: PathBuf,
    pub socket: PathBuf,
}

impl Paths {
    pub fn catalog(&self) -> PathBuf {
        self.state_dir.join("catalog.db")
    }

    pub fn secrets(&self) -> PathBuf {
        self.state_dir.join("secrets.json")
    }

    /// Resolve from an environment.
    ///
    /// State goes to `$XDG_STATE_HOME/shepherd`, else `$HOME/.local/state/shepherd`.
    /// The socket goes to `$XDG_RUNTIME_DIR/shepherd/daemon.sock` when there is
    /// a runtime dir — it is tmpfs, `0700`, and cleaned on logout, which is
    /// where a socket belongs — and falls back into the state directory when
    /// there is not. §4.3 specifies exactly that pair.
    pub fn resolve(env: &Env) -> Result<Paths, String> {
        let state_dir = match (&env.shepherd_state_dir, &env.xdg_state_home, &env.home) {
            (Some(explicit), _, _) => PathBuf::from(explicit),
            (None, Some(xdg), _) => PathBuf::from(xdg).join("shepherd"),
            (None, None, Some(home)) => PathBuf::from(home).join(".local/state/shepherd"),
            (None, None, None) => {
                return Err(
                    "cannot locate a state directory: none of SHEPHERD_STATE_DIR, \
                            XDG_STATE_HOME or HOME is set"
                        .into(),
                );
            }
        };

        let socket = match (&env.shepherd_socket, &env.xdg_runtime_dir) {
            (Some(explicit), _) => PathBuf::from(explicit),
            (None, Some(runtime)) => PathBuf::from(runtime).join("shepherd/daemon.sock"),
            (None, None) => state_dir.join("daemon.sock"),
        };

        Ok(Paths { state_dir, socket })
    }

    pub fn from_process() -> Result<Paths, String> {
        Self::resolve(&Env::from_process())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(runtime: Option<&str>, state: Option<&str>, home: Option<&str>) -> Env {
        Env {
            xdg_runtime_dir: runtime.map(String::from),
            xdg_state_home: state.map(String::from),
            home: home.map(String::from),
            ..Default::default()
        }
    }

    #[test]
    fn a_normal_linux_session_uses_the_runtime_dir_for_the_socket() {
        let p = Paths::resolve(&env(Some("/run/user/1000"), None, Some("/home/sam"))).unwrap();
        assert_eq!(
            p.socket,
            PathBuf::from("/run/user/1000/shepherd/daemon.sock")
        );
        assert_eq!(
            p.state_dir,
            PathBuf::from("/home/sam/.local/state/shepherd")
        );
        assert_eq!(
            p.catalog(),
            PathBuf::from("/home/sam/.local/state/shepherd/catalog.db")
        );
    }

    /// §4.3's fallback. A headless node or a `su` shell often has no
    /// `XDG_RUNTIME_DIR`, and that must not leave the daemon with nowhere to
    /// listen.
    #[test]
    fn no_runtime_dir_falls_back_into_the_state_directory() {
        let p = Paths::resolve(&env(None, None, Some("/home/sam"))).unwrap();
        assert_eq!(
            p.socket,
            PathBuf::from("/home/sam/.local/state/shepherd/daemon.sock")
        );
    }

    #[test]
    fn xdg_state_home_wins_over_the_home_default() {
        let p = Paths::resolve(&env(None, Some("/var/lib/x"), Some("/home/sam"))).unwrap();
        assert_eq!(p.state_dir, PathBuf::from("/var/lib/x/shepherd"));
    }

    #[test]
    fn explicit_overrides_win_over_everything() {
        let e = Env {
            shepherd_state_dir: Some("/tmp/s".into()),
            shepherd_socket: Some("/tmp/x.sock".into()),
            ..env(
                Some("/run/user/1000"),
                Some("/var/lib/x"),
                Some("/home/sam"),
            )
        };
        let p = Paths::resolve(&e).unwrap();
        assert_eq!(p.state_dir, PathBuf::from("/tmp/s"));
        assert_eq!(p.socket, PathBuf::from("/tmp/x.sock"));
    }

    #[test]
    fn an_environment_with_nothing_usable_is_an_error_not_a_guess() {
        // Defaulting to a relative path or /tmp would put the catalog — which
        // is the only address of destroyed originals — somewhere unpredictable.
        let err = Paths::resolve(&env(None, None, None)).unwrap_err();
        assert!(err.contains("HOME"), "{err}");
    }
}
