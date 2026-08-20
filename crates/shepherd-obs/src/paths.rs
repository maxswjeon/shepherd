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
//!
//! # Why this lives in `shepherd-obs` and not in `shepherd-daemon`
//!
//! Because the client needs the same answer. `shepctl` has to find the socket
//! the daemon chose, and while this module sat in `shepherd-daemon` the client
//! could not reach it: `shepherd-cli` deliberately does not depend on
//! `shepherd-daemon` (that edge would drag `rusqlite` and a bundled SQLite into
//! a CLI that needs neither, and would make `shepctl` unbuildable anywhere the
//! daemon is not). So the client grew a second, shorter list of candidate paths
//! — and the two disagreed. A daemon configured through `SHEPHERD_STATE_DIR` or
//! `XDG_STATE_HOME` listened perfectly while every unqualified `shepctl`
//! reported it unreachable.
//!
//! This is the same shape, and the same remedy, as [`crate::lingering`]: one
//! fact that the daemon, the `doctor` method and the offline CLI all need, kept
//! in the one crate all three already depend on, so there is one implementation
//! rather than three that drift.
//!
//! [`Paths::resolve`] is what the daemon binds; [`socket_candidates`] is the
//! same chain flattened into the list a client tries. They are checked against
//! each other over the whole environment matrix in this module's tests, and by
//! construction the first candidate *is* `resolve`'s socket. An explicit
//! `SHEPHERD_SOCKET` is the one case with no fallbacks at all — see
//! [`socket_candidates`] for why falling through would be worse than failing.

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

/// Every socket path a client should try, best first.
///
/// # Why a list at all, when the daemon binds exactly one
///
/// Because the client's environment is not guaranteed to be the daemon's. A
/// daemon started by systemd has `XDG_RUNTIME_DIR`; an `ssh` shell, a cron job
/// or a `su` often does not, and a user who exported `SHEPHERD_STATE_DIR` in
/// one shell has not exported it in the next. Collapsing this to the single
/// path [`Paths::resolve`] returns would trade one wrong answer for another.
///
/// So the first entry **is** `resolve(env).socket` — that is the agreement the
/// finding was about, and it is a property this module's tests assert over the
/// whole environment matrix rather than a convention two files try to maintain
/// separately. The rest are the same chain's other rungs, kept as fallbacks for
/// the skew above. Duplicates are removed so an error message does not list one
/// path twice.
///
/// # Except when the socket is named outright, where the list is one long
///
/// `SHEPHERD_SOCKET` exists so two daemons can run side by side, and naming one
/// is precisely a statement that the other must not be reached. Falling through
/// to the ordinary rungs when it is momentarily unavailable — the daemon
/// restarting, the path not yet bound — sends the command to whichever *other*
/// instance is listening, against a different catalog. An error the user can
/// act on is strictly better than silent success somewhere else, and on a
/// destructive command the difference is unrecoverable.
///
/// This also fixes the sharper half: the override used to be contributed by the
/// `resolve` arm, so an environment naming a socket and no state directory
/// (`env -i SHEPHERD_SOCKET=... shepctl`) yielded an **empty** list — the user
/// named the socket and was told nothing had been tried.
///
/// Empty only when the environment names nowhere at all, which is the same
/// condition [`Paths::resolve`] refuses outright.
pub fn socket_candidates(env: &Env) -> Vec<PathBuf> {
    // Checked before anything else, and returned alone. Not merely first:
    // the defect was entirely in what followed it.
    if let Some(explicit) = &env.shepherd_socket {
        return vec![PathBuf::from(explicit)];
    }

    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };

    // The daemon's own answer, first, whatever it is.
    if let Ok(resolved) = Paths::resolve(env) {
        push(resolved.socket);
    }

    if let Some(runtime) = &env.xdg_runtime_dir {
        push(PathBuf::from(runtime).join("shepherd/daemon.sock"));
    }
    // The state directory's socket, for a daemon that had no runtime dir.
    // Both spellings of "where state lives", because either may be the one the
    // daemon was started with.
    if let Some(explicit) = &env.shepherd_state_dir {
        push(PathBuf::from(explicit).join("daemon.sock"));
    }
    if let Some(xdg) = &env.xdg_state_home {
        push(PathBuf::from(xdg).join("shepherd/daemon.sock"));
    }
    if let Some(home) = &env.home {
        push(PathBuf::from(home).join(".local/state/shepherd/daemon.sock"));
    }
    out
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

    /// Every environment the two functions can be handed at once.
    ///
    /// 2^5 combinations of the five inputs, so no arm of either function is
    /// reachable without this matrix visiting it.
    fn every_env() -> Vec<Env> {
        let opt = |on: bool, v: &str| if on { Some(v.to_string()) } else { None };
        let mut out = Vec::new();
        for bits in 0u8..32 {
            out.push(Env {
                xdg_runtime_dir: opt(bits & 1 != 0, "/run/user/1000"),
                xdg_state_home: opt(bits & 2 != 0, "/var/lib/x"),
                home: opt(bits & 4 != 0, "/home/sam"),
                shepherd_state_dir: opt(bits & 8 != 0, "/tmp/s"),
                shepherd_socket: opt(bits & 16 != 0, "/tmp/x.sock"),
            });
        }
        out
    }

    /// The client's first guess is the daemon's actual answer. Always.
    ///
    /// This is the whole of the finding, stated as an invariant rather than as
    /// a convention. The client used to carry its own two-entry list, which knew
    /// about `XDG_RUNTIME_DIR` and `HOME` and nothing else; a daemon configured
    /// through `SHEPHERD_STATE_DIR` or `XDG_STATE_HOME` therefore listened on a
    /// path the client never tried.
    ///
    /// Asserting it over all 32 environments is what makes it a check on the
    /// *relationship* rather than on either function: neither can be changed in
    /// isolation without this failing, which is precisely the drift that could
    /// not be detected while the two lived in crates that cannot see each other.
    #[test]
    fn the_first_candidate_is_always_the_socket_the_daemon_binds() {
        let mut checked = 0;
        for env in every_env() {
            // An environment `resolve` refuses is one in which *this process*
            // could not be the daemon. It is emphatically not one in which the
            // client has nothing to try: a daemon started by systemd with `HOME`
            // set listens under `XDG_RUNTIME_DIR`, and a stripped client shell
            // that has only `XDG_RUNTIME_DIR` must still find it. That case is
            // asserted on its own below.
            let Ok(resolved) = Paths::resolve(&env) else {
                continue;
            };
            let candidates = socket_candidates(&env);
            assert_eq!(
                candidates.first(),
                Some(&resolved.socket),
                "a client would try {:?} first while the daemon listens on {} — env {env:?}",
                candidates.first(),
                resolved.socket.display()
            );
            checked += 1;
        }
        // Guards the loop against passing because `resolve` refused everything.
        assert_eq!(
            checked, 28,
            "the matrix must actually exercise the agreement, not skip it"
        );
    }

    /// A client whose environment is poorer than the daemon's still finds it.
    ///
    /// `resolve` refuses this environment — nothing here names a state
    /// directory, so no daemon could have *started* from it. But a daemon that
    /// started from a richer environment is listening under `XDG_RUNTIME_DIR`
    /// all the same, and this is the ordinary `ssh` or `env -i` shell. Returning
    /// an empty list here would replace one unreachable-daemon report with
    /// another.
    #[test]
    fn a_client_with_only_a_runtime_dir_still_has_somewhere_to_look() {
        let env = Env {
            xdg_runtime_dir: Some("/run/user/1000".into()),
            ..Default::default()
        };
        assert!(Paths::resolve(&env).is_err(), "no state directory is named");
        assert_eq!(
            socket_candidates(&env),
            vec![PathBuf::from("/run/user/1000/shepherd/daemon.sock")],
            "the runtime socket is where a systemd-started daemon listens"
        );
    }

    /// And an environment that names nowhere at all yields nothing, rather than
    /// a guess at a relative or `/tmp` path.
    #[test]
    fn an_empty_environment_yields_no_candidates() {
        assert!(socket_candidates(&Env::default()).is_empty());
    }

    /// The fallbacks survive, and the list never repeats itself.
    ///
    /// The invariant above is satisfied by a `socket_candidates` that returns
    /// exactly one path, which would be a regression: the client's environment
    /// is not guaranteed to be the daemon's, and dropping the other rungs would
    /// break the ordinary systemd-daemon-plus-ssh-shell case that the original
    /// two-entry list did get right.
    #[test]
    fn the_client_still_tries_the_other_rungs_and_lists_none_twice() {
        let env = Env {
            xdg_runtime_dir: Some("/run/user/1000".into()),
            xdg_state_home: Some("/var/lib/x".into()),
            home: Some("/home/sam".into()),
            shepherd_state_dir: Some("/tmp/s".into()),
            shepherd_socket: None,
        };
        let c = socket_candidates(&env);
        for want in [
            "/run/user/1000/shepherd/daemon.sock",
            "/tmp/s/daemon.sock",
            "/var/lib/x/shepherd/daemon.sock",
            "/home/sam/.local/state/shepherd/daemon.sock",
        ] {
            assert!(
                c.contains(&PathBuf::from(want)),
                "{want} is a place a daemon can legitimately be listening; got {c:?}"
            );
        }

        for env in every_env() {
            let c = socket_candidates(&env);
            let mut seen = c.clone();
            seen.sort();
            seen.dedup();
            assert_eq!(seen.len(), c.len(), "a path is listed twice for {env:?}");
        }
    }

    /// An explicit `SHEPHERD_SOCKET` is the ONLY candidate.
    ///
    /// The override exists so two daemons can run side by side, and the whole
    /// point of naming one is that the other must not be reached. While this
    /// function appended the ordinary rungs after it, a client whose named
    /// socket was momentarily unavailable — the daemon restarting, the file not
    /// yet bound — fell through to whatever *other* instance was listening
    /// under `XDG_RUNTIME_DIR`, and ran the command against that daemon's
    /// catalog instead. Failing to reach the socket you asked for is an error a
    /// user can act on; silently acting on a different catalog is not, and on a
    /// destructive command it is unrecoverable.
    ///
    /// Asserted as equality, not as `first()`: the bug was entirely in what
    /// came *after* the first entry, so an assertion on the head of the list
    /// would have passed throughout.
    #[test]
    fn an_explicit_socket_override_is_the_only_candidate() {
        let e = Env {
            shepherd_socket: Some("/tmp/x.sock".into()),
            ..env(
                Some("/run/user/1000"),
                Some("/var/lib/x"),
                Some("/home/sam"),
            )
        };
        assert_eq!(
            socket_candidates(&e),
            vec![PathBuf::from("/tmp/x.sock")],
            "an override that falls through reaches a different daemon's catalog"
        );
    }

    /// And it survives an environment `Paths::resolve` refuses.
    ///
    /// This is the sharper half. The override was pushed by the `resolve` arm,
    /// so an environment naming a socket and no state directory — `env -i
    /// SHEPHERD_SOCKET=... shepctl` — produced an **empty** candidate list: the
    /// user named the socket and was told nothing had been tried.
    #[test]
    fn an_explicit_socket_is_a_candidate_even_when_nothing_else_is_named() {
        let e = Env {
            shepherd_socket: Some("/tmp/x.sock".into()),
            ..Default::default()
        };
        assert!(
            Paths::resolve(&e).is_err(),
            "no state directory is named, so this process could not be the daemon"
        );
        assert_eq!(
            socket_candidates(&e),
            vec![PathBuf::from("/tmp/x.sock")],
            "the user named a socket; the client must at least try it"
        );
    }

    /// The accepting direction, so "return one candidate always" cannot pass.
    ///
    /// Collapsing the list to a single entry would satisfy both tests above and
    /// re-break the skew case `socket_candidates` was added for. With **no**
    /// override set, every rung is still tried.
    #[test]
    fn without_an_override_the_other_rungs_are_still_tried() {
        let e = env(
            Some("/run/user/1000"),
            Some("/var/lib/x"),
            Some("/home/sam"),
        );
        assert!(
            socket_candidates(&e).len() > 1,
            "no override is set, so the fallbacks must survive; got {:?}",
            socket_candidates(&e)
        );
    }

    /// The case the finding names, on its own, so a failure reads as the bug.
    #[test]
    fn a_state_dir_daemon_with_no_runtime_dir_is_findable() {
        let env = Env {
            shepherd_state_dir: Some("/tmp/s".into()),
            home: Some("/home/sam".into()),
            ..Default::default()
        };
        assert_eq!(
            socket_candidates(&env).first(),
            Some(&PathBuf::from("/tmp/s/daemon.sock")),
            "this is exactly the configuration in which the daemon runs normally and every \
             unqualified `shepctl` reported it unreachable"
        );
    }

    #[test]
    fn an_environment_with_nothing_usable_is_an_error_not_a_guess() {
        // Defaulting to a relative path or /tmp would put the catalog — which
        // is the only address of destroyed originals — somewhere unpredictable.
        let err = Paths::resolve(&env(None, None, None)).unwrap_err();
        assert!(err.contains("HOME"), "{err}");
    }
}
