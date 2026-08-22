//! `shepherdd install` / `uninstall` against a real `systemd --user` session.
//!
//! G-1-INSTALL-LINUX: unit tests in `service::systemd` prove `install()`
//! writes to wherever its environment resolves (respecting `XDG_CONFIG_HOME`
//! / `HOME` overrides), hermetically, with no systemctl call attached. What
//! they deliberately do NOT prove is that `daemon-reload` and `enable`
//! actually take effect — and that half cannot be made hermetic: a running
//! `systemd --user` manager resolves unit search paths once, at its own
//! startup, from the login session's real environment. Overriding
//! `XDG_CONFIG_HOME` for the `systemctl` client process (confirmed
//! empirically while writing this test — `systemctl --user list-unit-files`
//! against a unit dropped in an overridden path returns zero units) has no
//! effect on what the already-running manager sees, because the enable/reload
//! operations happen server-side over D-Bus. There is no way to hermetically
//! prove `enable` short of starting a second, private `systemd --user`
//! instance, which is out of scope here.
//!
//! So this test does the only thing that actually proves `daemon-reload` and
//! `enable` work: it runs the real `shepherdd install`/`uninstall` binary
//! against THIS session's real `~/.config/systemd/user`, and checks the
//! result with a real `systemctl --user`. It is `#[ignore]`d — matching this
//! crate's existing pattern for tests that need something beyond a plain
//! `cargo test` (see the module comment on the M1 corpus test in `e2e.rs`) —
//! because a live user D-Bus session is not guaranteed everywhere `cargo
//! test` runs, and because it is intentionally invasive to the real session's
//! service state, if only for the seconds it takes to run. Run explicitly:
//!
//! ```text
//! cargo test -p shepherd-daemon --test install_e2e -- --ignored --nocapture
//! ```

#![cfg(target_os = "linux")]

use std::path::PathBuf;
use std::process::Command;

const UNIT_NAME: &str = "shepherd.service";

fn real_unit_path() -> PathBuf {
    let home = std::env::var("HOME").expect("HOME must be set to run this test");
    let base = std::env::var("XDG_CONFIG_HOME")
        .ok()
        .filter(|v| !v.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(home).join(".config"));
    base.join("systemd/user").join(UNIT_NAME)
}

fn wants_symlink_path() -> PathBuf {
    real_unit_path()
        .parent()
        .unwrap()
        .join("default.target.wants")
        .join(UNIT_NAME)
}

fn is_enabled() -> String {
    let out = Command::new("systemctl")
        .args(["--user", "is-enabled", UNIT_NAME])
        .output()
        .expect("run systemctl --user is-enabled");
    String::from_utf8_lossy(&out.stdout).trim().to_string()
}

/// Unconditionally restores the real session to "shepherd.service not
/// installed", even if an assertion above panics mid-test.
struct CleanupGuard;
impl Drop for CleanupGuard {
    fn drop(&mut self) {
        let _ = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
            .arg("uninstall")
            .output();
        // Belt and suspenders: `uninstall` itself is under test here, so a
        // bug in IT must not leave the real session polluted either.
        let _ = std::fs::remove_file(real_unit_path());
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "disable", "--now", UNIT_NAME])
            .output();
        let _ = std::process::Command::new("systemctl")
            .args(["--user", "daemon-reload"])
            .output();
    }
}

#[test]
#[ignore = "invasive: writes to and enables a unit in the real user systemd session; \
            needs a live `systemd --user` D-Bus session. Run explicitly with \
            `-- --ignored`."]
fn install_and_uninstall_take_effect_in_the_real_session() {
    // Which world are we in? Reported either way, per the task brief.
    let status = Command::new("systemctl")
        .args(["--user", "status"])
        .output();
    match &status {
        Ok(out) if out.status.success() || out.status.code() == Some(0) => {
            eprintln!("systemctl --user status: reachable, proceeding for real");
        }
        Ok(out) => {
            eprintln!(
                "systemctl --user status exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            );
            eprintln!("no live user D-Bus session — skipping rather than faking success");
            return;
        }
        Err(e) => {
            eprintln!("could not run systemctl at all ({e}) — skipping rather than faking success");
            return;
        }
    }

    let unit_path = real_unit_path();
    if unit_path.exists() || is_enabled() != "not-found" {
        eprintln!(
            "a real {} already exists (state: {}) — refusing to touch a possibly-real \
             install; skipping",
            unit_path.display(),
            is_enabled()
        );
        return;
    }

    let _guard = CleanupGuard;

    // --- install ---------------------------------------------------------
    let out = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
        .arg("install")
        .output()
        .expect("run shepherdd install");
    let stdout = String::from_utf8_lossy(&out.stdout);
    assert!(
        out.status.success(),
        "install failed: {stdout}\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        stdout.contains(&format!("installed: {}", unit_path.display())),
        "{stdout}"
    );
    assert!(
        stdout.contains("ran: systemctl --user daemon-reload"),
        "{stdout}"
    );
    assert!(
        stdout.contains(&format!("ran: systemctl --user enable {UNIT_NAME}")),
        "{stdout}"
    );

    assert!(
        unit_path.exists(),
        "unit file was not written to {}",
        unit_path.display()
    );
    let text = std::fs::read_to_string(&unit_path).unwrap();
    assert!(text.contains("ExecStart="), "{text}");
    assert!(
        text.trim_end().ends_with("run") || text.contains(" run\n"),
        "{text}"
    );

    // The part no unit test can fake: the REAL systemd user manager now
    // reports this unit as enabled, and the [Install] symlink it creates on
    // enable actually exists.
    assert_eq!(
        is_enabled(),
        "enabled",
        "real systemctl did not report the unit enabled"
    );
    assert!(
        wants_symlink_path().exists(),
        "systemctl --user enable did not create {}",
        wants_symlink_path().display()
    );

    // --- idempotence on reinstall -----------------------------------------
    let out2 = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
        .arg("install")
        .output()
        .expect("run shepherdd install again");
    assert!(
        out2.status.success(),
        "{}",
        String::from_utf8_lossy(&out2.stderr)
    );
    assert_eq!(is_enabled(), "enabled");
    assert!(
        std::fs::read_dir(unit_path.parent().unwrap().join("default.target.wants"))
            .unwrap()
            .filter(|e| e.as_ref().unwrap().file_name() == UNIT_NAME)
            .count()
            <= 1,
        "reinstalling must not duplicate the enable symlink"
    );

    // --- uninstall ----------------------------------------------------------
    let out3 = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
        .arg("uninstall")
        .output()
        .expect("run shepherdd uninstall");
    let stdout3 = String::from_utf8_lossy(&out3.stdout);
    assert!(out3.status.success(), "uninstall failed: {stdout3}");
    assert!(
        stdout3.contains(&format!("removed: {}", unit_path.display())),
        "{stdout3}"
    );

    assert!(!unit_path.exists(), "uninstall left the unit file behind");
    assert_eq!(
        is_enabled(),
        "not-found",
        "real systemctl still sees the unit after uninstall"
    );
    assert!(
        !wants_symlink_path().exists(),
        "uninstall left the enable symlink behind"
    );
}
