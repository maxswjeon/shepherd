//! `shepctl doctor` check harness.
//!
//! The status enum is the load-bearing part. OQ-F requires Shepherd to detect
//! that systemd lingering is disabled on a headless Linux node, **warn with the
//! exact remediation command, and never enable it** — "on a headless Linux node
//! with lingering disabled, not starting is correct behaviour accompanied by a
//! warning, not a defect" (§4.2).
//!
//! So [`CheckStatus::Warn`] carries a `remediation` the user may run, and
//! [`Doctor::is_clean`] treats warnings as clean. If warnings failed the doctor,
//! the pressure to make `doctor` green would be pressure to enable lingering on
//! the user's behalf — the one thing OQ-F explicitly declines to do.

/// The outcome of one check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckStatus {
    Ok,
    /// A condition the user may want to change, with the exact command that
    /// would change it. Shepherd states the consequence; it does not act.
    Warn {
        detail: String,
        remediation: Option<String>,
    },
    /// Something is actually broken.
    Fail {
        detail: String,
    },
    /// The check does not apply here (a Windows check on Linux, a placeholder
    /// check on a delete-mode root).
    NotApplicable {
        reason: String,
    },
}

impl CheckStatus {
    pub fn warn(detail: impl Into<String>, remediation: impl Into<String>) -> Self {
        CheckStatus::Warn {
            detail: detail.into(),
            remediation: Some(remediation.into()),
        }
    }

    pub fn fail(detail: impl Into<String>) -> Self {
        CheckStatus::Fail {
            detail: detail.into(),
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            CheckStatus::Ok => "ok",
            CheckStatus::Warn { .. } => "warn",
            CheckStatus::Fail { .. } => "fail",
            CheckStatus::NotApplicable { .. } => "n/a",
        }
    }
}

/// One named check and its result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub name: String,
    pub status: CheckStatus,
}

impl Check {
    pub fn new(name: impl Into<String>, status: CheckStatus) -> Self {
        Self {
            name: name.into(),
            status,
        }
    }
}

/// A collected run of checks.
#[derive(Debug, Default, Clone)]
pub struct Doctor {
    pub checks: Vec<Check>,
}

impl Doctor {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, check: Check) -> &mut Self {
        self.checks.push(check);
        self
    }

    /// `true` when no check failed. Warnings do **not** make the doctor dirty —
    /// see the module docs.
    pub fn is_clean(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|c| matches!(c.status, CheckStatus::Fail { .. }))
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Check> {
        self.checks
            .iter()
            .filter(|c| matches!(c.status, CheckStatus::Warn { .. }))
    }

    pub fn failures(&self) -> impl Iterator<Item = &Check> {
        self.checks
            .iter()
            .filter(|c| matches!(c.status, CheckStatus::Fail { .. }))
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        for c in &self.checks {
            s.push_str(&format!("[{:>4}] {}\n", c.status.label(), c.name));
            match &c.status {
                CheckStatus::Warn {
                    detail,
                    remediation,
                } => {
                    s.push_str(&format!("       {detail}\n"));
                    if let Some(r) = remediation {
                        s.push_str(&format!("       to change this, run: {r}\n"));
                    }
                }
                CheckStatus::Fail { detail } => s.push_str(&format!("       {detail}\n")),
                CheckStatus::NotApplicable { reason } => s.push_str(&format!("       {reason}\n")),
                CheckStatus::Ok => {}
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OQ-F shape, asserted directly: a lingering-disabled node warns, names
    /// the command, and is still a clean doctor.
    #[test]
    fn a_lingering_warning_is_clean_and_names_the_command() {
        let mut d = Doctor::new();
        d.push(Check::new(
            "systemd user lingering",
            CheckStatus::warn(
                "lingering is disabled, so shepherdd will not start while you are logged out",
                "loginctl enable-linger $USER",
            ),
        ));
        assert!(d.is_clean(), "a warning must not fail the doctor (OQ-F)");
        assert_eq!(d.warnings().count(), 1);
        assert!(d.render().contains("loginctl enable-linger"));
    }

    #[test]
    fn a_failure_is_not_clean() {
        let mut d = Doctor::new();
        d.push(Check::new(
            "catalog writable",
            CheckStatus::fail("permission denied"),
        ));
        assert!(!d.is_clean());
        assert_eq!(d.failures().count(), 1);
    }

    #[test]
    fn not_applicable_is_clean() {
        let mut d = Doctor::new();
        d.push(Check::new(
            "windows sync root",
            CheckStatus::NotApplicable {
                reason: "not Windows".into(),
            },
        ));
        assert!(d.is_clean());
        assert_eq!(d.warnings().count(), 0);
    }
}
