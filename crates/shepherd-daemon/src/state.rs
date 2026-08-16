//! Process-wide daemon state, shared by every connection.

use std::sync::Arc;
use std::time::Instant;

use shepherd_jobs::worker::{CatalogActor, CatalogWriter};
use shepherd_proto::response::{CheckStatus, DoctorCheck};
use shepherd_proto::{Capability, RpcError, capability};

use crate::events::EventHub;
use crate::paths::Paths;

/// Everything a connection needs that outlives it.
pub struct Daemon {
    pub writer: CatalogWriter,
    pub events: EventHub,
    pub paths: Paths,
    pub started_at: Instant,
    pub capabilities: Vec<Capability>,
    /// Held so the actor and its WAL-checkpoint thread live as long as the
    /// daemon. Never used directly — `writer` is the handle.
    _actor: CatalogActor,
}

impl Daemon {
    pub fn new(actor: CatalogActor, events: EventHub, paths: Paths) -> Arc<Self> {
        let writer = actor.handle();
        Arc::new(Self {
            writer,
            events,
            paths,
            started_at: Instant::now(),
            // Advertised because the event buffer and its resume cursor exist
            // (`shepherd_proto::event`). Placeholders and hosted inference are
            // NOT advertised: Linux is delete-mode only and Phase 7 has not
            // happened, and advertising a capability this build does not have
            // is worse than omitting one it does.
            capabilities: vec![Capability::new(capability::EVENT_RESUME)],
            _actor: actor,
        })
    }

    /// The self-checks behind the `doctor` method.
    ///
    /// The lingering check comes from `shepherd_obs::lingering`, shared with
    /// startup and with `shepctl doctor`'s offline path, so the OQ-F wording
    /// exists once.
    pub fn run_checks(&self) -> Result<Vec<DoctorCheck>, RpcError> {
        let mut checks = Vec::new();

        let user = shepherd_obs::lingering::current_user();
        let state = shepherd_obs::lingering::probe(&user);
        checks.push(convert(shepherd_obs::lingering::check(
            &state,
            shepherd_obs::lingering::looks_seated(),
            &user,
        )));

        // Catalog reachability: the writer actor answering at all is the check.
        let reachable = self.writer.try_with(|cat| {
            cat.conn()
                .query_row("SELECT COUNT(*) FROM scan_root", [], |r| r.get::<_, i64>(0))
                .map_err(shepherd_catalog::CatalogError::from)
        });
        checks.push(DoctorCheck {
            name: "catalog".into(),
            status: match &reachable {
                Ok(_) => CheckStatus::Ok,
                Err(_) => CheckStatus::Fail,
            },
            detail: match &reachable {
                Ok(n) => Some(format!(
                    "{} at schema version {}, {n} root(s)",
                    self.paths.catalog().display(),
                    shepherd_catalog::SCHEMA_VERSION
                )),
                Err(e) => Some(e.to_string()),
            },
            remediation: None,
        });

        checks.push(DoctorCheck {
            name: "ipc socket".into(),
            status: CheckStatus::Ok,
            detail: Some(self.paths.socket.display().to_string()),
            remediation: None,
        });

        Ok(checks)
    }
}

/// `shepherd_obs::doctor::Check` -> the wire type.
///
/// A conversion rather than a shared type because `shepherd-proto` may not
/// depend on `shepherd-obs` any more than on anything else internal (§4.1
/// rule 1), and because the wire shape should be free to differ from the
/// in-process one.
pub fn convert(c: shepherd_obs::doctor::Check) -> DoctorCheck {
    use shepherd_obs::doctor::CheckStatus as S;
    let (status, detail, remediation) = match c.status {
        S::Ok => (CheckStatus::Ok, None, None),
        S::Warn {
            detail,
            remediation,
        } => (CheckStatus::Warn, Some(detail), remediation),
        S::Fail { detail } => (CheckStatus::Fail, Some(detail), None),
        S::NotApplicable { reason } => (CheckStatus::NotApplicable, Some(reason), None),
    };
    DoctorCheck {
        name: c.name,
        status,
        detail,
        remediation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_warning_converts_with_its_remediation_intact() {
        let c = shepherd_obs::doctor::Check::new(
            "systemd lingering",
            shepherd_obs::doctor::CheckStatus::warn("off", "loginctl enable-linger sam"),
        );
        let w = convert(c);
        assert_eq!(w.status, CheckStatus::Warn);
        assert_eq!(w.remediation.as_deref(), Some("loginctl enable-linger sam"));
        assert_eq!(w.detail.as_deref(), Some("off"));
    }

    #[test]
    fn every_obs_status_has_a_wire_counterpart() {
        use shepherd_obs::doctor::CheckStatus as S;
        for (s, want) in [
            (S::Ok, CheckStatus::Ok),
            (S::fail("x"), CheckStatus::Fail),
            (
                S::NotApplicable { reason: "x".into() },
                CheckStatus::NotApplicable,
            ),
        ] {
            assert_eq!(
                convert(shepherd_obs::doctor::Check::new("n", s)).status,
                want
            );
        }
    }
}
