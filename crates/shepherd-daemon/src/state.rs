//! Process-wide daemon state, shared by every connection.

use std::sync::{Arc, RwLock};
use std::time::Instant;

use shepherd_catalog::writer::{CatalogActor, CatalogWriter};
use shepherd_index::{MetaIndex, MetaIndexBuilder};
use shepherd_proto::response::{CheckStatus, DoctorCheck};
use shepherd_proto::{Capability, ErrorCode, RpcError, capability};

use crate::events::EventHub;
use crate::paths::Paths;

/// Everything a connection needs that outlives it.
pub struct Daemon {
    pub writer: CatalogWriter,
    pub events: EventHub,
    pub paths: Paths,
    pub started_at: Instant,
    pub capabilities: Vec<Capability>,
    /// The §4.6 metadata name index.
    ///
    /// `Option`, not a default-empty index, and the distinction is the whole
    /// point: a daemon whose index failed to build must *refuse* a search, not
    /// answer it with zero hits. "No matches" and "the thing that finds matches
    /// is not there" look identical to a caller and only one of them is an
    /// answer — this project has already shipped that confusion once, in the
    /// tantivy tokenizer that scored beautifully while matching nothing.
    ///
    /// `RwLock<Option<Arc<_>>>` so a rebuild constructs the new arena off to the
    /// side and swaps it in under a momentary write lock. At 10M rows a rebuild
    /// is seconds; holding a lock across it would stall every concurrent search
    /// for that long, and in-place mutation would expose a half-built arena.
    index: RwLock<Option<Arc<MetaIndex>>>,
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
            index: RwLock::new(None),
            // Advertised because the event buffer and its resume cursor exist
            // (`shepherd_proto::event`). Placeholders and hosted inference are
            // NOT advertised: Linux is delete-mode only and Phase 7 has not
            // happened, and advertising a capability this build does not have
            // is worse than omitting one it does.
            capabilities: vec![Capability::new(capability::EVENT_RESUME)],
            _actor: actor,
        })
    }

    /// The metadata index, or the reason there is not one.
    ///
    /// Never synthesises an empty index on failure — see the field docs.
    pub fn index(&self) -> Result<Arc<MetaIndex>, RpcError> {
        let guard = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        guard.clone().ok_or_else(|| {
            RpcError::new(
                ErrorCode::Precondition,
                "the metadata index has not been built; the daemon could not read the \
                 catalog at start-up. Run `shepctl doctor`, then restart the daemon.",
            )
        })
    }

    /// Rebuild the index from the catalog and swap it in.
    ///
    /// **This is the cold-start cost §4.6 accepted for this candidate.** The
    /// arena has no persisted form, so it is paid at every daemon start, and the
    /// daemon starts at every logon. Phase 0b measured it at ~3.5 s for 10M rows.
    ///
    /// A dedicated read-only connection rather than the writer actor: at 10M
    /// rows this read runs for seconds, and routing it through the actor would
    /// block every write — including the scan whose completion triggered it —
    /// for the duration. SQLite's WAL mode is many-readers/one-writer precisely
    /// so this does not have to be serialised (ADR-001).
    pub fn rebuild_index(&self) -> Result<usize, String> {
        let db = self.paths.catalog();
        let conn = rusqlite::Connection::open_with_flags(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| format!("opening {} read-only: {e}", db.display()))?;

        // Reserving up front avoids doubling a several-hundred-megabyte arena,
        // which costs both rebuild time and — because the old and new
        // allocations coexist during a copy — transient RSS charged to AC-46.
        let expected: i64 = conn
            .query_row("SELECT COUNT(*) FROM file", [], |r| r.get(0))
            .map_err(|e| format!("counting catalog rows: {e}"))?;
        let mut builder = MetaIndexBuilder::with_capacity(expected.max(0) as usize);

        // `ORDER BY id` is load-bearing, not tidiness: `MetaIndex` returns hits
        // in push order, so pushing in id order is what makes a paged search
        // return a stable, non-overlapping sequence of pages.
        let mut stmt = conn
            .prepare("SELECT id, rel_path FROM file ORDER BY id")
            .map_err(|e| format!("preparing the index rebuild query: {e}"))?;
        let mut rows = stmt
            .query([])
            .map_err(|e| format!("reading catalog rows: {e}"))?;
        while let Some(row) = rows.next().map_err(|e| format!("reading a row: {e}"))? {
            let id: i64 = row.get(0).map_err(|e| format!("file.id: {e}"))?;
            let rel_path: String = row.get(1).map_err(|e| format!("file.rel_path: {e}"))?;
            builder
                .push(id, &rel_path)
                .map_err(|e| format!("building the metadata index: {e}"))?;
        }

        let built = builder
            .build()
            .map_err(|e| format!("sealing the metadata index: {e}"))?;
        let entries = built.len();
        // Counted, then compared: a rebuild that silently indexed fewer rows
        // than the catalog holds is a search that silently cannot find them.
        if entries as i64 != expected {
            return Err(format!(
                "the metadata index holds {entries} entries but the catalog reported \
                 {expected} rows; refusing to serve searches from a partial index"
            ));
        }
        tracing::info!(
            entries,
            resident_bytes = built.resident_bytes(),
            segments = built.segment_count(),
            "metadata index rebuilt"
        );
        let mut guard = self
            .index
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Some(Arc::new(built));
        Ok(entries)
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

        // Reported because an absent index is the one failure that would
        // otherwise be invisible: `search` would answer, and it would answer
        // nothing, and nothing is a valid-looking result.
        checks.push(match self.index() {
            Ok(index) => DoctorCheck {
                name: "metadata index".into(),
                status: CheckStatus::Ok,
                detail: Some(format!(
                    "{} entries, {:.1} MiB resident, {} scan segment(s)",
                    index.len(),
                    index.resident_bytes() as f64 / (1024.0 * 1024.0),
                    index.segment_count()
                )),
                remediation: None,
            },
            Err(e) => DoctorCheck {
                name: "metadata index".into(),
                status: CheckStatus::Fail,
                detail: Some(e.message),
                remediation: Some("restart the daemon".into()),
            },
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
