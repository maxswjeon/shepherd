//! The `ShepherdApi` implementation — the daemon's whole product surface.
//!
//! # Why there is no `match` on method names here
//!
//! `ShepherdApi` is generated from `shepherd-proto`'s method table with one fn
//! per method and no default bodies, and `dispatch()` is generated too. So this
//! file cannot omit a method (it would not compile) and cannot route one to the
//! wrong handler (it does not do the routing). Adding a row to the table breaks
//! this file until someone decides what it does — which is the point.
//!
//! # What Phase 1 actually serves
//!
//! | served here | answered `MethodNotImplemented` |
//! |---|---|
//! | `root.add`, `root.list`, `root.remove` | `search` (the index is T7) |
//! | `scan.start`, `scan.status` | `target.*` (storage is T9, Phase 2) |
//! | `status`, `doctor` | `rule.*` (the engine is Phase 2) |
//! | `events.subscribe` | `tier.*`, `restore` (Phase 2) |
//!
//! The unimplemented ones return [`ErrorCode::MethodNotImplemented`] rather
//! than a stopgap. A catalog `LIKE` query dressed up as `search` would be a
//! second implementation to keep in step with T7's index and would make the
//! Phase 1 gate look passed when it is not. The distinct error code, and
//! `shepctl`'s exit status 4, are what make "not built yet" legible to a script.

use std::sync::Arc;

use shepherd_catalog::file_repo::FileRepo;
use shepherd_catalog::job_repo::JobClass;
use shepherd_catalog::writer::CatalogWriter;
use shepherd_catalog::{Catalog, CatalogError};
use shepherd_core::{RootId, Timestamp};
use shepherd_jobs::Queue;
use shepherd_proto::request::*;
use shepherd_proto::response::*;
use shepherd_proto::{ErrorCode, Negotiated, RpcError, ShepherdApi};

use crate::events::EventHub;
use crate::state::Daemon;

/// One connection's view of the daemon.
///
/// Carries the negotiated protocol terms, because `status` reports them and
/// because a method above the negotiated minor must not be served.
pub struct Session {
    pub daemon: Arc<Daemon>,
    pub negotiated: Negotiated,
}

impl Session {
    fn writer(&self) -> &CatalogWriter {
        &self.daemon.writer
    }

    fn hub(&self) -> &EventHub {
        &self.daemon.events
    }

    fn now(&self) -> Timestamp {
        shepherd_jobs::worker::now()
    }

    /// Run a catalog closure, mapping storage failures onto the wire taxonomy.
    fn cat<T, F>(&self, f: F) -> Result<T, RpcError>
    where
        F: FnOnce(&mut Catalog) -> Result<T, CatalogError> + Send + 'static,
        T: Send + 'static,
    {
        self.writer().try_with(f).map_err(map_worker_error)
    }
}

fn map_worker_error(e: shepherd_catalog::writer::WriterError) -> RpcError {
    use shepherd_catalog::writer::WriterError;
    match e {
        WriterError::Gone => RpcError::new(
            ErrorCode::InternalError,
            "the catalog writer has stopped; the daemon is shutting down or has faulted",
        ),
        WriterError::Catalog(c) => map_catalog_error(c),
    }
}

/// Catalog failures onto the transport taxonomy.
///
/// `Invariant` maps to `Unprovable`, not `InternalError`: §4.4's third-party
/// custody invariant failing means the catalog is asserting something about
/// custody that cannot be true, and `Unprovable` is the code that is never
/// retryable.
fn map_catalog_error(e: CatalogError) -> RpcError {
    match e {
        CatalogError::Invariant(m) => RpcError::new(ErrorCode::Unprovable, m),
        CatalogError::Invalid(m) => RpcError::new(ErrorCode::Invalid, m),
        CatalogError::SchemaVersion { found, expected } => RpcError::new(
            ErrorCode::Precondition,
            format!(
                "catalog is at schema version {found}, this build expects {expected}. \
                 Run the matching daemon build, or restore the catalog from the replica."
            ),
        ),
        CatalogError::Sqlite(e) => RpcError::new(ErrorCode::Io, e.to_string()),
    }
}

/// The standard answer for a registered-but-unserved method.
fn not_implemented(method: &str, owner: &str) -> RpcError {
    RpcError::new(
        ErrorCode::MethodNotImplemented,
        format!("`{method}` is registered in the protocol but not served by this build ({owner})"),
    )
}

impl ShepherdApi for Session {
    // --- roots ------------------------------------------------------------

    fn root_add(&mut self, req: RootAddRequest) -> Result<RootAddResult, RpcError> {
        let path = std::path::PathBuf::from(&req.path);
        if !path.is_absolute() {
            return Err(RpcError::new(
                ErrorCode::Invalid,
                format!("`{}` is not an absolute path", req.path),
            ));
        }
        if !path.is_dir() {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                format!("`{}` is not a directory that exists", req.path),
            ));
        }

        // Probed, never assumed — §4.9 exists because retrofitting identity
        // after Phase 2 destroys files is the scenario it prevents.
        let policies = shepherd_catalog::identity::probe_path_policies(&path);
        let atime_mode = shepherd_catalog::atime::detect(&path);
        let volume = shepherd_catalog::volume::volume_id(&path).ok();

        let mut warnings = Vec::new();
        if !atime_mode.supports_destructive_age_rule() {
            warnings.push(format!(
                "this root's atime is `{}`, so a rule matching on last access cannot be \
                 trusted to gate destruction here (§4.12)",
                atime_mode.as_str()
            ));
        }
        if volume.is_none() {
            warnings.push(
                "could not determine a stable volume id for this root; catalog rows may not \
                 survive a remount (§4.9 PM-3)"
                    .into(),
            );
        }

        let stub = match req.stub_mode {
            StubMode::Dehydrate => shepherd_core::StubMode::Dehydrate,
            StubMode::Delete => shepherd_core::StubMode::Delete,
        };
        if cfg!(target_os = "linux") && stub == shepherd_core::StubMode::Dehydrate {
            return Err(RpcError::new(
                ErrorCode::Refused,
                "Linux is delete-mode only (§3): OS placeholders need Windows CfAPI or the \
                 macOS File Provider, neither of which exists here",
            ));
        }

        let path_string = req.path.clone();
        let now = self.now();
        let root_id = self.cat(move |cat| {
            FileRepo::new(cat).insert_root(
                &path_string,
                stub,
                policies.case,
                policies.norm,
                atime_mode,
                volume.as_deref(),
                now,
            )
        })?;

        let root = self.load_root(root_id)?;
        Ok(RootAddResult { root, warnings })
    }

    fn root_list(&mut self, req: RootListRequest) -> Result<RootListResult, RpcError> {
        let include_disabled = req.include_disabled;
        let rows = self.cat(move |cat| list_roots(cat, include_disabled))?;
        Ok(RootListResult { roots: rows })
    }

    fn root_remove(&mut self, req: RootRemoveRequest) -> Result<RootRemoveResult, RpcError> {
        let id = RootId::new(req.root_id);
        let exists = self.cat(move |cat| FileRepo::new(cat).get_root(id))?;
        if exists.is_none() {
            return Err(RpcError::new(
                ErrorCode::NotFound,
                format!("no scan root with id {}", req.root_id),
            ));
        }

        // Custody rows are the only address of bytes that no longer exist
        // locally. Counting them before dropping anything is what makes the
        // refusal possible.
        let custody = self.cat(move |cat| count_custody_rows(cat, id))?;
        if req.forget_catalog && custody > 0 && !req.force {
            return Err(RpcError::new(
                ErrorCode::Refused,
                format!(
                    "{custody} file(s) under this root are tiered and hold custody records — \
                     the catalog is their only address. Dropping those rows loses the files. \
                     Restore them first, or pass --force if you accept that."
                ),
            ));
        }

        let forget = req.forget_catalog;
        let dropped = self.cat(move |cat| remove_root(cat, id, forget))?;
        Ok(RootRemoveResult {
            root_id: req.root_id,
            catalog_rows_dropped: dropped,
            custody_rows_dropped: if forget { custody } else { 0 },
        })
    }

    // --- scan -------------------------------------------------------------

    fn scan_start(&mut self, req: ScanStartRequest) -> Result<ScanStartResult, RpcError> {
        let roots = match req.root_id {
            Some(id) => {
                let rid = RootId::new(id);
                let found = self.cat(move |cat| FileRepo::new(cat).get_root(rid))?;
                match found {
                    Some(_) => vec![id],
                    None => {
                        return Err(RpcError::new(
                            ErrorCode::NotFound,
                            format!("no scan root with id {id}"),
                        ));
                    }
                }
            }
            None => self
                .cat(move |cat| list_roots(cat, false))?
                .into_iter()
                .map(|r| r.root_id)
                .collect(),
        };

        let mut job_ids = Vec::new();
        let mut started = Vec::new();
        let mut skipped = Vec::new();
        for root_id in roots {
            let payload = serde_json::json!({ "root_id": root_id, "full": req.full }).to_string();
            let now = self.now();
            match self.cat(move |cat| Queue::enqueue(cat, JobClass::Scan, 10, &payload, now)) {
                Ok(id) => {
                    job_ids.push(id.get());
                    started.push(root_id);
                }
                Err(e) => skipped.push(SkippedRoot {
                    root_id,
                    reason: e.message,
                }),
            }
        }
        Ok(ScanStartResult {
            job_ids,
            roots_started: started,
            skipped,
        })
    }

    fn scan_status(&mut self, req: ScanStatusRequest) -> Result<ScanStatusResult, RpcError> {
        let filter = req.root_id;
        let scans = self.cat(move |cat| scan_states(cat, filter))?;
        Ok(ScanStatusResult { scans })
    }

    // --- status and doctor ------------------------------------------------

    fn status(&mut self, _: StatusRequest) -> Result<StatusResult, RpcError> {
        let totals = self.cat(catalog_totals)?;
        let depth = self.cat(|cat| Queue::depth(cat))?;
        Ok(StatusResult {
            build: env!("CARGO_PKG_VERSION").to_string(),
            proto_version: shepherd_proto::PROTO_VERSION,
            negotiated_minor: self.negotiated.minor,
            capabilities: self.daemon.capabilities.clone(),
            uptime_secs: self.daemon.started_at.elapsed().as_secs(),
            roots: totals.roots,
            files_catalogued: totals.files,
            bytes_catalogued: totals.bytes,
            jobs_pending: depth
                .into_iter()
                .map(|d| JobClassDepth {
                    class: d.class,
                    pending: d.pending,
                    running: d.running,
                    failed: d.failed,
                })
                .collect(),
            // Nothing is tiered before Phase 2, so this is exactly zero rather
            // than unimplemented. AC-49 needs the field present from the start
            // so the Dashboard's contract does not change when tiering lands.
            bytes_pending_discard: 0,
        })
    }

    fn doctor(&mut self, _: DoctorRequest) -> Result<DoctorResult, RpcError> {
        let checks = self.daemon.run_checks()?;
        Ok(DoctorResult {
            clean: !checks
                .iter()
                .any(|c| matches!(c.status, shepherd_proto::response::CheckStatus::Fail)),
            checks,
            source: DoctorSource::Daemon,
        })
    }

    // --- events -----------------------------------------------------------

    fn events_subscribe(&mut self, req: SubscribeRequest) -> Result<SubscribeResult, RpcError> {
        // The connection loop performs the actual subscription so it can own
        // the pump thread; this arm exists because the trait requires it and
        // because a `subscribe` arriving outside a connection context (a future
        // in-process caller) still needs a correct answer.
        let (result, _replay, _rx) = self.hub().subscribe(req.streams, req.resume_from, None);
        Ok(result)
    }

    // --- registered, not served at Phase 1 --------------------------------

    fn search(&mut self, _: SearchRequest) -> Result<SearchResult, RpcError> {
        Err(not_implemented(
            "search",
            "the metadata index lands with shepherd-index in Phase 1 task T7",
        ))
    }

    fn target_add(&mut self, _: TargetAddRequest) -> Result<TargetAddResult, RpcError> {
        Err(not_implemented("target.add", "storage lands in Phase 2"))
    }

    fn target_list(&mut self, _: TargetListRequest) -> Result<TargetListResult, RpcError> {
        Err(not_implemented("target.list", "storage lands in Phase 2"))
    }

    fn target_test(&mut self, _: TargetTestRequest) -> Result<TargetTestResult, RpcError> {
        Err(not_implemented("target.test", "storage lands in Phase 2"))
    }

    fn rule_list(&mut self, _: RuleListRequest) -> Result<RuleListResult, RpcError> {
        Err(not_implemented(
            "rule.list",
            "the rule engine lands in Phase 2; only the matcher exists at Phase 1",
        ))
    }

    fn rule_preview(&mut self, _: RulePreviewRequest) -> Result<RulePreviewResult, RpcError> {
        Err(not_implemented(
            "rule.preview",
            "the rule engine and its mandatory dry-run land in Phase 2",
        ))
    }

    fn tier_plan(&mut self, _: TierPlanRequest) -> Result<TierPlanResult, RpcError> {
        Err(not_implemented("tier.plan", "tiering lands in Phase 2"))
    }

    fn tier_run(&mut self, _: TierRunRequest) -> Result<TierRunResult, RpcError> {
        Err(not_implemented("tier.run", "tiering lands in Phase 2"))
    }

    fn restore(&mut self, _: RestoreRequest) -> Result<RestoreResult, RpcError> {
        Err(not_implemented("restore", "restore lands in Phase 2"))
    }
}

impl Session {
    fn load_root(&self, id: RootId) -> Result<RootSummary, RpcError> {
        self.cat(move |cat| root_summary(cat, id))?
            .ok_or_else(|| RpcError::new(ErrorCode::NotFound, format!("root {id} vanished")))
    }
}

// ---------------------------------------------------------------------------
// Catalog queries
//
// Free functions rather than methods so they run inside the writer actor's
// closure, which is the only place a `&mut Catalog` exists.
// ---------------------------------------------------------------------------

struct Totals {
    roots: u64,
    files: u64,
    bytes: u64,
}

fn catalog_totals(cat: &mut Catalog) -> Result<Totals, CatalogError> {
    let roots: i64 = cat
        .conn()
        .query_row("SELECT COUNT(*) FROM scan_root", [], |r| r.get(0))?;
    let (files, bytes): (i64, i64) = cat.conn().query_row(
        "SELECT COUNT(*), COALESCE(SUM(size), 0) FROM file",
        [],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Totals {
        roots: roots as u64,
        files: files as u64,
        bytes: bytes as u64,
    })
}

fn count_custody_rows(cat: &mut Catalog, root: RootId) -> Result<u64, CatalogError> {
    let n: i64 = cat.conn().query_row(
        "SELECT COUNT(*) FROM file WHERE root_id = ?1 AND state IN ('stub', 'remote')",
        rusqlite::params![root.get()],
        |r| r.get(0),
    )?;
    Ok(n as u64)
}

fn remove_root(cat: &mut Catalog, root: RootId, forget: bool) -> Result<u64, CatalogError> {
    let tx = cat.conn_mut().transaction()?;
    let dropped = if forget {
        tx.execute(
            "DELETE FROM file WHERE root_id = ?1",
            rusqlite::params![root.get()],
        )? as u64
    } else {
        0
    };
    tx.execute(
        "DELETE FROM scan_root WHERE id = ?1",
        rusqlite::params![root.get()],
    )?;
    tx.commit()?;
    Ok(dropped)
}

fn root_summary(cat: &mut Catalog, id: RootId) -> Result<Option<RootSummary>, CatalogError> {
    Ok(list_roots(cat, true)?
        .into_iter()
        .find(|r| r.root_id == id.get()))
}

fn list_roots(cat: &mut Catalog, include_disabled: bool) -> Result<Vec<RootSummary>, CatalogError> {
    let mut stmt = cat.conn().prepare(
        "SELECT r.id, r.path, r.enabled, r.stub_mode, r.hosted_optin, r.availability,
                r.resync_required, r.path_case_policy, r.path_norm_policy, r.atime_mode,
                (SELECT COUNT(*) FROM file f WHERE f.root_id = r.id),
                (SELECT COALESCE(SUM(f.size), 0) FROM file f WHERE f.root_id = r.id)
         FROM scan_root r
         WHERE (?1 = 1 OR r.enabled = 1)
         ORDER BY r.id",
    )?;
    let rows = stmt
        .query_map(rusqlite::params![include_disabled as i64], |r| {
            Ok(RootSummary {
                root_id: r.get(0)?,
                path: r.get(1)?,
                enabled: r.get::<_, i64>(2)? != 0,
                stub_mode: match r.get::<_, String>(3)?.as_str() {
                    "dehydrate" => StubMode::Dehydrate,
                    _ => StubMode::Delete,
                },
                hosted_optin: r.get::<_, i64>(4)? != 0,
                availability: match r.get::<_, String>(5)?.as_str() {
                    "unavailable" => RootAvailability::Unavailable,
                    "unmounted" => RootAvailability::Unmounted,
                    _ => RootAvailability::Available,
                },
                resync_required: r.get::<_, i64>(6)? != 0,
                path_case_policy: match r.get::<_, String>(7)?.as_str() {
                    "insensitive" => PathCasePolicy::Insensitive,
                    _ => PathCasePolicy::Sensitive,
                },
                path_norm_policy: match r.get::<_, String>(8)?.as_str() {
                    "nfc" => PathNormPolicy::Nfc,
                    "nfd" => PathNormPolicy::Nfd,
                    _ => PathNormPolicy::Preserve,
                },
                atime_mode: match r.get::<_, String>(9)?.as_str() {
                    "reliable" => AtimeMode::Reliable,
                    "relatime" => AtimeMode::Relatime,
                    "disabled" => AtimeMode::Disabled,
                    _ => AtimeMode::Unknown,
                },
                file_count: r.get::<_, i64>(10)? as u64,
                bytes_total: r.get::<_, i64>(11)? as u64,
            })
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok(rows)
}

/// Scan progress, derived from the job rows rather than from separate state.
///
/// One source of truth: a `scan` job's row already carries its state, attempts
/// and checkpoint, and a parallel progress table would be a second place for
/// the same fact to be wrong.
fn scan_states(cat: &mut Catalog, root_id: Option<i64>) -> Result<Vec<ScanState>, CatalogError> {
    let mut stmt = cat.conn().prepare(
        "SELECT payload_json, checkpoint_json, state, created_at, updated_at, last_error
         FROM job WHERE class = 'scan' ORDER BY id DESC LIMIT 200",
    )?;
    let rows = stmt
        .query_map([], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, Option<String>>(5)?,
            ))
        })?
        .collect::<std::result::Result<Vec<_>, _>>()?;

    let mut out: Vec<ScanState> = Vec::new();
    for (payload, checkpoint, state, created, updated, last_error) in rows {
        let payload: serde_json::Value = serde_json::from_str(&payload).unwrap_or_default();
        let rid = payload.get("root_id").and_then(|v| v.as_i64()).unwrap_or(0);
        if root_id.is_some_and(|want| want != rid) {
            continue;
        }
        // Only the most recent job per root.
        if out.iter().any(|s| s.root_id == rid) {
            continue;
        }
        let cp: serde_json::Value = checkpoint
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default();
        let running = state == "running";
        out.push(ScanState {
            root_id: rid,
            running,
            files_seen: cp.get("files_seen").and_then(|v| v.as_u64()).unwrap_or(0),
            bytes_seen: cp.get("bytes_seen").and_then(|v| v.as_u64()).unwrap_or(0),
            started_at: Some(created),
            finished_at: (!running && state != "queued").then_some(updated),
            last_error,
        });
    }
    out.sort_by_key(|s| s.root_id);
    Ok(out)
}
