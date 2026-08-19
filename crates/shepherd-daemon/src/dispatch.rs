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
//! | `root.add`, `root.list`, `root.remove` | `target.list`, `target.test` (Phase 2) |
//! | `scan.start`, `scan.status` | `rule.*` (the engine is Phase 2) |
//! | `search` (T7's metadata index) | `tier.*`, `restore` (Phase 2) |
//! | `status`, `doctor`, `events.subscribe` | |
//! | `target.add` (see below) | |
//!
//! The unimplemented ones return [`ErrorCode::MethodNotImplemented`] rather
//! than a stopgap. The distinct error code, and `shepctl`'s exit status 4, are
//! what make "not built yet" legible to a script.
//!
//! # `target.add` is served ahead of the rest of `target.*`, on purpose
//!
//! Registration is the **only** moment at which a target's whole-object
//! multipart checksum can be decided: the value cannot be retrofitted without
//! re-uploading every object written through the target, at a measured 649x
//! scrub cost (ADR 0b §3). `shepherd_storage::s3::probe_multipart_checksum`
//! settles it, and [`crate::targets`] is where the daemon calls it — before the
//! `target` row exists, so a probe that cannot reach the provider refuses the
//! registration instead of recording a guess that looks like a measurement
//! forever after.
//!
//! `target.list` and `target.test` stay refused. Neither falls out of this
//! change, each needs work of its own, and serving a method with less than it
//! promises is the failure mode this whole file is arranged against.
//!
//! # `search` is served by the index, and by nothing else
//!
//! This file previously carried a standing warning that "a catalog `LIKE` query
//! dressed up as `search` would be a second implementation to keep in step with
//! T7's index". T7 has landed and the warning still stands, pointed the other
//! way: [`Session::search`] must keep going through `shepherd_index::MetaIndex`
//! even when a `LIKE` would be easier — for a filter, for a fallback while the
//! index rebuilds, for anything. `LIKE '%x%'` is the FTS5-shaped answer §4.6
//! measured at 378 ms p95, and a fallback that silently substitutes it would put
//! the 50 ms bar's failure mode back in the product behind a passing gate.
//!
//! What the catalog *does* own here is everything the index has no opinion
//! about: hydrating a row's size, mtime, state, hash and tags, and applying the
//! property filters. See `hydrate`.

use std::sync::Arc;

use shepherd_catalog::file_repo::FileRepo;
use shepherd_catalog::job_repo::JobClass;
use shepherd_catalog::target_repo::TargetRepo;
use shepherd_catalog::writer::CatalogWriter;
use shepherd_catalog::{Catalog, CatalogError};
use shepherd_core::{RootId, Timestamp};
use shepherd_jobs::Queue;
use shepherd_proto::request::*;
use shepherd_proto::response::*;
use shepherd_proto::{ErrorCode, Negotiated, RpcError, ShepherdApi};

use crate::events::EventHub;
use crate::state::Daemon;
use crate::targets::{self, S3TargetConfig};

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
        // `Precondition`, not `Invalid`: the request was well-formed and the
        // values in it were fine. What did not hold is the state the transition
        // assumed — which is precisely what `Precondition` names, and which a
        // caller retrying after a crash can read as "already done" rather than
        // as a request it must not repeat.
        CatalogError::AlreadyInState(m) => RpcError::new(ErrorCode::Precondition, m),
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
        // `detect_with_write_probe`, not `detect`: on Linux a strict mount is
        // recorded as the ABSENCE of an atime flag, so the option string alone
        // cannot tell strict from unstated and answers `Relatime` for both.
        // This is the one call site allowed to spend a write measuring the
        // difference — §4.12 forbids guessing it, and `probe_path_policies`
        // just above already writes to this same directory.
        let atime_mode = shepherd_catalog::atime::detect_with_write_probe(&path);
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
        // The third gap in the same shape as the two above, and the one whose
        // absence contradicted a comment three lines up: "Probed, never
        // assumed". `probe_path_policies` reports whether it actually ran, its
        // docs say "the caller records the distinction", and this is that
        // caller — it took `case` and `norm` and dropped `assumed`.
        //
        // It matters because `norm_key` is derived from these two policies and
        // every watcher event is matched against that key. A guessed policy that
        // guessed wrong produces false absence, which PM-3 shows is
        // discard-trigger territory — and there was no way, afterwards, to tell
        // a guessed root from a measured one.
        //
        // Warned rather than persisted: recording it durably needs a column on
        // `scan_root`, and a review round is the wrong place to add one. The
        // warning is the honest floor — the user hears it while standing in
        // front of the command that caused it. See the round report.
        if policies.assumed {
            warnings.push(format!(
                "could not probe this root's case and normalization behaviour (it is not \
                 writable); assuming the platform defaults `{}`/`{}`. §4.9 wants these \
                 measured, and a wrong guess makes watcher lookups miss (PM-3) — re-add \
                 this root from a writable mount if you can",
                policies.case.as_str(),
                policies.norm.as_str()
            ));
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

        // Compiled here, at the registration boundary, so an unusable pattern
        // is refused while the user is still standing in front of the command
        // that named it. `scan_exec` compiles the stored list again and fails
        // the job if it is bad, which is the right backstop but the wrong place
        // to learn about a typo: by then the root is registered, the scan has
        // been queued, and the failure arrives as a job error detached from the
        // request that caused it.
        //
        // The failure direction is what makes this worth a second compile.
        // `IgnoreSet::new` rejecting a pattern is the loud case; the quiet one
        // is a root that registers happily and then never excludes anything.
        if let Err(e) = shepherd_scan::IgnoreSet::new(&path, &req.ignore_patterns) {
            return Err(RpcError::new(
                ErrorCode::Invalid,
                format!("this root's ignore patterns cannot be compiled: {e}"),
            ));
        }

        let path_string = req.path.clone();
        let hosted_optin = req.hosted_optin;
        let ignore_patterns = req.ignore_patterns.clone();
        let now = self.now();
        let root_id = self.cat(move |cat| {
            FileRepo::new(cat).insert_root(
                &path_string,
                stub,
                policies.case,
                policies.norm,
                atime_mode,
                volume.as_deref(),
                hosted_optin,
                &ignore_patterns,
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

    // --- search -----------------------------------------------------------

    fn search(&mut self, req: SearchRequest) -> Result<SearchResult, RpcError> {
        let started = std::time::Instant::now();

        if req.query.is_empty() {
            return Err(RpcError::new(
                ErrorCode::Invalid,
                "`query` is empty. An empty as-you-type box matches every file in the \
                 catalog, which is not a search result — send no request instead.",
            ));
        }
        // A glob is `shepherd-rules`' predicate (AC-13), and implementing a
        // second globber here would be a second semantics to keep in step with
        // the one the rule engine destroys files by. Refused, and named.
        if req.filters.path_glob.is_some() {
            return Err(not_implemented(
                "search.filters.path_glob",
                "the glob predicate belongs to shepherd-rules' matcher and the search path \
                 adopts it with the rule engine in Phase 2",
            ));
        }

        // §4.6's vector side is Phase 5. Degrading and *saying so* is what the
        // proto's `degraded` field exists for; a silent downgrade would make a
        // metadata-only answer look like a semantic one.
        let degraded = match req.mode {
            SearchMode::Metadata => None,
            SearchMode::Semantic | SearchMode::Hybrid => Some(format!(
                "asked for `{}`, served `metadata`: the ANN index and embeddings land in \
                 Phase 5, so no semantic ranking exists to fuse",
                match req.mode {
                    SearchMode::Semantic => "semantic",
                    _ => "hybrid",
                }
            )),
        };

        let index = self.daemon.index()?;
        let offset = req.offset as usize;
        let limit = req.limit as usize;
        let want = offset.saturating_add(limit);

        // Filters are applied to catalog rows, so the index has to hand over
        // more candidates than the caller asked for or a filtered page comes
        // back short. The multiplier is a bounded guess, and `degraded` reports
        // when it was not enough rather than pretending it was.
        let cap = if req.filters == SearchFilters::default() {
            want
        } else {
            want.saturating_mul(FILTERED_CANDIDATE_FACTOR)
                .min(MAX_CANDIDATES)
        };

        let matched = index.search(&req.query, cap.max(1));
        let candidates = matched.ids.clone();
        let filters = req.filters.clone();
        let mut hits = self.cat(move |cat| hydrate(cat, &candidates, &filters))?;

        // The index already ordered by `file_id`; hydration reorders by
        // whatever SQLite felt like. Restoring index order is what keeps paging
        // stable across two calls that differ only in `offset`.
        let rank: std::collections::HashMap<i64, usize> = matched
            .ids
            .iter()
            .enumerate()
            .map(|(i, id)| (*id, i))
            .collect();
        hits.sort_by_key(|h| rank.get(&h.file_id).copied().unwrap_or(usize::MAX));

        let total = hits.len() as u64;
        let page: Vec<SearchHit> = hits.into_iter().skip(offset).take(limit).collect();

        // `total` is a count of what survived filtering, which is exact only
        // when the scan was not capped. Saying so beats reporting a truncated
        // count as authoritative — AC-40's UI shows this number to a human.
        let degraded = match (degraded, matched.truncated) {
            (Some(mode), true) => Some(format!(
                "{mode}; and the index scan stopped at {cap} candidates, so `total` is a \
                 lower bound"
            )),
            (Some(mode), false) => Some(mode),
            (None, true) => Some(format!(
                "the index scan stopped at {cap} candidates, so `total` is a lower bound, \
                 not a total"
            )),
            (None, false) => None,
        };

        Ok(SearchResult {
            hits: page,
            total,
            took_ms: started.elapsed().as_millis() as u64,
            degraded,
        })
    }

    // --- targets ----------------------------------------------------------

    /// Register a storage target, **probing it before it exists**.
    ///
    /// # The order of the steps below is the design
    ///
    /// Everything that can refuse cheaply refuses first, then the probe runs,
    /// and only then does a row appear. Two of those orderings are load-bearing
    /// rather than tidy:
    ///
    /// 1. **The probe runs before the insert.** A probe that cannot reach the
    ///    provider returns `Err`, and this method turns that into a refusal. If
    ///    the row were written first, the failure would leave a registered
    ///    target whose `multipart_checksum` is absent — which is
    ///    indistinguishable from a provider that genuinely supports none, is
    ///    permanent for every object written afterwards, and costs 649x on
    ///    scrub. "We could not tell" and "it does not support it" are different
    ///    facts and only one of them may be persisted.
    /// 2. **The name check runs before the probe.** Not for correctness —
    ///    `target.name` is `UNIQUE` and the insert would catch it — but the
    ///    probe uploads up to three 10 MiB multipart objects, and paying for
    ///    that to answer a question about a registration already doomed by a
    ///    name clash is a bill nobody agreed to.
    ///
    /// # What this deliberately does not probe
    ///
    /// `target.attestation_mode` is also documented as probed at registration
    /// (§4.10.2) and is left at its fail-closed `'none'` default here. That is
    /// a separate probe against a different provider property — bucket
    /// versioning — with its own destroy-path consequences, and guessing it
    /// from a successful checksum probe would be exactly the "silently landing
    /// on B while believing A" the schema comment warns about. A target
    /// registered by this build authorizes no destruction, which is the correct
    /// answer until someone writes that probe.
    fn target_add(&mut self, req: TargetAddRequest) -> Result<TargetAddResult, RpcError> {
        let name = req.name.trim().to_string();
        if name.is_empty() {
            return Err(RpcError::new(
                ErrorCode::Invalid,
                "`name` must not be empty; it is how every later command refers to this target",
            ));
        }
        if req.adapter != targets::S3_ADAPTER {
            return Err(RpcError::new(
                ErrorCode::Invalid,
                format!(
                    "`{}` is not an adapter this build can register. Served: `{}`. A target row                      for an adapter the daemon cannot construct would be a registration that                      every later phase has to special-case.",
                    req.adapter,
                    targets::S3_ADAPTER
                ),
            ));
        }

        let cfg = S3TargetConfig::parse_request(&req.config)?;
        // Resolved, used to build one `S3Config`, and never logged, never
        // stored, never returned. See `targets`' module docs.
        let credentials =
            targets::resolve_credentials(&self.daemon.secrets, req.credentials_ref.as_deref())?;

        let taken = {
            let n = name.clone();
            self.cat(move |c| TargetRepo::new(c).name_exists(&n))?
        };
        if taken {
            return Err(RpcError::new(
                ErrorCode::Invalid,
                format!("a target named `{name}` is already registered"),
            ));
        }

        let probe = targets::probe_multipart_checksum_blocking(&cfg.to_s3_config(credentials))?;
        // The summary carries the per-algorithm evidence and no credential
        // material — `ChecksumProbe` holds an endpoint and a bucket, never an
        // `S3Config`.
        tracing::info!(
            target_name = %name,
            probe = %probe.summary(),
            "registration checksum probe completed"
        );

        let config_json = serde_json::to_string(&cfg.with_probe(&probe)?).map_err(|e| {
            RpcError::new(
                ErrorCode::InternalError,
                format!("the effective target config could not be serialized: {e}"),
            )
        })?;

        let id = {
            let (n, cref) = (name.clone(), req.credentials_ref.clone());
            self.cat(move |c| {
                TargetRepo::new(c).insert(
                    &n,
                    targets::S3_ADAPTER,
                    // Not plugin-backed: `s3` is a first-party adapter.
                    false,
                    // §4.4 custody is a deliberate decision about where a sole
                    // copy may live, not something a registration confers.
                    false,
                    &config_json,
                    cref.as_deref(),
                )
            })?
        };

        Ok(TargetAddResult {
            target: TargetSummary {
                target_id: id.get(),
                name,
                adapter: targets::S3_ADAPTER.to_string(),
                enabled: true,
                is_third_party: false,
                custody_eligible: false,
                // Not persisted, so not claimed. `reachable` is the one thing
                // this call genuinely observed: the probe completed a real
                // multipart round trip against the bucket to get here.
                last_health_at: None,
                reachable: Some(true),
            },
        })
    }

    // --- registered, not served at Phase 1 --------------------------------

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

/// Deregister a root, and delete its catalog only if that was asked for.
///
/// # Why the default does not delete the `scan_root` row
///
/// `file.root_id` is `INTEGER NOT NULL REFERENCES scan_root(id) ON DELETE
/// CASCADE`. Deleting the root row therefore deletes every file row under it —
/// including the `stub`/`remote` rows that are a tiered file's *only* remote
/// address — and it did so on the path that reports `catalog_rows_dropped: 0`,
/// past a custody refusal that only runs when `forget` is true. A silent
/// cascade behind a zero is the failure this function is arranged against.
///
/// So the default *deregisters*: the row stays, `enabled` goes to 0, and every
/// file row under it stays reachable through the same root id. `root.list` hides
/// it (its `WHERE` already respects `enabled`), `scan.start` with no root skips
/// it for the same reason, and `scan_exec` refuses it by name if a job for it is
/// still queued. `--forget` remains the operation that destroys, and it says so.
fn remove_root(cat: &mut Catalog, root: RootId, forget: bool) -> Result<u64, CatalogError> {
    let tx = cat.conn_mut().transaction()?;
    let dropped = if forget {
        let n = tx.execute(
            "DELETE FROM file WHERE root_id = ?1",
            rusqlite::params![root.get()],
        )? as u64;
        tx.execute(
            "DELETE FROM scan_root WHERE id = ?1",
            rusqlite::params![root.get()],
        )?;
        n
    } else {
        tx.execute(
            "UPDATE scan_root SET enabled = 0 WHERE id = ?1",
            rusqlite::params![root.get()],
        )?;
        0
    };
    tx.commit()?;
    Ok(dropped)
}

fn root_summary(cat: &mut Catalog, id: RootId) -> Result<Option<RootSummary>, CatalogError> {
    Ok(list_roots(cat, true)?
        .into_iter()
        .find(|r| r.root_id == id.get()))
}

/// Candidates fetched per requested hit when filters are present.
///
/// Filters are catalog predicates, so the index cannot apply them; it hands over
/// a wider candidate set and SQL narrows it. Too small and a filtered page comes
/// back short; too large and a cheap query pays for a full scan. 16 is a guess,
/// and the `degraded` field is what makes it an honest one — a page that hit the
/// cap says so rather than reporting a short result as complete.
const FILTERED_CANDIDATE_FACTOR: usize = 16;

/// Absolute ceiling on candidates, whatever the factor computes.
///
/// Bounds the arena scan for a *filtered* query, where the factor above can
/// multiply a modest page into an enormous candidate set. It deliberately does
/// **not** apply to an unfiltered query: there, `cap` is exactly the page the
/// caller asked for, and clamping it would turn a legitimately deep page into
/// an empty result with a `degraded` note attached — a refusal wearing the
/// costume of an answer. The bind ceiling that made that clamp look necessary
/// is handled where it actually lives, in [`hydrate`].
const MAX_CANDIDATES: usize = 10_000;

/// The most bound values one SQLite statement accepts.
///
/// `SQLITE_MAX_VARIABLE_NUMBER`, which has defaulted to 32766 rather than the
/// often-quoted 999 since SQLite 3.32. Stated as the measured property of *this*
/// build — `libsqlite3-sys` compiles the amalgamation Shepherd ships, so the
/// value is fixed at our build time and not the host's — and
/// `a_page_deeper_than_sqlites_bind_limit_returns_its_rows` is what would catch
/// it changing under us.
const SQLITE_BIND_LIMIT: usize = 32_766;

/// Candidate ids bound into one hydration statement.
///
/// Well under [`SQLITE_BIND_LIMIT`] on purpose. The limit is the cliff; this is
/// the working size, and the gap between them is what a long `ext` filter is
/// allowed to consume without the two constants having to be re-derived
/// together.
const HYDRATE_CHUNK: usize = 8_000;

/// Turn index candidate ids into wire hits, applying the catalog-side filters.
///
/// The index's job ends at "these file ids match the text". Everything AC-40's
/// result row shows — size, mtime, state, hash, tags — and every predicate that
/// is about a file's *properties* rather than its name lives here, in the
/// catalog, which is the only place that knows them.
fn hydrate(
    cat: &mut Catalog,
    candidates: &[i64],
    filters: &SearchFilters,
) -> Result<Vec<SearchHit>, CatalogError> {
    if candidates.is_empty() {
        return Ok(Vec::new());
    }
    let (filter_sql, filter_params) = filter_clause(filters);

    // The candidate ids and the filter values share one statement's parameter
    // budget, so the room left for ids is what is left after the filters have
    // taken theirs. Computed rather than assumed: `filters.ext` is a
    // caller-supplied list of unbounded length, so a fixed chunk size that
    // happened to fit today would stop fitting the moment someone sent a long
    // enough one.
    let Some(budget) = SQLITE_BIND_LIMIT.checked_sub(filter_params.len()) else {
        return Err(CatalogError::Invalid(format!(
            "these search filters need {} bound values, more than the {SQLITE_BIND_LIMIT} \
             one SQLite statement accepts; narrow `ext`",
            filter_params.len()
        )));
    };
    if budget == 0 {
        return Err(CatalogError::Invalid(format!(
            "these search filters use the whole {SQLITE_BIND_LIMIT}-value budget of one \
             SQLite statement, leaving no room for a single candidate id; narrow `ext`"
        )));
    }
    let chunk = budget.min(HYDRATE_CHUNK);

    let mut hits: Vec<SearchHit> = Vec::new();
    for window in candidates.chunks(chunk) {
        hydrate_chunk(cat, window, &filter_sql, &filter_params, &mut hits)?;
    }

    attach_tags(cat, &mut hits)?;
    if !filters.tags.is_empty() {
        let want: Vec<String> = filters.tags.iter().map(|t| t.to_lowercase()).collect();
        // ALL, not ANY: two tag filters narrow a search. ANY would widen it,
        // which is the opposite of what a user adding a second filter means.
        hits.retain(|h| {
            want.iter()
                .all(|w| h.tags.iter().any(|t| t.to_lowercase() == *w))
        });
    }
    Ok(hits)
}

/// The catalog-side predicates, as a SQL fragment and the values it binds.
///
/// Built once and re-bound per chunk. Rebuilding it inside the loop would be
/// harmless; **omitting** it from any chunk after the first would not, so it is
/// a single value the chunk loop cannot forget to use.
fn filter_clause(filters: &SearchFilters) -> (String, Vec<Box<dyn rusqlite::ToSql>>) {
    let mut sql = String::new();
    let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();

    if !filters.ext.is_empty() {
        let marks = std::iter::repeat_n("?", filters.ext.len())
            .collect::<Vec<_>>()
            .join(",");
        sql.push_str(&format!(" AND ext IN ({marks})"));
        for e in &filters.ext {
            // `file.ext` is stored lowercase and without the dot by the
            // catalog's own `split_name`; matching its convention here is what
            // keeps `--filters '{"ext":["PDF"]}'` from silently finding nothing.
            params.push(Box::new(e.trim_start_matches('.').to_lowercase()));
        }
    }
    if let Some(min) = filters.min_size {
        sql.push_str(" AND size >= ?");
        params.push(Box::new(min as i64));
    }
    if let Some(max) = filters.max_size {
        sql.push_str(" AND size <= ?");
        params.push(Box::new(max as i64));
    }
    if let Some(after) = filters.modified_after {
        sql.push_str(" AND mtime > ?");
        params.push(Box::new(after));
    }
    if let Some(before) = filters.modified_before {
        sql.push_str(" AND mtime < ?");
        params.push(Box::new(before));
    }
    if let Some(state) = filters.state {
        sql.push_str(" AND state = ?");
        params.push(Box::new(file_state_str(state).to_string()));
    }
    if let Some(root) = filters.root_id {
        sql.push_str(" AND root_id = ?");
        params.push(Box::new(root));
    }

    (sql, params)
}

/// Hydrate one chunk of candidate ids, appending to `hits`.
fn hydrate_chunk(
    cat: &mut Catalog,
    candidates: &[i64],
    filter_sql: &str,
    filter_params: &[Box<dyn rusqlite::ToSql>],
    hits: &mut Vec<SearchHit>,
) -> Result<(), CatalogError> {
    // A bound parameter per id rather than string interpolation: these ids come
    // from the index, but "it came from inside the process" is exactly the
    // reasoning that makes the one interpolated query in a codebase the
    // injection.
    let placeholders = std::iter::repeat_n("?", candidates.len())
        .collect::<Vec<_>>()
        .join(",");

    let sql = format!(
        "SELECT id, root_id, rel_path, size, mtime, state, blake3
         FROM file
         WHERE id IN ({placeholders}){filter_sql}"
    );
    let params: Vec<&dyn rusqlite::ToSql> = candidates
        .iter()
        .map(|id| id as &dyn rusqlite::ToSql)
        .chain(filter_params.iter().map(|p| p.as_ref()))
        .collect();

    {
        let mut stmt = cat.conn().prepare(&sql)?;
        let rows = stmt.query_map(params.as_slice(), |r| {
            Ok(SearchHit {
                file_id: r.get(0)?,
                root_id: r.get(1)?,
                rel_path: r.get(2)?,
                size: r.get::<_, i64>(3)? as u64,
                mtime: r.get(4)?,
                state: match r.get::<_, String>(5)?.as_str() {
                    "stub" => FileState::Stub,
                    "remote" => FileState::Remote,
                    "missing" => FileState::Missing,
                    _ => FileState::Local,
                },
                blake3: r
                    .get::<_, Option<Vec<u8>>>(6)?
                    .and_then(|b| <[u8; 32]>::try_from(b.as_slice()).ok())
                    .map(|b| shepherd_core::Blake3Hash::from_bytes(b).to_hex()),
                tags: Vec::new(),
                // Absent by protocol contract for a metadata query: there is no
                // relevance model here, and inventing one would make a future
                // real score indistinguishable from this placeholder.
                score: None,
            })
        })?;
        for row in rows {
            hits.push(row?);
        }
    }
    Ok(())
}

/// Fill in each hit's tags with one query rather than one per hit.
fn attach_tags(cat: &mut Catalog, hits: &mut [SearchHit]) -> Result<(), CatalogError> {
    if hits.is_empty() {
        return Ok(());
    }
    let mut by_file: std::collections::HashMap<i64, Vec<String>> = std::collections::HashMap::new();
    // Chunked for the same reason `hydrate` is, and it is not a theoretical
    // second instance: this binds one parameter per *hit*, so a hit list that
    // cleared the ceiling above would hit it here instead, on a query the
    // caller never asked about.
    for window in hits.chunks(HYDRATE_CHUNK) {
        let placeholders = std::iter::repeat_n("?", window.len())
            .collect::<Vec<_>>()
            .join(",");
        let mut stmt = cat.conn().prepare(&format!(
            "SELECT ft.file_id, t.name
             FROM file_tag ft JOIN tag t ON t.id = ft.tag_id
             WHERE ft.file_id IN ({placeholders})
             ORDER BY t.name"
        ))?;
        let ids: Vec<&dyn rusqlite::ToSql> = window
            .iter()
            .map(|h| &h.file_id as &dyn rusqlite::ToSql)
            .collect();
        let rows = stmt.query_map(ids.as_slice(), |r| {
            Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
        })?;
        for row in rows {
            let (file_id, tag) = row?;
            by_file.entry(file_id).or_default().push(tag);
        }
    }
    for hit in hits.iter_mut() {
        if let Some(tags) = by_file.remove(&hit.file_id) {
            hit.tags = tags;
        }
    }
    Ok(())
}

/// The `file.state` column's spelling for a wire `FileState`.
///
/// The reverse mapping is inline in `hydrate`; this direction is separate
/// because a filter comparing against the wrong spelling matches zero rows and
/// looks exactly like a filter that legitimately matched nothing.
fn file_state_str(state: FileState) -> &'static str {
    match state {
        FileState::Local => "local",
        FileState::Stub => "stub",
        FileState::Remote => "remote",
        FileState::Missing => "missing",
    }
}

fn list_roots(cat: &mut Catalog, include_disabled: bool) -> Result<Vec<RootSummary>, CatalogError> {
    let mut stmt = cat.conn().prepare(
        "SELECT r.id, r.path, r.enabled, r.stub_mode, r.hosted_optin, r.availability,
                r.resync_required, r.path_case_policy, r.path_norm_policy, r.atime_mode,
                r.ignore_patterns_json,
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
                // Reported as stored. A list that will not parse is surfaced as
                // empty here rather than failing `root.list`, because the
                // parse that must be strict is `scan_exec`'s — that one decides
                // whether files get excluded, and it already refuses to treat
                // malformed JSON as "ignore nothing". Two strict parsers would
                // make an unlistable root unfixable.
                ignore_patterns: serde_json::from_str(&r.get::<_, String>(10)?).unwrap_or_default(),
                file_count: r.get::<_, i64>(11)? as u64,
                bytes_total: r.get::<_, i64>(12)? as u64,
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

#[cfg(test)]
mod tests {
    use super::*;
    use shepherd_catalog::{AtimeMode, PathCasePolicy, PathNormPolicy};
    use shepherd_core::{FileStat, StubMode};

    fn seed(cat: &mut Catalog, path: &str, files: &[&str]) -> RootId {
        let id = FileRepo::new(cat)
            .insert_root(
                path,
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Nfc,
                AtimeMode::Relatime,
                None,
                false,
                &[],
                Timestamp::from_nanos(1),
            )
            .unwrap();
        let root = FileRepo::new(cat).get_root(id).unwrap().unwrap();
        for f in files {
            FileRepo::new(cat)
                .upsert_file(
                    &root,
                    &FileStat {
                        root: id,
                        rel_path: (*f).into(),
                        size: 1,
                        mtime: Timestamp::from_nanos(1),
                        ctime: Timestamp::from_nanos(1),
                        atime: None,
                        blake3: None,
                    },
                    // These tests are not about generations; the sweep that
                    // reads this column is a separate concern.
                    1,
                    Timestamp::from_nanos(1),
                )
                .unwrap();
        }
        id
    }

    /// `count_custody_rows` is the entire basis of `root.remove`'s refusal to
    /// forget a catalog that is the only address of tiered bytes, so what has
    /// to be established is that it **can return a non-zero number**.
    ///
    /// Asserting only the zero could not establish that, and for a while did
    /// not: `upsert_file`'s INSERT did not name `state`, so no row in any
    /// catalog ever held `'stub'` or `'remote'`, and this query answered 0 for
    /// a reason that had nothing to do with custody. A safety refusal whose
    /// predicate is false by construction is not a refusal.
    ///
    /// So the zero and the non-zero are asserted through the same function,
    /// against the same catalog, one `UPDATE` apart. The `UPDATE` stands in for
    /// the tierer (Phase 2/3); what is under test is the count, not its writer.
    #[test]
    fn the_custody_count_is_zero_before_tiering_and_non_zero_after() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let root = seed(&mut cat, "/data", &["a.txt", "b.txt", "c.txt"]);

        assert_eq!(
            count_custody_rows(&mut cat, root).unwrap(),
            0,
            "nothing is tiered yet"
        );

        cat.conn_mut()
            .execute(
                "UPDATE file SET state = 'stub' WHERE rel_path = 'a.txt'",
                [],
            )
            .unwrap();
        cat.conn_mut()
            .execute(
                "UPDATE file SET state = 'remote' WHERE rel_path = 'b.txt'",
                [],
            )
            .unwrap();

        assert_eq!(
            count_custody_rows(&mut cat, root).unwrap(),
            2,
            "both custody states must be counted — this is what makes the zero above mean \
             `nothing is tiered` rather than `this query cannot see anything`"
        );
    }

    /// The refusal is per-root, and a count that ignored `root_id` would read
    /// as the safest possible bug: `root.remove --forget` on an untiered root
    /// would be refused because some *other* root holds custody.
    #[test]
    fn the_custody_count_does_not_see_another_roots_tiered_rows() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let a = seed(&mut cat, "/a", &["one.txt"]);
        let b = seed(&mut cat, "/b", &["two.txt"]);

        cat.conn_mut()
            .execute(
                "UPDATE file SET state = 'remote' WHERE root_id = ?1",
                rusqlite::params![b.get()],
            )
            .unwrap();

        assert_eq!(count_custody_rows(&mut cat, b).unwrap(), 1);
        assert_eq!(
            count_custody_rows(&mut cat, a).unwrap(),
            0,
            "root /a holds no custody; another root's tiered rows must not block removing it"
        );
    }

    /// `missing` is not custody. It means the bytes were where the catalog said
    /// and are not there now — dropping that row loses a record of a loss, not
    /// the only address of a file that still exists somewhere.
    #[test]
    fn a_missing_row_is_not_counted_as_custody() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let root = seed(&mut cat, "/data", &["gone.txt"]);
        cat.conn_mut()
            .execute("UPDATE file SET state = 'missing'", [])
            .unwrap();
        assert_eq!(count_custody_rows(&mut cat, root).unwrap(), 0);
    }

    fn file_count(cat: &mut Catalog, root: RootId) -> u64 {
        cat.conn()
            .query_row(
                "SELECT COUNT(*) FROM file WHERE root_id = ?1",
                rusqlite::params![root.get()],
                |r| r.get::<_, i64>(0),
            )
            .unwrap() as u64
    }

    /// The default `root.remove` must leave the catalog exactly where it was.
    ///
    /// `file.root_id` is declared `ON DELETE CASCADE`, so deleting the
    /// `scan_root` row deletes every file row under it — custody rows included,
    /// and a custody row is a tiered file's only remote address. That happened
    /// on the path that reports `catalog_rows_dropped: 0`, and the refusal that
    /// exists to stop it only runs when `forget` is true, so nothing was in the
    /// way. Deregistering is the operation the default asks for; deleting is
    /// not.
    ///
    /// What is asserted is that the rows are still THERE and still reachable
    /// through the root's id — `count_custody_rows`, the refusal's own
    /// predicate, must still see them. An `Ok` return would have been just as
    /// true of the cascade.
    #[test]
    fn removing_a_root_without_forget_disables_it_and_keeps_every_row() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let root = seed(&mut cat, "/data", &["a.txt", "b.txt", "c.txt"]);
        cat.conn_mut()
            .execute(
                "UPDATE file SET state = 'remote' WHERE rel_path = 'a.txt'",
                [],
            )
            .unwrap();

        let dropped = remove_root(&mut cat, root, false).unwrap();

        assert_eq!(dropped, 0, "nothing was asked to be forgotten");
        assert_eq!(
            file_count(&mut cat, root),
            3,
            "the catalog rows must survive a removal that did not ask to forget them"
        );
        assert_eq!(
            count_custody_rows(&mut cat, root).unwrap(),
            1,
            "the custody row is the tiered file's only remote address, and the refusal that \
             guards it can only see rows that still exist"
        );

        assert!(
            list_roots(&mut cat, false).unwrap().is_empty(),
            "a removed root is deregistered: it must not appear in the ordinary listing"
        );
        let all = list_roots(&mut cat, true).unwrap();
        assert_eq!(all.len(), 1, "the root row itself must still exist");
        assert!(!all[0].enabled, "and it must be disabled: {:?}", all[0]);
    }

    /// Removing twice without `--forget` stays Ok and still keeps the rows, so
    /// a user who soft-removed can still escalate to `--forget` afterwards.
    #[test]
    fn a_second_removal_without_forget_is_idempotent() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let root = seed(&mut cat, "/data", &["a.txt"]);
        remove_root(&mut cat, root, false).unwrap();
        assert_eq!(remove_root(&mut cat, root, false).unwrap(), 0);
        assert_eq!(file_count(&mut cat, root), 1);
    }

    /// `--forget` is the one that was actually asked for, and it still drops
    /// everything — otherwise the fix above would have turned the destructive
    /// path into a no-op and the count into a second lie.
    #[test]
    fn removing_a_root_with_forget_drops_the_rows_and_the_root() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let root = seed(&mut cat, "/data", &["a.txt", "b.txt"]);

        let dropped = remove_root(&mut cat, root, true).unwrap();

        assert_eq!(dropped, 2, "both rows were dropped and both were reported");
        assert_eq!(file_count(&mut cat, root), 0);
        assert!(
            list_roots(&mut cat, true).unwrap().is_empty(),
            "`--forget` deletes the root row too"
        );
    }

    /// The ids SQLite assigned to the seeded rows, in insertion order.
    fn ids_of(cat: &mut Catalog, root: RootId) -> Vec<i64> {
        let mut stmt = cat
            .conn()
            .prepare("SELECT id FROM file WHERE root_id = ?1 ORDER BY id")
            .unwrap();
        let rows = stmt
            .query_map(rusqlite::params![root.get()], |r| r.get::<_, i64>(0))
            .unwrap();
        rows.map(Result::unwrap).collect()
    }

    /// A candidate list of `len`, containing no id that exists in any catalog.
    ///
    /// One million is above every id the seeding helpers here produce, so a
    /// synthetic id can never collide with a real row and turn a miss into an
    /// accidental hit.
    fn synthetic_candidates(len: usize) -> Vec<i64> {
        (1_000_000..1_000_000 + len as i64).collect()
    }

    /// A deep page must come back with its rows, not with a SQLite failure.
    ///
    /// `search` computes `cap = offset + limit` for an unfiltered query and
    /// applies no ceiling to it, so a valid page deep into a large catalog
    /// hands `hydrate` a candidate list of that size, and `hydrate` bound one
    /// SQL parameter per candidate. This build's real ceiling is **32766** —
    /// measured, not remembered: `SQLITE_MAX_VARIABLE_NUMBER` has been 32766
    /// rather than 999 since SQLite 3.32, and `libsqlite3-sys`' bundled build
    /// is what decides it here. Past that, `prepare` refuses the statement and
    /// a page that exists and is reachable returns an error instead.
    ///
    /// The assertion is on the **rows**, and the real ids are deliberately
    /// placed on both sides of any plausible chunk boundary and beyond the
    /// bind ceiling itself. That is what stops the two fixes that would pass a
    /// weaker test: capping the candidate list would silently drop the ids at
    /// 35_000 and 39_999, and hydrating only the first batch would drop
    /// everything past the boundary. Both would return `Ok` with a short list;
    /// neither returns this page.
    #[test]
    fn a_page_deeper_than_sqlites_bind_limit_returns_its_rows() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let root = seed(&mut cat, "/data", &["a.txt", "b.txt", "c.txt"]);
        let real = ids_of(&mut cat, root);
        assert_eq!(real.len(), 3);

        let mut candidates = synthetic_candidates(40_000);
        candidates[9_000] = real[0];
        candidates[35_000] = real[1];
        candidates[39_999] = real[2];

        let hits = hydrate(&mut cat, &candidates, &SearchFilters::default())
            .expect("a page this deep is valid and must be answered, not refused");

        let mut got: Vec<i64> = hits.iter().map(|h| h.file_id).collect();
        got.sort_unstable();
        let mut want = real.clone();
        want.sort_unstable();
        assert_eq!(
            got, want,
            "every real row in the candidate list must be hydrated, including the ones \
             past the bind ceiling"
        );
    }

    /// Chunking must not cost the filters their reach.
    ///
    /// Splitting one `IN (...)` into several statements means the filter clause
    /// is rebuilt and re-bound per chunk. A fix that appended the predicates to
    /// only the first statement would return every row from every later chunk
    /// unfiltered — a search that quietly widens as the catalog grows.
    ///
    /// So the row that must NOT come back is placed past the boundary, where
    /// only a filter that is still applied there can exclude it.
    #[test]
    fn the_filters_still_narrow_every_chunk_of_a_deep_page() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let root = seed(&mut cat, "/data", &["keep.txt", "drop.bin"]);
        let real = ids_of(&mut cat, root);

        let mut candidates = synthetic_candidates(40_000);
        candidates[100] = real[0]; // keep.txt, in the first chunk
        candidates[38_000] = real[1]; // drop.bin, past the bind ceiling

        let filters = SearchFilters {
            ext: vec!["txt".into()],
            ..SearchFilters::default()
        };
        let hits = hydrate(&mut cat, &candidates, &filters).unwrap();

        let got: Vec<&str> = hits.iter().map(|h| h.rel_path.as_str()).collect();
        assert_eq!(
            got,
            vec!["keep.txt"],
            "`drop.bin` sits past the chunk boundary; a filter that stopped being applied \
             there would let it through"
        );
    }

    /// Tag hydration binds one parameter per hit, so it has the same ceiling as
    /// the candidate list and needs the same treatment.
    ///
    /// Without it, the bind limit simply moves: `hydrate` would survive 40_000
    /// candidates and then fail on the way out, on a query the caller never
    /// asked about. The tag assertion is what makes this more than a crash
    /// test — the tag has to actually arrive on the hit that owns it.
    #[test]
    fn tags_are_attached_across_a_hit_list_larger_than_the_bind_limit() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let names: Vec<String> = (0..40_000).map(|i| format!("f{i}.txt")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let root = seed(&mut cat, "/data", &refs);
        let real = ids_of(&mut cat, root);
        assert_eq!(real.len(), 40_000);

        cat.conn_mut()
            .execute(
                "INSERT INTO tag (name, source) VALUES ('invoice','user')",
                [],
            )
            .unwrap();
        let tag_id: i64 = cat
            .conn()
            .query_row("SELECT id FROM tag WHERE name = 'invoice'", [], |r| {
                r.get(0)
            })
            .unwrap();
        // On the last row, so it is reached only if every chunk is queried.
        cat.conn_mut()
            .execute(
                "INSERT INTO file_tag (file_id, tag_id) VALUES (?1, ?2)",
                rusqlite::params![real[39_999], tag_id],
            )
            .unwrap();

        let hits = hydrate(&mut cat, &real, &SearchFilters::default())
            .expect("40_000 hits must not exceed the bind ceiling on the tag query either");

        assert_eq!(hits.len(), 40_000);
        let tagged = hits
            .iter()
            .find(|h| h.file_id == real[39_999])
            .expect("the last row is a hit");
        assert_eq!(
            tagged.tags,
            vec!["invoice".to_string()],
            "the tag must reach the hit that owns it, from the last chunk"
        );
    }
}
