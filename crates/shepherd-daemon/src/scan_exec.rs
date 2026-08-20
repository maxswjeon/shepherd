//! The `scan` job executor: walk a root, upsert what it finds.
//!
//! This is the piece `main.rs` left a `ponytail:` note for — the empty
//! `Registry` now has one entry. With it, `shepctl root add && shepctl scan
//! start` reaches the catalog. T7's metadata index closed the third leg, so all
//! of §6 Phase 1's M1 demo now runs; this executor refreshes that index before
//! it reports the scan done (see the end of `run`).
//!
//! # What resumes, and what does not — stated plainly
//!
//! The executor checkpoints `{files_seen, bytes_seen}`, and `scan.status`
//! reads exactly those keys back out of `checkpoint_json`. That is **progress
//! reporting**, and it is deliberately not called resume.
//!
//! A restarted scan **re-walks and re-upserts from the beginning.** That is
//! correct rather than merely acceptable: `FileRepo::upsert_file` is
//! `ON CONFLICT DO UPDATE` and never overwrites `first_seen_at`, so a repeated
//! upsert converges on the same row.
//!
//! An index-based resume — "skip the first N of the sorted walk" — was
//! considered and rejected. It is only sound if the tree is unchanged between
//! runs, and a scan that restarts is disproportionately likely to be scanning a
//! tree that just changed. Skipping N entries of a *different* list silently
//! misses files, and a scanner that silently misses files is worse than one
//! that repeats work. AC-2's "resume without re-sending verified parts" is
//! about uploads, where the work is expensive and the object is immutable;
//! neither is true here.
//!
//! # `walk` is not streaming, and that is a ceiling
//!
//! `shepherd_scan::walk` returns the whole `Vec<FileStat>` before this executor
//! sees any of it, so progress events cannot be emitted *during* the walk —
//! only during the upsert phase that follows. On the 1M-file M1 corpus that
//! means a silent period followed by reported progress, and a `Vec` of 1M
//! `FileStat` in memory.
//! ponytail: non-streaming walk; if the 10M-file Phase 0d corpus makes either
//! the silence or the memory unacceptable, the fix is a callback-based walker
//! in `shepherd-scan`, not batching around it here.

use std::sync::Arc;

use rusqlite::OptionalExtension;
use shepherd_catalog::file_repo::{Availability, FileRepo, ScanRoot};
use shepherd_catalog::writer::CatalogWriter;
use shepherd_catalog::{Catalog, CatalogError, PathCasePolicy};
use shepherd_core::RootId;
use shepherd_jobs::worker::{Executor, JobContext, now};
use shepherd_proto::event::{EventPayload, EventStream};
use shepherd_scan::{DenyList, IgnoreSet, Skip, walk};

use crate::state::Daemon;

/// Files upserted per round-trip through the writer actor.
///
/// One actor call per file would put a rendezvous channel hop between every
/// row; one call for a million files would hold the single writer for the whole
/// scan and stall every concurrent `status`. 500 is a middle that keeps the
/// actor responsive without making the hop dominate.
/// ponytail: fixed batch of 500; tune only against a measured scan profile.
const UPSERT_BATCH: usize = 500;

/// Whether `path` is `ancestor` or lives under it, on canonical paths where
/// they resolve. `Path::starts_with` compares components, so a shared prefix
/// like `state-old` is not "under" `state`.
fn under(path: &std::path::Path, ancestor: &std::path::Path) -> bool {
    let real = |p: &std::path::Path| std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    real(path).starts_with(real(ancestor))
}

/// Emit a progress event no more often than this many files.
const PROGRESS_EVERY: usize = 2_000;

/// Holds the daemon rather than copies of its parts: the executor needs the
/// writer *and* the event hub, and both are already reachable through the same
/// `Arc` every connection thread holds. There is no cycle — the pool owns the
/// registry, and the daemon does not own the pool.
pub struct ScanExecutor {
    daemon: Arc<Daemon>,
}

impl ScanExecutor {
    pub fn new(daemon: Arc<Daemon>) -> Self {
        Self { daemon }
    }

    fn writer(&self) -> &CatalogWriter {
        &self.daemon.writer
    }

    fn publish(&self, root_id: i64, files: u64, bytes: u64, path: Option<String>, done: bool) {
        self.daemon.events.publish(
            EventStream::Scan,
            EventPayload::ScanProgress {
                root_id,
                files_seen: files,
                bytes_seen: bytes,
                current_path: path,
                done,
            },
        );
    }
}

impl Executor for ScanExecutor {
    fn run(&self, ctx: &JobContext) -> Result<(), String> {
        let payload: serde_json::Value = serde_json::from_str(&ctx.job.payload_json)
            .map_err(|e| format!("scan payload is not JSON: {e}"))?;
        let root_id = payload
            .get("root_id")
            .and_then(serde_json::Value::as_i64)
            .ok_or("scan payload has no `root_id`")?;
        let rid = RootId::new(root_id);

        // --- load the root and its ignore patterns ------------------------
        let loaded = self
            .writer()
            .try_with(move |cat| load_scan_input(cat, rid))
            .map_err(|e| e.to_string())?;
        let Some((root, patterns)) = loaded else {
            // Not retryable in any useful sense — the root is no longer
            // registered, whether it was forgotten outright or deregistered
            // with its catalog kept. Returning Err lets the queue's backoff run
            // its course and record why, rather than reporting success for work
            // that did not happen.
            return Err(format!(
                "scan root {root_id} is no longer registered for scanning"
            ));
        };

        // PM-3: an unavailable root processes zero absences. Walking one would
        // read an empty or partial tree and, worse, a later sweep could read
        // the resulting rows as files that had vanished.
        if root.availability != Availability::Available {
            return Err(format!(
                "root {root_id} is {} — refusing to scan a root that is not fully present (PM-3)",
                root.availability.as_str()
            ));
        }

        let path = std::path::PathBuf::from(&root.path);
        // The daemon's own state directory, denied by path.
        //
        // The builtin list only knows `.shepherd-staging`. Under the common
        // `$HOME` root the state directory sits inside the tree being walked,
        // so the walk catalogued the live `catalog.db` and its `-wal`/`-shm`
        // companions and any `secrets.json` — self-referential rows that move
        // under their own scan, and worse, candidates a later rule pass could
        // hash and tier.
        //
        // A root AT or INSIDE the state directory is REFUSED here rather than
        // excluded. Excluding it would prune the walk root itself, which
        // surfaces as "could not be read" — an unreadable-root refusal
        // manufactured out of an exclusion, and that check must never fire
        // spuriously. Falling back to the builtin-only list instead was worse:
        // it walked the live `catalog.db`, its WAL companions and any
        // `secrets.json`, which is exactly what the exclusion exists to stop.
        // `root.add` refuses the same path, so this is for rows enrolled before
        // that refusal existed, or for a state directory relocated under an
        // enrolled root.
        let state_dir = &self.daemon.paths.state_dir;
        if under(&path, state_dir) {
            return Err(format!(
                "root {root_id} at {} is inside the daemon's own state directory ({}); \
                 refusing to scan Shepherd's catalog, its write-ahead log and its secret \
                 store as if they were the user's files",
                root.path,
                state_dir.display()
            ));
        }
        // Case folding follows the ROOT's probed policy: on a case-insensitive
        // volume `.GIT` is the same directory as `.git`, and a deny-list entry
        // that can be evaded by pressing shift is not a safety policy.
        //
        // The socket's lock file is denied alongside it. `SHEPHERD_SOCKET` can
        // name a directory outside the state directory and inside a scan root
        // — the e2e suite runs exactly that arrangement — and unlike the socket
        // node, which the walk skips because it is not a regular file,
        // `<socket>.lock` is an ordinary file the daemon created for itself.
        let deny = DenyList::builtin()
            .case_insensitive(root.case_policy == PathCasePolicy::Insensitive)
            .with_extra_path(state_dir)
            .with_extra_path(&self.daemon.paths.socket_lock());
        let ignores = IgnoreSet::new(&path, &patterns)
            .map_err(|e| format!("root {root_id} has an unusable ignore pattern: {e}"))?;

        // The volume this root was ENROLLED on, re-asked now.
        //
        // `availability` is a catalog flag somebody set at some point; it says
        // nothing about which filesystem is mounted at this path today. A
        // removable disk swapped at the same mount point — or a registered
        // symlink retargeted at another volume — walks perfectly happily, and
        // `upsert_file` then pairs the NEW volume's inode numbers with the OLD
        // volume id. The resulting `fs_id` values are well-formed and false:
        // they name files that do not exist on the volume they claim, and the
        // path rows they update are treated as though they still described the
        // enrolled filesystem.
        //
        // Compared only when BOTH identities exist. A root enrolled without a
        // stable identity has nothing to disagree with — that case is warned
        // about at `root.add` — and no platform outside Linux can answer at
        // all until Phase 3, so demanding an answer here would refuse every
        // scan on macOS and Windows.
        if let Some(enrolled) = root.volume_id.as_deref()
            && let Some(current) = shepherd_catalog::volume::current_volume_id(&path)
            && current != enrolled
        {
            return Err(format!(
                "root {root_id} at {} was enrolled on volume `{enrolled}` and the filesystem \
                 mounted there now is `{current}`. Scanning would pair this volume's inode \
                 numbers with the enrolled volume's id, producing `fs_id` values that look \
                 valid and name files on neither. Re-point the root, or resynchronise it if \
                 the volume really was replaced",
                root.path
            ));
        }

        self.publish(root_id, 0, 0, Some(root.path.clone()), false);

        // --- walk ---------------------------------------------------------
        // On the worker thread, deliberately: this is the I/O-heavy half and
        // must not run inside the single-writer actor.
        let output = walk(rid, &path, &deny, &ignores, now())
            .map_err(|e| format!("walking {}: {e}", root.path))?;

        // **An unreadable root is not an empty root, and the difference is the
        // whole safety of the reconciliation below.**
        //
        // `walk` reports a directory it could not read as a `Skip::Unreadable`
        // and returns `Ok`. So a root on an unmounted volume — or one the user
        // deleted, or one whose permissions changed — produces a perfectly
        // successful walk of **zero files**. Reconciling on that would mark
        // every row under the root `'missing'`, including every tiered file
        // whose catalog row is the only address of its remote bytes.
        //
        // The PM-3 check above does not cover this: it refuses a root the
        // catalog already *knows* is unavailable, and nothing marks a root
        // unavailable when it disappears underneath a running daemon.
        //
        // `dirs_visited == 0` is exactly "not even the root itself was read".
        // Failing here rather than skipping the sweep is deliberate: a scan
        // that could not open its own root has not scanned anything, and
        // reporting that as success is the completion this file already warns
        // about twice.
        if output.dirs_visited == 0 {
            let why = output
                .skipped
                .iter()
                .find_map(|s| match s {
                    Skip::Unreadable { path: p, detail } if *p == path => Some(detail.as_str()),
                    _ => None,
                })
                .unwrap_or("no directory under it could be read");
            return Err(format!(
                "root {root_id} at {} could not be read ({why}); refusing to treat an \
                 unreadable root as an empty one — a scan that observed nothing must not \
                 reconcile anything",
                root.path
            ));
        }

        let skipped = summarise_skips(&output.skipped);
        tracing::info!(
            root = root_id,
            files = output.files.len(),
            dirs = output.dirs_visited,
            %skipped,
            "walk complete"
        );

        // --- upsert -------------------------------------------------------
        let mut files_seen: u64 = 0;
        let mut bytes_seen: u64 = 0;
        let mut since_progress = 0usize;

        // The generation this scan stamps on every row it sees.
        //
        // The job id, deliberately. `last_seen_gen` only has to be **monotonic
        // per root** for the absence sweep it exists to feed
        // (`last_seen_gen < :this_scan`), and a job id already is: it is a
        // SQLite `INTEGER PRIMARY KEY` allocated when the job is enqueued, so a
        // later scan of a root always carries a larger one than any earlier
        // scan of that root.
        //
        // Rejected alternatives, because both fail in the direction that marks
        // present files missing:
        //
        // * a wall clock — an NTP step backwards mid-run makes a *later* scan
        //   carry an *earlier* generation, and the next sweep then deletes the
        //   world. `last_seen_gen` exists precisely so absence does not depend
        //   on a clock;
        // * a per-root counter column — the same value, plus a schema change
        //   and a read-modify-write to keep it monotonic.
        //
        // NOTE: nothing sweeps on this yet. Stamping it is correct and inert on
        // its own; the reconciliation that reads it is a separate decision.
        let generation = ctx.id().get();

        // `into_iter`, not `chunks`: every `FileStat` the walk produced is
        // moved into exactly one batch and from there into the writer actor.
        // Copying each chunk out of a borrowed slice instead would re-allocate
        // every `rel_path` on the way to the catalog — 10M `String`s on the
        // Phase 0d corpus, none of which outlives its batch, because `output`
        // is not read again after this loop.
        //
        // **The partial move of `output.files` is deliberate**, and it reads as
        // wrong at a glance, so: every other read of `output` completes above.
        // `output.dirs_visited` and `output.skipped` are read by the
        // unreadable-root guard, `summarise_skips(&output.skipped)` borrows a
        // *different* field of this same struct — a borrow that ends on its own
        // line — and `output.files.len()` is read by the `"walk complete"` log
        // just above. Nothing reads `output` after this point, which is what
        // makes moving one field out of it legal and what would have to be
        // rechecked before adding a read below.
        //
        // NOTE: this is the scale path, and it is not measured. The multi-batch
        // behaviour is exercised functionally by the scan e2e tests, but the
        // 10M-file case belongs to `the_m1_demo_holds_at_a_million_files`, which
        // is `#[ignore]`d behind `SHEPHERD_M1_CORPUS` — a corpus this box no
        // longer has. The allocation claim above is reasoning, not a benchmark.
        let root = Arc::new(root);
        let mut remaining = output.files.into_iter();
        loop {
            let batch: Vec<shepherd_core::FileStat> =
                remaining.by_ref().take(UPSERT_BATCH).collect();
            if batch.is_empty() {
                break;
            }
            // One refcount bump per batch, not a copy of the root: `ScanRoot`
            // is immutable for the whole scan and every batch reads the same
            // one, but the writer closure is `'static` and so cannot borrow it.
            let root_for_batch = Arc::clone(&root);
            let n = batch.len();
            let bytes: u64 = batch.iter().map(|f| f.size).sum();
            let last_path = batch.last().map(|f| f.rel_path.clone());

            self.writer()
                .try_with(move |cat| upsert_batch(cat, &root_for_batch, &batch, generation))
                .map_err(|e| format!("upserting a batch of {n}: {e}"))?;

            files_seen += n as u64;
            bytes_seen += bytes;
            since_progress += n;

            // Checkpoint every batch: it is one more field on a write the
            // actor is already doing, and it is what `scan.status` reads.
            ctx.save_checkpoint(
                &serde_json::json!({
                    "files_seen": files_seen,
                    "bytes_seen": bytes_seen,
                })
                .to_string(),
            )
            .map_err(|e| format!("checkpointing after {files_seen} files: {e}"))?;

            if since_progress >= PROGRESS_EVERY {
                since_progress = 0;
                self.publish(root_id, files_seen, bytes_seen, last_path, false);
            }
        }

        // The metadata index is an in-RAM projection of `file`, so a scan that
        // updated `file` and did not refresh it leaves `search` answering from
        // the pre-scan catalog — which looks exactly like a correct search that
        // found nothing. Refreshing here, before the job is marked done, is what
        // makes `shepctl scan start && shepctl search ...` deterministic.
        //
        // A failure fails the JOB rather than being logged and swallowed: a
        // "successful" scan whose results are unsearchable is the completion
        // this project keeps having to walk back.
        let entries = self.daemon.rebuild_index().map_err(|e| {
            format!("refreshing the metadata index after scanning root {root_id}: {e}")
        })?;

        self.publish(root_id, files_seen, bytes_seen, None, true);
        tracing::info!(
            root = root_id,
            files_seen,
            bytes_seen,
            indexed = entries,
            "scan complete"
        );
        Ok(())
    }
}

/// The root this executor may scan, plus its ignore patterns, in one actor
/// round-trip.
///
/// `ignore_patterns_json` and `enabled` are not on `ScanRoot` — `get_root` is
/// the *identity* view — so they are read here rather than widening that struct
/// for one caller.
///
/// `None` means **this root is not registered for scanning**, and it covers both
/// forms that takes. `root.remove --forget` deletes the row; the default
/// `root.remove` keeps the row and its catalog and clears `enabled`, because
/// `file.root_id` cascades and deleting the row would take every custody record
/// with it (see `dispatch::remove_root`). A queued job outliving either one must
/// not walk the tree the user just deregistered, and this is the single point
/// both reach.
fn load_scan_input(
    cat: &mut Catalog,
    id: RootId,
) -> Result<Option<(ScanRoot, Vec<String>)>, CatalogError> {
    let Some(root) = FileRepo::new(cat).get_root(id)? else {
        return Ok(None);
    };
    // `?`, not `unwrap_or(None)`. `None` here has to mean "the column holds
    // NULL", and nothing else: a failed read that becomes an empty list is a
    // root that silently excludes nothing, which is the same wrong direction
    // the malformed-JSON arm below refuses. `.optional()` keeps the one benign
    // absence — no such row — separate from a failure to read one.
    let row: Option<(Option<String>, bool)> = cat
        .conn()
        .query_row(
            "SELECT ignore_patterns_json, enabled FROM scan_root WHERE id = ?1",
            rusqlite::params![id.get()],
            |r| Ok((r.get(0)?, r.get::<_, i64>(1)? != 0)),
        )
        .optional()?;
    let Some((raw, enabled)) = row else {
        return Ok(None);
    };
    if !enabled {
        return Ok(None);
    }
    // A malformed pattern list must not silently become "ignore nothing":
    // AC-9's failure direction matters, because a file the user excluded
    // becoming eligible for tiering is the expensive mistake.
    let patterns: Vec<String> = match raw.as_deref() {
        None | Some("") => Vec::new(),
        Some(text) => serde_json::from_str(text).map_err(|e| {
            CatalogError::Invalid(format!(
                "root {id}'s ignore_patterns_json is not a JSON array of strings: {e}"
            ))
        })?,
    };
    Ok(Some((root, patterns)))
}

/// One transaction per batch, so a crash mid-scan leaves whole batches.
///
/// # Why `BEGIN`/`COMMIT` by hand instead of `Connection::transaction()`
///
/// Rows go through `FileRepo::upsert_file` — the catalog's own statement, the
/// one that knows `first_seen_at` is never overwritten and that `blake3`
/// coalesces. Reproducing that SQL here would be a second implementation of the
/// same write, and its derived columns (`name`, `ext`, `norm_key`) would drift
/// from the original the first time either changed. AC-13 matches on `ext`, so
/// a drift there is a rule that silently stops matching.
///
/// An earlier draft of this file did copy the statement, together with a
/// hand-written *guess* at the catalog's private `split_name` — which is
/// precisely the duplication this executor's own handoff notes warn T7 against,
/// and it would have been unverifiable besides.
///
/// But `upsert_file` takes `&mut Catalog` and `Connection::transaction()`
/// borrows the connection for the guard's lifetime, so the two cannot be held
/// at once. Explicit `BEGIN`/`COMMIT` around the loop is what lets one
/// transaction wrap N calls to the owner's method.
///
/// Without a transaction each row is its own implicit one, and the catalog runs
/// `synchronous = FULL` — an fsync per file, across a million of them.
///
/// The rollback is not optional: an open transaction left behind would hold the
/// writer actor's connection inside it forever, and every later write in the
/// process would silently join it.
fn upsert_batch(
    cat: &mut Catalog,
    root: &ScanRoot,
    batch: &[shepherd_core::FileStat],
    generation: i64,
) -> Result<(), CatalogError> {
    cat.conn().execute_batch("BEGIN")?;
    let stamp = now();
    for stat in batch {
        if let Err(e) = FileRepo::new(cat).upsert_file(root, stat, generation, stamp) {
            let _ = cat.conn().execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    cat.conn().execute_batch("COMMIT")?;
    Ok(())
}

/// A one-line summary of what the walk did not look at.
///
/// Reported rather than swallowed: a scan that quietly skipped half a tree
/// looks identical to one that found half a tree.
fn summarise_skips(skips: &[Skip]) -> String {
    let (mut denied, mut cycles, mut ignored, mut symlinked, mut unreadable, mut unrepresentable) =
        (0, 0, 0, 0, 0, 0);
    for s in skips {
        match s {
            Skip::Denied { .. } => denied += 1,
            Skip::Cycle { .. } => cycles += 1,
            Skip::Ignored { .. } => ignored += 1,
            Skip::SymlinkedDir { .. } => symlinked += 1,
            Skip::Unreadable { .. } => unreadable += 1,
            Skip::Unrepresentable { .. } => unrepresentable += 1,
        }
    }
    format!(
        "denied={denied} cycles={cycles} ignored={ignored} \
         symlinked_dirs={symlinked} unreadable={unreadable} \
         unrepresentable={unrepresentable}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A root with `patterns`, in a fresh in-memory catalog.
    fn seeded_root(patterns: &[String]) -> (Catalog, RootId) {
        let mut cat = Catalog::open_in_memory().unwrap();
        let id = FileRepo::new(&mut cat)
            .insert_root(
                "/data",
                shepherd_core::StubMode::Delete,
                shepherd_catalog::PathCasePolicy::Sensitive,
                shepherd_catalog::PathNormPolicy::Nfc,
                shepherd_catalog::AtimeMode::Relatime,
                None,
                false,
                patterns,
                shepherd_core::Timestamp::from_nanos(1),
            )
            .unwrap();
        (cat, id)
    }

    /// The ordinary path, asserted so the refusal below cannot be satisfied by
    /// a `load_scan_input` that has simply stopped working.
    #[test]
    fn a_roots_stored_ignore_patterns_reach_the_scan() {
        let (mut cat, id) = seeded_root(&["*.tmp".to_string(), "cache/".to_string()]);
        let (_root, patterns) = load_scan_input(&mut cat, id).unwrap().unwrap();
        assert_eq!(patterns, vec!["*.tmp".to_string(), "cache/".to_string()]);
    }

    /// A catalog failure reading the ignore list must fail the scan, not read
    /// as "this root excludes nothing".
    ///
    /// The direction is the whole point, and it is the one the malformed-JSON
    /// arm of the same function already gets right: a file the user explicitly
    /// excluded, catalogued anyway, becomes a tiering candidate. `unwrap_or(None)`
    /// collapsed *every* failure of this query — transient, corrupt row, type
    /// mismatch — into the empty list, which is indistinguishable on the far
    /// side from a root that legitimately names no exclusions.
    ///
    /// The blob stands in for that class of failure: SQLite's TEXT affinity
    /// stores a blob as a blob, so reading the column as text fails the way a
    /// corrupt row would.
    #[test]
    fn a_catalog_failure_reading_the_ignore_list_fails_the_scan() {
        let (mut cat, id) = seeded_root(&["*.tmp".to_string()]);
        cat.conn_mut()
            .execute(
                "UPDATE scan_root SET ignore_patterns_json = X'00ff' WHERE id = ?1",
                rusqlite::params![id.get()],
            )
            .unwrap();

        let err = load_scan_input(&mut cat, id)
            .expect_err("a failed read of the ignore list must not be reported as `no patterns`");
        assert!(
            err.to_string().contains("ignore_patterns_json"),
            "the error must name the column that could not be read, got: {err}"
        );
    }

    /// A deregistered root must not be walked by a job that outlived it.
    ///
    /// `root.remove` without `--forget` now keeps the row and every catalog row
    /// under it and clears `enabled`, because deleting the row cascades away the
    /// custody records (see `dispatch::remove_root`). That is the only reason a
    /// `scan_root` row can be present and yet not be a scan target, and if this
    /// executor did not know the difference, removing a root would stop the
    /// listing without stopping the scanning.
    #[test]
    fn a_deregistered_root_is_not_a_scan_target() {
        let (mut cat, id) = seeded_root(&[]);
        assert!(
            load_scan_input(&mut cat, id).unwrap().is_some(),
            "the root is scannable while it is registered"
        );

        cat.conn_mut()
            .execute(
                "UPDATE scan_root SET enabled = 0 WHERE id = ?1",
                rusqlite::params![id.get()],
            )
            .unwrap();

        assert!(
            load_scan_input(&mut cat, id).unwrap().is_none(),
            "a root the user removed must not be scanned merely because its catalog was kept"
        );
    }

    #[test]
    fn skips_are_summarised_by_kind() {
        let skips = vec![
            Skip::Ignored { path: "a".into() },
            Skip::Ignored { path: "b".into() },
            Skip::Cycle { path: "c".into() },
        ];
        let s = summarise_skips(&skips);
        assert!(s.contains("ignored=2"), "{s}");
        assert!(s.contains("cycles=1"), "{s}");
        assert!(s.contains("denied=0"), "{s}");
    }
}
