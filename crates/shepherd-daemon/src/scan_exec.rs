//! The `scan` job executor: walk a root, upsert what it finds.
//!
//! This is the piece `main.rs` left a `ponytail:` note for — the empty
//! `Registry` now has one entry. With it, `shepctl root add && shepctl scan`
//! reaches the catalog, which is two of the three legs of §6 Phase 1's M1
//! demo. The third, `shepctl search`, is T7's index.
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

use shepherd_catalog::file_repo::{Availability, FileRepo, ScanRoot};
use shepherd_catalog::writer::CatalogWriter;
use shepherd_catalog::{Catalog, CatalogError};
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
            // Not retryable in any useful sense — the root is gone. Returning
            // Err lets the queue's backoff run its course and record why,
            // rather than reporting success for work that did not happen.
            return Err(format!("scan root {root_id} no longer exists"));
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
        let deny = DenyList::builtin();
        let ignores = IgnoreSet::new(&path, &patterns)
            .map_err(|e| format!("root {root_id} has an unusable ignore pattern: {e}"))?;

        self.publish(root_id, 0, 0, Some(root.path.clone()), false);

        // --- walk ---------------------------------------------------------
        // On the worker thread, deliberately: this is the I/O-heavy half and
        // must not run inside the single-writer actor.
        let output = walk(rid, &path, &deny, &ignores, now())
            .map_err(|e| format!("walking {}: {e}", root.path))?;

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

        for chunk in output.files.chunks(UPSERT_BATCH) {
            let batch: Vec<shepherd_core::FileStat> = chunk.to_vec();
            let root_for_batch = root.clone();
            let n = batch.len();
            let bytes: u64 = batch.iter().map(|f| f.size).sum();
            let last_path = batch.last().map(|f| f.rel_path.clone());

            self.writer()
                .try_with(move |cat| upsert_batch(cat, &root_for_batch, &batch))
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

        self.publish(root_id, files_seen, bytes_seen, None, true);
        tracing::info!(root = root_id, files_seen, bytes_seen, "scan complete");
        Ok(())
    }
}

/// The root plus its ignore patterns, in one actor round-trip.
///
/// `ignore_patterns_json` is not on `ScanRoot` — `get_root` is the *identity*
/// view — so it is read here rather than widening that struct for one caller.
fn load_scan_input(
    cat: &mut Catalog,
    id: RootId,
) -> Result<Option<(ScanRoot, Vec<String>)>, CatalogError> {
    let Some(root) = FileRepo::new(cat).get_root(id)? else {
        return Ok(None);
    };
    let raw: Option<String> = cat
        .conn()
        .query_row(
            "SELECT ignore_patterns_json FROM scan_root WHERE id = ?1",
            rusqlite::params![id.get()],
            |r| r.get(0),
        )
        .unwrap_or(None);
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
) -> Result<(), CatalogError> {
    cat.conn().execute_batch("BEGIN")?;
    let stamp = now();
    for stat in batch {
        if let Err(e) = FileRepo::new(cat).upsert_file(root, stat, stamp) {
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
    let (mut denied, mut cycles, mut ignored, mut symlinked, mut unreadable) = (0, 0, 0, 0, 0);
    for s in skips {
        match s {
            Skip::Denied { .. } => denied += 1,
            Skip::Cycle { .. } => cycles += 1,
            Skip::Ignored { .. } => ignored += 1,
            Skip::SymlinkedDir { .. } => symlinked += 1,
            Skip::Unreadable { .. } => unreadable += 1,
        }
    }
    format!(
        "denied={denied} cycles={cycles} ignored={ignored} \
         symlinked_dirs={symlinked} unreadable={unreadable}"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

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
