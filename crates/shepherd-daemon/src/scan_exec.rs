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

/// Full-tree walks that may be resident at once.
///
/// `shepherd_scan::walk` materialises the complete `Vec<FileStat>` before
/// batching, so a scan holds an entire tree for its duration — and the pool
/// runs `POOL_SIZE` workers. Per-root coalescing stops the same root being
/// walked twice; it says nothing about four DIFFERENT large roots, which is
/// the memory case unchanged.
///
/// Two, against a pool of four, so at most half the workers can be waiting here
/// and the other classes keep making progress. That asymmetry is the whole
/// reason this is a bound rather than a lock.
///
/// **This is a mitigation, not the fix.** The fix is a streaming walk that
/// never holds the tree, which is `shepherd-scan`'s to make; this bounds the
/// blast radius of the shape that exists today.
const MAX_CONCURRENT_WALKS: usize = 2;

/// How long a scan waits for a walk permit before giving the worker back.
///
/// A parked worker is a worker not running anything else, and `Pool::shutdown`
/// joins its threads — so an unbounded wait is a hung shutdown as well as a
/// starved queue. Giving up requeues the job with the queue's own backoff,
/// which costs one attempt in a case that only arises when two large scans are
/// already running.
const WALK_PERMIT_WAIT: std::time::Duration = std::time::Duration::from_secs(30);

static WALKS: std::sync::Mutex<usize> = std::sync::Mutex::new(0);
static WALK_FREED: std::sync::Condvar = std::sync::Condvar::new();

/// One in-flight full-tree walk, released on drop.
struct WalkPermit;

impl WalkPermit {
    /// Wait up to [`WALK_PERMIT_WAIT`] for a slot.
    fn acquire() -> Option<Self> {
        let deadline = std::time::Instant::now() + WALK_PERMIT_WAIT;
        let mut n = WALKS.lock().unwrap_or_else(|e| e.into_inner());
        loop {
            if *n < MAX_CONCURRENT_WALKS {
                *n += 1;
                return Some(Self);
            }
            let left = deadline.checked_duration_since(std::time::Instant::now())?;
            // `wait_timeout` rather than `wait`: a worker parked forever is a
            // hung `Pool::shutdown`, and the queue's backoff is a better place
            // to wait than a condvar nobody will signal if the running scans
            // are slow.
            let (guard, _) = WALK_FREED
                .wait_timeout(n, left)
                .unwrap_or_else(|e| e.into_inner());
            n = guard;
        }
    }
}

impl Drop for WalkPermit {
    fn drop(&mut self) {
        let mut n = WALKS.lock().unwrap_or_else(|e| e.into_inner());
        *n = n.saturating_sub(1);
        WALK_FREED.notify_one();
    }
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
        //
        // Only when the path is THERE. A root whose directory has been deleted
        // has no identity to report either, and the walk's own
        // unreadable-root refusal says something truer about it than "no
        // stable identity" would — this check is about a path that still
        // resolves and now belongs to a different filesystem, which is
        // precisely the case a deleted root is not.
        // The device is sampled on BOTH sides of the identity lookup, and the
        // two must agree.
        //
        // Sampling only afterwards left a window of its own: `current_volume_id`
        // could validate the enrolled filesystem and the sample a moment later
        // record a replacement's device, so the walk and the post-walk check
        // would agree with each other about a volume the identity lookup never
        // saw. Bracketing the lookup makes the recorded device one the
        // validation actually applies to — if anything moved across it, the
        // two samples differ and there is no validated device to record.
        let present = std::fs::symlink_metadata(&path).is_ok();
        let dev_before = present.then(|| device_of(&path)).flatten();
        if present
            && let Some(reason) = volume_refusal(
                rid,
                &root.path,
                root.volume_id.as_deref(),
                shepherd_catalog::volume::current_volume_id(&path).as_deref(),
            )
        {
            return Err(reason);
        }
        let dev_after = present.then(|| device_of(&path)).flatten();
        if present && dev_before != dev_after {
            return Err(format!(
                "the filesystem at root {root_id} ({}) changed while its identity was being \
                 verified, so nothing about it has been established. Nothing has been \
                 committed. Re-run the scan once the mount is stable",
                root.path
            ));
        }
        let checked_dev = dev_after;

        self.publish(root_id, 0, 0, Some(root.path.clone()), false);

        // --- walk ---------------------------------------------------------
        // On the worker thread, deliberately: this is the I/O-heavy half and
        // must not run inside the single-writer actor.
        //
        // Under a permit, because the walk MATERIALISES the tree — see
        // `MAX_CONCURRENT_WALKS`. Held past the batching loop below, since the
        // `Vec<FileStat>` it bounds is alive until that loop has drained it.
        let Some(_walk_permit) = WalkPermit::acquire() else {
            // DEFERRED, not failed. This attempt discovered nothing and changed
            // nothing — two large walks are simply already in flight — and
            // reporting it as a failure spent one of the queue's five attempts.
            // Two 10-million-file scans hold their permits for far longer than
            // five 30-second waits, so a third scan became terminally `failed`
            // without anything ever having gone wrong. `JobContext::defer`
            // gives back the attempt the claim took.
            ctx.defer(shepherd_core::Timestamp::from_nanos(
                now().as_nanos() + WALK_PERMIT_WAIT.as_nanos() as i64,
            ));
            tracing::info!(
                root = root_id,
                "deferring: {MAX_CONCURRENT_WALKS} full-tree walks are already in flight, and \
                 each holds an entire tree in memory"
            );
            return Ok(());
        };
        let output = walk(rid, &path, &deny, &ignores, now())
            .map_err(|e| format!("walking {}: {e}", root.path))?;

        // RE-ASKED, after the walk and before anything is committed.
        //
        // The check above and the walk are two pathname operations, so a volume
        // unmounted, replaced, or a registered symlink retargeted in between
        // leaves the walker reading a different filesystem entirely — capturing
        // its device as `root_dev`, accepting its inode sightings, and handing
        // them to `upsert_file` to be paired with the enrolled volume's id.
        //
        // Pinning the traversal to an opened directory would close the window
        // rather than narrow it, and that is `openat`-relative walking: a
        // change to every step of `shepherd_scan::walk`, tracked in #3 with the
        // other residuals of this shape. What this does instead is put the
        // check on the other side of the harm. The walk reading the wrong tree
        // costs nothing by itself; COMMITTING it is what writes false
        // identities, so the last thing before the commit is asking whether the
        // filesystem is still the one that was verified.
        //
        // Compared on `st_dev` rather than by re-deriving the volume id: this
        // is the same question over a much shorter interval, and `st_dev` is
        // exactly what the walker keyed its sightings on.
        if checked_dev.is_some() && device_of(&path) != checked_dev {
            return Err(format!(
                "the filesystem at root {root_id} ({}) changed while it was being walked, so \
                 the files this pass observed belong to a volume that was never verified. \
                 Nothing has been committed. Re-run the scan once the mount is stable",
                root.path
            ));
        }

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
        // Whether any batch has reached the catalog. See `abandon`.
        let mut committed = false;

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

            // ONCE A BATCH HAS LANDED, every way out of this loop owes the
            // index an invalidation.
            //
            // The rebuild below invalidates when the rebuild itself fails, and
            // that covered one exit of several. A checkpoint that fails after
            // batches have committed — running out of space is the obvious
            // one, and SQLite stays readable through it — returned straight
            // out of the executor, leaving the pre-scan arena installed and
            // `search` unable to find rows that are already in the catalog.
            // Once the retries are exhausted that answer is permanent, and it
            // is indistinguishable from a correct search that found nothing.
            //
            // `committed` is what separates "this scan changed the catalog"
            // from "it failed before touching it"; the second owes nothing.
            match self
                .writer()
                .try_with(move |cat| upsert_batch(cat, &root_for_batch, &batch, generation))
            {
                Ok(()) => committed = true,
                Err(e) => {
                    return Err(self.abandon(committed, format!("upserting a batch of {n}: {e}")));
                }
            }

            files_seen += n as u64;
            bytes_seen += bytes;
            since_progress += n;

            // Checkpoint every batch: it is one more field on a write the
            // actor is already doing, and it is what `scan.status` reads.
            if let Err(e) = ctx.save_checkpoint(
                &serde_json::json!({
                    "files_seen": files_seen,
                    "bytes_seen": bytes_seen,
                })
                .to_string(),
            ) {
                return Err(self.abandon(
                    committed,
                    format!("checkpointing after {files_seen} files: {e}"),
                ));
            }

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
        // A failure INVALIDATES the installed index as well as failing the job.
        //
        // Failing the job alone left the pre-scan arena installed, and
        // `Daemon::index` has no freshness check — it hands out whatever is
        // there. Every file this scan committed was then missing from `search`,
        // indefinitely once the retries ran out, while hydration itself was
        // perfectly healthy. That is a search answering confidently from a
        // catalog that no longer exists, which is the one thing an absent index
        // is honest about and a stale one is not.
        //
        // The watermark is taken the same way `root_remove` takes it, under the
        // ticket lock, so a rebuild that pinned AFTER this scan's batches
        // committed already reflects them and survives.
        let entries = match self.daemon.rebuild_index() {
            Ok(n) => n,
            Err(e) => {
                return Err(self.abandon(
                    committed,
                    format!("refreshing the metadata index after scanning root {root_id}: {e}"),
                ));
            }
        };

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

impl ScanExecutor {
    /// End a scan that failed, leaving the index honest about it.
    ///
    /// A scan that committed batches and then failed has changed the catalog
    /// the installed index was built from. Failing the job alone leaves that
    /// arena serving rows from before the scan — a `search` that confidently
    /// finds nothing, which is the one thing an ABSENT index is honest about
    /// and a stale one is not. The watermark is taken here rather than up
    /// front, and that is what makes it tight: taken now it is necessarily
    /// after the last batch that landed, so no snapshot pinned before that
    /// batch can install afterwards.
    ///
    /// A scan that failed before its first batch owes nothing — it changed
    /// nothing — and invalidating there would refuse `search` for a scan that
    /// never touched the catalog.
    fn abandon(&self, committed: bool, detail: String) -> String {
        if committed {
            let (_, mutated_at) = self.daemon.with_catalog_mutation(|| ());
            self.daemon.invalidate_index(mutated_at);
        }
        detail
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

    // STILL REGISTERED, re-read inside the transaction that writes.
    //
    // `load_scan_input` checked this once, before the walk. A default
    // `root.remove` keeps the row and its catalog and clears `enabled` — it
    // does not delete the row, because `file.root_id` cascades and deleting it
    // would take every custody record with it — so the foreign key these
    // upserts satisfy is still there and a scan walking a large tree went on
    // adding and updating files after removal had reported success, then
    // rebuilt the index from them.
    //
    // In the SAME transaction as the writes, not before the call: the writer
    // actor is single-threaded, so a check inside its transaction and the
    // upserts that follow cannot be separated by another writer. A check in
    // the executor would be a read the removal could land behind.
    let enabled: bool = cat
        .conn()
        .query_row(
            "SELECT enabled FROM scan_root WHERE id = ?1",
            [root.id.get()],
            |r| r.get::<_, i64>(0).map(|v| v != 0),
        )
        .unwrap_or(false);
    if !enabled {
        let _ = cat.conn().execute_batch("ROLLBACK");
        return Err(CatalogError::Invalid(format!(
            "root {} was deregistered while this scan was walking it, so these {} rows are \
             not ours to write",
            root.id.get(),
            batch.len()
        )));
    }

    let stamp = now();
    for stat in batch {
        if let Err(e) = FileRepo::new(cat).upsert_file(root, stat, generation, stamp) {
            let _ = cat.conn().execute_batch("ROLLBACK");
            return Err(e);
        }
    }
    // A FAILED COMMIT may leave the transaction open.
    //
    // Every other failure path here rolls back, and this one returned through
    // `?` — on the assumption that a failed COMMIT has ended the transaction.
    // `SQLITE_BUSY` is the counterexample: it can leave the transaction ACTIVE
    // for the caller to retry. This is the daemon's long-lived writer
    // connection, so the next actor operation then either fails with "cannot
    // start a transaction within a transaction" or, worse, runs inside the
    // abandoned scan transaction — one transient failure stalling catalog
    // writes for everything after it.
    //
    // `is_autocommit` rather than an unconditional ROLLBACK: rolling back when
    // the commit DID end the transaction is an error of its own, and swallowing
    // that would hide the case this exists to handle.
    if let Err(e) = cat.conn().execute_batch("COMMIT") {
        if !cat.conn().is_autocommit() {
            let _ = cat.conn().execute_batch("ROLLBACK");
        }
        return Err(e.into());
    }
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

/// The device number behind a path, or `None` if it cannot be read.
///
/// A coarser identity than `volume_id` and the right one for this job: it
/// answers "is this the same mounted filesystem as a moment ago", which is what
/// a check taken on both sides of a walk is asking.
fn device_of(path: &std::path::Path) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(path).ok().map(|md| md.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        None
    }
}

/// Whether the filesystem mounted at a root disagrees with the one it was
/// enrolled on.
///
/// Separated from the probe so the DECISION is testable without a filesystem.
/// Asking the OS for a volume id is environment-dependent — a machine with no
/// `/dev/disk/by-uuid`, an overlay root, or any platform whose implementation
/// is Phase 3's all answer `None` — and a test that depended on the answer
/// would assert this rule only on the machines that happen to have one.
///
/// The two `None`s are not symmetric, and the asymmetry is the point.
///
/// **`enrolled` is `None`** — nothing to disagree with. That root was recorded
/// without a stable identity, which `root.add` warns about, and no platform
/// outside Linux can answer at all until Phase 3. Refusing here would refuse
/// every scan on macOS and Windows for a check that could never have run.
///
/// **`current` is `None` while `enrolled` is `Some`** — a refusal. This root
/// HAS an identity and the filesystem at its path will not say whether it is
/// the same one, which is not the same as saying it is. It is what an unmounted
/// removable disk looks like: the mount point is still a readable directory, on
/// whatever overlay or tmpfs parent it sits on, and that parent has no stable
/// identity to report. Walking it pairs the parent's inode numbers with the
/// enrolled volume's id and writes `fs_id` values that are well-formed and name
/// files on neither filesystem.
///
/// Unverifiable is not verified. The direction is the same one PM-3 takes for
/// an unreadable root: absence of evidence about a destructive precondition is
/// a refusal, never a pass.
fn volume_refusal(
    root_id: RootId,
    path: &str,
    enrolled: Option<&str>,
    current: Option<&str>,
) -> Option<String> {
    let enrolled = enrolled?;
    let Some(current) = current else {
        return Some(format!(
            "root {root_id} at {path} was enrolled on volume `{enrolled}` and the filesystem \
             mounted there now reports no stable identity at all. That is what an unmounted \
             volume looks like — the mount point is still a readable directory on its parent \
             — and scanning it would pair the parent's inode numbers with the enrolled \
             volume's id, producing `fs_id` values that name files on neither. Mount the \
             volume, or resynchronise the root if it really has moved"
        ));
    };
    if enrolled == current {
        return None;
    }
    Some(format!(
        "root {root_id} at {path} was enrolled on volume `{enrolled}` and the filesystem \
         mounted there now is `{current}`. Scanning would pair this volume's inode numbers \
         with the enrolled volume's id, producing `fs_id` values that look valid and name \
         files on neither. Re-point the root, or resynchronise it if the volume really was \
         replaced"
    ))
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

    /// A volume swapped under a root is a refusal; everything else is not.
    ///
    /// The harm is quiet: a removable disk replaced at the same mount point, or
    /// a registered symlink retargeted, walks perfectly happily and
    /// `upsert_file` pairs the NEW volume's inode numbers with the OLD volume
    /// id. Those `fs_id` values are well-formed and name files on neither
    /// volume.
    ///
    /// All four combinations, because three of them must NOT refuse and each
    /// is a different reason: identical identities are the ordinary case; a
    /// root with no recorded identity has nothing to disagree with; and a
    /// platform that cannot answer must not have every scan refused for it.
    #[test]
    fn a_volume_that_disagrees_with_the_enrolled_one_refuses_the_scan() {
        let id = RootId::new(7);

        let refusal = volume_refusal(id, "/data", Some("uuid:aaa"), Some("uuid:bbb"))
            .expect("a different filesystem at the same path must refuse");
        assert!(
            refusal.contains("uuid:aaa") && refusal.contains("uuid:bbb"),
            "the refusal must name both identities: {refusal}"
        );

        assert_eq!(
            volume_refusal(id, "/data", Some("uuid:aaa"), Some("uuid:aaa")),
            None,
            "the same volume is the ordinary case and must scan"
        );
        // The asymmetric pair. An enrolled root with no answer is a refusal
        // above; a root that never had an identity has nothing to disagree
        // with, and refusing it would refuse every scan on a platform whose
        // implementation is Phase 3's.
        assert_eq!(
            volume_refusal(id, "/data", None, Some("uuid:bbb")),
            None,
            "a root enrolled without a stable identity has nothing to disagree \
             with; that case is warned about at `root.add`"
        );
        assert_eq!(volume_refusal(id, "/data", None, None), None);
        let unverifiable = volume_refusal(id, "/data", Some("uuid:aaa"), None).expect(
            "a root WITH an identity must not be scanned against a filesystem \
                     that will not say whether it is the same one",
        );
        assert!(
            unverifiable.contains("no stable identity"),
            "the refusal must say what was missing: {unverifiable}"
        );
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
