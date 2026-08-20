//! Reads and writes over `scan_root` and `file`.
//!
//! The one thing to understand before changing anything here: **lookups that
//! answer "does this file still exist?" go through `norm_key`, never
//! `rel_path`.** A watcher event arriving in a different Unicode normalization
//! than the scan that wrote the row produces a `rel_path` miss, the miss reads
//! as absence, and PM-3 calls absence discard-trigger territory. `rel_path`
//! remains the unique key for *storage*; `norm_key` is the key for *matching*.

use rusqlite::{OptionalExtension, params};
use shepherd_core::{Blake3Hash, FileStat, InodeSighting, RootId, StubMode, Timestamp};

use crate::atime::AtimeMode;
use crate::identity::{PathCasePolicy, PathNormPolicy, norm_key};
use crate::{Catalog, CatalogError, Result};

/// A registered scan root, as far as identity is concerned.
#[derive(Debug, Clone)]
pub struct ScanRoot {
    pub id: RootId,
    pub path: String,
    pub stub_mode: StubMode,
    pub case_policy: PathCasePolicy,
    pub norm_policy: PathNormPolicy,
    pub atime_mode: AtimeMode,
    pub volume_id: Option<String>,
    /// PM-3: while set, ALL tiering, destruction and discard for this root are
    /// refused.
    pub resync_required: bool,
    pub availability: Availability,
    /// D-12 (§4.10.1): this root's filesystem supports neither identity-bound
    /// staging nor enforceable writer exclusion, so its originals are NEVER
    /// destroyed. Set by a feasibility probe at enrollment, never discovered at
    /// destroy time.
    pub destruction_ineligible: bool,
    pub destruction_ineligible_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    Unavailable,
    Unmounted,
}

impl Availability {
    pub fn as_str(self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::Unavailable => "unavailable",
            Availability::Unmounted => "unmounted",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "available" => Availability::Available,
            "unavailable" => Availability::Unavailable,
            "unmounted" => Availability::Unmounted,
            _ => return None,
        })
    }
}

impl ScanRoot {
    /// Whether this root may take part in any operation that destroys anything.
    ///
    /// Both guards are PM-3's. A root needing resync has a gap in its event
    /// history, so its catalog rows may not reflect the disk. An unavailable
    /// root cannot be observed at all, and §4.4 is explicit that such a root
    /// "processes ZERO absences" — a file missing from an unmounted volume is
    /// not evidence the user deleted it.
    pub fn may_destroy(&self) -> bool {
        !self.resync_required
            && self.availability == Availability::Available
            && !self.destruction_ineligible
    }

    /// Why destruction is refused, for the preview and the audit record. `None`
    /// when it is permitted.
    ///
    /// One place rather than three call sites: a gate that has to be remembered
    /// at each use is a gate that will eventually be forgotten at one of them.
    pub fn destroy_refusal(&self) -> Option<String> {
        if self.resync_required {
            return Some(
                "root requires resync: the watcher journal overflowed, so the catalog may \
                 not reflect the disk (PM-3)"
                    .into(),
            );
        }
        if self.availability != Availability::Available {
            return Some(format!(
                "root is {}: an unavailable root processes zero absences (PM-3 #2)",
                self.availability.as_str()
            ));
        }
        if self.destruction_ineligible {
            return Some(
                self.destruction_ineligible_reason
                    .clone()
                    .unwrap_or_else(|| "root is destruction_ineligible (D-12)".into()),
            );
        }
        None
    }

    /// The `norm_key` for a path under this root, using this root's policies.
    pub fn norm_key(&self, rel_path: &str) -> String {
        norm_key(rel_path, self.case_policy, self.norm_policy)
    }
}

pub struct FileRepo<'a>(pub &'a mut Catalog);

impl<'a> FileRepo<'a> {
    pub fn new(cat: &'a mut Catalog) -> Self {
        Self(cat)
    }

    /// Register a scan root with its probed identity policies.
    ///
    /// # Why `hosted_optin` and `ignore_patterns` are parameters and not
    /// defaults
    ///
    /// Both columns existed from migration 0001 and neither was ever written.
    /// `hosted_optin` is a **consent** flag — `DEFAULT 0` made every root read
    /// back as "the user did not consent", which is the safe direction and
    /// therefore the one nobody notices; a user who *did* consent was silently
    /// overruled. `ignore_patterns_json`'s `DEFAULT '[]'` was the opposite
    /// direction and worse: a user's exclusions silently did not exist, so
    /// AC-9's matcher honoured an empty list on every scan that has ever run.
    ///
    /// Passing both here rather than defaulting them is what makes this
    /// function the single producer for each. Callers state consent and
    /// exclusions explicitly or not at all.
    ///
    /// `ignore_patterns` is stored as the JSON array `scan_exec` reads back.
    /// It is **not** validated here — `shepherd-catalog` may not depend on
    /// `shepherd-scan`, so the compile happens at the registration boundary
    /// (`dispatch::root_add`) where a bad pattern can still be refused.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_root(
        &mut self,
        path: &str,
        stub_mode: StubMode,
        case_policy: PathCasePolicy,
        norm_policy: PathNormPolicy,
        atime_mode: AtimeMode,
        volume_id: Option<&str>,
        hosted_optin: bool,
        ignore_patterns: &[String],
        now: Timestamp,
    ) -> Result<RootId> {
        let stub = match stub_mode {
            StubMode::Dehydrate => "dehydrate",
            StubMode::Delete => "delete",
        };
        let patterns_json = serde_json::to_string(ignore_patterns).map_err(|e| {
            CatalogError::Invalid(format!("ignore patterns are not serializable as JSON: {e}"))
        })?;
        self.0.conn_mut().execute(
            "INSERT INTO scan_root
                 (path, stub_mode, path_case_policy, path_norm_policy, atime_mode,
                  volume_id, hosted_optin, ignore_patterns_json, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                path,
                stub,
                case_policy.as_str(),
                norm_policy.as_str(),
                atime_mode.as_str(),
                volume_id,
                hosted_optin as i64,
                patterns_json,
                now.as_nanos()
            ],
        )?;
        Ok(RootId::new(self.0.conn().last_insert_rowid()))
    }

    /// Enroll `path` as a scan root, reviving a soft-removed one if that is what
    /// is there.
    ///
    /// # Why this exists
    ///
    /// The default `root.remove` deliberately keeps the `scan_root` row and
    /// every file row under it, because `file.root_id` cascades and a tiered
    /// file's catalog row is the only address of its remote bytes. Nothing ever
    /// set `enabled` back to 1, and `scan_root.path` is `NOT NULL UNIQUE` — so
    /// a plain insert made the retained state permanently unreachable. The only
    /// recovery was `--forget`, which destroys precisely what the retention was
    /// protecting. This is the way back in.
    ///
    /// # The three outcomes, and why the third is a refusal
    ///
    /// * no row → an ordinary first enrollment;
    /// * a **disabled** row → revived, catalog intact;
    /// * an **enabled** row → [`CatalogError::AlreadyInState`]. That is a
    ///   genuine duplicate, and it must stay refused: silently reactivating an
    ///   already-live root would let a second `root.add` rewrite a running
    ///   root's settings with no indication it had done so. `AlreadyInState`
    ///   maps to `Precondition` at the transport, which a caller retrying after
    ///   a crash can read as "already done" — the raw unique-constraint error it
    ///   replaces mapped to `Io` and read as "storage broke".
    ///
    /// # What is rewritten on a revival, and what is not
    ///
    /// **Rewritten**: `stub_mode`, `hosted_optin`, `ignore_patterns_json`,
    /// `volume_id`, `atime_mode`. The first three are user intent, stated afresh
    /// in this request; keeping the stored copies would reproduce the
    /// `ignore_patterns_json DEFAULT '[]'` failure this module already documents
    /// — a user's exclusions silently not existing. The last two are facts about
    /// the volume that may genuinely have changed across a remount.
    ///
    /// **NOT rewritten**: `path_case_policy` and `path_norm_policy`. Every
    /// retained file row carries a `norm_key` *derived* from those two policies,
    /// and `find_by_norm_key` is what watcher events match against. Swapping the
    /// policies without recomputing every key makes those lookups miss, and a
    /// miss reads as absence — which §4.9 PM-3 puts in discard-trigger territory.
    /// So the stored pair wins and a disagreement with the fresh probe is
    /// **reported** instead, via `kept_policies`. Recomputing the keys is the
    /// real fix and it is a migration, not a review-round change.
    ///
    /// **NOT touched at all**: the `file` table. Not one row, not one column.
    /// A re-enrollment establishes nothing about custody — it has not stat'd
    /// anything — so folding retained rows back to `'local'` would revoke
    /// custody on exactly the tiered files this retention exists to protect.
    /// The next scan is what re-establishes what is on disk.
    #[allow(clippy::too_many_arguments)]
    pub fn enroll_root(
        &mut self,
        path: &str,
        stub_mode: StubMode,
        case_policy: PathCasePolicy,
        norm_policy: PathNormPolicy,
        atime_mode: AtimeMode,
        volume_id: Option<&str>,
        hosted_optin: bool,
        ignore_patterns: &[String],
        now: Timestamp,
    ) -> Result<Enrollment> {
        // One SELECT and one write, in one call, made atomic by the fact that
        // every catalog write in the daemon goes through the single-threaded
        // writer actor (`CatalogWriter`) — this whole function runs inside one
        // of its closures. Splitting the lookup and the write across two
        // `Session::cat` calls would put a real TOCTOU window between them.
        let existing: Option<(i64, bool, String, String, Option<String>)> = self
            .0
            .conn()
            .query_row(
                "SELECT id, enabled, path_case_policy, path_norm_policy, volume_id
                 FROM scan_root WHERE path = ?1",
                params![path],
                |r| {
                    Ok((
                        r.get(0)?,
                        r.get::<_, i64>(1)? != 0,
                        r.get(2)?,
                        r.get(3)?,
                        r.get::<_, Option<String>>(4)?,
                    ))
                },
            )
            .optional()?;

        let Some((id, enabled, stored_case, stored_norm, stored_volume)) = existing else {
            return Ok(Enrollment::Created(self.insert_root(
                path,
                stub_mode,
                case_policy,
                norm_policy,
                atime_mode,
                volume_id,
                hosted_optin,
                ignore_patterns,
                now,
            )?));
        };
        if enabled {
            return Err(CatalogError::AlreadyInState(format!(
                "`{path}` is already registered as an enabled scan root (id {id})"
            )));
        }

        // The retained catalog was built against the OLD volume, so the old
        // volume is what it still describes.
        //
        // A soft-removed root keeps every file row, and each one's `fs_id`
        // embeds the identity this root had when they were written. Rewriting
        // `scan_root.volume_id` on revival made the record agree with whatever
        // is mounted there NOW while the rows went on describing what was
        // mounted there then — and the scan-time swap check compares the
        // record, so it would then see agreement and walk a different
        // filesystem into a catalog full of the previous one's identities.
        //
        // Refused rather than silently corrected, because the two possible
        // intentions are opposite and only the user knows which is theirs: the
        // volume really was replaced and the retained rows are stale (forget
        // them), or the wrong disk is mounted (mount the right one). A revival
        // whose identity cannot be established is refused for the same reason —
        // unverifiable is not verified.
        if let Some(stored) = stored_volume.as_deref()
            && volume_id != Some(stored)
        {
            return Err(CatalogError::Invalid(format!(
                "`{path}` was enrolled on volume `{stored}` and now reports {}. Its retained \
                 catalog rows carry `fs_id` values built from `{stored}`, so reviving the \
                 root against a different filesystem would mix them with files from another \
                 volume — and the scan-time check compares the root record, which this would \
                 have just rewritten. Re-add with `--forget` to drop the retained rows, or \
                 mount the volume this root was enrolled on",
                match volume_id {
                    Some(v) => format!("`{v}`"),
                    None => "no stable identity at all".to_string(),
                }
            )));
        }

        let id = RootId::new(id);
        let patterns_json = serde_json::to_string(ignore_patterns).map_err(|e| {
            CatalogError::Invalid(format!("ignore patterns are not serializable as JSON: {e}"))
        })?;
        let stub = match stub_mode {
            StubMode::Dehydrate => "dehydrate",
            StubMode::Delete => "delete",
        };
        self.0.conn_mut().execute(
            "UPDATE scan_root SET enabled = 1, stub_mode = ?2, hosted_optin = ?3,
                 ignore_patterns_json = ?4, volume_id = ?5, atime_mode = ?6
             WHERE id = ?1",
            params![
                id.get(),
                stub,
                hosted_optin as i64,
                patterns_json,
                volume_id,
                atime_mode.as_str()
            ],
        )?;

        let (retained_files, retained_custody): (i64, i64) = self.0.conn().query_row(
            "SELECT COUNT(*), COALESCE(SUM(state IN ('stub','remote')), 0)
             FROM file WHERE root_id = ?1",
            params![id.get()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;

        let kept_policies = (stored_case != case_policy.as_str()
            || stored_norm != norm_policy.as_str())
        .then_some((stored_case, stored_norm));

        tracing::info!(
            root = %id,
            path,
            retained_files,
            retained_custody,
            "scan root re-enrolled: its catalog was retained by an earlier soft removal"
        );
        Ok(Enrollment::Reactivated {
            id,
            retained_files: retained_files as u64,
            retained_custody: retained_custody as u64,
            kept_policies,
        })
    }

    pub fn get_root(&self, id: RootId) -> Result<Option<ScanRoot>> {
        self.0
            .conn()
            .query_row(
                "SELECT id, path, stub_mode, path_case_policy, path_norm_policy,
                        atime_mode, volume_id, resync_required, availability,
                        destruction_ineligible, destruction_ineligible_reason
                 FROM scan_root WHERE id = ?1",
                params![id.get()],
                row_to_root,
            )
            .optional()
            .map_err(CatalogError::from)?
            .transpose()
    }

    /// PM-3: set or clear the resync gate. Setting it is loud on purpose —
    /// journal overflow means the event history has a hole.
    pub fn set_resync_required(&mut self, id: RootId, required: bool) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE scan_root SET resync_required = ?2 WHERE id = ?1",
            params![id.get(), required as i64],
        )?;
        if required {
            tracing::warn!(root = %id, "resync-required set: tier/destroy/discard refused for this root");
        }
        Ok(())
    }

    /// D-12: record the enrollment probe's verdict. Setting it is loud — it is
    /// a user-visible capability reduction, not a tuning knob.
    pub fn set_destruction_ineligible(
        &mut self,
        id: RootId,
        ineligible: bool,
        reason: Option<&str>,
    ) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE scan_root SET destruction_ineligible = ?2,
                 destruction_ineligible_reason = ?3 WHERE id = ?1",
            params![id.get(), ineligible as i64, reason],
        )?;
        if ineligible {
            tracing::warn!(
                root = %id,
                reason = reason.unwrap_or("unspecified"),
                "root marked destruction_ineligible: originals under it will never be destroyed"
            );
        }
        Ok(())
    }

    pub fn set_availability(&mut self, id: RootId, availability: Availability) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE scan_root SET availability = ?2 WHERE id = ?1",
            params![id.get(), availability.as_str()],
        )?;
        Ok(())
    }

    /// Insert or update one file row.
    ///
    /// `norm_key` is computed here from the root's policies rather than taken
    /// from the caller, so no call site can forget it or compute it with the
    /// wrong root's policy.
    ///
    /// **`state` is written on insert and never on update.** A scanner that
    /// stat'd a file has established exactly one thing about custody: the bytes
    /// are on local disk, so a NEW row is `'local'`. It has established nothing
    /// about an EXISTING row — a tiered file is a placeholder that still stats,
    /// and folding it back to `'local'` on the next scan would erase the only
    /// record that its bytes live elsewhere. So the conflict branch leaves the
    /// column alone.
    ///
    /// Naming the column is **documentary, not corrective**, and saying so
    /// here is the point. The schema default is already `'local'` and the
    /// conflict branch already omitted `state`, so this statement behaves
    /// exactly as it did when the column was unnamed. What was missing was not
    /// the write — it was any test pinning the second half, which held by
    /// accident: adding `state = excluded.state` to the list below would have
    /// revoked custody on every tiered file at the next scan and broken
    /// nothing. `a_rescan_does_not_revoke_a_tiered_rows_custody` is that pin.
    ///
    /// # `generation`
    ///
    /// The scan pass this sighting belongs to, written to `last_seen_gen` on
    /// **both** the insert and the conflict branch. It is what lets a completed
    /// scan reconcile the rows it did *not* see: everything left below the
    /// current generation was not found on disk. This repo stamps it here and
    /// nowhere else, so "seen by a scan" has exactly one definition.
    ///
    /// **It is a counter, and it must never be a wall clock.** An `updated_at`
    /// watermark was considered and rejected: an NTP step backwards mid-scan
    /// would leave freshly-seen rows below the mark and sweep files that are
    /// still on disk to `'missing'` — worse than the reconciliation gap it
    /// would close. The caller owns the choice of source and its monotonicity;
    /// this function's contract is only to store faithfully what it is handed,
    /// on both paths.
    ///
    /// It is deliberately **not** an input to the `blake3` guard below. Every
    /// scan bumps the generation for every file it sees, so a digest guard that
    /// counted it as a metadata change would clear every hash in the catalog on
    /// the first re-scan.
    ///
    /// The reason `file.state` nonetheless only ever holds `'local'` is
    /// separate and still open: **nothing in the tree writes `'stub'` or
    /// `'remote'`**, here or anywhere else, because tiering is Phase 2/3 work.
    /// That is what makes `WHERE state IN ('stub','remote')` a filter over a
    /// single-valued column, and it is not fixed by this statement.
    ///
    /// # Concurrent scans of one root
    ///
    /// The statement's trailing `WHERE excluded.last_seen_gen >=
    /// file.last_seen_gen` exists because nothing serializes scans per root.
    /// `Queue::claim_next_of` selects by priority and class with no root
    /// exclusion, `scan.start` has no duplicate guard, `Queue::enqueue` has no
    /// dedup — and each walk happens OUTSIDE the writer actor, so the actor can
    /// take a later generation's batch first and an earlier generation's batch
    /// after it. Unconditional, the list above then wrote a stale `size`,
    /// `mtime`, `ctime` and `atime` over the fresh ones and lowered
    /// `last_seen_gen`, the column every reconciliation reads.
    ///
    /// **`>=`, not `>`, and it is load-bearing.** The generation is the job id
    /// (`scan_exec`), so a retried job re-runs under the SAME id; under `>`
    /// every batch of that retry would be a silent no-op.
    ///
    /// **One `WHERE` over the whole statement, not a guard per column**, and
    /// the digest is why. Per-column guards leave the `blake3` expression
    /// reading a stale scan's `excluded.size`/`mtime`/`ctime`, which do not
    /// match the row — so the `CASE` yields NULL, the `COALESCE` yields NULL,
    /// and a valid digest is cleared by a write that was supposed to be
    /// ignored. Skipping the statement is what keeps the guard reading only
    /// metadata the row was actually compared against.
    ///
    /// **This does NOT make the deferred absence sweep safe**, and must not be
    /// read as doing so. It stops a stale scan from OVERWRITING a fresher row;
    /// it cannot stop an older generation from being a row's only sighting.
    /// Jobs N < M, M claimed and walked first, file F created after M's walk:
    /// N's later walk sees F and stamps gen N, this guard never fires because M
    /// never upserts F at all, and M's sweep (`last_seen_gen < M`) then marks F
    /// missing while it is on disk. Same-root scan exclusion is still the
    /// prerequisite for that sweep.
    pub fn upsert_file(
        &mut self,
        root: &ScanRoot,
        stat: &FileStat,
        generation: i64,
        now: Timestamp,
    ) -> Result<()> {
        if stat.root != root.id {
            return Err(CatalogError::Invalid(format!(
                "FileStat belongs to {} but was upserted against root {}",
                stat.root, root.id
            )));
        }
        let nk = root.norm_key(&stat.rel_path);
        let (name, ext) = split_name(&stat.rel_path);
        // §4.4's `<stable-volume-id>:<inode>`, built from the inode the WALK
        // read and the root's recorded volume id.
        //
        // Nothing populated this column. It is what upload and destruction lock
        // on (`FileLocks`, and `LocalDestroyRequest::fs_id` says so in
        // capitals), and what tells a rename from a replacement — a NULL there
        // is a lock that protects nothing and a rename indistinguishable from a
        // delete-plus-create.
        //
        // `clear_fs_id` is the second half, and it exists because a NULL means
        // two opposite things. For [`InodeSighting::Unknown`] — no inode on
        // this platform, or an unreadable probe — the scan learned nothing and
        // must not overwrite a recorded identity, which is what the `COALESCE`
        // below does. For [`InodeSighting::ForeignVolume`] the scan learned
        // something specific: this path is now on a nested mount, so whatever
        // `fs_id` it carries was derived from the root's volume and the inode
        // of the file that USED to be here, and keeping it points the locks at
        // a file that is no longer at the path.
        let (fs_id, clear_fs_id) = match stat.ino {
            InodeSighting::Known(ino) => (
                root.volume_id
                    .as_deref()
                    .map(|vol| crate::volume::fs_id_from_ino(vol, ino).as_str().to_owned()),
                false,
            ),
            InodeSighting::ForeignVolume => (None, true),
            InodeSighting::Unknown => (None, false),
        };
        self.0.conn_mut().execute(
            "INSERT INTO file
                 (root_id, rel_path, name, ext, size, mtime, ctime, atime,
                  norm_key, first_seen_at, blake3, state, last_seen_gen, updated_at,
                  fs_id)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, 'local', ?12, ?10, ?13)
             ON CONFLICT(root_id, rel_path) DO UPDATE SET
                 name = excluded.name, ext = excluded.ext, size = excluded.size,
                 mtime = excluded.mtime, ctime = excluded.ctime, atime = excluded.atime,
                 norm_key = excluded.norm_key, updated_at = excluded.updated_at,
                 -- COALESCE, not a bare assignment: a scan of a root whose
                 -- volume id could not be determined carries NULL, and letting
                 -- that overwrite a good identity would silently unprotect a
                 -- file that had one.
                 --
                 -- ?14 is the deliberate exception. It is set only when the
                 -- walk positively established that the path is on a NESTED
                 -- MOUNT, where the recorded identity is not merely unknown but
                 -- WRONG — see `InodeSighting::ForeignVolume`.
                 fs_id = CASE
                     WHEN ?14 = 1 THEN NULL
                     ELSE COALESCE(excluded.fs_id, file.fs_id)
                 END,
                 -- last_seen_gen IS in this list, and that is the whole point
                 -- of it. The reconciling sweep is
                 -- `SET state='missing' WHERE last_seen_gen < :this_scan`, so a
                 -- row stamped on INSERT and never on UPDATE keeps its
                 -- first-ever generation and is swept as missing on the second
                 -- scan — the catalog declaring a file gone while it is on
                 -- disk. Both writes or neither, subject to the statement's
                 -- trailing WHERE — see `# Concurrent scans of one root`.
                 last_seen_gen = excluded.last_seen_gen,
                 -- first_seen_at is NEVER overwritten: §4.12 makes it the
                 -- min-age floor source where mtime is untrusted or in the
                 -- future, and a re-scan must not reset a file's apparent age.
                 --
                 -- state is NOT in this list either, and for the same shape of
                 -- reason: a stub or a tiered placeholder still stats, so a
                 -- re-scan that wrote excluded.state ('local') would silently
                 -- revoke custody on every file the tierer had moved.
                 --
                 -- blake3 survives a hashless re-scan ONLY where the metadata
                 -- that identified the hashed bytes held still. A bare COALESCE
                 -- kept the digest unconditionally, so a row could pair the new
                 -- size and mtime with the old bytes' hash — and since that
                 -- hash is what names the content-addressed object, the next
                 -- upload would put the NEW bytes under the OLD key and find
                 -- out after the full transfer. Clearing it costs a re-hash;
                 -- keeping it costs correctness of the object namespace.
                 --
                 -- ctime is in the comparison and atime is not, deliberately.
                 -- ctime catches a write that preserved mtime (`cp -p`, rsync
                 -- --times, `touch -r`); its false positive is a re-hash after
                 -- a chmod, which is wasted work, not a wrong answer. atime
                 -- moves on every READ, and a digest invalidated by reading
                 -- would re-hash the whole corpus every time anyone opened it.
                 --
                 -- READ THIS BEFORE WIRING HASHING. Clearing a digest is only
                 -- half a mechanism: something has to re-take it. Nothing does
                 -- today — the walker emits `blake3: None` unconditionally
                 -- (`shepherd-scan::walk`), `FileRepo::set_blake3` has no
                 -- caller outside this module''s tests, and there is no
                 -- selector anywhere that looks for unhashed rows. So the
                 -- column is always NULL in a running daemon and this
                 -- expression cannot yet clear anything real.
                 --
                 -- The moment hashing IS wired, the hashing job MUST select on
                 -- `WHERE blake3 IS NULL` (or an equivalent that re-queues a
                 -- cleared row). Wire it to scan-newly-inserted-rows only and
                 -- every digest this expression clears is never re-taken: the
                 -- file becomes permanently `PlanRefusal::Unhashed`, silently
                 -- excluded from every tier plan, which is a file that never
                 -- gets backed up and never reports why.
                 blake3 = COALESCE(
                     excluded.blake3,
                     CASE WHEN excluded.size  = file.size
                           AND excluded.mtime = file.mtime
                           AND excluded.ctime = file.ctime
                          THEN file.blake3 END)
             WHERE excluded.last_seen_gen >= file.last_seen_gen",
            params![
                root.id.get(),
                stat.rel_path,
                name,
                ext,
                stat.size as i64,
                stat.mtime.as_nanos(),
                stat.ctime.as_nanos(),
                stat.atime.map(|t| t.as_nanos()),
                nk,
                now.as_nanos(),
                stat.blake3.map(|h| h.as_bytes().to_vec()),
                generation,
                fs_id,
                clear_fs_id as i64,
            ],
        )?;
        Ok(())
    }

    /// Look up by the **matching** key. This is what watcher events use.
    ///
    /// Returns every row whose `norm_key` matches, which on a case-sensitive
    /// root can legitimately be more than one (`Report.txt` and `report.txt`
    /// under an `insensitive` policy fold together). Returning a `Vec` rather
    /// than an `Option` is deliberate: an event that matches two rows is an
    /// ambiguity the caller must resolve by `fs_id`, not something this layer
    /// should silently pick a winner for.
    pub fn find_by_norm_key(&self, root: &ScanRoot, rel_path: &str) -> Result<Vec<i64>> {
        let nk = root.norm_key(rel_path);
        let mut stmt = self
            .0
            .conn()
            .prepare("SELECT id FROM file WHERE root_id = ?1 AND norm_key = ?2")?;
        let ids = stmt
            .query_map(params![root.id.get(), nk], |r| r.get::<_, i64>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Record a hash without touching anything else. §6 Phase 1 makes hashing
    /// its own job class, so it arrives after the row exists.
    pub fn set_blake3(&mut self, file_id: i64, hash: Blake3Hash, now: Timestamp) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE file SET blake3 = ?2, updated_at = ?3 WHERE id = ?1",
            params![file_id, hash.as_bytes().to_vec(), now.as_nanos()],
        )?;
        Ok(())
    }

    /// Record a Shepherd-observed access (§4.12 step 2).
    ///
    /// `src` records which signal drove it, so a dry-run preview can state what
    /// actually matched rather than implying `atime` did.
    pub fn note_access(&mut self, file_id: i64, at: Timestamp, src: AccessSignal) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE file SET last_observed_access = ?2, access_signal_src = ?3 WHERE id = ?1",
            params![file_id, at.as_nanos(), src.as_str()],
        )?;
        Ok(())
    }
}

/// What [`FileRepo::enroll_root`] did.
///
/// A re-enrollment is not a first enrollment and the caller has to be able to
/// tell — the root arrives with a catalog already attached, which is a different
/// event to report and a different thing for a user to reason about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Enrollment {
    /// This path had never been enrolled.
    Created(RootId),
    /// A soft-removed root revived, with the rows an earlier `root.remove`
    /// deliberately kept.
    Reactivated {
        id: RootId,
        /// File rows that came back with it.
        retained_files: u64,
        /// How many of those are `stub`/`remote` — the rows whose catalog entry
        /// is the ONLY address of bytes that are no longer on local disk. This
        /// is the number that makes the retention worth having.
        retained_custody: u64,
        /// `Some((case, norm))` when the freshly-probed identity policies
        /// disagreed with the stored ones, carrying the **stored** pair, which
        /// is the one that was kept. See `enroll_root` for why it wins.
        kept_policies: Option<(String, String)>,
    },
}

/// Which signal drove an access timestamp (§4.12 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSignal {
    /// Shepherd saw the access itself — a hydration, a restore, a served open.
    Observed,
    /// OS atime, folded in only where fidelity is `reliable`.
    Atime,
    /// Last resort where no access signal exists at all.
    Mtime,
}

impl AccessSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            AccessSignal::Observed => "observed",
            AccessSignal::Atime => "atime",
            AccessSignal::Mtime => "mtime",
        }
    }
}

fn row_to_root(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ScanRoot>> {
    let stub: String = row.get(2)?;
    let case: String = row.get(3)?;
    let norm: String = row.get(4)?;
    let at: String = row.get(5)?;
    let avail: String = row.get(8)?;
    Ok((|| {
        Ok(ScanRoot {
            id: RootId::new(row.get(0)?),
            path: row.get(1)?,
            stub_mode: match stub.as_str() {
                "dehydrate" => StubMode::Dehydrate,
                "delete" => StubMode::Delete,
                other => return Err(CatalogError::Invalid(format!("stub_mode `{other}`"))),
            },
            case_policy: match case.as_str() {
                "sensitive" => PathCasePolicy::Sensitive,
                "insensitive" => PathCasePolicy::Insensitive,
                other => return Err(CatalogError::Invalid(format!("path_case_policy `{other}`"))),
            },
            norm_policy: match norm.as_str() {
                "nfc" => PathNormPolicy::Nfc,
                "nfd" => PathNormPolicy::Nfd,
                "preserve" => PathNormPolicy::Preserve,
                other => return Err(CatalogError::Invalid(format!("path_norm_policy `{other}`"))),
            },
            atime_mode: AtimeMode::parse(&at)
                .ok_or_else(|| CatalogError::Invalid(format!("atime_mode `{at}`")))?,
            volume_id: row.get(6)?,
            resync_required: row.get::<_, i64>(7)? != 0,
            availability: Availability::parse(&avail)
                .ok_or_else(|| CatalogError::Invalid(format!("availability `{avail}`")))?,
            destruction_ineligible: row.get::<_, i64>(9)? != 0,
            destruction_ineligible_reason: row.get(10)?,
        })
    })())
}

fn split_name(rel_path: &str) -> (String, Option<String>) {
    let name = rel_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(rel_path)
        .to_string();
    // A leading dot is not an extension separator: `.gitignore` has no
    // extension, and treating it as one puts every dotfile in the same `ext`
    // bucket, which the (ext, mtime) index then makes useless.
    let ext = name
        .rfind('.')
        .filter(|&i| i > 0)
        .map(|i| name[i + 1..].to_lowercase());
    (name, ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scan generation for tests that are not about generations.
    const GEN: i64 = 1;

    fn stat(root: RootId, rel: &str) -> FileStat {
        FileStat {
            root,
            rel_path: rel.into(),
            size: 10,
            mtime: Timestamp::from_nanos(1),
            ctime: Timestamp::from_nanos(1),
            atime: None,
            blake3: None,
            ino: InodeSighting::Unknown,
        }
    }

    /// A revival must not touch the `file` table at all.
    ///
    /// This is the assertion the wire cannot make. `state` is the column that
    /// matters: a re-enrollment has stat'd nothing, so folding a retained
    /// `'remote'` row back to `'local'` would revoke custody on exactly the
    /// tiered file whose catalog row is the only address of its remote bytes —
    /// the thing the soft-removal retention exists to protect. `first_seen_at`
    /// and `last_seen_gen` are asserted alongside it because a revival that
    /// "refreshed" the rows would reset the min-age floor (§4.12) and hand the
    /// next sweep a generation the scan never stamped.
    #[test]
    fn re_enrolling_a_disabled_root_revives_it_without_touching_a_single_file_row() {
        let (mut cat, root) = fixture();
        for rel in ["a.txt", "b.txt"] {
            FileRepo::new(&mut cat)
                .upsert_file(&root, &stat(root.id, rel), 3, Timestamp::from_nanos(1))
                .unwrap();
        }
        cat.conn_mut()
            .execute(
                "UPDATE file SET state = 'remote' WHERE rel_path = 'a.txt'",
                [],
            )
            .unwrap();
        let before: Vec<(String, String, i64, i64)> = rows(&mut cat);

        // The soft removal.
        cat.conn_mut()
            .execute("UPDATE scan_root SET enabled = 0", [])
            .unwrap();

        let out = FileRepo::new(&mut cat)
            .enroll_root(
                "/data",
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Nfc,
                AtimeMode::Relatime,
                Some("uuid:abc"),
                false,
                &[],
                Timestamp::from_nanos(9),
            )
            .unwrap();

        assert_eq!(
            out,
            Enrollment::Reactivated {
                id: root.id,
                retained_files: 2,
                retained_custody: 1,
                kept_policies: None,
            },
            "the SAME row is revived, and the custody count is what makes the retention \
             worth having"
        );
        let enabled: i64 = cat
            .conn()
            .query_row("SELECT enabled FROM scan_root", [], |r| r.get(0))
            .unwrap();
        assert_eq!(enabled, 1, "the root must actually be enabled again");

        assert_eq!(
            rows(&mut cat),
            before,
            "a re-enrollment stat'd nothing, so it may not rewrite a single file row — \
             folding the retained 'remote' row back to 'local' revokes custody on a file \
             whose bytes are not on this disk"
        );
    }

    /// The recorded identity policies win, and the disagreement is reported
    /// rather than applied.
    ///
    /// Every retained row's `norm_key` was derived from the STORED pair, and
    /// `find_by_norm_key` is what watcher events match against. Writing the
    /// freshly-probed pair without recomputing every key makes those lookups
    /// miss — and §4.9 PM-3 puts a miss in discard-trigger territory.
    #[test]
    fn re_enrolling_keeps_the_recorded_identity_policies_and_reports_the_disagreement() {
        let (mut cat, root) = fixture();
        FileRepo::new(&mut cat)
            .upsert_file(&root, &stat(root.id, "a.txt"), 1, Timestamp::from_nanos(1))
            .unwrap();
        let key_before: String = cat
            .conn()
            .query_row("SELECT norm_key FROM file", [], |r| r.get(0))
            .unwrap();
        cat.conn_mut()
            .execute("UPDATE scan_root SET enabled = 0", [])
            .unwrap();

        // The volume now probes as case-insensitive, which it was not.
        let out = FileRepo::new(&mut cat)
            .enroll_root(
                "/data",
                StubMode::Delete,
                PathCasePolicy::Insensitive,
                PathNormPolicy::Nfd,
                AtimeMode::Relatime,
                Some("uuid:abc"),
                false,
                &[],
                Timestamp::from_nanos(9),
            )
            .unwrap();

        let Enrollment::Reactivated { kept_policies, .. } = out else {
            panic!("expected a revival, got {out:?}");
        };
        assert_eq!(
            kept_policies,
            Some(("sensitive".to_string(), "nfc".to_string())),
            "the disagreement must be reported, and it must report the pair that was KEPT"
        );

        let (case, norm): (String, String) = cat
            .conn()
            .query_row(
                "SELECT path_case_policy, path_norm_policy FROM scan_root",
                [],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(
            (case.as_str(), norm.as_str()),
            ("sensitive", "nfc"),
            "the RECORDED policies must survive: every retained norm_key was derived from \
             them, and changing one without recomputing the keys makes watcher lookups miss"
        );
        assert_eq!(
            cat.conn()
                .query_row("SELECT norm_key FROM file", [], |r| r.get::<_, String>(0))
                .unwrap(),
            key_before,
            "and the keys themselves are untouched, which is the point of keeping them"
        );
    }

    /// User intent, stated afresh, is honoured afresh.
    ///
    /// The opposite — keeping the stored copies — is the exact shape of the
    /// `ignore_patterns_json DEFAULT '[]'` failure `insert_root` documents: a
    /// user's exclusions silently not being the ones they just asked for.
    #[test]
    fn re_enrolling_applies_the_settings_the_request_states() {
        let (mut cat, _root) = fixture();
        cat.conn_mut()
            .execute("UPDATE scan_root SET enabled = 0", [])
            .unwrap();

        FileRepo::new(&mut cat)
            .enroll_root(
                "/data",
                StubMode::Dehydrate,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Nfc,
                AtimeMode::Reliable,
                Some("uuid:abc"),
                true,
                &["*.tmp".to_string()],
                Timestamp::from_nanos(9),
            )
            .unwrap();

        let (stub, optin, ignores, vol, at): (String, i64, String, String, String) = cat
            .conn()
            .query_row(
                "SELECT stub_mode, hosted_optin, ignore_patterns_json, volume_id, atime_mode
                 FROM scan_root",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .unwrap();
        assert_eq!(stub, "dehydrate");
        assert_eq!(optin, 1, "consent is per-request and must not be stale");
        assert_eq!(ignores, r#"["*.tmp"]"#, "AC-9's exclusions, as just stated");
        // ORACLE CHANGED. This used to revive against `uuid:moved` under the
        // comment "a remount can legitimately change this". It cannot:
        // `volume_id` is derived from the filesystem's UUID precisely so a
        // remount does NOT change it — that is what
        // `fs_id_survives_a_remount_that_changes_st_dev` proves. A different
        // value means a different filesystem, and the test below is what
        // happens then.
        assert_eq!(
            vol, "uuid:abc",
            "the identity the retained rows were built against"
        );
        assert_eq!(at, "reliable");
    }

    /// Reviving a soft-removed root against a DIFFERENT volume is refused.
    ///
    /// The retained file rows carry `fs_id` values built from the old identity.
    /// Rewriting `scan_root.volume_id` on revival made the record agree with
    /// whatever is mounted there now while the rows went on describing what was
    /// mounted there then — and the scan-time swap check compares the record,
    /// so it would see agreement and walk a different filesystem into a catalog
    /// full of the previous one's identities.
    ///
    /// Refused rather than silently corrected: the two possible intentions are
    /// opposite and only the user knows which is theirs.
    #[test]
    fn re_enrolling_against_a_different_volume_is_refused() {
        let (mut cat, _root) = fixture();
        cat.conn_mut()
            .execute("UPDATE scan_root SET enabled = 0", [])
            .unwrap();

        let revive = |cat: &mut Catalog, volume: Option<&str>| {
            FileRepo::new(cat).enroll_root(
                "/data",
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Nfc,
                AtimeMode::Relatime,
                volume,
                false,
                &[],
                Timestamp::from_nanos(9),
            )
        };

        let err = revive(&mut cat, Some("uuid:different"))
            .expect_err("a different filesystem at the same path must not adopt these rows");
        let msg = err.to_string();
        assert!(
            msg.contains("uuid:abc") && msg.contains("uuid:different"),
            "the refusal must name both identities: {msg}"
        );

        // Unverifiable is not verified: an identity that has DISAPPEARED is the
        // unmounted-volume case, and adopting the rows against it is the same
        // mistake.
        let err = revive(&mut cat, None).expect_err("no identity is not the same identity");
        assert!(err.to_string().contains("no stable identity"), "{err}");

        // And the accepting direction, so this cannot pass by refusing every
        // revival: the same volume revives.
        revive(&mut cat, Some("uuid:abc")).expect("the enrolled volume is still there");
    }

    /// An ENABLED root at the same path is a genuine duplicate and stays
    /// refused. "Reactivate whatever you find" would let a second `root.add`
    /// silently rewrite a live root's settings.
    #[test]
    fn enrolling_a_path_that_is_already_enabled_is_refused() {
        let (mut cat, _root) = fixture();

        let err = FileRepo::new(&mut cat)
            .enroll_root(
                "/data",
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Nfc,
                AtimeMode::Relatime,
                None,
                false,
                &[],
                Timestamp::from_nanos(9),
            )
            .unwrap_err();

        // The FACT, not `is_err()`: this variant is what `map_catalog_error`
        // turns into `Precondition`, and it replaced a raw unique-constraint
        // error that mapped to `Io` and read as "storage broke".
        assert!(
            matches!(err, CatalogError::AlreadyInState(ref m) if m.contains("/data")),
            "expected AlreadyInState naming the path, got {err:?}"
        );
    }

    /// The accepting direction: an unseen path is still an ordinary first
    /// enrollment. A `enroll_root` that refused everything would pass the
    /// refusal test above while making the daemon unable to register anything.
    #[test]
    fn enrolling_an_unseen_path_creates_it() {
        let (mut cat, root) = fixture();

        let out = FileRepo::new(&mut cat)
            .enroll_root(
                "/other",
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Nfc,
                AtimeMode::Relatime,
                None,
                false,
                &[],
                Timestamp::from_nanos(9),
            )
            .unwrap();

        let Enrollment::Created(id) = out else {
            panic!("a path that was never enrolled must be Created, got {out:?}");
        };
        assert_ne!(id, root.id, "and it is a new row, not the existing one");
        assert!(FileRepo::new(&mut cat).get_root(id).unwrap().is_some());
    }

    /// Every file row's identity and vintage, for the untouched-rows assertion.
    fn rows(cat: &mut Catalog) -> Vec<(String, String, i64, i64)> {
        let mut stmt = cat
            .conn()
            .prepare(
                "SELECT rel_path, state, first_seen_at, last_seen_gen
                 FROM file ORDER BY rel_path",
            )
            .unwrap();
        stmt.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .unwrap()
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap()
    }

    fn fixture() -> (Catalog, ScanRoot) {
        let mut cat = Catalog::open_in_memory().unwrap();
        let id = FileRepo::new(&mut cat)
            .insert_root(
                "/data",
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Nfc,
                AtimeMode::Relatime,
                Some("uuid:abc"),
                false,
                &[],
                Timestamp::from_nanos(1),
            )
            .unwrap();
        let root = FileRepo::new(&mut cat).get_root(id).unwrap().unwrap();
        (cat, root)
    }

    /// The whole point of `norm_key`: a watcher event spelled in NFD finds the
    /// row a scan wrote in NFC. Without this the lookup misses, the miss reads
    /// as absence, and absence is discard-trigger territory (PM-3).
    #[test]
    fn an_nfd_event_finds_the_row_written_from_nfc() {
        let (mut cat, root) = fixture();
        let nfc = "caf\u{00e9}/notes.txt";
        let nfd = "cafe\u{0301}/notes.txt";
        FileRepo::new(&mut cat)
            .upsert_file(&root, &stat(root.id, nfc), GEN, Timestamp::from_nanos(2))
            .unwrap();

        let repo = FileRepo::new(&mut cat);
        assert_eq!(
            repo.find_by_norm_key(&root, nfd).unwrap().len(),
            1,
            "the NFD spelling must find the NFC row"
        );
        // And the naive lookup is exactly what would have failed.
        let by_path: i64 = cat
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM file WHERE root_id = ?1 AND rel_path = ?2",
                params![root.id.get(), nfd],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            by_path, 0,
            "rel_path lookup misses — this is the bug norm_key fixes"
        );
    }

    #[test]
    fn first_seen_at_survives_a_rescan() {
        let (mut cat, root) = fixture();
        let mut repo = FileRepo::new(&mut cat);
        repo.upsert_file(
            &root,
            &stat(root.id, "a.txt"),
            GEN,
            Timestamp::from_nanos(100),
        )
        .unwrap();
        repo.upsert_file(
            &root,
            &stat(root.id, "a.txt"),
            GEN,
            Timestamp::from_nanos(999),
        )
        .unwrap();
        let first: i64 = cat
            .conn()
            .query_row("SELECT first_seen_at FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            first, 100,
            "re-scanning must not reset apparent age — it is the min-age floor source"
        );
    }

    /// A new row is `'local'` and says so, rather than inheriting the schema
    /// default from a statement that never mentions the column.
    ///
    /// The paired half is [`a_rescan_does_not_revoke_a_tiered_row_s_custody`]:
    /// on its own, "a fresh row is local" is satisfied by a column nothing
    /// writes, since `'local'` is also the default.
    #[test]
    fn a_freshly_scanned_row_is_local() {
        let (mut cat, root) = fixture();
        FileRepo::new(&mut cat)
            .upsert_file(
                &root,
                &stat(root.id, "a.txt"),
                GEN,
                Timestamp::from_nanos(1),
            )
            .unwrap();
        let st: String = cat
            .conn()
            .query_row("SELECT state FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(st, "local");
    }

    /// The load-bearing half of writing `state` explicitly.
    ///
    /// A tiered file is a placeholder that still stats, so the scanner hands
    /// `upsert_file` an ordinary `FileStat` for it on every pass. If the
    /// conflict branch took `excluded.state`, each re-scan would rewrite
    /// `'stub'`/`'remote'` back to `'local'` — dropping the catalog's only
    /// record that the bytes are elsewhere, and taking `root.remove`'s custody
    /// refusal down with it.
    #[test]
    fn a_rescan_does_not_revoke_a_tiered_rows_custody() {
        let (mut cat, root) = fixture();
        FileRepo::new(&mut cat)
            .upsert_file(
                &root,
                &stat(root.id, "a.txt"),
                GEN,
                Timestamp::from_nanos(1),
            )
            .unwrap();
        // Stand in for the tierer, which is Phase 2/3 work. What is under test
        // is the re-scan, not who set the state.
        cat.conn_mut()
            .execute("UPDATE file SET state = 'stub'", [])
            .unwrap();

        FileRepo::new(&mut cat)
            .upsert_file(
                &root,
                &stat(root.id, "a.txt"),
                GEN,
                Timestamp::from_nanos(2),
            )
            .unwrap();

        let st: String = cat
            .conn()
            .query_row("SELECT state FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            st, "stub",
            "a re-scan reset a tiered row to local — every custody record under \
             this root would be lost on the next scan"
        );
        // The rest of the row still updated, so the assertion above is about
        // `state` specifically and not about the upsert having done nothing.
        let updated: i64 = cat
            .conn()
            .query_row("SELECT updated_at FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(updated, 2, "the re-scan must still have written the row");
    }

    #[test]
    fn a_rescan_without_a_hash_does_not_erase_one() {
        let (mut cat, root) = fixture();
        let mut repo = FileRepo::new(&mut cat);
        let mut s = stat(root.id, "a.txt");
        s.blake3 = Some(Blake3Hash::from_bytes([7; 32]));
        repo.upsert_file(&root, &s, GEN, Timestamp::from_nanos(1))
            .unwrap();
        // Hashing is its own job class, so a later metadata-only scan arrives
        // with blake3 = None. It must not clear the hash.
        repo.upsert_file(
            &root,
            &stat(root.id, "a.txt"),
            GEN,
            Timestamp::from_nanos(2),
        )
        .unwrap();
        let h: Option<Vec<u8>> = cat
            .conn()
            .query_row("SELECT blake3 FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(h, Some(vec![7u8; 32]));
    }

    /// The generation must advance on a RE-scan, not only on the first sight.
    ///
    /// `last_seen_gen` is what lets a completed scan reconcile the rows it did
    /// not see — the sweep is `UPDATE file SET state = 'missing' WHERE
    /// last_seen_gen < :this_scan`. So the dangerous omission is not forgetting
    /// the column: it is stamping it on the INSERT and forgetting the
    /// `DO UPDATE` list. A file present in every scan then keeps its
    /// first-ever generation for ever and is swept as **missing** on the second
    /// run — the catalog declaring the user's data gone while it sits on disk.
    ///
    /// That is a one-line omission with a data-shaped consequence, and it is
    /// invisible to any test that only inserts. Hence: the same path, twice,
    /// under two generations, asserting the value MOVED — not merely that the
    /// column is populated.
    #[test]
    fn a_rescan_advances_the_generation_it_was_given() {
        let (mut cat, root) = fixture();
        let mut repo = FileRepo::new(&mut cat);
        repo.upsert_file(&root, &stat(root.id, "a.txt"), 7, Timestamp::from_nanos(1))
            .unwrap();
        let first: i64 = cat
            .conn()
            .query_row("SELECT last_seen_gen FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            first, 7,
            "the insert must stamp the generation it was given"
        );

        FileRepo::new(&mut cat)
            .upsert_file(&root, &stat(root.id, "a.txt"), 8, Timestamp::from_nanos(2))
            .unwrap();
        let second: i64 = cat
            .conn()
            .query_row("SELECT last_seen_gen FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            second, 8,
            "a re-scan left the row at generation {first}. The next completed \
             scan sweeps `last_seen_gen < gen` to 'missing', so this file — \
             which the scan just saw on disk — would be marked missing"
        );
    }

    /// Two scans of one root run concurrently, and the older one must not
    /// overwrite the newer one's row.
    ///
    /// Nothing serializes scans per root — `Queue::claim_next_of` selects by
    /// priority and class with no root exclusion, `scan.start` has no duplicate
    /// guard and `Queue::enqueue` has no dedup — and both walks happen OUTSIDE
    /// the writer actor. So the actor can receive a later generation's batch
    /// first and an earlier generation's batch after it, carrying a filesystem
    /// snapshot that is already stale.
    ///
    /// Unconditional, the `DO UPDATE` list then wrote the stale `size`, `mtime`,
    /// `ctime` and `atime` over the fresh ones AND lowered `last_seen_gen`,
    /// which is the column every reconciliation reads. A catalog that reports a
    /// file's old size is wrong about the bytes a tier plan would upload.
    #[test]
    fn a_stale_scans_upsert_does_not_overwrite_a_newer_scans_row() {
        let (mut cat, root) = fixture();

        // Generation 9 — the later scan — lands first, with the current bytes.
        let mut fresh = stat(root.id, "a.txt");
        fresh.size = 4096;
        fresh.mtime = Timestamp::from_nanos(9_000);
        fresh.ctime = Timestamp::from_nanos(9_000);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &fresh, 9, Timestamp::from_nanos(9))
            .unwrap();

        // Generation 4 — the earlier scan, still holding the snapshot it took
        // before the file grew — arrives afterwards.
        let mut stale = stat(root.id, "a.txt");
        stale.size = 10;
        stale.mtime = Timestamp::from_nanos(4_000);
        stale.ctime = Timestamp::from_nanos(4_000);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &stale, 4, Timestamp::from_nanos(10))
            .unwrap();

        let (size, mtime, seen_gen): (i64, i64, i64) = cat
            .conn()
            .query_row("SELECT size, mtime, last_seen_gen FROM file", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(
            size, 4096,
            "an older scan's snapshot overwrote a newer one's size; the catalog now \
             describes bytes that are not on disk"
        );
        assert_eq!(mtime, 9_000, "and its mtime with it");
        assert_eq!(
            seen_gen, 9,
            "and it lowered last_seen_gen, which is what every reconciliation reads"
        );
    }

    /// §4.4's `<stable-volume-id>:<inode>` is written by the ingesting upsert.
    ///
    /// The column existed and nothing populated it, so every row's `fs_id` was
    /// NULL — and that value is what `FileLocks` keys on for upload and
    /// destruction, and what tells a rename from a delete-plus-create. A NULL
    /// there is a lock that collides with nothing, on the irreversible path.
    ///
    /// The exact string is asserted, not merely "not null": a value of the
    /// right shape built from the wrong number would pass that and protect
    /// nothing.
    ///
    /// Here rather than only end-to-end because the assertion must not depend
    /// on the host filesystem — `volume::volume_id` legitimately answers `None`
    /// on a mount with no stable UUID (every GitHub runner), which would make
    /// an e2e-only test silently untestable exactly where CI runs it.
    #[test]
    fn ingestion_writes_the_filesystem_identity() {
        let (mut cat, root) = fixture();
        assert_eq!(root.volume_id.as_deref(), Some("uuid:abc"));

        let mut s = stat(root.id, "a.txt");
        s.ino = InodeSighting::Known(4242);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &s, GEN, Timestamp::from_nanos(1))
            .unwrap();

        let stored: Option<String> = cat
            .conn()
            .query_row("SELECT CAST(fs_id AS TEXT) FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored.as_deref(), Some("uuid:abc:4242"));

        // A re-scan that could not determine the inode carries NULL, and must
        // not blank an identity the row already has: `COALESCE` in the
        // `DO UPDATE`. Letting it through would silently unprotect a file that
        // was protected a moment ago.
        let mut blind = stat(root.id, "a.txt");
        blind.ino = InodeSighting::Unknown;
        blind.size = 99;
        FileRepo::new(&mut cat)
            .upsert_file(&root, &blind, GEN + 1, Timestamp::from_nanos(2))
            .unwrap();

        let (stored, size): (Option<String>, i64) = cat
            .conn()
            .query_row("SELECT CAST(fs_id AS TEXT), size FROM file", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(size, 99, "the rest of the row still updated");
        assert_eq!(
            stored.as_deref(),
            Some("uuid:abc:4242"),
            "a scan that could not identify the file must not erase the identity \
             the lock depends on"
        );
    }

    /// A path that a nested mount has covered CLEARS its recorded identity.
    ///
    /// `ino: Unknown` and `ino: ForeignVolume` both arrive as "no `fs_id` to
    /// write", and they are opposite instructions. `COALESCE` keeps what is
    /// recorded, which is right for an unreadable probe and wrong here: the
    /// stored `fs_id` was `<root-volume>:<inode>` for the file that USED to be
    /// at this path, so keeping it leaves `FileLocks` — and the
    /// rename-versus-replacement decision — pointed at a file that is no longer
    /// there, on the irreversible path.
    #[test]
    fn a_path_covered_by_a_nested_mount_loses_its_recorded_identity() {
        let (mut cat, root) = fixture();

        let mut first = stat(root.id, "a.txt");
        first.ino = InodeSighting::Known(4242);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &first, GEN, Timestamp::from_nanos(1))
            .unwrap();
        let stored: Option<String> = cat
            .conn()
            .query_row("SELECT CAST(fs_id AS TEXT) FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored.as_deref(), Some("uuid:abc:4242"));

        // A later scan finds the same path on another filesystem.
        let mut covered = stat(root.id, "a.txt");
        covered.ino = InodeSighting::ForeignVolume;
        FileRepo::new(&mut cat)
            .upsert_file(&root, &covered, GEN + 1, Timestamp::from_nanos(2))
            .unwrap();

        let stored: Option<String> = cat
            .conn()
            .query_row("SELECT CAST(fs_id AS TEXT) FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            stored, None,
            "the identity of the file that used to be at this path must not survive it"
        );

        // And `Unknown` still does NOT clear — the two must stay distinguishable.
        let mut known_again = stat(root.id, "a.txt");
        known_again.ino = InodeSighting::Known(99);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &known_again, GEN + 2, Timestamp::from_nanos(3))
            .unwrap();
        let mut blind = stat(root.id, "a.txt");
        blind.ino = InodeSighting::Unknown;
        FileRepo::new(&mut cat)
            .upsert_file(&root, &blind, GEN + 3, Timestamp::from_nanos(4))
            .unwrap();
        let stored: Option<String> = cat
            .conn()
            .query_row("SELECT CAST(fs_id AS TEXT) FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            stored.as_deref(),
            Some("uuid:abc:99"),
            "a scan that learned nothing must not erase what a scan that learned something wrote"
        );
    }

    /// A root with no stable volume id records no identity, rather than half of
    /// one.
    ///
    /// `root.add` already warns when the volume id could not be determined.
    /// Writing `:<inode>` with an empty volume would be worse than NULL: an
    /// inode alone is unique only within one filesystem, so it would collide
    /// across roots and the lock would serialize unrelated files.
    #[test]
    fn a_root_without_a_volume_id_records_no_identity() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let id = FileRepo::new(&mut cat)
            .insert_root(
                "/data",
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
        let root = FileRepo::new(&mut cat).get_root(id).unwrap().unwrap();

        let mut s = stat(root.id, "a.txt");
        s.ino = InodeSighting::Known(4242);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &s, GEN, Timestamp::from_nanos(1))
            .unwrap();

        let stored: Option<String> = cat
            .conn()
            .query_row("SELECT CAST(fs_id AS TEXT) FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(stored, None);
    }

    /// The accepting direction, and the one a "never update on conflict" fix
    /// would silently break: an ordinary re-scan carries a HIGHER generation and
    /// must still write everything it saw.
    ///
    /// Without this, the guard above passes as `DO NOTHING` — and a row that
    /// never updates keeps its first-ever generation, which the reconciling
    /// sweep reads as "not seen by this scan" and marks missing.
    #[test]
    fn a_newer_scans_upsert_still_applies_over_an_older_row() {
        let (mut cat, root) = fixture();

        let mut old = stat(root.id, "a.txt");
        old.size = 10;
        old.mtime = Timestamp::from_nanos(4_000);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &old, 4, Timestamp::from_nanos(4))
            .unwrap();

        let mut new = stat(root.id, "a.txt");
        new.size = 4096;
        new.mtime = Timestamp::from_nanos(9_000);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &new, 9, Timestamp::from_nanos(9))
            .unwrap();

        let (size, mtime, seen_gen): (i64, i64, i64) = cat
            .conn()
            .query_row("SELECT size, mtime, last_seen_gen FROM file", [], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .unwrap();
        assert_eq!(size, 4096, "the later scan's snapshot is the current one");
        assert_eq!(mtime, 9_000);
        assert_eq!(
            seen_gen, 9,
            "and the generation must advance, or the next sweep marks this file missing"
        );
    }

    /// `>=`, not `>`, and it is load-bearing.
    ///
    /// The generation is the job id (`scan_exec`), so a job that is retried
    /// re-runs under the SAME id. A guard written `>` would make every batch of
    /// that retry a no-op: the rows the retry re-stats would keep whatever the
    /// abandoned attempt left, and rows it inserts fresh would sit beside them
    /// at the same generation with different vintages.
    #[test]
    fn a_retry_at_the_same_generation_still_applies() {
        let (mut cat, root) = fixture();

        let mut first = stat(root.id, "a.txt");
        first.size = 10;
        FileRepo::new(&mut cat)
            .upsert_file(&root, &first, 5, Timestamp::from_nanos(1))
            .unwrap();

        let mut retry = stat(root.id, "a.txt");
        retry.size = 4096;
        FileRepo::new(&mut cat)
            .upsert_file(&root, &retry, 5, Timestamp::from_nanos(2))
            .unwrap();

        let size: i64 = cat
            .conn()
            .query_row("SELECT size FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            size, 4096,
            "a retried job re-runs under the same job id, so the same generation must \
             still be allowed to write what it re-stat'd"
        );
    }

    /// The generation and the stale-digest guard must stay independent.
    ///
    /// Every scan bumps the generation for every file it sees; that is the
    /// point of it. A digest guard that treated the bump as "the metadata
    /// changed" would therefore clear **every hash in the catalog** on the
    /// first re-scan, turning a correctness fix into a corpus-wide re-hash.
    ///
    /// It is independent by construction — the `CASE` compares size, mtime and
    /// ctime and nothing else — but "obvious from the code" is exactly what
    /// stops being true when someone later makes the guard stricter.
    #[test]
    fn a_generation_bump_alone_does_not_clear_the_digest() {
        let (mut cat, root) = fixture();
        FileRepo::new(&mut cat)
            .upsert_file(&root, &stat(root.id, "a.txt"), 1, Timestamp::from_nanos(1))
            .unwrap();
        let id: i64 = cat
            .conn()
            .query_row("SELECT id FROM file", [], |r| r.get(0))
            .unwrap();
        FileRepo::new(&mut cat)
            .set_blake3(
                id,
                Blake3Hash::from_bytes([7; 32]),
                Timestamp::from_nanos(2),
            )
            .unwrap();

        // Identical bytes, identical metadata, next scan.
        FileRepo::new(&mut cat)
            .upsert_file(&root, &stat(root.id, "a.txt"), 2, Timestamp::from_nanos(3))
            .unwrap();

        let (h, seen_gen): (Option<Vec<u8>>, i64) = cat
            .conn()
            .query_row("SELECT blake3, last_seen_gen FROM file", [], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .unwrap();
        assert_eq!(seen_gen, 2, "the generation must still have advanced");
        assert_eq!(
            h,
            Some(vec![7u8; 32]),
            "advancing the scan generation re-hashed an unchanged file — on a \
             50 TB corpus that is every file, every scan"
        );
    }

    /// A digest is only valid for the bytes it was taken over.
    ///
    /// `COALESCE(excluded.blake3, file.blake3)` kept the old digest through a
    /// metadata-only re-scan **unconditionally**, so a row could carry the
    /// current size and mtime beside the hash of bytes that no longer existed.
    /// The digest is what names the content-addressed remote object, so the
    /// consequence is not a stale column: it is an upload of the NEW bytes
    /// under the OLD bytes' key, discovered only after the whole transfer.
    #[test]
    fn a_rescan_that_saw_new_bytes_does_not_keep_the_old_digest() {
        let (mut cat, root) = fixture();
        let old_hash = Blake3Hash::from_bytes([7; 32]);
        FileRepo::new(&mut cat)
            .upsert_file(
                &root,
                &stat(root.id, "a.txt"),
                GEN,
                Timestamp::from_nanos(1),
            )
            .unwrap();
        let id: i64 = cat
            .conn()
            .query_row("SELECT id FROM file", [], |r| r.get(0))
            .unwrap();
        // Hashing is its own job class (§6 Phase 1), so it lands here, not in
        // the scan that created the row.
        FileRepo::new(&mut cat)
            .set_blake3(id, old_hash, Timestamp::from_nanos(2))
            .unwrap();

        // The file is rewritten. The next scan is metadata-only, as scans are:
        // it reports the new size and mtime and carries no hash.
        let mut changed = stat(root.id, "a.txt");
        changed.size = 4096;
        changed.mtime = Timestamp::from_nanos(500);
        changed.ctime = Timestamp::from_nanos(500);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &changed, GEN, Timestamp::from_nanos(3))
            .unwrap();

        let h: Option<Vec<u8>> = cat
            .conn()
            .query_row("SELECT blake3 FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            h,
            None,
            "the row kept a digest of bytes that are gone. `plan_tier` accepts \
             any digest it finds, so this row's next upload would be addressed \
             {} — an object named for content it does not contain",
            crate::identity::content_key("p", old_hash).as_str()
        );
        // And the rest of the row did update, so the assertion above is about
        // the digest and not about the upsert having done nothing.
        let size: i64 = cat
            .conn()
            .query_row("SELECT size FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(size, 4096, "the re-scan must still have written the row");
    }

    /// The half of the guard that mtime alone would miss.
    ///
    /// `rsync --times`, `cp -p` and `touch -r` all restore mtime after writing,
    /// and a same-size edit is ordinary. Comparing only size and mtime would
    /// call that pair unchanged and keep the old digest — the exact stale-hash
    /// row this guard exists to prevent, reached by the commonest backup tools
    /// in use. ctime cannot be restored by a userspace tool, which is why it is
    /// in the comparison.
    #[test]
    fn a_write_that_restored_mtime_still_clears_the_digest() {
        let (mut cat, root) = fixture();
        FileRepo::new(&mut cat)
            .upsert_file(
                &root,
                &stat(root.id, "a.txt"),
                GEN,
                Timestamp::from_nanos(1),
            )
            .unwrap();
        let id: i64 = cat
            .conn()
            .query_row("SELECT id FROM file", [], |r| r.get(0))
            .unwrap();
        FileRepo::new(&mut cat)
            .set_blake3(
                id,
                Blake3Hash::from_bytes([7; 32]),
                Timestamp::from_nanos(2),
            )
            .unwrap();

        // Same size, same mtime — the tool put it back. Only ctime tells.
        let mut rewritten = stat(root.id, "a.txt");
        rewritten.ctime = Timestamp::from_nanos(500);
        FileRepo::new(&mut cat)
            .upsert_file(&root, &rewritten, GEN, Timestamp::from_nanos(3))
            .unwrap();

        let h: Option<Vec<u8>> = cat
            .conn()
            .query_row("SELECT blake3 FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            h, None,
            "a write with a restored mtime kept its old digest — every \
             mtime-preserving copy tool produces this row"
        );
    }

    /// The accepting direction, and the reason the guard is not "clear on any
    /// difference": **reading** a file changes its atime and nothing else. A
    /// hash invalidated by a read would be re-taken on every scan of every file
    /// anyone had opened, and hashing 50 TB is not free.
    #[test]
    fn a_rescan_that_saw_only_a_new_atime_keeps_the_digest() {
        let (mut cat, root) = fixture();
        FileRepo::new(&mut cat)
            .upsert_file(
                &root,
                &stat(root.id, "a.txt"),
                GEN,
                Timestamp::from_nanos(1),
            )
            .unwrap();
        let id: i64 = cat
            .conn()
            .query_row("SELECT id FROM file", [], |r| r.get(0))
            .unwrap();
        FileRepo::new(&mut cat)
            .set_blake3(
                id,
                Blake3Hash::from_bytes([7; 32]),
                Timestamp::from_nanos(2),
            )
            .unwrap();

        let mut read = stat(root.id, "a.txt");
        read.atime = Some(Timestamp::from_nanos(900));
        FileRepo::new(&mut cat)
            .upsert_file(&root, &read, GEN, Timestamp::from_nanos(3))
            .unwrap();

        let h: Option<Vec<u8>> = cat
            .conn()
            .query_row("SELECT blake3 FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            h,
            Some(vec![7u8; 32]),
            "an access re-hashed the file: the bytes did not change, only the \
             record of who looked at them"
        );
    }

    #[test]
    fn a_root_needing_resync_or_unavailable_may_not_destroy() {
        let (mut cat, root) = fixture();
        assert!(root.may_destroy());

        FileRepo::new(&mut cat)
            .set_resync_required(root.id, true)
            .unwrap();
        let r = FileRepo::new(&mut cat).get_root(root.id).unwrap().unwrap();
        assert!(!r.may_destroy(), "PM-3: a resync-required root is gated");

        FileRepo::new(&mut cat)
            .set_resync_required(root.id, false)
            .unwrap();
        FileRepo::new(&mut cat)
            .set_availability(root.id, Availability::Unmounted)
            .unwrap();
        let r = FileRepo::new(&mut cat).get_root(root.id).unwrap().unwrap();
        assert!(
            !r.may_destroy(),
            "PM-3 #2: an unmounted root processes zero absences"
        );
    }

    /// D-12 (§4.10.1): a root whose filesystem cannot host identity-bound
    /// staging is still scanned, indexed and copyable — its originals are just
    /// never destroyed. Refusing at destroy time instead would be discovering
    /// the constraint at the worst possible moment.
    #[test]
    fn a_destruction_ineligible_root_may_not_destroy_but_is_otherwise_usable() {
        let (mut cat, root) = fixture();
        assert!(root.may_destroy());
        assert_eq!(root.destroy_refusal(), None);

        FileRepo::new(&mut cat)
            .set_destruction_ineligible(
                root.id,
                true,
                Some("RENAME_NOREPLACE returned EINVAL on this filesystem"),
            )
            .unwrap();
        let r = FileRepo::new(&mut cat).get_root(root.id).unwrap().unwrap();

        assert!(!r.may_destroy());
        assert!(r.destroy_refusal().unwrap().contains("EINVAL"));
        // Still fully usable for everything that is not destruction.
        FileRepo::new(&mut cat)
            .upsert_file(&r, &stat(r.id, "a.txt"), GEN, Timestamp::from_nanos(2))
            .unwrap();
        assert_eq!(
            FileRepo::new(&mut cat)
                .find_by_norm_key(&r, "a.txt")
                .unwrap()
                .len(),
            1
        );
    }

    /// The refusal reason names WHICH gate refused — a preview and an audit
    /// record both need that, and "cannot destroy" alone helps nobody.
    #[test]
    fn each_gate_reports_itself_by_name() {
        let (mut cat, root) = fixture();
        FileRepo::new(&mut cat)
            .set_resync_required(root.id, true)
            .unwrap();
        let r = FileRepo::new(&mut cat).get_root(root.id).unwrap().unwrap();
        assert!(r.destroy_refusal().unwrap().contains("resync"));

        FileRepo::new(&mut cat)
            .set_resync_required(root.id, false)
            .unwrap();
        FileRepo::new(&mut cat)
            .set_availability(root.id, Availability::Unmounted)
            .unwrap();
        let r = FileRepo::new(&mut cat).get_root(root.id).unwrap().unwrap();
        assert!(r.destroy_refusal().unwrap().contains("unmounted"));
    }

    #[test]
    fn upserting_against_the_wrong_root_is_refused() {
        let (mut cat, root) = fixture();
        let wrong = stat(RootId::new(root.id.get() + 1), "a.txt");
        let err = FileRepo::new(&mut cat).upsert_file(&root, &wrong, GEN, Timestamp::from_nanos(1));
        assert!(
            err.is_err(),
            "a row must not be filed under another root's policies"
        );
    }

    #[test]
    fn dotfiles_have_no_extension() {
        assert_eq!(split_name("a/.gitignore"), (".gitignore".into(), None));
        assert_eq!(
            split_name("a/Report.TXT"),
            ("Report.TXT".into(), Some("txt".into()))
        );
        assert_eq!(split_name("noext"), ("noext".into(), None));
    }
}
