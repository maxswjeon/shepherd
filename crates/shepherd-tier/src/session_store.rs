//! The durable `TransferSessionStore`, backed by SQLite.
//!
//! # Why this lives in `shepherd-tier` and not in the catalog
//!
//! `shepherd-catalog` is the **bottom** of the stack: durable rows, with no
//! opinions about who reads them. `job_repo` is row storage rather than the
//! queue; `intent.rs` is the journal rather than the destroy protocol. Making
//! it implement a trait defined in `shepherd-storage` would invert that and put
//! the lowest layer in the business of knowing about a peer.
//!
//! `shepherd-tier` already depends on both, already owns the upload path that
//! creates and resumes these sessions, and is the crate whose dependency edges
//! are most scrutinised — rules 2 and 4 both fence it — so a new edge here gets
//! looked at rather than accumulating quietly.
//!
//! # Why it exists at all
//!
//! `MemStore` does not survive a process. AC-2's gate leg is "kill the daemon
//! mid-upload of a 50 GB file, restart, resume without re-sending verified
//! parts", and **a restart-resume test against an in-memory store measures
//! nothing** — there is no process to kill and nothing to reload from, so the
//! assertion passes without exercising the property. That is the same shape as
//! a test filter matching zero tests and exiting 0.
//!
//! # The durability contract
//!
//! `save` must not return until the record is durable. The whole state machine
//! rests on "the state was persisted before the side effect it authorizes", and
//! a `save` that returns while the write sits in a page cache makes every
//! ordering guarantee in `transfer_session.rs` a comment rather than a fact.
//!
//! That guarantee is **inherited, not assumed**: `shepherd-catalog` asserts
//! `synchronous = FULL` *at open* rather than merely setting the pragma, so a
//! pragma that silently failed to take cannot leave this claim false while
//! everything still looks fine.
//!
//! # Connection ownership — a real constraint, stated
//!
//! This store owns its own `Catalog`, behind a mutex. SQLite's WAL model is
//! many-readers/one-**writer**, so a daemon that runs this alongside another
//! writer on the same database will meet `SQLITE_BUSY` rather than corruption.
//! The daemon's single-writer discipline (`shepherd-jobs`' catalog actor) is
//! the eventual home for that, but its handle is `Send` and not `Sync` — it
//! carries an `mpsc::Sender` — so it cannot satisfy this trait's `Send + Sync`
//! bound as it stands. Routing this through the actor is a daemon-wiring
//! change, and pretending it is already done would be worse than saying so.

use std::sync::Mutex;

use rusqlite::OptionalExtension;
use shepherd_catalog::writer::{CatalogWriter, WriterError};
use shepherd_catalog::{Catalog, CatalogError};
/// The most parts any provider this build speaks to accepts.
///
/// S3's limit, which `multipart::plan` already works to — it grows the part
/// size rather than exceeding this. A persisted count above it did not come
/// from a plan this code made.
const MAX_PARTS: u32 = 10_000;

use shepherd_core::{
    Blake3Hash, FileId, FsId, JobId, ObjectKey, ObjectVersion, TargetId, Timestamp,
};
use shepherd_storage::adapter::{OpaqueToken, StorageError, StorageResult};
use shepherd_storage::multipart::{PartCheckpoint, PartPlan};
use shepherd_storage::transfer_session::{
    AbortOutcome, SourceIdentity, TransferSession, TransferSessionStore, TransferState,
};

/// SQLite-backed transfer sessions.
#[derive(Debug)]
pub struct CatalogSessionStore {
    backend: Backend,
}

/// Where the store's catalog access goes.
///
/// Two forms on purpose, and neither is a fallback for the other:
///
/// * [`Backend::Owned`] holds its own connection. This is what the AC-2 test
///   needs — a restart genuinely opens its own database, and a test sharing the
///   daemon's actor would be exercising something weaker than a restart.
/// * [`Backend::Actor`] routes through the single catalog writer. This is what
///   the **daemon** needs: SQLite's WAL model is many-readers/one-writer, so a
///   second writer on the same file is exactly what the actor exists to
///   prevent.
enum Backend {
    Owned(Mutex<Catalog>),
    Actor(CatalogWriter),
}

// Hand-written because `CatalogWriter` is not `Debug` — it wraps a channel
// sender, and there is nothing useful to print from one. Naming which backend
// is in use is the whole diagnostic value here: "owns its own connection"
// versus "routes through the daemon's single writer" is the difference that
// matters when a `SQLITE_BUSY` shows up in a log.
impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Backend::Owned(_) => f.write_str("Owned(<connection>)"),
            Backend::Actor(_) => f.write_str("Actor(<catalog writer>)"),
        }
    }
}

fn writer_err(e: WriterError) -> StorageError {
    StorageError::Transient {
        op: "transfer_session".into(),
        detail: e.to_string(),
    }
}

fn to_storage(e: CatalogError) -> StorageError {
    StorageError::Transient {
        op: "transfer_session".into(),
        detail: e.to_string(),
    }
}

fn sqlite(e: rusqlite::Error) -> StorageError {
    StorageError::Transient {
        op: "transfer_session".into(),
        detail: e.to_string(),
    }
}

/// `transfer_session.state` — the wire form of [`TransferState`].
///
/// Written out rather than derived from serde so the stored strings match the
/// committed `CHECK` constraint exactly. A mismatch would be caught by SQLite
/// at write time, which is a fine place to find it, but a worse place than
/// here.
fn state_to_str(s: TransferState) -> &'static str {
    match s {
        TransferState::Planned => "planned",
        TransferState::Initiating => "initiating",
        TransferState::Uploading => "uploading",
        TransferState::Completing => "completing",
        TransferState::Verifying => "verifying",
        TransferState::Committed => "committed",
        TransferState::AbortPending => "abort_pending",
        TransferState::Aborted(AbortOutcome::Clean) => "aborted_clean",
        TransferState::Aborted(AbortOutcome::Ambiguous) => "aborted_ambiguous",
    }
}

fn state_from_str(s: &str) -> Option<TransferState> {
    Some(match s {
        "planned" => TransferState::Planned,
        "initiating" => TransferState::Initiating,
        "uploading" => TransferState::Uploading,
        "completing" => TransferState::Completing,
        "verifying" => TransferState::Verifying,
        "committed" => TransferState::Committed,
        "abort_pending" => TransferState::AbortPending,
        "aborted_clean" => TransferState::Aborted(AbortOutcome::Clean),
        "aborted_ambiguous" => TransferState::Aborted(AbortOutcome::Ambiguous),
        _ => return None,
    })
}

fn hash_from(bytes: Option<Vec<u8>>) -> Option<Blake3Hash> {
    let b = bytes?;
    <[u8; 32]>::try_from(b.as_slice())
        .ok()
        .map(Blake3Hash::from_bytes)
}

impl CatalogSessionStore {
    /// Own a connection. For tests and for any caller that is the only writer.
    pub fn new(catalog: Catalog) -> Self {
        Self {
            backend: Backend::Owned(Mutex::new(catalog)),
        }
    }

    /// Open (or create) a catalog at `path` and own it.
    pub fn open(path: &std::path::Path) -> StorageResult<Self> {
        Ok(Self::new(Catalog::open(path).map_err(to_storage)?))
    }

    /// Route through the daemon's single catalog writer.
    ///
    /// # The one way to deadlock this
    ///
    /// `CatalogWriter::with` blocks on a rendezvous channel until the actor
    /// replies. **A store call made from inside another `with` closure wedges
    /// the catalog permanently** — the actor is busy running the outer closure
    /// and can never dequeue the inner one.
    ///
    /// This store is safe by construction rather than by convention, because
    /// [`crate::upload::upload_item`] loads and saves the session at the **top
    /// level** of the upload, before and around the driver run. There is no
    /// arrangement in which its catalog access ends up nested inside another
    /// one. Keep it that way: gather what a transaction needs in one closure,
    /// or make the store call the outer one.
    pub fn with_writer(writer: CatalogWriter) -> Self {
        Self {
            backend: Backend::Actor(writer),
        }
    }
}

#[async_trait::async_trait]
impl TransferSessionStore for CatalogSessionStore {
    /// Upsert the session and its parts in **one transaction**.
    ///
    /// One transaction and not two writes: a session whose row said
    /// "three parts acknowledged" while `transfer_part` held two would make the
    /// resume reconciliation re-send a part it had already proven — harmless —
    /// or skip one it had not — which is how a completed object becomes a
    /// chimera. The two must move together.
    async fn save(&self, session: &TransferSession) -> StorageResult<()> {
        match &self.backend {
            Backend::Owned(m) => {
                let mut cat = m.lock().unwrap_or_else(|e| e.into_inner());
                save_blocking(&mut cat, session)
            }
            Backend::Actor(w) => {
                // Cloned into the closure: `with` needs `'static`, and a
                // session is small next to the object it describes.
                let s = session.clone();
                w.with(move |cat| save_blocking(cat, &s))
                    .map_err(writer_err)?
            }
        }
    }

    /// One part, one row, one transaction.
    ///
    /// `save` replaces the whole part set — deliberately, because
    /// `restart_attempt` has to clear receipts a forgotten provider session
    /// left behind. Ordinary progress is the opposite case: exactly one
    /// checkpoint changed, and rewriting the other 3,199 to record it is what
    /// made a 50 GB upload do ~5.1 million inserts.
    ///
    /// Nothing on the session row is touched. `state` deliberately is not — a
    /// part landing is not a state transition, and the transitions are exactly
    /// what `save` exists to write atomically with the part set — and neither
    /// is `updated_at`, which `save` binds to the source's mtime and is
    /// therefore the same value on every call of a given session.
    async fn save_part(&self, session: &TransferSession, part_no: u32) -> StorageResult<()> {
        match &self.backend {
            Backend::Owned(m) => {
                let mut cat = m.lock().unwrap_or_else(|e| e.into_inner());
                save_part_blocking(&mut cat, session, part_no)
            }
            Backend::Actor(w) => {
                let s = session.clone();
                w.with(move |cat| save_part_blocking(cat, &s, part_no))
                    .map_err(writer_err)?
            }
        }
    }

    async fn load(&self, job_id: JobId) -> StorageResult<Option<TransferSession>> {
        match &self.backend {
            Backend::Owned(m) => {
                let cat = m.lock().unwrap_or_else(|e| e.into_inner());
                load_blocking(&cat, job_id)
            }
            Backend::Actor(w) => w
                .with(move |cat| load_blocking(cat, job_id))
                .map_err(writer_err)?,
        }
    }
}

/// The whole write, against a borrowed catalog.
///
/// Free functions rather than methods so both backends run **identical** SQL.
/// Two copies of a transaction that must stay atomic is how the owned path and
/// the daemon path drift into disagreeing about durability.
fn save_blocking(cat: &mut Catalog, session: &TransferSession) -> StorageResult<()> {
    {
        let tx = cat.conn_mut().transaction().map_err(sqlite)?;

        // Explicit UPDATE-then-INSERT rather than `ON CONFLICT(job_id)`.
        //
        // `transfer_session.job_id` carries **no UNIQUE constraint** — it is a
        // plain `REFERENCES job(id)` — so an upsert targeting it would fail at
        // run time with "ON CONFLICT clause does not match any PRIMARY KEY or
        // UNIQUE constraint". Found by reading the DDL rather than by running
        // it, which is the only reason it is not a runtime surprise.
        //
        // Safe under the single-writer discipline because both statements run
        // inside this transaction. The *schema-level* fix is a UNIQUE index on
        // `job_id`, and it is worth having: `load()` assumes one session per
        // job, so without it the database permits a state this code cannot
        // represent. Raised with the schema owner rather than worked around
        // silently.
        let updated = tx
            .execute(
                "UPDATE transfer_session SET
                    state           = ?2,
                    upload_id       = ?3,
                    attempt_epoch   = ?4,
                    manifest_blake3 = ?5,
                    object_version  = ?6,
                    part_count      = ?7,
                    updated_at      = ?8
                 WHERE job_id = ?1",
                rusqlite::params![
                    session.job_id.get(),
                    state_to_str(session.state),
                    session.upload_id.as_ref().map(|t| t.as_opaque()),
                    i64::from(session.attempt_epoch),
                    session.manifest_blake3.map(|h| h.as_bytes().to_vec()),
                    session.object_version.as_ref().map(|v| v.as_opaque()),
                    i64::from(session.plan.part_count),
                    session.source.mtime.as_nanos(),
                ],
            )
            .map_err(sqlite)?;

        if updated == 0 {
            tx.execute(
                "INSERT INTO transfer_session
                   (job_id, target_id, file_id, remote_key, state,
                    src_size, src_blake3, src_fs_id, src_mtime,
                    upload_id, part_size, part_count, attempt_epoch,
                    manifest_blake3, object_version, created_at, updated_at)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?16)",
                rusqlite::params![
                    session.job_id.get(),
                    session.target.get(),
                    session.source.file_id.get(),
                    session.remote_key.as_str(),
                    state_to_str(session.state),
                    session.source.size as i64,
                    session.source.blake3.as_bytes().to_vec(),
                    session.source.fs_id.as_str(),
                    session.source.mtime.as_nanos(),
                    session.upload_id.as_ref().map(|t| t.as_opaque()),
                    session.plan.part_size as i64,
                    i64::from(session.plan.part_count),
                    i64::from(session.attempt_epoch),
                    session.manifest_blake3.map(|h| h.as_bytes().to_vec()),
                    session.object_version.as_ref().map(|v| v.as_opaque()),
                    session.source.mtime.as_nanos(),
                ],
            )
            .map_err(sqlite)?;
        }

        let session_row: i64 = tx
            .query_row(
                "SELECT id FROM transfer_session WHERE job_id = ?1",
                [session.job_id.get()],
                |r| r.get(0),
            )
            .map_err(sqlite)?;

        // Replace the part set wholesale. `restart_attempt` clears every
        // receipt, and a partial update would leave receipts from a session the
        // provider has already forgotten — which resume would then trust.
        tx.execute(
            "DELETE FROM transfer_part WHERE session_id = ?1",
            [session_row],
        )
        .map_err(sqlite)?;

        for p in &session.parts {
            tx.execute(
                "INSERT INTO transfer_part
                   (session_id, job_id, upload_id, part_no, etag, bytes,
                    local_blake3, checksum, attempt_epoch)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                rusqlite::params![
                    session_row,
                    session.job_id.get(),
                    session.upload_id.as_ref().map(|t| t.as_opaque()),
                    i64::from(p.part_no),
                    p.etag.as_ref().map(|e| e.as_opaque()),
                    p.len as i64,
                    p.local_blake3.as_bytes().to_vec(),
                    p.checksum.as_deref(),
                    i64::from(session.attempt_epoch),
                ],
            )
            .map_err(sqlite)?;
        }

        // Durable before return. `synchronous = FULL` is asserted at open by
        // `shepherd-catalog`, so this commit really is on disk.
        tx.commit().map_err(sqlite)?;
    }
    Ok(())
}

/// The single-part write, against a borrowed catalog.
///
/// Free function for the same reason `save_blocking` is one: both backends must
/// run identical SQL, or the owned path and the daemon path drift into
/// disagreeing about what a checkpoint means.
fn save_part_blocking(
    cat: &mut Catalog,
    session: &TransferSession,
    part_no: u32,
) -> StorageResult<()> {
    let Some(p) = session.parts.iter().find(|p| p.part_no == part_no) else {
        return Err(StorageError::Provider {
            provider: "catalog",
            op: "transfer_part".into(),
            detail: format!("part {part_no} is not in the session being checkpointed"),
        });
    };

    let tx = cat.conn_mut().transaction().map_err(sqlite)?;

    let session_row: i64 = tx
        .query_row(
            "SELECT id FROM transfer_session WHERE job_id = ?1",
            [session.job_id.get()],
            |r| r.get(0),
        )
        .map_err(sqlite)?;

    // `(session_id, part_no)` is the table's PRIMARY KEY, so this upsert has a
    // constraint to target — unlike `save`'s session row, whose `job_id` did
    // not, and which is why that one is an explicit UPDATE-then-INSERT.
    tx.execute(
        "INSERT INTO transfer_part
           (session_id, job_id, upload_id, part_no, etag, bytes,
            local_blake3, checksum, attempt_epoch)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)
         ON CONFLICT(session_id, part_no) DO UPDATE SET
             upload_id = excluded.upload_id, etag = excluded.etag,
             bytes = excluded.bytes, local_blake3 = excluded.local_blake3,
             checksum = excluded.checksum,
             attempt_epoch = excluded.attempt_epoch",
        rusqlite::params![
            session_row,
            session.job_id.get(),
            session.upload_id.as_ref().map(|t| t.as_opaque()),
            i64::from(p.part_no),
            p.etag.as_ref().map(|e| e.as_opaque()),
            p.len as i64,
            p.local_blake3.as_bytes().to_vec(),
            p.checksum.as_deref(),
            i64::from(session.attempt_epoch),
        ],
    )
    .map_err(sqlite)?;

    tx.commit().map_err(sqlite)?;
    Ok(())
}

fn load_blocking(cat: &Catalog, job_id: JobId) -> StorageResult<Option<TransferSession>> {
    {
        let conn = cat.conn();

        let row = conn
            .query_row(
                "SELECT id, target_id, file_id, remote_key, state,
                        src_size, src_blake3, src_fs_id, src_mtime,
                        upload_id, part_size, part_count, attempt_epoch,
                        manifest_blake3, object_version
                 FROM transfer_session WHERE job_id = ?1",
                [job_id.get()],
                |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, i64>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, i64>(5)?,
                        r.get::<_, Option<Vec<u8>>>(6)?,
                        r.get::<_, Option<String>>(7)?,
                        r.get::<_, Option<i64>>(8)?,
                        r.get::<_, Option<String>>(9)?,
                        r.get::<_, i64>(10)?,
                        r.get::<_, Option<i64>>(11)?,
                        r.get::<_, i64>(12)?,
                        r.get::<_, Option<Vec<u8>>>(13)?,
                        r.get::<_, Option<String>>(14)?,
                    ))
                },
            )
            .optional()
            .map_err(sqlite)?;

        let Some(r) = row else { return Ok(None) };

        let state = state_from_str(&r.4).ok_or_else(|| StorageError::Provider {
            provider: "catalog",
            op: "transfer_session".into(),
            detail: format!("unknown state {:?} — refusing to guess", r.4),
        })?;
        // A session with no source hash cannot be resumed: AC-1 makes the hash
        // the precondition for ever destroying the original, so a row without
        // one is corrupt rather than merely incomplete.
        let blake3 = hash_from(r.6).ok_or_else(|| StorageError::Provider {
            provider: "catalog",
            op: "transfer_session".into(),
            detail: "row has no src_blake3; a session without a source hash is unresumable".into(),
        })?;

        let mut parts = Vec::new();
        let mut stmt = conn
            .prepare(
                "SELECT part_no, etag, bytes, local_blake3, checksum
                 FROM transfer_part WHERE session_id = ?1 ORDER BY part_no",
            )
            .map_err(sqlite)?;
        // VALIDATED, not cast. The schema has no CHECK on these columns, so an
        // imported, hand-edited or damaged row can hold a negative — and `as
        // u64` turns that into a value near `u64::MAX`, after which resume
        // derives ranges that make `FileSource::read_range` attempt a
        // near-address-space allocation instead of rejecting the checkpoint.
        // The loader already refuses an unknown state and a missing source
        // hash; a corrupt size is the same kind of row.
        let nonneg = |what: &str, v: i64| -> StorageResult<u64> {
            u64::try_from(v).map_err(|_| StorageError::Provider {
                provider: "catalog",
                op: "transfer_session".into(),
                detail: format!("row has {what} = {v}, which is not a size — refusing to resume"),
            })
        };
        let part_size = nonneg("part_size", r.10)?;
        let src_size = nonneg("src_size", r.5)?;
        // `part_count` was only CONVERTED, and conversion is not validation:
        // `u32::try_from(..).unwrap_or(1)` turned a negative into 1 and let
        // `4_294_967_295` straight through, after which `reconcile_parts`
        // allocates an actions vector of that length and the daemon dies. Zero
        // was accepted too, which is not a plan.
        //
        // Bounded by the same invariant `multipart::plan` works to: no provider
        // this build speaks to takes more than `MAX_PARTS`, so a row above it
        // did not come from a plan this code made.
        let part_count = {
            let raw = r.11.unwrap_or(1);
            u32::try_from(raw)
                .ok()
                .filter(|n| (1..=MAX_PARTS).contains(n))
                .ok_or_else(|| StorageError::Provider {
                    provider: "catalog",
                    op: "transfer_session".into(),
                    detail: format!(
                        "row has part_count = {raw}, outside 1..={MAX_PARTS} — refusing to \
                         resume a plan this build could not have produced"
                    ),
                })?
        };

        // THE LAYOUT, not only the range. A count inside 1..=MAX_PARTS can
        // still describe a plan `PartPlan::new` would never emit, and the range
        // check alone reads as though it had settled that.
        //
        // `part_count == ceil(src_size / part_size)` is the invariant that
        // construction maintains — `div_ceil`, so a remainder gets its own
        // part. A 50 GB source with 16 MiB parts and `part_count = 1` resumes
        // as a one-part upload, completes 16 MiB of it, and then fails
        // whole-object verification on every retry forever: the checkpoint is
        // internally consistent enough to load and cannot ever succeed.
        //
        // A zero part size is its own arm because the division would panic, and
        // because it produces empty ranges rather than wrong ones.
        if part_size == 0 {
            return Err(StorageError::Provider {
                provider: "catalog",
                op: "transfer_session".into(),
                detail: "row has part_size = 0, which describes no upload at all".into(),
            });
        }
        let expected = src_size.div_ceil(part_size).max(1);
        if u64::from(part_count) != expected {
            return Err(StorageError::Provider {
                provider: "catalog",
                op: "transfer_session".into(),
                detail: format!(
                    "row has part_count = {part_count} for {src_size} bytes at {part_size} \
                     bytes per part, which is {expected}; this plan could not have come from \
                     `PartPlan::new`, and resuming it uploads a prefix that can never verify"
                ),
            });
        }
        // The three validated numbers ARE the plan, so the per-part ranges come
        // from `PartPlan` itself rather than from a second copy of its
        // arithmetic living here.
        let plan = PartPlan {
            total_size: src_size,
            part_size,
            part_count,
        };
        let rows = stmt
            .query_map([r.0], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                    row.get::<_, Option<String>>(4)?,
                ))
            })
            .map_err(sqlite)?;
        for row in rows {
            let (part_no, etag, bytes, local, checksum) = row.map_err(sqlite)?;
            let bytes = nonneg("a part's `bytes`", bytes)?;
            // Against the PLAN, not merely against `u32`. The comment that
            // replaced `unwrap_or_default` said multipart parts are 1-based and
            // then only checked the conversion — so 0 and every value above
            // `part_count` still loaded. Reconciliation ignores such a
            // checkpoint, but the stale row survives in `session.parts` and
            // `acknowledged_receipts` hands it to `complete_multipart`, which
            // fails the completion even after every valid part is uploaded.
            let part_no = u32::try_from(part_no)
                .ok()
                .filter(|n| (1..=part_count).contains(n))
                .ok_or_else(|| StorageError::Provider {
                    provider: "catalog",
                    op: "transfer_session".into(),
                    detail: format!(
                        "row has part_no = {part_no}, outside 1..={part_count} — it belongs to \
                         no part of this plan"
                    ),
                })?;
            // Against the PLAN, both halves. The offset was already derived
            // rather than stored — `part_size` is immutable for a session's
            // life, which is what makes the column redundant — but `bytes` was
            // taken as given, so an imported, hand-edited or damaged row could
            // name a length no part of this plan has.
            //
            // That is not caught later. Reconciliation SKIPS a part whose
            // provider listing agrees with the persisted length, and a session
            // reloaded in `completing` never reconciles at all. Completion then
            // publishes a truncated object under a content-addressed key, and
            // because the key names bytes the object does not contain, every
            // retry fails verification forever — the object cannot be repaired,
            // only abandoned. So the refusal belongs at LOAD, where the
            // session can still be rejected as a whole.
            //
            // `range_of` rather than the formula again: this file derived the
            // offset by hand, and a second copy of a plan's arithmetic is the
            // way the two stop agreeing.
            let range = plan
                .range_of(part_no)
                .ok_or_else(|| StorageError::Provider {
                    provider: "catalog",
                    op: "transfer_session".into(),
                    detail: format!("part {part_no} has no range in a {part_count}-part plan"),
                })?;
            if bytes != range.len {
                return Err(StorageError::Provider {
                    provider: "catalog",
                    op: "transfer_session".into(),
                    detail: format!(
                        "part {part_no} is recorded as {bytes} bytes, but this plan's part \
                         {part_no} is {} bytes ({src_size} bytes in {part_count} parts of \
                         {part_size}); resuming it publishes an object whose content-addressed \
                         key names bytes it does not contain",
                        range.len
                    ),
                });
            }
            parts.push(PartCheckpoint {
                part_no,
                offset: range.offset,
                len: range.len,
                local_blake3: hash_from(local).unwrap_or(Blake3Hash::from_bytes([0u8; 32])),
                etag: etag.map(OpaqueToken::new),
                // PERSISTED now, and the old comment here was wrong about the
                // gap it dismissed. It said the resume path re-adopts the
                // checksum from the provider's `list_parts` — true for a resume
                // that runs `upload_pending`, and a session reloaded in
                // `completing` never does. It starts AT completion, echoes
                // `checksum: None` for every part, and a checksum-enabled
                // provider answers `InvalidPart`: the one state where the value
                // could not be re-fetched was the one state that needed it.
                //
                // Opaque, like the etag beside it. `restart_attempt` clears both
                // together, because a receipt from a session the provider has
                // forgotten proves nothing about the next one.
                checksum,
            });
        }

        Ok(Some(TransferSession {
            job_id,
            target: TargetId::new(r.1),
            remote_key: ObjectKey::new(r.3),
            source: SourceIdentity {
                file_id: FileId::new(r.2),
                // NOT PERSISTED. `transfer_session` stores `file_id`,
                // `remote_key` and the source fingerprint, but no source path,
                // so a resumed session cannot say which file it is uploading.
                //
                // Not a correctness gap: the resume path takes its path from
                // the `TierItem` the caller holds, and the PM-1 guard compares
                // `(size, mtime, fs_id)` rather than the name. It is a
                // DIAGNOSTIC gap — a resumed session's errors name an empty
                // path — and it is left empty rather than reconstructed from
                // `file_id`, because a plausible-looking path recovered by a
                // join is worse than an obviously absent one.
                rel_path: String::new(),
                size: src_size,
                mtime: Timestamp::from_nanos(r.8.unwrap_or_default()),
                fs_id: FsId::new(r.7.unwrap_or_default()),
                blake3,
            },
            state,
            plan: PartPlan {
                total_size: src_size,
                part_size,
                part_count,
            },
            attempt_epoch: u32::try_from(r.12).unwrap_or_default(),
            upload_id: r.9.map(OpaqueToken::new),
            parts,
            manifest_blake3: hash_from(r.13),
            // NOT PERSISTED, and the loss is symmetric: `transfer_session` has
            // no `attestation_mode` column, so `save_blocking` has nothing to
            // write and this has nothing to read. `None` is what the row
            // genuinely says, not a placeholder for a value hiding elsewhere in
            // it — the same distinction `checksum` above draws.
            //
            // What it would have said is which mechanism the driver probed at
            // verify (§4.10.2's A or B), stamped onto the session by
            // `TransferDriver::verify`. Reconstructing it here is not available:
            // re-probing needs an adapter this function does not have, and
            // defaulting to either mechanism is exactly the "silently landing on
            // B while believing A" §4.10.2 forbids.
            //
            // It is **latent rather than live**, and that is a claim about
            // today's consumers rather than a judgement that it does not matter.
            // Nothing reads a reloaded session's copy: the destroy predicate
            // takes its attestation from `revalidate::Location`, whose durable
            // source is the catalog's `target.attestation_mode` — a separate
            // column, probed at target registration, fail-closed at `'none'`
            // (see `shepherd-daemon`'s `target_add`) — and the destroy audit
            // record's `attestation` field is written from that same `Location`.
            // The one assertion that does read it, `m2_e2e`'s, runs against
            // `MemStore`, which keeps the whole struct in memory.
            //
            // So the first consumer that needs the verification claim to survive
            // a restart makes this a `transfer_session` column plus both sides
            // of the SQL, not a repair inside this function. Recorded here
            // rather than closed, because a column added for no reader is a
            // migration nobody can justify and a field hard-coded away is a gap
            // nobody can find.
            attestation_mode: None,
            object_version: r.14.map(ObjectVersion::new),
        }))
    }
}

#[cfg(test)]
#[path = "session_store_tests.rs"]
mod tests;
