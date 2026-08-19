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
                    local_blake3, attempt_epoch)
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
                rusqlite::params![
                    session_row,
                    session.job_id.get(),
                    session.upload_id.as_ref().map(|t| t.as_opaque()),
                    i64::from(p.part_no),
                    p.etag.as_ref().map(|e| e.as_opaque()),
                    p.len as i64,
                    p.local_blake3.as_bytes().to_vec(),
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
                "SELECT part_no, etag, bytes, local_blake3
                 FROM transfer_part WHERE session_id = ?1 ORDER BY part_no",
            )
            .map_err(sqlite)?;
        let part_size = r.10 as u64;
        let rows = stmt
            .query_map([r.0], |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Option<String>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, Option<Vec<u8>>>(3)?,
                ))
            })
            .map_err(sqlite)?;
        for row in rows {
            let (part_no, etag, bytes, local) = row.map_err(sqlite)?;
            let part_no = u32::try_from(part_no).unwrap_or_default();
            parts.push(PartCheckpoint {
                part_no,
                // Derived, not stored: `part_size` is immutable for a session's
                // life, which is what makes this safe and the column redundant.
                offset: u64::from(part_no.saturating_sub(1)) * part_size,
                len: bytes as u64,
                local_blake3: hash_from(local).unwrap_or(Blake3Hash::from_bytes([0u8; 32])),
                etag: etag.map(OpaqueToken::new),
                // Not stored and not derivable: `transfer_part` has no checksum
                // column, so `None` is what the row genuinely says rather than a
                // placeholder for a value hiding elsewhere.
                //
                // What keeps that from being a gap is the resume path: a part
                // whose etag and size still agree with the provider adopts the
                // checksum from the provider's own `list_parts` response, which
                // resume already fetches to verify those two fields. The value
                // comes back on the same round trip, from the authority that has
                // to receive it again at completion.
                checksum: None,
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
                size: r.5 as u64,
                mtime: Timestamp::from_nanos(r.8.unwrap_or_default()),
                fs_id: FsId::new(r.7.unwrap_or_default()),
                blake3,
            },
            state,
            plan: PartPlan {
                total_size: r.5 as u64,
                part_size,
                part_count: u32::try_from(r.11.unwrap_or(1)).unwrap_or(1),
            },
            attempt_epoch: u32::try_from(r.12).unwrap_or_default(),
            upload_id: r.9.map(OpaqueToken::new),
            parts,
            manifest_blake3: hash_from(r.13),
            attestation_mode: None,
            object_version: r.14.map(ObjectVersion::new),
        }))
    }
}

#[cfg(test)]
#[path = "session_store_tests.rs"]
mod tests;
