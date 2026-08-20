//! Driving one file's upload.
//!
//! # Deliberately thin — the state machine is T9's, not this module's
//!
//! `shepherd-storage::TransferDriver` already owns the
//! `planned → … → committed` machine, all four crash windows, and the resume
//! reconciliation AC-2 measures. Re-implementing any of that here would give
//! the workspace two transfer state machines, which is the same defect as two
//! `StorageAdapter` doubles or two readings of one predicate. This module does
//! exactly two things the driver cannot do for itself:
//!
//! 1. **Serialize on the remote key**, below.
//! 2. Read the source from a real file, which is the `SourceReader` port the
//!    driver takes.
//!
//! # Why the lock is on the remote key and not only on `fs_id`
//!
//! §4.10.7 requires hydrate/dehydrate/upload/verify/destroy/restore to be
//! mutually exclusive **per file**, and `FileLocks::acquire` gives that. But a
//! transfer session is keyed by **remote key**, and §4.9's content addressing
//! makes that mapping many-to-one on purpose: two files with identical content
//! share one object (AC-47's dedup).
//!
//! So an `fs_id` lock does **not** serialize two sessions at one key — and
//! `TransferDriver`'s window-1 recovery aborts *every* live multipart upload at
//! the key it is working on. Two concurrent uploads of duplicate content would
//! therefore have one abort the other's in-flight session, and the loser would
//! restart from zero on a 50 GB object without anything reporting a fault.
//!
//! [`upload_item`] takes `FileLocks::acquire_key` and holds it across the whole
//! driver run for exactly that reason.

use std::path::PathBuf;

use bytes::Bytes;
use shepherd_core::{Blake3Hash, FsId, JobId, Timestamp};
use shepherd_storage::adapter::{ByteRange, StorageAdapter, StorageError, StorageResult};
use shepherd_storage::transfer_session::{
    SourceFingerprint, SourceIdentity, SourceReader, TransferDriver, TransferOutcome,
    TransferSession, TransferSessionStore,
};

use crate::plan::TierItem;
use crate::serialize::FileLocks;

/// A `SourceReader` over a real file.
///
/// Ranged `read_at` rather than a streaming handle because the driver may
/// re-read arbitrary parts on resume, in any order — a sequential reader would
/// have to seek anyway, and pretending otherwise would hide that.
#[derive(Debug)]
pub struct FileSource {
    path: PathBuf,
    /// The **stable** half of the catalog's `fs_id` — the volume identifier.
    /// Kept because it is the one part of the identity a fresh `stat` cannot
    /// supply; the inode half is re-read on every fingerprint.
    volume_id: String,
    /// The identity the caller planned against. Read **only** on platforms
    /// where `shepherd_catalog::volume::fs_id` cannot run — see
    /// [`FileSource::fs_id_of`]. Kept unconditionally so the two builds do
    /// not have two different structs.
    #[cfg_attr(unix, allow(dead_code))]
    planned_fs_id: FsId,
}

impl FileSource {
    /// Classify an I/O failure while reading the source.
    ///
    /// `NotFound` is TERMINAL — the file is gone, so no retry can finish this
    /// transfer and the driver must reap its provider session rather than let
    /// the queue burn its budget. Everything else is transient: a permission
    /// change, a full page cache, a flaky disk are all worth another attempt,
    /// and the parts already uploaded are worth keeping for it.
    fn read_error(&self, op: &str, e: &std::io::Error) -> StorageError {
        if e.kind() == std::io::ErrorKind::NotFound {
            StorageError::NotFound {
                key: self.path.display().to_string(),
            }
        } else {
            StorageError::Transient {
                op: format!("{op} source"),
                detail: e.to_string(),
            }
        }
    }

    /// `fs_id` is the catalog's identity for this file, `<volume-id>:<inode>`
    /// as produced by `shepherd_catalog::volume::fs_id`.
    ///
    /// Only its **volume** half is retained. The inode half is deliberately
    /// discarded: it is the mutable part, and remembering it is what made
    /// [`Self::fingerprint`] hand the driver's guard the same value on both
    /// sides of its own comparison.
    pub fn new(path: impl Into<PathBuf>, fs_id: FsId) -> Self {
        // A catalog `fs_id` is `<volume-id>:<inode>` and the inode is numeric,
        // so the LAST colon splits it. A value with no colon at all is not one
        // this constructor can decompose — it is kept whole rather than
        // silently emptied, which would make every derived identity collide.
        let volume_id = fs_id
            .as_str()
            .rsplit_once(':')
            .map_or_else(|| fs_id.as_str().to_owned(), |(vol, _ino)| vol.to_owned());
        Self {
            path: path.into(),
            volume_id,
            planned_fs_id: fs_id,
        }
    }

    /// The identity of the file the fingerprint just statted.
    ///
    /// Built from **that** stat's inode rather than taking a second one.
    /// `volume::fs_id` re-stats the path, and the two stats can straddle an
    /// unlink: the fingerprint succeeds, the identity lookup does not, and its
    /// `VolumeError::Stat` — `NotFound` underneath — used to be mapped
    /// unconditionally to `Transient`. On a job's final attempt the queue then
    /// failed without anything reaching `abandon`, leaving an `Uploading`
    /// session and its multipart parts allocated.
    ///
    /// One stat has no window to straddle, so the classification problem does
    /// not arise. It also cannot disagree with itself about which file it saw,
    /// which the two-stat form could.
    ///
    /// Still routed through `shepherd_catalog::volume`, via `fs_id_from_ino`,
    /// rather than formatting `<volume>:<ino>` here — for the reason
    /// [`crate::destroy::LocalDestroyRequest::fs_id`] spells out at length: a
    /// locally synthesized identity compiles, compares, and protects nothing,
    /// because it never equals the value the rest of the system uses for the
    /// same file.
    fn fs_id_of(&self, md: &std::fs::Metadata) -> StorageResult<FsId> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let _ = &md;
            Ok(shepherd_catalog::volume::fs_id_from_ino(
                &self.volume_id,
                md.ino(),
            ))
        }
        // A COVERAGE GAP, stated rather than papered over. `volume::fs_id` is
        // `cfg(unix)`; on Windows it returns `Unsupported`, so no caller there
        // can produce a catalog `fs_id` in the first place and this branch is
        // unreachable in production. It exists so the non-unix legs compile.
        // Phase 3 owns `FILE_ID_INFO` + volume serial — see `volume.rs`.
        #[cfg(not(unix))]
        {
            let _ = md;
            Ok(self.planned_fs_id.clone())
        }
    }
}

#[async_trait::async_trait]
impl SourceReader for FileSource {
    async fn fingerprint(&self) -> StorageResult<SourceFingerprint> {
        // A missing source is TERMINAL, everything else transient.
        //
        // Classifying `NotFound` as transient meant a deleted source produced a
        // retryable error, the queue spent its whole attempt budget on a file
        // that was never coming back, and the multipart session stayed
        // `Uploading` with its parts allocated at the provider — with the
        // source gone, nothing later revisits that key to reap them.
        //
        // The ambiguity is real and worth naming: an unmounted volume answers
        // `ENOENT` for the same path. Failing the job is the right response to
        // both — nothing is destroyed by an upload that does not happen, the
        // failure is visible, and a rescan re-enqueues the work when the volume
        // returns. PM-3's root-availability gate is the layer that should stop
        // the job being claimed at all in that case; that wiring is Phase 2's.
        let md = std::fs::metadata(&self.path).map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                StorageError::NotFound {
                    key: self.path.display().to_string(),
                }
            } else {
                StorageError::Transient {
                    op: "stat source".into(),
                    detail: e.to_string(),
                }
            }
        })?;
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| Timestamp::from_nanos(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)))
            .unwrap_or(Timestamp::EPOCH);
        // From the file that was just statted, NOT from what the caller
        // planned with. Copying the planned value here made
        // `TransferDriver::assert_source_unchanged` compare the caller's
        // `fs_id` with the caller's `fs_id` — a comparison whose two sides are
        // the same value, so it could never fail. A path replaced by a
        // different inode of the same size with a preserved mtime was
        // therefore invisible to every one of the fingerprint's three fields.
        //
        // This is a SECOND stat, and the two can straddle a replacement. That
        // races only in the fail-closed direction: the path resolves to the
        // replacement for the later call, so the fingerprint mixes the old
        // size/mtime with the new inode and disagrees with the session — which
        // refuses. There is no interleaving that produces agreement.
        Ok(SourceFingerprint {
            size: md.len(),
            mtime,
            fs_id: self.fs_id_of(&md)?,
        })
    }

    async fn read_range(&self, range: ByteRange) -> StorageResult<Bytes> {
        use std::io::{Read, Seek, SeekFrom};
        // Same classification as `fingerprint`, and for the same reason: a
        // source that is GONE is terminal, so the driver can abandon its
        // provider session instead of the queue retrying a file that is never
        // coming back. This is the path that sees a deletion landing AFTER the
        // fingerprint gate — on a final attempt there is no later fingerprint
        // call to reach `abandon` through, so it has to be reachable from here.
        let mut f = std::fs::File::open(&self.path).map_err(|e| self.read_error("open", &e))?;
        f.seek(SeekFrom::Start(range.offset))
            .map_err(|e| self.read_error("seek", &e))?;
        // A LOOP over `read`, not `read_exact`, so a source that shrank comes
        // back SHORT instead of as an error.
        //
        // `read_exact` reports a concurrent truncation as `UnexpectedEof`,
        // which is an ordinary retryable I/O error by kind — so the driver
        // returned it directly and never reached the abandonment, and on a
        // final attempt the multipart session stayed allocated. Worse, the
        // driver's own short-body branch, which exists to abandon exactly this,
        // was unreachable: `read_exact` never returns a short buffer.
        //
        // Returning the short read puts the decision in the one place that
        // already makes it correctly, rather than teaching this function a
        // second copy of the same rule.
        let want = usize::try_from(range.len).unwrap_or(0);
        let mut buf = vec![0u8; want];
        let mut filled = 0;
        while filled < want {
            match f.read(&mut buf[filled..]) {
                Ok(0) => break, // the file ends here; the caller decides
                Ok(n) => filled += n,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
                Err(e) => return Err(self.read_error("read", &e)),
            }
        }
        buf.truncate(filled);
        Ok(Bytes::from(buf))
    }
}

/// Upload one planned item, resuming an existing session if there is one.
///
/// Holds the **remote-key** lock across the whole run — see the module docs.
///
/// `preferred_part_size` is a hint — [`PartPlan::new`] clamps it into the
/// provider's band. It is a parameter for the same reason
/// `TransferSession::plan` takes one: §4.5 treats part size as a real
/// per-target tuning knob, since a LAN NAS and a metered WAN link do not want
/// the same one, and the plan is persisted so it must be chosen once and then
/// honoured by every resume. [`shepherd_storage::multipart::DEFAULT_PART_SIZE`] is the ordinary argument.
///
/// `size`, `mtime` **and `fs_id`** are read from the source rather than taken
/// as arguments, deliberately. The driver's first act is to compare the
/// session's recorded fingerprint against a fresh one (PM-1's
/// modify-during-upload guard), so a caller-supplied value that disagreed with
/// the filesystem by even one nanosecond would abort the transfer before it
/// started. That is the guard working, but it is a trap in an API: the only
/// correct value is the one the source reports, so the source reports it.
///
/// `fs_id` was the exception, and the exception was the defect. The planned
/// identity was copied into the session *and* into every fresh fingerprint, so
/// the guard's two sides were the same value and a replaced inode could not be
/// seen. The `fs_id` **argument** is still the catalog's, because that is what
/// the lock key must be — see [`crate::destroy::LocalDestroyRequest::fs_id`] —
/// but only its volume half survives into the identity that gets compared.
pub async fn upload_item(
    job: JobId,
    item: &TierItem,
    adapter: &dyn StorageAdapter,
    store: &dyn TransferSessionStore,
    locks: &FileLocks,
    fs_id: FsId,
    preferred_part_size: u64,
) -> StorageResult<TransferOutcome> {
    // Both keyspaces, in the fixed order `acquire_both` imposes, so two call
    // sites cannot deadlock each other.
    let _guards = locks.acquire_both(&fs_id, &item.remote_key).await;

    let source = FileSource::new(&item.path, fs_id);

    // Resume if a session survived; plan a fresh one otherwise. The driver
    // handles every crash window from whichever state it finds.
    let mut session = match store.load(job).await? {
        Some(s) => s,
        None => {
            // From the source, so it cannot disagree with what the driver will
            // re-read a moment later.
            let fp = source.fingerprint().await?;

            // The driver's PM-1 guard starts at session creation, so a file
            // edited between planning (where its hash and key were computed)
            // and here is invisible to it until `Verifying` — after the whole
            // object has been uploaded. Worse, the failed object then sits at a
            // content-addressed key whose name does not describe its bytes, and
            // v1 cannot reap it (D-10 disables GC and the delete verbs are
            // gated), so it poisons conditional-create at that key until scrub
            // flags it.
            //
            // A size change is the cheap half of that check and costs one stat.
            // A same-size edit still slips through to the `Verifying` hash and
            // is documented as scrub-caught rather than claimed closed.
            if fp.size != item.size {
                return Err(StorageError::ContentMismatch {
                    key: item.path.clone(),
                    expected: format!("{} bytes at planning time", item.size),
                    actual: format!("{} bytes now — re-plan rather than upload", fp.size),
                });
            }
            let identity = SourceIdentity {
                file_id: item.file,
                rel_path: item.path.clone(),
                size: fp.size,
                mtime: fp.mtime,
                // From the fingerprint, for the same reason `size` and `mtime`
                // are: the session's recorded identity and the fresh one the
                // driver compares it against must be produced by one procedure,
                // or the guard compares two different notions of identity and
                // refuses every upload.
                // Moved out of `fp`, whose last use this is. Still the
                // *fingerprint's* `fs_id` and deliberately not `item`'s — see
                // `SourceIdentity::fs_id`: the session's identity comes from
                // the statted file, while `acquire_both`'s lock key stays the
                // caller's catalog `fs_id`. Two identities, two purposes.
                fs_id: fp.fs_id,
                blake3: item.blake3,
            };
            let s = TransferSession::plan(
                job,
                item.target,
                item.remote_key.clone(),
                identity,
                adapter,
                preferred_part_size,
            )?;
            store.save(&s).await?;
            s
        }
    };

    TransferDriver::new(adapter, store, &source)
        .run(&mut session)
        .await
}

/// Hash a local file, for the planning step that assigns its content-addressed
/// key.
///
/// Streamed, because the whole point of the tier path is that these files are
/// large — a 50 GB read into a `Vec` would defeat the exercise.
pub fn hash_file(path: &std::path::Path) -> StorageResult<Blake3Hash> {
    use std::io::Read;
    let mut f = std::fs::File::open(path).map_err(|e| StorageError::Transient {
        op: "open source".into(),
        detail: e.to_string(),
    })?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(|e| StorageError::Transient {
            op: "read source".into(),
            detail: e.to_string(),
        })?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Blake3Hash::from_bytes(*hasher.finalize().as_bytes()))
}

#[cfg(test)]
#[path = "upload_tests.rs"]
mod tests;
