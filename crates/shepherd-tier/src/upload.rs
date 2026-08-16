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
    fs_id: FsId,
}

impl FileSource {
    pub fn new(path: impl Into<PathBuf>, fs_id: FsId) -> Self {
        Self {
            path: path.into(),
            fs_id,
        }
    }
}

#[async_trait::async_trait]
impl SourceReader for FileSource {
    async fn fingerprint(&self) -> StorageResult<SourceFingerprint> {
        let md = std::fs::metadata(&self.path).map_err(|e| StorageError::Transient {
            op: "stat source".into(),
            detail: e.to_string(),
        })?;
        let mtime = md
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| Timestamp::from_nanos(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)))
            .unwrap_or(Timestamp::EPOCH);
        Ok(SourceFingerprint {
            size: md.len(),
            mtime,
            fs_id: self.fs_id.clone(),
        })
    }

    async fn read_range(&self, range: ByteRange) -> StorageResult<Bytes> {
        use std::io::{Read, Seek, SeekFrom};
        let mut f = std::fs::File::open(&self.path).map_err(|e| StorageError::Transient {
            op: "open source".into(),
            detail: e.to_string(),
        })?;
        f.seek(SeekFrom::Start(range.offset))
            .map_err(|e| StorageError::Transient {
                op: "seek source".into(),
                detail: e.to_string(),
            })?;
        let mut buf = vec![0u8; usize::try_from(range.len).unwrap_or(0)];
        f.read_exact(&mut buf)
            .map_err(|e| StorageError::Transient {
                op: "read source".into(),
                detail: e.to_string(),
            })?;
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
/// `size` and `mtime` are read from the source rather than taken as arguments,
/// deliberately. The driver's first act is to compare the session's recorded
/// fingerprint against a fresh one (PM-1's modify-during-upload guard), so a
/// caller-supplied value that disagreed with the filesystem by even one
/// nanosecond would abort the transfer before it started. That is the guard
/// working, but it is a trap in an API: the only correct value is the one the
/// source reports, so the source reports it.
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

    let source = FileSource::new(&item.path, fs_id.clone());

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
                fs_id,
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
