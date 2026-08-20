//! Restore — exclusive-create, then prove the fidelity contract held.
//!
//! # Restore never overwrites, and the primitive matters
//!
//! §4.10.5: "Restore and hydration writes are exclusive-create, never replace.
//! **Shepherd never destroys data by writing**, only by the audited destroy
//! path." Locally that means `O_EXCL` — [`std::fs::File::create_new`] — and
//! **not** a `metadata()` check followed by a `create()`. The check-then-create
//! pair is a TOCTOU: something can appear in the gap, and the loser of that
//! race is a file the user made while this one was gone.
//!
//! [`crate::fidelity::choose_restore_path`] picks the name; this module does
//! the write, and re-checks exclusivity at the syscall because the name may
//! have been taken between the two.
//!
//! # mtime is restored, then read back
//!
//! §4.10.6 puts `mtime` in the floor, partly so a restored file does not
//! instantly re-match an age rule. But *setting* an mtime and *having it stick*
//! are different claims: some filesystems quantise the value on write, so the
//! read-back can differ from what the manifest asked for. That is exactly the
//! kind of gap a pure-logic comparison cannot see, so [`restore_file`] writes,
//! sets, re-reads, and verifies against the manifest — and its test runs
//! against a real temp file rather than a fake.
//!
//! # A failed attempt cleans up after itself, by INODE
//!
//! `create_new` succeeding is not the same fact as the restore succeeding.
//! `ENOSPC` on the write, a failed `sync_all`, a metadata call the filesystem
//! refuses, a read-back that will not read, a fidelity breach — every one of
//! them used to return with the file Shepherd had just created still occupying
//! the destination. The next attempt then found the original path taken, read
//! it as a **user-owned conflict**, and restored the file beside itself while
//! alerting the operator about a collision with Shepherd's own wreckage.
//!
//! The cleanup is bound to the **exact inode this attempt created**, never to
//! the path. Unlinking by path would delete whatever is at the name at cleanup
//! time, and the whole reason `create_new` is used above is that something else
//! can appear at that name — so a path-keyed cleanup would reintroduce, on the
//! error path, precisely the data loss `O_EXCL` closes on the success path.
//! [`discard_failed_attempt`] compares `(dev, ino)` and leaves anything that
//! is not ours alone.
//!
//! ## Why not stage-then-publish
//!
//! Writing to a private staging file and publishing it exclusively is the
//! stronger shape, and it does not fit here. The exclusive publish primitive is
//! `renameat2(RENAME_NOREPLACE)` / `renamex_np(RENAME_EXCL)`, which already
//! exists in `shepherd-placeholder::delete_mode` and is private to it; this
//! crate has no `libc` dependency, so adopting it would mean a second copy of
//! exactly the primitive the workspace centralises. `std::fs::rename` cannot
//! substitute — it **replaces**, which is §4.10.5's prohibition verbatim — and
//! `std::fs::hard_link`, the only exclusive publish in `std`, is unsupported on
//! vfat/exFAT, i.e. on the removable disks §4.4 goes out of its way to keep
//! working. `delete_mode` itself refuses rather than falling back when
//! `RENAME_NOREPLACE` is unavailable; taking the same line here would make
//! restore — a non-destructive operation — start refusing on those
//! filesystems. So the cleanup is inode-bound instead, which the finding names
//! as the alternative.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shepherd_core::{Blake3Hash, Timestamp};

use crate::fidelity::{
    FidelityBreach, FidelityManifest, RestoreTarget, RestoredAttrs, choose_restore_path,
    verify_restore,
};

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("io error at {path}: {detail}")]
    Io { path: String, detail: String },

    /// The path was taken between choosing it and creating it. Not an error to
    /// paper over: it means something else is writing where we are about to.
    #[error("{path} already exists — restore is exclusive-create, never replace")]
    AlreadyExists { path: String },

    /// The bytes or metadata did not survive the round trip (§4.10.6).
    #[error("restore fidelity breached at {path}: {breaches:?}")]
    FidelityBreached {
        path: String,
        breaches: Vec<FidelityBreach>,
    },
}

type Result<T> = std::result::Result<T, RestoreError>;

fn to_system_time(ts: Timestamp) -> SystemTime {
    let n = ts.as_nanos();
    if n >= 0 {
        UNIX_EPOCH + Duration::from_nanos(n as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(n.unsigned_abs())
    }
}

fn from_system_time(st: SystemTime) -> Timestamp {
    match st.duration_since(UNIX_EPOCH) {
        Ok(d) => Timestamp::from_nanos(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)),
        Err(e) => {
            Timestamp::from_nanos(-i64::try_from(e.duration().as_nanos()).unwrap_or(i64::MAX))
        }
    }
}

/// What a restore produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Where it actually landed. A [`RestoreTarget::Conflict`] means the
    /// original path was occupied and the caller owes the user an alert.
    pub target: RestoreTarget,
    pub attrs: RestoredAttrs,
}

impl RestoreOutcome {
    pub fn path(&self) -> &str {
        match &self.target {
            RestoreTarget::Original(p) => p,
            RestoreTarget::Conflict { chosen, .. } => chosen,
        }
    }

    /// Whether the user must be told the file did not land where it came from.
    pub fn needs_conflict_alert(&self) -> bool {
        matches!(self.target, RestoreTarget::Conflict { .. })
    }
}

/// Write `bytes` back, honouring the fidelity contract.
///
/// Exclusive-create at the syscall, then `mtime` and `mode`, then a read-back
/// verified against `manifest`. Returns the breaches rather than a bare failure
/// so a restore report can name what did not survive.
pub fn restore_file(
    original: &Path,
    bytes: &[u8],
    manifest: &FidelityManifest,
) -> Result<RestoreOutcome> {
    let original_s = original.to_string_lossy().to_string();
    let target = choose_restore_path(&original_s, &|p| Path::new(p).exists());
    let chosen = PathBuf::from(match &target {
        RestoreTarget::Original(p) => p.clone(),
        RestoreTarget::Conflict { chosen, .. } => chosen.clone(),
    });

    // O_EXCL, not exists()-then-create. The gap between a check and a create is
    // a window in which the user's own new file can appear, and overwriting it
    // would be Shepherd destroying data by writing.
    let f = std::fs::File::create_new(&chosen).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            RestoreError::AlreadyExists {
                path: chosen.display().to_string(),
            }
        } else {
            RestoreError::Io {
                path: chosen.display().to_string(),
                detail: e.to_string(),
            }
        }
    })?;

    // Captured from the HANDLE, before anything can go wrong, because this is
    // the only moment at which "the inode at `chosen`" and "the inode this
    // attempt created" are known to be the same thing. `None` means the
    // platform (or a failing `fstat`) cannot name it, and a cleanup that cannot
    // prove ownership does nothing — see [`discard_failed_attempt`].
    let created = f.metadata().ok().and_then(|md| inode_of(&md));

    // Every failure from here on goes through the cleanup. Nothing is returned
    // early: an error path that skipped it is exactly the defect this shape
    // exists to make unreachable.
    match write_and_verify(f, &chosen, bytes, manifest) {
        Ok(attrs) => Ok(RestoreOutcome { target, attrs }),
        Err(e) => {
            discard_failed_attempt(&chosen, created);
            Err(e)
        }
    }
}

/// Everything between the exclusive create and a verified restore.
///
/// Split out so that [`restore_file`] has exactly one error path to clean up
/// after, rather than six `?`s each of which has to remember to.
fn write_and_verify(
    mut f: std::fs::File,
    chosen: &Path,
    bytes: &[u8],
    manifest: &FidelityManifest,
) -> Result<RestoredAttrs> {
    let io = |e: std::io::Error| RestoreError::Io {
        path: chosen.display().to_string(),
        detail: e.to_string(),
    };

    f.write_all(bytes).map_err(io)?;
    f.sync_all().map_err(io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(chosen, std::fs::Permissions::from_mode(manifest.core.mode))
            .map_err(io)?;
    }

    // Set mtime last: writing and chmod both touch it.
    f.set_modified(to_system_time(manifest.core.mtime))
        .map_err(io)?;
    drop(f);

    let attrs = read_back(chosen)?;
    if let Err(breaches) = verify_restore(manifest, &attrs) {
        return Err(RestoreError::FidelityBreached {
            path: chosen.display().to_string(),
            breaches,
        });
    }
    Ok(attrs)
}

/// The exact inode one restore attempt created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CreatedInode {
    dev: u64,
    ino: u64,
}

/// `(dev, ino)` where the platform has them.
///
/// `None` off unix is a COVERAGE GAP rather than a solved problem, and it is
/// the same one `destroy.rs` states: Windows has `FILE_ID_INFO` plus a volume
/// serial and nobody has written it, so a failed restore there still leaves its
/// file behind. Phase 3 owns Windows; a cleanup that guessed at identity would
/// be worse than one that declines, because it would unlink by path.
fn inode_of(md: &std::fs::Metadata) -> Option<CreatedInode> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(CreatedInode {
            dev: md.dev(),
            ino: md.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        None
    }
}

/// Remove a failed attempt's file — **only** if the name still holds the inode
/// that attempt created.
///
/// Never unlinks by path alone. Between the failure and this call, the name can
/// have been taken by a file somebody else made, and deleting that would be
/// Shepherd destroying data on the error path of an operation whose whole
/// premise is that it never destroys data. That is the same hazard
/// `identity.rs`'s probe had.
///
/// The `symlink_metadata`-then-`remove_file` pair is itself a TOCTOU, stated
/// rather than hidden: a replacement landing in that window is unlinked. Closing
/// it needs an unlink-by-handle primitive POSIX does not offer, and the window
/// is orders of magnitude smaller than the one this closes — the failed attempt
/// otherwise occupies the path until a human notices.
///
/// Reports rather than returns: the caller already has the real error, and
/// replacing it with a cleanup failure would hide why the restore failed.
fn discard_failed_attempt(chosen: &Path, created: Option<CreatedInode>) {
    let Some(created) = created else {
        tracing::warn!(
            path = %chosen.display(),
            "a failed restore cannot be cleaned up: this platform cannot name the inode \
             it created, so the file is left rather than unlinked by path"
        );
        return;
    };
    match std::fs::symlink_metadata(chosen) {
        Ok(md) if inode_of(&md) == Some(created) => {
            if let Err(e) = std::fs::remove_file(chosen) {
                tracing::error!(
                    path = %chosen.display(),
                    error = %e,
                    "a failed restore could not be cleaned up; the path is occupied by \
                     partial or invalid data and a retry will treat it as a conflict"
                );
            }
        }
        Ok(_) => tracing::warn!(
            path = %chosen.display(),
            "a failed restore's path now holds a DIFFERENT file; leaving it alone rather \
             than deleting something this attempt did not create"
        ),
        // Already gone. Nothing to do, and not a fault.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::error!(
            path = %chosen.display(),
            error = %e,
            "a failed restore's path cannot be statted, so its cleanup cannot prove \
             ownership; leaving the file rather than unlinking by path"
        ),
    }
}

/// Read a restored file's attributes back off the filesystem.
///
/// Separate and public because "we asked for this mtime" and "the filesystem
/// kept it" are different claims, and only the read-back settles the second.
pub fn read_back(path: &Path) -> Result<RestoredAttrs> {
    let bytes = std::fs::read(path).map_err(|e| RestoreError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    let md = std::fs::metadata(path).map_err(|e| RestoreError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    let mtime = md.modified().map_err(|e| RestoreError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = u32::from(md.permissions().readonly());

    Ok(RestoredAttrs {
        blake3: Blake3Hash::from_bytes(*blake3::hash(&bytes).as_bytes()),
        size: bytes.len() as u64,
        mtime: from_system_time(mtime),
        mode,
    })
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;
