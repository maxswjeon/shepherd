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
    let mut f = std::fs::File::create_new(&chosen).map_err(|e| {
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
    f.write_all(bytes).map_err(|e| RestoreError::Io {
        path: chosen.display().to_string(),
        detail: e.to_string(),
    })?;
    f.sync_all().map_err(|e| RestoreError::Io {
        path: chosen.display().to_string(),
        detail: e.to_string(),
    })?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&chosen, std::fs::Permissions::from_mode(manifest.core.mode))
            .map_err(|e| RestoreError::Io {
                path: chosen.display().to_string(),
                detail: e.to_string(),
            })?;
    }

    // Set mtime last: writing and chmod both touch it.
    f.set_modified(to_system_time(manifest.core.mtime))
        .map_err(|e| RestoreError::Io {
            path: chosen.display().to_string(),
            detail: e.to_string(),
        })?;
    drop(f);

    let attrs = read_back(&chosen)?;
    if let Err(breaches) = verify_restore(manifest, &attrs) {
        return Err(RestoreError::FidelityBreached {
            path: chosen.display().to_string(),
            breaches,
        });
    }

    Ok(RestoreOutcome { target, attrs })
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
