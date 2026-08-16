//! The `PlaceholderProvider` trait — where every destructive syscall lives.
//!
//! # Why this crate exists at all
//!
//! §4.1 rule 2: **no crate except `shepherd-tier` may depend on
//! `shepherd-placeholder`.** The destructive syscalls genuinely must live in a
//! platform crate, because each is a different OS API — `unlink` here,
//! `CfDehydratePlaceholder` on Windows, File Provider eviction on macOS. Cargo
//! cannot forbid a syscall, but it can forbid an edge, so putting them behind
//! this one means **the only path to any of them runs through
//! `shepherd-tier::destroy`**. `cargo xtask check-deps` fails the build if that
//! edge is ever drawn from anywhere else.
//!
//! # The trait is split by reversibility, not by convenience
//!
//! §4.10.1's ordering interleaves storage calls between filesystem operations:
//!
//! ```text
//! 0. open-handle precondition (OQ-J)
//! 1. probe safety floors (AC-8) + acquire handle
//! 2. rename into staging (RENAME_NOREPLACE)   <- reversible
//! 3. compare identity: (dev, ino) of the staged handle == the verified one
//! 4. re-hash THROUGH THE STAGED HANDLE        <- second-to-last
//! 5. cheap remote HEAD                         (async, in shepherd-tier)
//! 6. unlink the staged entry                  <- irreversible
//! ```
//!
//! So destruction cannot be one call. It is split where the reversibility
//! changes:
//!
//! * [`PlaceholderProvider::stage_for_destruction`] — step 2. §4.10.1 describes
//!   it as converting the TOCTOU "into a **reversible** state", and reversible
//!   is exactly why it is not a tracked destructive symbol.
//! * [`PlaceholderProvider::destroy_local`] — step 6. Irreversible, tracked by
//!   `deps-policy.toml`, and callable only from `shepherd-tier::destroy`.
//! * [`PlaceholderProvider::restore_staged`] — §4.10.4's move-back, the
//!   recovery direction. Also reversible, also untracked.
//!
//! The rejected alternative is named in §4.10.1: `unlinkat` followed by a
//! post-check on `st_nlink == 0` "*unlinks the replacement file before
//! discovering the race* — it detects wrong-file deletion after committing it".

use std::fmt;
use std::path::{Path, PathBuf};

use shepherd_core::Blake3Hash;

#[derive(Debug, thiserror::Error)]
pub enum ProviderError {
    #[error("cannot acquire {path}: {detail}")]
    Acquire { path: String, detail: String },

    /// `RENAME_NOREPLACE` refused because the destination exists. On the
    /// staging path this means a stale entry; on the move-back path it means
    /// the original path was reoccupied while the file was staged.
    #[error("destination already exists: {path}")]
    DestinationExists { path: String },

    /// The staged handle is not the file that was verified. §4.10.1 step 3.
    #[error("identity mismatch for {path}: verified {expected}, staged {actual}")]
    IdentityMismatch {
        path: String,
        expected: String,
        actual: String,
    },

    /// The filesystem does not support identity-bound staging (`EINVAL` from
    /// `RENAME_NOREPLACE` on some FUSE/exFAT mounts). §4.10.1: **there is no
    /// detect-only fallback** — the root is marked `destruction_ineligible`
    /// rather than falling back to pathname deletion.
    #[error("{path}: filesystem supports neither identity-bound staging nor writer exclusion")]
    NotFeasible { path: String },

    #[error("io error on {path}: {detail}")]
    Io { path: String, detail: String },

    #[error("{0} is not implemented on this platform yet")]
    Unsupported(&'static str),
}

pub type Result<T> = std::result::Result<T, ProviderError>;

/// Which destruction primitive a root uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderMode {
    /// Unix delete-mode roots: rename-into-staging, then unlink. The reference
    /// implementation, and the only one Linux has.
    DeleteMode,
    /// Windows: `SetFileInformationByHandle` + `FileDispositionInfoEx` on the
    /// held handle — no pathname is ever re-resolved. Phase 3.
    CloudFilesApi,
    /// macOS File Provider: eviction is the primitive, staging is not used, and
    /// the identity predicate is the File Provider item identifier plus content
    /// hash rather than `(dev, ino)`. Phase 3.
    FileProvider,
}

/// Whether a root can host identity-bound destruction at all (D-12).
///
/// §4.10.1 requires this to be answered by a **probe at enrollment**, not
/// discovered at destroy time. A root that fails it is scanned, indexed,
/// searched and may be *copied* to a target — but its originals are never
/// destroyed. That is a real, user-visible capability reduction, and disclosing
/// it up front is the point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Feasibility {
    /// Identity-bound staging works. Destruction is permitted.
    Supported,
    /// It does not. `destruction_ineligible` for this root, with a reason a
    /// human can act on.
    Ineligible { reason: String },
}

impl Feasibility {
    pub fn is_supported(&self) -> bool {
        matches!(self, Feasibility::Supported)
    }
}

/// OS-level identity of an open file, compared at §4.10.1 step 3.
///
/// Taken from the **held handle**, never re-derived from the path — the whole
/// point of the staging design is that no pathname is re-resolved between
/// verification and destruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileIdentity {
    pub dev: u64,
    pub ino: u64,
    pub nlink: u64,
}

impl fmt::Display for FileIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "dev={} ino={} nlink={}", self.dev, self.ino, self.nlink)
    }
}

/// A file renamed into staging and still held open.
///
/// Holds the descriptor acquired at step 1, **before** the rename. `rename()`
/// does not invalidate open descriptors, which is what lets step 4 hash through
/// this handle rather than reopening a path that could by then resolve
/// somewhere else.
///
/// It is also, per §4.10.1, exactly what a crash leaves behind: staged files are
/// discoverable by scanning the staging directory, and recovery is
/// **move-back, never complete-forward**.
#[derive(Debug)]
pub struct Staged {
    /// Where the file was. The move-back target.
    pub original: PathBuf,
    /// Where it is now.
    pub staged: PathBuf,
    /// Identity as read from the held handle after staging.
    pub identity: FileIdentity,
    /// The handle acquired before the rename.
    pub handle: std::fs::File,
}

/// What a move-back did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreOutcome {
    /// The file is back at its original path.
    Restored { path: PathBuf },
    /// The original path was occupied, so the file was restored under a
    /// conflict name. §4.10.1 requires an alert, not a silent overwrite — the
    /// occupant may be a file the user created while this one was staged.
    Conflicted { path: PathBuf, original: PathBuf },
}

/// The destructive primitives for one platform.
///
/// Every method that irreversibly destroys user data is named per the contract
/// in `xtask/deps-policy.toml`: `destroy_local`, `dehydrate_placeholder`,
/// `evict_placeholder`. A destructive method under any other name is
/// **unchecked by rule 4**, so adding one means adding it to that policy in the
/// same change.
pub trait PlaceholderProvider: Send + Sync + fmt::Debug {
    fn mode(&self) -> ProviderMode;

    /// D-12's enrollment probe. Cheap, and run once per root.
    fn probe_feasibility(&self, root: &Path) -> Result<Feasibility>;

    /// §4.10.1 steps 1–3: acquire a handle, rename into staging with
    /// `RENAME_NOREPLACE`, and read identity back from the held handle.
    ///
    /// Reversible: [`PlaceholderProvider::restore_staged`] undoes it. Not a
    /// tracked destructive symbol, so any module may call it.
    fn stage_for_destruction(&self, path: &Path) -> Result<Staged>;

    /// §4.10.1 step 6 — **the irreversible one**.
    ///
    /// Unlinks the staged entry. Tracked by `deps-policy.toml`; `check-deps`
    /// rule 4 fails the build if anything but `shepherd-tier::destroy` calls
    /// it, and `clippy::disallowed_methods` denies it everywhere but
    /// `destroy.rs`.
    ///
    /// `expected` is the hash proven at step 4, carried here so an
    /// implementation can record what it destroyed. It is **not** re-checked
    /// here: re-reading at this point would reopen the window step 4 exists to
    /// close.
    fn destroy_local(&self, staged: &Staged, expected: Blake3Hash) -> Result<()>;

    /// §4.10.4's move-back. Recovery is **abort-forward-never**: a crash
    /// between rename and unlink restores the file, it never completes the
    /// destruction it cannot prove is still correct.
    fn restore_staged(&self, staged: Staged) -> Result<RestoreOutcome>;

    /// Every staged entry a crash left behind, for recovery at startup.
    fn list_staged(&self, root: &Path) -> Result<Vec<PathBuf>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feasibility_is_explicit_about_ineligibility() {
        assert!(Feasibility::Supported.is_supported());
        let f = Feasibility::Ineligible {
            reason: "RENAME_NOREPLACE returned EINVAL".into(),
        };
        assert!(!f.is_supported());
    }

    #[test]
    fn identity_renders_all_three_fields() {
        let id = FileIdentity {
            dev: 66306,
            ino: 12345,
            nlink: 1,
        };
        let s = id.to_string();
        assert!(s.contains("dev=66306") && s.contains("ino=12345") && s.contains("nlink=1"));
    }
}
