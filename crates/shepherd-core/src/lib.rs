//! Shepherd domain types, identifiers and errors.
//!
//! # This crate performs no I/O
//!
//! §4.1 dependency rule 1 says `shepherd-core` depends on nothing internal, and
//! the crate description says "NO I/O". `#![forbid(unsafe_code)]` plus the
//! absence of any filesystem, network or database dependency is what makes that
//! true rather than aspirational; `cargo xtask check-deps` enforces the
//! dependency half on every build.
//!
//! Everything here is data that other crates produce and consume: the free
//! metadata a scan collects, the per-root stub mode, the custody class that P1's
//! restated truth model turns on, and the identifiers that address them.

#![forbid(unsafe_code)]

pub mod error;
pub mod ids;

pub use error::{CoreError, Result};
pub use ids::{
    AuditId, Blake3Hash, CONTROL_PREFIX, FileId, FsId, IntentId, JobId, ObjectKey, ObjectVersion,
    RootId, RuleId, TargetId,
};

use serde::{Deserialize, Serialize};

/// Nanoseconds since the Unix epoch.
///
/// A fixed integer epoch rather than `SystemTime`, because these values are
/// written to SQLite, compared against remote timestamps, and round-tripped
/// through JSON-RPC. AC-5's restore-fidelity contract asserts `mtime` equality
/// after a restore, so the representation must not lose precision on the way.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub const EPOCH: Timestamp = Timestamp(0);

    pub const fn from_nanos(n: i64) -> Self {
        Self(n)
    }

    pub const fn as_nanos(self) -> i64 {
        self.0
    }

    pub const fn as_secs(self) -> i64 {
        self.0.div_euclid(1_000_000_000)
    }
}

/// What happens to a file's bytes locally once it is durably remote.
///
/// Per scan root, not global: AC-10 requires the *same root* to be switchable
/// between modes. Linux is delete-mode only (§3 "Linux headless-only,
/// delete-mode"); placeholders are a Windows and macOS capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StubMode {
    /// Leave an OS placeholder that hydrates on open (Windows cfapi, macOS
    /// File Provider).
    Dehydrate,
    /// Remove the local file outright. The only mode available on Linux.
    Delete,
}

/// P1's restated truth model: which kind of thing a catalog row is.
///
/// This is the distinction that decides what a disaster-recovery bundle must
/// carry (§4.10.3a). Getting it wrong is not a display bug — a `Custody` row is
/// the *only address* of bytes that no longer exist locally.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CustodyClass {
    /// Rebuildable from the filesystem by re-scanning. Safe to discard.
    Derived,
    /// The only address of a destroyed original. Recoverable only via the
    /// replica, so it must be in the recovery bundle.
    Custody,
    /// User-authored configuration, derived from nothing: targets, rules,
    /// delete policies, schedules, settings, model choices.
    DurableConfig,
}

impl CustodyClass {
    /// Whether losing this row loses information that cannot be rebuilt by
    /// re-scanning the filesystem.
    pub fn requires_replica(self) -> bool {
        matches!(self, CustodyClass::Custody | CustodyClass::DurableConfig)
    }
}

/// The metadata a scan collects without reading file contents.
///
/// `blake3` is `Option` on purpose: §6 Phase 1 makes BLAKE3 hashing "its own job
/// class (never a scan prerequisite)", so a freshly walked file legitimately has
/// no hash yet. Modelling it as non-optional would have forced the scan to hash,
/// which is the coupling that phase explicitly removes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileStat {
    pub root: RootId,
    /// Path relative to the scan root, in the platform's native separators.
    pub rel_path: String,
    pub size: u64,
    pub mtime: Timestamp,
    pub ctime: Timestamp,
    /// `None` where the platform or mount does not report a usable atime;
    /// §4.12's `atime_mode` detection decides that per root.
    pub atime: Option<Timestamp>,
    pub blake3: Option<Blake3Hash>,
    /// The inode, as the walk's own `stat` reported it — **and only where it is
    /// meaningful against the ROOT's volume id.**
    ///
    /// Carried from the walk rather than re-`stat`ed at write time for two
    /// reasons: the writer actor must not do filesystem I/O, and a second
    /// `stat` by path would be a different file if the path was replaced in
    /// between — which is precisely the event this identity exists to detect.
    ///
    /// `None` on platforms with no inode, on any entry whose metadata could not
    /// be read, and on any entry that lives on a NESTED MOUNT: the catalog
    /// pairs this with the root's `volume_id`, and an inode is unique only
    /// within its own filesystem, so a nested-mount inode would collide with a
    /// root-filesystem one under a single `fs_id`. See
    /// `shepherd_scan::walk::on_root_volume`.
    pub ino: Option<u64>,
}

impl FileStat {
    /// Whether this row can take part in a tiering decision that ends in
    /// destruction.
    ///
    /// AC-1 makes a remote re-read hash match the precondition for destroying
    /// anything, and a hash match is not expressible without a local hash.
    pub fn is_hash_bearing(&self) -> bool {
        self.blake3.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unhashed_rows_cannot_reach_a_destroy_decision() {
        let mut f = FileStat {
            root: RootId::new(1),
            rel_path: "a/b.txt".into(),
            size: 10,
            mtime: Timestamp::from_nanos(1),
            ctime: Timestamp::from_nanos(1),
            atime: None,
            blake3: None,
            ino: None,
        };
        assert!(!f.is_hash_bearing());
        f.blake3 = Some(Blake3Hash::from_bytes([0u8; 32]));
        assert!(f.is_hash_bearing());
    }

    #[test]
    fn custody_and_config_need_the_replica_derived_does_not() {
        assert!(CustodyClass::Custody.requires_replica());
        assert!(CustodyClass::DurableConfig.requires_replica());
        assert!(!CustodyClass::Derived.requires_replica());
    }

    #[test]
    fn timestamp_seconds_floor_toward_negative_infinity() {
        assert_eq!(Timestamp::from_nanos(1_500_000_000).as_secs(), 1);
        assert_eq!(Timestamp::from_nanos(-1).as_secs(), -1);
    }

    #[test]
    fn stub_mode_serializes_as_snake_case() {
        let j = serde_json::to_string(&StubMode::Dehydrate).unwrap();
        assert_eq!(j, "\"dehydrate\"");
    }
}
