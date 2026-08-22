//! Identifiers.
//!
//! Every id is a distinct newtype. The catalog holds file, root, rule, target,
//! job and object identities side by side, and §4.9 makes identity a
//! safety-critical concern: the catalog is the *only address* of a destroyed
//! original, so an id used in the wrong position is a data-loss bug, not a type
//! error you find in testing. Newtypes make that class unrepresentable.
//!
//! Nothing here performs I/O. Deriving a content-addressed key, probing a
//! root's case/normalization policy and computing `fs_id` on stable volume
//! identity are Phase 1 catalog concerns (§4.9); this module supplies only the
//! types they produce.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Declare an opaque id newtype over a monotonic integer.
macro_rules! int_id {
    ($(#[$m:meta])* $name:ident, $prefix:literal) => {
        $(#[$m])*
        #[derive(
            Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub i64);

        impl $name {
            pub const fn new(v: i64) -> Self {
                Self(v)
            }
            pub const fn get(self) -> i64 {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, concat!($prefix, "{}"), self.0)
            }
        }
    };
}

int_id!(
    /// A file tracked in the catalog.
    FileId,
    "file:"
);
int_id!(
    /// A registered scan root.
    RootId,
    "root:"
);
int_id!(
    /// A tiering or delete rule.
    RuleId,
    "rule:"
);
int_id!(
    /// A configured storage target.
    TargetId,
    "target:"
);
int_id!(
    /// A queued unit of work.
    JobId,
    "job:"
);
int_id!(
    /// An entry in the append-only audit log (§4.10).
    AuditId,
    "audit:"
);
int_id!(
    /// A record in the fsync'd intent journal (§4.10).
    IntentId,
    "intent:"
);

/// A BLAKE3 content hash.
///
/// Stored as raw bytes rather than a hex `String` so a hash can never be
/// compared against a differently-cased or differently-encoded rendering of
/// itself. AC-1 makes an equality test on this value the precondition for
/// irreversible destruction.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Blake3Hash(pub [u8; 32]);

impl Blake3Hash {
    pub const fn from_bytes(b: [u8; 32]) -> Self {
        Self(b)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        let mut s = String::with_capacity(64);
        for b in self.0 {
            s.push(char::from_digit((b >> 4) as u32, 16).unwrap_or('0'));
            s.push(char::from_digit((b & 0x0f) as u32, 16).unwrap_or('0'));
        }
        s
    }

    /// Parse 64 lowercase or uppercase hex characters.
    pub fn from_hex(s: &str) -> Option<Self> {
        if s.len() != 64 {
            return None;
        }
        let mut out = [0u8; 32];
        let bytes = s.as_bytes();
        for (i, slot) in out.iter_mut().enumerate() {
            let hi = (bytes[i * 2] as char).to_digit(16)?;
            let lo = (bytes[i * 2 + 1] as char).to_digit(16)?;
            *slot = ((hi << 4) | lo) as u8;
        }
        Some(Self(out))
    }
}

impl fmt::Debug for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Blake3Hash({})", self.to_hex())
    }
}

impl fmt::Display for Blake3Hash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

/// A provider-assigned object version (S3 version id, Azure ETag, Graph
/// cTag, …).
///
/// §4.5 is explicit that these are **opaque tokens**: never parsed, never
/// assumed to be content hashes. The newtype exposes no accessor that would
/// invite either.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectVersion(String);

impl ObjectVersion {
    pub fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }

    /// The token as the provider gave it. Compare it; do not interpret it.
    pub fn as_opaque(&self) -> &str {
        &self.0
    }
}

/// A storage key: the remote address of one object.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ObjectKey(String);

impl ObjectKey {
    pub fn new(k: impl Into<String>) -> Self {
        Self(k.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Whether this key lives under the `_shepherd/` control prefix.
    ///
    /// §4.1 rule 4 and §4.5 both hang on this distinction: control objects are
    /// reachable by replica maintenance and by `delete_system_object`, and are
    /// never counted by the discard breaker. User data is neither.
    pub fn is_control_object(&self) -> bool {
        self.0.starts_with(CONTROL_PREFIX)
    }
}

/// The prefix reserved for Shepherd's own control objects (§4.5).
pub const CONTROL_PREFIX: &str = "_shepherd/";

/// Stable volume identity, used so a remount does not orphan catalog rows
/// (§4.9). Its derivation is per-platform and lives in `shepherd-catalog`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct FsId(String);

impl FsId {
    pub fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_hex_roundtrip() {
        let mut raw = [0u8; 32];
        for (i, b) in raw.iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(7).wrapping_add(3);
        }
        let h = Blake3Hash::from_bytes(raw);
        let hex = h.to_hex();
        assert_eq!(hex.len(), 64);
        assert_eq!(Blake3Hash::from_hex(&hex), Some(h));
        assert_eq!(Blake3Hash::from_hex(&hex.to_uppercase()), Some(h));
    }

    #[test]
    fn hash_hex_rejects_malformed() {
        assert_eq!(Blake3Hash::from_hex(""), None);
        assert_eq!(Blake3Hash::from_hex(&"0".repeat(63)), None);
        assert_eq!(Blake3Hash::from_hex(&"z".repeat(64)), None);
    }

    #[test]
    fn control_prefix_detection() {
        assert!(ObjectKey::new("_shepherd/replica/seg-0001").is_control_object());
        assert!(!ObjectKey::new("data/photos/img.raw").is_control_object());
        // A user path that merely mentions the prefix is not a control object.
        assert!(!ObjectKey::new("home/_shepherd/notes.txt").is_control_object());
    }

    #[test]
    fn ids_are_distinct_types_and_display_tagged() {
        assert_eq!(FileId::new(7).to_string(), "file:7");
        assert_eq!(JobId::new(7).to_string(), "job:7");
    }
}
