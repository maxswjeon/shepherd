//! The `StorageAdapter` ABI.
//!
//! # Why this trait has `create` and not `put`
//!
//! Every write verb here is **immutable create**. There is no `put`, no
//! `rename`, no `move_to_trash`, and adding one would be a change to this file
//! that a reviewer sees. That is deliberate and load-bearing well beyond
//! tidiness:
//!
//! * §4.9 makes object keys content-addressed (`objects/<b3[0:2]>/<b3[2:4]>/<b3>`).
//!   A key therefore *names its own bytes*. Overwriting a key with different
//!   bytes is not a legal state of the system, so the ABI does not offer a verb
//!   that produces it.
//! * §4.10.5 requires that "Shepherd never destroys data by writing". An
//!   adapter that cannot express overwrite cannot violate that rule by mistake —
//!   the guarantee is structural rather than a code-review convention.
//! * OQ-1's replica records are immutable by construction for the same reason:
//!   a pointer record that could be replaced is a pointer record that a
//!   restarted writer with a stale listing can silently orphan.
//!
//! The two destructive verbs that do exist are split exactly as §4.1 rule 4
//! requires. [`StorageAdapter::delete_object`] touches user data and is callable
//! only from `shepherd-tier::destroy`; [`StorageAdapter::delete_system_object`]
//! is scoped **by construction** — not by convention — to the `_shepherd/`
//! control prefix, because it takes a [`ControlKey`], which cannot be built from
//! a key outside that prefix.
//!
//! # ETags are opaque
//!
//! §4.5: upload ids and ETags are "opaque tokens — never parsed, never assumed
//! to be content hashes". [`OpaqueToken`] has no accessor that invites either,
//! and no `From<OpaqueToken> for Blake3Hash` exists anywhere in this crate. An
//! ETag can be compared with a previously observed ETag to answer "is this the
//! same part I uploaded?"; it can never answer "do these bytes hash to X?".
//! That question is answered only by reading the bytes back and hashing them.

use std::fmt;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use shepherd_core::{Blake3Hash, CONTROL_PREFIX, ObjectKey, ObjectVersion};

/// A provider-issued token: a multipart upload id, an ETag, a continuation
/// token.
///
/// Deliberately not `Blake3Hash`, and deliberately without a hex or byte
/// accessor. The only legal operations are equality against another token from
/// the same provider and round-tripping it back to that provider.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueToken(String);

impl OpaqueToken {
    pub fn new(v: impl Into<String>) -> Self {
        Self(v.into())
    }

    /// The token exactly as the provider issued it. Send it back; do not
    /// interpret it.
    pub fn as_opaque(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for OpaqueToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Rendered as `opaque(...)` so a log line can never be misread as a
        // content hash by a human skimming it.
        write!(f, "opaque({})", self.0)
    }
}

/// A key proven to live under the `_shepherd/` control prefix.
///
/// This is how §4.1 rule 4's "scoped by construction to the `_shepherd/`
/// prefix" is made true rather than asserted. `delete_system_object` accepts
/// only this type, so replica maintenance physically cannot be handed a user
/// data key — there is no constructor that would produce one.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ControlKey(ObjectKey);

impl ControlKey {
    /// `None` if `key` is not under `_shepherd/`.
    pub fn new(key: ObjectKey) -> Option<Self> {
        key.is_control_object().then_some(Self(key))
    }

    /// Build a control key from a path *relative to* the control prefix.
    pub fn under(rel: impl AsRef<str>) -> Self {
        Self(ObjectKey::new(format!("{CONTROL_PREFIX}{}", rel.as_ref())))
    }

    pub fn as_key(&self) -> &ObjectKey {
        &self.0
    }
}

/// How a target proves that a remote object is the object Shepherd verified
/// (§4.10.2).
///
/// Probed at target registration and recorded per target — never assumed. The
/// S3 rider in §4.10.2 is the reason: **bucket versioning is off by default**,
/// so an ordinary S3/MinIO bucket is [`AttestationMode::Content`], and
/// "silently landing on B while believing A is exactly how a safety claim
/// decays into a slogan".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttestationMode {
    /// Mechanism A — the provider attests. Immutable version ids; a cheap HEAD
    /// after the local hash is a genuine re-attestation.
    Version,
    /// Mechanism B — Shepherd attests. The BLAKE3 is committed into the key, so
    /// a full re-read that hashes to the expected value proves the key holds
    /// exactly those bytes. A closing HEAD catches deletion and truncation
    /// **only** — it is not a re-attestation.
    Content,
    /// Neither. Destruction is refused, permanently.
    None,
}

impl AttestationMode {
    /// Whether a target in this mode may ever authorize destroying the last
    /// local copy.
    ///
    /// §4.10.2's destroy predicate requires `attestation_mode != none`. Encoded
    /// here so the fail-closed direction is a property of the type rather than
    /// something each call site re-derives.
    pub fn permits_destruction(self) -> bool {
        !matches!(self, AttestationMode::None)
    }

    /// Whether the closing cheap HEAD of §4.10.2's ordering genuinely
    /// re-attests identity, or merely proves existence and size.
    pub fn head_reattests(self) -> bool {
        matches!(self, AttestationMode::Version)
    }
}

/// What a reader can assume about this provider's LIST.
///
/// OQ-1 marks LIST uniformity `[U]`: S3/Azure/GCS are strongly consistent,
/// Drive and Graph are index-backed with propagation lag, SMB and NFS give no
/// ordering guarantee. A provider whose visibility cannot be bounded stays
/// `custody_eligible = false`, so this is not cosmetic metadata.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListVisibility {
    /// A create is visible to a subsequent exhaustive listing.
    Strong,
    /// Visible within a bounded window.
    Bounded,
    /// No bound can be stated. Custody-ineligible.
    Unbounded,
}

/// Static facts about a provider that the provider-agnostic layers branch on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdapterCapabilities {
    /// Short provider name, for logs and audit records.
    pub provider: &'static str,
    /// Whether exclusive create (`If-None-Match: *` or equivalent) is offered.
    ///
    /// OQ-1: where this is `true` Shepherd **uses it and treats failure as a
    /// hard error**. Iteration 2 called it "an optimization, never a
    /// requirement", which was wrong — it is the difference between detecting
    /// an epoch collision at write time and discovering it at recovery.
    pub conditional_create: bool,
    /// Smallest legal non-final part.
    pub min_part_size: u64,
    /// Largest legal part.
    pub max_part_size: u64,
    /// Largest legal part number (S3: 10 000).
    pub max_parts: u32,
    pub list_visibility: ListVisibility,
}

/// Whether a create must be exclusive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CreatePrecondition {
    /// Fail if the key already exists. Requires
    /// [`AdapterCapabilities::conditional_create`].
    IfAbsent,
    /// No precondition. Legal only where the substrate offers nothing better —
    /// collision-proof keys and hash chaining carry the load there (OQ-1).
    Unconditional,
}

/// What Shepherd knows about a remote object after a HEAD or a create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: ObjectKey,
    pub size: u64,
    /// Present only under [`AttestationMode::Version`].
    pub version: Option<ObjectVersion>,
    /// Opaque. Not a content hash — see the module docs.
    pub etag: Option<OpaqueToken>,
}

/// The receipt for a completed create, single-shot or multipart.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CreateReceipt {
    pub key: ObjectKey,
    pub version: Option<ObjectVersion>,
    pub etag: Option<OpaqueToken>,
}

/// A part as the provider reports it. `etag` is opaque.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartReceipt {
    pub part_no: u32,
    pub size: u64,
    pub etag: OpaqueToken,
}

/// A multipart upload the provider still considers live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncompleteUpload {
    pub key: ObjectKey,
    pub upload_id: OpaqueToken,
}

/// A half-open byte range, used to stream a full-content verification without
/// buffering the object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub offset: u64,
    pub len: u64,
}

/// One page of a listing.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ListPage {
    pub keys: Vec<ObjectKey>,
    /// `Some` if more pages remain. OQ-1 requires **pagination exhausted, not
    /// first-page**, so callers must loop until this is `None`.
    pub next: Option<OpaqueToken>,
}

/// A version-scoped deletion guard.
///
/// §4.10.2: "Deletion is version-scoped (`If-Match`) so a discard cannot
/// destroy a *replacement*." Under mechanism B there is no version to scope to,
/// and the guard records that explicitly rather than defaulting to "no guard".
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionGuard {
    /// Delete only if the object still carries this version.
    Version(ObjectVersion),
    /// Mechanism B: the key is content-addressed, so the key *is* the guard.
    ContentAddressed { expect: Blake3Hash },
}

/// Errors an adapter can return.
///
/// The variants a caller must distinguish are the ones that change control
/// flow: a lost provider session ([`StorageError::NoSuchUpload`]) restarts a
/// transfer, a failed precondition ([`StorageError::PreconditionFailed`]) is a
/// hard error under OQ-1, and only [`StorageError::Transient`] may be retried.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum StorageError {
    #[error("object not found: {key}")]
    NotFound { key: String },

    /// The provider forgot the multipart session — expiry, an abort, or a
    /// lifecycle rule. §4.5 requires this to be distinguishable, because the
    /// only correct response is to restart the upload under a new attempt
    /// epoch rather than to retry the part.
    #[error("provider no longer knows upload session for {key}")]
    NoSuchUpload { key: String },

    /// An `If-None-Match` / `If-Match` precondition failed.
    #[error("precondition failed for {key}: {detail}")]
    PreconditionFailed { key: String, detail: String },

    /// The provider does not offer a primitive this call needs.
    #[error("{provider} does not support {what}")]
    Unsupported {
        provider: &'static str,
        what: String,
    },

    /// Retryable: a timeout, a 5xx, a dropped connection.
    #[error("transient failure on {op}: {detail}")]
    Transient { op: String, detail: String },

    /// Everything else the provider reported. Not retryable by default —
    /// failing closed is the direction that cannot lose data.
    #[error("{provider} error on {op}: {detail}")]
    Provider {
        provider: &'static str,
        op: String,
        detail: String,
    },

    /// The bytes read back did not hash to the expected value.
    #[error("content mismatch at {key}: expected {expected}, read {actual}")]
    ContentMismatch {
        key: String,
        expected: String,
        actual: String,
    },
}

impl StorageError {
    /// Only [`StorageError::Transient`] is retryable.
    ///
    /// Mirrors `CoreError::is_retryable`'s reasoning: retrying a fail-closed
    /// decision is how a fail-closed system becomes a fail-open one. In
    /// particular a [`StorageError::ContentMismatch`] is never retried — a
    /// second read that happens to succeed would not make the first
    /// disagreement go away.
    pub fn is_retryable(&self) -> bool {
        matches!(self, StorageError::Transient { .. })
    }
}

pub type StorageResult<T> = Result<T, StorageError>;

/// The provider ABI.
///
/// `async_trait` rather than native `async fn` in traits because one `target`
/// row selects one adapter at runtime, so this must be usable as
/// `dyn StorageAdapter`, and AFIT is not dyn-compatible on the pinned
/// toolchain.
#[async_trait::async_trait]
pub trait StorageAdapter: Send + Sync + fmt::Debug {
    fn capabilities(&self) -> &AdapterCapabilities;

    /// Probe how this target can attest object identity (§4.10.2).
    ///
    /// Probed, never assumed — an S3 bucket without versioning is
    /// [`AttestationMode::Content`], and believing otherwise is a silent
    /// downgrade of a safety claim.
    async fn probe_attestation_mode(&self) -> StorageResult<AttestationMode>;

    /// Immutable create of a whole small object.
    ///
    /// Used for control objects (pointer records, bootstrap) — never for user
    /// data, which is always multipart so it is always resumable (spec:89).
    async fn create(
        &self,
        key: &ObjectKey,
        body: Bytes,
        precondition: CreatePrecondition,
    ) -> StorageResult<CreateReceipt>;

    async fn create_multipart(&self, key: &ObjectKey) -> StorageResult<OpaqueToken>;

    async fn upload_part(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
        part_no: u32,
        body: Bytes,
    ) -> StorageResult<PartReceipt>;

    /// Every part the provider currently holds for this session.
    ///
    /// **Implementations must exhaust pagination.** S3 pages `ListParts` at
    /// 1000, and a 50 GB object at 16 MiB parts is 3 200 parts, so a
    /// first-page-only reconcile would re-send verified parts or complete with
    /// a truncated part list — an AC-2 failure either way.
    async fn list_parts(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
    ) -> StorageResult<Vec<PartReceipt>>;

    async fn complete_multipart(
        &self,
        key: &ObjectKey,
        upload_id: &OpaqueToken,
        parts: &[PartReceipt],
        precondition: CreatePrecondition,
    ) -> StorageResult<CreateReceipt>;

    async fn abort_multipart(&self, key: &ObjectKey, upload_id: &OpaqueToken) -> StorageResult<()>;

    /// Live multipart sessions under `prefix`.
    ///
    /// §4.5: "Killed uploads are reaped so incomplete multiparts do not accrue
    /// storage cost." This is what the reaper enumerates.
    async fn list_incomplete_uploads(&self, prefix: &str) -> StorageResult<Vec<IncompleteUpload>>;

    /// Existence, size and — under mechanism A — version.
    ///
    /// `Ok(None)` means absent. Absence is a legitimate answer here, so it is
    /// not an error.
    async fn head(&self, key: &ObjectKey) -> StorageResult<Option<ObjectMeta>>;

    /// Read one range. Full-object verification loops this; see
    /// [`verify_full_content`].
    async fn get_range(&self, key: &ObjectKey, range: ByteRange) -> StorageResult<Bytes>;

    /// One page of a prefix listing. Callers must loop until
    /// [`ListPage::next`] is `None`.
    async fn list(&self, prefix: &str, page: Option<&OpaqueToken>) -> StorageResult<ListPage>;

    /// Destroy a user-data object. **Callable only from
    /// `shepherd-tier::destroy`** (§4.1 rule 4); `cargo xtask check-deps` rule
    /// 4a enforces that no other file so much as names it.
    async fn delete_object(&self, key: &ObjectKey, guard: &VersionGuard) -> StorageResult<()>;

    /// Destroy a `_shepherd/` control object. Callable by replica maintenance
    /// and never counted by the discard breaker — the [`ControlKey`] argument
    /// is what confines it to the control prefix by construction.
    async fn delete_system_object(&self, key: &ControlKey) -> StorageResult<()>;
}

/// Read `key` in `chunk` sized ranges and prove it hashes to `expected`.
///
/// This is AC-1's mandatory full re-read, and it is the **only** thing in this
/// crate that may conclude "the remote bytes are the right bytes". It streams
/// rather than buffering: a 50 GB object verified by
/// `get_range(..).await?` into one `Vec<u8>` would need 50 GB of RAM, so the
/// hasher is fed range by range.
///
/// A short read is treated as truncation and fails closed.
pub async fn verify_full_content(
    adapter: &dyn StorageAdapter,
    key: &ObjectKey,
    expected: Blake3Hash,
    size: u64,
    chunk: u64,
) -> StorageResult<()> {
    debug_assert!(chunk > 0, "chunk size must be positive");
    let mut hasher = blake3::Hasher::new();
    let mut offset = 0u64;
    while offset < size {
        let len = chunk.min(size - offset);
        let bytes = adapter.get_range(key, ByteRange { offset, len }).await?;
        if bytes.len() as u64 != len {
            return Err(StorageError::ContentMismatch {
                key: key.as_str().to_owned(),
                expected: format!("{len} bytes at offset {offset}"),
                actual: format!("{} bytes", bytes.len()),
            });
        }
        hasher.update(&bytes);
        offset += len;
    }
    let actual = Blake3Hash::from_bytes(*hasher.finalize().as_bytes());
    if actual != expected {
        return Err(StorageError::ContentMismatch {
            key: key.as_str().to_owned(),
            expected: expected.to_hex(),
            actual: actual.to_hex(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn control_key_cannot_be_built_from_a_user_data_key() {
        assert!(ControlKey::new(ObjectKey::new("objects/ab/cd/abcd")).is_none());
        assert!(ControlKey::new(ObjectKey::new("_shepherd/catalog/ptr-1-1-x.json")).is_some());
        // The convenience constructor always lands inside the prefix.
        assert!(
            ControlKey::under("catalog/ptr-1-1-x.json")
                .as_key()
                .is_control_object()
        );
    }

    #[test]
    fn only_transient_failures_are_retryable() {
        assert!(
            StorageError::Transient {
                op: "upload_part".into(),
                detail: "timeout".into()
            }
            .is_retryable()
        );
        // A hash disagreement is terminal: a second read that happens to
        // succeed would not unmake the first disagreement.
        assert!(
            !StorageError::ContentMismatch {
                key: "k".into(),
                expected: "a".into(),
                actual: "b".into()
            }
            .is_retryable()
        );
        assert!(
            !StorageError::NoSuchUpload { key: "k".into() }.is_retryable(),
            "a lost session must restart the transfer, not retry the part"
        );
    }

    #[test]
    fn attestation_none_fails_closed_and_only_version_reattests() {
        assert!(!AttestationMode::None.permits_destruction());
        assert!(AttestationMode::Content.permits_destruction());
        assert!(AttestationMode::Version.permits_destruction());

        assert!(AttestationMode::Version.head_reattests());
        // §4.10.2: under mechanism B the closing HEAD proves existence and size
        // only. Claiming otherwise is the exact decay this flag prevents.
        assert!(!AttestationMode::Content.head_reattests());
    }

    #[test]
    fn opaque_token_debug_does_not_look_like_a_hash() {
        let t = OpaqueToken::new("d41d8cd98f00b204e9800998ecf8427e");
        assert_eq!(format!("{t:?}"), "opaque(d41d8cd98f00b204e9800998ecf8427e)");
    }
}
