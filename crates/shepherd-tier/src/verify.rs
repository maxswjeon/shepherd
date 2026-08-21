//! Post-upload verification (AC-1).
//!
//! # Thin, and the thinness is the point
//!
//! `shepherd-storage::verify_full_content` is the full re-read. This module
//! adds only what the *tiering decision* needs on top of it: pin the
//! attestation, and refuse to record a location as verified on a target that
//! could never authorize a destruction anyway.
//!
//! # A HEAD is not a verification, and the type says so
//!
//! PM-2's distinction is that `last_presence_check_at` and
//! `last_full_hash_verified_at` are different columns because they are
//! different claims. [`VerifiedLocation`] carries both timestamps separately
//! for the same reason: a caller cannot accidentally satisfy AC-1 by writing
//! the cheap one.

use shepherd_core::{Blake3Hash, ObjectKey, ObjectVersion, TargetId, Timestamp};
use shepherd_storage::adapter::{
    AttestationMode, ObjectChecksum, StorageAdapter, StorageError, StorageResult,
    verify_full_content_of,
};

/// The chunk size for the streaming full-content read.
pub const VERIFY_CHUNK: u64 = 16 * 1024 * 1024;

/// What a successful verification established.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLocation {
    pub target: TargetId,
    pub key: ObjectKey,
    pub size: u64,
    /// Pinned under mechanism A; `None` under B.
    pub object_version: Option<ObjectVersion>,
    pub attestation_mode: AttestationMode,
    /// A HEAD proved the object exists. **Presence only.**
    pub presence_checked_at: Timestamp,
    /// A full read proved the bytes hash correctly. This is AC-1's claim, and
    /// it is never set by a HEAD.
    pub full_hash_verified_at: Timestamp,
    /// The provider's whole-object checksum, where it offered one.
    ///
    /// Recorded so `remote_object.checksum_kind` can be written from it. This
    /// is the value the scrub path compares against on later passes WITHOUT
    /// egress — which is the entire reason the upload asks for it, and it is
    /// dropped forever if it is not captured at the moment of verification.
    ///
    /// `None` means scrub must read this object back in full.
    pub whole_object_checksum: Option<ObjectChecksum>,
}

/// Verify an uploaded object end to end.
///
/// HEAD for existence and size, then the attestation probe, then the mandatory
/// full re-read.
///
/// The order matters and the probe used to be LAST, under a comment claiming
/// that probing first would make a target that cannot attest pay for the full
/// read — which is the argument for the order it did not have. A target
/// reporting `AttestationMode::None` is refused permanently, and it was refused
/// only after a 50 GB object had been downloaded and hashed: minutes and paid
/// egress spent to reach a conclusion the probe alone establishes.
///
/// The probe cannot move above the HEAD: a size mismatch is the cheaper
/// refusal, and it is about this object rather than about the target.
pub async fn verify_upload(
    adapter: &dyn StorageAdapter,
    key: &ObjectKey,
    expected: Blake3Hash,
    expected_size: u64,
    target: TargetId,
    now: Timestamp,
) -> StorageResult<VerifiedLocation> {
    let meta = adapter
        .head(key)
        .await?
        .ok_or_else(|| StorageError::NotFound {
            key: key.as_str().to_owned(),
        })?;
    if meta.size != expected_size {
        return Err(StorageError::ContentMismatch {
            key: key.as_str().to_owned(),
            expected: format!("{expected_size} bytes"),
            actual: format!("{} bytes", meta.size),
        });
    }

    let mode = adapter.probe_attestation_mode().await?;
    if mode == AttestationMode::None {
        // The bytes may well be correct — but this target can never authorize
        // destroying the original, so recording the location as custody-bearing
        // would overstate what was established. Fail closed here rather than
        // let §4.10.2's predicate discover it later, and fail closed BEFORE the
        // full read rather than after: the answer does not depend on the bytes.
        return Err(StorageError::Unsupported {
            provider: adapter.capabilities().provider,
            what: format!(
                "target has no attestation mechanism, so {} can hold a replica but never \
                 authorize a destruction",
                key.as_str()
            ),
        });
    }

    // AC-1. Streamed by range: a 50 GB object read into one buffer would need
    // 50 GB of RAM, and these are exactly the objects the tier path exists for.
    //
    // BY VERSION, pinned to the one the HEAD above returned. Unversioned ranges
    // hash whatever is current while they are being read, which is a different
    // claim from the one `VerifiedLocation` records: a writer that replaces the
    // object between the HEAD and the reads, with bytes that happen to match,
    // leaves this returning `object_version: meta.version` for bytes nobody
    // hashed. Deleting the replacement then exposes that earlier version again,
    // and its closing HEAD authorizes a destruction on the strength of a
    // verification that never looked at it. Same fix the transfer-session path
    // took, and it is the same mistake — the pin has to reach the reads, not
    // only the record.
    verify_full_content_of(
        adapter,
        key,
        meta.version.as_ref(),
        expected,
        expected_size,
        VERIFY_CHUNK,
    )
    .await?;

    Ok(VerifiedLocation {
        target,
        key: key.clone(),
        size: meta.size,
        // Pinned only where the provider actually attests it. Recording a
        // version under mechanism B would invite a later closing HEAD to
        // "re-attest" against a value the provider never guaranteed.
        object_version: (mode == AttestationMode::Version)
            .then_some(meta.version)
            .flatten(),
        attestation_mode: mode,
        presence_checked_at: now,
        full_hash_verified_at: now,
        // Only a genuinely whole-object value. A composite digest-of-digests
        // would never match a checksum of the bytes, so persisting one would
        // make every multipart object look corrupt on its first scrub.
        whole_object_checksum: meta.whole_object_checksum.filter(|c| c.whole_object),
    })
}

#[cfg(test)]
#[path = "verify_tests.rs"]
mod tests;
