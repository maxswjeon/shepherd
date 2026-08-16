//! Verification tests, against the shared in-memory adapter.

use super::*;
use bytes::Bytes;
use shepherd_storage::testing::MemAdapter;

fn hash_of(b: &[u8]) -> Blake3Hash {
    Blake3Hash::from_bytes(*blake3::hash(b).as_bytes())
}

const BODY: &[u8] = b"tiered bytes that must round-trip exactly";

fn key() -> ObjectKey {
    ObjectKey::new("objects/aa/bb/aabb")
}

#[tokio::test]
async fn a_correct_object_verifies_and_records_both_timestamps() {
    let a = MemAdapter::content_addressed();
    a.put_raw(&key(), Bytes::from_static(BODY));

    let v = verify_upload(
        &a,
        &key(),
        hash_of(BODY),
        BODY.len() as u64,
        TargetId::new(1),
        Timestamp::from_nanos(99),
    )
    .await
    .expect("verify");

    assert_eq!(v.attestation_mode, AttestationMode::Content);
    assert_eq!(v.size, BODY.len() as u64);
    // PM-2: presence and integrity are different claims, recorded separately.
    assert_eq!(v.presence_checked_at, Timestamp::from_nanos(99));
    assert_eq!(v.full_hash_verified_at, Timestamp::from_nanos(99));
}

#[tokio::test]
async fn a_versioned_target_pins_a_version_and_a_content_target_does_not() {
    let versioned = MemAdapter::versioned();
    versioned.put_raw(&key(), Bytes::from_static(BODY));
    let v = verify_upload(
        &versioned,
        &key(),
        hash_of(BODY),
        BODY.len() as u64,
        TargetId::new(1),
        Timestamp::from_nanos(1),
    )
    .await
    .expect("verify");
    assert_eq!(v.attestation_mode, AttestationMode::Version);
    assert!(v.object_version.is_some(), "mechanism A must pin a version");

    let content = MemAdapter::content_addressed();
    content.put_raw(&key(), Bytes::from_static(BODY));
    let v = verify_upload(
        &content,
        &key(),
        hash_of(BODY),
        BODY.len() as u64,
        TargetId::new(1),
        Timestamp::from_nanos(1),
    )
    .await
    .expect("verify");
    assert_eq!(
        v.object_version, None,
        "recording a version under mechanism B would invite a closing HEAD to \
         re-attest against a value the provider never guaranteed"
    );
}

/// The whole point of AC-1's full re-read.
#[tokio::test]
async fn a_same_size_content_replacement_is_caught_because_a_head_alone_is_not_enough() {
    let a = MemAdapter::content_addressed();
    let mut wrong = BODY.to_vec();
    wrong[0] ^= 0xff; // same length, different bytes
    a.put_raw(&key(), Bytes::from(wrong));

    let err = verify_upload(
        &a,
        &key(),
        hash_of(BODY),
        BODY.len() as u64,
        TargetId::new(1),
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("must fail");
    assert!(
        matches!(err, StorageError::ContentMismatch { .. }),
        "got {err:?}"
    );
    assert!(!err.is_retryable(), "a hash disagreement is terminal");
}

#[tokio::test]
async fn a_wrong_size_is_caught_before_paying_for_a_full_read() {
    let a = MemAdapter::content_addressed();
    a.put_raw(&key(), Bytes::from_static(b"short"));
    let err = verify_upload(
        &a,
        &key(),
        hash_of(BODY),
        BODY.len() as u64,
        TargetId::new(1),
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("must fail");
    assert!(matches!(err, StorageError::ContentMismatch { .. }));
}

#[tokio::test]
async fn the_whole_object_checksum_is_captured_rather_than_dropped() {
    // The upload asks the provider for a whole-object checksum precisely so the
    // scrub path can compare against it later WITHOUT egress. If verification
    // does not capture it, the value is gone and the whole upload-time decision
    // bought nothing.
    let a = MemAdapter::content_addressed();
    a.put_raw(&key(), Bytes::from_static(BODY));
    let v = verify_upload(
        &a,
        &key(),
        hash_of(BODY),
        BODY.len() as u64,
        TargetId::new(1),
        Timestamp::from_nanos(1),
    )
    .await
    .expect("verify");

    // The in-memory adapter models a provider that offers none, so this is the
    // documented fallback: scrub must read this object back in full.
    assert_eq!(
        v.whole_object_checksum, None,
        "a provider that offers no checksum must leave the field empty, \
         not fabricate one"
    );
    // The field exists so `remote_object.checksum_kind` can be written from it.
    let _: Option<ObjectChecksum> = v.whole_object_checksum;
}

#[tokio::test]
async fn a_missing_object_is_not_found_rather_than_a_silent_pass() {
    let a = MemAdapter::content_addressed();
    let err = verify_upload(
        &a,
        &key(),
        hash_of(BODY),
        BODY.len() as u64,
        TargetId::new(1),
        Timestamp::from_nanos(1),
    )
    .await
    .expect_err("must fail");
    assert!(matches!(err, StorageError::NotFound { .. }));
}
