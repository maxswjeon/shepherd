//! Verification tests, against the shared in-memory adapter.

use super::*;
use bytes::Bytes;
use shepherd_storage::adapter::ChecksumAlgorithm;
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

/// Helper for the two `Some` branches, which had no coverage at all until the
/// adapter's checksum became settable.
async fn verify_with_checksum(c: ObjectChecksum) -> Option<ObjectChecksum> {
    let a = MemAdapter::content_addressed();
    a.put_raw(&key(), Bytes::from_static(BODY));
    a.set_whole_object_checksum(Some(c));
    verify_upload(
        &a,
        &key(),
        hash_of(BODY),
        BODY.len() as u64,
        TargetId::new(1),
        Timestamp::from_nanos(1),
    )
    .await
    .expect("verify")
    .whole_object_checksum
}

#[tokio::test]
async fn a_genuine_whole_object_checksum_survives_verification() {
    // The value scrub compares against on every later pass WITHOUT egress. It
    // is measured on real S3 and MinIO alike (ADR 0b §3a), and `9f241ef` is
    // proof this link gets dropped: it was already broken once, silently,
    // because every step still returned Ok.
    let got = verify_with_checksum(ObjectChecksum {
        algorithm: ChecksumAlgorithm::Crc64Nvme,
        value: "CnmyweQWB7U=".into(),
        whole_object: true,
    })
    .await;

    assert_eq!(
        got,
        Some(ObjectChecksum {
            algorithm: ChecksumAlgorithm::Crc64Nvme,
            value: "CnmyweQWB7U=".into(),
            whole_object: true,
        }),
        "a whole-object checksum must reach VerifiedLocation intact — dropping it \
         costs nothing observable and silently returns scrub to full reads"
    );
}

#[tokio::test]
async fn a_composite_checksum_is_dropped_rather_than_persisted_as_a_content_hash() {
    // **The safety branch.** Real S3 returns exactly this for a multipart
    // object uploaded without ChecksumType FULL_OBJECT — measured, ADR 0b §3b:
    //
    //     x-amz-checksum-crc32: 72M33w==-2
    //     x-amz-checksum-type:  COMPOSITE
    //
    // The trailing `-2` is the part count: it is a digest-of-digests and can
    // never equal a CRC32 of the bytes. Persisting it as though it were a
    // content hash is a CORRECTNESS defect in scrub, not a cost one — every
    // multipart object would compare unequal forever, so scrub would either
    // alarm on all of them or, worse, have its comparison "fixed" by someone
    // who concluded the checksum was unreliable.
    let got = verify_with_checksum(ObjectChecksum {
        algorithm: ChecksumAlgorithm::Crc32,
        value: "72M33w==-2".into(),
        whole_object: false,
    })
    .await;

    assert_eq!(
        got, None,
        "a COMPOSITE digest-of-digests must never be persisted as a content hash; \
         the honest answer is None, which sends scrub to a full read"
    );
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
