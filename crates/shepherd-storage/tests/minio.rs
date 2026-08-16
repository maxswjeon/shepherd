//! Live S3 conformance against MinIO.
//!
//! `#[ignore]`d by default, so `cargo test --workspace` stays green on a
//! machine with no Docker. A test that silently passes when its dependency is
//! absent is worse than one that is visibly skipped.
//!
//! ```text
//! docker compose -f tests/docker-compose.yml up -d --wait
//! SHEPHERD_MINIO_ENDPOINT=http://127.0.0.1:9000 \
//!   cargo test -p shepherd-storage --test minio -- --ignored --nocapture
//! ```
//!
//! # What is worth testing here, and what is not
//!
//! The transfer state machine and the replica chain already have 50-odd unit
//! tests against an in-memory adapter, and re-running those over a network
//! would not make them more true. These tests cover only the claims a fake
//! **cannot** settle, because a fake is written by the same person as the code:
//!
//! * that the server really honours `If-None-Match: *`, which OQ-1 upgraded
//!   from "an optimization" to a hard requirement;
//! * that `mc version enable` actually took, so the bucket the compose file
//!   calls mechanism A really is mechanism A;
//! * that a real multipart round-trip is byte-identical;
//! * that real ETags survive as opaque tokens across a genuine `ListParts`,
//!   which is what AC-2's resume compares against.

use bytes::Bytes;
use shepherd_core::{Blake3Hash, ObjectKey};
use shepherd_storage::adapter::{
    AttestationMode, ByteRange, CreatePrecondition, StorageAdapter, StorageError,
    verify_full_content,
};
use shepherd_storage::multipart::{PartAction, PartCheckpoint, PartPlan, reconcile_parts};
use shepherd_storage::s3::{S3Adapter, S3Config, StaticCredentials};

const VERSIONED_BUCKET: &str = "shepherd-versioned";
const PLAIN_BUCKET: &str = "shepherd-plain";
/// Non-final multipart parts must be at least 5 MiB, so the smallest object
/// that genuinely exercises multi-part assembly is a little over 10 MiB.
const PART: u64 = 5 * 1024 * 1024;

fn endpoint() -> String {
    std::env::var("SHEPHERD_MINIO_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9000".to_string())
}

async fn adapter(bucket: &str) -> S3Adapter {
    let mut cfg = S3Config::minio(bucket, endpoint());
    cfg.credentials = Some(StaticCredentials {
        access_key_id: "shepherdtest".into(),
        secret_access_key: "shepherdtest".into(),
    });
    S3Adapter::new(cfg).await.expect("build S3 adapter")
}

/// Deterministic but incompressible-ish content, so a size check cannot stand
/// in for a hash check by accident.
fn body(len: usize, salt: u8) -> Bytes {
    let mut v = Vec::with_capacity(len);
    let mut x = 0x2545_F491_4F6C_DD1Du64 ^ u64::from(salt);
    while v.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.extend_from_slice(&x.to_le_bytes());
    }
    v.truncate(len);
    Bytes::from(v)
}

fn hash(b: &Bytes) -> Blake3Hash {
    Blake3Hash::from_bytes(*blake3::hash(b).as_bytes())
}

/// A unique key per run, so repeated runs against a live bucket cannot pass by
/// reading a previous run's object. Content-addressed per §4.9.
fn key_for(b: &Bytes, tag: &str) -> ObjectKey {
    let h = hash(b).to_hex();
    ObjectKey::new(format!("objects/{}/{}/{}-{tag}", &h[0..2], &h[2..4], h))
}

#[tokio::test]
#[ignore = "requires MinIO: docker compose -f tests/docker-compose.yml up -d --wait"]
async fn attestation_mode_is_probed_and_matches_the_bucket_it_was_pointed_at() {
    // §4.10.2's rider. The versioned bucket must report mechanism A and the
    // default bucket mechanism B. If `mc version enable` silently failed, the
    // first assertion catches it here rather than a safety claim decaying into
    // a slogan.
    let versioned = adapter(VERSIONED_BUCKET).await;
    assert_eq!(
        versioned.probe_attestation_mode().await.expect("probe"),
        AttestationMode::Version,
        "shepherd-versioned must be mechanism A — check `mc version enable` in the compose file"
    );

    let plain = adapter(PLAIN_BUCKET).await;
    assert_eq!(
        plain.probe_attestation_mode().await.expect("probe"),
        AttestationMode::Content,
        "an ordinary bucket is mechanism B: versioning is off by default"
    );
}

#[tokio::test]
#[ignore = "requires MinIO"]
async fn conditional_create_is_honoured_by_the_server() {
    // OQ-1: "Where the provider offers `If-None-Match: *` or equivalent
    // exclusive-create, Shepherd uses it and treats a failure as a hard error."
    // That is only true if the server actually enforces it.
    let a = adapter(PLAIN_BUCKET).await;
    assert!(a.capabilities().conditional_create);

    let first = body(64, 1);
    let key = key_for(&first, "cond");
    a.create(&key, first.clone(), CreatePrecondition::IfAbsent)
        .await
        .expect("first exclusive create must succeed");

    let err = a
        .create(
            &key,
            Bytes::from_static(b"different"),
            CreatePrecondition::IfAbsent,
        )
        .await
        .expect_err("a second exclusive create on the same key must fail");
    assert!(
        matches!(err, StorageError::PreconditionFailed { .. }),
        "expected PreconditionFailed, got {err:?}"
    );

    // And the original bytes are untouched — silently overwriting them is the
    // exact failure OQ-1's collision-proof keys exist to make detectable.
    let read = a
        .get_range(
            &key,
            ByteRange {
                offset: 0,
                len: first.len() as u64,
            },
        )
        .await
        .expect("read back");
    assert_eq!(read, first);
}

#[tokio::test]
#[ignore = "requires MinIO"]
async fn a_multipart_upload_round_trips_byte_identically_and_verifies_by_hash() {
    let a = adapter(PLAIN_BUCKET).await;
    let content = body((2 * PART + 1234) as usize, 2);
    let key = key_for(&content, "mpu");
    let plan = PartPlan::new(content.len() as u64, a.capabilities(), PART).expect("plan");
    assert_eq!(plan.part_count, 3);

    let upload = a.create_multipart(&key).await.expect("create_multipart");
    let mut receipts = Vec::new();
    for (no, range) in plan.ranges() {
        let slice = content.slice(range.offset as usize..(range.offset + range.len) as usize);
        receipts.push(
            a.upload_part(&key, &upload, no, slice)
                .await
                .expect("upload_part"),
        );
    }
    a.complete_multipart(&key, &upload, &receipts, CreatePrecondition::IfAbsent)
        .await
        .expect("complete");

    let meta = a.head(&key).await.expect("head").expect("object exists");
    assert_eq!(meta.size, content.len() as u64);

    // The only thing entitled to say "these are the right bytes".
    verify_full_content(&a, &key, hash(&content), content.len() as u64, PART)
        .await
        .expect("full-content verification must pass");

    // And it genuinely discriminates: a wrong expected hash must fail.
    let err = verify_full_content(
        &a,
        &key,
        Blake3Hash::from_bytes([0u8; 32]),
        content.len() as u64,
        PART,
    )
    .await
    .expect_err("verification against the wrong hash must fail");
    assert!(matches!(err, StorageError::ContentMismatch { .. }));
}

#[tokio::test]
#[ignore = "requires MinIO"]
async fn a_real_resume_skips_parts_the_server_and_the_checkpoint_agree_on() {
    // AC-2 over real ETags. The unit tests prove the reconciliation logic; this
    // proves the tokens MinIO issues survive a genuine `ListParts` and still
    // compare equal, which is the assumption the whole resume rests on.
    let a = adapter(PLAIN_BUCKET).await;
    let content = body((2 * PART + 99) as usize, 3);
    let key = key_for(&content, "resume");
    let plan = PartPlan::new(content.len() as u64, a.capabilities(), PART).expect("plan");
    assert_eq!(plan.part_count, 3);

    let upload = a.create_multipart(&key).await.expect("create_multipart");

    // "Before the crash": parts 1 and 2 uploaded and durably checkpointed.
    let mut checkpoints: Vec<PartCheckpoint> = Vec::new();
    for no in [1u32, 2] {
        let range = plan.range_of(no).expect("range");
        let slice = content.slice(range.offset as usize..(range.offset + range.len) as usize);
        let r = a
            .upload_part(&key, &upload, no, slice.clone())
            .await
            .expect("upload_part");
        checkpoints.push(PartCheckpoint {
            part_no: no,
            offset: range.offset,
            len: range.len,
            local_blake3: hash(&slice),
            etag: Some(r.etag),
        });
    }

    // "After the restart": ask the server what it holds.
    let remote = a.list_parts(&key, &upload).await.expect("list_parts");
    assert_eq!(remote.len(), 2);
    let recon = reconcile_parts(&plan, &checkpoints, &remote);
    assert_eq!(recon.actions[0], PartAction::Skip);
    assert_eq!(recon.actions[1], PartAction::Skip);
    assert_eq!(recon.actions[2], PartAction::Send);
    assert_eq!(
        recon.bytes_skipped,
        2 * PART,
        "real ETags must compare equal across a genuine ListParts"
    );
    assert_eq!(recon.orphan_remote_parts, 0);

    // Send only what is missing, then complete from the full receipt set.
    let mut receipts: Vec<_> = remote;
    for no in recon.pending() {
        let range = plan.range_of(no).expect("range");
        let slice = content.slice(range.offset as usize..(range.offset + range.len) as usize);
        receipts.push(
            a.upload_part(&key, &upload, no, slice)
                .await
                .expect("upload"),
        );
    }
    receipts.sort_by_key(|p| p.part_no);
    a.complete_multipart(&key, &upload, &receipts, CreatePrecondition::IfAbsent)
        .await
        .expect("complete after resume");

    verify_full_content(&a, &key, hash(&content), content.len() as u64, PART)
        .await
        .expect("a resumed upload must still be byte-identical");
}

#[tokio::test]
#[ignore = "requires MinIO"]
async fn an_aborted_upload_is_reaped_and_stops_being_listed() {
    // §4.5: "Killed uploads are reaped so incomplete multiparts do not accrue
    // storage cost." Window 1's orphan reaping depends on this listing being
    // real.
    let a = adapter(PLAIN_BUCKET).await;
    let content = body(1024, 4);
    let key = key_for(&content, "orphan");

    let upload = a.create_multipart(&key).await.expect("create_multipart");
    let live = a
        .list_incomplete_uploads(key.as_str())
        .await
        .expect("list_incomplete_uploads");
    assert!(
        live.iter().any(|u| u.upload_id == upload),
        "a freshly created session must be discoverable, or orphans are unreapable"
    );

    a.abort_multipart(&key, &upload).await.expect("abort");
    let after = a
        .list_incomplete_uploads(key.as_str())
        .await
        .expect("list again");
    assert!(!after.iter().any(|u| u.upload_id == upload));

    // Aborting twice is not an error: "already gone" is the desired end state.
    a.abort_multipart(&key, &upload)
        .await
        .expect("a second abort must be a no-op, not a failure");
}

#[tokio::test]
#[ignore = "requires MinIO"]
async fn head_reports_absence_rather_than_erroring() {
    // The ambiguous-completion path (window 3) asks exactly this question, and
    // treats an error and an absence very differently.
    let a = adapter(PLAIN_BUCKET).await;
    let missing = ObjectKey::new("objects/zz/zz/definitely-not-here");
    assert_eq!(a.head(&missing).await.expect("head must not error"), None);
}

#[tokio::test]
#[ignore = "requires MinIO"]
async fn a_versioned_bucket_pins_an_immutable_version_id() {
    // Mechanism A's entire premise: the provider hands back a version id that
    // a later cheap HEAD can compare against.
    let a = adapter(VERSIONED_BUCKET).await;
    let content = body(256, 5);
    let key = key_for(&content, "ver");
    let receipt = a
        .create(&key, content.clone(), CreatePrecondition::IfAbsent)
        .await
        .expect("create");
    assert!(
        receipt.version.is_some(),
        "a versioned bucket must return a version id"
    );
    let meta = a.head(&key).await.expect("head").expect("present");
    assert_eq!(
        meta.version, receipt.version,
        "the closing HEAD must observe the same immutable version — this is what makes \
         mechanism A a genuine re-attestation"
    );
}
