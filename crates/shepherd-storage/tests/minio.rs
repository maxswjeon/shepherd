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

/// Where the whole-object-checksum probe runs.
///
/// Defaults to the compose-file MinIO like every other test here. Setting
/// `SHEPHERD_S3_BUCKET` aims the same probe at a real service instead, because
/// the capacity model's claim is that **one run against a real endpoint settles
/// the question** — which is only true if the test can actually be aimed:
///
/// ```text
/// SHEPHERD_S3_BUCKET=shepherd-probe-xxxxxxxx SHEPHERD_S3_REGION=ap-northeast-2 \
///   cargo test -p shepherd-storage --test minio -- --ignored --nocapture \
///   whole_object_checksums_on_multipart_are_probed_not_assumed
/// ```
///
/// Credentials come from the ambient chain there rather than the compose file's
/// fixed pair, and path style follows the endpoint: real S3 serves virtual-host
/// buckets, every self-hosted compatible needs path style. Setting
/// `SHEPHERD_S3_ENDPOINT` as well points it at R2, B2 or any other
/// S3-compatible, which is how the remaining `unknown` rows in the provider
/// table get filled in without a code change.
fn probe_target() -> (S3Config, String) {
    match std::env::var("SHEPHERD_S3_BUCKET") {
        Ok(bucket) if !bucket.is_empty() => {
            let region =
                std::env::var("SHEPHERD_S3_REGION").unwrap_or_else(|_| "us-east-1".to_string());
            let endpoint_url = std::env::var("SHEPHERD_S3_ENDPOINT")
                .ok()
                .filter(|s| !s.is_empty());
            let label = match &endpoint_url {
                Some(u) => format!("{u} (bucket {bucket})"),
                None => format!("AWS S3 {region} (bucket {bucket})"),
            };
            (
                S3Config {
                    bucket,
                    force_path_style: endpoint_url.is_some(),
                    endpoint_url,
                    region: Some(region),
                    // The ambient chain: `~/.aws`, the environment, or an
                    // instance role. Never the compose file's fixed pair.
                    credentials: None,
                    multipart_checksum: None,
                },
                label,
            )
        }
        _ => {
            let mut cfg = S3Config::minio(PLAIN_BUCKET, endpoint());
            cfg.credentials = Some(StaticCredentials {
                access_key_id: "shepherdtest".into(),
                secret_access_key: "shepherdtest".into(),
            });
            (cfg, format!("MinIO at {}", endpoint()))
        }
    }
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

/// A unique key per RUN, so these tests are idempotent against a bucket that
/// outlives them.
///
/// The process id is not decoration. Without it a second run reuses the same
/// content-addressed keys and the exclusive-create test fails on its FIRST
/// create rather than its second — the suite would pass once against a fresh
/// `docker compose up` and then fail forever, which is the worst possible
/// failure shape because it looks like a regression in the code under test.
fn key_for(b: &Bytes, tag: &str) -> ObjectKey {
    let h = hash(b).to_hex();
    ObjectKey::new(format!(
        "objects/{}/{}/{}-{tag}-run{}",
        &h[0..2],
        &h[2..4],
        h,
        std::process::id()
    ))
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
            checksum: r.checksum,
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

/// **The Phase-0b capacity finding, probed rather than assumed.**
///
/// A multipart ETag is a digest-of-digests, so it cannot be compared against a
/// checksum of the bytes — and per the capacity model the 2% of files large
/// enough to be multipart hold 60.3% of all bytes. If the provider can return a
/// **whole-object** checksum from HEAD, those objects move onto the cheap scrub
/// path; if it cannot, scrub must read them back in full and the cost model
/// stands as measured.
///
/// This test does not assert which way it goes. It **reports** what this server
/// actually does, because that is the finding — and asserts only the invariant
/// that must hold either way: a composite checksum is never presented as a
/// whole-object one.
///
/// It names the provider it actually reached and the key it wrote, so the raw
/// server fields can be pulled independently. A probe that reports a negative
/// without saying where it was pointed is indistinguishable from one that never
/// left the emulator.
#[tokio::test]
#[ignore = "requires MinIO, or SHEPHERD_S3_BUCKET for a real endpoint"]
async fn whole_object_checksums_on_multipart_are_probed_not_assumed() {
    let (mut cfg, provider) = probe_target();
    cfg.multipart_checksum = Some(shepherd_storage::adapter::ChecksumAlgorithm::Crc64Nvme);
    let a = S3Adapter::new(cfg).await.expect("adapter");

    let content = body((2 * PART + 77) as usize, 9);
    let key = key_for(&content, "crc64");
    println!("FINDING: probing {provider}");
    println!("FINDING: key={}", key.as_str());
    let plan = PartPlan::new(content.len() as u64, a.capabilities(), PART).expect("plan");
    assert_eq!(plan.part_count, 3, "must genuinely be a multipart upload");

    let upload = match a.create_multipart(&key).await {
        Ok(u) => u,
        Err(e) => {
            println!(
                "FINDING: {provider} rejected CreateMultipartUpload with FULL_OBJECT CRC64NVME: {e}"
            );
            println!("FINDING: scrub must read multipart objects back in full on this provider.");
            return;
        }
    };
    let mut receipts = Vec::new();
    for (no, range) in plan.ranges() {
        let slice = content.slice(range.offset as usize..(range.offset + range.len) as usize);
        match a.upload_part(&key, &upload, no, slice).await {
            Ok(r) => receipts.push(r),
            Err(e) => {
                println!("FINDING: upload_part failed under FULL_OBJECT checksums: {e}");
                let _ = a.abort_multipart(&key, &upload).await;
                return;
            }
        }
    }
    if let Err(e) = a
        .complete_multipart(&key, &upload, &receipts, CreatePrecondition::IfAbsent)
        .await
    {
        println!("FINDING: complete_multipart failed under FULL_OBJECT checksums: {e}");
        let _ = a.abort_multipart(&key, &upload).await;
        return;
    }

    let meta = a.head(&key).await.expect("head").expect("present");
    match &meta.whole_object_checksum {
        Some(c) => {
            println!(
                "FINDING: {provider} returned a checksum on HEAD: algorithm={} whole_object={} value={}",
                c.algorithm.as_str(),
                c.whole_object,
                c.value
            );
            assert!(
                !c.value.is_empty(),
                "a reported checksum must carry a value"
            );
        }
        None => println!(
            "FINDING: {provider} returned NO whole-object checksum on HEAD — \
             scrub must read multipart objects back in full on this provider."
        ),
    }

    // The invariant that holds either way: bytes are still what we sent.
    verify_full_content(&a, &key, hash(&content), content.len() as u64, PART)
        .await
        .expect("content must round-trip regardless of checksum support");
}

/// **E-5's producer, run against a real provider.**
///
/// `probe_multipart_checksum` is the registration-time producer for
/// `S3Config::multipart_checksum` — the field that has always had three
/// readers, a doc saying it must be probed at registration, and no writer
/// outside a test. The selection logic (preference order, fallback,
/// unreachable-is-not-a-negative) is unit-tested in `s3.rs` against a scripted
/// provider, because no single real provider exercises more than one path
/// through it. This is the other half: that the round trip it performs is a
/// real one.
///
/// **It reports rather than asserting which way it goes**, in the style of
/// `whole_object_checksums_on_multipart_are_probed_not_assumed` above: R2 and
/// B2 are genuinely unknown and guessing at them is what E-3 had to walk back.
/// What it does assert is the invariant that must hold on any provider —
/// whatever is adopted must have come back from HEAD as `whole_object`, and a
/// negative must carry a reason for every algorithm rather than being a bare
/// `None`.
#[tokio::test]
#[ignore = "requires MinIO, or SHEPHERD_S3_BUCKET for a real endpoint"]
async fn the_registration_probe_adopts_a_checksum_the_provider_actually_round_trips() {
    let (cfg, provider) = probe_target();
    println!("FINDING: probing {provider}");

    let probe = shepherd_storage::s3::probe_multipart_checksum(&cfg)
        .await
        .expect("the provider must be reachable to run this test at all");

    println!("FINDING: {}", probe.summary());

    match probe.adopted {
        Some(alg) => {
            // The adopted algorithm's own attempt must be the round-tripped
            // one. A probe that adopted an algorithm whose attempt was recorded
            // as rejected would be reporting the request rather than the answer.
            let attempt = probe
                .attempts
                .iter()
                .find(|a| a.algorithm == alg)
                .expect("the adopted algorithm must appear in the attempts");
            match &attempt.outcome {
                shepherd_storage::s3::AttemptOutcome::RoundTripped { value } => {
                    assert!(!value.is_empty(), "an adopted checksum must carry a value");
                    println!(
                        "FINDING: {provider} round-tripped {} = {value}",
                        alg.as_str()
                    );
                }
                other => panic!("adopted {} but recorded {other:?}", alg.as_str()),
            }
            // Every earlier algorithm in the preference order must have been
            // tried and rejected — otherwise the adoption skipped a stronger
            // one silently.
            for earlier in shepherd_storage::s3::FULL_OBJECT_PREFERENCE
                .iter()
                .take_while(|a| **a != alg)
            {
                let a = probe
                    .attempts
                    .iter()
                    .find(|x| x.algorithm == *earlier)
                    .unwrap();
                assert!(
                    matches!(
                        a.outcome,
                        shepherd_storage::s3::AttemptOutcome::Rejected { .. }
                    ),
                    "{} was skipped rather than refused: {a:?}",
                    earlier.as_str()
                );
            }
        }
        None => {
            println!(
                "FINDING: {provider} supports no FULL_OBJECT checksum; scrub must read \
                 multipart objects back in full there."
            );
            assert_eq!(probe.attempts.len(), 3);
            for a in &probe.attempts {
                assert!(
                    matches!(
                        a.outcome,
                        shepherd_storage::s3::AttemptOutcome::Rejected { .. }
                    ),
                    "a negative must name a reason for {}: {a:?}",
                    a.algorithm.as_str()
                );
            }
        }
    }
}

/// The concurrency the probe has to survive: two `target.add` calls against one
/// bucket at the same time.
///
/// While the probe object's key was a pure function of the algorithm, every
/// concurrent probe wrote and deleted **the same object**. One probe's cleanup
/// `DELETE` landing between another's `complete_multipart` and its `HEAD` makes
/// the second read a missing object — and this code reads a missing checksum as
/// "the provider does not offer this algorithm". That negative is persisted by
/// `target.add` as `adopted: none`, which is irreversible per object and costs
/// 649x on scrub. A transient race must not mint a durable claim about a
/// provider's capabilities; the same argument that made an auth failure stop
/// being recorded as non-support.
///
/// Ground truth is an **uncontended** probe taken first, rather than agreement
/// between the concurrent ones: two probes that both raced into `adopted: none`
/// agree perfectly. It also keeps the test provider-agnostic — a provider that
/// genuinely supports nothing passes, because the uncontended answer is the one
/// contention must not change.
#[tokio::test]
#[ignore = "requires MinIO, or SHEPHERD_S3_BUCKET for a real endpoint"]
async fn concurrent_registration_probes_do_not_race_into_a_false_negative() {
    let (cfg, provider) = probe_target();

    let baseline = shepherd_storage::s3::probe_multipart_checksum(&cfg)
        .await
        .expect("the provider must be reachable to run this test at all");
    println!(
        "FINDING: uncontended baseline on {provider}: {}",
        baseline.summary()
    );

    // Rounds and width both matter: the window is one network round-trip wide,
    // so a single pair proves very little in either direction.
    for round in 0..5 {
        // `tokio::join!` rather than a `futures` dependency: four is enough
        // width to skew the probes apart, and the crate does not need a new
        // dependency to say so.
        let (r0, r1, r2, r3) = tokio::join!(
            shepherd_storage::s3::probe_multipart_checksum(&cfg),
            shepherd_storage::s3::probe_multipart_checksum(&cfg),
            shepherd_storage::s3::probe_multipart_checksum(&cfg),
            shepherd_storage::s3::probe_multipart_checksum(&cfg),
        );

        for (i, r) in [r0, r1, r2, r3].into_iter().enumerate() {
            let p = r.unwrap_or_else(|e| {
                panic!("round {round} probe {i}: contention must not fail registration: {e}")
            });
            assert_eq!(
                p.adopted,
                baseline.adopted,
                "round {round} probe {i}: contention changed the answer.\n                   uncontended: {}\n  contended:   {}",
                baseline.summary(),
                p.summary()
            );
        }
    }
}

/// The other direction, and the one that decides whether a $441/month mistake
/// becomes permanent: an unreachable endpoint must be an error, never a
/// recorded "this provider supports nothing".
///
/// Not `#[ignore]`d — it needs no provider, only the absence of one — so it
/// runs on every `cargo test`. That matters: the fail-closed leg of a probe is
/// exactly the leg that rots when it lives only behind a gate nobody runs.
#[tokio::test]
async fn an_unreachable_endpoint_fails_registration_rather_than_recording_no_support() {
    let cfg = S3Config {
        bucket: "shepherd-nonexistent-probe".into(),
        // Reserved by RFC 6761 to never resolve.
        endpoint_url: Some("http://probe.invalid:9".into()),
        region: Some("us-east-1".into()),
        force_path_style: true,
        credentials: Some(StaticCredentials {
            access_key_id: "x".into(),
            secret_access_key: "y".into(),
        }),
        multipart_checksum: None,
    };

    let err = shepherd_storage::s3::probe_multipart_checksum(&cfg)
        .await
        .expect_err(
            "an unreachable endpoint must not produce a probe record — recording \
             `adopted: None` here is permanent and indistinguishable from a genuine \
             measurement afterwards",
        );
    assert!(
        err.to_string().contains("proves nothing"),
        "the refusal must explain why it is not a negative result: {err}"
    );
    assert!(err.is_retryable(), "and it must be retryable: {err:?}");
}
