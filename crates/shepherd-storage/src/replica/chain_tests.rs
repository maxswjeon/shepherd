//! Tests for OQ-1's hash-chained pointer records.

use super::*;
use crate::testing::MemAdapter;
use std::sync::Mutex;

fn hex(seed: u8) -> String {
    Blake3Hash::from_bytes([seed; 32]).to_hex()
}

fn rec(epoch: u64, seq: u64, uuid: &str, prev: Option<String>) -> PointerRecord {
    PointerRecord {
        epoch,
        seq,
        uuid: uuid.into(),
        schema_version: POINTER_SCHEMA_VERSION,
        prev_ptr_blake3: prev,
        segment_blake3: hex(1),
        segment_key: format!("_shepherd/catalog/seg-{epoch}-{seq}-{uuid}.jsonl.zst"),
        cumulative_state_blake3: hex(2),
        self_blake3: String::new(),
    }
    .seal()
    .expect("seal")
}

fn listed(records: &[PointerRecord]) -> Vec<(String, PointerRecord)> {
    records
        .iter()
        .map(|r| (r.key().pointer_name(), r.clone()))
        .collect()
}

/// A golden vector, so an accidental change to canonicalization fails loudly
/// rather than silently invalidating every pointer ever written.
#[test]
fn canonical_self_hash_is_pinned_by_a_golden_vector() {
    let r = PointerRecord {
        epoch: 7,
        seq: 412,
        uuid: "0189d3f2-0000-7000-8000-000000000001".into(),
        schema_version: 1,
        prev_ptr_blake3: Some(
            "1111111111111111111111111111111111111111111111111111111111111111".into(),
        ),
        segment_blake3: "2222222222222222222222222222222222222222222222222222222222222222".into(),
        segment_key: "_shepherd/catalog/seg-7-412-0189d3f2-0000-7000-8000-000000000001.jsonl.zst"
            .into(),
        cumulative_state_blake3: "3333333333333333333333333333333333333333333333333333333333333333"
            .into(),
        self_blake3: String::new(),
    };
    assert_eq!(
        r.compute_self_hash().expect("hash").to_hex(),
        "9bd3d0833a62a5a6ecc51c7ddf1200d5d607594b17438e9fb00da4ba516884d8",
        "canonicalization changed — every pointer already written would fail validation"
    );
}

#[test]
fn canonicalization_ignores_json_key_order() {
    let r = rec(1, 1, "u1", None);
    let as_written = serde_json::to_string(&r).expect("ser");

    // Re-serialize with keys in a different order, as another implementation
    // or a hand-edited recovery file might.
    let v: serde_json::Value = serde_json::from_str(&as_written).expect("de");
    let shuffled = format!(
        "{{\"self_blake3\":{},\"uuid\":{},\"seq\":{},\"epoch\":{},\"schema_version\":{},\
          \"prev_ptr_blake3\":{},\"segment_blake3\":{},\"segment_key\":{},\
          \"cumulative_state_blake3\":{}}}",
        v["self_blake3"],
        v["uuid"],
        v["seq"],
        v["epoch"],
        v["schema_version"],
        v["prev_ptr_blake3"],
        v["segment_blake3"],
        v["segment_key"],
        v["cumulative_state_blake3"],
    );
    let back: PointerRecord = serde_json::from_str(&shuffled).expect("de shuffled");
    assert_eq!(
        back.compute_self_hash().unwrap(),
        r.compute_self_hash().unwrap()
    );
    assert!(back.validate().is_ok());
}

#[test]
fn a_single_chain_resolves_but_topology_alone_is_not_custody() {
    let g = rec(1, 1, "u1", None);
    let b = rec(1, 2, "u2", Some(g.self_blake3.clone()));
    let c = rec(2, 3, "u3", Some(b.self_blake3.clone()));

    // Listing order is deliberately shuffled: a listing has no ordering
    // guarantee on SMB or NFS.
    let r = resolve_chain(&listed(&[c.clone(), g.clone(), b.clone()]));
    assert_eq!(r.status, ChainStatus::Single);
    // Topology is clean — and that alone is deliberately not custody. Nothing
    // here fetched a segment, so there is no evidence the recovery payload
    // exists; see `a_verified_chain_is_custody_eligible` for the other half.
    assert_eq!(r.segments, SegmentEvidence::Unchecked);
    assert!(
        !r.custody_eligible(),
        "an unforked gapless chain is necessary for custody, not sufficient"
    );
    assert!(r.invalid.is_empty());
    assert_eq!(
        r.records.iter().map(|x| x.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "records must replay in (epoch, seq) order regardless of listing order"
    );
    assert_eq!(r.head, Blake3Hash::from_hex(&c.self_blake3));
}

#[test]
fn a_fork_is_detected_and_refuses_custody() {
    let g = rec(1, 1, "u1", None);
    // Two records claiming the same predecessor — the restart-overlap case.
    let a = rec(1, 2, "ua", Some(g.self_blake3.clone()));
    let b = rec(2, 2, "ub", Some(g.self_blake3.clone()));

    let r = resolve_chain(&listed(&[g, a, b]));
    assert!(
        matches!(r.status, ChainStatus::Fork { .. }),
        "{:?}",
        r.status
    );
    assert!(
        !r.custody_eligible(),
        "a forked target may hold replicas but must never authorize a sole-copy destruction"
    );
    assert_eq!(
        r.records.len(),
        3,
        "merge ALL valid branches — a scalar max would discard one silently"
    );
    assert_eq!(r.head, None);
}

#[test]
fn two_genesis_records_are_a_fork() {
    let a = rec(1, 1, "ua", None);
    let b = rec(2, 1, "ub", None);
    let r = resolve_chain(&listed(&[a, b]));
    assert!(matches!(r.status, ChainStatus::Fork { .. }));
    assert!(!r.custody_eligible());
}

#[test]
fn a_gap_is_detected_and_refuses_custody() {
    let missing = rec(1, 1, "u1", None);
    let orphan = rec(1, 2, "u2", Some(missing.self_blake3.clone()));
    // `missing` is not in the listing.
    let r = resolve_chain(&listed(&[orphan]));
    match &r.status {
        ChainStatus::Gap { missing: m } => assert_eq!(m, &vec![missing.self_blake3.clone()]),
        other => panic!("expected a gap, got {other:?}"),
    }
    assert!(!r.custody_eligible());
}

#[test]
fn a_gap_outranks_a_fork_in_the_report() {
    // An incomplete listing cannot be trusted to have shown every branch, so
    // calling it merely a fork would understate the problem.
    let ghost = rec(1, 1, "ghost", None);
    let a = rec(1, 2, "ua", Some(ghost.self_blake3.clone()));
    let b = rec(1, 3, "ub", Some(ghost.self_blake3.clone()));
    let r = resolve_chain(&listed(&[a, b]));
    assert!(
        matches!(r.status, ChainStatus::Gap { .. }),
        "{:?}",
        r.status
    );
}

#[test]
fn a_tampered_record_is_reported_not_silently_dropped() {
    let good = rec(1, 1, "u1", None);
    let mut tampered = rec(1, 2, "u2", Some(good.self_blake3.clone()));
    // A perfectly well-formed body whose hash no longer covers it.
    tampered.cumulative_state_blake3 = hex(9);

    let r = resolve_chain(&listed(&[good, tampered]));
    assert_eq!(r.invalid.len(), 1, "the bad record must be reported");
    assert!(r.invalid[0].1.contains("self_blake3"));
    assert!(
        !r.custody_eligible(),
        "an unexplained invalid record must block custody"
    );
}

#[test]
fn a_record_from_a_newer_schema_is_refused_rather_than_guessed_at() {
    let mut r = rec(1, 1, "u1", None);
    r.schema_version = POINTER_SCHEMA_VERSION + 1;
    let r = r.seal().expect("seal");
    let err = r.validate().expect_err("must refuse");
    assert!(err.to_string().contains("newer than this build"));
}

#[test]
fn record_names_round_trip_and_reject_foreign_keys() {
    let k = RecordKey {
        epoch: 7,
        seq: 412,
        uuid: "0189d3f2-abc".into(),
    };
    assert_eq!(k.pointer_name(), "ptr-7-412-0189d3f2-abc.json");
    assert_eq!(
        k.segment_name(SegmentKind::Snapshot),
        "seg-7-412-0189d3f2-abc.sqlite.zst"
    );
    assert_eq!(
        RecordKey::parse_pointer(k.pointer_name().as_str()),
        Some(k.clone())
    );
    assert_eq!(
        RecordKey::parse_pointer("_shepherd/catalog/ptr-7-412-0189d3f2-abc.json"),
        Some(k)
    );
    // Segments are not pointers.
    assert_eq!(
        RecordKey::parse_pointer("_shepherd/catalog/seg-7-412-u.jsonl.zst"),
        None
    );
    assert_eq!(RecordKey::parse_pointer("ptr-x-1-u.json"), None);
    assert_eq!(RecordKey::parse_pointer("ptr-1-1-.json"), None);
}

#[test]
fn fresh_keys_differ_even_for_an_identical_epoch_and_sequence() {
    // The rolled-back-database case: the same (epoch, seq) is handed out twice,
    // and the uuid is the only thing keeping the two records from colliding.
    let a = RecordKey::new(7, 412);
    let b = RecordKey::new(7, 412);
    assert_eq!((a.epoch, a.seq), (b.epoch, b.seq));
    assert_ne!(a.uuid, b.uuid);
    assert_ne!(a.pointer_name(), b.pointer_name());
    // And the name still parses back to the key that produced it.
    assert_eq!(RecordKey::parse_pointer(&a.pointer_name()), Some(a));
}

#[test]
fn pointer_and_segment_keys_land_under_the_control_prefix() {
    let k = RecordKey {
        epoch: 1,
        seq: 1,
        uuid: "u".into(),
    };
    assert!(k.pointer_key().as_key().is_control_object());
    assert!(
        k.segment_key(SegmentKind::Delta)
            .as_key()
            .is_control_object()
    );
    assert_eq!(
        k.pointer_key().as_key().as_str(),
        "_shepherd/catalog/ptr-1-1-u.json"
    );
}

// --- the writer -----------------------------------------------------------

/// An allocator that records how it was called, so the "never reads LIST"
/// property can be asserted rather than asserted-in-a-comment.
#[derive(Debug, Default)]
struct FakeAllocator {
    state: Mutex<(u64, u64, Vec<Blake3Hash>)>, // epoch, hwm, heads
}

impl FakeAllocator {
    fn at_epoch(epoch: u64) -> Self {
        Self {
            state: Mutex::new((epoch, 0, Vec::new())),
        }
    }
    fn heads(&self) -> Vec<Blake3Hash> {
        self.state.lock().unwrap().2.clone()
    }
}

#[async_trait::async_trait]
impl SequenceAllocator for FakeAllocator {
    async fn allocate(&self, _target: TargetId) -> Result<RecordKey, ChainError> {
        let mut s = self.state.lock().unwrap();
        s.1 += 1;
        Ok(RecordKey {
            epoch: s.0,
            seq: s.1,
            uuid: format!("uuid-{}", s.1),
        })
    }
    async fn record_head(&self, _t: TargetId, head: Blake3Hash) -> Result<(), ChainError> {
        self.state.lock().unwrap().2.push(head);
        Ok(())
    }
}

#[tokio::test]
async fn publish_allocates_without_listing_and_writes_segment_before_pointer() {
    let adapter = MemAdapter::content_addressed();
    let alloc = FakeAllocator::at_epoch(7);
    let writer = ChainWriter::new(&adapter, &alloc, TargetId::new(1));

    let record = writer
        .publish(
            SegmentKind::Delta,
            Bytes::from_static(b"delta-1"),
            None,
            Blake3Hash::from_bytes([5u8; 32]),
        )
        .await
        .expect("publish");

    assert_eq!(
        adapter.list_calls(),
        0,
        "allocation must never read LIST — that is the hole iteration 2 left open"
    );
    assert_eq!(record.epoch, 7);
    assert_eq!(record.seq, 1);
    assert_eq!(record.prev_ptr_blake3, None, "the first record is genesis");
    record.validate().expect("a published record must validate");

    // Segment-then-pointer: both exist, and the pointer names the segment.
    let seg_key = RecordKey {
        epoch: 7,
        seq: 1,
        uuid: "uuid-1".into(),
    }
    .segment_key(SegmentKind::Delta);
    assert!(adapter.object(seg_key.as_key()).is_some());
    assert_eq!(record.segment_key, seg_key.as_key().as_str());
    assert_eq!(alloc.heads(), vec![record.compute_self_hash().unwrap()]);
}

#[tokio::test]
async fn a_second_publish_chains_onto_the_first() {
    let adapter = MemAdapter::content_addressed();
    let alloc = FakeAllocator::at_epoch(3);
    let writer = ChainWriter::new(&adapter, &alloc, TargetId::new(1));

    let first = writer
        .publish(
            SegmentKind::Delta,
            Bytes::from_static(b"a"),
            None,
            Blake3Hash::from_bytes([1; 32]),
        )
        .await
        .expect("first");
    let head = first.compute_self_hash().unwrap();
    let second = writer
        .publish(
            SegmentKind::Delta,
            Bytes::from_static(b"b"),
            Some(head),
            Blake3Hash::from_bytes([2; 32]),
        )
        .await
        .expect("second");

    assert_eq!(second.prev_ptr_blake3, Some(head.to_hex()));

    let mut resolved = read_chain(&adapter).await.expect("read back");
    assert_eq!(resolved.status, ChainStatus::Single);
    assert_eq!(resolved.records.len(), 2);
    assert_eq!(resolved.head, Some(second.compute_self_hash().unwrap()));

    // `read_chain` fetches pointer bodies only, so it cannot mint custody.
    assert!(!resolved.custody_eligible());
    verify_segments(&adapter, &mut resolved)
        .await
        .expect("both segments are present and intact");
    assert_eq!(resolved.segments, SegmentEvidence::Verified);
    assert!(
        resolved.custody_eligible(),
        "a verified two-record chain must be a usable custody authority"
    );
}

#[tokio::test]
async fn conditional_create_failure_is_a_hard_error_not_a_warning() {
    let adapter = MemAdapter::content_addressed();
    let alloc = FakeAllocator::at_epoch(1);
    let writer = ChainWriter::new(&adapter, &alloc, TargetId::new(1));

    // Simulate the collision this design exists to detect: the key an allocator
    // is about to use is already occupied.
    let occupied = RecordKey {
        epoch: 1,
        seq: 1,
        uuid: "uuid-1".into(),
    }
    .segment_key(SegmentKind::Delta);
    adapter.put_raw(
        occupied.as_key(),
        Bytes::from_static(b"someone else's bytes"),
    );

    let err = writer
        .publish(
            SegmentKind::Delta,
            Bytes::from_static(b"mine"),
            None,
            Blake3Hash::from_bytes([1; 32]),
        )
        .await
        .expect_err("an exclusive-create collision must fail hard");
    assert!(
        matches!(
            err,
            ChainError::Storage(StorageError::PreconditionFailed { .. })
        ),
        "got {err:?}"
    );
    assert_eq!(
        adapter.object(occupied.as_key()).unwrap().as_ref(),
        b"someone else's bytes",
        "the pre-existing object must be untouched — silently overwriting it is the whole bug"
    );
}

/// An empty listing is not an unbroken chain — it is no chain at all.
///
/// `custody_eligible` authorizes destroying a sole local copy. `resolve_chain`
/// on an empty listing finds nothing to fork and nothing to be missing, so a
/// predicate that asks only "is the status `Single` and is nothing invalid?"
/// answers yes for a target holding no genesis pointer, no segment and no
/// recovery state whatsoever. That is the fail-open direction on the one path
/// that cannot be undone, and it is reachable on a newly configured target or
/// one whose listing came back empty.
#[test]
fn an_empty_chain_is_not_custody_eligible() {
    let r = resolve_chain(&[]);
    assert!(r.records.is_empty());
    assert_eq!(r.head, None, "there is no head to point at");
    assert!(
        !r.custody_eligible(),
        "a target with no recovery bundle at all must never authorize a sole-copy destruction"
    );
}

/// The other half of the pair: the fix must not be "always refuse".
///
/// A single sealed genesis record IS a complete, unforked, gapless chain with a
/// concrete head, and it must still be able to act as a custody authority —
/// otherwise the guard above would be indistinguishable from breaking custody
/// entirely.
#[test]
fn a_single_valid_record_satisfies_every_topology_clause() {
    let g = rec(1, 1, "u1", None);
    let r = resolve_chain(&listed(std::slice::from_ref(&g)));
    assert_eq!(r.status, ChainStatus::Single);
    assert_eq!(r.records.len(), 1);
    assert_eq!(r.head, Blake3Hash::from_hex(&g.self_blake3));
    assert!(
        r.invalid.is_empty(),
        "one valid genesis record with a head clears every clause resolve_chain can judge"
    );
    // The remaining clause is not judgeable from pointers alone.
    assert_eq!(r.segments, SegmentEvidence::Unchecked);
}

// --- segments, not just pointers -------------------------------------------
//
// A chain's pointers and the segments they publish are separate objects. These
// four tests hold the two apart: intact pointers over a deleted or rewritten
// segment must never authorize destroying the sole local catalog, and a chain
// whose segments really are intact must still be able to.

/// A chain with two records, published for real through [`ChainWriter`].
async fn published_pair(adapter: &MemAdapter) -> (PointerRecord, PointerRecord) {
    let alloc = FakeAllocator::at_epoch(3);
    let writer = ChainWriter::new(adapter, &alloc, TargetId::new(1));
    let first = writer
        .publish(
            SegmentKind::Delta,
            Bytes::from_static(b"segment-one"),
            None,
            Blake3Hash::from_bytes([1; 32]),
        )
        .await
        .expect("first");
    let head = first.compute_self_hash().unwrap();
    let second = writer
        .publish(
            SegmentKind::Delta,
            Bytes::from_static(b"segment-two"),
            Some(head),
            Blake3Hash::from_bytes([2; 32]),
        )
        .await
        .expect("second");
    (first, second)
}

/// **The accepting direction.** A guard hard-wired to refuse would pass all
/// three refusal tests below while making every replica permanently
/// custody-ineligible — which is the failure mode that voids tiering rather
/// than the one that loses data, and so the easier one to ship unnoticed.
#[tokio::test]
async fn a_verified_chain_is_custody_eligible() {
    let adapter = MemAdapter::content_addressed();
    let _ = published_pair(&adapter).await;

    let mut resolved = read_chain(&adapter).await.expect("read");
    verify_segments(&adapter, &mut resolved)
        .await
        .expect("intact segments verify");

    assert_eq!(resolved.segments, SegmentEvidence::Verified);
    assert!(resolved.invalid.is_empty(), "{:?}", resolved.invalid);
    assert!(resolved.custody_eligible());
}

/// The finding's first half: the pointer records are intact but the object
/// they reference was deleted.
#[tokio::test]
async fn a_deleted_segment_invalidates_custody() {
    let adapter = MemAdapter::content_addressed();
    let (first, _second) = published_pair(&adapter).await;
    let gone = ObjectKey::new(first.segment_key.clone());
    adapter.remove_raw(&gone);

    let mut resolved = read_chain(&adapter).await.expect("read");
    assert_eq!(
        resolved.status,
        ChainStatus::Single,
        "precondition: pointer topology is still perfect — that is the whole problem"
    );

    verify_segments(&adapter, &mut resolved)
        .await
        .expect("a missing segment is a verdict, not a transport error");

    assert_eq!(resolved.segments, SegmentEvidence::Unchecked);
    assert_eq!(
        resolved.invalid.len(),
        1,
        "the missing segment must be reported, not silently skipped: {:?}",
        resolved.invalid
    );
    assert!(
        resolved.invalid[0].1.contains(gone.as_str()),
        "the report must name the segment: {:?}",
        resolved.invalid[0]
    );
    assert!(!resolved.custody_eligible());
}

/// The finding's second half, and the one existence alone cannot catch: the
/// segment is present, the right size, and holds different bytes.
#[tokio::test]
async fn a_corrupted_segment_of_the_same_size_invalidates_custody() {
    let adapter = MemAdapter::content_addressed();
    let (first, _second) = published_pair(&adapter).await;
    let key = ObjectKey::new(first.segment_key.clone());
    let original = adapter.object(&key).expect("published");

    // Same length, different bytes — so a HEAD-based check would see nothing.
    let corrupt = Bytes::from_static(b"segment-ONE");
    assert_eq!(corrupt.len(), original.len(), "precondition: same size");
    assert_ne!(corrupt, original);
    adapter.put_raw(&key, corrupt);

    let mut resolved = read_chain(&adapter).await.expect("read");
    assert_eq!(resolved.status, ChainStatus::Single);

    verify_segments(&adapter, &mut resolved)
        .await
        .expect("a hash disagreement is a verdict");

    assert_eq!(resolved.segments, SegmentEvidence::Unchecked);
    assert_eq!(resolved.invalid.len(), 1, "{:?}", resolved.invalid);
    assert!(
        !resolved.custody_eligible(),
        "a same-size rewrite is exactly what a size check cannot see, which is why \
         custody requires the hash"
    );
}

/// A pass that gives up partway must not leave the previous pass's verdict
/// standing, nor throw away what it did observe.
///
/// The evidence used to be written only at the end. So a resolution an earlier
/// pass had marked `Verified` stayed `Verified` while a later pass ran — and
/// stayed `Verified` if that pass hit a transport error, even though it had
/// already, conclusively, seen a segment go missing. `custody_eligible()` went
/// on authorizing destruction on the strength of a verification that had just
/// been contradicted.
///
/// Both halves are asserted: the stale `Verified` is gone, and the failure
/// observed before the error is in `invalid` rather than discarded.
#[tokio::test]
async fn a_verification_that_errors_partway_neither_keeps_nor_discards_evidence() {
    let adapter = MemAdapter::content_addressed();
    let (first, second) = published_pair(&adapter).await;

    // A clean pass first, so there is a stale `Verified` for the next one to
    // wrongly inherit. Without this the test proves only half of it.
    let mut resolved = read_chain(&adapter).await.expect("read");
    verify_segments(&adapter, &mut resolved)
        .await
        .expect("intact segments verify");
    assert_eq!(resolved.segments, SegmentEvidence::Verified);
    assert!(resolved.custody_eligible());

    // Now the world breaks in two ways: one segment is gone (a verdict), and
    // the provider stops answering for the other (not a verdict).
    let gone = ObjectKey::new(first.segment_key.clone());
    adapter.remove_raw(&gone);
    adapter.set_faults(crate::testing::Faults {
        fail_head_for: Some(second.segment_key.clone()),
        ..Default::default()
    });
    assert_eq!(
        resolved.records.first().map(|r| r.segment_key.as_str()),
        Some(first.segment_key.as_str()),
        "precondition: the deleted segment must be visited BEFORE the one that \
         errors, or this run never reaches the case under test"
    );

    let err = verify_segments(&adapter, &mut resolved)
        .await
        .expect_err("the provider stopped answering");
    assert!(
        matches!(err, StorageError::Transient { .. }),
        "the transport error must propagate as itself: {err:?}"
    );

    assert_eq!(
        resolved.segments,
        SegmentEvidence::Unchecked,
        "a pass that gave up partway left the previous pass's `Verified` standing"
    );
    assert!(
        resolved
            .invalid
            .iter()
            .any(|(_, why)| why.contains(gone.as_str())),
        "the missing segment was observed and then discarded because a LATER \
         segment could not be reached: {:?}",
        resolved.invalid
    );
    assert!(!resolved.custody_eligible());
}

/// Verification is not something a caller can skip by accident: the only
/// constructor of a `ChainResolution` starts at `Unchecked`, and reading the
/// chain — however completely — never raises it.
#[tokio::test]
async fn reading_the_chain_alone_never_produces_custody() {
    let adapter = MemAdapter::content_addressed();
    let _ = published_pair(&adapter).await;

    let resolved = read_chain(&adapter).await.expect("read");
    assert_eq!(resolved.status, ChainStatus::Single);
    assert!(resolved.invalid.is_empty());
    assert_eq!(resolved.records.len(), 2);
    assert!(resolved.head.is_some());
    assert_eq!(
        resolved.segments,
        SegmentEvidence::Unchecked,
        "read_chain fetches pointer bodies only"
    );
    assert!(
        !resolved.custody_eligible(),
        "every topology clause passes and custody must still be refused"
    );
}

/// A pointer LIST named and HEAD cannot produce is malformed evidence, not an
/// entry to drop.
///
/// Skipping it resolved whatever older prefix remained — and if the vanished
/// key was the newest tip, what is left looks gapless and single-headed. The
/// caller is then told the replica is whole while it is missing its latest
/// catalog mutations, which is the one conclusion this resolution exists to
/// make impossible.
#[tokio::test]
async fn a_listed_pointer_that_head_cannot_produce_is_refused() {
    let adapter = MemAdapter::content_addressed();
    let alloc = FakeAllocator::at_epoch(3);
    let writer = ChainWriter::new(&adapter, &alloc, TargetId::new(1));
    writer
        .publish(
            SegmentKind::Delta,
            Bytes::from_static(b"a"),
            None,
            Blake3Hash::from_bytes([1; 32]),
        )
        .await
        .expect("first");

    // Without the phantom the chain resolves cleanly — so the assertion below
    // is about the phantom and not about an already-broken fixture.
    let ok = read_chain(&adapter).await.expect("resolves");
    assert_eq!(ok.status, ChainStatus::Single);

    // A newer tip the provider lists and then will not produce.
    let ghost = RecordKey {
        epoch: 9,
        seq: 99,
        uuid: "ghost".into(),
    }
    .pointer_key()
    .as_key()
    .clone();
    assert!(
        RecordKey::parse_pointer(ghost.as_str()).is_some(),
        "the fixture key must actually parse as a pointer, or this test skips it \
         before reaching the branch under test"
    );
    adapter.add_phantom_key(&ghost);

    let err = read_chain(&adapter)
        .await
        .expect_err("a listing the provider will not stand behind is not a chain");
    match err {
        StorageError::Provider { op, detail, .. } => {
            assert_eq!(op, "read_chain");
            assert!(detail.contains("absent on HEAD"), "{detail}");
        }
        other => panic!("expected a provider error, got {other:?}"),
    }
}
