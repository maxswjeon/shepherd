//! Tests for §4.10.3a's four-class recovery bundle and its per-class reducers.

use super::*;

fn clock(epoch: u64, seq: u64) -> LogicalClock {
    LogicalClock {
        writer_epoch: epoch,
        seq,
    }
}

fn custody(
    path: &str,
    seed: u8,
    target: i64,
    clock: LogicalClock,
    tombstone: bool,
) -> CustodyRecord {
    CustodyRecord {
        key: CustodyKey {
            path: path.into(),
            blake3: Blake3Hash::from_bytes([seed; 32]),
        },
        target: TargetId::new(target),
        object_key: format!("objects/{seed:02x}/{seed:02x}/{}", hex_of(seed)),
        object_version: None,
        size: 1024,
        mtime: Timestamp::from_nanos(42),
        mode: 0o644,
        restore_metadata: BTreeMap::new(),
        clock,
        tombstone,
    }
}

fn hex_of(seed: u8) -> String {
    Blake3Hash::from_bytes([seed; 32]).to_hex()
}

fn config(id: &str, value: i64, clock: LogicalClock, tombstone: bool) -> DurableConfigRecord {
    DurableConfigRecord {
        kind: ConfigKind::Rule,
        entity_id: id.into(),
        body: serde_json::json!({ "v": value }),
        clock,
        tombstone,
    }
}

#[test]
fn derived_state_is_excluded_and_the_other_two_classes_are_carried() {
    assert_eq!(
        bundle_class_of(CustodyClass::Derived),
        None,
        "tags, embeddings and indexes are rebuilt, never carried"
    );
    assert_eq!(
        bundle_class_of(CustodyClass::Custody),
        Some(BundleClass::Custody)
    );
    assert_eq!(
        bundle_class_of(CustodyClass::DurableConfig),
        Some(BundleClass::DurableConfig)
    );
}

#[test]
fn custody_is_keyed_on_path_and_hash_never_on_file_id() {
    // Two rows for the same path but different content are different custody
    // records — a `file_id` key would have collapsed them, and `file_id` is not
    // stable across an AC-6 rebuild anyway.
    let a = custody("docs/a.txt", 1, 1, clock(1, 1), false);
    let b = custody("docs/a.txt", 2, 1, clock(1, 2), false);
    let merged = merge_custody(&[a, b]);
    assert_eq!(merged.len(), 2);
}

#[test]
fn custody_merges_as_a_union_across_branches() {
    // Two branches each recorded a file the other did not see. Losing either is
    // the failure mode that matters; duplicating one is harmless.
    let branch_a = custody("docs/a.txt", 1, 1, clock(1, 5), false);
    let branch_b = custody("docs/b.txt", 2, 1, clock(2, 5), false);
    let merged = merge_custody(&[branch_a.clone(), branch_b.clone()]);
    assert_eq!(merged.len(), 2);
    assert!(merged.iter().any(|r| r.key == branch_a.key));
    assert!(merged.iter().any(|r| r.key == branch_b.key));
}

#[test]
fn the_same_record_on_two_branches_collapses_to_one() {
    let r = custody("docs/a.txt", 1, 1, clock(1, 5), false);
    assert_eq!(merge_custody(&[r.clone(), r]).len(), 1);
}

#[test]
fn a_custody_tombstone_yields_to_any_live_branch_that_reasserts_it() {
    let live = custody("docs/a.txt", 1, 1, clock(1, 5), false);
    let dead = custody("docs/a.txt", 1, 1, clock(9, 9), true);

    // Tombstoned on every branch, asserted live on none: gone.
    assert!(merge_custody(std::slice::from_ref(&dead)).is_empty());

    // Tombstone PLUS a live re-assertion on another branch: kept, even though
    // the tombstone's clock is strictly higher. This is the case that separates
    // the custody reducer from the durable-config one — there, delete wins;
    // here, honouring a stale tombstone costs the only surviving address of a
    // file whose original may already be destroyed, while keeping a duplicate
    // costs nothing.
    let merged = merge_custody(&[dead, live.clone()]);
    assert_eq!(
        merged.len(),
        1,
        "a live branch re-asserting the record must defeat the tombstone"
    );
    assert_eq!(merged[0].key, live.key);
    assert!(!merged[0].tombstone);

    // Distinct target: unaffected by the other target's tombstone.
    let other_target = custody("docs/a.txt", 1, 2, clock(1, 5), false);
    let merged = merge_custody(&[custody("docs/a.txt", 1, 1, clock(9, 9), true), other_target]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].target, TargetId::new(2));
}

#[test]
fn durable_config_is_last_writer_wins_within_one_epoch() {
    let old = config("rule-1", 1, clock(3, 10), false);
    let new = config("rule-1", 2, clock(3, 11), false);
    let merged = merge_durable_config(&[new.clone(), old]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].body, new.body);
}

#[test]
fn a_delete_then_recreate_in_one_epoch_yields_the_recreated_entity() {
    // Sequential edits by one writer: its own ordering is meaningful, so an
    // undelete is legitimate and must not be swallowed by delete-wins.
    let deleted = config("rule-1", 0, clock(4, 7), true);
    let recreated = config("rule-1", 9, clock(4, 8), false);
    let merged = merge_durable_config(&[deleted, recreated.clone()]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].body, recreated.body);
}

#[test]
fn delete_wins_over_a_concurrent_edit_on_another_branch() {
    // "rule R edited on branch A" and "rule R deleted on branch B" has no
    // additive answer. Delete-wins is the conservative direction: it cannot
    // resurrect a rule the user removed, and a resurrected tiering rule could
    // tier files the user deliberately excluded.
    let edited = config("rule-1", 5, clock(9, 100), false); // higher clock
    let deleted = config("rule-1", 0, clock(2, 1), true); // different epoch
    assert!(
        merge_durable_config(&[edited, deleted]).is_empty(),
        "a concurrent delete must win even against a numerically newer edit"
    );
}

#[test]
fn a_tombstone_as_outright_winner_deletes() {
    let edited = config("rule-1", 5, clock(2, 1), false);
    let deleted = config("rule-1", 0, clock(2, 2), true);
    assert!(merge_durable_config(&[edited, deleted]).is_empty());
}

#[test]
fn distinct_entities_and_kinds_do_not_interfere() {
    let mut a = config("rule-1", 1, clock(1, 1), false);
    a.kind = ConfigKind::Rule;
    let mut b = config("rule-1", 2, clock(1, 1), false);
    b.kind = ConfigKind::DeletePolicy; // same id, different kind
    let c = config("rule-2", 3, clock(1, 1), false);
    assert_eq!(merge_durable_config(&[a, b, c]).len(), 3);
}

#[test]
fn a_bundle_segment_round_trips_through_zstd_jsonl() {
    let entries = vec![
        BundleEntry::Bootstrap(BootstrapRecord::new(
            vec!["https://s3.example/bucket".into()],
            "shepherd/".into(),
            AttestationMode::Content,
        )),
        BundleEntry::Custody(custody("docs/a.txt", 1, 1, clock(1, 1), false)),
        BundleEntry::DurableConfig(config("rule-1", 7, clock(1, 2), false)),
    ];
    let encoded = encode_segment(&entries).expect("encode");
    // Really compressed, not merely renamed: zstd frames start with the magic
    // number 0xFD2FB528, little-endian.
    assert_eq!(&encoded[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
    assert_eq!(decode_segment(&encoded).expect("decode"), entries);
}

#[test]
fn an_empty_segment_round_trips() {
    let encoded = encode_segment(&[]).expect("encode");
    assert!(decode_segment(&encoded).expect("decode").is_empty());
}

#[test]
fn the_bootstrap_record_lands_on_a_well_known_control_key() {
    // The scenario: a user has a target URL and credentials and nothing else.
    assert_eq!(
        bootstrap_key().as_key().as_str(),
        "_shepherd/bootstrap.json"
    );
    assert!(bootstrap_key().as_key().is_control_object());

    let b = BootstrapRecord::new(
        vec!["https://x/y".into()],
        "p/".into(),
        AttestationMode::Version,
    );
    assert_eq!(b.bundle_schema_version, BUNDLE_SCHEMA_VERSION);
    // It records which attestation mechanism the target was probed to support,
    // so a recovering machine does not have to guess.
    assert_eq!(b.attestation_mode, AttestationMode::Version);
}

#[test]
fn corrupt_segment_bytes_are_reported_rather_than_partially_accepted() {
    assert!(decode_segment(b"not a zstd frame").is_err());
}
