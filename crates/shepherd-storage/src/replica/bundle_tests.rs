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
fn a_custody_tombstone_yields_to_a_live_assertion_it_does_not_dominate() {
    let dead = custody("docs/a.txt", 1, 1, clock(9, 9), true);

    // Tombstoned on every branch, asserted live on none: gone.
    assert!(merge_custody(std::slice::from_ref(&dead)).is_empty());

    // A tombstone from a DIFFERENT epoch retires nothing. `writer_epoch`
    // increments on every daemon start, so a writer restarted from a stale
    // predecessor publishes a higher-epoch tombstone without ever having
    // observed this branch — and its live assertion may be the only one there
    // is. This is also the case that separates the custody reducer from the
    // durable-config one: there, delete wins; here, honouring a tombstone costs
    // the only surviving address of a file whose original may already be
    // destroyed, while keeping a duplicate costs nothing.
    for other_branch in [
        // Genuinely concurrent: the same clock.
        custody("docs/a.txt", 1, 1, clock(9, 9), false),
        // A lower epoch — the tombstone's writer counted higher, which says
        // nothing about whether it saw this.
        custody("docs/a.txt", 1, 1, clock(1, 5), false),
        // A higher epoch — a re-assertion, and equally unretired.
        custody("docs/a.txt", 1, 1, clock(10, 1), false),
    ] {
        let merged = merge_custody(&[dead.clone(), other_branch.clone()]);
        assert_eq!(
            merged.len(),
            1,
            "a tombstone from another epoch retired a live assertion it never observed: \
             {other_branch:?}"
        );
        assert!(!merged[0].tombstone);
    }

    // Distinct target: unaffected by the other target's tombstone.
    let other_target = custody("docs/a.txt", 1, 2, clock(1, 5), false);
    let merged = merge_custody(&[dead, other_target]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].target, TargetId::new(2));
}

/// A tombstone published by a RESTARTED writer does not retire a sibling
/// branch's only live assertion.
///
/// `LogicalClock` is a counter, not a causal clock, and these records arrive
/// flattened across every valid fork branch — so a higher `(epoch, seq)` says
/// only that some writer counted higher. A writer resuming from a stale
/// predecessor does exactly that without having observed the sibling branch,
/// and reading it as domination filtered out a custody record nothing had
/// retired: the only address of bytes whose original may already be gone.
#[test]
fn a_restarted_writers_tombstone_does_not_retire_another_branch() {
    // Branch A: the only live assertion, from the run that made it.
    let live = custody("docs/a.txt", 1, 1, clock(4, 12), false);
    // Branch B: a later run, resumed from a predecessor that never carried A,
    // retiring what IT believed the record to be.
    let tombstone = custody("docs/a.txt", 1, 1, clock(7, 1), true);

    let merged = merge_custody(&[tombstone.clone(), live.clone()]);
    assert_eq!(
        merged.len(),
        1,
        "the surviving branch's custody record was filtered out by a tombstone that never \
         observed it"
    );
    assert_eq!(merged[0].clock, live.clock);
    assert!(!merged[0].tombstone);

    // Order-independent, as a merge must be.
    assert_eq!(merge_custody(&[live, tombstone]).len(), 1);
}

/// A live record retired later by the SAME writer stays retired.
///
/// The reducer used to filter every tombstone out before grouping, so a live
/// assertion survived any tombstone at all — correct against a concurrent
/// branch, and wrong against the writer's own history. Live at `(1, 1)` then a
/// tombstone at `(1, 2)` is an ordinary retirement, and resurrecting it during
/// disaster recovery hands the user a remote location that no longer holds the
/// object.
#[test]
fn a_custody_record_retired_later_by_the_same_writer_stays_retired() {
    let live = custody("docs/a.txt", 1, 1, clock(1, 1), false);
    let retired = custody("docs/a.txt", 1, 1, clock(1, 2), true);

    assert!(
        merge_custody(&[live.clone(), retired.clone()]).is_empty(),
        "a tombstone that strictly dominates the live assertion retires it"
    );
    // Order of records must not matter — this is a merge, not a fold over a
    // stream someone controls the order of.
    assert!(merge_custody(&[retired, live]).is_empty());
}

#[test]
fn durable_config_is_last_writer_wins_within_one_epoch() {
    let old = config("rule-1", 1, clock(3, 10), false);
    let new = config("rule-1", 2, clock(3, 11), false);
    let merged = merge_durable_config(&[vec![new.clone(), old]]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].body, new.body);
}

#[test]
fn a_delete_then_recreate_in_one_epoch_yields_the_recreated_entity() {
    // Sequential edits by one writer: its own ordering is meaningful, so an
    // undelete is legitimate and must not be swallowed by delete-wins.
    let deleted = config("rule-1", 0, clock(4, 7), true);
    let recreated = config("rule-1", 9, clock(4, 8), false);
    let merged = merge_durable_config(&[vec![deleted, recreated.clone()]]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].body, recreated.body);
}

#[test]
fn delete_wins_over_a_concurrent_edit_on_another_branch() {
    // "rule R edited on branch A" and "rule R deleted on branch B" has no
    // additive answer. Delete-wins is the conservative direction: it cannot
    // resurrect a rule the user removed, and a resurrected tiering rule could
    // tier files the user deliberately excluded.
    //
    // ORACLE CHANGED. This test used to give both records the SAME clock, under
    // the comment "concurrency is the same clock" — which is what the reducer
    // believed and is false. Two records on sibling branches are concurrent
    // whatever their numbers say, and the numbers are usually different.
    let edited = config("rule-1", 5, clock(9, 100), false);
    let deleted = config("rule-1", 0, clock(9, 100), true);
    assert!(
        merge_durable_config(&[vec![edited], vec![deleted]]).is_empty(),
        "a concurrent delete must win"
    );
}

/// The resurrection this reducer was returning: a HIGHER clock on a sibling
/// branch is not a later edit.
///
/// A stale writer that restarted (epoch 5) republishes a rule while a sibling
/// branch, still in epoch 3, deleted it. `(5, 10) > (3, 40)` as a value and
/// means nothing as causality: neither writer ever saw the other. The reducer
/// read the number as the order, the live record won, and disaster recovery
/// brought back a rule the user had removed — for a tiering rule, one that
/// would then act on files they deliberately excluded.
///
/// The clocks are deliberately the wrong way round: the delete has the LARGER
/// `seq` and the smaller epoch, so no clock-only rule can pass this and the
/// preceding test at once.
#[test]
fn a_numerically_higher_record_on_a_sibling_branch_does_not_beat_a_delete() {
    let stale_writer_republished = config("rule-1", 5, clock(5, 10), false);
    let deleted_elsewhere = config("rule-1", 0, clock(3, 40), true);

    assert!(
        merge_durable_config(&[
            vec![stale_writer_republished.clone()],
            vec![deleted_elsewhere.clone()],
        ])
        .is_empty(),
        "the branches share no ancestry, so the delete is concurrent and wins"
    );

    // Order of the branches must not matter.
    assert!(
        merge_durable_config(&[vec![deleted_elsewhere], vec![stale_writer_republished]]).is_empty()
    );
}

/// History before a fork point belongs to every branch that descends from it,
/// so a pre-fork tombstone stays in the winner's past.
///
/// Without this, "share a branch" could be implemented as "the winner's branch
/// list is exactly this one's" and every entity with any history at all would
/// come back deleted.
#[test]
fn a_tombstone_from_before_the_fork_is_still_in_the_winners_past() {
    let deleted_early = config("rule-1", 0, clock(1, 1), true);
    let recreated = config("rule-1", 9, clock(1, 2), false);
    // Both branches carry the shared prefix; one of them went on to edit.
    let edited_on_a = config("rule-1", 9, clock(2, 5), false);

    let merged = merge_durable_config(&[
        vec![
            deleted_early.clone(),
            recreated.clone(),
            edited_on_a.clone(),
        ],
        vec![deleted_early, recreated],
    ]);
    assert_eq!(
        merged.len(),
        1,
        "the tombstone precedes both branches' surviving records on a branch \
         they share, so it is history, not a conflict"
    );
    assert_eq!(merged[0].body, edited_on_a.body);
}

/// A delete and a re-creation ACROSS a restart is one writer editing, not two
/// branches conflicting.
///
/// `writer_epoch` increments on every daemon start, so the rule "a tombstone in
/// a different epoch is concurrent" called every cross-restart re-creation a
/// conflict and let the old tombstone suppress it. Recovery then omitted rules,
/// targets and settings the user was actively using — and did so precisely when
/// the re-creation crossed a restart, which is the ordinary way a user
/// re-creates anything.
#[test]
fn a_delete_then_recreate_across_a_restart_yields_the_recreated_entity() {
    let deleted = config("rule-1", 0, clock(2, 7), true);
    let recreated = config("rule-1", 9, clock(3, 1), false);

    let merged = merge_durable_config(&[vec![deleted.clone(), recreated.clone()]]);
    assert_eq!(
        merged.len(),
        1,
        "an epoch-2 delete is in an epoch-3 re-creation's PAST, not concurrent with it"
    );
    assert_eq!(merged[0].body, recreated.body);

    // And the opposite order still deletes: a re-creation in epoch 2 followed
    // by a delete in epoch 3 is equally sequential.
    let created = config("rule-1", 9, clock(2, 7), false);
    let then_deleted = config("rule-1", 0, clock(3, 1), true);
    assert!(merge_durable_config(&[vec![created, then_deleted]]).is_empty());
}

#[test]
fn a_tombstone_as_outright_winner_deletes() {
    let edited = config("rule-1", 5, clock(2, 1), false);
    let deleted = config("rule-1", 0, clock(2, 2), true);
    assert!(merge_durable_config(&[vec![edited, deleted]]).is_empty());
}

#[test]
fn distinct_entities_and_kinds_do_not_interfere() {
    let mut a = config("rule-1", 1, clock(1, 1), false);
    a.kind = ConfigKind::Rule;
    let mut b = config("rule-1", 2, clock(1, 1), false);
    b.kind = ConfigKind::DeletePolicy; // same id, different kind
    let c = config("rule-2", 3, clock(1, 1), false);
    assert_eq!(merge_durable_config(&[vec![a, b, c]]).len(), 3);
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
