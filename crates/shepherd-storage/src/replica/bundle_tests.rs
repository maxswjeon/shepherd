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
    let merged = merge_custody(&[branch("p", &[&a, &b])]);
    assert_eq!(merged.len(), 2);
}

#[test]
fn custody_merges_as_a_union_across_branches() {
    // Two branches each recorded a file the other did not see. Losing either is
    // the failure mode that matters; duplicating one is harmless.
    let branch_a = custody("docs/a.txt", 1, 1, clock(1, 5), false);
    let branch_b = custody("docs/b.txt", 2, 1, clock(2, 5), false);
    let merged = merge_custody(&[branch("pa", &[&branch_a]), branch("pb", &[&branch_b])]);
    assert_eq!(merged.len(), 2);
    assert!(merged.iter().any(|r| r.key == branch_a.key));
    assert!(merged.iter().any(|r| r.key == branch_b.key));
}

#[test]
fn the_same_record_on_two_branches_collapses_to_one() {
    let r = custody("docs/a.txt", 1, 1, clock(1, 5), false);
    assert_eq!(
        merge_custody(&[vec![cus_of(&r, "shared")], vec![cus_of(&r, "shared")]]).len(),
        1
    );
}

#[test]
fn a_custody_tombstone_yields_to_a_live_assertion_it_does_not_dominate() {
    let dead = custody("docs/a.txt", 1, 1, clock(9, 9), true);

    // Tombstoned on every branch, asserted live on none: gone.
    assert!(merge_custody(&[branch("p", &[&dead])]).is_empty());

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
        let merged = merge_custody(&[branch("pa", &[&dead]), branch("pb", &[&other_branch])]);
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
    let merged = merge_custody(&[branch("pa", &[&dead]), branch("pb", &[&other_target])]);
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

    let merged = merge_custody(&[branch("pb", &[&tombstone]), branch("pa", &[&live])]);
    assert_eq!(
        merged.len(),
        1,
        "the surviving branch's custody record was filtered out by a tombstone that never \
         observed it"
    );
    assert_eq!(merged[0].clock, live.clock);
    assert!(!merged[0].tombstone);

    // Order-independent, as a merge must be.
    assert_eq!(
        merge_custody(&[branch("pa", &[&live]), branch("pb", &[&tombstone])]).len(),
        1
    );
}

/// A tombstone in the SAME epoch on a sibling branch retires nothing.
///
/// The reducer used to accept `same writer_epoch && higher seq` as proof that a
/// tombstone followed an assertion. That reads an epoch as a branch, and this
/// module explicitly supports the case where it is not: a rolled-back local
/// catalog REUSES an epoch — which is why the pointer key carries a uuid at all
/// — so such a writer republishes from a stale predecessor, counts past a
/// sibling branch it never saw, and its tombstone retired the only live custody
/// record for bytes whose original may already be gone.
///
/// Custody is the class where this costs the most: honouring a tombstone that
/// retired nothing loses the last address of a missing file, while keeping a
/// duplicate costs nothing.
#[test]
fn a_same_epoch_tombstone_on_a_sibling_branch_retires_nothing() {
    // Branch A holds the only live assertion.
    let live = custody("docs/a.txt", 1, 1, clock(4, 2), false);
    // Branch B: the same epoch, reused after a rollback, counting higher from a
    // predecessor that never carried A.
    let stale_tombstone = custody("docs/a.txt", 1, 1, clock(4, 9), true);

    let merged = merge_custody(&[branch("pa", &[&live]), branch("pb", &[&stale_tombstone])]);
    assert_eq!(
        merged.len(),
        1,
        "a same-epoch tombstone from a branch that never saw this assertion \
         retired it: {merged:?}"
    );
    assert!(!merged[0].tombstone);
    assert_eq!(merged[0].clock, live.clock);

    // THE DISCRIMINATOR. Put both on ONE branch — now the tombstone really does
    // follow the assertion — and it retires it, which is what
    // `a_custody_record_retired_later_by_the_same_writer_stays_retired`
    // requires and what a rule of "never retire across epochs" would break.
    assert!(
        merge_custody(&[branch("p", &[&live, &stale_tombstone])]).is_empty(),
        "a tombstone later on the SAME branch is an ordinary retirement"
    );
}

/// And across a restart on one branch, which the old epoch-equality rule
/// could not express at all.
///
/// A live assertion in epoch 4 retired in epoch 5 by the same writer, on the
/// same chain, is one writer's own sequence — exactly the cross-restart case
/// the durable-config reducer was corrected for in round 11.
#[test]
fn a_retirement_across_a_restart_on_one_branch_still_retires() {
    let live = custody("docs/a.txt", 1, 1, clock(4, 12), false);
    let retired_next_boot = custody("docs/a.txt", 1, 1, clock(5, 1), true);
    assert!(
        merge_custody(&[branch("p", &[&live, &retired_next_boot])]).is_empty(),
        "one writer's own history spans its restarts"
    );
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
        merge_custody(&[branch("p", &[&live, &retired])]).is_empty(),
        "a tombstone that strictly dominates the live assertion retires it"
    );
    // Order of records must not matter — this is a merge, not a fold over a
    // stream someone controls the order of.
    assert!(merge_custody(&[branch("p", &[&retired, &live])]).is_empty());
}

/// One publication carrying one record. Distinct ids are distinct
/// publications even when the records are byte-identical.
fn pub_of(r: &DurableConfigRecord, id: &str) -> Publication<DurableConfigRecord> {
    Publication::new(id, vec![r.clone()])
}

/// The same, for custody records.
fn cus_of(r: &CustodyRecord, id: &str) -> Publication<CustodyRecord> {
    Publication::new(id, vec![r.clone()])
}

/// One branch carrying a sequence of single-record publications, ids derived
/// from `prefix` so two branches built this way share no ancestry.
fn branch(prefix: &str, records: &[&CustodyRecord]) -> Vec<Publication<CustodyRecord>> {
    records
        .iter()
        .enumerate()
        .map(|(i, r)| cus_of(r, &format!("{prefix}-{i}")))
        .collect()
}

#[test]
fn durable_config_is_last_writer_wins_within_one_epoch() {
    let old = config("rule-1", 1, clock(3, 10), false);
    let new = config("rule-1", 2, clock(3, 11), false);
    let merged = merge_durable_config(&[vec![pub_of(&new, "p2"), pub_of(&old, "p1")]]);
    assert_eq!(merged.len(), 1);
    assert_eq!(merged[0].body, new.body);
}

#[test]
fn a_delete_then_recreate_in_one_epoch_yields_the_recreated_entity() {
    // Sequential edits by one writer: its own ordering is meaningful, so an
    // undelete is legitimate and must not be swallowed by delete-wins.
    let deleted = config("rule-1", 0, clock(4, 7), true);
    let recreated = config("rule-1", 9, clock(4, 8), false);
    let merged = merge_durable_config(&[vec![pub_of(&deleted, "p1"), pub_of(&recreated, "p2")]]);
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
        merge_durable_config(&[vec![pub_of(&edited, "pa")], vec![pub_of(&deleted, "pb")]])
            .is_empty(),
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
            vec![pub_of(&stale_writer_republished, "pa")],
            vec![pub_of(&deleted_elsewhere, "pb")],
        ])
        .is_empty(),
        "the branches share no ancestry, so the delete is concurrent and wins"
    );

    // Order of the branches must not matter.
    assert!(
        merge_durable_config(&[
            vec![pub_of(&deleted_elsewhere, "pb")],
            vec![pub_of(&stale_writer_republished, "pa")],
        ])
        .is_empty()
    );
}

/// A tombstone its OWN branch has moved past is history, not a conflict.
///
/// Branch B deleted the rule and then re-created it; branch A carries an
/// unrelated live record with a numerically higher clock. Both branches END on
/// "alive", so there is nothing to resolve — but comparing raw records instead
/// of branch frontiers made B's superseded tombstone face A's winner, find no
/// shared branch, and win as a concurrent delete. Recovery then omitted a rule,
/// target or setting that was active on every branch.
#[test]
fn a_tombstone_its_own_branch_re_created_past_does_not_delete() {
    let live_on_a = config("rule-1", 1, clock(5, 10), false);
    let deleted_on_b = config("rule-1", 0, clock(3, 40), true);
    let recreated_on_b = config("rule-1", 2, clock(3, 41), false);

    let merged = merge_durable_config(&[
        vec![pub_of(&live_on_a, "pa")],
        vec![pub_of(&deleted_on_b, "pb1"), pub_of(&recreated_on_b, "pb2")],
    ]);
    assert_eq!(
        merged.len(),
        1,
        "both branches end on a live record; the delete is B's own history"
    );
    assert_eq!(
        merged[0].body, live_on_a.body,
        "and last-writer-wins still picks the higher clock between two live \
         frontiers"
    );

    // The discriminating pair: strip the re-creation and the very same
    // tombstone becomes B's frontier, concurrent with A, and wins.
    assert!(
        merge_durable_config(&[
            vec![pub_of(&live_on_a, "pa")],
            vec![pub_of(&deleted_on_b, "pb1")]
        ])
        .is_empty(),
        "a tombstone that IS its branch's frontier must still delete"
    );
}

/// Two writers that independently emit the SAME record have not seen each
/// other, and value equality cannot tell that from shared history.
///
/// Both branches delete the rule at the same clock; A then re-creates it. The
/// two tombstones are byte-identical, so collapsing on value merged them into
/// one `Seen` that appeared on both branches — and B's frontier, a concurrent
/// delete, then looked as though it shared branch A with the re-creation and
/// was called dominated. The rule came back on a branch that never re-created
/// it.
///
/// Distinct `origin`s are what say "two publications". Same value, same clock,
/// different pointers.
#[test]
fn identical_records_from_sibling_writers_are_not_shared_history() {
    let deleted = config("rule-1", 0, clock(4, 1), true);
    let recreated_on_a = config("rule-1", 7, clock(4, 2), false);

    let merged = merge_durable_config(&[
        vec![pub_of(&deleted, "pa1"), pub_of(&recreated_on_a, "pa2")],
        // B emitted its own delete — same bytes, same clock, its own pointer.
        vec![pub_of(&deleted, "pb1")],
    ]);
    assert!(
        merged.is_empty(),
        "B's delete is concurrent with A's re-creation; equal bytes are not \
         evidence that B ever saw A. Got {merged:?}"
    );

    // THE DISCRIMINATOR. Give the tombstone one shared origin — now it really
    // is one publication both branches descend through — and the re-creation
    // dominates it, as `a_tombstone_from_before_the_fork_is_still_in_the_winners_past`
    // requires.
    let merged = merge_durable_config(&[
        vec![pub_of(&deleted, "shared"), pub_of(&recreated_on_a, "pa2")],
        vec![pub_of(&deleted, "shared")],
    ]);
    assert_eq!(
        merged.len(),
        1,
        "the same publication on both branches IS shared history: {merged:?}"
    );
    assert_eq!(merged[0].body, recreated_on_a.body);
}

/// One segment can carry several entries for one entity, and they are several
/// records.
///
/// A batched edit followed by its tombstone shares the publishing pointer, so
/// keying identity on that pointer alone collapsed them and kept only the
/// first: the tombstone vanished and a destructive rule was recovered alive.
/// Reversed, a re-creation batched after a delete was the one suppressed.
///
/// The identity is `(publication, position)`, so entries from one segment stay
/// distinct while the same segment seen from two branches stays one.
#[test]
fn several_entries_in_one_segment_are_several_records() {
    let edited = config("rule-1", 5, clock(2, 1), false);
    let then_deleted = config("rule-1", 0, clock(2, 2), true);

    // One publication, two entries, in that order.
    let batched = Publication::new("p1", vec![edited.clone(), then_deleted.clone()]);
    assert!(
        merge_durable_config(&[vec![batched]]).is_empty(),
        "the tombstone batched behind the edit was dropped, and the rule came \
         back alive"
    );

    // The other order, which the same defect suppressed rather than resurrected.
    let recreated = config("rule-1", 9, clock(2, 3), false);
    let batched = Publication::new(
        "p1",
        vec![config("rule-1", 0, clock(2, 2), true), recreated.clone()],
    );
    let merged = merge_durable_config(&[vec![batched]]);
    assert_eq!(
        merged.len(),
        1,
        "a re-creation batched after a delete must survive: {merged:?}"
    );
    assert_eq!(merged[0].body, recreated.body);

    // And the same publication seen from two branches is still ONE history:
    // both entries collapse per branch, not per occurrence.
    let shared = Publication::new("p1", vec![edited, config("rule-1", 0, clock(2, 2), true)]);
    assert!(
        merge_durable_config(&[vec![shared.clone()], vec![shared]]).is_empty(),
        "two descendants of one publication do not make its entries concurrent"
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

    // The shared prefix carries the SAME origins on both branches, because it
    // is the same publication seen from two descendants — which is exactly the
    // thing value equality could not prove.
    let merged = merge_durable_config(&[
        vec![
            pub_of(&deleted_early, "p1"),
            pub_of(&recreated, "p2"),
            pub_of(&edited_on_a, "p3"),
        ],
        vec![pub_of(&deleted_early, "p1"), pub_of(&recreated, "p2")],
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

    let merged = merge_durable_config(&[vec![pub_of(&deleted, "p1"), pub_of(&recreated, "p2")]]);
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
    assert!(
        merge_durable_config(&[vec![pub_of(&created, "p1"), pub_of(&then_deleted, "p2")]])
            .is_empty()
    );
}

#[test]
fn a_tombstone_as_outright_winner_deletes() {
    let edited = config("rule-1", 5, clock(2, 1), false);
    let deleted = config("rule-1", 0, clock(2, 2), true);
    assert!(
        merge_durable_config(&[vec![pub_of(&edited, "p1"), pub_of(&deleted, "p2")]]).is_empty()
    );
}

#[test]
fn distinct_entities_and_kinds_do_not_interfere() {
    let mut a = config("rule-1", 1, clock(1, 1), false);
    a.kind = ConfigKind::Rule;
    let mut b = config("rule-1", 2, clock(1, 1), false);
    b.kind = ConfigKind::DeletePolicy; // same id, different kind
    let c = config("rule-2", 3, clock(1, 1), false);
    assert_eq!(
        merge_durable_config(&[vec![pub_of(&a, "p1"), pub_of(&b, "p1"), pub_of(&c, "p1")]]).len(),
        3
    );
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

/// A segment that expands past the ceiling is refused before it is held.
///
/// The compressed body comes from the TARGET and zstd's expansion ratio is
/// unbounded, so a small planted or corrupted object can decompress to many
/// gigabytes — and `decode_all` built the whole frame in one `Vec` before
/// anything parsed it. Recovery is exactly when the daemon has least to spare.
#[test]
fn a_segment_that_expands_past_the_ceiling_is_refused() {
    // Highly compressible, and larger than the ceiling. Zeroes cost almost
    // nothing to encode, which is the shape of the attack.
    let huge = vec![0u8; (MAX_SEGMENT_BYTES + 1024) as usize];
    let bomb = zstd::encode_all(huge.as_slice(), 3).expect("encode");
    assert!(
        (bomb.len() as u64) < MAX_SEGMENT_BYTES / 100,
        "the fixture must be small compressed, or it is not testing expansion: {} bytes",
        bomb.len()
    );

    let err = decode_segment(&bomb).expect_err("an expansion past the ceiling must be refused");
    assert!(
        format!("{err:?}").contains("ceiling"),
        "the refusal must say what it refused: {err:?}"
    );

    // AND THE ACCEPTING DIRECTION: an ordinary segment still round-trips, so
    // the ceiling cannot be satisfied by refusing everything.
    let entries = vec![BundleEntry::Bootstrap(BootstrapRecord::new(
        vec!["https://s3.example".into()],
        "shepherd".into(),
        AttestationMode::Version,
    ))];
    let ok = encode_segment(&entries).expect("encode");
    assert_eq!(decode_segment(&ok).expect("decode"), entries);
}

/// A segment from another schema version is refused, not half-read.
///
/// `BootstrapRecord` carries `bundle_schema_version` and nothing read it — and
/// serde ignores unknown fields by default, so a future segment deserialises
/// cleanly while this build drops whatever it added and applies version-1
/// meaning to whatever it changed. Disaster recovery that is quietly incomplete
/// is worse than one that refuses: the refusal is fixed by upgrading, and the
/// silent version is discovered by finding files missing.
#[test]
fn a_segment_from_another_schema_version_is_refused() {
    let mut record = BootstrapRecord::new(
        vec!["https://s3.example".into()],
        "shepherd".into(),
        AttestationMode::Version,
    );
    record.bundle_schema_version = BUNDLE_SCHEMA_VERSION + 1;
    let body = encode_segment(&[BundleEntry::Bootstrap(record)]).expect("encode");

    let err = decode_segment(&body).expect_err("another schema version must be refused");
    let text = format!("{err:?}");
    assert!(
        text.contains(&(BUNDLE_SCHEMA_VERSION + 1).to_string())
            && text.contains(&BUNDLE_SCHEMA_VERSION.to_string()),
        "the refusal must name both versions: {text}"
    );
}
