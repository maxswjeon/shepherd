//! Engine tests.
//!
//! The load-bearing one is `a_dry_run_and_a_real_run_enumerate_the_same_set`:
//! AC-14 requires it, and it is a property of there being one traversal rather
//! than a claim about two.

use super::*;
use crate::delete_policy::DeleteAction;
use shepherd_core::{Blake3Hash, RootId, TargetId};

const DAY: i64 = 86_400 * 1_000_000_000;

fn now() -> Timestamp {
    Timestamp::from_nanos(1_000 * DAY)
}

fn candidate(id: i64, name: &str, age_days: i64, size: u64) -> Candidate {
    let mtime = Timestamp::from_nanos(now().as_nanos() - age_days * DAY);
    Candidate {
        file: FileId::new(id),
        stat: FileStat {
            root: RootId::new(1),
            rel_path: name.into(),
            size,
            mtime,
            ctime: mtime,
            atime: Some(mtime),
            blake3: Some(Blake3Hash::from_bytes([1u8; 32])),
        },
        last_observed_access: Some(mtime),
        tags: Vec::new(),
    }
}

fn corpus() -> Vec<Candidate> {
    vec![
        candidate(1, "Photos/old.raw", 400, 50_000_000),
        candidate(2, "Photos/new.raw", 5, 50_000_000),
        candidate(3, "Docs/notes.txt", 400, 1_000),
    ]
}

fn body(action: RuleAction) -> RuleBody {
    RuleBody {
        name: "archive old raws".into(),
        match_json: serde_json::json!({ "ext": ["raw"], "older_than_days": 365 }),
        action,
        age_signal: None,
    }
}

fn tiering() -> RuleBody {
    body(RuleAction::Tier {
        destinations: vec![TargetId::new(1)],
    })
}

/// **AC-14.** The dry run must enumerate exactly the real run's set.
#[test]
fn a_dry_run_and_a_real_run_enumerate_the_same_set() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    let c = corpus();

    let dry = e.run(&c, RunMode::DryRun, None, now()).expect("dry run");
    let preview = e.preview(&c, now()).expect("preview");
    let real = e
        .run(&c, RunMode::Execute, Some(&preview), now())
        .expect("execute");

    assert_eq!(
        dry.matches, real.matches,
        "the dry run and the real run must enumerate the same set"
    );
    // Only the old raw matches: new.raw is too young, notes.txt is not a raw.
    assert_eq!(dry.matches.len(), 1);
    assert_eq!(dry.matches[0].file, FileId::new(1));
    assert_eq!(dry.considered, 3);
}

#[test]
fn a_dry_run_plans_nothing() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    let dry = e.run(&corpus(), RunMode::DryRun, None, now()).expect("dry");
    assert!(!dry.matches.is_empty(), "precondition: something matched");
    assert!(
        dry.actions.is_empty(),
        "a dry run must not produce actions even when files match"
    );
}

#[test]
fn a_real_run_produces_one_action_per_match() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    let c = corpus();
    let p = e.preview(&c, now()).expect("preview");
    let real = e.run(&c, RunMode::Execute, Some(&p), now()).expect("run");

    assert_eq!(real.actions.len(), real.matches.len());
    assert_eq!(real.actions[0].file, FileId::new(1));
    assert_eq!(real.actions[0].action, b.action);
}

// --- enablement is re-checked at execution --------------------------------

#[test]
fn executing_without_a_preview_is_refused() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    match e.run(&corpus(), RunMode::Execute, None, now()) {
        Err(EngineRefusal::NotEnabled { .. }) => {}
        other => panic!("a real run with no preview must be refused: {other:?}"),
    }
}

/// The gap `preview.rs` alone cannot close: enable, then edit, then run.
#[test]
fn executing_against_a_preview_of_a_different_body_is_refused() {
    let original = tiering();
    let e0 = Engine::new(&original, AtimeMode::Reliable);
    let stale = e0.preview(&corpus(), now()).expect("preview");

    // The user widens the rule after it was previewed and enabled.
    let mut edited = tiering();
    edited.match_json = serde_json::json!({ "ext": ["raw"], "older_than_days": 1 });
    let e1 = Engine::new(&edited, AtimeMode::Reliable);

    match e1.run(&corpus(), RunMode::Execute, Some(&stale), now()) {
        Err(EngineRefusal::NotEnabled { .. }) => {}
        other => panic!("an edit between enable and run must not slip through: {other:?}"),
    }

    // A dry run of the edited rule is still fine — that is how you re-preview.
    let dry = e1
        .run(&corpus(), RunMode::DryRun, None, now())
        .expect("dry");
    assert_eq!(
        dry.matches.len(),
        2,
        "the widened rule now matches both raws, which is why re-previewing matters"
    );
}

// --- §4.12 and the matcher --------------------------------------------------

#[test]
fn a_destructive_atime_rule_on_an_untrustworthy_root_is_refused_at_compile() {
    let mut b = tiering(); // Tier is destructive on a delete-mode root
    b.match_json = serde_json::json!({ "ext": ["raw"], "atime_older_than_days": 365 });
    let e = Engine::new(&b, AtimeMode::Disabled);
    match e.run(&corpus(), RunMode::DryRun, None, now()) {
        Err(EngineRefusal::Untrustworthy { .. }) => {}
        other => panic!("expected a §4.12 refusal, got {other:?}"),
    }
}

#[test]
fn relatime_is_permitted_because_it_is_the_linux_default() {
    let mut b = tiering();
    b.match_json = serde_json::json!({ "ext": ["raw"], "atime_older_than_days": 365 });
    let e = Engine::new(&b, AtimeMode::Relatime);
    assert!(
        e.run(&corpus(), RunMode::DryRun, None, now()).is_ok(),
        "refusing relatime would refuse destructive age rules on nearly every Linux root"
    );
}

#[test]
fn a_non_destructive_rule_may_rest_on_weak_atime() {
    let mut b = body(RuleAction::Delete(DeleteAction::Orphan));
    b.match_json = serde_json::json!({ "ext": ["raw"], "atime_older_than_days": 365 });
    let e = Engine::new(&b, AtimeMode::Disabled);
    assert!(e.run(&corpus(), RunMode::DryRun, None, now()).is_ok());
}

/// An unknown key is refused, not ignored.
#[test]
fn a_typo_in_a_predicate_key_is_refused_rather_than_silently_dropped() {
    let mut b = tiering();
    // `older_thn_days` dropped silently would mean "every raw file ever".
    b.match_json = serde_json::json!({ "ext": ["raw"], "older_thn_days": 365 });
    let e = Engine::new(&b, AtimeMode::Reliable);
    match e.run(&corpus(), RunMode::DryRun, None, now()) {
        Err(EngineRefusal::InvalidRule { detail }) => {
            assert!(detail.contains("older_thn_days"), "{detail}");
        }
        other => panic!("a typo'd key must be refused, got {other:?}"),
    }
}

// --- the preview records provenance ---------------------------------------

#[test]
fn the_preview_records_the_signal_that_actually_drove_each_match() {
    // Under relatime the matcher resolves an atime predicate against mtime and
    // says so. The preview must print what drove the match, not what the rule
    // asked for.
    let mut b = tiering();
    b.match_json = serde_json::json!({ "ext": ["raw"], "atime_older_than_days": 365 });
    let e = Engine::new(&b, AtimeMode::Relatime);
    let p = e.preview(&corpus(), now()).expect("preview");

    assert!(!p.matches.is_empty());
    assert_ne!(
        p.matches[0].signal,
        AccessSignalSource::Atime,
        "under relatime the signal must not claim to be atime"
    );
}

#[test]
fn a_preview_binds_to_the_body_it_was_taken_against() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    let p = e.preview(&corpus(), now()).expect("preview");
    assert_eq!(p.rule_hash, preview_hash(&b));
    assert!(may_enable(&b, Some(&p), AtimeMode::Reliable).is_permitted());
}

#[test]
fn zero_matches_is_distinguishable_from_nothing_considered() {
    // "Is my rule working?" has two very different answers here.
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);

    let none_match = e
        .run(
            &[candidate(9, "Docs/a.txt", 5, 10)],
            RunMode::DryRun,
            None,
            now(),
        )
        .expect("dry");
    assert_eq!(none_match.matches.len(), 0);
    assert_eq!(none_match.considered, 1);

    let nothing_seen = e.run(&[], RunMode::DryRun, None, now()).expect("dry");
    assert_eq!(nothing_seen.considered, 0);
}

// --- execution is bound to the previewed SET, not just the rule body -------
//
// `may_enable` proves the rule text has not changed. It says nothing about the
// corpus, which moves on its own: files are created, deleted, retagged and
// touched between the dry run an operator read and the run they authorized.
// AC-14's "exactly the real run's set" is a claim about the set, so the set is
// what gets compared.

/// A candidate whose Shepherd-owned access signal is absent, so an `atime`
/// predicate falls through to `atime` itself.
fn candidate_without_observed_access(id: i64, name: &str, age_days: i64) -> Candidate {
    Candidate {
        last_observed_access: None,
        ..candidate(id, name, age_days, 50_000_000)
    }
}

#[test]
fn a_file_that_appeared_after_the_preview_is_not_acted_on() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    let previewed = e.preview(&corpus(), now()).expect("preview");

    // A second old raw lands between the dry run and the run.
    let mut later = corpus();
    later.push(candidate(4, "Photos/older.raw", 500, 50_000_000));

    match e.run(&later, RunMode::Execute, Some(&previewed), now()) {
        Err(EngineRefusal::PreviewDrifted { drift }) => {
            assert_eq!(
                drift.added,
                vec![PreviewedMatch {
                    file: FileId::new(4),
                    signal: AccessSignalSource::Observed,
                }],
                "the operator never saw file 4"
            );
            assert!(
                drift.removed.is_empty() && drift.changed.is_empty(),
                "{drift:?}"
            );
        }
        other => panic!("a file the preview never enumerated must not be acted on, got {other:?}"),
    }
}

#[test]
fn a_previewed_file_that_vanished_refuses_rather_than_quietly_shrinking() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    let previewed = e.preview(&corpus(), now()).expect("preview");

    // The matching file is gone by the time the run happens.
    let later: Vec<Candidate> = corpus()
        .into_iter()
        .filter(|c| c.file != FileId::new(1))
        .collect();

    match e.run(&later, RunMode::Execute, Some(&previewed), now()) {
        Err(EngineRefusal::PreviewDrifted { drift }) => {
            assert_eq!(
                drift.removed,
                vec![PreviewedMatch {
                    file: FileId::new(1),
                    signal: AccessSignalSource::Observed,
                }]
            );
            assert!(
                drift.added.is_empty() && drift.changed.is_empty(),
                "{drift:?}"
            );
        }
        other => panic!("a shrunken set is still not the approved set, got {other:?}"),
    }
}

#[test]
fn a_previewed_file_that_was_touched_since_no_longer_matches_and_is_refused() {
    // The everyday case: the user opened the file after reading the dry run.
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    let previewed = e.preview(&corpus(), now()).expect("preview");

    let mut later = corpus();
    later[0] = candidate(1, "Photos/old.raw", 1, 50_000_000);

    match e.run(&later, RunMode::Execute, Some(&previewed), now()) {
        Err(EngineRefusal::PreviewDrifted { drift }) => {
            assert_eq!(drift.removed.len(), 1);
            assert_eq!(drift.removed[0].file, FileId::new(1));
        }
        other => panic!("a file that stopped matching must not still be acted on, got {other:?}"),
    }
}

/// AC-14 makes the preview state *which signal* drove each match. A match the
/// operator read as Shepherd-observed and that now rests on raw `atime` is not
/// the match they approved, even though the file id is the same.
#[test]
fn a_match_driven_by_a_different_signal_is_not_the_match_that_was_approved() {
    // `older_than_days` is §4.12's fallback-order predicate: observed → atime
    // → mtime. The signal it lands on is a property of the file, not the rule.
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);

    let observed = vec![candidate(1, "Photos/old.raw", 400, 50_000_000)];
    let previewed = e.preview(&observed, now()).expect("preview");
    assert_eq!(
        previewed.matches[0].signal,
        AccessSignalSource::Observed,
        "precondition: the dry run rested on the Shepherd-owned signal"
    );

    // Same file, still matching, but the observed signal is gone.
    let fallen_back = vec![candidate_without_observed_access(1, "Photos/old.raw", 400)];
    match e.run(&fallen_back, RunMode::Execute, Some(&previewed), now()) {
        Err(EngineRefusal::PreviewDrifted { drift }) => {
            assert_eq!(drift.changed.len(), 1, "{drift:?}");
            assert_eq!(
                drift.changed[0].previewed.signal,
                AccessSignalSource::Observed
            );
            assert_eq!(drift.changed[0].current.signal, AccessSignalSource::Atime);
        }
        other => panic!("a match on a different signal is a different match, got {other:?}"),
    }
}

/// The accepting direction. Without this, "refuse every execution" passes every
/// refusal test above and the engine can never act again.
#[test]
fn a_corpus_that_moved_around_the_match_set_still_executes() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);
    let previewed = e.preview(&corpus(), now()).expect("preview");

    // Files added, files removed, order changed — but *the match set* is
    // identical, and the match set is what was approved.
    let later = vec![
        candidate(7, "Docs/new-note.txt", 900, 10),
        candidate(1, "Photos/old.raw", 400, 50_000_000),
        candidate(2, "Photos/new.raw", 5, 50_000_000),
    ];

    let real = e
        .run(&later, RunMode::Execute, Some(&previewed), now())
        .expect("an unchanged match set must still run");
    assert_eq!(real.actions.len(), 1);
    assert_eq!(real.actions[0].file, FileId::new(1));
}

/// The zero-comparison trap, stated as a test: an absent preview must never
/// read as "an empty previewed set, and nothing drifted from it".
#[test]
fn no_preview_at_all_is_distinguishable_from_a_preview_nothing_drifted_from() {
    let b = tiering();
    let e = Engine::new(&b, AtimeMode::Reliable);

    // Nothing matches, so a drift comparison against an absent preview would
    // compare empty with empty and wave the run through.
    match e.run(&[], RunMode::Execute, None, now()) {
        Err(EngineRefusal::NotEnabled { decision }) => {
            assert_eq!(decision.refusals(), [EnableRefusal::NoPreview]);
        }
        other => panic!("an absent preview is not an empty one, got {other:?}"),
    }

    // A preview that really did enumerate nothing is a different answer: it
    // exists, so the run proceeds and plans nothing.
    let barren = [candidate(9, "Docs/a.txt", 5, 10)];
    let previewed = e.preview(&barren, now()).expect("preview");
    assert!(previewed.matches.is_empty(), "precondition");
    let real = e
        .run(&barren, RunMode::Execute, Some(&previewed), now())
        .expect("an empty preview is a preview");
    assert!(real.actions.is_empty());
    assert_eq!(real.considered, 1);
}
