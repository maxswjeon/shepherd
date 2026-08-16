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
