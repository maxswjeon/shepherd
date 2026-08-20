//! Tests for AC-14's enablement gate and §4.12's signal-provenance rejection.

use super::*;
use crate::delete_policy::DeleteAction;

fn body() -> RuleBody {
    RuleBody {
        name: "archive old raws".into(),
        match_json: serde_json::json!({ "ext": ["raw", "cr2"], "older_than_days": 365 }),
        action: RuleAction::Tier {
            destinations: vec![TargetId::new(1)],
        },
        age_signal: Some(AccessSignalSource::Observed),
    }
}

fn preview_of(b: &RuleBody) -> PreviewRecord {
    PreviewRecord {
        rule_hash: preview_hash(b),
        previewed_at: Timestamp::from_nanos(1),
        matches: vec![PreviewedMatch {
            file: FileId::new(7),
            signal: Some(AccessSignalSource::Observed),
        }],
    }
}

#[test]
fn a_rule_with_no_preview_cannot_be_enabled() {
    let b = body();
    let d = may_enable(&b, None, AtimeMode::Reliable);
    assert!(!d.is_permitted());
    assert_eq!(d.refusals(), [EnableRefusal::NoPreview]);
}

#[test]
fn a_previewed_rule_can_be_enabled() {
    // A gate that never permits would pass every other test in this file.
    let b = body();
    let p = preview_of(&b);
    assert_eq!(
        may_enable(&b, Some(&p), AtimeMode::Reliable),
        EnableDecision::Permitted
    );
}

#[test]
fn editing_a_rule_after_its_preview_re_blocks_enablement() {
    let b = body();
    let p = preview_of(&b);

    let mut edited = b.clone();
    edited.match_json = serde_json::json!({ "ext": ["raw"], "older_than_days": 30 });

    let d = may_enable(&edited, Some(&p), AtimeMode::Reliable);
    assert!(!d.is_permitted(), "an edited rule must be re-previewed");
    assert!(matches!(d.refusals(), [EnableRefusal::PreviewStale { .. }]));
}

#[test]
fn changing_the_action_or_destinations_also_re_blocks() {
    let b = body();
    let p = preview_of(&b);

    let mut retargeted = b.clone();
    retargeted.action = RuleAction::Tier {
        destinations: vec![TargetId::new(2)],
    };
    assert!(
        !may_enable(&retargeted, Some(&p), AtimeMode::Reliable).is_permitted(),
        "sending the same files somewhere else is a different rule"
    );

    let mut destructive = b.clone();
    destructive.action = RuleAction::Delete(DeleteAction::Discard);
    assert!(
        !may_enable(&destructive, Some(&p), AtimeMode::Reliable).is_permitted(),
        "turning a tiering rule into a discard must not inherit its preview"
    );
}

#[test]
fn the_preview_hash_is_independent_of_json_key_order() {
    // A rule body round-tripped through a database or an IPC hop must hash the
    // same, or every stored preview would spuriously invalidate.
    let mut a = body();
    a.match_json = serde_json::json!({ "alpha": 1, "beta": 2 });
    let mut b = body();
    b.match_json = serde_json::json!({ "beta": 2, "alpha": 1 });
    assert_eq!(preview_hash(&a), preview_hash(&b));
}

#[test]
fn the_hash_does_not_cover_lifecycle_state_only_behaviour() {
    // `RuleBody` has no `enabled` field by construction. If it gained one, the
    // act of enabling would change the hash and invalidate the very preview
    // that authorized it — no rule could ever be enabled. This test documents
    // why the field is absent rather than merely forgotten.
    let json = serde_json::to_value(body()).expect("serialize");
    let obj = json.as_object().expect("object");
    assert!(!obj.contains_key("enabled"), "got {obj:?}");
    assert!(!obj.contains_key("last_preview_at"));
}

// --- §4.12: signal provenance ---------------------------------------------

#[test]
fn a_destructive_atime_rule_is_rejected_on_untrustworthy_roots() {
    let mut b = body();
    b.age_signal = Some(AccessSignalSource::Atime);
    let p = preview_of(&b);

    // §4.12 draws the line at disabled/unknown — NOT at "anything short of
    // reliable".
    for mode in [AtimeMode::Disabled, AtimeMode::Unknown] {
        let d = may_enable(&b, Some(&p), mode);
        assert!(
            !d.is_permitted(),
            "a destructive atime rule must be REJECTED on {mode:?}, not warned about"
        );
        assert_eq!(
            d.refusals(),
            [EnableRefusal::DestructiveRuleOnUntrustedAtime { mode }]
        );
    }

    // Reliable is fine, and so is relatime.
    assert!(may_enable(&b, Some(&p), AtimeMode::Reliable).is_permitted());
}

#[test]
fn relatime_is_permitted_because_it_is_the_linux_default() {
    // Rejecting relatime would refuse destructive age rules on very nearly
    // every Linux root. §4.12 asks for a warning and per-match signal
    // provenance there, not a refusal — and the preview carries that provenance
    // structurally, since `PreviewedMatch::signal` is not optional.
    let mut b = body();
    b.age_signal = Some(AccessSignalSource::Atime);
    let p = preview_of(&b);
    assert!(
        may_enable(&b, Some(&p), AtimeMode::Relatime).is_permitted(),
        "relatime must warn, not block"
    );
    // And this crate must agree with the catalog's own predicate rather than
    // re-deriving one that can drift from it.
    assert!(AtimeMode::Relatime.supports_destructive_age_rule());
}

#[test]
fn unknown_atime_is_treated_exactly_as_disabled() {
    // An undetermined signal is not a permissive one.
    let mut b = body();
    b.age_signal = Some(AccessSignalSource::Atime);
    let p = preview_of(&b);
    assert_eq!(
        may_enable(&b, Some(&p), AtimeMode::Unknown)
            .refusals()
            .len(),
        may_enable(&b, Some(&p), AtimeMode::Disabled)
            .refusals()
            .len()
    );
}

#[test]
fn a_non_destructive_rule_may_rest_on_weak_atime() {
    // The rejection is scoped to destructive rules; an `orphan` policy destroys
    // nothing, so a weak signal is a quality question, not a safety one.
    let mut b = body();
    b.action = RuleAction::Delete(DeleteAction::Orphan);
    b.age_signal = Some(AccessSignalSource::Atime);
    let p = preview_of(&b);
    assert!(may_enable(&b, Some(&p), AtimeMode::Disabled).is_permitted());
}

#[test]
fn a_destructive_rule_on_a_non_atime_signal_is_unaffected() {
    let mut b = body();
    b.age_signal = Some(AccessSignalSource::Observed);
    let p = preview_of(&b);
    assert!(may_enable(&b, Some(&p), AtimeMode::Disabled).is_permitted());

    b.age_signal = None; // no age predicate at all
    let p = preview_of(&b);
    assert!(may_enable(&b, Some(&p), AtimeMode::Unknown).is_permitted());
}

#[test]
fn tiering_counts_as_destructive_because_delete_mode_unlinks_the_original() {
    assert!(
        RuleAction::Tier {
            destinations: vec![TargetId::new(1)]
        }
        .is_destructive(),
        "on a delete-mode root, tiering IS the path to unlinking the original"
    );
    assert!(RuleAction::Delete(DeleteAction::Discard).is_destructive());
    assert!(
        RuleAction::Delete(DeleteAction::Archive {
            destination: TargetId::new(2)
        })
        .is_destructive(),
        "archive's origin-side deletion is a real remote destroy"
    );
    assert!(!RuleAction::Delete(DeleteAction::Orphan).is_destructive());
}

#[test]
fn both_refusals_are_reported_together() {
    let mut b = body();
    b.age_signal = Some(AccessSignalSource::Atime);
    // No preview AND an untrustworthy signal.
    let d = may_enable(&b, None, AtimeMode::Disabled);
    assert_eq!(d.refusals().len(), 2, "{:?}", d.refusals());
    assert!(d.refusals().contains(&EnableRefusal::NoPreview));
}

#[test]
fn a_preview_records_the_signal_that_drove_every_match() {
    // Structural rather than checked: `PreviewedMatch::signal` is mandatory,
    // so a preview that omits provenance cannot be constructed.
    let p = preview_of(&body());
    assert!(!p.matches.is_empty());
    for m in &p.matches {
        // The FIELD is mandatory; its value may be `None`, which is the
        // statement "no timestamp drove this match" rather than an omission.
        let _: Option<AccessSignalSource> = m.signal;
    }
}
