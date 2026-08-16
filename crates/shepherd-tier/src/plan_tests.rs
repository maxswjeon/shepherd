//! Plan tests. The one that matters is that keys are content-addressed, never
//! path-derived — §4.9's collision is silent and permanent.

use super::*;

fn h(seed: u8) -> Blake3Hash {
    Blake3Hash::from_bytes([seed; 32])
}

fn sel(id: i64, path: &str, hash: Option<u8>) -> SelectedFile {
    SelectedFile {
        file: FileId::new(id),
        path: path.into(),
        size: 1024,
        blake3: hash.map(h),
    }
}

/// §4.9's scenario, as a test.
#[test]
fn two_paths_differing_only_in_case_do_not_collide_because_keys_are_content_addressed() {
    // ext4 holds these as two files; SMB and OneDrive fold them to one name.
    // A path-derived key would give both the same object — the second upload
    // silently overwrites the first, whose local original may already be gone.
    let plan = plan_tier(
        &[
            sel(1, "/root/Report.txt", Some(1)),
            sel(2, "/root/report.txt", Some(2)),
        ],
        &[TargetId::new(1)],
        "shepherd",
    );
    assert_eq!(plan.items.len(), 2);
    assert_ne!(
        plan.items[0].remote_key, plan.items[1].remote_key,
        "different content must never share a key"
    );
    assert_eq!(plan.distinct_objects(), 2);
}

#[test]
fn identical_content_shares_one_object_which_is_ac47_dedup_not_a_bug() {
    let plan = plan_tier(
        &[
            sel(1, "/root/a.raw", Some(7)),
            sel(2, "/root/copies/a.raw", Some(7)),
        ],
        &[TargetId::new(1)],
        "shepherd",
    );
    assert_eq!(plan.items.len(), 2, "both files are still tracked");
    assert_eq!(
        plan.items[0].remote_key, plan.items[1].remote_key,
        "identical content legitimately shares one object"
    );
    assert_eq!(
        plan.distinct_objects(),
        1,
        "so bytes-to-transfer must count objects, not files"
    );
}

#[test]
fn the_key_is_content_addressed_and_fanned_out() {
    let k = derive_object_key("shepherd", h(0xab));
    let hex = h(0xab).to_hex();
    assert_eq!(
        k.as_str(),
        format!("shepherd/objects/{}/{}/{}", &hex[0..2], &hex[2..4], hex)
    );
    // The path never appears in it.
    assert!(!k.as_str().contains("Report"));
}

#[test]
fn a_key_derived_without_a_prefix_is_still_well_formed() {
    let k = derive_object_key("", h(3));
    assert!(k.as_str().starts_with("objects/"));
    // A trailing slash on the prefix must not double up.
    assert_eq!(
        derive_object_key("shepherd/", h(3)).as_str(),
        derive_object_key("shepherd", h(3)).as_str()
    );
}

#[test]
fn an_unhashed_file_is_refused_with_a_reason_not_silently_dropped() {
    // Phase 1 makes hashing its own job class, so this is an ordinary state —
    // but a file missing from a plan must be distinguishable from a file the
    // rule never matched.
    let plan = plan_tier(&[sel(1, "/root/a.raw", None)], &[TargetId::new(1)], "p");
    assert!(plan.items.is_empty());
    assert_eq!(
        plan.refused,
        [PlanRefusal::Unhashed {
            file: FileId::new(1)
        }]
    );
}

#[test]
fn a_rule_with_no_destinations_is_refused_rather_than_read_as_nowhere() {
    let plan = plan_tier(&[sel(1, "/root/a.raw", Some(1))], &[], "p");
    assert!(plan.items.is_empty());
    assert_eq!(
        plan.refused,
        [PlanRefusal::NoDestination {
            file: FileId::new(1)
        }]
    );
}

/// §4.10.2: a rule asking for two targets does not get to destroy the original
/// because one succeeded.
#[test]
fn a_rule_with_two_destinations_plans_two_uploads() {
    let plan = plan_tier(
        &[sel(1, "/root/a.raw", Some(1))],
        &[TargetId::new(1), TargetId::new(2)],
        "p",
    );
    assert_eq!(plan.items.len(), 2);
    assert_eq!(plan.items[0].target, TargetId::new(1));
    assert_eq!(plan.items[1].target, TargetId::new(2));
    // Same content, so the same key on both targets.
    assert_eq!(plan.items[0].remote_key, plan.items[1].remote_key);
}

#[test]
fn an_empty_selection_plans_nothing_and_refuses_nothing() {
    let plan = plan_tier(&[], &[TargetId::new(1)], "p");
    assert_eq!(plan, TierPlan::default());
    assert_eq!(plan.distinct_objects(), 0);
}
