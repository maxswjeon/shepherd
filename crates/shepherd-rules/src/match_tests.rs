//! AC-13 over all seven predicate kinds, plus §4.12's fidelity rejection.

use super::*;
use shepherd_core::RootId;

const DAY: i64 = 86_400_000_000_000;

fn now() -> Timestamp {
    Timestamp::from_nanos(1_000 * DAY)
}

fn file(rel: &str, size: u64, age_days: i64) -> FileStat {
    let t = Timestamp::from_nanos(now().as_nanos() - age_days * DAY);
    FileStat {
        root: RootId::new(1),
        rel_path: rel.into(),
        size,
        mtime: t,
        ctime: t,
        atime: Some(t),
        blake3: None,
    }
}

fn ctx<'a>(mode: AtimeMode, tags: &'a [String]) -> MatchContext<'a> {
    MatchContext {
        now: now(),
        atime_mode: mode,
        last_observed_access: None,
        tags,
    }
}

fn tier() -> RuleAction {
    RuleAction::Tier {
        destinations: vec![],
    }
}

fn compile(json: serde_json::Value) -> Matcher {
    Matcher::compile("t", &json, &tier(), AtimeMode::Relatime).expect("compiles")
}

fn hit(m: &Matcher, f: &FileStat) -> bool {
    m.matches(f, &ctx(AtimeMode::Relatime, &[])).matched
}

// --- AC-13's seven predicate kinds ------------------------------------------

#[test]
fn extension_matches_case_insensitively_and_ignores_dotfiles() {
    let m = compile(serde_json::json!({ "ext": ["raw", ".CR2"] }));
    assert!(hit(&m, &file("a/photo.raw", 1, 0)));
    assert!(hit(&m, &file("a/PHOTO.RAW", 1, 0)));
    assert!(hit(&m, &file("a/b.cr2", 1, 0)));
    assert!(!hit(&m, &file("a/notes.txt", 1, 0)));
    // A dotfile has no extension, so `ext` cannot match it. Same rule the
    // scanner applies — two different answers would be worse than either.
    assert!(!hit(&m, &file("a/.raw", 1, 0)));
}

#[test]
fn path_glob_matches_and_does_not_over_match() {
    let m = compile(serde_json::json!({ "path_glob": "Photos/**/*.raw" }));
    assert!(hit(&m, &file("Photos/2024/a.raw", 1, 0)));
    assert!(hit(&m, &file("Photos/2024/06/b.raw", 1, 0)));
    assert!(!hit(&m, &file("Docs/2024/a.raw", 1, 0)));
    // Separators are unified, so a Windows-authored path matches the same rule.
    assert!(hit(&m, &file("Photos\\2024\\c.raw", 1, 0)));
}

/// The direction of failure that matters: a glob must not select files the user
/// did not name, because `Tier` is destructive on a delete-mode root.
#[test]
fn a_single_star_does_not_cross_directory_separators() {
    let m = compile(serde_json::json!({ "path_glob": "Photos/*.raw" }));
    assert!(hit(&m, &file("Photos/a.raw", 1, 0)));
    assert!(
        !hit(&m, &file("Photos/2024/a.raw", 1, 0)),
        "`*` must not cross `/` — over-matching here selects files nobody named"
    );
}

#[test]
fn size_bounds_are_inclusive_and_combine() {
    let m = compile(serde_json::json!({ "min_size": 1000, "max_size": 2000 }));
    assert!(!hit(&m, &file("a", 999, 0)));
    assert!(hit(&m, &file("a", 1000, 0)));
    assert!(hit(&m, &file("a", 2000, 0)));
    assert!(!hit(&m, &file("a", 2001, 0)));
}

#[test]
fn mtime_ctime_and_atime_age_predicates_each_read_their_own_field() {
    let mut f = file("a", 1, 0);
    f.mtime = Timestamp::from_nanos(now().as_nanos() - 400 * DAY);
    f.ctime = Timestamp::from_nanos(now().as_nanos() - 10 * DAY);
    f.atime = Some(Timestamp::from_nanos(now().as_nanos() - 200 * DAY));

    assert!(hit(
        &compile(serde_json::json!({"mtime_older_than_days": 365})),
        &f
    ));
    assert!(!hit(
        &compile(serde_json::json!({"ctime_older_than_days": 365})),
        &f
    ));

    // atime is only read where fidelity permits; under Relatime it falls back
    // to mtime, which here is older still — so the match is on mtime.
    let m = compile(serde_json::json!({"atime_older_than_days": 365}));
    let out = m.matches(&f, &ctx(AtimeMode::Relatime, &[]));
    assert!(out.matched);
    assert_eq!(out.age_signal, Some(AccessSignalSource::Mtime));
}

#[test]
fn tag_and_tags_predicates() {
    let tags = vec!["invoice".to_string(), "2024".to_string()];
    let m = compile(serde_json::json!({ "tag": "invoice" }));
    assert!(
        m.matches(&file("a", 1, 0), &ctx(AtimeMode::Relatime, &tags))
            .matched
    );
    assert!(
        !m.matches(&file("a", 1, 0), &ctx(AtimeMode::Relatime, &[]))
            .matched
    );

    // `tags` is an AND — every named tag must be present.
    let m = compile(serde_json::json!({ "tags": ["invoice", "2024"] }));
    assert!(
        m.matches(&file("a", 1, 0), &ctx(AtimeMode::Relatime, &tags))
            .matched
    );
    let one = vec!["invoice".to_string()];
    assert!(
        !m.matches(&file("a", 1, 0), &ctx(AtimeMode::Relatime, &one))
            .matched
    );
}

#[test]
fn a_flat_object_is_an_and_of_its_keys() {
    let m = compile(serde_json::json!({ "ext": ["raw"], "min_size": 1000 }));
    assert!(hit(&m, &file("a.raw", 2000, 0)));
    assert!(!hit(&m, &file("a.raw", 10, 0)), "size fails");
    assert!(!hit(&m, &file("a.txt", 2000, 0)), "ext fails");
}

#[test]
fn any_all_and_not_combine() {
    let m = compile(serde_json::json!({
        "any": [{ "ext": ["raw"] }, { "ext": ["cr2"] }]
    }));
    assert!(hit(&m, &file("a.raw", 1, 0)));
    assert!(hit(&m, &file("a.cr2", 1, 0)));
    assert!(!hit(&m, &file("a.txt", 1, 0)));

    let m = compile(serde_json::json!({ "not": { "ext": ["tmp"] } }));
    assert!(hit(&m, &file("a.raw", 1, 0)));
    assert!(!hit(&m, &file("a.tmp", 1, 0)));
}

// --- §4.12: the part that is safety work ------------------------------------

/// §4.12 rule 4. A destructive rule resting on `atime` where fidelity is
/// `disabled` is **rejected**, not warned about.
#[test]
fn a_destructive_atime_rule_is_rejected_on_a_disabled_root() {
    for mode in [AtimeMode::Disabled, AtimeMode::Unknown] {
        let err = Matcher::compile(
            "archive-old",
            &serde_json::json!({ "older_than_days": 365 }),
            &tier(),
            mode,
        )
        .unwrap_err();
        assert!(
            matches!(err, MatchError::AtimeUntrustworthy { .. }),
            "{mode:?} must be refused: {err}"
        );
    }
}

/// **The regression that matters most.** `relatime` is Linux's DEFAULT mount
/// option. Rejecting it would refuse destructive age rules on very nearly every
/// Linux root — the platform M2 ships on. §4.12 draws the line at
/// disabled/unknown, and this calls `supports_destructive_age_rule()` rather
/// than re-deriving it precisely so the two sides cannot drift.
#[test]
fn relatime_and_reliable_are_permitted_because_relatime_is_the_linux_default() {
    for mode in [AtimeMode::Relatime, AtimeMode::Reliable] {
        assert!(
            Matcher::compile(
                "archive-old",
                &serde_json::json!({ "older_than_days": 365 }),
                &tier(),
                mode,
            )
            .is_ok(),
            "{mode:?} must be permitted"
        );
    }
}

/// A NON-destructive rule is not subject to the rejection — only `Orphan`
/// destroys nothing, and §4.12's rule is about destruction.
#[test]
fn a_non_destructive_rule_may_rest_on_untrustworthy_atime() {
    let orphan = RuleAction::Delete(crate::delete_policy::DeleteAction::Orphan);
    assert!(!orphan.is_destructive());
    assert!(
        Matcher::compile(
            "just-unbind",
            &serde_json::json!({ "older_than_days": 365 }),
            &orphan,
            AtimeMode::Disabled,
        )
        .is_ok()
    );
}

/// A rule with NO age predicate is unaffected by fidelity, however bad it is.
#[test]
fn a_rule_without_an_age_predicate_is_unaffected_by_atime_fidelity() {
    assert!(
        Matcher::compile(
            "big-raws",
            &serde_json::json!({ "ext": ["raw"], "min_size": 100 }),
            &tier(),
            AtimeMode::Disabled,
        )
        .is_ok()
    );
}

/// §4.12's fallback order, and the provenance the preview must state.
#[test]
fn the_age_signal_follows_the_documented_fallback_order() {
    let f = file("a", 1, 400);
    let m = compile(serde_json::json!({ "older_than_days": 365 }));

    // 1. Shepherd's own observed access wins wherever it exists.
    let mut c = ctx(AtimeMode::Reliable, &[]);
    c.last_observed_access = Some(Timestamp::from_nanos(now().as_nanos() - 500 * DAY));
    assert_eq!(
        m.matches(&f, &c).age_signal,
        Some(AccessSignalSource::Observed)
    );

    // 2. Then OS atime, but ONLY where fidelity is reliable.
    let c = ctx(AtimeMode::Reliable, &[]);
    assert_eq!(
        m.matches(&f, &c).age_signal,
        Some(AccessSignalSource::Atime)
    );

    // 3. Otherwise mtime — including under relatime, which is permitted for
    //    destructive rules but is not a trustworthy access signal.
    let c = ctx(AtimeMode::Relatime, &[]);
    assert_eq!(
        m.matches(&f, &c).age_signal,
        Some(AccessSignalSource::Mtime)
    );
}

#[test]
fn a_rule_with_no_age_predicate_reports_no_signal() {
    let m = compile(serde_json::json!({ "ext": ["raw"] }));
    assert_eq!(
        m.matches(&file("a.raw", 1, 0), &ctx(AtimeMode::Reliable, &[]))
            .age_signal,
        None
    );
}

/// A timestamp in the future has a negative age and must not read as ancient.
/// §4.12's `first_seen_at` is the real remedy; refusing to match is the
/// fail-safe direction here.
#[test]
fn a_future_timestamp_does_not_match_an_older_than_predicate() {
    let mut f = file("a", 1, 0);
    let ahead = Timestamp::from_nanos(now().as_nanos() + 10 * DAY);
    f.mtime = ahead;
    f.ctime = ahead;
    f.atime = Some(ahead);
    let m = compile(serde_json::json!({ "mtime_older_than_days": 1 }));
    assert!(!hit(&m, &f));
}

// --- refusing rather than ignoring ------------------------------------------

/// **A typo must not widen the rule.** `older_thn_days` silently dropped would
/// turn "old raw files" into "every raw file ever", and the action may destroy.
#[test]
fn an_unknown_predicate_key_is_refused_not_ignored() {
    let err = Matcher::compile(
        "typo",
        &serde_json::json!({ "ext": ["raw"], "older_thn_days": 365 }),
        &tier(),
        AtimeMode::Reliable,
    )
    .unwrap_err();
    match err {
        MatchError::Invalid(m) => assert!(m.contains("older_thn_days"), "{m}"),
        other => panic!("expected Invalid, got {other}"),
    }
}

#[test]
fn an_empty_predicate_is_refused_because_it_would_match_everything() {
    assert!(
        Matcher::compile(
            "empty",
            &serde_json::json!({}),
            &tier(),
            AtimeMode::Reliable
        )
        .is_err()
    );
    assert!(
        Matcher::compile(
            "empty-any",
            &serde_json::json!({ "any": [] }),
            &tier(),
            AtimeMode::Reliable
        )
        .is_err()
    );
}

#[test]
fn an_invalid_glob_is_reported_rather_than_matching_nothing() {
    let err = Matcher::compile(
        "bad",
        &serde_json::json!({ "path_glob": "a/[" }),
        &tier(),
        AtimeMode::Reliable,
    )
    .unwrap_err();
    assert!(matches!(err, MatchError::Glob { .. }), "{err}");
}

#[test]
fn wrong_types_are_refused() {
    for bad in [
        serde_json::json!({ "min_size": "big" }),
        serde_json::json!({ "ext": "raw" }),
        serde_json::json!({ "older_than_days": -5 }),
        serde_json::json!("not-an-object"),
    ] {
        assert!(
            Matcher::compile("x", &bad, &tier(), AtimeMode::Reliable).is_err(),
            "{bad} should not compile"
        );
    }
}
