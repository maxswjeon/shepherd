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
        ino: shepherd_core::InodeSighting::Unknown,
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

/// **The bypass `first_age_field` allowed.** The destructive-atime refusal read
/// only the FIRST age predicate in the tree, so a compound rule whose leading
/// condition is `mtime` walked straight past it — and the trailing `atime`
/// condition was then evaluated under the fallback, silently selecting files by
/// `mtime` for a rule the user wrote in terms of last access. §4.12's rejection
/// is a property of the RULE, so every age predicate in it has to be checked.
#[test]
fn a_trailing_atime_predicate_is_refused_not_only_a_leading_one() {
    for mode in [AtimeMode::Disabled, AtimeMode::Unknown] {
        // Leading `mtime`, trailing `atime` — the shape that walked past it.
        let err = Matcher::compile(
            "sweep",
            &serde_json::json!({
                "all": [
                    { "mtime_older_than_days": 30 },
                    { "atime_older_than_days": 365 },
                ]
            }),
            &tier(),
            mode,
        )
        .unwrap_err();
        assert!(
            matches!(err, MatchError::AtimeUntrustworthy { .. }),
            "{mode:?}: a trailing atime predicate must be refused, got {err}"
        );

        // And buried — under `any`, inside `not`. `older_than_days` is
        // `Accessed`, whose fallback chain ends at the same untrusted atime, so
        // depth and polarity change nothing about the answer.
        let err = Matcher::compile(
            "sweep-nested",
            &serde_json::json!({
                "any": [
                    { "ext": ["tmp"] },
                    { "not": { "all": [
                        { "min_size": 10 },
                        { "older_than_days": 365 },
                    ] } },
                ]
            }),
            &tier(),
            mode,
        )
        .unwrap_err();
        assert!(
            matches!(err, MatchError::AtimeUntrustworthy { .. }),
            "{mode:?}: a nested access predicate must be refused, got {err}"
        );
    }
}

/// The other direction, and the one that stops the fix from degenerating into
/// "refuse every compound destructive rule". `mtime` and `ctime` are read
/// straight off the file and owe nothing to atime fidelity, so a compound rule
/// built only from those compiles on the worst root there is.
#[test]
fn a_compound_rule_with_no_atime_dependence_is_still_permitted() {
    assert!(
        Matcher::compile(
            "old-big-raws",
            &serde_json::json!({
                "all": [
                    { "mtime_older_than_days": 30 },
                    { "ext": ["raw"] },
                    { "not": { "ctime_older_than_days": 3650 } },
                ]
            }),
            &tier(),
            AtimeMode::Disabled,
        )
        .is_ok()
    );
}

/// The traversal widens WHICH predicates are inspected. It must not widen WHICH
/// modes are refused: `relatime` is Linux's default mount option and §4.12
/// permits it, so a compound atime rule stays legal there.
#[test]
fn a_compound_atime_rule_is_still_permitted_under_relatime() {
    for mode in [AtimeMode::Relatime, AtimeMode::Reliable] {
        assert!(
            Matcher::compile(
                "sweep",
                &serde_json::json!({
                    "all": [
                        { "mtime_older_than_days": 30 },
                        { "atime_older_than_days": 365 },
                    ]
                }),
                &tier(),
                mode,
            )
            .is_ok(),
            "{mode:?} must stay permitted"
        );
    }
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

/// A match no timestamp authorized reports NO age signal.
///
/// `any: [{ext}, {age}]` selected by extension, and a `not` around an age
/// predicate, are both matches where nothing about a timestamp is what chose
/// the file. The rule-level fallback was applied to them anyway, so the preview
/// claimed a timestamp had authorized the match — and made `age_signal` depend
/// on a value the match never read, which is how `PreviewDrifted` can fire on a
/// run whose matched set and authorizing branch are both unchanged.
#[test]
fn a_match_that_no_timestamp_authorized_reports_no_signal() {
    let mut f = file("a.raw", 1, 0);
    f.mtime = Timestamp::from_nanos(now().as_nanos() - DAY);
    f.ctime = f.mtime;
    f.atime = Some(f.mtime);

    // Selected by EXTENSION. The age branch is present and false.
    let m = compile(serde_json::json!({
        "any": [
            { "ext": ["raw"] },
            { "mtime_older_than_days": 365 },
        ]
    }));
    let out = m.matches(&f, &ctx(AtimeMode::Relatime, &[]));
    assert!(out.matched, "the extension branch matches");
    assert_eq!(
        out.age_signal, None,
        "no timestamp authorized this match, and naming one is the mislabel the signal \
         contract exists to prevent"
    );
    assert_eq!(m.age_signal_for(&f, &ctx(AtimeMode::Relatime, &[])), None);

    // Selected by NEGATION of an age predicate — equally not a timestamp
    // authorizing anything.
    let m = compile(serde_json::json!({ "not": { "mtime_older_than_days": 365 } }));
    let out = m.matches(&f, &ctx(AtimeMode::Relatime, &[]));
    assert!(out.matched, "the file is one day old, so `not older` holds");
    assert_eq!(out.age_signal, None);

    // And a NON-match still reports the rule-level signal, because `None` there
    // would read as "this rule has no age predicate".
    let m = compile(serde_json::json!({ "mtime_older_than_days": 365 }));
    let out = m.matches(&f, &ctx(AtimeMode::Relatime, &[]));
    assert!(!out.matched);
    assert_eq!(out.age_signal, Some(AccessSignalSource::Mtime));
}

/// In a compound `any`, the branch that actually matched names the signal.
///
/// `age_field` was resolved once at compile time as the *first* age predicate
/// in the tree, which answers "which predicate is written first", not "which
/// one selected this file". For `any: [mtime…, ctime…]` where only the ctime
/// branch is true, the preview said `Mtime` — a timestamp that provably cannot
/// have driven the match, since it is one day old under a 365-day predicate.
///
/// This is the same class as the ctime mislabel below, and the `Ctime` variant
/// added for that one does not reach it: the selection happens before
/// `resolve_signal` is ever asked.
#[test]
fn a_compound_rule_reports_the_branch_that_actually_matched() {
    let mut f = file("a", 1, 0);
    f.mtime = Timestamp::from_nanos(now().as_nanos() - DAY);
    f.ctime = Timestamp::from_nanos(now().as_nanos() - 400 * DAY);
    f.atime = Some(Timestamp::from_nanos(now().as_nanos() - DAY));

    let m = compile(serde_json::json!({
        "any": [
            { "mtime_older_than_days": 365 },
            { "ctime_older_than_days": 365 },
        ]
    }));

    let out = m.matches(&f, &ctx(AtimeMode::Relatime, &[]));
    assert!(out.matched, "the ctime branch is 400 days old");
    assert_eq!(
        out.age_signal,
        Some(AccessSignalSource::Ctime),
        "mtime is one day old and cannot have satisfied a 365-day predicate; \
         the signal named must be the one that did"
    );
    assert_eq!(
        m.age_signal_for(&f, &ctx(AtimeMode::Relatime, &[])),
        Some(AccessSignalSource::Ctime),
        "and the two paths must not disagree"
    );
}

/// A `ctime_older_than_days` predicate reads `file.ctime` — and must SAY so.
///
/// It reported `Mtime`, and that is not a cosmetic slip. `Engine::run` refuses
/// to execute when the signal a match resolves differs from the one the preview
/// recorded, on the argument that a substitution of signals is exactly what the
/// `AtimeMode` apparatus exists to prevent. That refusal is only ever as good as
/// the labels it compares, and this one was a lie: every ctime match ever
/// previewed told the operator an mtime rule had selected the file.
///
/// The fixture makes the mislabel *provably* wrong rather than merely wrong:
/// mtime is one day old, so it cannot satisfy a 365-day predicate. Naming
/// `Mtime` as the driving signal names a timestamp that does not drive it.
#[test]
fn a_ctime_predicate_reports_ctime_as_the_driving_signal() {
    let mut f = file("a", 1, 0);
    f.ctime = Timestamp::from_nanos(now().as_nanos() - 400 * DAY);
    f.mtime = Timestamp::from_nanos(now().as_nanos() - DAY);
    f.atime = Some(Timestamp::from_nanos(now().as_nanos() - DAY));

    let m = compile(serde_json::json!({ "ctime_older_than_days": 365 }));
    let out = m.matches(&f, &ctx(AtimeMode::Relatime, &[]));
    assert!(out.matched, "ctime is 400 days old");
    assert_eq!(
        out.age_signal,
        Some(AccessSignalSource::Ctime),
        "the matcher read ctime; the record must not say mtime"
    );
    // `age_signal_for` is the path `RuleBody::age_signal` takes, and it must
    // not disagree with the one the match report took.
    assert_eq!(
        m.age_signal_for(&f, &ctx(AtimeMode::Relatime, &[])),
        Some(AccessSignalSource::Ctime)
    );

    // The accepting direction, and it is load-bearing: relabelling EVERY
    // predicate `Ctime` would satisfy the assertions above. The other fields
    // must keep naming themselves.
    let mt = compile(serde_json::json!({ "mtime_older_than_days": 1 }));
    assert_eq!(
        mt.matches(&f, &ctx(AtimeMode::Relatime, &[])).age_signal,
        Some(AccessSignalSource::Mtime)
    );
    let at = compile(serde_json::json!({ "atime_older_than_days": 1 }));
    assert_eq!(
        at.matches(&f, &ctx(AtimeMode::Reliable, &[])).age_signal,
        Some(AccessSignalSource::Atime)
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

/// **A combinator must not be a hole in the rule above this one.** `all`, `any`
/// and `not` returned the moment the key was seen, so anything beside them was
/// dropped unread: `max_size` widened away, and — worse — a typo'd
/// `older_thn_days` escaped the unknown-key refusal entirely, which is the very
/// defect that refusal exists to catch.
///
/// Refused rather than folded into a conjunction, because
/// `{"any":[A,B],"max_size":N}` has two honest readings — `(A|B) AND N`, or an
/// `N` the author meant to put INSIDE the list — and picking one for a
/// destructive rule is the guess the empty-list refusal already declines to
/// make. Say so and let the author write what they meant.
#[test]
fn a_combinator_with_sibling_keys_is_refused_rather_than_silently_dropped() {
    for bad in [
        serde_json::json!({ "all": [ { "ext": ["raw"] } ], "max_size": 1000 }),
        serde_json::json!({ "any": [ { "ext": ["raw"] } ], "min_size": 1000 }),
        serde_json::json!({ "not": { "ext": ["tmp"] }, "max_size": 1000 }),
        // The typo the combinator path let through: `older_thn_days` is refused
        // in a flat object, and must not become acceptable beside an `all`.
        serde_json::json!({ "all": [ { "ext": ["raw"] } ], "older_thn_days": 365 }),
        // Two combinators are the same defect wearing a different hat — one of
        // the two was being dropped.
        serde_json::json!({ "all": [ { "ext": ["raw"] } ], "any": [ { "ext": ["cr2"] } ] }),
    ] {
        let err = Matcher::compile("sibling", &bad, &tier(), AtimeMode::Reliable)
            .expect_err(&format!("{bad} must not compile"));
        assert!(
            matches!(err, MatchError::Invalid(_)),
            "{bad}: expected Invalid, got {err}"
        );
    }

    // And it NAMES what it refused. A refusal that says only "invalid" leaves
    // the author to find the dropped key themselves, which is most of the
    // distance back to dropping it silently.
    let err = Matcher::compile(
        "sibling",
        &serde_json::json!({ "all": [ { "ext": ["raw"] } ], "max_size": 1000 }),
        &tier(),
        AtimeMode::Reliable,
    )
    .unwrap_err()
    .to_string();
    assert!(err.contains("max_size") && err.contains("all"), "{err}");

    // The refusal is about the SIBLINGS, not about combinators being suspect: a
    // bare combinator — including one carrying the same predicate INSIDE the
    // list, which is the rewrite the error asks for — still compiles.
    for good in [
        serde_json::json!({ "all": [ { "ext": ["raw"] }, { "max_size": 1000 } ] }),
        serde_json::json!({ "any": [ { "ext": ["raw"] }, { "ext": ["cr2"] } ] }),
        serde_json::json!({ "not": { "ext": ["tmp"] } }),
    ] {
        assert!(
            Matcher::compile("bare", &good, &tier(), AtimeMode::Reliable).is_ok(),
            "{good} must still compile"
        );
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

/// An empty LIST predicate is refused for the same reason an empty predicate
/// object is, and `tags` is the one that matters.
///
/// `{"tags":[]}` compiled to `Predicate::All([])`, and an `all` over no
/// conditions is vacuously TRUE — so the rule matched every candidate in the
/// corpus, with a destructive action attached. `{"ext":[]}` fails the other
/// way, matching nothing; still not something anybody meant to write, and
/// refused at the same place so a future list predicate inherits the guard
/// rather than having to remember it.
#[test]
fn an_empty_list_predicate_is_refused_rather_than_matching_everything() {
    for empty in [
        serde_json::json!({ "tags": [] }),
        serde_json::json!({ "ext": [] }),
        // Nested, because a rule reaches the same hazard through a combinator.
        serde_json::json!({ "any": [{ "tags": [] }] }),
        serde_json::json!({ "all": [{ "ext": ["raw"] }, { "tags": [] }] }),
    ] {
        let err = Matcher::compile("empty-list", &empty, &tier(), AtimeMode::Reliable)
            .expect_err(&format!("{empty} must be refused"));
        assert!(matches!(err, MatchError::Invalid(_)), "{empty} -> {err:?}");
    }

    // The accepting direction, so "refuse every list" cannot pass.
    assert!(
        Matcher::compile(
            "populated",
            &serde_json::json!({ "tags": ["keep"] }),
            &tier(),
            AtimeMode::Reliable
        )
        .is_ok()
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
