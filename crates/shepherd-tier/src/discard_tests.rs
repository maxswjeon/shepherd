//! Tests for the discard seam.
//!
//! The headline is `the_translation_exists_and_trashing_never_confirms`: it is
//! the mechanism that lets §4.1 rule 2 hold without a `dev_exemptions` entry.
//! If it were missing, `shepherd-rules` would need to reach
//! `shepherd-placeholder` after all.

use super::*;
use crate::breaker::Candidate;
use shepherd_core::{FileId, RootId, TargetId};
use shepherd_placeholder::mock::MockPlaceholderProvider;
use shepherd_rules::delete_policy::{
    ClockProvenance, ClockReading, Deferral, DeferralKind, DeleteAction, DiscardRefusal, RootGates,
};

const HOUR: i64 = 3_600 * 1_000_000_000;
const DAY: i64 = 24 * HOUR;

fn t(days: i64) -> Timestamp {
    Timestamp::from_nanos(days * DAY)
}

fn clock(days: i64) -> ClockReading {
    ClockReading {
        wall: t(days),
        monotonic_nanos: u64::try_from(days * DAY).unwrap(),
        boot_id: "b1".into(),
    }
}

fn ready_episode(now: Timestamp) -> Episode {
    let mut e = Episode::open(RootId::new(1), TargetId::new(1), now);
    e.enumerate(vec![Candidate {
        file: FileId::new(1),
        path: "/root/a.raw".into(),
        blake3: None,
    }]);
    e.confirm("operator", now, HOUR);
    e
}

fn inputs<'a>(
    now: &'a ClockReading,
    deferral: Option<&'a Deferral>,
    confirmation: Option<PermanentDeleteConfirmation>,
) -> DiscardInputs<'a> {
    DiscardInputs {
        file: FileId::new(1),
        target: TargetId::new(1),
        action: DeleteAction::Discard,
        confirmation,
        policy_window_override: Some(14),
        deferral,
        now,
        gates: RootGates {
            root: RootId::new(1),
            resync_required: false,
            available: true,
        },
        // Deliberately WRONG. `evaluate_discard` must overwrite these from the
        // breaker rather than trust them — see the dedicated test below.
        breaker: BreakerState {
            charged: false,
            candidate_set_bound: false,
        },
    }
}

/// **The mechanism that makes the rule-2 answer real.**
#[test]
fn the_translation_exists_and_trashing_never_confirms() {
    // Permanently deleted -> a confirmation, per platform.
    assert_eq!(
        confirmation_from_stub(StubState::PermanentlyDeleted, StubPlatform::WindowsCfApi),
        Some(PermanentDeleteConfirmation::WindowsCfApi)
    );
    assert_eq!(
        confirmation_from_stub(
            StubState::PermanentlyDeleted,
            StubPlatform::MacosFileProvider
        ),
        Some(PermanentDeleteConfirmation::MacosFileProvider)
    );

    // Everything reversible yields nothing.
    for state in [
        StubState::TrashedPending,
        StubState::Restored,
        StubState::Present,
    ] {
        assert_eq!(
            confirmation_from_stub(state, StubPlatform::WindowsCfApi),
            None,
            "{state:?} must NOT confirm a permanent delete"
        );
    }
}

#[test]
fn the_translation_runs_against_the_real_mock_lifecycle() {
    // End to end across the seam: placeholder events -> tier translation ->
    // the fact `shepherd-rules` consumes, with no edge between those crates.
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a.raw");
    m.emit_trashed("/root/a.raw").unwrap();

    let state = m.state_of(std::path::Path::new("/root/a.raw")).unwrap();
    assert_eq!(
        confirmation_from_stub(state, StubPlatform::MacosFileProvider),
        None,
        "a trashed stub must not confirm"
    );

    // The user empties the trash.
    m.emit_deleted("/root/a.raw");
    let state = m.state_of(std::path::Path::new("/root/a.raw")).unwrap();
    assert_eq!(
        confirmation_from_stub(state, StubPlatform::MacosFileProvider),
        Some(PermanentDeleteConfirmation::MacosFileProvider)
    );

    // And an undelete before that would have cancelled it instead.
    let m2 = MockPlaceholderProvider::new();
    m2.emit_created("/root/b.raw");
    m2.emit_trashed("/root/b.raw").unwrap();
    m2.emit_undeleted("/root/b.raw").unwrap();
    let state = m2.state_of(std::path::Path::new("/root/b.raw")).unwrap();
    assert_eq!(
        confirmation_from_stub(state, StubPlatform::WindowsCfApi),
        None
    );
}

#[test]
fn linux_confirmation_comes_from_an_operator_not_from_absence() {
    // §4.10.3: Linux delete-mode has no automatic trigger, because absence is
    // the steady state of every tiered file.
    let c = confirmation_from_operator(t(3));
    assert_eq!(
        c,
        PermanentDeleteConfirmation::OperatorExplicit { at: t(3) }
    );
    // There is no stub state that produces this variant.
    for state in [
        StubState::Present,
        StubState::TrashedPending,
        StubState::Restored,
        StubState::PermanentlyDeleted,
    ] {
        assert_ne!(
            confirmation_from_stub(state, StubPlatform::WindowsCfApi),
            Some(PermanentDeleteConfirmation::OperatorExplicit { at: t(3) })
        );
    }
}

// --- the two gates compose ------------------------------------------------

#[test]
fn both_gates_passing_permits_the_discard() {
    // A composition that never permits would pass every negative test here.
    let now = clock(20);
    let opened = clock(0);
    let d = Deferral::open(
        FileId::new(1),
        TargetId::new(1),
        DeferralKind::Remote,
        14,
        &opened,
        ClockProvenance::NtpSynced,
    );
    let e = ready_episode(t(20));
    assert_eq!(
        evaluate_discard(
            inputs(
                &now,
                Some(&d),
                Some(PermanentDeleteConfirmation::WindowsCfApi)
            ),
            &e,
            &RateWindow::default(),
            &BreakerLimits::default(),
            t(20),
        ),
        Ok(())
    );
}

/// The breaker is the single source of truth for its own booleans.
#[test]
fn caller_supplied_breaker_booleans_are_overwritten_not_trusted() {
    let now = clock(20);
    let opened = clock(0);
    let d = Deferral::open(
        FileId::new(1),
        TargetId::new(1),
        DeferralKind::Remote,
        14,
        &opened,
        ClockProvenance::NtpSynced,
    );
    let e = ready_episode(t(20));

    // `inputs()` supplies charged: false, candidate_set_bound: false. If those
    // were trusted, this would be refused. The breaker says otherwise, and the
    // breaker is what actually knows.
    let i = inputs(
        &now,
        Some(&d),
        Some(PermanentDeleteConfirmation::WindowsCfApi),
    );
    assert!(!i.breaker.charged, "precondition: caller says not charged");
    assert_eq!(
        evaluate_discard(
            i,
            &e,
            &RateWindow::default(),
            &BreakerLimits::default(),
            t(20)
        ),
        Ok(()),
        "the breaker's own verdict must win over a caller's assertion"
    );
}

#[test]
fn an_unconfirmed_episode_blocks_even_when_the_policy_is_satisfied() {
    let now = clock(20);
    let opened = clock(0);
    let d = Deferral::open(
        FileId::new(1),
        TargetId::new(1),
        DeferralKind::Remote,
        14,
        &opened,
        ClockProvenance::NtpSynced,
    );
    // Enumerated but never confirmed.
    let mut e = Episode::open(RootId::new(1), TargetId::new(1), t(20));
    e.enumerate(vec![Candidate {
        file: FileId::new(1),
        path: "/root/a.raw".into(),
        blake3: None,
    }]);

    let refusals = evaluate_discard(
        inputs(
            &now,
            Some(&d),
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &RateWindow::default(),
        &BreakerLimits::default(),
        t(20),
    )
    .expect_err("must refuse");

    assert!(!refusals.breaker.is_empty());
    // And the policy side sees it too, via the derived boolean.
    assert!(
        refusals
            .policy
            .contains(&DiscardRefusal::CandidateSetNotBound),
        "{:?}",
        refusals.policy
    );
}

#[test]
fn a_running_deferral_blocks_even_when_the_breaker_is_happy() {
    let now = clock(3); // only 3 days into a 14-day window
    let opened = clock(0);
    let d = Deferral::open(
        FileId::new(1),
        TargetId::new(1),
        DeferralKind::Remote,
        14,
        &opened,
        ClockProvenance::NtpSynced,
    );
    let e = ready_episode(t(3));

    let refusals = evaluate_discard(
        inputs(
            &now,
            Some(&d),
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &RateWindow::default(),
        &BreakerLimits::default(),
        t(3),
    )
    .expect_err("must refuse");
    assert!(refusals.breaker.is_empty(), "{:?}", refusals.breaker);
    assert!(
        refusals
            .policy
            .iter()
            .any(|r| matches!(r, DiscardRefusal::DeferralStillRunning { .. }))
    );
}

#[test]
fn a_trashed_file_is_refused_end_to_end() {
    // The composed path, from a stub state that is not a permanent delete.
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a.raw");
    m.emit_trashed("/root/a.raw").unwrap();
    let state = m.state_of(std::path::Path::new("/root/a.raw")).unwrap();
    let confirmation = confirmation_from_stub(state, StubPlatform::MacosFileProvider);

    let now = clock(20);
    let opened = clock(0);
    let d = Deferral::open(
        FileId::new(1),
        TargetId::new(1),
        DeferralKind::Remote,
        14,
        &opened,
        ClockProvenance::NtpSynced,
    );
    let e = ready_episode(t(20));

    let refusals = evaluate_discard(
        inputs(&now, Some(&d), confirmation),
        &e,
        &RateWindow::default(),
        &BreakerLimits::default(),
        t(20),
    )
    .expect_err("a trashed file must never be discarded");
    assert!(
        refusals
            .policy
            .contains(&DiscardRefusal::NoPermanentDeleteConfirmation)
    );
}

#[test]
fn a_hold_blocks_destroy_and_nothing_else() {
    assert!(hold_blocks(JobClass::Destroy));
    for class in [
        JobClass::Scan,
        JobClass::Hash,
        JobClass::Extract,
        JobClass::Tag,
        JobClass::Embed,
        JobClass::Upload,
        JobClass::Verify,
        JobClass::Restore,
        JobClass::Replicate,
        JobClass::Scrub,
    ] {
        assert!(
            !hold_blocks(class),
            "{class:?} must keep running under a discard hold"
        );
    }
}
