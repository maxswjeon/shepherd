//! Tests for the discard predicate and the deferral clock.
//!
//! The headline test is `a_nonzero_window_does_not_behave_like_zero`: that is
//! the iteration-3 defect, where the predicate used OR and every window length
//! was behaviourally identical. It is a test that would have failed against the
//! plan text as written, which is the only kind worth having here.

use super::*;

const DAY: i64 = 86_400 * 1_000_000_000;

fn boot(id: &str, wall_days: i64, mono_days: i64) -> ClockReading {
    ClockReading {
        wall: Timestamp::from_nanos(wall_days * DAY),
        monotonic_nanos: u64::try_from(mono_days * DAY).unwrap(),
        boot_id: id.into(),
    }
}

fn deferral_at(now: &ClockReading, days: u32) -> Deferral {
    Deferral::open(
        FileId::new(1),
        TargetId::new(1),
        DeferralKind::Remote,
        days,
        now,
        ClockProvenance::NtpSynced,
    )
}

fn inputs<'a>(
    now: &'a ClockReading,
    deferral: Option<&'a Deferral>,
    window: Option<u32>,
) -> DiscardInputs<'a> {
    DiscardInputs {
        file: FileId::new(1),
        target: TargetId::new(1),
        action: DeleteAction::Discard,
        confirmation: Some(PermanentDeleteConfirmation::WindowsCfApi),
        policy_window_override: window,
        deferral,
        now,
        gates: RootGates {
            root: RootId::new(1),
            resync_required: false,
            available: true,
        },
        breaker: BreakerState {
            charged: true,
            candidate_set_bound: true,
        },
    }
}

/// **The iteration-3 defect.** With `OR`, provider confirmation alone would
/// permit the discard and every nonzero window would behave like zero.
#[test]
fn a_nonzero_window_does_not_behave_like_zero() {
    let start = boot("b1", 0, 0);
    let d = deferral_at(&start, 14);

    // Provider confirmation IS present — under the OR formulation this would
    // already be permitted on day one.
    let day_one = boot("b1", 1, 1);
    let decision = discard_permitted(&inputs(&day_one, Some(&d), Some(14)));
    assert!(
        !decision.is_permitted(),
        "confirmation alone must not satisfy the predicate — that is the OR bug"
    );
    assert!(matches!(
        decision.refusals(),
        [DiscardRefusal::DeferralStillRunning { .. }]
    ));

    // Day 15: the window really has elapsed.
    let day_fifteen = boot("b1", 15, 15);
    assert!(discard_permitted(&inputs(&day_fifteen, Some(&d), Some(14))).is_permitted());
}

#[test]
fn different_window_lengths_are_behaviourally_different() {
    // The property the user's 7-vs-14-vs-30 choice depends on.
    let start = boot("b1", 0, 0);
    let short = deferral_at(&start, 7);
    let long = deferral_at(&start, 30);
    let day_ten = boot("b1", 10, 10);

    assert!(discard_permitted(&inputs(&day_ten, Some(&short), Some(7))).is_permitted());
    assert!(!discard_permitted(&inputs(&day_ten, Some(&long), Some(30))).is_permitted());
}

#[test]
fn the_default_window_is_fourteen_days() {
    assert_eq!(DEFAULT_DEFERRAL_WINDOW_DAYS, 14);
    // NULL in the policy row inherits the default (OQ-H).
    assert_eq!(effective_window_days(None), 14);
    assert_eq!(effective_window_days(Some(30)), 30);
    assert_eq!(effective_window_days(Some(0)), 0);
}

#[test]
fn a_zero_window_permits_immediately_but_still_honours_a_cancellation() {
    let start = boot("b1", 0, 0);
    let now = boot("b1", 0, 0);
    assert!(discard_permitted(&inputs(&now, None, Some(0))).is_permitted());

    let mut cancelled = deferral_at(&start, 0);
    cancelled.cancelled_at = Some(Timestamp::from_nanos(1));
    let decision = discard_permitted(&inputs(&now, Some(&cancelled), Some(0)));
    assert!(
        !decision.is_permitted(),
        "a zero window must still not destroy something the user undeleted"
    );
    assert_eq!(decision.refusals(), [DiscardRefusal::DeferralCancelled]);
}

#[test]
fn a_configured_window_with_no_deferral_record_fails_closed() {
    // A missing record is not an elapsed one.
    let now = boot("b1", 100, 100);
    let decision = discard_permitted(&inputs(&now, None, Some(14)));
    assert!(!decision.is_permitted());
    assert_eq!(
        decision.refusals(),
        [DiscardRefusal::WindowConfiguredButNoDeferral { window_days: 14 }]
    );
}

#[test]
fn an_undelete_before_expiry_cancels_and_destroys_nothing() {
    let start = boot("b1", 0, 0);
    let mut d = deferral_at(&start, 14);
    d.cancelled_at = Some(Timestamp::from_nanos(3 * DAY));
    let long_after = boot("b1", 99, 99);
    assert_eq!(d.status(&long_after), DeferralStatus::Cancelled);
    assert!(!discard_permitted(&inputs(&long_after, Some(&d), Some(14))).is_permitted());
}

#[test]
fn within_one_boot_the_monotonic_deadline_governs_and_ignores_wall_clock_jumps() {
    let start = boot("b1", 0, 0);
    let d = deferral_at(&start, 14);

    // An NTP step jumps the wall clock a year forward; monotonic says 1 day.
    let jumped = ClockReading {
        wall: Timestamp::from_nanos(365 * DAY),
        monotonic_nanos: u64::try_from(DAY).unwrap(),
        boot_id: "b1".into(),
    };
    assert!(
        matches!(d.status(&jumped), DeferralStatus::Pending { .. }),
        "a wall-clock jump must not expire a window inside one boot"
    );
}

#[test]
fn across_a_reboot_the_wall_clock_governs_because_monotonic_is_meaningless() {
    let start = boot("b1", 0, 0);
    let d = deferral_at(&start, 14);

    // New boot: monotonic restarts near zero, but 20 wall-clock days passed.
    let after_reboot = boot("b2", 20, 0);
    assert_eq!(
        d.status(&after_reboot),
        DeferralStatus::Expired,
        "a monotonic instant does not survive a reboot; the wall clock must govern"
    );

    // And a reboot before the window elapsed must NOT expire it.
    let early_reboot = boot("b2", 3, 0);
    assert!(matches!(
        d.status(&early_reboot),
        DeferralStatus::Pending { .. }
    ));
}

#[test]
fn a_backwards_wall_clock_holds_the_window_and_never_shortens_it() {
    let start = boot("b1", 100, 100);
    let d = deferral_at(&start, 14);

    // Reboot, and the clock came back wrong — earlier than when we deferred.
    let backwards = boot("b2", 90, 0);
    match d.status(&backwards) {
        DeferralStatus::HeldClockWentBackwards { by_nanos } => {
            assert_eq!(by_nanos, 10 * DAY);
        }
        other => panic!("expected a hold, got {other:?}"),
    }

    let decision = discard_permitted(&inputs(&backwards, Some(&d), Some(14)));
    assert!(!decision.is_permitted());
    assert!(matches!(
        decision.refusals(),
        [DiscardRefusal::ClockWentBackwards { .. }]
    ));
}

#[test]
fn trashing_is_not_a_permanent_delete() {
    // The whole reason `PermanentDeleteConfirmation` exists. A confirmation is
    // constructed only from a genuinely permanent signal; absence of one is a
    // refusal, and there is no variant meaning "trashed".
    let now = boot("b1", 99, 99);
    let start = boot("b1", 0, 0);
    let d = deferral_at(&start, 14);

    let mut i = inputs(&now, Some(&d), Some(14));
    i.confirmation = None; // trashed, not deleted
    let decision = discard_permitted(&i);
    assert!(!decision.is_permitted());
    assert_eq!(
        decision.refusals(),
        [DiscardRefusal::NoPermanentDeleteConfirmation]
    );
}

#[test]
fn only_discard_is_sole_copy_destruction() {
    assert!(DeleteAction::Discard.is_sole_copy_destruction());
    // Archive deletes from the origin only AFTER a verified copy exists.
    assert!(
        !DeleteAction::Archive {
            destination: TargetId::new(2)
        }
        .is_sole_copy_destruction()
    );
    assert!(!DeleteAction::Orphan.is_sole_copy_destruction());
}

#[test]
fn a_non_discard_action_never_returns_permitted() {
    let now = boot("b1", 99, 99);
    for action in [
        DeleteAction::Archive {
            destination: TargetId::new(2),
        },
        DeleteAction::Orphan,
    ] {
        let mut i = inputs(&now, None, Some(0));
        i.action = action.clone();
        let decision = discard_permitted(&i);
        assert!(
            !decision.is_permitted(),
            "{action:?} must not be permitted by the DISCARD predicate"
        );
        assert!(decision.refusals().contains(&DiscardRefusal::NotADiscard));
    }
}

#[test]
fn pm3_root_gates_block_every_destructive_decision() {
    let now = boot("b1", 99, 99);

    let mut resync = inputs(&now, None, Some(0));
    resync.gates.resync_required = true;
    assert!(
        resync
            .clone()
            .pipe_refusals()
            .contains(&DiscardRefusal::ResyncRequired)
    );

    let mut unavailable = inputs(&now, None, Some(0));
    unavailable.gates.available = false;
    assert!(
        unavailable
            .pipe_refusals()
            .contains(&DiscardRefusal::RootUnavailable)
    );
}

#[test]
fn the_breaker_and_the_candidate_set_binding_are_both_required() {
    let now = boot("b1", 99, 99);

    let mut open = inputs(&now, None, Some(0));
    open.breaker.charged = false;
    assert!(open.pipe_refusals().contains(&DiscardRefusal::BreakerOpen));

    let mut unbound = inputs(&now, None, Some(0));
    unbound.breaker.candidate_set_bound = false;
    assert!(
        unbound
            .pipe_refusals()
            .contains(&DiscardRefusal::CandidateSetNotBound)
    );
}

#[test]
fn every_failing_conjunct_is_reported_not_just_the_first() {
    // A held discard is operator-facing; "blocked by one of six things" is not
    // actionable, so the predicate must not short-circuit.
    let now = boot("b1", 99, 99);
    let mut i = inputs(&now, None, Some(14));
    i.confirmation = None;
    i.gates.resync_required = true;
    i.gates.available = false;
    i.breaker.charged = false;
    i.breaker.candidate_set_bound = false;

    let decision = discard_permitted(&i);
    let r = decision.refusals();
    assert_eq!(r.len(), 6, "expected all six, got {r:?}");
    for want in [
        DiscardRefusal::NoPermanentDeleteConfirmation,
        DiscardRefusal::WindowConfiguredButNoDeferral { window_days: 14 },
        DiscardRefusal::ResyncRequired,
        DiscardRefusal::RootUnavailable,
        DiscardRefusal::BreakerOpen,
        DiscardRefusal::CandidateSetNotBound,
    ] {
        assert!(r.contains(&want), "missing {want:?} in {r:?}");
    }
}

#[test]
fn the_happy_path_really_can_be_permitted() {
    // A predicate that can never return true would pass every test above.
    let start = boot("b1", 0, 0);
    let d = deferral_at(&start, 14);
    let after = boot("b1", 15, 15);
    assert_eq!(
        discard_permitted(&inputs(&after, Some(&d), Some(14))),
        DiscardDecision::Permitted
    );
}

/// Small helper so the gate tests read as one line each.
impl DiscardInputs<'_> {
    fn pipe_refusals(self) -> Vec<DiscardRefusal> {
        discard_permitted(&self).refusals().to_vec()
    }
}
