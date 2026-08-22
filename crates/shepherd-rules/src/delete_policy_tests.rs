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
        provenance: ClockProvenance::NtpSynced,
    }
}

fn deferral_at(now: &ClockReading, days: u32) -> Deferral {
    Deferral::open(
        FileId::new(1),
        TargetId::new(1),
        DeferralKind::Remote,
        days,
        now,
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
        confirmation: Some(PermanentDeleteConfirmation {
            file: FileId::new(1),
            source: ConfirmationSource::WindowsCfApi,
        }),
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

/// A cross-boot window may only be ended by a clock somebody can vouch for.
///
/// Across a reboot the monotonic reading is meaningless and the wall clock is
/// the only judge, so an RTC that comes up AHEAD of real time reports the
/// deadline passed the instant the daemon starts — and on the `discard` path
/// that is an irreversible deletion of the last copy inside a window the user
/// still had. The backwards-jump check cannot see it: a clock wrongly ahead
/// looks exactly like time having passed.
#[test]
fn a_cross_boot_window_holds_until_the_wall_clock_is_trustworthy() {
    let start = boot("b1", 0, 0);
    let d = deferral_at(&start, 14);

    // Rebooted, and the RTC came up a year ahead of the deferral with nothing
    // having synchronised it yet.
    let mut untrusted = boot("b2", 365, 0);
    untrusted.provenance = ClockProvenance::Local;
    assert_eq!(
        d.status(&untrusted),
        DeferralStatus::HeldClockUntrusted {
            stored: ClockProvenance::NtpSynced,
            current: ClockProvenance::Local,
        },
        "an unsynchronised RTC that reads a year ahead must not end the window"
    );

    // `Unknown` is nobody having asked, which is not better than `Local`.
    let mut never_asked = boot("b2", 365, 0);
    never_asked.provenance = ClockProvenance::Unknown;
    assert!(!d.status(&never_asked).is_expired());

    // THE ACCEPTING DIRECTION. Once the clock is synchronised the same reading
    // expires it — without this, "hold forever" would pass.
    let trusted = boot("b2", 365, 0);
    assert_eq!(trusted.provenance, ClockProvenance::NtpSynced);
    assert_eq!(d.status(&trusted), DeferralStatus::Expired);

    // And a trusted clock still inside the window is Pending, not held: the
    // refusal must be about trust, not about refusing everything cross-boot.
    assert!(matches!(
        d.status(&boot("b2", 7, 0)),
        DeferralStatus::Pending { .. }
    ));
}

/// The deadline is only as good as the clock that WROTE it, so an untrusted
/// reading at creation holds too.
///
/// A `deferred_at` recorded by a slow clock makes `wall_clock_deadline` too
/// early, and the window is shortened by exactly that error. It is the same
/// hazard as the current reading, pointed the other way.
#[test]
fn a_window_opened_on_an_untrusted_clock_also_holds() {
    let mut opened = boot("b1", 0, 0);
    opened.provenance = ClockProvenance::Local;
    let d = deferral_at(&opened, 14);
    assert_eq!(d.clock_provenance, ClockProvenance::Local);

    assert_eq!(
        d.status(&boot("b2", 365, 0)),
        DeferralStatus::HeldClockUntrusted {
            stored: ClockProvenance::Local,
            current: ClockProvenance::NtpSynced,
        }
    );

    // Within the SAME boot none of this applies: the monotonic deadline is
    // authoritative and owes nothing to the wall clock's provenance.
    assert_eq!(d.status(&boot("b1", 0, 20)), DeferralStatus::Expired);
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
        provenance: ClockProvenance::NtpSynced,
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

// --- a deferral authorizes its OWN destruction and no other ----------------
//
// The same shape as the destroy-lock defect: two sides of a guard disagreeing
// about what identity means. An elapsed window is only evidence about the file,
// target and side of the system it was opened for. A lookup that returns the
// wrong row must not be able to spend one file's elapsed window on another.

fn deferral_keyed(
    file: i64,
    target: i64,
    kind: DeferralKind,
    now: &ClockReading,
    days: u32,
) -> Deferral {
    Deferral::open(FileId::new(file), TargetId::new(target), kind, days, now)
}

/// `file` is load-bearing on its own.
#[test]
fn an_elapsed_window_belonging_to_another_file_authorizes_nothing() {
    let start = boot("b1", 0, 0);
    let after = boot("b1", 15, 15);
    // Same target, same kind, same elapsed window — only the file differs.
    let other_file = deferral_keyed(2, 1, DeferralKind::Remote, &start, 14);
    assert_eq!(
        other_file.status(&after),
        DeferralStatus::Expired,
        "precondition: the window really has elapsed, so only identity can refuse it"
    );

    let decision = discard_permitted(&inputs(&after, Some(&other_file), Some(14)));
    assert_eq!(
        decision.refusals(),
        [DiscardRefusal::DeferralForAnotherKey {
            deferral_file: FileId::new(2),
            deferral_target: TargetId::new(1),
            deferral_kind: DeferralKind::Remote,
        }],
        "file 2's elapsed window must not destroy file 1"
    );
}

/// `target` is load-bearing on its own — a test that only varies `file` cannot
/// tell you this field is compared at all.
#[test]
fn an_elapsed_window_for_another_target_authorizes_nothing() {
    let start = boot("b1", 0, 0);
    let after = boot("b1", 15, 15);
    let other_target = deferral_keyed(1, 9, DeferralKind::Remote, &start, 14);
    assert_eq!(other_target.status(&after), DeferralStatus::Expired);

    let decision = discard_permitted(&inputs(&after, Some(&other_target), Some(14)));
    assert_eq!(
        decision.refusals(),
        [DiscardRefusal::DeferralForAnotherKey {
            deferral_file: FileId::new(1),
            deferral_target: TargetId::new(9),
            deferral_kind: DeferralKind::Remote,
        }],
        "the same file on a different target is a different destruction"
    );
}

/// `kind` is load-bearing on its own. PM-1's local unlink and PM-2's remote
/// discard protect opposite sides of the system; an elapsed window for one is
/// no authority over the other.
#[test]
fn an_elapsed_local_unlink_window_does_not_authorize_a_remote_discard() {
    let start = boot("b1", 0, 0);
    let after = boot("b1", 15, 15);
    let local = deferral_keyed(1, 1, DeferralKind::Local, &start, 14);
    assert_eq!(local.status(&after), DeferralStatus::Expired);

    let decision = discard_permitted(&inputs(&after, Some(&local), Some(14)));
    assert_eq!(
        decision.refusals(),
        [DiscardRefusal::DeferralForAnotherKey {
            deferral_file: FileId::new(1),
            deferral_target: TargetId::new(1),
            deferral_kind: DeferralKind::Local,
        }],
        "a local unlink window is not a remote discard window"
    );
}

/// The accepting direction. "Never authorize" passes all three tests above and
/// disables the deferral window entirely.
#[test]
fn the_files_own_elapsed_window_still_authorizes_it() {
    let start = boot("b1", 0, 0);
    let after = boot("b1", 15, 15);
    let own = deferral_keyed(1, 1, DeferralKind::Remote, &start, 14);
    assert_eq!(
        discard_permitted(&inputs(&after, Some(&own), Some(14))),
        DiscardDecision::Permitted,
        "the whole point of the window is that it can elapse"
    );
}

/// The zero-window branch reads `cancelled_at`, which is also a status. It gets
/// the same identity check, and for the same reason.
#[test]
fn a_zero_window_does_not_read_another_files_deferral_either() {
    let start = boot("b1", 0, 0);
    let now = boot("b1", 1, 1);
    let mut other_file = deferral_keyed(2, 1, DeferralKind::Remote, &start, 0);
    other_file.cancelled_at = Some(Timestamp::from_nanos(1));

    let decision = discard_permitted(&inputs(&now, Some(&other_file), Some(0)));
    assert_eq!(
        decision.refusals(),
        [DiscardRefusal::DeferralForAnotherKey {
            deferral_file: FileId::new(2),
            deferral_target: TargetId::new(1),
            deferral_kind: DeferralKind::Remote,
        }],
        "another file's cancellation is not this file's cancellation, either way round"
    );
}

/// A deferral opened under a different window is not evidence for this one.
///
/// The deadline was computed from `window_days` when the deferral was opened,
/// and editing the policy afterwards does not move it. Lengthening the window
/// from one day to fourteen therefore left a one-day deferral satisfying a
/// fourteen-day policy, and the sole-copy discard ran thirteen days before the
/// active policy permits. The window is the whole insurance against a
/// misclassified permanent delete, so serving it from a stale row is serving it
/// from a policy nobody chose.
#[test]
fn a_deferral_opened_under_another_window_does_not_satisfy_this_policy() {
    let opened = boot("b", 0, 0);
    let d = deferral_at(&opened, 1);
    // A day later the one-day window has expired on its own terms.
    let now = boot("b", 2, 2);

    // Under the window it was opened for, it is exactly what it claims.
    assert_eq!(
        discard_permitted(&inputs(&now, Some(&d), Some(1))).refusals(),
        &[] as &[DiscardRefusal],
        "a deferral matching the live window still permits"
    );

    // The operator lengthens the policy. The stored row is unchanged, and it is
    // now the wrong evidence.
    let refusals = discard_permitted(&inputs(&now, Some(&d), Some(14)))
        .refusals()
        .to_vec();
    assert_eq!(
        refusals,
        vec![DiscardRefusal::DeferralWindowStale {
            deferral_days: 1,
            policy_days: 14,
        }],
        "a one-day deferral satisfied a fourteen-day policy: {refusals:?}"
    );

    // SHORTENING is refused too, and that is the deliberate direction. A longer
    // deferral than the policy asks for is still a window the operator has
    // replaced; refusing costs a new deferral and some waiting, accepting means
    // honouring a policy nobody chose. Between two ways to be wrong about an
    // irreversible operation, this one waits.
    let long = deferral_at(&opened, 30);
    assert_eq!(
        discard_permitted(&inputs(&now, Some(&long), Some(14))).refusals(),
        &[DiscardRefusal::DeferralWindowStale {
            deferral_days: 30,
            policy_days: 14,
        }]
    );
}

/// A confirmation is about a FILE, and one for another file proves nothing.
///
/// The predicate asked only whether some confirmation was present, and the
/// value carried no identity — so in a batch a confirmation produced for file A
/// could be cloned into file B's otherwise correctly keyed proof, and B's
/// remote copies discarded with no permanent-delete event for B anywhere. Every
/// other authority in this module is checked against the candidate before its
/// status is read; this one had nothing to check.
#[test]
fn a_confirmation_for_another_file_does_not_authorize_this_discard() {
    let now = boot("b", 2, 2);
    let opened = boot("b", 0, 0);
    let d = deferral_at(&opened, 1);

    let mut i = inputs(&now, Some(&d), Some(1));
    i.confirmation = Some(PermanentDeleteConfirmation {
        file: FileId::new(99),
        source: ConfirmationSource::WindowsCfApi,
    });
    assert_eq!(
        discard_permitted(&i).refusals(),
        &[DiscardRefusal::ConfirmationForAnotherFile {
            confirmed_file: FileId::new(99),
        }],
        "a confirmation naming another file authorized this one"
    );

    // Distinct from having none at all, deliberately: one says the platform
    // never reported a permanent delete, the other says the proof was carried
    // across from something else, and the second is a bug in the caller.
    let mut i = inputs(&now, Some(&d), Some(1));
    i.confirmation = None;
    assert_eq!(
        discard_permitted(&i).refusals(),
        &[DiscardRefusal::NoPermanentDeleteConfirmation]
    );
}
