//! Tests for §4.10.5's blast-radius controls.
//!
//! The ones that matter most are the evasion tests: a rate limit that a
//! restart or a split pass can walk around is not a rate limit, and a
//! confirmation that survives a changed candidate set authorizes destroying
//! files the human never saw.

use super::*;

const HOUR: i64 = 3_600 * 1_000_000_000;

fn t(hours: i64) -> Timestamp {
    Timestamp::from_nanos(hours * HOUR)
}

fn candidates(n: u32) -> Vec<Candidate> {
    (0..n)
        .map(|i| Candidate {
            file: FileId::new(i64::from(i)),
            path: format!("/root/f{i}.raw"),
            blake3: Some(Blake3Hash::from_bytes([u8::try_from(i % 251).unwrap(); 32])),
        })
        .collect()
}

fn limits() -> BreakerLimits {
    BreakerLimits {
        max_in_window: 10,
        window_nanos: 24 * HOUR,
        max_per_episode: 8,
    }
}

fn confirmed_episode(n: u32, now: Timestamp) -> Episode {
    let mut e = Episode::open(RootId::new(1), TargetId::new(1), now);
    e.enumerate(candidates(n));
    e.confirm("operator", now, DEFAULT_CONFIRMATION_TTL_NANOS);
    e
}

#[test]
fn a_confirmed_episode_within_limits_may_execute() {
    // A breaker that never permits would pass every other test here.
    let now = t(0);
    let e = confirmed_episode(3, now);
    assert_eq!(
        e.may_execute(&RateWindow::default(), &limits(), now),
        Ok(())
    );
}

#[test]
fn nothing_executes_before_the_complete_set_is_enumerated() {
    // Iteration 1 claimed "a 200-item pass destroys nothing before
    // confirmation" without requiring the preflight that makes it true.
    let now = t(0);
    let e = Episode::open(RootId::new(1), TargetId::new(1), now);
    assert_eq!(e.state, EpisodeState::Enumerating);
    let refusals = e
        .may_execute(&RateWindow::default(), &limits(), now)
        .expect_err("must refuse");
    assert_eq!(refusals, [BreakerRefusal::SetNotEnumerated]);
}

#[test]
fn an_enumerated_but_unconfirmed_episode_is_held() {
    let now = t(0);
    let mut e = Episode::open(RootId::new(1), TargetId::new(1), now);
    e.enumerate(candidates(3));
    assert_eq!(e.state, EpisodeState::Held);
    assert!(
        e.may_execute(&RateWindow::default(), &limits(), now)
            .expect_err("must refuse")
            .contains(&BreakerRefusal::NotConfirmed {
                state: EpisodeState::Held
            })
    );
}

/// The one that matters: a confirmation must not survive the set changing.
#[test]
fn a_confirmation_expires_when_the_candidate_set_changes() {
    let now = t(0);
    let mut e = confirmed_episode(3, now);
    assert!(
        e.may_execute(&RateWindow::default(), &limits(), now)
            .is_ok()
    );

    // A new file started matching between confirmation and execution.
    let mut grown = candidates(3);
    grown.push(Candidate {
        file: FileId::new(999),
        path: "/root/surprise.raw".into(),
        blake3: None,
    });
    e.candidates = grown;
    e.candidate_set_blake3 = Some(candidate_set_hash(&e.candidates));

    let refusals = e
        .may_execute(&RateWindow::default(), &limits(), now)
        .expect_err("a changed set must invalidate the confirmation");
    assert!(
        refusals
            .iter()
            .any(|r| matches!(r, BreakerRefusal::ConfirmationStale { .. })),
        "{refusals:?}"
    );
}

#[test]
fn re_enumerating_returns_to_held_and_never_to_confirmed() {
    // A hold escalates; it does not time out — or re-enumerate — into action.
    let now = t(0);
    let mut e = confirmed_episode(3, now);
    e.re_enumerate(candidates(4));

    assert_eq!(e.state, EpisodeState::Held);
    assert_eq!(e.confirmed_set_blake3, None);
    assert_eq!(e.confirmed_at, None);
    assert!(
        e.may_execute(&RateWindow::default(), &limits(), now)
            .is_err()
    );
}

#[test]
fn a_confirmation_expires_on_its_own_ttl() {
    let now = t(0);
    let e = confirmed_episode(3, now);
    // Inside the TTL.
    assert!(
        e.may_execute(&RateWindow::default(), &limits(), t(0))
            .is_ok()
    );
    // Past it.
    let refusals = e
        .may_execute(&RateWindow::default(), &limits(), t(2))
        .expect_err("must expire");
    assert!(
        refusals
            .iter()
            .any(|r| matches!(r, BreakerRefusal::ConfirmationExpired { .. })),
        "{refusals:?}"
    );
}

#[test]
fn the_candidate_set_hash_is_order_independent() {
    // A different SQL plan is not a different set. Making this order-sensitive
    // would expire confirmations at random and train people to re-confirm
    // without reading.
    let a = candidates(5);
    let mut b = a.clone();
    b.reverse();
    assert_eq!(candidate_set_hash(&a), candidate_set_hash(&b));
}

#[test]
fn the_candidate_set_hash_distinguishes_different_sets() {
    assert_ne!(
        candidate_set_hash(&candidates(3)),
        candidate_set_hash(&candidates(4))
    );

    // And a path change is a different set, even at the same file id.
    let mut moved = candidates(2);
    moved[1].path = "/root/elsewhere.raw".into();
    assert_ne!(
        candidate_set_hash(&candidates(2)),
        candidate_set_hash(&moved)
    );

    // Field separators: "ab" + "c" must not hash the same as "a" + "bc".
    let one = vec![Candidate {
        file: FileId::new(1),
        path: "ab".into(),
        blake3: None,
    }];
    let two = vec![Candidate {
        file: FileId::new(1),
        path: "a".into(),
        blake3: None,
    }];
    assert_ne!(candidate_set_hash(&one), candidate_set_hash(&two));
}

// --- the rolling window ----------------------------------------------------

/// **The evasion test.** Repeated sub-threshold passes must not walk around
/// the limit.
#[test]
fn repeated_sub_threshold_passes_cannot_evade_the_window() {
    let l = limits(); // max_in_window: 10
    let mut w = RateWindow::default();

    // Three passes of 4, each individually under the per-episode cap of 8.
    w.record(t(1), 4);
    w.record(t(2), 4);
    assert_eq!(w.count_within(t(3), l.window_nanos), 8);

    let e = confirmed_episode(4, t(3));
    let refusals = e
        .may_execute(&w, &l, t(3))
        .expect_err("8 already used + 4 more exceeds 10");
    assert!(
        refusals
            .iter()
            .any(|r| matches!(r, BreakerRefusal::RateWindowExhausted { .. })),
        "{refusals:?}"
    );
}

#[test]
fn the_window_counts_this_episode_too_not_just_history() {
    // Authorizing a pass that would itself breach the limit is the arithmetic
    // a per-batch cap alone misses.
    let l = limits(); // max_in_window: 10, max_per_episode: 8
    let e = confirmed_episode(8, t(0));
    // Empty history, but 8 <= 10 so this is fine.
    assert!(e.may_execute(&RateWindow::default(), &l, t(0)).is_ok());

    let mut w = RateWindow::default();
    w.record(t(0), 3);
    assert!(
        e.may_execute(&w, &l, t(0)).is_err(),
        "3 used + 8 requested = 11 > 10"
    );
}

#[test]
fn the_window_rolls_so_old_discards_stop_counting() {
    let l = limits(); // 24h window
    let mut w = RateWindow::default();
    w.record(t(0), 9);
    assert_eq!(w.count_within(t(1), l.window_nanos), 9);
    // 25 hours later the old bucket is outside the window.
    assert_eq!(w.count_within(t(25), l.window_nanos), 0);
}

#[test]
fn the_window_survives_a_restart_because_it_is_data_not_state() {
    // Serialize, drop, reload — as a restarted daemon would. An in-memory
    // counter would make the breaker evadable by restarting the process, which
    // is the failure a rate limit most needs to survive.
    let mut w = RateWindow::default();
    w.record(t(1), 7);
    let json = serde_json::to_string(&w).expect("serialize");
    let reloaded: RateWindow = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(reloaded.count_within(t(2), 24 * HOUR), 7);
}

#[test]
fn pruning_only_drops_buckets_that_can_no_longer_matter() {
    let mut w = RateWindow::default();
    w.record(t(0), 5);
    w.record(t(30), 2);
    w.prune(t(31), 24 * HOUR);
    assert_eq!(w.buckets.len(), 1);
    assert_eq!(w.count_within(t(31), 24 * HOUR), 2);
}

#[test]
fn the_per_episode_cap_is_retained_alongside_the_rolling_window() {
    // Not replaced by it: a single enormous pass must be refused even with an
    // entirely empty history.
    let l = limits(); // max_per_episode: 8
    let e = confirmed_episode(9, t(0));
    let refusals = e
        .may_execute(&RateWindow::default(), &l, t(0))
        .expect_err("must refuse");
    assert!(
        refusals.contains(&BreakerRefusal::EpisodeTooLarge { count: 9, limit: 8 }),
        "{refusals:?}"
    );
}

// --- hold semantics --------------------------------------------------------

#[test]
fn a_hold_blocks_only_destructive_classes_and_only_its_own_target() {
    let hold = HoldScope {
        target: TargetId::new(1),
    };

    // Typed, not string-matched: a renamed variant is now a compile error here
    // rather than a hold that silently stops blocking the class it was written
    // to block.
    assert!(hold.blocks(JobClass::Destroy, TargetId::new(1)));

    // Every other job class continues — a hold is not a pause button for the
    // product.
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
            !hold.blocks(class, TargetId::new(1)),
            "{class:?} must keep running under a discard hold"
        );
    }

    // And another target is unaffected.
    assert!(!hold.blocks(JobClass::Destroy, TargetId::new(2)));
}

#[test]
fn a_cancelled_episode_never_executes() {
    let now = t(0);
    let mut e = confirmed_episode(3, now);
    e.cancel();
    assert!(
        e.may_execute(&RateWindow::default(), &limits(), now)
            .expect_err("must refuse")
            .contains(&BreakerRefusal::Cancelled)
    );
}

#[test]
fn every_failing_check_is_reported_not_just_the_first() {
    // A held bulk discard is operator-facing; one reason at a time turns
    // unblocking it into a guessing game.
    let mut e = confirmed_episode(9, t(0)); // over the per-episode cap
    e.candidates.push(Candidate {
        file: FileId::new(500),
        path: "/root/extra".into(),
        blake3: None,
    });
    e.candidate_set_blake3 = Some(candidate_set_hash(&e.candidates)); // now stale
    let mut w = RateWindow::default();
    w.record(t(0), 10); // window already exhausted

    let refusals = e.may_execute(&w, &limits(), t(0)).expect_err("must refuse");
    assert!(refusals.len() >= 3, "{refusals:?}");
}
