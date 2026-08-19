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

// --- the rolling breaker is charged, before anything is deleted -------------

/// A [`RateLedger`] over an in-memory window.
///
/// The `Mutex` is not decoration: it is what makes `charge` a genuine
/// test-and-consume rather than a read followed by a write, which is the
/// property the real SQLite-backed ledger has to reproduce with a transaction.
struct MemLedger {
    window: std::sync::Mutex<RateWindow>,
}

impl MemLedger {
    fn new() -> Self {
        Self {
            window: std::sync::Mutex::new(RateWindow::default()),
        }
    }

    /// The snapshot `evaluate_discard` reads. Advisory by construction — the
    /// authority is `charge`.
    fn snapshot(&self) -> RateWindow {
        self.window.lock().unwrap().clone()
    }

    fn used(&self, at: Timestamp, window_nanos: i64) -> u32 {
        self.window.lock().unwrap().count_within(at, window_nanos)
    }
}

#[async_trait::async_trait]
impl RateLedger for MemLedger {
    async fn charge(
        &self,
        _target: TargetId,
        _root: RootId,
        at: Timestamp,
        n: u32,
        limits: &BreakerLimits,
    ) -> Result<(), BreakerRefusal> {
        self.window.lock().unwrap().try_charge(at, n, limits)
    }
}

fn episode_with(count: usize, now: Timestamp) -> Episode {
    let mut e = Episode::open(RootId::new(1), TargetId::new(1), now);
    e.enumerate(
        (0..count)
            .map(|i| Candidate {
                file: FileId::new(i as i64 + 1),
                path: format!("/root/{i}.raw"),
                blake3: None,
            })
            .collect(),
    );
    e.confirm("operator", now, HOUR);
    e
}

/// A remote holding `count` deletable objects, plus the audit log the discard
/// path insists on.
struct Remote {
    dir: std::path::PathBuf,
    adapter: shepherd_storage::testing::MemAdapter,
    audit: crate::audit::AuditLog,
    keys: Vec<shepherd_core::ObjectKey>,
}

impl Remote {
    fn new(tag: &str, count: usize) -> Self {
        let dir =
            std::env::temp_dir().join(format!("shepherd-discard-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let adapter = shepherd_storage::testing::MemAdapter::versioned();
        let keys: Vec<_> = (0..count)
            .map(|i| {
                let k = shepherd_core::ObjectKey::new(format!("objects/ab/cd/obj{i}"));
                adapter.put_versioned(&k, bytes::Bytes::from_static(b"x"), "v9");
                k
            })
            .collect();
        let audit = crate::audit::AuditLog::open(&dir.join("audit.jsonl")).unwrap();
        Self {
            dir,
            adapter,
            audit,
            keys,
        }
    }

    fn guard() -> VersionGuard {
        VersionGuard::Version(shepherd_core::ObjectVersion::new("v9"))
    }

    async fn discard(
        &self,
        charge: &mut DiscardCharge,
        i: usize,
        now: Timestamp,
    ) -> std::result::Result<(), DestroyError> {
        execute_discard(
            charge,
            shepherd_core::IntentId::new(i as i64 + 1),
            &(&self.adapter as &dyn shepherd_storage::StorageAdapter),
            &self.keys[i],
            &Self::guard(),
            &self.audit,
            "version",
            now,
        )
        .await
    }

    fn deleted(&self) -> usize {
        self.adapter.deleted_keys().len()
    }
}

impl Drop for Remote {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn deferral() -> Deferral {
    Deferral::open(
        FileId::new(1),
        TargetId::new(1),
        DeferralKind::Remote,
        14,
        &clock(0),
        ClockProvenance::NtpSynced,
    )
}

fn limits(max_in_window: u32) -> BreakerLimits {
    BreakerLimits {
        max_in_window,
        window_nanos: DAY,
        max_per_episode: 500,
    }
}

/// **The accepting direction, and the fix's headline fact.** A breaker wired
/// to refuse everything would satisfy every refusal test below while silently
/// disabling discard, so this asserts that the episode completes *and* that
/// the window ends up holding exactly what was spent — not zero (the pre-fix
/// behaviour) and not double (a reserve that also charges per deletion).
#[tokio::test]
async fn an_executed_episode_charges_the_window_exactly_once_per_object() {
    let now = t(20);
    let ledger = MemLedger::new();
    let e = episode_with(3, now);
    let remote = Remote::new("charged", 3);
    let d = deferral();
    let lim = limits(10);

    let mut charge = reserve_discard(
        inputs(
            &clock(20),
            Some(&d),
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &ledger.snapshot(),
        &lim,
        now,
        &ledger,
    )
    .await
    .expect("both gates permit and the budget is free");

    assert_eq!(charge.reserved(), 3);
    assert_eq!(
        ledger.used(now, lim.window_nanos),
        3,
        "the charge must be persisted by `reserve_discard`, before any deletion"
    );

    for i in 0..3 {
        remote.discard(&mut charge, i, now).await.expect("discard");
    }

    assert_eq!(remote.deleted(), 3, "all three objects really were deleted");
    assert_eq!(
        ledger.used(now, lim.window_nanos),
        3,
        "the window must hold exactly the three that were spent"
    );
    assert_eq!(charge.remaining(), 0);
}

/// The rolling window's entire purpose: repeated sub-threshold episodes must
/// accumulate against one budget. Pre-fix, episode two saw the same unused
/// window episode one had seen.
#[tokio::test]
async fn repeated_sub_threshold_episodes_accumulate_against_one_budget() {
    let now = t(20);
    let ledger = MemLedger::new();
    let d = deferral();
    let lim = limits(3); // two episodes of 2 are individually fine, jointly not

    let first = reserve_discard(
        inputs(
            &clock(20),
            Some(&d),
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &episode_with(2, now),
        &ledger.snapshot(),
        &lim,
        now,
        &ledger,
    )
    .await
    .expect("the first episode is within budget");
    assert_eq!(first.reserved(), 2);

    let refusals = reserve_discard(
        inputs(
            &clock(20),
            Some(&d),
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &episode_with(2, now),
        &ledger.snapshot(),
        &lim,
        now,
        &ledger,
    )
    .await
    .expect_err("2 + 2 exceeds a budget of 3");

    assert_eq!(
        refusals.breaker,
        vec![BreakerRefusal::RateWindowExhausted {
            used: 2,
            limit: 3,
            window_nanos: DAY,
        }],
        "the second episode must be refused by the window the first one charged"
    );
    assert_eq!(
        ledger.used(now, lim.window_nanos),
        2,
        "a refused reservation must not consume budget"
    );
}

/// The TOCTOU the finding names. Both episodes are evaluated against the same
/// snapshot — as two concurrent workers would be — and both pass that
/// advisory check. Only the atomic charge separates them.
#[tokio::test]
async fn two_episodes_evaluating_against_one_snapshot_cannot_both_reserve() {
    let now = t(20);
    let ledger = MemLedger::new();
    let d = deferral();
    let lim = limits(2);
    // The snapshot both racers read, taken once, before either charges.
    let snapshot = ledger.snapshot();

    for (label, expect_ok) in [("first", true), ("second", false)] {
        // Precondition: the advisory gate says yes to BOTH, which is exactly
        // why it cannot be the authority.
        assert_eq!(
            evaluate_discard(
                inputs(
                    &clock(20),
                    Some(&d),
                    Some(PermanentDeleteConfirmation::WindowsCfApi),
                ),
                &episode_with(2, now),
                &snapshot,
                &lim,
                now,
            ),
            Ok(()),
            "{label}: the snapshot check must pass for both racers"
        );

        let got = reserve_discard(
            inputs(
                &clock(20),
                Some(&d),
                Some(PermanentDeleteConfirmation::WindowsCfApi),
            ),
            &episode_with(2, now),
            &snapshot,
            &lim,
            now,
            &ledger,
        )
        .await;

        assert_eq!(
            got.is_ok(),
            expect_ok,
            "{label}: exactly one racer may reserve the budget, got {got:?}"
        );
    }

    assert_eq!(
        ledger.used(now, lim.window_nanos),
        2,
        "the budget must have been consumed once, not twice"
    );
}

/// The charge is spent **before** the deletion, so an exhausted one stops the
/// delete from happening at all. Asserted on the fact — the adapter's delete
/// count — because an assertion on the error alone would pass even if the
/// object had been destroyed first and the refusal raised afterwards.
#[tokio::test]
async fn an_exhausted_charge_refuses_before_anything_is_deleted() {
    let now = t(20);
    let ledger = MemLedger::new();
    let d = deferral();
    let lim = limits(10);
    let remote = Remote::new("exhausted", 2);

    // Reserved for one object; the episode tries to delete two.
    let mut charge = reserve_discard(
        inputs(
            &clock(20),
            Some(&d),
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &episode_with(1, now),
        &ledger.snapshot(),
        &lim,
        now,
        &ledger,
    )
    .await
    .expect("reserve");

    remote
        .discard(&mut charge, 0, now)
        .await
        .expect("the object the charge paid for");
    assert_eq!(remote.deleted(), 1);

    let err = remote
        .discard(&mut charge, 1, now)
        .await
        .expect_err("a second deletion was never paid for");
    assert!(
        matches!(
            err,
            DestroyError::Breaker(BreakerRefusal::ChargeExhausted { reserved: 1 })
        ),
        "{err:?}"
    );
    assert_eq!(
        remote.deleted(),
        1,
        "the unpaid deletion must not have reached the remote: the charge is spent \
         before the object is destroyed, not after"
    );
}
