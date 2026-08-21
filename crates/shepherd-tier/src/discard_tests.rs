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
        provenance: ClockProvenance::NtpSynced,
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

/// A candidate this episode never enumerated — another episode's object, or an
/// item a wiring error left out of `Episode::candidates`.
fn stranger() -> Candidate {
    candidate(99)
}

/// A deferral per candidate. `reserve_discard` charges for every candidate, so
/// every candidate needs its own expired window — one file's deferral no longer
/// authorizes its neighbours, which is the whole point of the batch proof.
fn deferrals_for(e: &Episode) -> Vec<Deferral> {
    e.candidates
        .iter()
        .map(|c| {
            Deferral::open(
                c.file,
                TargetId::new(1),
                DeferralKind::Remote,
                14,
                &clock(0),
            )
        })
        .collect()
}

/// One proof per candidate the episode holds — what `reserve_discard` requires
/// now that a charge covering N files needs N proofs.
///
/// `deferrals` is matched by file, so a candidate with none in the slice gets
/// `None` and is refused. Pass `&[]` to prove nothing.
fn proofs_for<'a>(
    e: &Episode,
    now: &'a ClockReading,
    deferrals: &'a [Deferral],
    confirmation: Option<PermanentDeleteConfirmation>,
) -> Vec<DiscardInputs<'a>> {
    e.candidates
        .iter()
        .map(|c| DiscardInputs {
            file: c.file,
            ..inputs(
                now,
                deferrals.iter().find(|d| d.file == c.file),
                confirmation.clone(),
            )
        })
        .collect()
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

/// The target's key prefix. Load-bearing: the key `spend` mints is derived
/// from it, so an object under a different prefix is a different object.
const PREFIX: &str = "shepherd";

const ROOT: RootId = RootId::new(1);
const TARGET: TargetId = TargetId::new(1);

/// Candidate `i`, with a REAL hash — a candidate without one names no
/// content-addressed object and is refused, which is its own test below.
fn candidate(i: usize) -> Candidate {
    Candidate {
        file: FileId::new(i as i64 + 1),
        path: format!("/root/{i}.raw"),
        blake3: Some(shepherd_core::Blake3Hash::from_bytes(
            *blake3::hash(format!("candidate-{i}").as_bytes()).as_bytes(),
        )),
    }
}

fn episode_with(count: usize, now: Timestamp) -> Episode {
    let mut e = Episode::open(ROOT, TARGET, now);
    e.enumerate((0..count).map(candidate).collect());
    e.confirm("operator", now, HOUR);
    e
}

/// A remote holding `count` deletable objects, plus the audit log the discard
/// path insists on.
struct Remote {
    dir: std::path::PathBuf,
    adapter: shepherd_storage::testing::MemAdapter,
    audit: crate::audit::AuditLog,
    locks: crate::serialize::FileLocks,
    keys: Vec<shepherd_core::ObjectKey>,
}

impl Remote {
    /// Seeds one object per candidate, at the key §4.9 says that candidate's
    /// content lives under — the same derivation `spend` uses, so the test
    /// remote and the authorisation agree by construction rather than by a
    /// hand-written table that could drift from it.
    fn new(tag: &str, count: usize) -> Self {
        let dir =
            std::env::temp_dir().join(format!("shepherd-discard-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let adapter = shepherd_storage::testing::MemAdapter::versioned();
        let keys: Vec<_> = (0..count)
            .map(|i| {
                let k = crate::plan::derive_object_key(
                    PREFIX,
                    candidate(i).blake3.expect("test candidates are hashed"),
                );
                adapter.put_versioned(&k, bytes::Bytes::from_static(b"x"), "v9");
                k
            })
            .collect();
        let audit = crate::audit::AuditLog::open(&dir.join("audit.jsonl")).unwrap();
        Self {
            dir,
            adapter,
            audit,
            locks: crate::serialize::FileLocks::new(),
            keys,
        }
    }

    fn guard() -> VersionGuard {
        VersionGuard::Version(shepherd_core::ObjectVersion::new("v9"))
    }

    /// Discard candidate `i`, in the ordinary scope.
    async fn discard(
        &self,
        charge: &mut DiscardCharge,
        i: usize,
        now: Timestamp,
    ) -> std::result::Result<(), DestroyError> {
        self.discard_as(charge, &candidate(i), TARGET, ROOT, PREFIX, i, now)
            .await
    }

    /// Discard whatever the caller names, so a test can vary exactly one
    /// component and nothing else.
    #[allow(clippy::too_many_arguments)]
    async fn discard_as(
        &self,
        charge: &mut DiscardCharge,
        candidate: &Candidate,
        target: TargetId,
        root: RootId,
        prefix: &str,
        intent: usize,
        now: Timestamp,
    ) -> std::result::Result<(), DestroyError> {
        execute_discard(
            charge,
            // Bound to the DERIVED KEY, which is what `execute_discard`
            // deletes — the round-30 fixture bound to the bare prefix, and a
            // fixture's guess becomes the contract the moment something checks
            // it. `derive_object_key` is the single place §4.9 keys are built,
            // so it is also the single place a caller should be deriving the
            // binding from.
            shepherd_catalog::intent::PreparedIntent::fabricated_for_tests(
                shepherd_core::IntentId::new(intent as i64 + 1),
                shepherd_catalog::intent::IntentKind::Remote,
                candidate
                    .blake3
                    .map(|h| crate::plan::derive_object_key(prefix, h))
                    .as_ref()
                    .map_or("", |k| k.as_str()),
                0,
                None,
            ),
            &crate::destroy::TargetGate::new(shepherd_core::TargetId::new(1), &self.adapter),
            candidate,
            target,
            root,
            prefix,
            &Self::guard(),
            &self.locks,
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
    let ds = deferrals_for(&e);
    let lim = limits(10);

    let mut charge = reserve_discard(
        &proofs_for(
            &e,
            &clock(20),
            &ds,
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

/// **One file's proof cannot authorize its neighbours.**
///
/// A charge covers every candidate in the episode, and the reservation used to
/// evaluate exactly ONE `DiscardInputs` before spending for all of them. A
/// three-candidate episode was therefore authorized by file 1's deferral alone:
/// files 2 and 3 could be discarded with no permanent-delete confirmation, an
/// unexpired window, or a root that was unavailable or needed resync — every
/// conjunct §4.10.5 states, checked once and applied to files it never looked
/// at.
#[tokio::test]
async fn a_batch_needs_a_policy_proof_for_every_candidate() {
    let now = t(20);
    let ledger = MemLedger::new();
    let e = episode_with(3, now);
    let lim = limits(10);
    let all = deferrals_for(&e);

    // The accepting direction first, so this cannot pass by refusing
    // everything: proofs for all three reserve.
    let _ = reserve_discard(
        &proofs_for(
            &e,
            &clock(20),
            &all,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &ledger.snapshot(),
        &lim,
        now,
        &ledger,
    )
    .await
    .expect("every candidate is proved");

    // Exactly the shape that shipped: one deferral, for file 1, and a batch of
    // three. It must not reserve, and the refusal must NAME the files that
    // were never proved.
    let only_first: Vec<_> = all.iter().take(1).cloned().collect();
    let refusals = reserve_discard(
        &proofs_for(
            &e,
            &clock(20),
            &only_first,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &MemLedger::new().snapshot(),
        &lim,
        now,
        &MemLedger::new(),
    )
    .await
    .expect_err("file 1's deferral does not authorize files 2 and 3");
    let unproven: Vec<FileId> = refusals
        .policy
        .iter()
        .filter_map(|r| match r {
            DiscardRefusal::CandidateUnproven { file } => Some(*file),
            _ => None,
        })
        .collect();
    assert!(
        unproven.contains(&FileId::new(2)) && unproven.contains(&FileId::new(3)),
        "the refusal must name the unproved candidates: {refusals:?}"
    );

    // And a proof set that does not MATCH the batch is not a proof of it: a
    // proof for a file this episode never enumerated is refused rather than
    // quietly ignored.
    let at = clock(20);
    let mut extra = proofs_for(
        &e,
        &at,
        &all,
        Some(PermanentDeleteConfirmation::WindowsCfApi),
    );
    extra.push(DiscardInputs {
        file: FileId::new(404),
        ..inputs(&at, None, Some(PermanentDeleteConfirmation::WindowsCfApi))
    });
    let refusals = reserve_discard(
        &extra,
        &e,
        &MemLedger::new().snapshot(),
        &lim,
        now,
        &MemLedger::new(),
    )
    .await
    .expect_err("a proof for a file outside the episode is refused");
    assert!(
        refusals.policy.iter().any(|r| matches!(
            r,
            DiscardRefusal::ProofForAnotherCandidate { file } if *file == FileId::new(404)
        )),
        "{refusals:?}"
    );
}

/// A proof must name this batch's TARGET and ROOT, not just its file.
///
/// The membership check compared `FileId` alone, so a proof for
/// `(file, target B)` authorized a candidate in an episode that deletes from
/// target A. B's deferral is expired and B's confirmation is present, and
/// `discard_permitted` agrees with all of it — it checks the deferral against
/// the PROOF's target, which matches. The charge then goes to A, whose own
/// deferral may be missing or still running.
///
/// The root is the same hole pointed at a different field: `RootGates` carries
/// the root it describes, so a proof could vouch for a root that is available
/// and in sync while the episode's own is neither.
#[tokio::test]
async fn a_proof_must_be_bound_to_the_episodes_target_and_root() {
    let now = t(20);
    let e = episode_with(1, now);
    let lim = limits(10);
    let at = clock(20);

    // A deferral for the SAME file on another target: expired, valid, and
    // entirely about somebody else's target.
    let other_target = TargetId::new(999);
    let elsewhere = Deferral::open(
        FileId::new(1),
        other_target,
        DeferralKind::Remote,
        14,
        &clock(0),
    );

    let wrong_target = vec![DiscardInputs {
        file: FileId::new(1),
        target: other_target,
        deferral: Some(&elsewhere),
        ..inputs(&at, None, Some(PermanentDeleteConfirmation::WindowsCfApi))
    }];
    let ledger = MemLedger::new();
    let refusals = reserve_discard(&wrong_target, &e, &ledger.snapshot(), &lim, now, &ledger)
        .await
        .expect_err("target B's proof does not authorize a deletion from target A");
    assert!(
        refusals.policy.iter().any(|r| matches!(
            r,
            DiscardRefusal::CandidateUnproven { file } if *file == FileId::new(1)
        )),
        "the candidate is unproved, whatever target B's deferral says: {refusals:?}"
    );

    // Same shape, wrong ROOT.
    let ds = deferrals_for(&e);
    let wrong_root = vec![DiscardInputs {
        gates: RootGates {
            root: RootId::new(998),
            resync_required: false,
            available: true,
        },
        ..proofs_for(
            &e,
            &at,
            &ds,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        )
        .remove(0)
    }];
    let ledger = MemLedger::new();
    reserve_discard(&wrong_root, &e, &ledger.snapshot(), &lim, now, &ledger)
        .await
        .expect_err("gates describing another root do not vouch for this one");

    // THE ACCEPTING DIRECTION: the right file, target and root still reserve.
    let ledger = MemLedger::new();
    let _ = reserve_discard(
        &proofs_for(
            &e,
            &at,
            &ds,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &ledger.snapshot(),
        &lim,
        now,
        &ledger,
    )
    .await
    .expect("a proof bound to this episode authorizes it");
}

/// The rolling window's entire purpose: repeated sub-threshold episodes must
/// accumulate against one budget. Pre-fix, episode two saw the same unused
/// window episode one had seen.
#[tokio::test]
async fn repeated_sub_threshold_episodes_accumulate_against_one_budget() {
    let now = t(20);
    let ledger = MemLedger::new();
    let e = episode_with(2, now);
    let ds = deferrals_for(&e);
    let lim = limits(3); // two episodes of 2 are individually fine, jointly not

    let first = reserve_discard(
        &proofs_for(
            &e,
            &clock(20),
            &ds,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &ledger.snapshot(),
        &lim,
        now,
        &ledger,
    )
    .await
    .expect("the first episode is within budget");
    assert_eq!(first.reserved(), 2);

    let refusals = reserve_discard(
        &proofs_for(
            &e,
            &clock(20),
            &ds,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
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

        let racer = episode_with(2, now);
        let ds = deferrals_for(&racer);
        let got = reserve_discard(
            &proofs_for(
                &racer,
                &clock(20),
                &ds,
                Some(PermanentDeleteConfirmation::WindowsCfApi),
            ),
            &racer,
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

/// The charge is spent **before** the deletion, so a refused draw stops the
/// delete from happening at all. Asserted on the fact — the adapter's delete
/// count — because an assertion on the error alone would pass even if the
/// object had been destroyed first and the refusal raised afterwards.
///
/// Pre-round-3 this refused with `ChargeExhausted`: the episode had paid for
/// one deletion and this was the second. That was an arithmetic answer to a
/// question about identity, and it is why the second object could be *any*
/// object. Now the refusal names what is actually wrong — candidate 1 is not in
/// a set that only ever held candidate 0.
#[tokio::test]
async fn an_object_outside_the_confirmed_set_refuses_before_anything_is_deleted() {
    let now = t(20);
    let ledger = MemLedger::new();
    let lim = limits(10);
    let remote = Remote::new("exhausted", 2);
    let one = episode_with(1, now);
    let ds = deferrals_for(&one);

    // Confirmed for one object; the episode tries to delete two.
    let mut charge = reserve_discard(
        &proofs_for(
            &one,
            &clock(20),
            &ds,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &one,
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
        .expect_err("a second deletion was never confirmed");
    assert!(
        matches!(
            err,
            DestroyError::Breaker(BreakerRefusal::NotACandidate { file }) if file == candidate(1).file
        ),
        "{err:?}"
    );
    assert_eq!(
        remote.deleted(),
        1,
        "the unconfirmed deletion must not have reached the remote: the charge is spent \
         before the object is destroyed, not after"
    );
}

// --- a charge authorises NAMED objects, not a quantity ---------------------
//
// Round 2 made "forgot to charge the breaker" unreachable. It did not make
// "charged for the wrong object" unreachable, and these are the tests for the
// second half. Every one of them asserts on the adapter's delete count, never
// on `is_err()`: a refusal raised *after* an irreversible deletion is not a
// refusal.

/// A helper: a confirmed charge over `count` candidates, with budget to spare.
async fn charge_for(ledger: &MemLedger, count: usize, now: Timestamp) -> DiscardCharge {
    let e = episode_with(count, now);
    let ds = deferrals_for(&e);
    reserve_discard(
        &proofs_for(
            &e,
            &clock(20),
            &ds,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &ledger.snapshot(),
        &limits(10),
        now,
        ledger,
    )
    .await
    .expect("both gates permit and the budget is free")
}

/// **The finding, at its centre.** A candidate from another episode — never in
/// this episode's set, never read by the operator who confirmed it — must not
/// be deletable with this episode's charge.
#[tokio::test]
async fn a_candidate_from_another_episode_cannot_be_deleted_with_this_episodes_charge() {
    let now = t(20);
    let ledger = MemLedger::new();
    let remote = Remote::new("foreign", 1);
    let mut charge = charge_for(&ledger, 1, now).await;

    let got = remote
        .discard_as(&mut charge, &stranger(), TARGET, ROOT, PREFIX, 0, now)
        .await;

    assert!(
        matches!(
            got,
            Err(DestroyError::Breaker(BreakerRefusal::NotACandidate { .. }))
        ),
        "{got:?}"
    );
    assert_eq!(
        remote.deleted(),
        0,
        "an object the operator never reviewed must not be deleted"
    );
    assert_eq!(
        charge.remaining(),
        1,
        "a refused draw must not consume the unit the confirmed candidate still needs"
    );
}

/// Every field of a candidate is independently load-bearing. A membership test
/// on `file` alone would accept a row whose path or hash had drifted from the
/// one the operator actually read.
#[tokio::test]
async fn varying_any_single_field_of_a_candidate_refuses_it() {
    let now = t(20);
    let confirmed = candidate(0);

    let mut wrong_file = confirmed.clone();
    wrong_file.file = FileId::new(4242);
    let mut wrong_path = confirmed.clone();
    wrong_path.path = "/root/somewhere-else.raw".into();
    let mut wrong_hash = confirmed.clone();
    wrong_hash.blake3 = Some(shepherd_core::Blake3Hash::from_bytes(
        *blake3::hash(b"different content").as_bytes(),
    ));

    for (field, impostor) in [
        ("file", wrong_file),
        ("path", wrong_path),
        ("blake3", wrong_hash),
    ] {
        let ledger = MemLedger::new();
        let remote = Remote::new(&format!("field-{field}"), 1);
        let mut charge = charge_for(&ledger, 1, now).await;

        let got = remote
            .discard_as(&mut charge, &impostor, TARGET, ROOT, PREFIX, 0, now)
            .await;

        assert!(
            matches!(
                got,
                Err(DestroyError::Breaker(BreakerRefusal::NotACandidate { .. }))
            ),
            "a candidate differing only in `{field}` was accepted: {got:?}"
        );
        assert_eq!(
            remote.deleted(),
            0,
            "a candidate differing only in `{field}` reached the remote"
        );
    }
}

/// A charge is scoped to one `(target, root)` — the pair the ledger's budget is
/// keyed on. Varying only the target.
#[tokio::test]
async fn a_charge_will_not_pay_for_a_deletion_at_another_target() {
    let now = t(20);
    let ledger = MemLedger::new();
    let remote = Remote::new("wrong-target", 1);
    let mut charge = charge_for(&ledger, 1, now).await;

    let got = remote
        .discard_as(
            &mut charge,
            &candidate(0),
            TargetId::new(2), // the ONLY thing that differs
            ROOT,
            PREFIX,
            0,
            now,
        )
        .await;

    assert!(
        matches!(
            got,
            Err(DestroyError::Breaker(BreakerRefusal::WrongTarget { .. }))
        ),
        "{got:?}"
    );
    assert_eq!(remote.deleted(), 0);
}

/// Varying only the root.
#[tokio::test]
async fn a_charge_will_not_pay_for_a_deletion_under_another_root() {
    let now = t(20);
    let ledger = MemLedger::new();
    let remote = Remote::new("wrong-root", 1);
    let mut charge = charge_for(&ledger, 1, now).await;

    let got = remote
        .discard_as(
            &mut charge,
            &candidate(0),
            TARGET,
            RootId::new(2), // the ONLY thing that differs
            PREFIX,
            0,
            now,
        )
        .await;

    assert!(
        matches!(
            got,
            Err(DestroyError::Breaker(BreakerRefusal::WrongRoot { .. }))
        ),
        "{got:?}"
    );
    assert_eq!(remote.deleted(), 0);
}

/// The prefix is load-bearing too, and this is the test a `key.ends_with(hash)`
/// suffix check would fail: the hash is right, the object is somebody else's.
#[tokio::test]
async fn the_key_is_derived_from_the_candidate_and_the_targets_prefix() {
    let now = t(20);
    let ledger = MemLedger::new();
    let remote = Remote::new("prefix", 1);
    let mut charge = charge_for(&ledger, 1, now).await;

    // The same candidate, under a DIFFERENT target's prefix. Nothing exists
    // there, so the deletion cannot touch the object seeded under `PREFIX`.
    remote
        .discard_as(
            &mut charge,
            &candidate(0),
            TARGET,
            ROOT,
            "some-other-target",
            0,
            now,
        )
        .await
        .expect("the derivation itself does not refuse — it names a different object");

    assert!(
        remote.adapter.object(&remote.keys[0]).is_some(),
        "a deletion derived under another prefix must not have reached THIS \
         target's object, whose hash is identical"
    );
}

/// One candidate, one unit. An iteration error that visits the same row twice
/// would otherwise delete one object twice and leave another alive while the
/// count still balanced.
#[tokio::test]
async fn one_candidate_cannot_be_spent_twice() {
    let now = t(20);
    let ledger = MemLedger::new();
    let remote = Remote::new("double-spend", 2);
    let mut charge = charge_for(&ledger, 2, now).await;

    remote.discard(&mut charge, 0, now).await.expect("first");
    let got = remote.discard(&mut charge, 0, now).await;

    assert!(
        matches!(
            got,
            Err(DestroyError::Breaker(BreakerRefusal::AlreadySpent { .. }))
        ),
        "{got:?}"
    );
    assert_eq!(
        remote.deleted(),
        1,
        "the second draw on one candidate must not reach the remote"
    );
    assert_eq!(
        charge.remaining(),
        1,
        "candidate 1's unit must still be there: a double spend on 0 that consumed \
         it would leave a confirmed object undeletable"
    );
}

/// A candidate with no hash names no content-addressed object (§4.9). Today
/// `plan_tier` refuses unhashed files so this cannot happen — which is exactly
/// why it needs a test, so the day `plan_tier` changes this fails loudly
/// instead of deriving a key from nothing.
#[tokio::test]
async fn an_unhashed_candidate_is_refused_rather_than_naming_a_key_from_nothing() {
    let now = t(20);
    let ledger = MemLedger::new();
    let remote = Remote::new("unhashed", 1);

    // An episode whose confirmed set genuinely contains the unhashed candidate,
    // so membership passes and only the missing hash is left to refuse it.
    let unhashed = Candidate {
        file: FileId::new(1),
        path: "/root/0.raw".into(),
        blake3: None,
    };
    let mut e = Episode::open(ROOT, TARGET, now);
    e.enumerate(vec![unhashed.clone()]);
    e.confirm("operator", now, HOUR);

    let ds = deferrals_for(&e);
    let mut charge = reserve_discard(
        &proofs_for(
            &e,
            &clock(20),
            &ds,
            Some(PermanentDeleteConfirmation::WindowsCfApi),
        ),
        &e,
        &ledger.snapshot(),
        &limits(10),
        now,
        &ledger,
    )
    .await
    .expect("reserve");

    let got = remote
        .discard_as(&mut charge, &unhashed, TARGET, ROOT, PREFIX, 0, now)
        .await;

    assert!(
        matches!(
            got,
            Err(DestroyError::Breaker(BreakerRefusal::Unhashed { .. }))
        ),
        "{got:?}"
    );
    assert_eq!(remote.deleted(), 0);
    assert_eq!(
        charge.remaining(),
        1,
        "a refusal that consumed the unit would be a silent budget leak"
    );
}

/// A discard waits on the **remote-key** lock, the one `upload_item` takes.
///
/// `upload::upload_item` holds `FileLocks::acquire_key` for the object it is
/// publishing; this path did not even accept `FileLocks`, so the two
/// interleaved freely on one content-addressed key. A delete landing between an
/// upload's completion and its verification makes that upload fail after it has
/// already published, and a completion landing after the delete recreates an
/// object the discard has already audited as gone — a live object with a
/// forensic record saying it was destroyed.
///
/// Asserted by CONTENTION rather than by reading the code: the lock is taken
/// first, and the discard must not get past it. A timeout that expires is the
/// pass, and the release-then-finish afterwards is what proves the test was
/// measuring the lock rather than a hang.
#[tokio::test]
async fn a_discard_waits_on_the_remote_key_lock() {
    let now = t(20);
    let ledger = MemLedger::new();
    let r = Remote::new("keylock", 1);
    let mut charge = charge_for(&ledger, 1, now).await;

    let held = r.locks.acquire_key(&r.keys[0]).await;

    let discarding = r.discard(&mut charge, 0, now);
    tokio::pin!(discarding);
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(250), &mut discarding)
            .await
            .is_err(),
        "the discard ran while the remote key was locked by an upload"
    );
    assert_eq!(r.deleted(), 0, "and it deleted nothing while blocked");

    drop(held);
    tokio::time::timeout(std::time::Duration::from_secs(20), discarding)
        .await
        .expect("releasing the key lock must let the discard proceed")
        .expect("the discard itself succeeds");
    assert_eq!(r.deleted(), 1);
}
