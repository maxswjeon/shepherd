//! Crash-window tests for the transfer state machine.
//!
//! One test per window in the table at the top of `transfer_session.rs`, plus
//! PM-1's modify-during-upload race and the transition table itself. Each
//! "crash" is a durable-write failure at a chosen point followed by reloading
//! the session from the store — so every assertion is about what the resumed
//! process could actually read, not about in-memory state that a real restart
//! would have lost.

use super::*;
use crate::multipart::PartAction;
use crate::testing::{Faults, MemAdapter, MemSource, MemStore};

const PART: u64 = 10;
const BODY: usize = 40; // 4 parts of 10 bytes.

fn body_of(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i % 251) as u8).collect()
}

struct Rig {
    adapter: MemAdapter,
    store: MemStore,
    source: MemSource,
    key: ObjectKey,
}

impl Rig {
    fn new(versioned: bool) -> Self {
        let bytes = body_of(BODY);
        Self {
            adapter: if versioned {
                MemAdapter::versioned()
            } else {
                MemAdapter::content_addressed()
            },
            store: MemStore::new(),
            source: MemSource::new(bytes),
            key: ObjectKey::new("objects/aa/bb/aabbcc"),
        }
    }

    fn session(&self) -> TransferSession {
        self.session_with_part_size(PART)
    }

    fn session_with_part_size(&self, part_size: u64) -> TransferSession {
        let body = self.source.body();
        let source = SourceIdentity {
            file_id: FileId::new(1),
            rel_path: "docs/big.bin".into(),
            size: body.len() as u64,
            mtime: Timestamp::from_nanos(1_000),
            fs_id: FsId::new("vol-1:inode-7"),
            blake3: self.source.blake3(),
        };
        TransferSession::plan(
            JobId::new(42),
            TargetId::new(3),
            self.key.clone(),
            source,
            &self.adapter,
            part_size,
        )
        .expect("plan")
    }

    fn driver(&self) -> TransferDriver<'_> {
        let mut d = TransferDriver::new(&self.adapter, &self.store, &self.source);
        d.verify_chunk = PART;
        d
    }

    /// What a restarted process would find in the database.
    async fn reload(&self) -> TransferSession {
        self.store
            .load(JobId::new(42))
            .await
            .expect("load")
            .expect("a session must have been persisted before the crash")
    }
}

/// Every per-part checkpoint goes through `save_part`, not a whole-session
/// `save`.
///
/// `upload_pending` checkpoints once per acknowledged part, and the durable
/// store replaces its ENTIRE part set on a `save` — so routing the hot loop
/// through `save` makes checkpoint work quadratic in the part count. On the
/// 3,200-part 50 GB transfer the plan sizes for, that is ~5.1 million part
/// inserts under `synchronous = FULL` to record 3,200 events.
///
/// Asserted at the seam rather than by timing: this double has nothing cheaper
/// than a full save, so the only thing observable — and the only thing that
/// matters here — is WHICH method the driver reaches for.
#[tokio::test]
async fn each_acknowledged_part_is_checkpointed_singly() {
    let rig = Rig::new(false);
    let mut s = rig.session();
    let out = rig.driver().run(&mut s).await.expect("run");

    assert_eq!(out.parts_sent, 4, "the fixture is four parts");
    assert_eq!(
        rig.store.part_saves(),
        4,
        "one single-part checkpoint per acknowledged part"
    );

    // The remaining writes are the state transitions, which are exactly what a
    // whole-session save is for. Their count is a property of the STATE
    // MACHINE, so it must not move when the part count doubles — which is the
    // difference between a constant and the per-part save this replaced.
    let whole = rig.store.saves() - rig.store.part_saves();

    let fine = Rig::new(false);
    let mut s = fine.session_with_part_size(PART / 2);
    let out2 = fine.driver().run(&mut s).await.expect("run");
    assert_ne!(
        out2.parts_sent, out.parts_sent,
        "a smaller part size must actually produce a different part count, or \
         this comparison measures nothing"
    );
    assert_eq!(fine.store.part_saves(), out2.parts_sent as usize);
    assert_eq!(
        fine.store.saves() - fine.store.part_saves(),
        whole,
        "whole-session saves must be a property of the state machine, not of \
         the part count"
    );
}

#[tokio::test]
async fn happy_path_uploads_verifies_and_commits() {
    let rig = Rig::new(false);
    let mut s = rig.session();
    let out = rig.driver().run(&mut s).await.expect("run");

    assert_eq!(out.state, TransferState::Committed);
    assert_eq!(out.parts_sent, 4);
    assert_eq!(out.bytes_skipped, 0);
    assert!(!out.resolved_ambiguous_completion);
    assert_eq!(
        rig.adapter.object(&rig.key).expect("object").as_ref(),
        rig.source.body().as_ref(),
        "the assembled object must be byte-identical to the source"
    );
    // A non-versioned bucket lands on mechanism B — probed, not assumed.
    assert_eq!(s.attestation_mode, Some(AttestationMode::Content));
    assert_eq!(s.object_version, None);
}

#[tokio::test]
async fn a_versioned_target_pins_a_version_and_reports_mechanism_a() {
    let rig = Rig::new(true);
    let mut s = rig.session();
    rig.driver().run(&mut s).await.expect("run");
    assert_eq!(s.attestation_mode, Some(AttestationMode::Version));
    assert!(
        s.object_version.is_some(),
        "mechanism A must pin an immutable version id at verify"
    );
}

/// **AC-2.** Kill mid-upload, restart, resume without re-sending verified parts.
#[tokio::test]
async fn ac2_resume_does_not_resend_durably_acknowledged_parts() {
    let rig = Rig::new(false);
    let mut s = rig.session();
    assert_eq!(s.plan.part_count, 4);

    // Saves: 1 = Initiating, 2 = Uploading, 3 = part1, 4 = part2, 5 = part3.
    // Dying at 5 leaves parts 1 and 2 durable; part 3 reached the provider but
    // its checkpoint never landed.
    rig.store.die_at_save(5);
    let err = rig.driver().run(&mut s).await.expect_err("must die");
    assert!(err.is_retryable(), "a lost write is transient: {err}");

    // --- restart ---
    rig.store.revive();
    let mut resumed = rig.reload().await;
    assert_eq!(resumed.state, TransferState::Uploading);
    assert_eq!(
        resumed.parts.iter().filter(|p| p.is_acknowledged()).count(),
        2,
        "exactly two parts were durably acknowledged before the crash"
    );

    let out = rig.driver().run(&mut resumed).await.expect("resume");
    assert_eq!(out.state, TransferState::Committed);
    assert_eq!(
        out.bytes_skipped,
        2 * PART,
        "the two verified parts must not be re-sent — this is what AC-2 measures"
    );
    assert_eq!(
        out.parts_sent, 2,
        "only the unacknowledged parts 3 and 4 are re-sent"
    );
    assert_eq!(
        rig.adapter.object(&rig.key).expect("object").as_ref(),
        rig.source.body().as_ref()
    );
}

/// Window 2 — the part reached the provider, the checkpoint did not.
#[tokio::test]
async fn a_part_uploaded_before_its_checkpoint_is_resent_not_adopted() {
    let rig = Rig::new(false);
    let mut s = rig.session();

    rig.store.die_at_save(3); // dies committing part 1's checkpoint
    rig.driver().run(&mut s).await.expect_err("must die");

    rig.store.revive();
    let resumed = rig.reload().await;
    assert!(
        resumed.parts.iter().all(|p| !p.is_acknowledged()),
        "no checkpoint became durable"
    );

    // The provider genuinely holds part 1 — but nothing durable attributes it
    // to us, and an opaque ETag cannot close that gap.
    let remote = rig
        .adapter
        .list_parts(&rig.key, resumed.upload_id.as_ref().expect("token"))
        .await
        .expect("list_parts");
    assert_eq!(remote.len(), 1, "the provider does hold the orphaned part");

    let recon = crate::multipart::reconcile_parts(&resumed.plan, &resumed.parts, &remote);
    assert_eq!(recon.actions[0], PartAction::Send);
    assert_eq!(recon.orphan_remote_parts, 1);
    assert_eq!(recon.bytes_skipped, 0);
}

/// Window 1 — a provider session exists that the database never learned about.
#[tokio::test]
async fn an_orphaned_provider_session_is_reaped_before_a_new_one_starts() {
    let rig = Rig::new(false);
    let mut s = rig.session();

    // Save 1 = Initiating (durable), then create_multipart succeeds, then
    // save 2 (which would record the upload id) dies.
    rig.store.die_at_save(2);
    rig.driver().run(&mut s).await.expect_err("must die");
    assert_eq!(
        rig.adapter.live_upload_count(),
        1,
        "the provider is holding a session nobody has the id for"
    );

    rig.store.revive();
    let mut resumed = rig.reload().await;
    assert_eq!(resumed.state, TransferState::Initiating);
    assert_eq!(resumed.upload_id, None, "the id never became durable");

    let out = rig.driver().run(&mut resumed).await.expect("resume");
    assert_eq!(out.state, TransferState::Committed);
    assert_eq!(
        rig.adapter.aborts().len(),
        1,
        "the orphan must be aborted, so abandoned multiparts stop accruing cost"
    );
    assert_eq!(
        rig.adapter.live_upload_count(),
        0,
        "nothing is left dangling once the transfer commits"
    );
}

/// Window 3 — the completion succeeded and its response was lost.
#[tokio::test]
async fn a_lost_completion_response_resolves_by_head_plus_full_hash() {
    let rig = Rig::new(false);
    rig.adapter.set_faults(Faults {
        lose_complete_response: true,
        ..Faults::default()
    });

    let mut s = rig.session();
    rig.driver()
        .run(&mut s)
        .await
        .expect_err("the completion response is lost");

    let resumed_state = rig.reload().await;
    assert_eq!(
        resumed_state.state,
        TransferState::Completing,
        "`Completing` must be durable BEFORE the call, or the ambiguity is unrecoverable"
    );

    let mut resumed = rig.reload().await;
    let out = rig.driver().run(&mut resumed).await.expect("resume");
    assert_eq!(out.state, TransferState::Committed);
    assert!(
        out.resolved_ambiguous_completion,
        "the run must report that it resolved an ambiguous completion"
    );
    assert_eq!(
        out.parts_sent, 0,
        "the object was already complete; nothing is re-uploaded"
    );
}

/// Window 3, adversarial — the object is present but holds the wrong bytes.
///
/// This is the test that proves the resolution is HEAD **plus a full hash**
/// rather than a HEAD alone. A HEAD-only resolution would commit here.
#[tokio::test]
async fn an_ambiguous_completion_over_wrong_bytes_fails_closed() {
    let rig = Rig::new(false);
    let mut s = rig.session();
    s.state = TransferState::Completing;
    s.upload_id = Some(crate::adapter::OpaqueToken::new("stale-upload"));
    rig.store.save(&s).await.expect("seed");

    // Same length, different content: a size-checking HEAD cannot tell.
    let mut wrong = body_of(BODY);
    wrong[0] ^= 0xff;
    rig.adapter.put_raw(&rig.key, Bytes::from(wrong));

    let err = rig
        .driver()
        .run(&mut s)
        .await
        .expect_err("a same-size content replacement must be caught");
    assert!(
        matches!(err, StorageError::ContentMismatch { .. }),
        "expected a content mismatch, got {err:?}"
    );
    assert!(!err.is_retryable(), "a hash disagreement is terminal");
    assert_ne!(s.state, TransferState::Committed);
}

/// Window 4 — the provider forgot the session.
#[tokio::test]
async fn provider_session_expiry_opens_a_new_attempt_epoch() {
    let rig = Rig::new(false);
    rig.adapter.set_faults(Faults {
        expire_session_once: true,
        ..Faults::default()
    });

    let mut s = rig.session();
    let out = rig.driver().run(&mut s).await.expect("run");

    assert_eq!(out.state, TransferState::Committed);
    assert_eq!(
        s.attempt_epoch, 1,
        "losing the session must open a new attempt epoch, not retry a dead token"
    );
    assert_eq!(
        rig.adapter.object(&rig.key).expect("object").as_ref(),
        rig.source.body().as_ref()
    );
}

#[tokio::test]
async fn a_target_that_never_keeps_a_session_fails_closed() {
    let rig = Rig::new(false);
    let mut s = rig.session();
    s.attempt_epoch = DEFAULT_MAX_ATTEMPT_EPOCHS;
    s.state = TransferState::Uploading;
    s.upload_id = Some(crate::adapter::OpaqueToken::new("dead"));
    rig.store.save(&s).await.expect("seed");

    let err = rig.driver().run(&mut s).await.expect_err("must give up");
    assert!(
        err.to_string().contains("giving up"),
        "a permanently-expiring target must stop, not spin: {err}"
    );
}

/// The source is DELETED mid-transfer, not edited — and the provider session
/// still has to be reaped.
///
/// A missing source used to be classified transient, so the fingerprint gate
/// returned it directly: the queue spent its whole attempt budget on a file
/// that was never coming back, marked the job failed, and left the transfer
/// `Uploading` with its multipart parts allocated. Nothing revisits a key whose
/// source no longer exists, so those parts accrued storage until the bucket's
/// own lifecycle rules noticed — if it had any.
///
/// Distinct from the edited-source test below: that one has a fingerprint to
/// compare and fails on the comparison. This one never gets a fingerprint at
/// all, which is the path that bypassed `abandon`.
#[tokio::test]
async fn a_source_deleted_between_attempts_abandons_its_provider_session() {
    let rig = Rig::new(false);
    let mut s = rig.session();

    rig.store.die_at_save(4);
    rig.driver().run(&mut s).await.expect_err("must die");

    // The user deletes the file while the daemon is down.
    rig.source.vanish();

    rig.store.revive();
    let mut resumed = rig.reload().await;
    // Precondition: there really is a session at the provider to leak.
    assert_eq!(
        rig.adapter.live_upload_count(),
        1,
        "this test is about reaping a live session; without one it proves nothing"
    );

    let err = rig
        .driver()
        .run(&mut resumed)
        .await
        .expect_err("a source that is gone cannot be uploaded");
    assert!(
        matches!(err, StorageError::NotFound { .. }),
        "a deleted source must be terminal, not a transient the queue retries \
         five times: {err:?}"
    );
    assert!(!err.is_retryable());

    assert_eq!(
        resumed.state,
        TransferState::Aborted(AbortOutcome::Clean),
        "the session must be abandoned where the failure is detected; nothing \
         later revisits a key whose source no longer exists"
    );
    assert_eq!(
        rig.adapter.live_upload_count(),
        0,
        "and the abandonment has to reach the provider"
    );
}

/// The source is deleted BETWEEN the fingerprint gate and a part read.
///
/// The gate runs once, before the first part. A deletion landing after it is
/// first observed in `read_range` — and on a job's final attempt there is no
/// later fingerprint call to reach `abandon` through, so the error returned
/// directly and the session stayed `Uploading` with its parts allocated.
///
/// Distinct from `a_source_deleted_between_attempts_abandons_its_provider_session`,
/// which never gets past the gate. This one passes the gate and dies mid-read,
/// which is the path that had no abandonment.
#[tokio::test]
async fn a_source_deleted_mid_read_abandons_its_provider_session() {
    let rig = Rig::new(false);
    let mut s = rig.session();

    // Let the transfer get as far as having a live provider session.
    rig.store.die_at_save(4);
    rig.driver().run(&mut s).await.expect_err("must die");
    rig.store.revive();
    let mut resumed = rig.reload().await;
    assert_eq!(
        rig.adapter.live_upload_count(),
        1,
        "precondition: there is a session to leak"
    );

    // Past the gate, then gone: the fingerprint still answers, the reads do
    // not. That is exactly the window the gate cannot cover.
    rig.source.vanish_after_fingerprint();

    let err = rig
        .driver()
        .run(&mut resumed)
        .await
        .expect_err("a source that vanishes mid-read cannot be uploaded");
    assert!(
        matches!(err, StorageError::NotFound { .. }),
        "a deleted source must be terminal wherever it is first seen: {err:?}"
    );
    assert_eq!(
        resumed.state,
        TransferState::Aborted(AbortOutcome::Clean),
        "the read path is the last place this can be caught on a final attempt"
    );
    assert_eq!(rig.adapter.live_upload_count(), 0);
}

/// The source is TRUNCATED mid-read, and the session is still reaped.
///
/// `read_exact` reported a concurrent truncation as `UnexpectedEof`, an
/// ordinary retryable I/O kind — so the driver returned before `abandon` and,
/// on a final attempt, left the transfer `Uploading` with its parts allocated.
/// The driver's own short-body branch exists to abandon exactly this and was
/// unreachable, because `read_exact` never returns a short buffer.
///
/// So the read returns what is left and the branch decides. This test is what
/// makes that branch reachable at all.
#[tokio::test]
async fn a_source_truncated_mid_read_abandons_its_provider_session() {
    let rig = Rig::new(false);
    let mut s = rig.session();

    rig.store.die_at_save(4);
    rig.driver().run(&mut s).await.expect_err("must die");
    rig.store.revive();
    let mut resumed = rig.reload().await;
    assert_eq!(
        rig.adapter.live_upload_count(),
        1,
        "precondition: there is a session to leak"
    );

    // Shorter, but still present and still fingerprinting — the fingerprint is
    // taken from the source itself, so the gate sees the new length and the
    // PLAN does not. The read is where the disagreement shows up.
    rig.source.truncate_to(BODY / 2);

    let err = rig
        .driver()
        .run(&mut resumed)
        .await
        .expect_err("a source that shrank cannot satisfy the plan");
    assert!(!err.is_retryable(), "a truncation is terminal: {err:?}");
    assert_eq!(
        resumed.state,
        TransferState::Aborted(AbortOutcome::Clean),
        "the short read must reach the abandonment branch"
    );
    assert_eq!(rig.adapter.live_upload_count(), 0);
}

/// PM-1 — the user edits the file while it is being uploaded.
#[tokio::test]
async fn a_source_that_changes_between_attempts_aborts_rather_than_splicing() {
    let rig = Rig::new(false);
    let mut s = rig.session();

    rig.store.die_at_save(4);
    rig.driver().run(&mut s).await.expect_err("must die");

    // The user saves the file while the daemon is down.
    let mut edited = body_of(BODY);
    edited[35] ^= 0xff;
    rig.source.mutate(edited);

    rig.store.revive();
    let mut resumed = rig.reload().await;
    let err = rig
        .driver()
        .run(&mut resumed)
        .await
        .expect_err("a mutated source must not be spliced with pre-crash parts");
    assert!(
        matches!(err, StorageError::ContentMismatch { .. }),
        "expected the fingerprint gate to fire, got {err:?}"
    );
    assert_ne!(resumed.state, TransferState::Committed);

    // And the provider session it had been filling is ABANDONED, not merely
    // left behind. This mismatch is terminal — replanning the edited file picks
    // a different content-addressed key, so no `adopt_or_reap` visit ever
    // reaches this one again — and the parts already uploaded would otherwise
    // accrue storage until the bucket's lifecycle rules noticed.
    //
    // The read-stream hash at the END of `upload_pending` already abandoned;
    // this is the fingerprint gate at the TOP of it, which returned directly
    // and never reached that code.
    assert_eq!(
        resumed.state,
        TransferState::Aborted(AbortOutcome::Clean),
        "a terminal source mismatch must abandon its multipart session wherever it is \
         detected, not only at the last of the two places that detect it"
    );
    assert_eq!(
        rig.adapter.live_upload_count(),
        0,
        "and the abandonment has to reach the provider"
    );
}

#[test]
fn the_transition_table_is_closed_against_illegal_moves() {
    use TransferState::{
        AbortPending, Aborted, Committed, Completing, Initiating, Planned, Uploading, Verifying,
    };

    // Legal.
    assert!(Planned.can_advance_to(Initiating));
    assert!(Initiating.can_advance_to(Uploading));
    assert!(Uploading.can_advance_to(Completing));
    assert!(Completing.can_advance_to(Verifying));
    assert!(Verifying.can_advance_to(Committed));
    assert!(Uploading.can_advance_to(Uploading), "resume is re-entrant");
    assert!(Uploading.can_advance_to(Initiating), "window 4 restart");
    assert!(Completing.can_advance_to(Initiating), "window 4 restart");
    assert!(AbortPending.can_advance_to(Aborted(AbortOutcome::Clean)));

    // Illegal — the ones that would skip a durability point.
    assert!(
        !Planned.can_advance_to(Uploading),
        "must persist Initiating first"
    );
    assert!(
        !Uploading.can_advance_to(Verifying),
        "verification may not skip the completion record"
    );
    assert!(
        !Completing.can_advance_to(Committed),
        "AC-1's full re-read may never be skipped"
    );
    assert!(!Verifying.can_advance_to(Uploading));

    // Terminal states are terminal, including for abort requests.
    for t in [
        Committed,
        Aborted(AbortOutcome::Clean),
        Aborted(AbortOutcome::Ambiguous),
    ] {
        assert!(t.is_terminal());
        assert!(!t.can_advance_to(Initiating));
        assert!(!t.can_advance_to(AbortPending));
    }
    // Abort may be requested from any live state.
    for t in [Planned, Initiating, Uploading, Completing, Verifying] {
        assert!(t.can_advance_to(AbortPending), "{t:?} must be abortable");
    }
}

#[tokio::test]
async fn an_abort_that_the_provider_did_not_confirm_is_recorded_as_ambiguous() {
    let rig = Rig::new(false);
    let mut s = rig.session();
    // Nothing was ever created remotely, so the abort is trivially clean.
    s.state = TransferState::AbortPending;
    rig.store.save(&s).await.expect("seed");
    let out = rig.driver().run(&mut s).await.expect("abort");
    assert_eq!(out.state, TransferState::Aborted(AbortOutcome::Clean));
}

/// **A freshly registered S3 target must be able to finish an upload.**
///
/// `target.add` now probes for a whole-object checksum and adopts one at
/// registration, so "the session carries a checksum algorithm" is not a corner
/// case — it is what a newly registered target produces. In that configuration
/// `upload_part` returns a per-part checksum and `complete_multipart` requires
/// it echoed back: MinIO answers `InvalidPart` otherwise, which
/// `S3Adapter::complete_multipart` records verbatim.
///
/// No crash, no restart, no fault injection. This is the ordinary happy path on
/// the configuration the probe hands back.
#[tokio::test]
async fn a_checksum_enabled_session_completes_without_any_restart() {
    let rig = Rig::new(false);
    rig.adapter.require_part_checksums();
    let mut s = rig.session();

    let out = rig
        .driver()
        .run(&mut s)
        .await
        .expect("a session on a successfully probed target must complete");

    assert_eq!(out.state, TransferState::Committed);
    assert_eq!(out.parts_sent, 4);
    assert_eq!(
        rig.adapter.object(&rig.key).expect("object").as_ref(),
        rig.source.body().as_ref(),
        "the assembled object must be byte-identical to the source"
    );
}

/// **A checkpoint that carries no checksum must be healed, not trusted and not
/// re-sent.**
///
/// Two things produce exactly this shape and neither is hypothetical: a
/// checkpoint serialized before the `checksum` field existed, and a durable
/// store whose `transfer_part` table has no column for it. Both read back with
/// the ETag intact and the checksum absent.
///
/// Trusting it means completing with `checksum: None` on a checksum-enabled
/// session, which the provider rejects — the original bug, surviving a restart.
/// Refusing to skip it means re-uploading every part on every resume against
/// any provider that reports per-part checksums, which is AC-2's failure
/// condition. Neither is acceptable, so the driver adopts the provider's own
/// value for a part whose ETag and length already agree.
#[tokio::test]
async fn a_resume_heals_checkpoints_that_carry_no_checksum() {
    let rig = Rig::new(false);
    rig.adapter.require_part_checksums();
    let mut s = rig.session();

    // Same kill point as AC-2: parts 1 and 2 durably acknowledged.
    rig.store.die_at_save(5);
    let err = rig.driver().run(&mut s).await.expect_err("must die");
    assert!(err.is_retryable(), "a lost write is transient: {err}");

    // --- restart, through a store that never had a checksum column ---
    rig.store.revive();
    let mut resumed = rig.reload().await;
    for p in &mut resumed.parts {
        p.checksum = None;
    }
    assert_eq!(
        resumed.parts.iter().filter(|p| p.is_acknowledged()).count(),
        2,
        "the ETags survived; only the checksums were never stored"
    );

    let out = rig
        .driver()
        .run(&mut resumed)
        .await
        .expect("a resume must not be blocked by a checksum the store could not hold");

    assert_eq!(out.state, TransferState::Committed);
    assert_eq!(
        out.bytes_skipped,
        2 * PART,
        "the two acknowledged parts must still be skipped — re-sending them is the AC-2 \
         regression this fix must not buy"
    );
    assert!(
        resumed
            .parts
            .iter()
            .filter(|p| p.is_acknowledged())
            .all(|p| p.checksum.is_some()),
        "every acknowledged part must end up holding the provider's checksum: {:?}",
        resumed.parts
    );
    assert_eq!(
        rig.adapter.object(&rig.key).expect("object").as_ref(),
        rig.source.body().as_ref()
    );
}

/// **The heal is observable where it matters: in what completion was sent.**
///
/// `a_resume_heals_checkpoints_that_carry_no_checksum` asserts the resume
/// commits, which a fake could satisfy by being lenient. The failure being
/// guarded against is `CompleteMultipartUpload` refusing a resumed
/// checksum-enabled session, so the load-bearing claim is about the receipts
/// completion was handed — specifically that a part which was **skipped**
/// rather than re-sent still carried the provider's own checksum back.
#[tokio::test]
async fn a_healed_resume_echoes_the_providers_checksum_for_parts_it_skipped() {
    let rig = Rig::new(false);
    rig.adapter.require_part_checksums();
    let mut s = rig.session();

    rig.store.die_at_save(5);
    rig.driver().run(&mut s).await.expect_err("must die");
    rig.store.revive();

    let mut resumed = rig.reload().await;
    // A store with no checksum column returns exactly this.
    for p in &mut resumed.parts {
        p.checksum = None;
    }

    // What the provider itself holds for the parts that survived the crash.
    let upload = resumed.upload_id.clone().expect("a live provider session");
    let held = rig
        .adapter
        .list_parts(&rig.key, &upload)
        .await
        .expect("list_parts");
    let expected: Vec<(u32, Option<String>)> = held
        .iter()
        .map(|r| (r.part_no, r.checksum.clone()))
        .collect();
    assert!(
        expected.iter().all(|(_, c)| c.is_some()),
        "the fixture is only meaningful if the provider reports checksums: {expected:?}"
    );

    let out = rig.driver().run(&mut resumed).await.expect("resume");
    assert_eq!(out.state, TransferState::Committed);
    assert_eq!(
        out.bytes_skipped,
        2 * PART,
        "the healed parts must have been SKIPPED — a re-send would supply the checksum \
         trivially and prove nothing"
    );

    let sent = rig.adapter.completion_receipts();
    assert_eq!(sent.len(), 4);
    for (part_no, provider_value) in expected {
        let r = sent
            .iter()
            .find(|r| r.part_no == part_no)
            .expect("every part must appear in the completion");
        assert_eq!(
            r.checksum, provider_value,
            "part {part_no} was skipped, so its completion receipt can only carry a checksum \
             the resume adopted from the provider — and it must be the provider's own value"
        );
    }
}

// ---------------------------------------------------------------------------
// PM-1, the sharper form: the source moves *while* the parts are being read.
//
// The fingerprint gate at the top of `upload_pending` runs once, before any
// part is read. Everything below is about the window it does not cover, and
// the assertion that matters in every one of them is about the REMOTE OBJECT,
// not about the error value: pre-fix these paths also return
// `ContentMismatch` — from `verify()`, after `complete_multipart` has already
// published the mixed bytes under an immutable content-addressed key that no
// retry can replace. Same error, opposite outcome. Only `adapter.object()` and
// the persisted state tell the two apart.
// ---------------------------------------------------------------------------

/// A source that edits itself in place between two part reads.
struct EditsBetweenReads {
    inner: MemSource,
    /// Apply the edit once this many `read_range` calls have completed.
    edit_after_read: usize,
    reads: std::sync::Mutex<usize>,
    replacement: Vec<u8>,
}

impl EditsBetweenReads {
    fn new(body: Vec<u8>, edit_after_read: usize, replacement: Vec<u8>) -> Self {
        Self {
            inner: MemSource::new(body),
            edit_after_read,
            reads: std::sync::Mutex::new(0),
            replacement,
        }
    }
}

#[async_trait::async_trait]
impl SourceReader for EditsBetweenReads {
    async fn fingerprint(&self) -> StorageResult<SourceFingerprint> {
        self.inner.fingerprint().await
    }

    async fn read_range(&self, range: ByteRange) -> StorageResult<Bytes> {
        let body = self.inner.read_range(range).await?;
        let mut n = self.reads.lock().expect("poisoned");
        *n += 1;
        if *n == self.edit_after_read {
            self.inner
                .mutate_preserving_fingerprint(self.replacement.clone());
        }
        Ok(body)
    }
}

/// PM-1 — the edit lands after the gate, between two part reads.
///
/// Parts 1 and 2 carry the original bytes, parts 3 and 4 carry the edited
/// ones, and no such file ever existed on disk. Nothing may be published.
#[tokio::test]
async fn a_source_edited_between_part_reads_publishes_nothing() {
    let rig = Rig::new(false);
    let mut s = rig.session();

    let mut edited = body_of(BODY);
    edited[35] ^= 0xff; // inside part 4, read after the edit lands
    let src = EditsBetweenReads::new(body_of(BODY), 2, edited.clone());

    let mut d = TransferDriver::new(&rig.adapter, &rig.store, &src);
    d.verify_chunk = PART;
    let err = d
        .run(&mut s)
        .await
        .expect_err("an object spliced from two different files must not be published");

    assert!(
        rig.adapter.object(&rig.key).is_none(),
        "the key is content-addressed and immutable: publishing mixed bytes under it \
         poisons it for every future retry. Published {:?}",
        rig.adapter.object(&rig.key)
    );
    assert!(
        matches!(err, StorageError::ContentMismatch { .. }),
        "expected the read-stream hash to fail closed, got {err:?}"
    );

    // The session is FINISHED, not merely stopped before `Completing`.
    //
    // This mismatch is terminal — replanning the changed file picks a different
    // content-addressed key, so nothing ever revisits this one — and the parts
    // already uploaded would otherwise accrue storage until the bucket's
    // lifecycle rules noticed. `Uploading` was the old assertion and it only
    // said the run had not gone too far; it did not say the multipart session
    // had been cleaned up, and it had not been.
    assert_eq!(
        s.state,
        TransferState::Aborted(AbortOutcome::Clean),
        "a terminal source mismatch must abandon its multipart session, not leave it \
         mid-flight for nobody to collect"
    );
    assert_eq!(
        rig.adapter.live_upload_count(),
        0,
        "and the abandonment has to reach the provider, not just the state machine"
    );
}

/// The accepting direction, and the reason the check is a hash and not a stat.
///
/// The edit lands after part 1 was already read and sent, and touches only
/// part 1's own range — so the bytes that actually went to the provider are
/// exactly the planned bytes, and the transfer is correct. A post-read
/// re-`stat` would refuse this; hashing what was read accepts it.
#[tokio::test]
async fn an_edit_confined_to_an_already_uploaded_range_still_commits() {
    let rig = Rig::new(false);
    let mut s = rig.session();

    let mut edited = body_of(BODY);
    edited[3] ^= 0xff; // inside part 1, which has already been read
    let src = EditsBetweenReads::new(body_of(BODY), 1, edited);

    let mut d = TransferDriver::new(&rig.adapter, &rig.store, &src);
    d.verify_chunk = PART;
    let out = d
        .run(&mut s)
        .await
        .expect("the uploaded bytes are the planned bytes");

    assert_eq!(out.state, TransferState::Committed);
    assert_eq!(
        rig.adapter.object(&rig.key).expect("object").as_ref(),
        body_of(BODY).as_slice(),
        "the published object must be the planned content"
    );
}

/// A resume must prove the parts an EARLIER attempt uploaded still match the
/// source, not merely that the source is intact now.
///
/// The first attempt reads a file that has been edited in place without
/// disturbing size, mtime or `fs_id`, so its fingerprint gate passes and parts
/// 1 and 2 land carrying the edited bytes. The file is then restored. The
/// resume now sees a source that fingerprints correctly AND hashes to the
/// planned value — every whole-file check passes — while parts 1 and 2 on the
/// provider are still the edited bytes. `PartCheckpoint::local_blake3` is the
/// only record that can tell, which is exactly what its doc comment says it is
/// for.
#[tokio::test]
async fn a_resume_refuses_to_complete_over_parts_an_earlier_attempt_mis_uploaded() {
    let rig = Rig::new(false);
    let mut s = rig.session();
    let planned = body_of(BODY);

    // The edit is invisible to the stat and lands in part 1.
    let mut edited = planned.clone();
    edited[3] ^= 0xff;
    rig.source.mutate_preserving_fingerprint(edited);

    // Saves: 1 = Initiating, 2 = Uploading, 3 = part1, 4 = part2, 5 = part3.
    rig.store.die_at_save(5);
    rig.driver().run(&mut s).await.expect_err("must die");

    // The user restores the file before the daemon comes back.
    rig.source.mutate_preserving_fingerprint(planned.clone());
    rig.store.revive();

    let mut resumed = rig.reload().await;
    assert_eq!(
        resumed.parts.iter().filter(|p| p.is_acknowledged()).count(),
        2,
        "two parts were durably acknowledged, and both carry the edited bytes"
    );

    let err =
        rig.driver().run(&mut resumed).await.expect_err(
            "parts uploaded from content that is no longer on disk must not be completed",
        );

    assert!(
        rig.adapter.object(&rig.key).is_none(),
        "nothing may be published: the object would be edited parts 1-2 spliced onto \
         planned parts 3-4. Published {:?}",
        rig.adapter.object(&rig.key)
    );
    // Not merely "before `Completing`" — FINISHED. The mismatch is terminal, so
    // the session is abandoned and its provider-side parts released; leaving it
    // in `Uploading` was the state a session accrues storage in forever,
    // because replanning the edited file picks a different content-addressed
    // key and nothing revisits this one.
    assert_eq!(
        resumed.state,
        TransferState::Aborted(AbortOutcome::Clean),
        "a terminal mismatch inside the part loop must abandon its session too"
    );
    assert_eq!(
        rig.adapter.live_upload_count(),
        0,
        "and the abandonment has to reach the provider"
    );
    assert!(
        matches!(err, StorageError::ContentMismatch { .. }),
        "expected the per-part local hash to fail closed, got {err:?}"
    );
}
