//! The `transfer_session` durable state machine (§4.5).
//!
//! # Why this is a state machine and not a row
//!
//! §4.4 sketches `transfer_part(job_id, upload_id, part_no, etag, bytes,
//! verified_at)`. That row records what was uploaded; it does not record
//! **what the daemon was in the middle of doing when it died**, and those are
//! different questions. A crash between "the provider created the session" and
//! "the database learned the session id" leaves no `transfer_part` row at all,
//! yet leaves a live, billable multipart upload on the provider. A row cannot
//! express that; a persisted state can.
//!
//! So the unit of durability is the whole session:
//! `Planned → Initiating → Uploading → Completing → Verifying → Committed`,
//! plus `AbortPending → Aborted`.
//!
//! # The four crash windows, and where each is closed
//!
//! | # | Window | Closed by |
//! |---|---|---|
//! | 1 | Remote session created before the DB commit | `Initiating` is persisted **before** `create_multipart`. On resume, [`TransferDriver::adopt_or_reap`] lists live uploads at the key and aborts the orphans before starting a new one |
//! | 2 | Part uploaded before the checkpoint commit | [`crate::multipart::reconcile_parts`] — a part is skipped only when the durable checkpoint *and* the provider agree on the opaque token and the length |
//! | 3 | Completion succeeded, its response was lost | `Completing` is persisted **before** `complete_multipart`. On resume, an ambiguous completion is resolved by HEAD **plus a full BLAKE3 re-read** — never by the HEAD alone |
//! | 4 | Provider session expiry | [`StorageError::NoSuchUpload`] is a distinguishable variant. It bumps `attempt_epoch`, clears the token and every part receipt, and re-enters `Initiating` |
//!
//! # Ordering rule
//!
//! Every state is persisted **before** the side effect it authorizes, never
//! after. That is the same discipline §4.10.4 applies to the destroy path, for
//! the same reason: a record written after its effect cannot describe a crash
//! that happened in between, and the recovery code then has nothing to read.
//!
//! # The source is proved three times, and each proof answers a different question
//!
//! `SourceIdentity` persists size, mtime, `fs_id` and the BLAKE3 the transfer
//! was planned against. PM-1's modify-during-upload race would otherwise splice
//! pre-crash parts and post-crash parts into a single object that never existed
//! on disk, so:
//!
//! 1. **The fingerprint**, before a single byte is read. Cheap, and it refuses
//!    to read anything out of a file that has obviously moved. It is also the
//!    weakest: it runs once, so an edit landing *between* two part reads sails
//!    past it, and an in-place edit that restores the mtime leaves it nothing
//!    to see at all.
//! 2. **The read-stream hash**, in `TransferDriver::upload_pending`, before
//!    `Completing`. Every part is read in ascending order into one hasher and
//!    the result must equal the planned BLAKE3; a part being *skipped* is
//!    instead matched against the [`crate::multipart::PartCheckpoint`]
//!    `local_blake3` an earlier attempt recorded for it. Together those say the
//!    bytes the provider holds are the planned bytes.
//! 3. **The full remote BLAKE3 re-read** in `Verifying`. Authoritative, and the
//!    only one that can speak for what the provider actually stored.
//!
//! The middle one is not redundant with the third, and the reason is the whole
//! shape of this module: `Verifying` runs *after* `complete_multipart` has
//! published the object under a content-addressed, **immutable** key. A key
//! that cannot be rewritten cannot be repaired — the session sticks in
//! `Verifying` and every retry rediscovers the same poisoned object. So the
//! last moment a wrong object can still be *refused* rather than merely
//! *detected* is before completion, and refusing there requires a local proof.
//!
//! What it costs is close to nothing. A fresh upload hashes the bytes it was
//! already reading. A resume additionally re-reads the ranges it is skipping —
//! one local pass, strictly cheaper than the full *remote* re-read step 3
//! performs unconditionally. AC-2 is untouched either way: it measures parts
//! re-**sent**, and no skipped part is re-sent.

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use shepherd_core::{
    Blake3Hash, FileId, FsId, JobId, ObjectKey, ObjectVersion, TargetId, Timestamp,
};

use crate::adapter::{
    AttestationMode, ByteRange, CreatePrecondition, OpaqueToken, PartReceipt, StorageAdapter,
    StorageError, StorageResult, verify_full_content,
};
use crate::multipart::{
    DEFAULT_PART_SIZE, PartAction, PartCheckpoint, PartPlan, Reconciliation, reconcile_parts,
};

/// How a session ended once an abort was requested.
///
/// The plan calls these `aborted-clean` and `aborted-ambiguous`; the two are
/// kept distinct because they mean different things to the reaper. `Clean` says
/// the provider confirmed the session is gone. `Ambiguous` says Shepherd asked
/// and does not know, so residue may still be accruing storage cost and a
/// sweep must revisit the prefix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbortOutcome {
    Clean,
    Ambiguous,
}

/// The durable state of a transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransferState {
    Planned,
    Initiating,
    Uploading,
    Completing,
    Verifying,
    Committed,
    /// The intent to abort, persisted before the abort call — so a crash
    /// mid-abort is still recoverable as an abort rather than resuming an
    /// upload the system already decided to stop.
    AbortPending,
    Aborted(AbortOutcome),
}

impl TransferState {
    /// Whether `next` is a legal successor.
    ///
    /// Written as an explicit table rather than as scattered `if` statements so
    /// that "can a committed session go back to uploading?" has exactly one
    /// answer, in one place, that a test can enumerate.
    pub fn can_advance_to(self, next: TransferState) -> bool {
        use TransferState::{
            AbortPending, Aborted, Committed, Completing, Initiating, Planned, Uploading, Verifying,
        };
        // Abort may be requested from any live state.
        if next == AbortPending {
            return !self.is_terminal();
        }
        match (self, next) {
            (Planned, Initiating) => true,
            (Initiating, Uploading) => true,
            // Re-entrant: resume re-enters Uploading to send the remaining parts.
            (Uploading, Uploading | Completing) => true,
            // Window 4 — the provider forgot the session. A new attempt epoch
            // restarts from Initiating rather than retrying a dead token.
            (Uploading | Completing, Initiating) => true,
            (Completing, Verifying) => true,
            (Verifying, Committed) => true,
            (AbortPending, Aborted(_)) => true,
            _ => false,
        }
    }

    /// Terminal states accept no further transition.
    pub fn is_terminal(self) -> bool {
        matches!(self, TransferState::Committed | TransferState::Aborted(_))
    }
}

/// The cheap, non-hashing part of a source file's identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceFingerprint {
    pub size: u64,
    pub mtime: Timestamp,
    /// §4.4: OS-level identity, never `st_dev`.
    pub fs_id: FsId,
}

/// Who the bytes belong to, pinned when the transfer was planned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceIdentity {
    pub file_id: FileId,
    pub rel_path: String,
    pub size: u64,
    pub mtime: Timestamp,
    /// The identity **derived from the statted file**, not the one the caller
    /// planned with.
    ///
    /// These are usually equal and are not the same thing, which is why the
    /// distinction is written down. `upload.rs::fingerprint` used to copy the
    /// caller's catalog `fs_id` into every fresh fingerprint while statting the
    /// size and mtime — so `assert_source_unchanged` compared the expected value
    /// with itself and could never fail. A path swapped to a different inode
    /// with the same size and preserved mtime sailed through, and the wrong
    /// bytes completed under a key naming the right hash.
    ///
    /// The **lock** key is the other one: `acquire_both` still takes the
    /// caller's catalog `fs_id`, for the reason `LocalDestroyRequest::fs_id`
    /// spells out. Two identities, two purposes; do not collapse them.
    pub fs_id: FsId,
    /// The hash the transfer was planned against. The uploaded object must
    /// read back as exactly this.
    pub blake3: Blake3Hash,
}

impl SourceIdentity {
    pub fn fingerprint(&self) -> SourceFingerprint {
        SourceFingerprint {
            size: self.size,
            mtime: self.mtime,
            fs_id: self.fs_id.clone(),
        }
    }
}

/// Everything a resumed transfer needs that it cannot recompute.
///
/// This is the shape `shepherd-catalog` must persist. It is deliberately larger
/// than §4.4's `transfer_part`: source identity/hash/size, target and remote
/// key, the provider token, the part plan, the attempt epoch, per-part offsets
/// and local hashes, and the final manifest hash.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransferSession {
    pub job_id: JobId,
    pub target: TargetId,
    /// Content-addressed per §4.9 — never path-derived.
    pub remote_key: ObjectKey,
    pub source: SourceIdentity,
    pub state: TransferState,
    pub plan: PartPlan,
    /// Incremented every time the provider session is abandoned. Keeps the
    /// checkpoints of a dead session from being mistaken for a live one.
    pub attempt_epoch: u32,
    /// The provider's session token. Opaque (§4.5).
    pub upload_id: Option<OpaqueToken>,
    pub parts: Vec<PartCheckpoint>,
    /// BLAKE3 of the §4.10.6 restore-fidelity sidecar manifest, once written.
    pub manifest_blake3: Option<Blake3Hash>,
    /// Recorded per target at registration (§4.10.2) and stamped onto the
    /// session so the audit record says which mechanism authorized it.
    pub attestation_mode: Option<AttestationMode>,
    /// Pinned at verify under mechanism A.
    pub object_version: Option<ObjectVersion>,
}

impl TransferSession {
    /// A fresh session for `source` at `remote_key`.
    ///
    /// `preferred_part_size` is a hint — [`PartPlan::new`] clamps it into the
    /// provider's legal band and grows it if the object would otherwise exceed
    /// the part-number ceiling. [`DEFAULT_PART_SIZE`] is the ordinary argument;
    /// it is a parameter because part size is a real per-target tuning knob
    /// (a LAN NAS and a metered WAN link do not want the same one) and because
    /// the plan is persisted, so it must be chosen once and then honoured by
    /// every resume.
    pub fn plan(
        job_id: JobId,
        target: TargetId,
        remote_key: ObjectKey,
        source: SourceIdentity,
        adapter: &dyn StorageAdapter,
        preferred_part_size: u64,
    ) -> StorageResult<Self> {
        let plan = PartPlan::new(source.size, adapter.capabilities(), preferred_part_size)?;
        Ok(Self {
            job_id,
            target,
            remote_key,
            source,
            state: TransferState::Planned,
            plan,
            attempt_epoch: 0,
            upload_id: None,
            parts: Vec::new(),
            manifest_blake3: None,
            attestation_mode: None,
            object_version: None,
        })
    }

    fn checkpoint_mut(&mut self, part_no: u32) -> &mut PartCheckpoint {
        if let Some(i) = self.parts.iter().position(|p| p.part_no == part_no) {
            &mut self.parts[i]
        } else {
            self.parts.push(PartCheckpoint {
                part_no,
                offset: 0,
                len: 0,
                local_blake3: Blake3Hash::from_bytes([0u8; 32]),
                etag: None,
                checksum: None,
            });
            self.parts.last_mut().expect("just pushed")
        }
    }

    /// Provider receipts for every acknowledged part, in ascending part order.
    ///
    /// The checkpoint's checksum is carried, not dropped.
    /// `CompleteMultipartUpload` requires each part to echo back the checksum
    /// the provider issued once the session was created with an algorithm —
    /// `S3Adapter::complete_multipart` says so, and MinIO answers `InvalidPart`
    /// when it is absent. Reconstructing these with `checksum: None` made every
    /// upload to a successfully probed target fail at completion.
    fn acknowledged_receipts(&self) -> Vec<PartReceipt> {
        let mut v: Vec<PartReceipt> = self
            .parts
            .iter()
            .filter_map(|p| {
                p.etag.as_ref().map(|e| PartReceipt {
                    part_no: p.part_no,
                    size: p.len,
                    etag: e.clone(),
                    checksum: p.checksum.clone(),
                })
            })
            .collect();
        v.sort_by_key(|p| p.part_no);
        v
    }

    /// Abandon the provider session and start a new attempt epoch.
    ///
    /// Every part receipt is dropped: the receipts were issued by a session the
    /// provider no longer knows, so they prove nothing about the new one. That
    /// includes the checksum — it is the provider's value for a part in a
    /// session that no longer exists, and echoing it back at the next
    /// completion would be quoting a receipt from a different upload.
    fn restart_attempt(&mut self) {
        self.attempt_epoch = self.attempt_epoch.saturating_add(1);
        self.upload_id = None;
        for p in &mut self.parts {
            p.etag = None;
            p.checksum = None;
        }
        self.state = TransferState::Initiating;
    }
}

/// Durable storage for [`TransferSession`], implemented by `shepherd-catalog`.
///
/// **Contract:** `save` must not return until the record is durable. The whole
/// state machine rests on "the state was persisted before the side effect it
/// authorizes", and a `save` that returns while the write sits in a page cache
/// makes every ordering guarantee in this module a comment rather than a fact.
#[async_trait::async_trait]
pub trait TransferSessionStore: Send + Sync {
    async fn save(&self, session: &TransferSession) -> StorageResult<()>;

    /// Checkpoint the ONE part that just changed.
    ///
    /// `upload_pending` calls this after every acknowledged part, so its cost
    /// is paid `part_count` times per transfer. A whole-session `save` there is
    /// quadratic: the store replaces the entire accumulated part set on each
    /// call, so a 3,200-part 50 GB upload performs about 5.1 million part
    /// inserts to record 3,200 events, and the checkpoint work can outweigh the
    /// transfer it is checkpointing.
    ///
    /// The default is a full `save`, which is correct and merely slow — a store
    /// with nothing cheaper does not have to implement this, and no store can
    /// be wrong by not implementing it.
    ///
    /// Wholesale replacement still belongs to `save`: `restart_attempt` clears
    /// every receipt, and a partial write there would leave receipts from a
    /// provider session that no longer exists, which resume would trust.
    async fn save_part(&self, session: &TransferSession, part_no: u32) -> StorageResult<()> {
        let _ = part_no;
        self.save(session).await
    }

    async fn load(&self, job_id: JobId) -> StorageResult<Option<TransferSession>>;
}

/// Reads the local file being transferred.
///
/// A port rather than direct `tokio::fs` use, so the crash-window tests can
/// drive the state machine deterministically — including the case where the
/// source mutates between attempts, which is not reproducible on a real
/// filesystem on demand.
#[async_trait::async_trait]
pub trait SourceReader: Send + Sync {
    async fn fingerprint(&self) -> StorageResult<SourceFingerprint>;
    async fn read_range(&self, range: ByteRange) -> StorageResult<Bytes>;
}

/// What a completed run did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransferOutcome {
    pub state: TransferState,
    pub bytes_uploaded: u64,
    pub bytes_skipped: u64,
    pub parts_sent: u32,
    /// True when the run resolved a lost completion response (window 3) rather
    /// than completing normally. Surfaced because it is the case that costs a
    /// full object re-read, so it should be visible in metrics rather than
    /// silently expensive.
    pub resolved_ambiguous_completion: bool,
}

/// Drives a [`TransferSession`] to `Committed`.
pub struct TransferDriver<'a> {
    pub adapter: &'a dyn StorageAdapter,
    pub store: &'a dyn TransferSessionStore,
    pub source: &'a dyn SourceReader,
    /// Range size for the streaming full-content verification.
    pub verify_chunk: u64,
    /// Ceiling on provider-session restarts before the transfer fails closed.
    ///
    /// Window 4 sends the machine back to `Initiating`, so a target that
    /// expires every session it issues would otherwise spin forever, re-reading
    /// the source and re-uploading every part on each pass. A stuck transfer
    /// that reports an error is recoverable; a stuck transfer that silently
    /// burns bandwidth is not.
    pub max_attempt_epochs: u32,
}

/// Default restart ceiling. Generous enough to absorb a flaky link, small
/// enough that a misconfigured target surfaces within one job rather than
/// overnight.
pub const DEFAULT_MAX_ATTEMPT_EPOCHS: u32 = 8;

impl<'a> TransferDriver<'a> {
    pub fn new(
        adapter: &'a dyn StorageAdapter,
        store: &'a dyn TransferSessionStore,
        source: &'a dyn SourceReader,
    ) -> Self {
        Self {
            adapter,
            store,
            source,
            verify_chunk: DEFAULT_PART_SIZE,
            max_attempt_epochs: DEFAULT_MAX_ATTEMPT_EPOCHS,
        }
    }

    /// Persist `next` and only then let the caller perform its side effect.
    async fn advance(
        &self,
        session: &mut TransferSession,
        next: TransferState,
    ) -> StorageResult<()> {
        if !session.state.can_advance_to(next) {
            return Err(StorageError::Provider {
                provider: self.adapter.capabilities().provider,
                op: "transfer_session".into(),
                detail: format!("illegal transition {:?} -> {next:?}", session.state),
            });
        }
        session.state = next;
        self.store.save(session).await
    }

    /// Abandon the provider's multipart session, then return `err`.
    ///
    /// Every terminal source failure has to come through here. The mismatch is
    /// not retryable, and replanning the changed file picks a different
    /// content-addressed key — so no later `adopt_or_reap` visit ever reaches
    /// this key again and the parts already uploaded accrue storage for as long
    /// as the bucket's lifecycle rules allow, which on a 50 GB transfer is not
    /// a rounding error. Returning the error without a transition simply
    /// forgets about them.
    ///
    /// `AbortPending` is persisted BEFORE the abort is attempted, which is what
    /// makes it survive a crash in the middle: `run`'s `AbortPending` arm
    /// finishes it on the next pass, and `finish_abort` reports `Ambiguous`
    /// rather than `Clean` when it could not confirm, so a sweep revisits it.
    ///
    /// A failure to record the abandonment replaces the caller's error: the
    /// caller wanted to know the source moved, and "the session is in an
    /// unknown state" is the more urgent of the two.
    async fn abandon(&self, session: &mut TransferSession, err: StorageError) -> StorageError {
        // Already terminal, or never started: nothing to abandon.
        if !session.state.can_advance_to(TransferState::AbortPending) {
            return err;
        }
        if let Err(e) = self.advance(session, TransferState::AbortPending).await {
            return e;
        }
        let out = self.finish_abort(session).await;
        if let Err(e) = self.advance(session, TransferState::Aborted(out)).await {
            return e;
        }
        err
    }

    /// Fail closed if the source moved under us (PM-1).
    ///
    /// The caller gets the error; the provider gets the abandonment. This runs
    /// at the top of `Initiating` — before a session exists, where `abandon` is
    /// a no-op — and again at the top of `upload_pending`, where a session very
    /// much does exist and a source edited between attempts would otherwise
    /// leave it filled and forgotten.
    ///
    /// A source that **cannot be read at all** takes the same path as one that
    /// changed, and only when the failure is terminal. Both are "this transfer
    /// will never complete", and both leave a session to reap; a transient stat
    /// failure is neither, so it propagates and the session survives for the
    /// retry.
    async fn assert_source_unchanged(&self, session: &mut TransferSession) -> StorageResult<()> {
        let now = match self.source.fingerprint().await {
            Ok(f) => f,
            // Transient: the next attempt may well succeed, and the parts
            // already uploaded are worth keeping. Propagates untouched.
            Err(e) if e.is_retryable() => return Err(e),
            // TERMINAL — the source is gone or permanently unreadable, so no
            // later attempt can ever finish this transfer. Abandoned here,
            // while the session id is still in hand: returning the error
            // directly let the queue burn its attempts and mark the job failed
            // while the transfer stayed `Uploading` and its multipart parts
            // stayed allocated at the provider, with nothing that would revisit
            // the key to reap them.
            Err(e) => return Err(self.abandon(session, e).await),
        };
        if now != session.source.fingerprint() {
            let err = StorageError::ContentMismatch {
                key: session.remote_key.as_str().to_owned(),
                expected: format!("{:?}", session.source.fingerprint()),
                actual: format!("{now:?}"),
            };
            return Err(self.abandon(session, err).await);
        }
        Ok(())
    }

    /// Window 4: abandon the dead provider session, or give up if this target
    /// keeps losing them.
    async fn restart_or_fail(&self, session: &mut TransferSession) -> StorageResult<()> {
        if session.attempt_epoch >= self.max_attempt_epochs {
            return Err(StorageError::Provider {
                provider: self.adapter.capabilities().provider,
                op: "transfer_session".into(),
                detail: format!(
                    "provider discarded the upload session {} times; giving up rather than \
                     re-uploading {} bytes indefinitely",
                    session.attempt_epoch, session.source.size
                ),
            });
        }
        session.restart_attempt();
        self.store.save(session).await
    }

    /// Window 1: a previous attempt may have created a provider session whose
    /// id never reached the database. Reap those before creating a new one, so
    /// abandoned multiparts do not accrue storage cost (§4.5).
    async fn adopt_or_reap(&self, session: &TransferSession) -> StorageResult<()> {
        let live = self
            .adapter
            .list_incomplete_uploads(session.remote_key.as_str())
            .await?;
        for u in live {
            if u.key == session.remote_key {
                // Not adopted: an orphan session's parts carry opaque tokens no
                // durable checkpoint can vouch for, so adopting it would mean
                // trusting bytes we cannot attribute. Aborting is cheap; the
                // parts are re-sent under a session we know is ours.
                self.adapter.abort_multipart(&u.key, &u.upload_id).await?;
            }
        }
        Ok(())
    }

    /// Drive to a terminal state.
    pub async fn run(&self, session: &mut TransferSession) -> StorageResult<TransferOutcome> {
        let mut outcome = TransferOutcome {
            state: session.state,
            bytes_uploaded: 0,
            bytes_skipped: 0,
            parts_sent: 0,
            resolved_ambiguous_completion: false,
        };

        loop {
            match session.state {
                TransferState::Planned => {
                    self.advance(session, TransferState::Initiating).await?;
                }

                TransferState::Initiating => {
                    // REAP FIRST, then check the source. `Initiating` is
                    // already persisted, so the provider is safe to touch here
                    // — and window 1's orphan is precisely a session this
                    // process does not know the id of.
                    //
                    // The other order lost it. A crash between
                    // `create_multipart` and persisting the id leaves an
                    // untracked upload at the key; if the source then vanished,
                    // `assert_source_unchanged` abandoned the transfer,
                    // `finish_abort` had no id to abort, and `adopt_or_reap` —
                    // the only thing that could have found the orphan — was
                    // never reached. The upload stayed allocated with nothing
                    // left that would ever look for it.
                    self.adopt_or_reap(session).await?;
                    self.assert_source_unchanged(session).await?;
                    let id = self.adapter.create_multipart(&session.remote_key).await?;
                    session.upload_id = Some(id);
                    self.advance(session, TransferState::Uploading).await?;
                }

                TransferState::Uploading => {
                    match self.upload_pending(session, &mut outcome).await {
                        Ok(()) => {
                            self.advance(session, TransferState::Completing).await?;
                        }
                        Err(StorageError::NoSuchUpload { .. }) => {
                            // Window 4.
                            self.restart_or_fail(session).await?;
                        }
                        Err(e) => return Err(e),
                    }
                }

                TransferState::Completing => {
                    match self.complete(session, &mut outcome).await {
                        Ok(()) => {
                            self.advance(session, TransferState::Verifying).await?;
                        }
                        Err(StorageError::NoSuchUpload { .. }) => {
                            // Window 3, negative branch: the provider forgot the
                            // session and no object exists. Start over.
                            self.restart_or_fail(session).await?;
                        }
                        Err(e) => return Err(e),
                    }
                }

                TransferState::Verifying => {
                    self.verify(session).await?;
                    self.advance(session, TransferState::Committed).await?;
                }

                TransferState::Committed | TransferState::Aborted(_) => break,

                TransferState::AbortPending => {
                    let out = self.finish_abort(session).await;
                    self.advance(session, TransferState::Aborted(out)).await?;
                }
            }
        }

        outcome.state = session.state;
        Ok(outcome)
    }

    /// Reconcile against the provider, then send whatever is still missing.
    async fn upload_pending(
        &self,
        session: &mut TransferSession,
        outcome: &mut TransferOutcome,
    ) -> StorageResult<()> {
        self.assert_source_unchanged(session).await?;

        let upload_id = session
            .upload_id
            .clone()
            .ok_or_else(|| StorageError::NoSuchUpload {
                key: session.remote_key.as_str().to_owned(),
            })?;

        // Pagination is exhausted inside the adapter (see the trait docs) — a
        // first-page reconcile of a 3 200-part object is an AC-2 failure.
        let remote = self
            .adapter
            .list_parts(&session.remote_key, &upload_id)
            .await?;
        let recon: Reconciliation = reconcile_parts(&session.plan, &session.parts, &remote);
        outcome.bytes_skipped = recon.bytes_skipped;

        // Adopt the provider's per-part checksum for parts this resume is about
        // to skip but whose checkpoint holds none — a checkpoint written before
        // the field existed, or loaded from a store with no column for it.
        //
        // This is not the opaque-token rule being relaxed. `reconcile_parts`
        // has already refused to skip anything the durable ETag and length did
        // not vouch for, so the part's identity is settled before this runs;
        // what is copied is the provider's own value for a part the provider
        // has already been made to agree about, and the provider re-validates
        // it at completion. The full BLAKE3 re-read in `Verifying` remains the
        // authority on whether the object is right. Without this, a checkpoint
        // the store could not hold a checksum for would either complete with
        // `checksum: None` — the failure this closes — or re-upload every part
        // on every resume.
        let mut healed = false;
        for cp in &mut session.parts {
            if cp.checksum.is_some() || !cp.is_acknowledged() {
                continue;
            }
            if recon.action_of(cp.part_no) != Some(PartAction::Skip) {
                continue;
            }
            let from_provider = remote
                .iter()
                .find(|r| r.part_no == cp.part_no)
                .and_then(|r| r.checksum.clone());
            if from_provider.is_some() {
                cp.checksum = from_provider;
                healed = true;
            }
        }
        if healed {
            self.store.save(session).await?;
        }

        // The source is proved twice, and the two proofs answer different
        // questions. The fingerprint at the top of this function is the cheap
        // gate: it refuses to read anything out of a file that has obviously
        // moved. Everything below proves what was actually *read*.
        //
        // The second proof has to exist because the gate runs exactly once,
        // before the first part is read, so an edit landing between two part
        // reads sails past it. The spliced object is then caught only by the
        // full remote BLAKE3 in `Verifying` — which runs *after*
        // `complete_multipart` published it under a content-addressed,
        // immutable key. That key cannot be rewritten, so the session sticks in
        // `Verifying` and every future retry rediscovers the same poisoned
        // object. The check must therefore be local, and must run before
        // `Completing`.
        //
        // What it costs: every part is read in ascending order and fed to one
        // hasher, so a fresh upload reads exactly the bytes it was already
        // going to read — no amplification at all. A resume additionally
        // re-reads the ranges it is skipping, one local pass, which is strictly
        // cheaper than the full *remote* re-read `Verifying` already performs
        // unconditionally. AC-2 is untouched: it measures parts re-*sent*, and
        // no skipped part is re-sent.
        //
        // A hash of what was read, rather than a second `stat`, is also the
        // more *accepting* of the two. An edit confined to a range that was
        // already read and sent leaves the uploaded bytes exactly equal to the
        // planned bytes; a post-read fingerprint would refuse that correct
        // transfer, and this does not.
        let plan = session.plan;
        let mut read_back = blake3::Hasher::new();
        for (part_no, range) in plan.ranges() {
            let body = match self.source.read_range(range).await {
                Ok(b) => b,
                // Transient: another attempt may read it. The parts already
                // uploaded are worth keeping, so the session survives.
                Err(e) if e.is_retryable() => return Err(e),
                // TERMINAL — the source went away between the fingerprint gate
                // above and this read, and no later attempt can finish the
                // transfer. This is the ONLY place that observes it on a final
                // attempt: there is no subsequent fingerprint call to reach
                // `abandon` through, so returning the error directly left the
                // session `Uploading` with its multipart parts allocated and
                // nothing that would ever revisit the key to reap them.
                Err(e) => return Err(self.abandon(session, e).await),
            };
            if body.len() as u64 != range.len {
                // Through `abandon`, like every other terminal mismatch: the
                // source was truncated under us, `ContentMismatch` is
                // explicitly non-retryable, and replanning the shortened file
                // picks a different content-addressed key — so nothing ever
                // revisits this session and its uploaded parts accrue storage
                // until the bucket's lifecycle rules notice.
                let err = StorageError::ContentMismatch {
                    key: session.source.rel_path.clone(),
                    expected: format!("{} bytes at {}", range.len, range.offset),
                    actual: format!("{} bytes", body.len()),
                };
                return Err(self.abandon(session, err).await);
            }
            let local_blake3 = Blake3Hash::from_bytes(*blake3::hash(&body).as_bytes());
            read_back.update(&body);

            if recon.action_of(part_no) == Some(PartAction::Skip) {
                // This part's bytes are already on the provider, uploaded by an
                // earlier attempt. The whole-file hash below proves the disk
                // holds the planned content *now*; it cannot prove the earlier
                // attempt read it from that content, because that attempt may
                // have run against an in-place edit that was since reverted —
                // and a fingerprint-preserving edit leaves the gate nothing to
                // see. `PartCheckpoint::local_blake3` is the only record that
                // can tell, which is what its doc comment says it is for.
                //
                // A checkpoint carrying no hash reads back as all zeroes and so
                // fails here. That is deliberate: a part nothing can attribute
                // must not be completed over, and refusing costs a re-upload
                // while accepting costs an unreplaceable wrong object.
                let recorded = session
                    .parts
                    .iter()
                    .find(|p| p.part_no == part_no)
                    .map(|p| p.local_blake3);
                if recorded != Some(local_blake3) {
                    // Terminal, so abandoned rather than returned. See the
                    // truncation branch above and `abandon`.
                    let err = StorageError::ContentMismatch {
                        key: session.source.rel_path.clone(),
                        expected: format!(
                            "part {part_no} on the provider was read from blake3 {}",
                            recorded.map_or_else(|| "<no checkpoint>".to_owned(), |h| h.to_hex())
                        ),
                        actual: format!("the source now holds blake3 {}", local_blake3.to_hex()),
                    };
                    return Err(self.abandon(session, err).await);
                }
                continue;
            }

            let receipt = self
                .adapter
                .upload_part(&session.remote_key, &upload_id, part_no, body)
                .await?;

            // Checkpoint AFTER the provider acknowledged, so the record never
            // claims more than the provider confirmed. The reverse ordering
            // would let a checkpoint vouch for a part that never landed.
            let cp = session.checkpoint_mut(part_no);
            cp.offset = range.offset;
            cp.len = range.len;
            cp.local_blake3 = local_blake3;
            cp.etag = Some(receipt.etag);
            cp.checksum = receipt.checksum;
            // One part, not the whole set: this runs once per part, and a
            // whole-session save here makes checkpointing quadratic in the part
            // count. See `TransferSessionStore::save_part`.
            self.store.save_part(session, part_no).await?;

            outcome.bytes_uploaded += range.len;
            outcome.parts_sent += 1;
        }

        // Everything the provider now holds was either read in the loop above
        // or vouched for against its checkpoint there, so this settles whether
        // the object about to be published is the planned one — before it is
        // published, while refusing is still recoverable.
        let read_back = Blake3Hash::from_bytes(*read_back.finalize().as_bytes());
        if read_back != session.source.blake3 {
            return Err(self
                .abandon(
                    session,
                    StorageError::ContentMismatch {
                        key: session.source.rel_path.clone(),
                        expected: format!("blake3 {}", session.source.blake3.to_hex()),
                        actual: format!("the parts as read hash to blake3 {}", read_back.to_hex()),
                    },
                )
                .await);
        }
        Ok(())
    }

    /// `Completing` is already persisted when this runs, which is what makes
    /// window 3 recoverable.
    async fn complete(
        &self,
        session: &mut TransferSession,
        outcome: &mut TransferOutcome,
    ) -> StorageResult<()> {
        let upload_id = session
            .upload_id
            .clone()
            .ok_or_else(|| StorageError::NoSuchUpload {
                key: session.remote_key.as_str().to_owned(),
            })?;

        // Window 3, positive branch: a previous attempt's completion may have
        // succeeded with its response lost. Ask before re-completing — blindly
        // re-completing would fail the `IfAbsent` precondition and look like a
        // hard error when in fact the transfer had already succeeded.
        //
        // The HEAD settles only *whether* an object is there. It says nothing
        // about its content, and conflating "a HEAD proves existence" with "a
        // full read proves integrity" is precisely PM-2's failure mode. So this
        // returns without concluding anything: `Verifying` is unconditionally
        // the next state, and it performs the full BLAKE3 re-read. HEAD **plus**
        // full hash, with the hash done exactly once.
        if self.adapter.head(&session.remote_key).await?.is_some() {
            outcome.resolved_ambiguous_completion = true;
            // The provider session, if one survives, is now residue.
            let _ = self
                .adapter
                .abort_multipart(&session.remote_key, &upload_id)
                .await;
            return Ok(());
        }

        let parts = session.acknowledged_receipts();
        let precondition = if self.adapter.capabilities().conditional_create {
            CreatePrecondition::IfAbsent
        } else {
            CreatePrecondition::Unconditional
        };
        let receipt = self
            .adapter
            .complete_multipart(&session.remote_key, &upload_id, &parts, precondition)
            .await?;
        session.object_version = receipt.version;
        Ok(())
    }

    /// AC-1's mandatory full re-read, plus the attestation probe.
    async fn verify(&self, session: &mut TransferSession) -> StorageResult<()> {
        let meta = self
            .adapter
            .head(&session.remote_key)
            .await?
            .ok_or_else(|| StorageError::NotFound {
                key: session.remote_key.as_str().to_owned(),
            })?;
        if meta.size != session.source.size {
            return Err(StorageError::ContentMismatch {
                key: session.remote_key.as_str().to_owned(),
                expected: format!("{} bytes", session.source.size),
                actual: format!("{} bytes", meta.size),
            });
        }
        verify_full_content(
            self.adapter,
            &session.remote_key,
            session.source.blake3,
            session.source.size,
            self.verify_chunk,
        )
        .await?;

        let mode = self.adapter.probe_attestation_mode().await?;
        session.attestation_mode = Some(mode);
        if mode == AttestationMode::Version {
            session.object_version = meta.version;
        }
        Ok(())
    }

    /// Best-effort abort. The distinction it returns is the whole point: an
    /// abort Shepherd could not confirm must be revisited by a sweep.
    async fn finish_abort(&self, session: &TransferSession) -> AbortOutcome {
        let Some(id) = session.upload_id.as_ref() else {
            // Nothing was ever created remotely.
            return AbortOutcome::Clean;
        };
        match self.adapter.abort_multipart(&session.remote_key, id).await {
            Ok(()) => AbortOutcome::Clean,
            // The provider already forgot it: the desired end state holds.
            Err(StorageError::NoSuchUpload { .. }) => AbortOutcome::Clean,
            Err(_) => AbortOutcome::Ambiguous,
        }
    }
}

#[cfg(test)]
#[path = "transfer_session_tests.rs"]
mod tests;
