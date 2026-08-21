#![allow(clippy::disallowed_methods)]
//! **THE DESTROY PATH.** §4.10's ordering, and the only caller of any
//! destructive primitive.
//!
//! # Why this file carries the escape hatch
//!
//! `clippy::disallowed_methods` is denied workspace-wide, and
//! `xtask/clippy.toml` lists `PlaceholderProvider::destroy_local` and
//! `StorageAdapter::delete_object`. The `#![allow]` above is the **single**
//! permitted escape, and `cargo xtask check-deps` rule 4b fails the build if
//! that line appears in any other file. Rule 4a additionally asserts, by source
//! scan, that no other file so much as *names* those symbols.
//!
//! Three independent mechanisms guard one property, and they fail differently
//! on purpose: rule 2 stops another crate reaching `shepherd-placeholder` at
//! all; rule 4a stops another module here calling the primitive; the clippy
//! deny stops it compiling. The first is the load-bearing one — Cargo cannot
//! forbid a syscall, but it can forbid an edge.
//!
//! # The ordering (§4.10.1 + §4.10.2), and what each step buys
//!
//! ```text
//! 0. open-handle precondition (OQ-J)      -- "cannot determine" == open
//! 1. re-validate safety floors (AC-8)     -- ALL of them; every one is mutable
//! 2. rename into staging (RENAME_NOREPLACE)
//! 3. compare identity: staged handle == the verified file
//! 4. re-hash THROUGH THE STAGED HANDLE    -- second-to-last
//! 5. cheap remote HEAD                    -- last; A re-attests, B does not
//! 6. unlink the staged entry              -- irreversible
//! ```
//!
//! Steps 4 and 5 are in this order because exactly one of them can finish at
//! ≈ the unlink, and §4.10.2 chooses to minimise the window on the *plausible*
//! hazard: a process holding a writable descriptor is ordinary, while a remote
//! attacker writing mismatched bytes to a hash-named key is not. The cost is a
//! **10–100 ms** local-fd window, stated rather than hidden, and it is OQ-J's
//! accepted residual (D-8, D-15, R-21).
//!
//! Every refusal in here is a **fail-closed** exit. The intent row is fsync'd
//! before step 2, so a failure at that point refuses; an audit failure after
//! step 6 cannot refuse — the file is gone — so it halts all *subsequent*
//! destruction instead (§4.10.4, [`crate::audit`]).

use std::path::Path;
use std::time::Duration;

use shepherd_catalog::file_repo::ScanRoot;
use shepherd_catalog::intent::{IntentKind, IntentState, PreparedIntent};
use shepherd_core::ObjectKey;
use shepherd_core::{Blake3Hash, FsId, IntentId, RootId, TargetId, Timestamp};
use shepherd_placeholder::provider::{PlaceholderProvider, Staged};
use shepherd_scan::floors::{self, FloorContext, FloorInput, FloorPolicy};
use shepherd_storage::adapter::{ObjectMeta, StorageAdapter, StorageError, VersionGuard};

use crate::audit::{AuditLog, AuditRecord};
use crate::revalidate::{ClosingCheck, DestroyRefusal, Location};
use crate::serialize::FileLocks;

#[derive(Debug, thiserror::Error)]
pub enum DestroyError {
    #[error("refused: {0:?}")]
    Refused(DestroyRefusal),
    /// A blast-radius control refused — §4.10.5's breaker, not §4.10.2's
    /// custody predicate. Kept as its own variant so the two cannot be
    /// confused at a call site that only handles one of them.
    #[error("breaker refused: {0:?}")]
    Breaker(crate::breaker::BreakerRefusal),
    #[error("floor refused: {code} — {detail}")]
    Floor { code: &'static str, detail: String },
    #[error("root refuses destruction: {0}")]
    Root(String),
    #[error(transparent)]
    Provider(#[from] shepherd_placeholder::provider::ProviderError),
    #[error(transparent)]
    Audit(#[from] crate::audit::AuditError),
    #[error("identity changed between verification and staging: {detail}")]
    IdentityMismatch { detail: String },
    /// The request is not bound to the proofs it arrived with.
    ///
    /// Distinct from [`Self::Refused`], which carries §4.10.2's predicate
    /// verdict about the world. This one is about the REQUEST: a prepared
    /// intent, a custody proof and a remote key that do not all describe the
    /// same bytes at the same path. Nothing here needs I/O to decide, which is
    /// why it is decided before the lock.
    #[error("request is not bound to its proof: {detail}")]
    Unbound { detail: String },
    #[error("local content changed after verification: expected {expected}, staged holds {actual}")]
    ContentChanged { expected: String, actual: String },
    #[error("storage: {0}")]
    Storage(String),
    /// The provider refused because the guard did not hold — the object is not
    /// the version (or the content) the destruction was authorised against.
    ///
    /// Kept distinct from [`DestroyError::Storage`] because it is the one
    /// provider failure that is *knowably* pre-operation: the refusal is the
    /// provider saying it did not act. Flattened into `Storage` it became
    /// indistinguishable from a lost acknowledgement, and
    /// [`resolve_ambiguous_delete`] would then treat a refusal as an outcome to
    /// resolve.
    #[error("precondition failed for {key}: {detail}")]
    PreconditionFailed { key: String, detail: String },
    #[error("io: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, DestroyError>;

/// Everything the destroy path needs about one file.
pub struct LocalDestroyRequest<'a> {
    /// Proof that an intent reached `prepared` DURABLY before anything
    /// irreversible was attempted.
    ///
    /// A bare [`IntentId`] is an integer any caller can invent, and this
    /// function's stated ordering — "the intent is fsync'd before the syscall"
    /// — rested entirely on every caller having remembered to do that, with
    /// nothing able to tell a journal-backed id from a fabricated one. A crash
    /// between the unlink and the audit append would then leave no intent to
    /// reconstruct the forensic record from, which is the guarantee §4.10.4
    /// exists to make. `PreparedIntent` can only be minted by
    /// `IntentJournal::prepare`, which returns after the commit.
    pub intent: PreparedIntent,
    pub path: &'a Path,
    pub root: &'a ScanRoot,
    /// The catalog `root_id` that OWNS [`Self::path`], as the file row records
    /// it.
    ///
    /// Not derived from [`Self::root`], because that is the snapshot the caller
    /// chose and this is the fact the catalog holds. §4.9 allows roots to
    /// overlap, so pathname containment cannot settle which root owns a file —
    /// a caller could hand A's file to B's open snapshot and gate, and every
    /// PM-3 check would then run against B's authority while A required resync.
    pub file_root: RootId,
    /// The hash proven against the remote copy.
    pub expected_hash: Blake3Hash,
    pub expected_size: u64,
    /// Identity as recorded at verification time.
    pub verified_identity: shepherd_placeholder::provider::FileIdentity,
    /// **The catalog's** identity for this file — `<stable-volume-id>:<inode>`,
    /// as produced by `shepherd_catalog::volume::fs_id`.
    ///
    /// Carried from the caller rather than synthesized here, because the only
    /// thing a lock key is for is *colliding with the other holder*. This path
    /// once built `<st_dev>:<inode>` from [`Self::verified_identity`], which is
    /// a different string from the one [`crate::upload`] locks on for the same
    /// file — so an upload and a destruction of one file could run
    /// concurrently while both appeared to be serialized.
    ///
    /// The repair is to carry the catalog's value, never to make
    /// `volume::fs_id` use `st_dev`: G-1-IDENTITY-FSID exists because `st_dev`
    /// does not survive a remount, and `fs_id_survives_a_remount_that_changes_st_dev`
    /// is the test that pins it.
    ///
    /// **If you are wiring a new caller — the daemon's destroy path, T10's
    /// discard — pass `file.fs_id` from the catalog, or the value
    /// `shepherd_catalog::volume::fs_id` returns for this path.** Anything you
    /// build here from `dev`/`ino` compiles, locks, and protects nothing; the
    /// failure is silent and it is on the irreversible path.
    /// `a_destroy_waits_on_the_lock_the_catalog_identity_names` and
    /// `a_destroy_does_not_wait_on_a_dev_ino_shaped_key` are the pair that
    /// hold this down from both sides.
    pub fs_id: &'a FsId,
    /// Age, resolved by the caller per §4.12's fallback order.
    pub age: Duration,
    pub floor_policy: FloorPolicy,
    /// The location authorising this destruction — already checked against
    /// §4.10.2's N-location predicate by [`crate::revalidate::destroy_permitted`].
    pub custodian: &'a Location,
    pub remote_key: &'a ObjectKey,
    /// [`Self::root`]'s gates, HELD across the unlink rather than re-read.
    ///
    /// The snapshot above is what the caller saw when it assembled this; PM-3's
    /// gates are mutable and everything between here and step 6 takes time.
    /// See [`RootGate`].
    pub root_gate: &'a dyn RootGate,
    /// Where this destruction's §4.4 lifecycle transitions are recorded.
    ///
    /// See [`IntentGate`].
    pub intent_gate: &'a dyn IntentGate,
}

/// Execute §4.10's local destruction for one file.
///
/// Deliberately **not** named `destroy_local`: that name is tracked by rule 4,
/// and a public entry point bearing it would make every caller — T10's discard,
/// the integration tests — trip the gate. The tracked name belongs to the
/// primitive; this is the protocol around it.
#[allow(clippy::too_many_arguments)]
pub async fn execute_local_destruction(
    req: LocalDestroyRequest<'_>,
    provider: &dyn PlaceholderProvider,
    remote: &impl RemoteGate,
    audit: &AuditLog,
    locks: &FileLocks,
    now: Timestamp,
) -> Result<()> {
    // An incomplete forensic record halts everything. Checked first: it is the
    // cheapest refusal and the one that must not be bypassed by any later
    // success.
    audit.check_not_halted()?;

    // PM-3 and D-12. One call, so a new gate cannot be added in the catalog and
    // forgotten here.
    if let Some(reason) = req.root.destroy_refusal() {
        return Err(DestroyError::Root(reason));
    }

    // The ROOT must be the one that owns this file.
    //
    // `root` and `path` arrived independently, and §4.9 allows roots to
    // overlap — so pathname containment cannot decide it, and the catalog's own
    // answer is the only one that can. Without this, A's file could be
    // destroyed under B's snapshot and B's gate: the floors, the refusal check
    // and the held gate would all be about a root that does not own it.
    if req.file_root != req.root.id {
        return Err(DestroyError::Unbound {
            detail: format!(
                "the catalog records this file under root {} and the request supplies root \
                 {}; overlapping roots are allowed, so containment does not decide which \
                 one's PM-3 gates govern it",
                req.file_root.get(),
                req.root.id.get()
            ),
        });
    }

    // The intent must be THIS destruction's, and the custody proof must be
    // about THESE bytes. Both are cheap refusals on the request alone, so both
    // are made before the lock, before staging, and long before the syscall.
    //
    // Neither was checked. `PreparedIntent` proved only that some row reached
    // `prepared`, so an intent prepared for one path authorized an unlink of
    // another and the sole forensic record described a file that still exists.
    // `custodian` proved only that SOME location was recently verified: under
    // `AttestationMode::Content`, `destroy_permitted` could hand back a
    // custodian holding different same-sized content, the local re-hash would
    // pass against this request's hash, and the closing HEAD would prove only
    // that an object of the right size exists — while the last local copy of
    // different bytes went away. A predicate that authorizes destroying bytes
    // has to name the bytes.
    req.intent
        .authorizes(
            IntentKind::Local,
            &req.path.to_string_lossy(),
            req.expected_size,
            req.expected_hash,
        )
        .map_err(|detail| DestroyError::Unbound { detail })?;
    check_custody_binds(&req, remote.target(), remote.prefix())?;

    // Per-file serialization, keyed on identity. Held across every await below.
    //
    // On the CATALOG's identity — the caller's value, not one synthesized from
    // `verified_identity`. A lock key exists to collide with the other holder,
    // and `<st_dev>:<inode>` never collides with the `<volume-uuid>:<inode>`
    // that [`crate::upload`] locks on. See [`LocalDestroyRequest::fs_id`].
    let _guard = locks.acquire(req.fs_id).await;

    // --- steps 0 and 1: the acquisition gate ---------------------------------
    //
    // ALL floors are re-evaluated here, not reused from planning time: §4.10
    // says open/locked, nlink, sparse and symlink are all mutable between the
    // two moments. `FloorContext::Acquisition` is what adds OQ-J's open-handle
    // precondition, and "cannot determine" is treated as open.
    let md = std::fs::symlink_metadata(req.path).map_err(|e| DestroyError::Io(e.to_string()))?;
    let input = FloorInput {
        path: req.path.to_path_buf(),
        size: md.len(),
        age: req.age,
        nlink: nlink_of(&md),
        is_symlink: md.is_symlink(),
        allocated_bytes: allocated_of(&md),
        fs_id: Some(req.fs_id.clone()),
        observed_at: now,
    };
    let verdict = floors::evaluate(&req.floor_policy, &input, FloorContext::Acquisition);
    if let Some(refusal) = verdict.refusal() {
        return Err(DestroyError::Floor {
            code: refusal.code(),
            detail: format!("{refusal:?}"),
        });
    }

    // --- step 2: stage. Reversible from here until step 6. -------------------
    //
    // Staged into the REGISTERED ROOT's staging directory, because that is the
    // one path startup recovery lists. Staging under the file's own parent
    // would put a nested file's bytes somewhere `list_staged` never looks.
    let staged = provider.stage_for_destruction(Path::new(&req.root.path), req.path)?;

    // From here on, every failure path must restore rather than proceed.
    // §4.10.4 is abort-forward-never.
    let outcome = destroy_staged(&req, &staged, remote, now).await;
    match outcome {
        Ok(()) => {}
        Err(e) => {
            restore_or_report(provider, staged, "destruction aborted", &e);
            return Err(e);
        }
    }

    // --- the audit gate -----------------------------------------------------
    //
    // The halt at the top of this function was read before staging, and it is
    // now stale: another destruction can have failed its append in the interval,
    // and §4.10.4's halt is GLOBAL — it is a claim about every subsequent
    // destruction, not only about the ones that start after it.
    //
    // `admit` re-reads it under a process-wide gate and holds that gate across
    // the syscall and the append, so no destruction can be between those two
    // while another is admitted. Refusing here is still a refusal *before*
    // anything irreversible, so abort-forward-never applies exactly as it does
    // above. See [`crate::audit`] for what the gate costs.
    let permit = match audit.admit().await {
        Ok(p) => p,
        Err(e) => {
            restore_or_report(provider, staged, "destruction halted at the audit gate", &e);
            return Err(e.into());
        }
    };

    // PM-3, RE-READ, under the permit and one statement before the syscall.
    //
    // The check at the top of this function used the caller's snapshot and is
    // now as old as everything that has happened since: the file lock was
    // waited for, the file was staged, its bytes were re-hashed through the
    // handle and a HEAD went to the provider and came back. A watcher overflow
    // setting `resync_required`, or a volume going away, lands in that window
    // and PM-3 stops destruction while the gate is SET — not while it was set
    // when the request was built.
    //
    // Under the permit, because the permit is what serialises this against
    // every other destruction; refusing here is still a refusal BEFORE anything
    // irreversible, so abort-forward-never applies exactly as it does above.
    // HELD, not read. `_root_hold` lives until the end of this function, which
    // is past the unlink — that binding is the fix, and dropping it earlier
    // would silently restore the window this closes.
    let _root_hold = match req.root_gate.hold_open(req.root.id).await {
        Ok(Ok(hold)) => hold,
        Ok(Err(reason)) => {
            let e = DestroyError::Root(reason);
            drop(permit);
            restore_or_report(provider, staged, "destruction refused by the root gate", &e);
            return Err(e);
        }
        // A gate that cannot be read is not a gate that says yes. This is the
        // last check before an irreversible step, so it fails closed.
        Err(e) => {
            drop(permit);
            restore_or_report(provider, staged, "the root gate could not be held", &e);
            return Err(e);
        }
    };

    // THE CLOSING HEAD AGAIN, adjacent to the unlink this time.
    //
    // `destroy_staged` asked it before the two waits below it, and both are
    // unbounded: `audit.admit()` takes a process-wide gate that `AuditLog`
    // documents as held across another destruction's network DELETE, and
    // `hold_open` is another await on top of that. Under contention the replica
    // that authorised this can therefore vanish in the gap after its own HEAD
    // said it was there, and the last local copy is still unlinked — which is
    // the one outcome §4.10.2 exists to prevent.
    //
    // Repeated rather than moved: acquiring the permit before step 5 would hold
    // that process-wide gate across staging and a full local re-hash, which is
    // the cost `crate::audit` says it is worth avoiding. A HEAD is a round trip
    // against a re-hash of the whole file, and this one buys the property the
    // first one only appeared to.
    //
    // Both waits are behind it now, and the hold is still alive, so what
    // remains between this answer and the syscall is straight-line code.
    if let Err(e) = closing_head(&req, remote).await {
        drop(permit);
        restore_or_report(
            provider,
            staged,
            "the replica disappeared while this destruction waited",
            &e,
        );
        return Err(e);
    }

    // --- step 6: the irreversible one ---------------------------------------
    //
    // If the unlink itself fails, the destruction has NOT happened — the staged
    // entry is still there and still holds the bytes. §4.10.4 is
    // abort-forward-never, so this restores rather than leaving the file
    // orphaned in staging for a later recovery pass to find. Startup recovery
    // remains the backstop (the entry is discoverable via `list_staged`), but
    // recovering in-process while we still hold the context is strictly better
    // than deferring to a pass that has to reconstruct it.
    // §4.4: the syscall is ABOUT to be issued.
    //
    // Before it, so a crash between this and the unlink is distinguishable from
    // one before either — which is the whole reason the state exists. Recorded
    // under the permit, alongside everything else that has to survive.
    let intent_id = req.intent.id();
    // THIS ONE IS A PRECONDITION, not a trail entry.
    //
    // Everything after the unlink is recorded best-effort, because there is
    // nothing left to abort to. This is before it, and it is the whole reason
    // the state exists: if `syscall-issued` is not durable, a crash leaves
    // deleted bytes behind an intent that still says `prepared`, and recovery
    // cannot tell an unissued operation from a completed one. A write that
    // failed for `SQLITE_BUSY` or ENOSPC has to stop the destruction, not be
    // logged past.
    //
    // Refused BEFORE the syscall, so abort-forward-never applies exactly as it
    // does to every other pre-syscall refusal: the staged file is restored.
    if let Err(e) = req
        .intent_gate
        .advance(intent_id, IntentState::SyscallIssued)
        .await
    {
        drop(permit);
        restore_or_report(
            provider,
            staged,
            "the intent could not be advanced to `syscall-issued`",
            &e,
        );
        return Err(e);
    }

    if let Err(e) = provider.destroy_local(&staged, req.expected_hash) {
        // `DestroyedNotDurable` is the one failure here that is NOT a failure to
        // destroy: the unlink succeeded and only its directory could not be
        // fsync'd. Abort-forward-never does not apply — there is nothing left to
        // restore, and a retry would unlink a name that is already gone. What is
        // owed is what any unresolvable irreversible step is owed: the record,
        // written under the permit still held, and the global halt, because a
        // crash can still resurrect the entry and leave the log describing a
        // destruction that did not survive.
        if let shepherd_placeholder::provider::ProviderError::DestroyedNotDurable { path, detail } =
            &e
        {
            let detail = format!("{path} was unlinked but the removal is not durable: {detail}");
            tracing::error!(%detail, "destruction is irreversible but not durable");
            permit.append(&AuditRecord {
                at: now,
                intent: req.intent.id(),
                kind: "local",
                path: req.path.display().to_string(),
                size: req.expected_size,
                blake3: Some(req.expected_hash),
                attestation: format!("{:?}", req.custodian.attestation).to_lowercase(),
                target_keys: vec![req.remote_key.as_str().to_owned()],
                reconstructed: false,
            })?;
            record_transition(req.intent_gate, intent_id, IntentState::OutcomeAmbiguous).await;
            audit.halt_for_recovery(&detail);
            return Err(e.into());
        }

        // The syscall was issued and did not remove anything, which is an
        // OUTCOME — a known one — and then the intent is aborted, because
        // nothing irreversible happened and this destruction is over.
        record_transition(req.intent_gate, intent_id, IntentState::OutcomeKnown).await;
        record_transition(req.intent_gate, intent_id, IntentState::Aborted).await;

        // The permit goes back before the restore: nothing irreversible
        // happened, so there is no record owed and no reason to hold every
        // other destruction while this one unwinds.
        drop(permit);
        restore_or_report(provider, staged, "unlink failed", &e);
        return Err(e.into());
    }

    // The audit write happens AFTER the syscall by construction, so it cannot
    // refuse. A failure here halts subsequent destruction (§4.10.4) — and
    // because it happens under the permit, "subsequent" includes every
    // destruction that has not yet been admitted, rather than only those that
    // have not yet started.
    permit.append(&AuditRecord {
        at: now,
        intent: req.intent.id(),
        kind: "local",
        path: req.path.display().to_string(),
        size: req.expected_size,
        blake3: Some(req.expected_hash),
        attestation: format!("{:?}", req.custodian.attestation).to_lowercase(),
        target_keys: vec![req.remote_key.as_str().to_owned()],
        reconstructed: false,
    })?;

    // §4.4's tail, and it STOPS AT `audited`.
    //
    // After the audit append, never before: `audited` claiming a record that
    // does not exist is exactly the lie the state is supposed to rule out.
    //
    // `catalog-committed` is NOT recorded here, and adding it was wrong: this
    // function unlinks a file and appends a record, and changes no catalog row
    // at all — the caller cannot make that change until this returns. Claiming
    // it settles the intent, which takes it out of `unresolved()`, so a crash
    // between this return and the caller's write leaves the catalog saying the
    // file is still local with nothing left to reconcile it. The transaction
    // that records the destruction is the one that may advance the final state,
    // because it is the only place the two can be made atomic.
    record_transition(req.intent_gate, intent_id, IntentState::OutcomeKnown).await;
    record_transition(req.intent_gate, intent_id, IntentState::Audited).await;

    Ok(())
}

/// Record a lifecycle transition, reporting a failure rather than raising it.
///
/// Every call site is at or after the irreversible step, where there is nothing
/// to abort to — and refusing to continue would leave the AUDIT record unwritten
/// as well, trading a journal that is behind for a forensic record that does not
/// exist. The audit log's own halt is the mechanism for an unrecordable
/// irreversible step; this trail is finer-grained and sits beside it.
///
/// Logged at `error`, because a journal that silently stops advancing is a
/// recovery path that silently stops working.
async fn record_transition(gate: &dyn IntentGate, id: IntentId, to: IntentState) {
    if let Err(e) = gate.advance(id, to).await {
        tracing::error!(
            intent = id.get(),
            to = to.as_str(),
            error = %e,
            "could not advance the destroy intent; recovery will read this row as unresolved"
        );
    }
}

/// §4.10.4's abort-forward-never, at every point that has staged a file and then
/// decided not to destroy it.
///
/// One function rather than three copies, because the decision it encodes — put
/// the file back, and if that fails say loudly that the bytes are in staging —
/// is one decision. Reports rather than returns: the caller already holds the
/// real error, and replacing it with a restore failure would hide why the
/// destruction stopped.
fn restore_or_report(
    provider: &dyn PlaceholderProvider,
    staged: Staged,
    why: &str,
    error: &dyn std::fmt::Display,
) {
    match provider.restore_staged(staged) {
        Ok(o) => tracing::warn!(?o, %error, "{why}; file restored"),
        Err(re) => tracing::error!(
            %error,
            restore_error = %re,
            "{why} AND restore failed — the file is in staging and needs recovery"
        ),
    }
}

/// The custody proof must be about the bytes being destroyed.
///
/// Two clauses, because the hash alone leaves the key free to name something
/// else: the closing HEAD in step 5 asks about the KEY, so a key that does not
/// name these bytes turns that HEAD into a statement about a different object.
///
/// The LEAF, not the whole key and not a fan-out suffix. §4.9 has two key
/// layouts — `content_key`'s `objects/aa/bb/<hex>` and `id_key`'s
/// `objects/<file-id>/<hex>` for providers that need a human-navigable tree —
/// and both end in the hash. Pinning `derive_object_key`'s shape would refuse
/// the id-addressed layout outright the day it is wired up, which is a
/// coupling to today's only caller rather than to §4.9. The leaf is the part
/// that is about the bytes, and it is the part both layouts agree on.
fn check_custody_binds(
    req: &LocalDestroyRequest<'_>,
    gate: Option<TargetId>,
    prefix: Option<&str>,
) -> Result<()> {
    // The key must live in the GATE's namespace.
    //
    // The leaf check below says the key names these bytes and the target check
    // says the HEAD reaches the custodian's target; neither says the key is
    // under that target's prefix. Two logical targets can share one adapter and
    // one bucket, so a request with a custodian and gate for A can name a
    // hash-suffixed key under B's namespace — and under content attestation a
    // same-sized object there satisfies both closing HEADs while A's
    // catalogued replica is gone. The local original is then unlinked with no
    // reachable location recorded for the surviving bytes.
    //
    // Same finding as the discard path's, one file over: binding the target
    // without binding the prefix leaves the hole open one level down.
    // On a COMPONENT boundary, not on leading bytes.
    //
    // `starts_with` accepted `tenant/archive/objects/...` for a gate configured
    // `tenant/a`: a different namespace that happens to share a prefix string,
    // which in a shared bucket is a neighbouring tenant rather than a
    // hypothetical. The target and hash-leaf checks pass there too, so content
    // attestation could authorise the unlink from an object the custodian's
    // target never held.
    //
    // The trailing slash is trimmed first because `derive_object_key` trims it
    // when building the key, so a prefix configured `tenant/a/` and one
    // configured `tenant/a` name the same objects and must be accepted the same
    // way. An empty prefix means the bucket root, and every key is under it.
    match prefix.map(|p| p.trim_end_matches('/')) {
        Some(p)
            if p.is_empty()
                || req
                    .remote_key
                    .as_str()
                    .strip_prefix(p)
                    .is_some_and(|rest| rest.starts_with('/')) => {}
        Some(p) => {
            return Err(DestroyError::Unbound {
                detail: format!(
                    "the remote key `{}` is not under this target's prefix `{p}`, so the \
                     closing HEAD would ask about an object in another target's namespace",
                    req.remote_key.as_str()
                ),
            });
        }
        None => {
            return Err(DestroyError::Unbound {
                detail: "this remote gate cannot say where its target's objects live, so the \
                         remote key cannot be bound to it. Wrap the adapter in `TargetGate`"
                    .to_owned(),
            });
        }
    }

    match gate {
        Some(t) if t == req.custodian.target => {}
        Some(t) => {
            return Err(DestroyError::Unbound {
                detail: format!(
                    "the custody proof is for target {} and the closing HEAD would be sent to \
                     target {}; proving an object exists somewhere else says nothing about \
                     the replica that authorized this destruction",
                    req.custodian.target.get(),
                    t.get()
                ),
            });
        }
        None => {
            return Err(DestroyError::Unbound {
                detail: format!(
                    "this remote gate cannot say which target it speaks to, so the closing \
                     HEAD cannot be bound to the custody proof for target {}. Wrap the \
                     adapter in `TargetGate`",
                    req.custodian.target.get()
                ),
            });
        }
    }

    if req.custodian.expected_hash != req.expected_hash {
        return Err(DestroyError::Unbound {
            detail: format!(
                "the custody proof is for blake3 {} and this destruction is of {}; a location \
             verified against other bytes cannot authorize destroying these",
                req.custodian.expected_hash.to_hex(),
                req.expected_hash.to_hex()
            ),
        });
    }
    let hex = req.expected_hash.to_hex();
    if req.remote_key.as_str().rsplit('/').next() != Some(hex.as_str()) {
        return Err(DestroyError::Unbound {
            detail: format!(
                "the remote key `{}` does not name blake3 {hex}, so the closing HEAD would ask \
             about a different object than the one being destroyed",
                req.remote_key.as_str()
            ),
        });
    }
    Ok(())
}

/// Steps 3–5. Split out so every error path above restores the staged file.
async fn destroy_staged(
    req: &LocalDestroyRequest<'_>,
    staged: &Staged,
    remote: &impl RemoteGate,
    _now: Timestamp,
) -> Result<()> {
    // --- step 3: identity, from the HELD handle ------------------------------
    if staged.identity.dev != req.verified_identity.dev
        || staged.identity.ino != req.verified_identity.ino
    {
        return Err(DestroyError::IdentityMismatch {
            detail: format!(
                "verified {} but staged {}",
                req.verified_identity, staged.identity
            ),
        });
    }
    // nlink is re-checked here as well as in the floors: a hard link created
    // between step 1 and step 2 would mean destroying this name frees nothing.
    if staged.identity.nlink > 1 {
        return Err(DestroyError::IdentityMismatch {
            detail: format!(
                "nlink is {} at staging: another name reaches these bytes",
                staged.identity.nlink
            ),
        });
    }

    // --- step 4: re-hash THROUGH THE STAGED HANDLE ---------------------------
    //
    // Through the handle, never by reopening the staged path — reopening is the
    // path re-resolution the whole design exists to avoid.
    let actual = hash_through_handle(&staged.handle)?;
    if actual != req.expected_hash {
        return Err(DestroyError::ContentChanged {
            expected: req.expected_hash.to_hex(),
            actual: actual.to_hex(),
        });
    }

    // --- step 5: the cheap closing HEAD --------------------------------------
    closing_head(req, remote).await
}

/// §4.10.2 step 3's closing HEAD: the replica that authorises this destruction
/// is still there, and still the one that was verified.
///
/// Split out because it is asked TWICE, and the second time is the one that
/// matters. See the call site immediately before the unlink.
async fn closing_head(req: &LocalDestroyRequest<'_>, remote: &impl RemoteGate) -> Result<()> {
    let meta = remote.head_meta(req.remote_key).await?;
    let check = ClosingCheck {
        mode: req.custodian.attestation,
        observed_version: meta.as_ref().and_then(|m| m.version.clone()),
        observed_size: meta.as_ref().map(|m| m.size),
    };
    check
        .evaluate(req.custodian.object_version.as_ref(), req.expected_size)
        .map_err(DestroyError::Refused)
}

/// Advance an intent along §4.4's lifecycle, as a narrow port.
///
/// # Why this exists at all
///
/// `IntentState` has a full successor machine — `prepared → syscall-issued →
/// outcome-known → audited → catalog-committed`, with `IntentJournal::transition`
/// validating every move — and nothing called it. A destruction that ran start
/// to finish therefore left its row in `prepared`, which
/// `IntentJournal::unresolved` reports as needing recovery: every successful
/// destroy looked, to recovery, exactly like a crash. Worse in the other
/// direction, a crash immediately after the unlink was indistinguishable from
/// one before it, which is the distinction §4.10.4's ordering exists to make.
///
/// Filed as #5 when the binding half landed, because the destroy path had no
/// catalog access; `RootGate` established the shape, and this is the writing
/// counterpart.
///
/// # Failures do not stop the destruction
///
/// A transition that cannot be recorded is reported and does not abort: after
/// the unlink there is nothing to abort TO, and refusing to continue would
/// leave the audit record unwritten as well — trading a journal that is behind
/// for a forensic record that does not exist. The audit log's own halt is the
/// mechanism for an unrecordable irreversible step; this is the finer-grained
/// trail beside it.
#[async_trait::async_trait]
pub trait IntentGate: Send + Sync {
    async fn advance(&self, id: IntentId, to: IntentState) -> Result<()>;
}

/// Re-read a root's destruction gates, as a narrow port.
///
/// # Why the snapshot in the request is not enough
///
/// `LocalDestroyRequest::root` is a `ScanRoot` the CALLER read, and PM-3's
/// gates are mutable: a watcher journal overflow sets `resync_required`, a
/// volume disappearing sets `availability`, and D-12's
/// `destruction_ineligible` is an operator action. The gate was therefore
/// checked once, at the top, before waiting for the file lock and before
/// staging, hashing and the remote HEAD — all of which take time a gate can
/// change in. PM-3 says destruction stops while the gate is set, not that it
/// stops if the gate was set when the request was assembled.
///
/// So it is re-read under the audit permit, immediately before the unlink,
/// which is the last moment that can still refuse and the one the permit
/// serialises against every other destruction.
///
/// A read-only port, and deliberately not the journal seam #5 needs: this asks
/// the catalog a question, and advancing an intent asks it to record an answer.
/// The wiring that supplies a real implementation lands with the caller that
/// assembles `LocalDestroyRequest` — nothing in the tree does yet, which is why
/// this file's tests are its only implementors today.
#[async_trait::async_trait]
pub trait RootGate: Send + Sync {
    /// Take the gate for `root` and HOLD it.
    ///
    /// `Ok(Err(reason))` is a set gate; `Ok(Ok(hold))` is an open one, and the
    /// hold must remain alive until the unlink has happened.
    ///
    /// # Why a hold rather than a value
    ///
    /// The first version returned `Option<String>` — a snapshot, taken and
    /// released before the caller had even finished matching on it. That is
    /// better than the request's own stale snapshot and it is not the property
    /// PM-3 states: a watcher overflow landing between the read and the syscall
    /// still meets an unlink that has already decided to proceed. The audit
    /// permit does not help, because it serialises destructions and audit
    /// writes, not root-state updates.
    ///
    /// So the value the gate returns is a GUARD, and the destroy path keeps it
    /// alive across `destroy_local`. What the guard holds is the
    /// implementation's business — a transaction, a read lock, a version it
    /// re-checks on drop — and an implementation that holds nothing is no worse
    /// than the value this replaced. What the type does is make "the gate is
    /// open FOR THE DURATION" the thing a caller has to obtain, rather than a
    /// fact it can read once and assume. Same move as `bind(path, state_lock)`
    /// making the lock-before-listen ordering a type in this PR's daemon.
    ///
    /// `root` is passed rather than implied. The request carries `root` and
    /// `root_gate` independently, so a gate for root B could be attached to a
    /// destruction under root A and answer "open" while A requires resync — an
    /// implementation that looks the root up by this argument cannot be asked
    /// the wrong question.
    async fn hold_open(&self, root: RootId) -> Result<std::result::Result<RootHold, String>>;
}

/// Proof that a root's gates were open, held for as long as it is alive.
///
/// Opaque on purpose: the destroy path must not be able to inspect it, only to
/// keep it. What is inside is whatever the implementation needs to make the
/// claim true — a live transaction, a read lock, nothing at all for a caller
/// that has no gate mutations to race.
pub struct RootHold(#[allow(dead_code)] Box<dyn std::any::Any + Send>);

impl RootHold {
    pub fn new<T: std::any::Any + Send>(held: T) -> Self {
        Self(Box::new(held))
    }

    /// A hold over nothing, for a caller whose root state cannot change under
    /// it. Named so that using it is a claim rather than an oversight.
    pub fn nothing_can_change_this_root() -> Self {
        Self::new(())
    }
}

/// The remote operations the destroy path needs, as a narrow port.
///
/// **Why a port rather than using `StorageAdapter` directly.** Rule 4 tracks the
/// name `delete_object`, and it is deliberately tracked in *both* directions:
/// only `destroy.rs` may call it, and only `shepherd-storage` may implement it.
/// A test double implementing `StorageAdapter` would therefore be a violation —
/// which the gate caught, correctly, the first time this file had one.
///
/// So the tracked name appears exactly once, in the blanket impl below, inside
/// the one file allowed to name it. Everything else — the destroy path's own
/// logic, and every test double — speaks this port instead. That is the shape
/// the rule was asking for rather than an evasion of it: there is still exactly
/// one call site, and it is still here.
#[async_trait::async_trait]
pub trait RemoteGate: Send + Sync {
    /// The §4.9 key prefix configured for this target, if the gate knows it.
    ///
    /// Beside [`Self::target`] because it is the same fact: two logical targets
    /// can share one adapter and one bucket and be told apart only by their
    /// prefix, so a gate that knows which target it is must know where that
    /// target's objects live. Taking the prefix as a separate argument let a
    /// charge and gate for A delete the matching content object under B's
    /// prefix — same bucket, same adapter, different namespace, and neither B's
    /// policy proof nor B's budget involved.
    ///
    /// `None` for the same reason [`Self::target`] is: a bare adapter is a
    /// connection, and the prefix is configuration the catalog holds.
    fn prefix(&self) -> Option<&str>;

    /// Which target this gate speaks to, if it knows.
    ///
    /// The closing HEAD proves an object exists — on whatever target the gate
    /// happens to reach. Nothing tied that to the LOCATION that authorized the
    /// destruction, so a custody proof from target A could be paired with a
    /// HEAD against target B: under content attestation any same-sized object
    /// at a hash-named key on B satisfies it, and the last local copy is
    /// unlinked without A's replica ever being rechecked — A's may have
    /// vanished.
    ///
    /// `None` is not a skip. `execute_local_destruction` REFUSES a gate that
    /// cannot name its target, because "I do not know which target answered"
    /// is not a weaker proof than a mismatch, it is the same one.
    fn target(&self) -> Option<TargetId>;

    /// §4.10.2 step 3's cheap closing HEAD.
    async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>>;

    /// PM-2's remote destruction.
    async fn remove_object(&self, key: &ObjectKey, guard: &VersionGuard) -> Result<()>;
}

/// A [`RemoteGate`] that knows which target it speaks to.
///
/// The identity travels WITH the gate rather than beside it as another
/// argument, for the reason [`LocalDestroyRequest::fs_id`] documents about lock
/// keys: a value passed separately is a value that can be passed wrongly, and
/// the failure is silent and on the irreversible path. Wrapping is how the
/// caller says which target this adapter is, once, where it knows.
pub struct TargetGate<'a> {
    target: TargetId,
    prefix: &'a str,
    adapter: &'a dyn StorageAdapter,
}

impl<'a> TargetGate<'a> {
    pub fn new(target: TargetId, prefix: &'a str, adapter: &'a dyn StorageAdapter) -> Self {
        Self {
            target,
            prefix,
            adapter,
        }
    }
}

#[async_trait::async_trait]
impl RemoteGate for TargetGate<'_> {
    fn target(&self) -> Option<TargetId> {
        Some(self.target)
    }

    fn prefix(&self) -> Option<&str> {
        Some(self.prefix)
    }

    async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>> {
        RemoteGate::head_meta(&self.adapter, key).await
    }

    async fn remove_object(&self, key: &ObjectKey, guard: &VersionGuard) -> Result<()> {
        RemoteGate::remove_object(&self.adapter, key, guard).await
    }
}

#[async_trait::async_trait]
impl RemoteGate for &dyn StorageAdapter {
    /// A bare adapter does not know which target it is, nor where that
    /// target's objects live — both are facts the catalog holds, not the
    /// connection. Local destruction and bulk discard refuse it; remote
    /// discard, whose key the caller has already derived, does not need it.
    fn target(&self) -> Option<TargetId> {
        None
    }

    fn prefix(&self) -> Option<&str> {
        None
    }

    async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>> {
        StorageAdapter::head(*self, key)
            .await
            .map_err(|e| DestroyError::Storage(e.to_string()))
    }

    async fn remove_object(&self, key: &ObjectKey, guard: &VersionGuard) -> Result<()> {
        // THE call site. Rule 4a asserts this is the only file naming it;
        // `clippy::disallowed_methods` is denied workspace-wide and allowed only
        // by the `#![allow]` at the top of this file.
        StorageAdapter::delete_object(*self, key, guard)
            .await
            .map_err(|e| match e {
                // NOT flattened: a failed precondition is the provider stating
                // that it did not act, and that is the one thing an ambiguous
                // DELETE can never state. See `DestroyError::PreconditionFailed`.
                StorageError::PreconditionFailed { key, detail } => {
                    DestroyError::PreconditionFailed { key, detail }
                }
                other => DestroyError::Storage(other.to_string()),
            })
    }
}

/// Remote destruction — PM-2's `discard` branch.
///
/// **The seam T10 must use.** Rule 4 makes this file the sole caller of
/// `StorageAdapter::delete_object`, so `shepherd-tier::discard` calls *this*
/// rather than the adapter. Routing it here is not bureaucracy: PM-2 requires
/// the discard branch to go through the same intent + audit apparatus as local
/// destruction, and a second call site would be a second place for that to be
/// forgotten.
#[allow(clippy::too_many_arguments)]
pub async fn execute_remote_discard(
    intent: PreparedIntent,
    remote: &impl RemoteGate,
    key: &ObjectKey,
    guard: &VersionGuard,
    audit: &AuditLog,
    intent_gate: &dyn IntentGate,
    attestation: &str,
    now: Timestamp,
) -> Result<()> {
    // The intent must be THIS deletion's. `authorizes` was wired to the local
    // path alone, so an intent prepared for remote object A accompanied a
    // DELETE of object B: the audit record then cites A's intent id while the
    // durable recovery row describes A rather than the object that was
    // irreversibly removed — a forensic record pointing at the wrong object,
    // which is worse than none because recovery trusts it.
    //
    // Refused before `admit`, so a mismatch is not even charged against the
    // audit gate. The key is the whole binding and that is sufficient here:
    // §4.9 keys name the hash, so the key IS the statement about the bytes.
    intent
        .authorizes_object(key.as_str())
        .map_err(|detail| DestroyError::Unbound { detail })?;

    // Under the same gate as local destruction, and for the same reason: this
    // path is irreversible too, and a halt that only stopped the branch that set
    // it would not be the global halt §4.10.4 promises. The gate is therefore
    // held across the provider DELETE — see [`crate::audit`] for what that
    // costs.
    let permit = audit.admit().await?;

    // §4.4, the same sequence the local path records — the omission was in both
    // entry points, and a lifecycle only one half of the destroy apparatus
    // advances is a lifecycle recovery cannot read.
    let intent_id = intent.id();
    // A precondition here too — see the local path. Nothing irreversible has
    // happened yet, so this refuses rather than being logged past.
    if let Err(e) = intent_gate
        .advance(intent_id, IntentState::SyscallIssued)
        .await
    {
        drop(permit);
        return Err(e);
    }

    if let Err(e) = remote.remove_object(key, guard).await {
        // A refused precondition is not ambiguous: the provider says it did not
        // act. Nothing irreversible happened, so nothing is owed a record and
        // halting every other destruction would be an outage manufactured out
        // of a guard doing its job.
        if matches!(e, DestroyError::PreconditionFailed { .. }) {
            record_transition(intent_gate, intent_id, IntentState::OutcomeKnown).await;
            record_transition(intent_gate, intent_id, IntentState::Aborted).await;
            drop(permit);
            return Err(e);
        }
        return resolve_ambiguous_delete(
            e,
            intent,
            remote,
            key,
            guard,
            audit,
            permit,
            intent_gate,
            attestation,
            now,
        )
        .await;
    }

    permit.append(&AuditRecord {
        at: now,
        intent: intent.id(),
        kind: "remote",
        path: key.as_str().to_owned(),
        size: 0,
        blake3: None,
        attestation: attestation.to_owned(),
        target_keys: vec![key.as_str().to_owned()],
        reconstructed: false,
    })?;

    // Stops at `audited`, for the reason the local tail does: the catalog
    // change is the caller's, and settling the intent here would take it out of
    // `unresolved()` before anything had reconciled it.
    record_transition(intent_gate, intent_id, IntentState::OutcomeKnown).await;
    record_transition(intent_gate, intent_id, IntentState::Audited).await;
    Ok(())
}

/// Decide what an errored DELETE means, while the permit is still held.
///
/// # Why the error alone is not the answer
///
/// A failed `unlink(2)` is knowable: it either removed the directory entry or
/// it did not, and the errno says which. A failed `DeleteObject` is not. The
/// request goes out, the provider applies it, and the acknowledgement is lost
/// to a reset, a gateway timeout, or a 500 raised after the delete marker was
/// already written. The SDK surfaces an error in every one of those cases, so
/// treating the error as "nothing happened" — which is what a bare `?` here
/// did — silently drops the permit on an operation that may have been
/// irreversible, leaving no record and no halt.
///
/// # The three outcomes
///
/// The object's own state is the only thing that can settle it, so this asks:
///
/// * **gone** — the DELETE landed. Irreversible, so §4.10.4 owes it a record,
///   and the permit is still held precisely so it can be written now. The
///   provider error is not returned: the operation this function was asked to
///   perform demonstrably happened and is now audited.
/// * **still there** — a pre-operation failure (refused connection, 403,
///   precondition). Nothing irreversible happened, nothing is owed, and the
///   error goes back to the caller to retry. Halting here would manufacture an
///   outage out of a retryable error.
/// * **cannot tell** — the case the global halt exists for. An irreversible
///   step may have happened and its record cannot be completed, so subsequent
///   destruction stops until a human or a repair routine settles it.
///
/// Under [`VersionGuard::Version`] the comparison is against the **version**,
/// not merely the key's presence: on a versioned bucket the guarded version can
/// be gone while an older one still answers a plain HEAD, and reading that as
/// "still there" would put an irreversible delete back in the unaudited case
/// this exists to close.
#[allow(clippy::too_many_arguments)]
async fn resolve_ambiguous_delete(
    err: DestroyError,
    intent: PreparedIntent,
    remote: &impl RemoteGate,
    key: &ObjectKey,
    guard: &VersionGuard,
    audit: &AuditLog,
    permit: crate::audit::DestroyPermit<'_>,
    intent_gate: &dyn IntentGate,
    attestation: &str,
    now: Timestamp,
) -> Result<()> {
    let intent_id = intent.id();
    let unresolved = |audit: &AuditLog, permit, why: String| {
        let detail = format!(
            "remote destruction of {} failed ambiguously ({err}) and the outcome could not \
             be resolved: {why}",
            key.as_str()
        );
        // Set while the permit is still held, so the halt is in place before
        // any other destruction can be admitted.
        audit.halt_for_recovery(&detail);
        drop(permit);
        DestroyError::Storage(detail)
    };

    match remote.head_meta(key).await {
        // The KEY is gone, which is a different claim depending on the guard.
        //
        // Under `ContentAddressed` the key IS the identity, so an absent key
        // is an absent object and the DELETE landed. Fall through to the
        // record.
        Ok(None) if matches!(guard, VersionGuard::ContentAddressed { .. }) => {}

        // Under `Version` it settles nothing, and reading it as success was
        // the defect. `head` answers about the CURRENT version, and a delete
        // marker — pre-existing, or written by another writer — makes it
        // answer "absent" while the guarded version is still there as a
        // noncurrent one. So this is equally consistent with "the ambiguous
        // DELETE never reached the provider", and appending a destruction
        // record would describe an object that still exists.
        //
        // The same reasoning the version-mismatch arm below already applies,
        // reached from the other direction: `head_meta` cannot ask about a
        // specific version, so the honest answer is that this is unresolved.
        Ok(None) => {
            return Err(unresolved(
                audit,
                permit,
                "the key is absent, but the guard names a VERSION and a plain HEAD answers \
                 only about the current one — a delete marker hides a version that is still \
                 there, so this is equally consistent with the DELETE never having been \
                 applied"
                    .to_owned(),
            ));
        }

        Ok(Some(meta)) => match guard {
            // The key is the guard, and the key still answers: nothing was
            // deleted. No record is owed, and holding every other destruction
            // while this one is retried would be wrong.
            VersionGuard::ContentAddressed { .. } => {
                drop(permit);
                return Err(err);
            }
            VersionGuard::Version(v) if meta.version.as_ref() == Some(v) => {
                drop(permit);
                return Err(err);
            }
            // The guarded version is not the current one — and that settles
            // NOTHING. `head` answers about the current version only, so on a
            // versioned bucket `v` may still exist as a noncurrent version, and
            // the object may equally have been replaced by another writer
            // before the DELETE was applied. Reading this as "the delete
            // landed" would append a record for a destruction that may not have
            // happened; reading it as "it did not" would drop an irreversible
            // one. It is exactly the case the global halt exists for.
            VersionGuard::Version(v) => {
                return Err(unresolved(
                    audit,
                    permit,
                    format!(
                        "the guard named version {} and the key now answers with {:?}, which \
                         does not establish whether the guarded version was deleted",
                        v.as_opaque(),
                        meta.version.as_ref().map(|got| got.as_opaque()),
                    ),
                ));
            }
        },

        Err(head_err) => {
            return Err(unresolved(audit, permit, head_err.to_string()));
        }
    }

    tracing::warn!(
        key = %key.as_str(),
        error = %err,
        "the remote DELETE reported an error but the object is gone; auditing it as destroyed"
    );
    permit.append(&AuditRecord {
        at: now,
        intent: intent.id(),
        kind: "remote",
        path: key.as_str().to_owned(),
        size: 0,
        blake3: None,
        attestation: attestation.to_owned(),
        target_keys: vec![key.as_str().to_owned()],
        reconstructed: false,
    })?;

    // Stops at `audited`, for the reason the local tail does: the catalog
    // change is the caller's, and settling the intent here would take it out of
    // `unresolved()` before anything had reconciled it.
    record_transition(intent_gate, intent_id, IntentState::OutcomeKnown).await;
    record_transition(intent_gate, intent_id, IntentState::Audited).await;
    Ok(())
}

/// BLAKE3 over an already-open handle.
///
/// Takes the `File` rather than a path on purpose: `shepherd_scan::hash_file`
/// opens by path, and step 4 forbids exactly that re-resolution.
fn hash_through_handle(handle: &std::fs::File) -> Result<Blake3Hash> {
    use std::io::{Read, Seek, SeekFrom};
    let mut h = handle
        .try_clone()
        .map_err(|e| DestroyError::Io(e.to_string()))?;
    h.seek(SeekFrom::Start(0))
        .map_err(|e| DestroyError::Io(e.to_string()))?;
    let mut hasher = blake3::Hasher::new();
    let mut buf = vec![0u8; 64 * 1024];
    loop {
        let n = h
            .read(&mut buf)
            .map_err(|e| DestroyError::Io(e.to_string()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(Blake3Hash::from_bytes(*hasher.finalize().as_bytes()))
}

fn nlink_of(md: &std::fs::Metadata) -> u64 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        md.nlink()
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        1
    }
}

fn allocated_of(md: &std::fs::Metadata) -> Option<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(md.blocks() * 512)
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        None
    }
}

// POSIX-only, and that is a COVERAGE GAP rather than a solved problem.
//
// These tests assert file identity through `std::os::unix::fs::MetadataExt`
// (`dev`/`ino`) to prove a destroy did not silently act on a replaced file.
// Windows has an equivalent — `file_index` and `volume_serial_number` — and
// nobody has written it, so the whole module is gated rather than half-ported.
//
// What Windows therefore does NOT run: the acquisition-floor refusals these
// tests now assert on every non-Linux platform. That refusal is real on Windows
// too — `open_handles()` is Linux-only, so the floor fails closed there exactly
// as it does on macOS — and nothing checks it. Phase 3 owns Windows destroy;
// whoever takes it should port `identity_of` first and delete this comment,
// because the value of these tests off-Linux is precisely that they assert the
// refusal rather than the destruction.
#[cfg(all(test, unix))]
#[path = "destroy_tests.rs"]
mod tests;
