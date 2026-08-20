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
use shepherd_core::ObjectKey;
use shepherd_core::{Blake3Hash, FsId, IntentId, Timestamp};
use shepherd_placeholder::provider::{PlaceholderProvider, Staged};
use shepherd_scan::floors::{self, FloorContext, FloorInput, FloorPolicy};
use shepherd_storage::adapter::{ObjectMeta, StorageAdapter, VersionGuard};

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
    #[error("local content changed after verification: expected {expected}, staged holds {actual}")]
    ContentChanged { expected: String, actual: String },
    #[error("storage: {0}")]
    Storage(String),
    #[error("io: {0}")]
    Io(String),
}

pub type Result<T> = std::result::Result<T, DestroyError>;

/// Everything the destroy path needs about one file.
pub struct LocalDestroyRequest<'a> {
    pub intent: IntentId,
    pub path: &'a Path,
    pub root: &'a ScanRoot,
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
}

/// Execute §4.10's local destruction for one file.
///
/// Deliberately **not** named `destroy_local`: that name is tracked by rule 4,
/// and a public entry point bearing it would make every caller — T10's discard,
/// the integration tests — trip the gate. The tracked name belongs to the
/// primitive; this is the protocol around it.
#[allow(clippy::too_many_arguments)]
pub async fn execute_local_destruction(
    req: &LocalDestroyRequest<'_>,
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
    let outcome = destroy_staged(req, &staged, remote, now).await;
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

    // --- step 6: the irreversible one ---------------------------------------
    //
    // If the unlink itself fails, the destruction has NOT happened — the staged
    // entry is still there and still holds the bytes. §4.10.4 is
    // abort-forward-never, so this restores rather than leaving the file
    // orphaned in staging for a later recovery pass to find. Startup recovery
    // remains the backstop (the entry is discoverable via `list_staged`), but
    // recovering in-process while we still hold the context is strictly better
    // than deferring to a pass that has to reconstruct it.
    if let Err(e) = provider.destroy_local(&staged, req.expected_hash) {
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
        intent: req.intent,
        kind: "local",
        path: req.path.display().to_string(),
        size: req.expected_size,
        blake3: Some(req.expected_hash),
        attestation: format!("{:?}", req.custodian.attestation).to_lowercase(),
        target_keys: vec![req.remote_key.as_str().to_owned()],
        reconstructed: false,
    })?;

    Ok(())
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
    let meta = remote.head_meta(req.remote_key).await?;
    let check = ClosingCheck {
        mode: req.custodian.attestation,
        observed_version: meta.as_ref().and_then(|m| m.version.clone()),
        observed_size: meta.as_ref().map(|m| m.size),
    };
    check
        .evaluate(req.custodian.object_version.as_ref(), req.expected_size)
        .map_err(DestroyError::Refused)?;

    Ok(())
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
    /// §4.10.2 step 3's cheap closing HEAD.
    async fn head_meta(&self, key: &ObjectKey) -> Result<Option<ObjectMeta>>;

    /// PM-2's remote destruction.
    async fn remove_object(&self, key: &ObjectKey, guard: &VersionGuard) -> Result<()>;
}

#[async_trait::async_trait]
impl RemoteGate for &dyn StorageAdapter {
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
            .map_err(|e| DestroyError::Storage(e.to_string()))
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
pub async fn execute_remote_discard(
    intent: IntentId,
    remote: &impl RemoteGate,
    key: &ObjectKey,
    guard: &VersionGuard,
    audit: &AuditLog,
    attestation: &str,
    now: Timestamp,
) -> Result<()> {
    // Under the same gate as local destruction, and for the same reason: this
    // path is irreversible too, and a halt that only stopped the branch that set
    // it would not be the global halt §4.10.4 promises. The gate is therefore
    // held across the provider DELETE — see [`crate::audit`] for what that
    // costs.
    let permit = audit.admit().await?;

    remote.remove_object(key, guard).await?;

    permit.append(&AuditRecord {
        at: now,
        intent,
        kind: "remote",
        path: key.as_str().to_owned(),
        size: 0,
        blake3: None,
        attestation: attestation.to_owned(),
        target_keys: vec![key.as_str().to_owned()],
        reconstructed: false,
    })?;
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
