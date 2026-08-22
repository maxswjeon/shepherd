//! The destroy audit log — an append-only **file**, not a table.
//!
//! §4.4 is explicit: "The destroy audit log is a separate append-only file, not
//! a table — a row can be lost with the database; the forensic record must not
//! be able to be." The intent journal is the opposite kind of record: it must be
//! transactionally consistent with the catalog it describes, so it *is* a table
//! (`shepherd_catalog::intent`). Two records, two jobs, and merging them would
//! sacrifice one property or the other.
//!
//! # Ordering, and why an audit failure is not the same as an intent failure
//!
//! §4.10.4 puts them at different points, so they have different answers:
//!
//! * A failed **intent** fsync happens *before* the syscall → **refuse the
//!   destruction.** Fail closed; nothing has happened yet.
//! * A failed **audit** write happens *after* the syscall → refusing is not
//!   available, the file is already gone. The record is reconstructed from the
//!   intent and marked `reconstructed-after-crash`, and **subsequent
//!   destruction halts** until audit writes succeed again.
//!
//! Iteration 3 conflated these. They are different tests because they are at
//! different points in the ordering, and [`AuditLog::is_halted`] is the
//! persistent consequence rather than a log line — a halt that only existed in
//! memory would evaporate at exactly the restart that most needs it.
//!
//! # The halt is GLOBAL, so reading a flag is not enough
//!
//! §4.10.4 says *subsequent* destruction halts — every destruction, not the
//! ones that happen to check afterwards. A caller that reads [`AuditLog::is_halted`]
//! and then, some milliseconds later, performs an irreversible syscall has not
//! delivered that: another destruction can fail its append in the gap, and the
//! first one crosses the unlink anyway. Per-file locking cannot help, because
//! two destructions of two different files are exactly the case that is allowed
//! to overlap.
//!
//! So admission and the append are coordinated rather than merely ordered.
//! [`AuditLog::admit`] takes a process-wide gate, re-reads the halt **inside**
//! it, and hands back a [`DestroyPermit`]; the permit is what the irreversible
//! step runs under and what [`DestroyPermit::append`] consumes. No operation can
//! be between its unlink and its append while another one is admitted, so a halt
//! set by any append is seen by every destruction that has not already crossed.
//!
//! **What this costs, stated rather than hidden.** The irreversible step of every
//! destruction is serialized against every other — for local destruction an
//! `unlink` plus an fsync'd append, and for [`crate::destroy::execute_remote_discard`]
//! a network DELETE. Remote discards therefore do not overlap. That is the price
//! of the promise: the alternative is a global halt that is true of the flag and
//! false of the behaviour. The rest of the destroy path — floors, staging,
//! re-hash, the closing HEAD — stays fully concurrent, and it is where the time
//! actually goes.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

use tokio::sync::{Mutex as AsyncMutex, MutexGuard as AsyncMutexGuard};

use shepherd_catalog::intent::{DestroyIntent, IntentState};
use shepherd_core::{Blake3Hash, IntentId, Timestamp};

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error("cannot write audit record to {path}: {detail}")]
    Write { path: String, detail: String },
    #[error(
        "destruction is HALTED: a previous audit write failed, so the forensic record is \
         incomplete. Destruction stays refused until audit writes succeed ({detail})"
    )]
    Halted { detail: String },
}

pub type Result<T> = std::result::Result<T, AuditError>;

/// One destroyed thing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    pub at: Timestamp,
    pub intent: IntentId,
    pub kind: &'static str,
    pub path: String,
    pub size: u64,
    pub blake3: Option<Blake3Hash>,
    /// Which locations attested, and how. §4.10.2's rider requires the
    /// attestation mode on **every** destroy audit record — "silently landing
    /// on B while believing A is exactly how a safety claim decays into a
    /// slogan".
    pub attestation: String,
    pub target_keys: Vec<String>,
    /// Set when this record was rebuilt from the intent after an audit failure.
    pub reconstructed: bool,
}

impl AuditRecord {
    /// One line of JSON. Line-delimited so a truncated tail costs one record
    /// rather than the file, and so `tail -f` is a usable forensic tool.
    fn to_line(&self) -> String {
        let obj = serde_json::json!({
            "at": self.at.as_nanos(),
            "intent": self.intent.get(),
            "kind": self.kind,
            "path": self.path,
            "size": self.size,
            "blake3": self.blake3.map(|h| h.to_hex()),
            "attestation": self.attestation,
            "target_keys": self.target_keys,
            "reconstructed": self.reconstructed,
        });
        format!("{obj}\n")
    }
}

/// Append-only audit log.
#[derive(Debug)]
pub struct AuditLog {
    path: PathBuf,
    /// Set when a write failed. Persists for the process; recovery at startup
    /// re-derives it from unresolved intents.
    halted: AtomicBool,
    /// Serializes [read the halt → irreversible step → append].
    ///
    /// Async because the remote branch's irreversible step is a network call
    /// held across an await. Not a second source of truth for the halt: it makes
    /// the ONE source of truth readable at a moment when acting on it is still
    /// possible.
    gate: AsyncMutex<()>,
    /// `(dev, ino)` of the file whose name `open` durably published.
    ///
    /// `append` reopens by path — it does not hold a descriptor — so without
    /// this it cannot tell the published file from a different one that has
    /// taken its name.
    ///
    /// `None` off unix, and the consequence is worth stating rather than
    /// leaving to be discovered: **on Windows a rotated or replaced log is not
    /// detected**, because the equivalent identity sits behind an unstable
    /// `std` feature and reaching it means a platform dependency — Phase 3's,
    /// with the rest of Windows durability that `sync_dir` already defers. The
    /// vanished-file half holds on every platform, since `append` no longer
    /// creates.
    identity: Option<(u64, u64)>,
}

/// Permission to perform one irreversible destruction.
///
/// Held from before the syscall until the record is written, which is what makes
/// [`AuditLog::is_halted`] mean "no destruction will proceed" rather than "no
/// destruction will start". Existence is the permission; [`Self::append`]
/// consumes it, and dropping it without appending is the correct thing to do
/// when the irreversible step did not happen after all.
#[must_use = "the permit holds the destroy gate; drop it deliberately or spend \
              it on the audit record"]
pub struct DestroyPermit<'a> {
    log: &'a AuditLog,
    /// Released when the permit is dropped. Never read.
    _gate: AsyncMutexGuard<'a, ()>,
}

impl std::fmt::Debug for DestroyPermit<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DestroyPermit")
            .field("log", &self.log.path)
            .finish()
    }
}

impl DestroyPermit<'_> {
    /// Record the destruction this permit authorized, then release the gate.
    ///
    /// Takes `self` because a permit is good for exactly one destruction. A
    /// second append under the same permit would be a second irreversible act
    /// admitted by one reading of the halt.
    pub fn append(self, record: &AuditRecord) -> Result<()> {
        self.log.append(record)
    }
}

/// fsync a directory, so an entry created in it survives a crash.
///
/// POSIX-only, and a no-op elsewhere rather than an error: opening a directory
/// as a file is not something the Windows API permits, so the durability this
/// buys on unix simply is not expressible there. Silently doing nothing is the
/// honest translation — Windows durability is Phase 3's, along with the rest of
/// the platform.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// `(dev, ino)` for an OPEN file, or `None` where that pair is unavailable.
///
/// `st_dev` is used here for what it is good for — telling two files apart at
/// one instant — and never stored beyond the life of the process, which is the
/// distinction §4.4's prohibition draws.
#[cfg(unix)]
fn file_identity(f: &std::fs::File) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let md = f.metadata().ok()?;
    Some((md.dev(), md.ino()))
}

#[cfg(not(unix))]
fn file_identity(_f: &std::fs::File) -> Option<(u64, u64)> {
    None
}

/// The same pair for a PATH rather than an open file.
///
/// The distinction is the whole point of having both: `file_identity` answers
/// "which file did I open", and this answers "which file does the name resolve
/// to now". A rotation is exactly the case where those two differ.
#[cfg(unix)]
fn path_identity(p: &Path) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let md = std::fs::metadata(p).ok()?;
    Some((md.dev(), md.ino()))
}

#[cfg(not(unix))]
fn path_identity(_p: &Path) -> Option<(u64, u64)> {
    None
}

impl AuditLog {
    /// Open the log, creating the file and **durably publishing its name**
    /// before any destruction can be admitted.
    ///
    /// The file is created here rather than by the first `append`, and its
    /// parent directory is fsynced. `sync_all` on a freshly created file makes
    /// its CONTENTS durable and says nothing about the directory entry that
    /// names it, so on a filesystem where a new entry needs its parent fsynced
    /// a power loss after the first append could lose the audit path and the
    /// record with it — after an irreversible deletion had already completed.
    /// That is precisely the outcome this file exists to prevent, arriving
    /// through the one write it cannot retry.
    ///
    /// Done at `open` and not at `append`: the cost is one `fsync` per daemon
    /// start rather than a branch on the hot path, and `open` happens before
    /// anything can be destroyed, which is the ordering the guarantee needs.
    pub fn open(path: &Path, unresolved: &[DestroyIntent]) -> Result<Self> {
        let io = |p: &Path, e: std::io::Error| AuditError::Write {
            path: p.display().to_string(),
            detail: e.to_string(),
        };
        if let Some(parent) = path.parent() {
            // Every directory `create_dir_all` creates needs ITS OWN parent
            // fsynced, not just the deepest one. Syncing `parent` alone
            // publishes the log file's entry inside it and leaves the entry
            // NAMING that directory unpublished in the level above — so a power
            // loss can take the whole new directory away, and the only audit
            // log with it, after a destruction has completed.
            //
            // Collected before the create, deepest first, so only the levels
            // this call actually adds are synced.
            let created: Vec<&Path> = parent.ancestors().take_while(|a| !a.exists()).collect();
            std::fs::create_dir_all(parent).map_err(|e| io(parent, e))?;
            for dir in created.iter().rev() {
                if let Some(above) = dir.parent() {
                    sync_dir(above).map_err(|e| io(above, e))?;
                }
            }
        }
        let published = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| io(path, e))?;
        // Taken from the DESCRIPTOR, not by stat'ing the path afterwards: the
        // point is to record the identity of the file this call published, and
        // a second lookup by name could already be answering about another one.
        let identity = file_identity(&published);
        if let Some(parent) = path.parent() {
            sync_dir(parent).map_err(|e| io(parent, e))?;
        }
        // THE HALT IS RECONSTRUCTED, not reset.
        //
        // `halted` is in-memory, so reopening the log after a crash cleared it
        // — and the crash that matters is the one that left an irreversible
        // step with an incomplete record, which is the exact condition this
        // flag exists to hold. A restarted process could therefore admit
        // another destruction while the forensic record of the last one was
        // still unfinished, which is the opposite of what this type documents.
        //
        // Rebuilt from the journal rather than persisted separately: the
        // journal already knows, and a second durable copy of one fact is a
        // second thing to keep in step.
        //
        // Only POST-SYSCALL states halt. `prepared` means nothing irreversible
        // happened, so an abandoned preparation must not stop the daemon
        // forever; `audited` means the record IS written and only the catalog
        // change is outstanding, which is the caller's to finish and not a
        // forensic gap.
        let log = Self {
            path: path.to_path_buf(),
            halted: AtomicBool::new(false),
            gate: AsyncMutex::new(()),
            identity,
        };
        if let Some(i) = unresolved.iter().find(|i| {
            matches!(
                i.state,
                IntentState::SyscallIssued
                    | IntentState::OutcomeKnown
                    | IntentState::OutcomeAmbiguous
            )
        }) {
            log.halt_for_recovery(&format!(
                "intent {} is `{}`: an irreversible step may have happened and its record is \
                 not complete. Resolve it before any further destruction",
                i.id.get(),
                i.state.as_str()
            ));
        }
        Ok(log)
    }

    /// [`AuditLog::open`] for a caller with no journal to consult.
    ///
    /// Named so that using it is a CLAIM — "nothing could have been left
    /// unresolved" — rather than the path of least resistance. Every test that
    /// is not about recovery uses it; the daemon must not.
    pub fn open_with_no_unresolved_intents(path: &Path) -> Result<Self> {
        Self::open(path, &[])
    }

    /// Whether destruction is currently refused because the forensic record is
    /// incomplete.
    pub fn is_halted(&self) -> bool {
        self.halted.load(Ordering::SeqCst)
    }

    /// Refuse if halted. Called by the destroy path **before** it does anything
    /// irreversible.
    pub fn check_not_halted(&self) -> Result<()> {
        if self.is_halted() {
            return Err(AuditError::Halted {
                detail: format!("audit log at {}", self.path.display()),
            });
        }
        Ok(())
    }

    /// Admit one destruction through its irreversible step.
    ///
    /// Waits until no other destruction is between its syscall and its audit
    /// append, then re-reads the halt. Refusing here is refusing *before*
    /// anything irreversible, which is the whole reason the check is at this
    /// point rather than only at the top of the caller.
    ///
    /// The cheap top-of-path [`Self::check_not_halted`] is still worth making:
    /// it refuses before staging, so a halted log does not move a file into
    /// staging and back out again for nothing. This one is the load-bearing
    /// check.
    pub async fn admit(&self) -> Result<DestroyPermit<'_>> {
        let gate = self.gate.lock().await;
        // INSIDE the gate. Read outside it, this is the same one-time check the
        // caller already made, and the window is back.
        self.check_not_halted()?;
        Ok(DestroyPermit {
            log: self,
            _gate: gate,
        })
    }

    /// Append and fsync.
    ///
    /// The fsync is the point. An audit record sitting in the page cache when
    /// the machine loses power describes a destruction that happened with no
    /// surviving evidence — which is the one outcome this file exists to
    /// prevent.
    ///
    /// On failure the log **halts**: the caller cannot un-destroy the file, so
    /// the only remaining protection is to stop destroying more.
    pub fn append(&self, record: &AuditRecord) -> Result<()> {
        // NOT `create(true)`. Recreating the file here silently undid what
        // `open` exists to guarantee: the forensic history was already gone,
        // the fresh directory entry was never fsynced the way `open` fsyncs
        // one, and the append succeeded with `halted` still false — so the
        // documented halt did not fire on the one condition it is for.
        //
        // A missing file now fails the open and halts through the same arm as
        // any other write failure.
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&self.path)
            .map_err(|e| self.halt(e.to_string()))?;
        // And a file that is PRESENT but is not the one `open` published — the
        // log rotated out from under a running daemon — is the same loss of
        // history wearing the right name.
        if let (Some(published), Some(now)) = (self.identity, file_identity(&f))
            && published != now
        {
            return Err(self.halt(
                "the audit log at this path is not the file this process published: it has \
                 been replaced or rotated, and the records written before it are no longer \
                 at the configured path"
                    .to_string(),
            ));
        }
        f.write_all(record.to_line().as_bytes())
            .map_err(|e| self.halt(e.to_string()))?;
        f.sync_all().map_err(|e| self.halt(e.to_string()))?;

        // DURABLE, AND STILL AT THE CONFIGURED PATH. The check above compares
        // the descriptor this call opened; a rotation landing between that open
        // and this write finds the comparison already passed, and the record is
        // then fsynced into a file that no longer answers to the audit path.
        // The append returned success, nothing halted, and the next destruction
        // was admitted against a path whose history had moved.
        //
        // Asked AFTER the fsync, not before, and deliberately: the record is
        // more useful written than withheld, and it lands in the file holding
        // all of its predecessors. What must not happen is reporting that as an
        // ordinary success — so the record is kept, and the log halts.
        //
        // This closes the window rather than narrowing it: any rotation, before
        // or during, leaves the path naming a different file than the one this
        // process published, and both checks compare against that same
        // published identity.
        if let Some(published) = self.identity
            && path_identity(&self.path) != Some(published)
        {
            return Err(self.halt(
                "the audit log was renamed or replaced while this record was being written. \
                 The record is durable in the file this process opened, which still holds \
                 the whole history — but that file is no longer at the configured path, so \
                 nothing further may be destroyed against it"
                    .to_string(),
            ));
        }
        Ok(())
    }

    fn halt(&self, detail: String) -> AuditError {
        self.halted.store(true, Ordering::SeqCst);
        tracing::error!(
            path = %self.path.display(),
            %detail,
            "AUDIT WRITE FAILED — destruction halted until this succeeds"
        );
        AuditError::Write {
            path: self.path.display().to_string(),
            detail,
        }
    }

    /// Halt without a write attempt. Used by startup recovery when it finds an
    /// intent that reached the syscall but has no audit record.
    pub fn halt_for_recovery(&self, detail: &str) {
        self.halted.store(true, Ordering::SeqCst);
        tracing::error!(%detail, "destruction halted by recovery");
    }

    /// Clear the halt. Deliberately explicit: it means a human or a repair
    /// routine has established that the record is whole again.
    pub fn resume(&self) {
        self.halted.store(false, Ordering::SeqCst);
    }

    pub fn read_all(&self) -> Vec<String> {
        std::fs::read_to_string(&self.path)
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let d =
                std::env::temp_dir().join(format!("shepherd-audit-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn record(n: i64) -> AuditRecord {
        AuditRecord {
            at: Timestamp::from_nanos(n),
            intent: IntentId::new(n),
            kind: "local",
            path: format!("/data/{n}.raw"),
            size: 1024,
            blake3: Some(Blake3Hash::from_bytes([9; 32])),
            attestation: "version".into(),
            target_keys: vec!["p/objects/aa/bb/cc".into()],
            reconstructed: false,
        }
    }

    #[test]
    fn records_append_in_order_and_survive_reopen() {
        let t = Tmp::new("append");
        let p = t.0.join("destroy-audit.jsonl");
        {
            let log = AuditLog::open_with_no_unresolved_intents(&p).unwrap();
            log.append(&record(1)).unwrap();
            log.append(&record(2)).unwrap();
        }
        let log = AuditLog::open_with_no_unresolved_intents(&p).unwrap();
        let lines = log.read_all();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("/data/1.raw"));
        assert!(lines[1].contains("/data/2.raw"));
    }

    /// §4.10.2's rider: the attestation mode is on every record, so a later
    /// reader can tell whether the provider attested or Shepherd did.
    #[test]
    fn every_record_names_the_attestation_mode() {
        let t = Tmp::new("attest");
        let log = AuditLog::open_with_no_unresolved_intents(&t.0.join("a.jsonl")).unwrap();
        let mut r = record(1);
        r.attestation = "content".into();
        log.append(&r).unwrap();
        assert!(log.read_all()[0].contains("\"attestation\":\"content\""));
    }

    /// A failed audit write halts destruction. The file is already gone by this
    /// point, so refusing this one is not available — stopping the *next* one
    /// is the only protection left.
    /// The log's NAME is durable before any destruction can be admitted.
    ///
    /// `sync_all` on a freshly created file makes its contents durable and says
    /// nothing about the directory entry naming it. On a filesystem where a new
    /// entry needs its parent fsynced, a power loss after the first append
    /// could therefore lose the audit path and the record with it — after an
    /// irreversible deletion had already completed, through the one write this
    /// module cannot retry.
    #[test]
    fn opening_the_log_creates_and_publishes_it() {
        let t = Tmp::new("publish");
        // Two missing levels, not one: `create_dir_all` adds an entry in EACH
        // of them, and syncing only the deepest leaves the entry naming it
        // unpublished in the level above — so a power loss takes the whole
        // directory and the only audit log with it.
        let p = t.0.join("nested").join("deeper").join("destroy.jsonl");
        assert!(!p.exists());

        let log = AuditLog::open_with_no_unresolved_intents(&p).unwrap();

        assert!(
            p.exists(),
            "the log file must exist before anything can be destroyed, not after the first \
             record is appended to it"
        );
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "");

        // And it is a working log, not merely a created file.
        log.append(&record(1)).unwrap();
        assert_eq!(log.read_all().len(), 1);
    }

    #[test]
    fn a_failed_write_halts_destruction() {
        let t = Tmp::new("halt");
        let p = t.0.join("blocked.jsonl");

        // Opened normally FIRST — `open` now creates the file and fsyncs its
        // parent, so a directory sitting at the path is refused there rather
        // than at the first append, which is the better failure and not the one
        // under test. The log is then replaced by a directory, so the next
        // append fails on a log that had opened cleanly: an audit file that
        // becomes unwritable after the daemon started.
        let log = AuditLog::open_with_no_unresolved_intents(&p).unwrap();
        std::fs::remove_file(&p).unwrap();
        std::fs::create_dir(&p).unwrap();
        assert!(!log.is_halted());
        assert!(log.append(&record(1)).is_err());
        assert!(
            log.is_halted(),
            "a failed audit write must halt destruction"
        );

        let err = log.check_not_halted().unwrap_err();
        assert!(matches!(err, AuditError::Halted { .. }));
    }

    /// A vanished audit log halts; it is not quietly recreated.
    ///
    /// `append` used `create(true)`, so a log deleted or rotated after `open`
    /// was replaced by an empty file: the append succeeded, `halted` stayed
    /// false, the forensic history of every destruction so far was gone, and
    /// the new directory entry was never fsynced the way `open` fsyncs one.
    /// The one condition the halt is documented for was the one it missed.
    #[test]
    fn a_vanished_audit_log_halts_rather_than_being_recreated() {
        let t = Tmp::new("vanished");
        let p = t.0.join("gone.jsonl");
        let log = AuditLog::open_with_no_unresolved_intents(&p).unwrap();
        log.append(&record(1)).expect("the first append works");

        std::fs::remove_file(&p).unwrap();
        assert!(
            log.append(&record(2)).is_err(),
            "an audit log that is no longer at its path must not be recreated"
        );
        assert!(log.is_halted(), "and destruction must halt");
        assert!(
            !p.exists(),
            "the halted append must not have left a fresh log behind, which \
             would read as an intact history containing one record"
        );
    }

    /// And a log REPLACED between opens is the same loss wearing the right
    /// name: the path resolves, the file is writable, and everything written
    /// before it is somewhere else.
    ///
    /// Unix only, because the detection is. `file_identity` needs `(dev, ino)`,
    /// and the Windows equivalent — `GetFileInformationByHandle`'s volume
    /// serial and file index — is behind an unstable `std` feature, so reaching
    /// it means a platform dependency. That belongs with the rest of Windows
    /// durability in Phase 3, alongside `sync_dir`, which already does nothing
    /// there for the same reason. The VANISHED half is caught on every
    /// platform: `append` no longer creates, so a missing file simply fails to
    /// open.
    #[cfg(unix)]
    #[test]
    fn a_replaced_audit_log_halts() {
        let t = Tmp::new("replaced");
        let p = t.0.join("swapped.jsonl");
        let log = AuditLog::open_with_no_unresolved_intents(&p).unwrap();
        log.append(&record(1)).expect("the first append works");

        // Rotated: the original moved aside and a new file put in its place.
        std::fs::rename(&p, t.0.join("swapped.jsonl.1")).unwrap();
        std::fs::write(&p, b"").unwrap();

        let err = log
            .append(&record(2))
            .expect_err("a different file at the audit path must halt");
        // On "replaced" rather than on either guard's exact wording. TWO
        // guards can produce this — the descriptor comparison before the write
        // and the path comparison after it — and which one fires depends on
        // when the rename lands. Asserting one message would pass only for one
        // interleaving and call the other a regression. Each was checked to
        // halt on its own by disabling the other.
        assert!(
            err.to_string().contains("replaced"),
            "the halt must say what happened: {err}"
        );
        assert!(log.is_halted());
    }

    #[test]
    fn a_halt_can_only_be_cleared_explicitly() {
        let t = Tmp::new("resume");
        let log = AuditLog::open_with_no_unresolved_intents(&t.0.join("a.jsonl")).unwrap();
        log.halt_for_recovery("intent reached the syscall with no audit record");
        assert!(log.check_not_halted().is_err());
        log.resume();
        assert!(log.check_not_halted().is_ok());
    }

    #[test]
    fn a_reconstructed_record_says_so() {
        let t = Tmp::new("recon");
        let log = AuditLog::open_with_no_unresolved_intents(&t.0.join("a.jsonl")).unwrap();
        let mut r = record(1);
        r.reconstructed = true;
        log.append(&r).unwrap();
        assert!(log.read_all()[0].contains("\"reconstructed\":true"));
    }

    /// The halt survives a restart, rebuilt from the journal.
    ///
    /// `halted` is in-memory, so reopening the log cleared it — and the crash
    /// that matters is the one that left an irreversible step with an
    /// incomplete record, which is the exact condition the flag exists to hold.
    /// A restarted process could admit another destruction while the forensic
    /// record of the last one was unfinished.
    #[test]
    fn a_reopened_log_halts_on_an_unresolved_post_syscall_intent() {
        use shepherd_catalog::intent::{DestroyIntent, IntentKind};

        let t = Tmp::new("halt-rebuild");
        let p = t.0.join("a.jsonl");

        let intent = |state: IntentState| DestroyIntent {
            id: IntentId::new(7),
            kind: IntentKind::Local,
            file_id: Some(1),
            path: "/data/a.raw".into(),
            size: 10,
            blake3: None,
            state,
            batch_id: None,
            episode_id: None,
        };

        // POST-SYSCALL and unsettled: an irreversible step may have happened
        // and its record is not complete.
        for state in [
            IntentState::SyscallIssued,
            IntentState::OutcomeKnown,
            IntentState::OutcomeAmbiguous,
        ] {
            let log = AuditLog::open(&p, &[intent(state)]).unwrap();
            assert!(
                log.is_halted(),
                "reopening with an unresolved `{}` intent must halt",
                state.as_str()
            );
            assert!(log.check_not_halted().is_err());
        }

        // PRE-SYSCALL, and the record-is-written case. `prepared` means nothing
        // irreversible happened, so an abandoned preparation must not stop the
        // daemon forever; `audited` means the record IS complete and only the
        // catalog change is outstanding, which is the caller's to finish.
        for state in [IntentState::Prepared, IntentState::Audited] {
            let log = AuditLog::open(&p, &[intent(state)]).unwrap();
            assert!(
                !log.is_halted(),
                "reopening with a `{}` intent must not halt",
                state.as_str()
            );
        }

        // And nothing unresolved at all is the ordinary start.
        assert!(!AuditLog::open(&p, &[]).unwrap().is_halted());
    }
}
