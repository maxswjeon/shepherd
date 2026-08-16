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

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};

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
}

impl AuditLog {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| AuditError::Write {
                path: parent.display().to_string(),
                detail: e.to_string(),
            })?;
        }
        Ok(Self {
            path: path.to_path_buf(),
            halted: AtomicBool::new(false),
        })
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
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)
            .map_err(|e| self.halt(e.to_string()))?;
        f.write_all(record.to_line().as_bytes())
            .map_err(|e| self.halt(e.to_string()))?;
        f.sync_all().map_err(|e| self.halt(e.to_string()))?;
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
            let log = AuditLog::open(&p).unwrap();
            log.append(&record(1)).unwrap();
            log.append(&record(2)).unwrap();
        }
        let log = AuditLog::open(&p).unwrap();
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
        let log = AuditLog::open(&t.0.join("a.jsonl")).unwrap();
        let mut r = record(1);
        r.attestation = "content".into();
        log.append(&r).unwrap();
        assert!(log.read_all()[0].contains("\"attestation\":\"content\""));
    }

    /// A failed audit write halts destruction. The file is already gone by this
    /// point, so refusing this one is not available — stopping the *next* one
    /// is the only protection left.
    #[test]
    fn a_failed_write_halts_destruction() {
        let t = Tmp::new("halt");
        // A directory where the log file should be: opening it for append fails.
        let p = t.0.join("blocked.jsonl");
        std::fs::create_dir(&p).unwrap();

        let log = AuditLog::open(&p).unwrap();
        assert!(!log.is_halted());
        assert!(log.append(&record(1)).is_err());
        assert!(
            log.is_halted(),
            "a failed audit write must halt destruction"
        );

        let err = log.check_not_halted().unwrap_err();
        assert!(matches!(err, AuditError::Halted { .. }));
    }

    #[test]
    fn a_halt_can_only_be_cleared_explicitly() {
        let t = Tmp::new("resume");
        let log = AuditLog::open(&t.0.join("a.jsonl")).unwrap();
        log.halt_for_recovery("intent reached the syscall with no audit record");
        assert!(log.check_not_halted().is_err());
        log.resume();
        assert!(log.check_not_halted().is_ok());
    }

    #[test]
    fn a_reconstructed_record_says_so() {
        let t = Tmp::new("recon");
        let log = AuditLog::open(&t.0.join("a.jsonl")).unwrap();
        let mut r = record(1);
        r.reconstructed = true;
        log.append(&r).unwrap();
        assert!(log.read_all()[0].contains("\"reconstructed\":true"));
    }
}
