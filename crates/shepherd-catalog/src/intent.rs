//! The destroy intent journal (§4.10.4).
//!
//! **Scope, stated up front so nobody mistakes this for the destroy path.**
//! This module is the *journal*: it writes intent rows, moves them between the
//! states §4.4 enumerates, and lists the ones a crash left unresolved. The
//! protocol that decides *whether* to destroy — remote re-read and hash match,
//! revalidation immediately before the syscall, handle/staging binding, the
//! audit record, abort-forward-never recovery — is `shepherd-tier::destroy`,
//! Phase 2, task T8. Nothing here destroys anything, and nothing here should
//! grow the ability to.
//!
//! # Why the journal is separate from the audit log
//!
//! §4.4 puts the destroy **audit** log in a separate append-only *file*, not a
//! table, "because a row can be lost with the database and the forensic record
//! must not be able to be". The *intent* row is the opposite kind of thing: it
//! must be transactionally consistent with the catalog it is about, so it is a
//! table. They are two records with two different jobs, and merging them would
//! sacrifice one property or the other.
//!
//! # Ordering, which is the whole point
//!
//! The intent row is written and made durable **before** the syscall. §4.10.4's
//! table is explicit about what follows from that: a failed intent `fsync`, or
//! `ENOSPC` at that moment, **refuses the destruction** — fail closed. Whereas
//! a failed *audit* write happens after the syscall, so refusing is not
//! available to it; the record is reconstructed from the intent and marked
//! `reconstructed-after-crash`, and subsequent destruction halts until audit
//! writes succeed. Iteration 3 conflated those two cases; they are different
//! tests because they are at different points in the ordering.

use rusqlite::{OptionalExtension, params};
use shepherd_core::{Blake3Hash, IntentId, Timestamp};

use crate::{Catalog, CatalogError, Result};

/// `destroy_intent.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentKind {
    /// PM-1: a local unlink or dehydrate.
    Local,
    /// PM-2: the `discard` branch of a delete policy — remote destruction,
    /// routed through this same apparatus rather than a shortcut.
    Remote,
}

impl IntentKind {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentKind::Local => "local",
            IntentKind::Remote => "remote",
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "local" => IntentKind::Local,
            "remote" => IntentKind::Remote,
            _ => return None,
        })
    }
}

/// §4.4's eight states, transcribed rather than summarised.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IntentState {
    /// Written and fsync'd. The syscall has NOT been issued.
    Prepared,
    /// The syscall was issued; its outcome is not yet known.
    SyscallIssued,
    OutcomeKnown,
    /// The process died between issue and outcome. Recovery must determine what
    /// actually happened rather than assume either way.
    OutcomeAmbiguous,
    Audited,
    CatalogCommitted,
    /// Refused before the syscall — the fail-closed exit.
    Aborted,
    /// The audit write failed after the syscall and the record was rebuilt from
    /// this intent. Destruction halts until audit writes succeed again.
    ReconstructedAfterCrash,
}

impl IntentState {
    pub fn as_str(self) -> &'static str {
        match self {
            IntentState::Prepared => "prepared",
            IntentState::SyscallIssued => "syscall-issued",
            IntentState::OutcomeKnown => "outcome-known",
            IntentState::OutcomeAmbiguous => "outcome-ambiguous",
            IntentState::Audited => "audited",
            IntentState::CatalogCommitted => "catalog-committed",
            IntentState::Aborted => "aborted",
            IntentState::ReconstructedAfterCrash => "reconstructed-after-crash",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "prepared" => IntentState::Prepared,
            "syscall-issued" => IntentState::SyscallIssued,
            "outcome-known" => IntentState::OutcomeKnown,
            "outcome-ambiguous" => IntentState::OutcomeAmbiguous,
            "audited" => IntentState::Audited,
            "catalog-committed" => IntentState::CatalogCommitted,
            "aborted" => IntentState::Aborted,
            "reconstructed-after-crash" => IntentState::ReconstructedAfterCrash,
            _ => return None,
        })
    }

    /// Whether a row in this state needs recovery attention at startup.
    ///
    /// `Prepared` counts. A row that says "about to destroy" and nothing more
    /// means the daemon died in the window around the syscall, and recovery
    /// must establish which side of it we are on — not assume the syscall never
    /// happened because the state was never advanced.
    pub fn needs_recovery(self) -> bool {
        matches!(
            self,
            IntentState::Prepared
                | IntentState::SyscallIssued
                | IntentState::OutcomeAmbiguous
                | IntentState::OutcomeKnown
        )
    }

    /// Whether this state is terminal for the intent's lifecycle.
    pub fn is_settled(self) -> bool {
        matches!(self, IntentState::CatalogCommitted | IntentState::Aborted)
    }
}

/// One intent row.
#[derive(Debug, Clone)]
pub struct DestroyIntent {
    pub id: IntentId,
    pub kind: IntentKind,
    pub file_id: Option<i64>,
    pub path: String,
    pub size: i64,
    pub blake3: Option<Blake3Hash>,
    pub state: IntentState,
    pub batch_id: Option<String>,
    pub episode_id: Option<i64>,
}

/// What the caller must supply to record an intent.
///
/// `attested_identity_json` carries §4.10.2's proof: a provider version id, or
/// a content self-attestation on version-less substrates (OQ-I, mechanism B).
/// It is `Option` in the row and required in practice — the destroy predicate,
/// not this journal, is what refuses to proceed without it, because failing
/// closed is a decision that belongs at the decision point.
#[derive(Debug, Clone)]
pub struct NewIntent<'a> {
    pub kind: IntentKind,
    pub file_id: Option<i64>,
    pub path: &'a str,
    pub size: i64,
    pub blake3: Option<Blake3Hash>,
    pub target_ids_json: &'a str,
    pub remote_keys_json: &'a str,
    pub attested_identity_json: Option<&'a str>,
    pub verified_at: Option<Timestamp>,
    pub batch_id: Option<&'a str>,
    pub episode_id: Option<i64>,
}

pub struct IntentJournal<'a>(pub &'a mut Catalog);

impl<'a> IntentJournal<'a> {
    pub fn new(cat: &'a mut Catalog) -> Self {
        Self(cat)
    }

    /// Record an intent in state `prepared` and make it durable.
    ///
    /// Returns only after the transaction commits. With `synchronous = FULL`
    /// (see [`crate::PRAGMAS`]) that commit is an fsync, which is what §4.10.4
    /// means by "fsync'd BEFORE the syscall". A caller that treats a returned
    /// id as permission to destroy is relying on that, so the pragma is
    /// asserted at open rather than merely set.
    pub fn prepare(&mut self, new: &NewIntent<'_>, now: Timestamp) -> Result<IntentId> {
        let tx = self.0.conn_mut().transaction()?;
        tx.execute(
            "INSERT INTO destroy_intent
                 (kind, file_id, path, size, blake3, target_ids_json, remote_keys_json,
                  attested_identity_json, verified_at, state, batch_id, episode_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 'prepared', ?10, ?11, ?12)",
            params![
                new.kind.as_str(),
                new.file_id,
                new.path,
                new.size,
                new.blake3.map(|h| h.as_bytes().to_vec()),
                new.target_ids_json,
                new.remote_keys_json,
                new.attested_identity_json,
                new.verified_at.map(|t| t.as_nanos()),
                new.batch_id,
                new.episode_id,
                now.as_nanos(),
            ],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(IntentId::new(id))
    }

    /// Advance an intent's state.
    ///
    /// Refuses to move a settled row. An intent that reached `aborted` and then
    /// became `syscall-issued` would be a record of a destruction that the
    /// system had already decided not to perform, and the journal is the thing
    /// a human reads after data goes missing.
    pub fn transition(&mut self, id: IntentId, to: IntentState) -> Result<()> {
        let current = self
            .get(id)?
            .ok_or_else(|| CatalogError::Invalid(format!("no intent {id}")))?
            .state;
        if current.is_settled() && current != to {
            return Err(CatalogError::Invariant(format!(
                "intent {id} is settled at `{}` and may not move to `{}`",
                current.as_str(),
                to.as_str()
            )));
        }
        self.0.conn_mut().execute(
            "UPDATE destroy_intent SET state = ?2 WHERE id = ?1",
            params![id.get(), to.as_str()],
        )?;
        Ok(())
    }

    pub fn get(&self, id: IntentId) -> Result<Option<DestroyIntent>> {
        self.0
            .conn()
            .query_row(
                "SELECT id, kind, file_id, path, size, blake3, state, batch_id, episode_id
                 FROM destroy_intent WHERE id = ?1",
                params![id.get()],
                row_to_intent,
            )
            .optional()
            .map_err(CatalogError::from)?
            .transpose()
    }

    /// Every intent a crash left mid-flight.
    ///
    /// T8's recovery calls this at startup. §4.10.4 is abort-forward-never: the
    /// recovery either completes the operation or moves the file back, and it
    /// never re-issues a destruction it cannot prove is still correct. This
    /// function only enumerates; it decides nothing.
    pub fn unresolved(&self) -> Result<Vec<DestroyIntent>> {
        let mut stmt = self.0.conn().prepare(
            "SELECT id, kind, file_id, path, size, blake3, state, batch_id, episode_id
             FROM destroy_intent
             WHERE state IN ('prepared','syscall-issued','outcome-known','outcome-ambiguous')
             ORDER BY id",
        )?;
        let rows = stmt
            .query_map([], row_to_intent)?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        rows.into_iter().collect()
    }
}

fn row_to_intent(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<DestroyIntent>> {
    let kind: String = row.get(1)?;
    let state: String = row.get(6)?;
    let hash: Option<Vec<u8>> = row.get(5)?;
    Ok((|| {
        Ok(DestroyIntent {
            id: IntentId::new(row.get(0)?),
            kind: IntentKind::parse(&kind)
                .ok_or_else(|| CatalogError::Invalid(format!("intent kind `{kind}`")))?,
            file_id: row.get(2)?,
            path: row.get(3)?,
            size: row.get(4)?,
            blake3: hash
                .map(|b| {
                    <[u8; 32]>::try_from(b.as_slice())
                        .map(Blake3Hash::from_bytes)
                        .map_err(|_| CatalogError::Invalid("blake3 column is not 32 bytes".into()))
                })
                .transpose()?,
            state: IntentState::parse(&state)
                .ok_or_else(|| CatalogError::Invalid(format!("intent state `{state}`")))?,
            batch_id: row.get(7)?,
            episode_id: row.get(8)?,
        })
    })())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn new_intent<'a>(path: &'a str) -> NewIntent<'a> {
        NewIntent {
            kind: IntentKind::Local,
            file_id: None,
            path,
            size: 42,
            blake3: Some(Blake3Hash::from_bytes([3; 32])),
            target_ids_json: "[1]",
            remote_keys_json: r#"["p/objects/aa/bb/cc"]"#,
            attested_identity_json: Some(r#"{"version":"v1"}"#),
            verified_at: Some(Timestamp::from_nanos(10)),
            batch_id: Some("batch-1"),
            episode_id: None,
        }
    }

    #[test]
    fn an_intent_starts_prepared_and_round_trips() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = IntentJournal::new(&mut c)
            .prepare(&new_intent("/data/a.raw"), Timestamp::from_nanos(1))
            .unwrap();
        let got = IntentJournal::new(&mut c).get(id).unwrap().unwrap();
        assert_eq!(got.state, IntentState::Prepared);
        assert_eq!(got.path, "/data/a.raw");
        assert_eq!(got.blake3, Some(Blake3Hash::from_bytes([3; 32])));
        assert_eq!(got.kind, IntentKind::Local);
    }

    /// A `prepared` row means the daemon died in the window around the syscall.
    /// Recovery must look at it — not assume the syscall never happened just
    /// because the state was never advanced.
    #[test]
    fn a_prepared_row_still_needs_recovery() {
        assert!(IntentState::Prepared.needs_recovery());
        assert!(IntentState::SyscallIssued.needs_recovery());
        assert!(IntentState::OutcomeAmbiguous.needs_recovery());
        assert!(!IntentState::Aborted.needs_recovery());
        assert!(!IntentState::CatalogCommitted.needs_recovery());
    }

    #[test]
    fn unresolved_lists_exactly_the_rows_recovery_must_look_at() {
        let mut c = Catalog::open_in_memory().unwrap();
        let t = Timestamp::from_nanos(1);
        let a = IntentJournal::new(&mut c)
            .prepare(&new_intent("/a"), t)
            .unwrap();
        let b = IntentJournal::new(&mut c)
            .prepare(&new_intent("/b"), t)
            .unwrap();
        let d = IntentJournal::new(&mut c)
            .prepare(&new_intent("/d"), t)
            .unwrap();

        IntentJournal::new(&mut c)
            .transition(b, IntentState::SyscallIssued)
            .unwrap();
        IntentJournal::new(&mut c)
            .transition(d, IntentState::Aborted)
            .unwrap();

        let un = IntentJournal::new(&mut c).unresolved().unwrap();
        let ids: Vec<i64> = un.iter().map(|i| i.id.get()).collect();
        assert_eq!(ids, vec![a.get(), b.get()]);
        assert!(
            !ids.contains(&d.get()),
            "an aborted intent is settled — the destruction was refused"
        );
    }

    /// The fail-closed exit must stay closed. A row that reached `aborted` and
    /// then moved to `syscall-issued` would record a destruction the system had
    /// already decided not to perform.
    #[test]
    fn a_settled_intent_cannot_be_reopened() {
        let mut c = Catalog::open_in_memory().unwrap();
        let t = Timestamp::from_nanos(1);
        let id = IntentJournal::new(&mut c)
            .prepare(&new_intent("/a"), t)
            .unwrap();
        IntentJournal::new(&mut c)
            .transition(id, IntentState::Aborted)
            .unwrap();

        let err = IntentJournal::new(&mut c).transition(id, IntentState::SyscallIssued);
        assert!(err.is_err(), "an aborted intent must not become issued");

        let err = IntentJournal::new(&mut c).transition(id, IntentState::CatalogCommitted);
        assert!(err.is_err(), "nor committed");
    }

    #[test]
    fn the_remote_discard_branch_uses_the_same_journal() {
        // PM-2: remote destruction is routed through the same intent+audit
        // apparatus as local, not through a shortcut.
        let mut c = Catalog::open_in_memory().unwrap();
        let mut n = new_intent("s3://bucket/key");
        n.kind = IntentKind::Remote;
        let id = IntentJournal::new(&mut c)
            .prepare(&n, Timestamp::from_nanos(1))
            .unwrap();
        assert_eq!(
            IntentJournal::new(&mut c).get(id).unwrap().unwrap().kind,
            IntentKind::Remote
        );
    }

    #[test]
    fn all_eight_states_round_trip_with_the_check_constraint() {
        let mut c = Catalog::open_in_memory().unwrap();
        for s in [
            IntentState::Prepared,
            IntentState::SyscallIssued,
            IntentState::OutcomeKnown,
            IntentState::OutcomeAmbiguous,
            IntentState::Audited,
            IntentState::CatalogCommitted,
            IntentState::Aborted,
            IntentState::ReconstructedAfterCrash,
        ] {
            assert_eq!(IntentState::parse(s.as_str()), Some(s));
            // The schema must accept every one of them.
            let id = IntentJournal::new(&mut c)
                .prepare(&new_intent("/x"), Timestamp::from_nanos(1))
                .unwrap();
            IntentJournal::new(&mut c).transition(id, s).unwrap();
        }
    }

    #[test]
    fn an_unknown_state_is_refused_by_the_schema() {
        let mut c = Catalog::open_in_memory().unwrap();
        let err = c.conn_mut().execute(
            "INSERT INTO destroy_intent (kind, path, size, state, created_at)
             VALUES ('local', '/x', 1, 'definitely-fine', 1)",
            [],
        );
        assert!(err.is_err());
    }
}
