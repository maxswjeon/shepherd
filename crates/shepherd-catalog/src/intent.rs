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
    /// **Recovery is the complement of settled**, and it is written that way
    /// rather than as its own list. An enumeration here drifted from
    /// [`IntentJournal::unresolved`]'s once already, and it dropped `Audited` —
    /// a destruction that has happened and was never committed to the catalog,
    /// so the file was gone while the catalog went on claiming it was local.
    /// Deriving from [`IntentState::is_settled`] means a state added later is
    /// recovered until someone deliberately declares it terminal, which is the
    /// fail-closed direction.
    ///
    /// `Prepared` counts, and that is the same rule rather than an exception. A
    /// row that says "about to destroy" and nothing more means the daemon died
    /// in the window around the syscall, and recovery must establish which side
    /// of it we are on — not assume the syscall never happened because the state
    /// was never advanced.
    pub fn needs_recovery(self) -> bool {
        !self.is_settled()
    }

    /// Whether this state is terminal for the intent's lifecycle.
    pub fn is_settled(self) -> bool {
        matches!(self, IntentState::CatalogCommitted | IntentState::Aborted)
    }

    /// §4.4's lifecycle, written out as an edge list.
    ///
    /// # Why terminality was not enough
    ///
    /// The guard used to ask only whether the *source* was settled. Everything
    /// else was legal: `prepared` straight to `catalog-committed`, skipping the
    /// syscall and the audit; `audited` back to `prepared`; any non-settled
    /// state backwards. Two of those are worse than untidy. A premature
    /// `catalog-committed` **settles** the row, and settled is exactly the
    /// predicate [`IntentState::needs_recovery`] and
    /// [`IntentJournal::unresolved`] use to decide a row is finished — so an
    /// intent whose destruction protocol never ran drops out of the
    /// unresolved set and is never examined again. A backward move rewrites
    /// the journal that a human reads after data goes missing.
    ///
    /// # Where each edge comes from
    ///
    /// * `prepared → syscall-issued` — the ordinary path.
    /// * `prepared → aborted` — "Refused before the syscall", the fail-closed
    ///   exit. It is reachable *only* from here, because that is what "before
    ///   the syscall" means.
    /// * `syscall-issued → outcome-known | outcome-ambiguous` — the syscall
    ///   returned, or the process died before it could be observed.
    /// * `outcome-known → audited` — the audit append succeeded.
    /// * `outcome-known → reconstructed-after-crash` — it did not, and the
    ///   record was rebuilt from this intent. Refusing is not available after
    ///   the syscall, so this is a state, not an error.
    /// * `audited → catalog-committed` — the destruction is recorded and the
    ///   catalog now agrees with the disk.
    ///
    /// # Three edges DECIDED IN REVIEW, not transcribed from a spec
    ///
    /// **There is no §4.4 state table in this repository.** The edges above are
    /// derived from this module's own doc comments; the three below were not
    /// determined by anything in the tree and were **decided during PR #1
    /// round 2 review**. They are recorded as decisions, with their reasoning,
    /// so the next reader does not mistake a judgement call for a requirement.
    ///
    /// They follow from one principle, stated once because it settles two of
    /// them: **`aborted` is a claim about the FILE, not about the code path.**
    /// It must mean "we have positive evidence the bytes were not destroyed",
    /// because it is the word a reader trusts when deciding whether the user's
    /// data still exists — and because `aborted` is settled, a wrong one is
    /// precisely the lie nothing will ever re-examine.
    ///
    /// * `outcome-ambiguous → outcome-known` — recovery "must determine what
    ///   actually happened rather than assume either way"; determining it is
    ///   this edge.
    /// * `outcome-ambiguous → aborted` — permitted, but **only for a PROVEN
    ///   negative**: recovery established that the syscall never took effect.
    ///   This edge is where that sentence above is enforced rather than merely
    ///   quoted. It is not a way to give up on an ambiguity.
    /// * `reconstructed-after-crash → catalog-committed`, and **nothing else**.
    ///   The absence of `aborted` here is deliberate and is the principle
    ///   again: this state is reachable only *after* the syscall fired, so
    ///   `aborted` from here would be a settled row claiming a file is intact
    ///   when it is already gone — the sole-copy loss this crate exists to
    ///   prevent, recorded in its own journal. **Do not add it.** (The same
    ///   care as the `wal_autocheckpoint` note in [`crate::PRAGMAS`]: an
    ///   absence that reads as an oversight gets helpfully "fixed" later.)
    ///
    /// `reconstructed-after-crash` is likewise **not** reachable from
    /// `outcome-ambiguous`, for a reason worth stating: **you cannot
    /// reconstruct an audit record of an event you cannot describe.**
    /// Reconstruction presupposes a known outcome. The route is
    /// `outcome-ambiguous → outcome-known → reconstructed-after-crash`, which
    /// costs a caller one extra call and keeps "we know what happened" a
    /// precondition instead of something reconstruction quietly asserts.
    ///
    /// Anything not listed is refused, which is the direction that fails
    /// closed: a lifecycle gaining a state gets no edges until someone writes
    /// them.
    fn successors(self) -> &'static [IntentState] {
        use IntentState::*;
        match self {
            Prepared => &[SyscallIssued, Aborted],
            SyscallIssued => &[OutcomeKnown, OutcomeAmbiguous],
            OutcomeAmbiguous => &[OutcomeKnown, Aborted],
            OutcomeKnown => &[Audited, ReconstructedAfterCrash],
            Audited => &[CatalogCommitted],
            ReconstructedAfterCrash => &[CatalogCommitted],
            CatalogCommitted | Aborted => &[],
        }
    }

    /// Whether `self → to` is a legal move.
    ///
    /// **A self-transition is not one**, and that is a decision made in PR #1
    /// round 2 review rather than an inherited behaviour. The old guard did
    /// permit it, but by accident — `current.is_settled() && current != to`
    /// exempted a no-op in order to let a settled row alone, and the exemption
    /// leaked to every other state.
    ///
    /// `catalog-committed → catalog-committed` is harmless.
    /// **`syscall-issued → syscall-issued` means the irreversible syscall was
    /// issued twice**, which on this path is exactly the event a journal exists
    /// to make visible. No rule can permit the first without permitting the
    /// second, so both are refused and idempotency moves from implicit to
    /// explicit — the refusal is [`CatalogError::AlreadyInState`], which a
    /// crash-retry can match on and skip. A retry that asks and is told
    /// "already there" is fine; one that blind-writes and silently succeeds is
    /// the behaviour being removed.
    fn may_transition_to(self, to: IntentState) -> bool {
        self.successors().contains(&to)
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

/// Proof that an intent reached `prepared` **durably**, before anything
/// irreversible was attempted.
///
/// A bare [`IntentId`] is an integer anyone can invent, and
/// `shepherd_tier::execute_local_destruction` took one — so its stated ordering
/// guarantee ("the intent is fsync'd BEFORE the syscall") rested on every
/// caller having remembered to do that, with nothing in the type system or at
/// run time able to tell a journal-backed id from a fabricated one. A crash
/// between the unlink and the audit append would then leave no intent to
/// reconstruct the forensic record from, which is the one thing §4.10.4's
/// ordering exists to guarantee.
///
/// Only [`IntentJournal::prepare`] can mint one, and it returns after the
/// transaction commits — an fsync under `synchronous = FULL`. Passing it by
/// value into the destroy path makes "an intent was durably prepared for this"
/// a precondition the caller cannot skip rather than a comment it can ignore.
/// # Bound to ONE destruction, not merely to the fact that one was prepared
///
/// The token used to be `PreparedIntent(IntentId)` and `Copy`. That proved a
/// row existed and nothing about WHICH row: the destroy path never compared it
/// against the request it arrived with, so one prepared intent could authorize
/// an unlink of a different path, of different bytes, or of a different kind
/// entirely — and being `Copy`, could authorize any number of them, leaving a
/// single journal row that describes only the first. The row is §4.10.4's whole
/// forensic record; a record that describes a different file than the one that
/// was destroyed is worse than none, because recovery trusts it.
///
/// So the token carries what `prepare` wrote, and [`Self::authorizes`] (local)
/// and [`Self::authorizes_object`] (remote) are how the destroy path turns that
/// into a refusal. The fields are private and there is no setter: a binding the
/// holder can edit binds nothing.
///
/// **Neither `Copy` nor `Clone`, deliberately.** Both are ways for one prepared
/// row to back several irreversible operations while describing only the first,
/// and the row is the entire forensic record. Dropping `Copy` immediately
/// caught a reuse in `ac6_recovery`; `Clone` was the escape hatch left behind,
/// and a token that can be duplicated is a token that can be spent twice.
#[derive(Debug, PartialEq, Eq)]
pub struct PreparedIntent {
    id: IntentId,
    kind: IntentKind,
    path: String,
    size: i64,
    blake3: Option<Blake3Hash>,
}

impl PreparedIntent {
    pub fn id(&self) -> IntentId {
        self.id
    }

    /// Whether this token authorizes destroying exactly what is described.
    ///
    /// `Err` names the field that disagreed, because the alternative — a bare
    /// "intent does not match" on an irreversible path — tells an operator
    /// nothing about whether they hit a bug or an attack.
    ///
    /// A `None` hash in the row does NOT match a request that names one: the
    /// row was prepared without recording which bytes it covers, so it cannot
    /// be evidence about them. Fail closed.
    pub fn authorizes(
        &self,
        kind: IntentKind,
        path: &str,
        size: u64,
        blake3: Blake3Hash,
    ) -> std::result::Result<(), String> {
        self.names(kind, path)?;
        if self.size != size as i64 {
            return Err(format!(
                "intent {} was prepared for {} bytes and this destruction names {size}",
                self.id.get(),
                self.size
            ));
        }
        match self.blake3 {
            Some(h) if h == blake3 => Ok(()),
            Some(h) => Err(format!(
                "intent {} was prepared for blake3 {} and this destruction names {}",
                self.id.get(),
                h.to_hex(),
                blake3.to_hex()
            )),
            None => Err(format!(
                "intent {} recorded no blake3, so it is not evidence about the bytes this \
                 destruction names",
                self.id.get()
            )),
        }
    }

    /// Whether this token authorizes destroying one REMOTE object.
    ///
    /// The key is the whole binding here, and that is not a weaker check than
    /// the local one: §4.9 keys name the hash, so a key is a statement about
    /// the bytes in a way a local pathname is not. Size and digest are what the
    /// remote row does not carry — `execute_remote_discard`'s own audit record
    /// writes `size: 0, blake3: None` — so requiring them would be requiring a
    /// caller to invent them.
    pub fn authorizes_object(&self, key: &str) -> std::result::Result<(), String> {
        self.names(IntentKind::Remote, key)
    }

    fn names(&self, kind: IntentKind, path: &str) -> std::result::Result<(), String> {
        if self.kind != kind {
            return Err(format!(
                "intent {} was prepared as `{}` and this is a `{}` destruction",
                self.id.get(),
                self.kind.as_str(),
                kind.as_str()
            ));
        }
        if self.path != path {
            return Err(format!(
                "intent {} was prepared for `{}` and this destruction names `{path}`",
                self.id.get(),
                self.path
            ));
        }
        Ok(())
    }

    /// Mint one WITHOUT a journal. **Behind the `test-util` feature**, which is
    /// off by default, so no production dependent can reach it.
    ///
    /// The name was the only guard before, and a name enforces nothing: this
    /// was a public method on a shipping API that hands the destroy path a
    /// token no `prepared` row backs, which is the crash window
    /// [`PreparedIntent`] exists to close. `#[doc(hidden)]` hides the
    /// documentation and not the function.
    ///
    /// Every use of this is a test that is NOT exercising the journal. Prefer
    /// [`IntentJournal::prepare`] wherever a `Catalog` is at hand — `ac6_recovery`
    /// does, and the destroy path is the better tested for it.
    #[cfg(feature = "test-util")]
    pub fn fabricated_for_tests(
        id: IntentId,
        kind: IntentKind,
        path: &str,
        size: i64,
        blake3: Option<Blake3Hash>,
    ) -> Self {
        Self {
            id,
            kind,
            path: path.to_owned(),
            size,
            blake3,
        }
    }
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
    pub fn prepare(&mut self, new: &NewIntent<'_>, now: Timestamp) -> Result<PreparedIntent> {
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
        // The token repeats what the row says, so the destroy path can refuse a
        // request that does not match it without another read.
        Ok(PreparedIntent {
            id: IntentId::new(id),
            kind: new.kind,
            path: new.path.to_owned(),
            size: new.size,
            blake3: new.blake3,
        })
    }

    /// Advance an intent's state along §4.4's lifecycle.
    ///
    /// Every move is checked against [`IntentState::successors`], not merely
    /// against whether the source is terminal. Terminality alone let a caller
    /// jump `prepared → catalog-committed`, and a `catalog-committed` row is
    /// settled — so a premature commit did not just mislabel the intent, it
    /// removed it from the set recovery is defined over. It also let the
    /// journal run backwards, and the journal is the thing a human reads after
    /// data goes missing.
    pub fn transition(&mut self, id: IntentId, to: IntentState) -> Result<()> {
        let current = self
            .get(id)?
            .ok_or_else(|| CatalogError::Invalid(format!("no intent {id}")))?
            .state;
        if current == to {
            return Err(CatalogError::AlreadyInState(format!(
                "intent {id} is already `{}`",
                current.as_str()
            )));
        }
        if !current.may_transition_to(to) {
            let allowed = current.successors();
            let allowed = if allowed.is_empty() {
                "it is settled, and settled is the end of the lifecycle".to_string()
            } else {
                format!(
                    "§4.4 allows only {}",
                    allowed
                        .iter()
                        .map(|s| format!("`{}`", s.as_str()))
                        .collect::<Vec<_>>()
                        .join(" or ")
                )
            };
            return Err(CatalogError::Invariant(format!(
                "intent {id} may not move from `{}` to `{}`: {allowed}",
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
    ///
    /// **Phrased as `NOT IN` the settled states**, mirroring
    /// [`IntentState::needs_recovery`], because the two must agree and the
    /// cheapest way to make them agree is to state the same short list once
    /// each. An earlier version enumerated the four *pre*-syscall states, which
    /// silently dropped `audited` — a row recording a destruction that already
    /// happened — and `reconstructed-after-crash`, which carries the audit halt.
    /// Written this way, a state added to the lifecycle is recovered by default
    /// and has to be declared terminal on purpose.
    pub fn unresolved(&self) -> Result<Vec<DestroyIntent>> {
        let mut stmt = self.0.conn().prepare(
            "SELECT id, kind, file_id, path, size, blake3, state, batch_id, episode_id
             FROM destroy_intent
             WHERE state NOT IN ('catalog-committed','aborted')
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

    const ALL_STATES: [IntentState; 8] = [
        IntentState::Prepared,
        IntentState::SyscallIssued,
        IntentState::OutcomeKnown,
        IntentState::OutcomeAmbiguous,
        IntentState::Audited,
        IntentState::CatalogCommitted,
        IntentState::Aborted,
        IntentState::ReconstructedAfterCrash,
    ];

    /// Drive a fresh intent to `target` along §4.4's lifecycle, one legal step
    /// at a time.
    ///
    /// The tests below used to reach a state by transitioning to it directly
    /// from `prepared`, which is the very thing the guard now refuses. Routing
    /// them through the lifecycle is not a workaround: it makes every one of
    /// them an accepting-direction test as a side effect, so a guard that
    /// refused everything would fail the whole module rather than pass it.
    fn walk_to(c: &mut Catalog, path: &str, target: IntentState) -> IntentId {
        use IntentState::*;
        let id = IntentJournal::new(c)
            .prepare(&new_intent(path), Timestamp::from_nanos(1))
            .unwrap()
            .id();
        let route: &[IntentState] = match target {
            Prepared => &[],
            Aborted => &[Aborted],
            SyscallIssued => &[SyscallIssued],
            OutcomeKnown => &[SyscallIssued, OutcomeKnown],
            OutcomeAmbiguous => &[SyscallIssued, OutcomeAmbiguous],
            Audited => &[SyscallIssued, OutcomeKnown, Audited],
            ReconstructedAfterCrash => &[SyscallIssued, OutcomeKnown, ReconstructedAfterCrash],
            CatalogCommitted => &[SyscallIssued, OutcomeKnown, Audited, CatalogCommitted],
        };
        for step in route {
            IntentJournal::new(c)
                .transition(id, *step)
                .unwrap_or_else(|e| {
                    panic!(
                        "`{}` is unreachable along the lifecycle: {e}",
                        target.as_str()
                    )
                });
        }
        assert_eq!(
            IntentJournal::new(c).get(id).unwrap().unwrap().state,
            target
        );
        id
    }

    fn state_of(c: &mut Catalog, id: IntentId) -> IntentState {
        IntentJournal::new(c).get(id).unwrap().unwrap().state
    }

    #[test]
    fn an_intent_starts_prepared_and_round_trips() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = IntentJournal::new(&mut c)
            .prepare(&new_intent("/data/a.raw"), Timestamp::from_nanos(1))
            .unwrap()
            .id();
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
            .unwrap()
            .id();
        let b = IntentJournal::new(&mut c)
            .prepare(&new_intent("/b"), t)
            .unwrap()
            .id();
        let d = IntentJournal::new(&mut c)
            .prepare(&new_intent("/d"), t)
            .unwrap()
            .id();

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

    /// Recovery is the **complement of settled**, checked against the query for
    /// every state rather than trusting two lists to stay in step.
    ///
    /// They were once out of step, and in the dangerous direction: `audited` and
    /// `reconstructed-after-crash` are both post-syscall and neither is settled,
    /// and the query enumerated four states that did not include them.
    #[test]
    fn unresolved_returns_exactly_the_states_that_need_recovery() {
        for s in ALL_STATES {
            // A fresh catalog per state, so the row under test is the only one
            // that could be listed.
            let mut c = Catalog::open_in_memory().unwrap();
            let id = walk_to(&mut c, "/x", s);

            let un = IntentJournal::new(&mut c).unresolved().unwrap();
            let listed = un.iter().any(|i| i.id.get() == id.get());
            assert_eq!(
                listed,
                s.needs_recovery(),
                "`unresolved()` and `needs_recovery()` disagree about `{}`. Whichever is \
                 right, a state that recovery's predicate claims and its query drops is a \
                 row startup never examines",
                s.as_str()
            );
        }
    }

    /// The hole that mattered, named in both directions.
    ///
    /// `audited` is the state of a crash **after** the irreversible syscall and
    /// the audit append but **before** the catalog commit. If startup never
    /// looks at that row, the file is gone while the catalog goes on claiming it
    /// is local — the exact outcome the custody model exists to prevent. A
    /// `reconstructed-after-crash` row forgotten the same way lets the audit
    /// halt disappear on the next restart.
    ///
    /// The negative is what stops the fix from being "recover everything": a
    /// settled row is not recovery's business.
    #[test]
    fn an_audited_intent_is_recovered_and_a_settled_one_is_not() {
        let mut c = Catalog::open_in_memory().unwrap();
        let audited = walk_to(&mut c, "/audited", IntentState::Audited);
        let reconstructed = walk_to(
            &mut c,
            "/reconstructed",
            IntentState::ReconstructedAfterCrash,
        );
        let committed = walk_to(&mut c, "/committed", IntentState::CatalogCommitted);

        let un = IntentJournal::new(&mut c).unresolved().unwrap();
        let ids: Vec<i64> = un.iter().map(|i| i.id.get()).collect();

        assert!(
            ids.contains(&audited.get()),
            "an `audited` row is a destruction that happened and was never committed to \
             the catalog. Skipping it leaves the file gone while the catalog claims it is \
             local: {ids:?}"
        );
        assert!(
            ids.contains(&reconstructed.get()),
            "a `reconstructed-after-crash` row halts destruction until audit writes \
             succeed. Forgotten at startup, the halt silently lifts: {ids:?}"
        );
        assert!(
            !ids.contains(&committed.get()),
            "a settled row is finished. Listing it would make recovery mean `everything`, \
             which is not a recovery predicate: {ids:?}"
        );
    }

    /// The skip that costs the most: `prepared` straight to
    /// `catalog-committed`.
    ///
    /// `catalog-committed` is **settled**, and settled is the whole definition
    /// of "finished" that [`IntentJournal::unresolved`] and
    /// [`IntentState::needs_recovery`] are written against. So a premature
    /// commit does not merely mislabel a row — it takes an intent whose syscall
    /// and audit never happened out of the unresolved set entirely.
    ///
    /// **Stated carefully, because the consequence is currently latent.**
    /// Nothing in this workspace calls `unresolved()` or `needs_recovery()`:
    /// there is no startup consumer yet, so no run is rescued or lost today.
    /// What this test asserts is therefore the journal-level fact and not a
    /// runtime outcome — the refusal happens, the row does not move, and it is
    /// still in the set `unresolved()` reports.
    #[test]
    fn a_premature_commit_is_refused_and_the_row_stays_unresolved() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = IntentJournal::new(&mut c)
            .prepare(&new_intent("/data/a.raw"), Timestamp::from_nanos(1))
            .unwrap()
            .id();

        let err = IntentJournal::new(&mut c)
            .transition(id, IntentState::CatalogCommitted)
            .expect_err("a prepared intent must not commit without destroying anything");
        assert!(
            err.to_string().contains("may not move from `prepared`"),
            "the refusal must name the edge it refused, got: {err}"
        );

        assert_eq!(
            state_of(&mut c, id),
            IntentState::Prepared,
            "the refusal must leave the row where it was"
        );
        let un = IntentJournal::new(&mut c).unresolved().unwrap();
        assert_eq!(
            un.iter().map(|i| i.id.get()).collect::<Vec<_>>(),
            vec![id.get()],
            "an intent that never issued its syscall dropped out of the \
             unresolved set by being marked committed"
        );
    }

    /// The journal is what a human reads after data goes missing, so it may not
    /// be rewritten to say something earlier happened later.
    ///
    /// `audited` means the irreversible syscall ran and was recorded. Moving
    /// that row back to `prepared` or `syscall-issued` claims the destruction
    /// is still pending — and the old guard permitted it, because `audited` is
    /// not terminal and terminality was the only thing checked.
    #[test]
    fn the_journal_does_not_run_backwards() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = walk_to(&mut c, "/data/a.raw", IntentState::Audited);

        for back in [IntentState::Prepared, IntentState::SyscallIssued] {
            let err = IntentJournal::new(&mut c)
                .transition(id, back)
                .expect_err("an audited destruction must not become pending again");
            assert!(
                err.to_string().contains("may not move from `audited`"),
                "got: {err}"
            );
            assert_eq!(
                state_of(&mut c, id),
                IntentState::Audited,
                "a refused backward move still rewrote the row"
            );
        }
    }

    /// The accepting direction, spelled out rather than left implicit in the
    /// helpers: the whole ordinary lifecycle runs end to end.
    ///
    /// Without this, "refuse every transition" satisfies every negative test
    /// above it.
    #[test]
    fn the_ordinary_lifecycle_runs_end_to_end() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = IntentJournal::new(&mut c)
            .prepare(&new_intent("/data/a.raw"), Timestamp::from_nanos(1))
            .unwrap()
            .id();
        for step in [
            IntentState::SyscallIssued,
            IntentState::OutcomeKnown,
            IntentState::Audited,
            IntentState::CatalogCommitted,
        ] {
            IntentJournal::new(&mut c)
                .transition(id, step)
                .unwrap_or_else(|e| {
                    panic!("the legal step to `{}` was refused: {e}", step.as_str())
                });
            assert_eq!(state_of(&mut c, id), step);
        }
        assert!(
            IntentJournal::new(&mut c).unresolved().unwrap().is_empty(),
            "a completed intent is not recovery's business"
        );
    }

    /// Every one of the 64 ordered pairs, checked against the declared edge
    /// list — including that a refused move leaves the row untouched.
    ///
    /// The named tests above are the spec; this one is the sweep that catches
    /// an edge nobody thought to name. The eight diagonal pairs are refusals:
    /// a self-transition is not a legal move — see
    /// [`IntentState::may_transition_to`].
    #[test]
    fn transition_accepts_exactly_the_declared_lifecycle() {
        for from in ALL_STATES {
            for to in ALL_STATES {
                let mut c = Catalog::open_in_memory().unwrap();
                let id = walk_to(&mut c, "/x", from);
                let accepted = IntentJournal::new(&mut c).transition(id, to).is_ok();
                let legal = from.successors().contains(&to);
                assert_eq!(
                    accepted,
                    legal,
                    "`{}` -> `{}` was {}, but the lifecycle says {}",
                    from.as_str(),
                    to.as_str(),
                    if accepted { "accepted" } else { "refused" },
                    if legal { "it is legal" } else { "it is not" }
                );
                assert_eq!(
                    state_of(&mut c, id),
                    if legal { to } else { from },
                    "the row's state disagrees with the outcome of `{}` -> `{}`",
                    from.as_str(),
                    to.as_str()
                );
            }
        }
    }

    /// `aborted` is a claim about the FILE, not about the code path — the
    /// principle the review decided two of these edges from, pinned so it
    /// survives the reasoning being forgotten.
    ///
    /// `reconstructed-after-crash` is reachable only after the syscall fired.
    /// Moving from there to `aborted` would produce a **settled** row asserting
    /// the bytes are intact when they are already gone: the sole-copy loss this
    /// crate exists to prevent, written into its own journal, in the one state
    /// nothing ever re-examines. The sweep in
    /// [`transition_accepts_exactly_the_declared_lifecycle`] covers this pair
    /// too, but only against the table — this test says why the table is
    /// shaped that way, where someone about to "fix" the omission will read it.
    #[test]
    fn a_destruction_that_already_happened_can_never_report_itself_aborted() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = walk_to(&mut c, "/data/a.raw", IntentState::ReconstructedAfterCrash);
        let err = IntentJournal::new(&mut c)
            .transition(id, IntentState::Aborted)
            .expect_err(
                "the file is already destroyed; `aborted` would be a settled row \
                 claiming it is intact",
            );
        assert!(matches!(err, CatalogError::Invariant(_)), "got {err:?}");
        assert_eq!(state_of(&mut c, id), IntentState::ReconstructedAfterCrash);

        // The accepting direction, so this is not satisfied by stranding the
        // state: the one edge it does have still works.
        IntentJournal::new(&mut c)
            .transition(id, IntentState::CatalogCommitted)
            .expect("a reconstructed record may still be committed");
    }

    /// You cannot reconstruct an audit record of an event you cannot describe.
    ///
    /// Reconstruction presupposes a **known** outcome, so it is not reachable
    /// from `outcome-ambiguous` directly. Recovery resolves the ambiguity
    /// first. This costs a caller one extra transition and keeps "we know what
    /// happened" a precondition rather than something reconstruction quietly
    /// asserts on its behalf.
    #[test]
    fn an_unresolved_outcome_cannot_be_reconstructed_until_it_is_resolved() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = walk_to(&mut c, "/data/a.raw", IntentState::OutcomeAmbiguous);
        let err = IntentJournal::new(&mut c)
            .transition(id, IntentState::ReconstructedAfterCrash)
            .expect_err("an audit record cannot describe an outcome nobody knows");
        assert!(matches!(err, CatalogError::Invariant(_)), "got {err:?}");

        // The route that exists: resolve the ambiguity, THEN reconstruct.
        for step in [
            IntentState::OutcomeKnown,
            IntentState::ReconstructedAfterCrash,
        ] {
            IntentJournal::new(&mut c)
                .transition(id, step)
                .unwrap_or_else(|e| panic!("`{}` was refused: {e}", step.as_str()));
        }
        assert_eq!(state_of(&mut c, id), IntentState::ReconstructedAfterCrash);
    }

    /// Re-asserting a state is refused, and the refusal says which kind it is.
    ///
    /// The state that matters is `syscall-issued`: re-asserting it describes
    /// **the irreversible syscall being issued twice**, which is the single
    /// event this journal exists to make visible. The old guard accepted it
    /// silently. `catalog-committed → catalog-committed` is harmless on its
    /// own, but no rule permits the harmless one without permitting the other,
    /// so both are refused.
    ///
    /// The refusal is a **distinct variant**, not a distinctive message. An
    /// idempotent crash-retry has to be able to skip on "already there" while
    /// still failing on "illegal edge", and deciding that by searching the
    /// error text is how a later rephrasing turns a skip into an outage — or,
    /// worse, an outage into a skip.
    #[test]
    fn re_asserting_a_state_is_refused_and_says_so_by_type() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = walk_to(&mut c, "/data/a.raw", IntentState::SyscallIssued);

        let err = IntentJournal::new(&mut c)
            .transition(id, IntentState::SyscallIssued)
            .expect_err("issuing the syscall twice must not be recorded as one issue");
        assert!(
            matches!(err, CatalogError::AlreadyInState(_)),
            "a retry must be able to recognise `already there` by type, not by \
             reading the message; got {err:?}"
        );
        assert_eq!(
            state_of(&mut c, id),
            IntentState::SyscallIssued,
            "the refusal must leave the row where it was"
        );

        // The other half: an ILLEGAL edge must NOT look like an idempotent
        // retry, or a caller that skips on `AlreadyInState` would skip past a
        // genuine lifecycle violation.
        let other = IntentJournal::new(&mut c)
            .prepare(&new_intent("/data/b.raw"), Timestamp::from_nanos(1))
            .unwrap()
            .id();
        let err = IntentJournal::new(&mut c)
            .transition(other, IntentState::CatalogCommitted)
            .expect_err("prepared -> catalog-committed is illegal");
        assert!(
            matches!(err, CatalogError::Invariant(_)),
            "an illegal edge reported itself as an idempotent retry: {err:?}"
        );
    }

    /// The settled states get the same treatment, and it is worth its own
    /// assertion because this is where the old exemption lived: the guard read
    /// `current.is_settled() && current != to`, so a settled row could be
    /// re-asserted and every other state inherited the loophole.
    #[test]
    fn a_settled_state_may_not_be_re_asserted_either() {
        let mut c = Catalog::open_in_memory().unwrap();
        let id = walk_to(&mut c, "/data/a.raw", IntentState::Aborted);
        let err = IntentJournal::new(&mut c)
            .transition(id, IntentState::Aborted)
            .expect_err("re-asserting a settled state is still not a transition");
        assert!(
            matches!(err, CatalogError::AlreadyInState(_)),
            "got {err:?}"
        );
        assert_eq!(state_of(&mut c, id), IntentState::Aborted);
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
            .unwrap()
            .id();
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
            .unwrap()
            .id();
        assert_eq!(
            IntentJournal::new(&mut c).get(id).unwrap().unwrap().kind,
            IntentKind::Remote
        );
    }

    #[test]
    fn all_eight_states_round_trip_with_the_check_constraint() {
        let mut c = Catalog::open_in_memory().unwrap();
        for s in ALL_STATES {
            assert_eq!(IntentState::parse(s.as_str()), Some(s));
            // The schema must accept every one of them — and, now that the
            // lifecycle is enforced, every one of them must still be REACHABLE
            // through it. A state the edge list stranded would fail here
            // instead of sitting in the enum unreferenced.
            walk_to(&mut c, "/x", s);
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
