//! §4.10.3a — the four-class disaster-recovery bundle.
//!
//! # What this artifact is for
//!
//! > **No local original may be destroyed until a recovery bundle entry
//! > covering it has been durably published to a custody-eligible target and
//! > confirmed by a fresh-client publication receipt.**
//!
//! Publication is part of the destroy predicate, not a background chore that
//! happens to run earlier.
//!
//! Iteration 3's shape was `{path, blake3, object_version, key, target,
//! restore_metadata}`. That **cannot rebuild a machine**: it omits target
//! configuration, rules, delete policies, schedules, settings, models, label
//! prototypes — and decisively, the bootstrap information needed to find
//! itself. The requirement is that a user holding *only* a target URL and
//! re-entered credentials can reconstruct everything else. So: four classes.
//!
//! | Class | On recovery |
//! |---|---|
//! | [`BootstrapRecord`] | Written to a well-known key. Entered by the user once, then self-describing |
//! | [`CustodyRecord`] (authoritative) | Replayed verbatim. **The only authority for files whose originals are gone** |
//! | [`DurableConfigRecord`] (authoritative) | Replayed; the user re-authenticates each target |
//! | Derived — tags, embeddings, indexes | **Never** carried. Rebuilt by rescan and re-inference |
//!
//! The fourth class is absent *by construction*: [`BundleEntry`] has three
//! variants and no way to express a derived one, and
//! [`bundle_entry_kind`] returns `None` for [`CustodyClass::Derived`].
//!
//! # The authority question both critics flagged
//!
//! The replica was called a recovery authority *and* "explicitly never
//! authoritative". Both are true of different things: the bundle is
//! authoritative for **custody and durable-config records**, which are derived
//! from nothing on the local disk. It is **never** authoritative for file
//! content or for the state of files still present locally, where the
//! filesystem wins. It cannot overrule a `stat()`; it is the only thing that
//! can answer "where did the bytes go" once there is no file left to `stat`.
//!
//! # Keys are `(path, blake3)`, never `file_id`
//!
//! `file_id` is a local database identifier and is **not stable across an AC-6
//! rebuild**. Keying recovery on it would make the artifact useless in exactly
//! the scenario it exists for.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use shepherd_core::{Blake3Hash, CustodyClass, TargetId, Timestamp};

use crate::adapter::{AttestationMode, ControlKey};

/// Bundle schema version, carried in the bootstrap record.
pub const BUNDLE_SCHEMA_VERSION: u32 = 1;

/// The well-known key a recovering user can find with only a target URL.
pub fn bootstrap_key() -> ControlKey {
    ControlKey::under("bootstrap.json")
}

/// A record's position in the writer's logical time.
///
/// Ordered `(writer_epoch, seq)` — the derived `Ord` depends on field order, so
/// the fields are declared in that order deliberately.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, Default,
)]
pub struct LogicalClock {
    pub writer_epoch: u64,
    pub seq: u64,
}

/// Class 1 — how to find everything else.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapRecord {
    pub bundle_schema_version: u32,
    /// Endpoint URLs for this target, in preference order.
    pub endpoints: Vec<String>,
    pub prefix: String,
    pub region: Option<String>,
    /// Probed at registration, never assumed (§4.10.2).
    pub attestation_mode: AttestationMode,
}

impl BootstrapRecord {
    pub fn new(endpoints: Vec<String>, prefix: String, attestation_mode: AttestationMode) -> Self {
        Self {
            bundle_schema_version: BUNDLE_SCHEMA_VERSION,
            endpoints,
            prefix,
            region: None,
            attestation_mode,
        }
    }
}

/// The identity a custody record is keyed on.
///
/// `(path, blake3)` — **not** `file_id`. See the module docs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct CustodyKey {
    pub path: String,
    pub blake3: Blake3Hash,
}

/// Class 2 — where the bytes went. Authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustodyRecord {
    pub key: CustodyKey,
    pub target: TargetId,
    /// The content-addressed remote key (§4.9).
    pub object_key: String,
    /// Present under mechanism A only.
    pub object_version: Option<String>,
    pub size: u64,
    /// §4.10.6 preserves bytes, mtime and mode at minimum.
    pub mtime: Timestamp,
    pub mode: u32,
    /// Whatever the provider allowed capturing: xattrs, POSIX ACLs, resource
    /// forks, ADS. Anything absent is documented as not preserved rather than
    /// silently dropped.
    pub restore_metadata: BTreeMap<String, String>,
    pub clock: LogicalClock,
    pub tombstone: bool,
}

/// Which kind of durable-config entity a record carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigKind {
    Target,
    Rule,
    DeletePolicy,
    Schedule,
    Setting,
    Model,
    LabelPrototype,
}

/// Class 3 — user-authored configuration, derived from nothing. Authoritative.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DurableConfigRecord {
    pub kind: ConfigKind,
    /// Stable entity id, unique within `kind`.
    pub entity_id: String,
    /// The entity body. Secrets are **never** here — §4.10.3a says the user
    /// re-authenticates each target on recovery.
    pub body: serde_json::Value,
    pub clock: LogicalClock,
    pub tombstone: bool,
}

/// One entry in a bundle segment.
///
/// Three variants, permanently. There is no `Derived` variant and adding one
/// would be a visible change to this enum — which is how "derived state is
/// excluded" is enforced rather than merely intended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum BundleEntry {
    Bootstrap(BootstrapRecord),
    Custody(CustodyRecord),
    DurableConfig(DurableConfigRecord),
}

/// The class a bundle entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BundleClass {
    Bootstrap,
    Custody,
    DurableConfig,
}

/// Which bundle class a catalog row belongs to — `None` if it is excluded.
///
/// The `None` arm is the fourth class. Tags, embeddings and indexes are
/// rebuilt by rescan and re-inference, and carrying 10M × 384-dim embeddings
/// would be ~15 GB against ~250 MB of metadata. Expressed as a total function
/// over [`CustodyClass`] so that adding a catalog row class forces someone to
/// decide, here, whether it survives a disaster.
pub fn bundle_class_of(class: CustodyClass) -> Option<BundleClass> {
    match class {
        CustodyClass::Derived => None,
        CustodyClass::Custody => Some(BundleClass::Custody),
        CustodyClass::DurableConfig => Some(BundleClass::DurableConfig),
    }
}

/// Merge custody records across all valid branches.
///
/// **Union by `(path, blake3, target)`.** Custody records are append-only and
/// additive: losing one is the failure mode that matters — it is the only
/// address of bytes whose original may already be gone — while duplicating one
/// is harmless.
///
/// A tombstone applies **only against a live assertion it strictly dominates**.
/// That asymmetry is deliberate and points the same way as everything else on
/// this path: re-asserting a custody record costs a duplicate, honouring a
/// stale tombstone costs the file. So a tombstone whose clock is not strictly
/// greater than a live assertion's — concurrent with it, or older than it — is
/// ignored, and a tie goes to `live`.
///
/// # Three wrong rules, and why this is the one that is left
///
/// The first version kept a separate tombstone set and subtracted it at the
/// end, which quietly implemented *delete-wins* — the custody reducer with the
/// durable-config reducer's rule, and the one direction that can drop the only
/// remaining address of a destroyed file.
///
/// The second ignored tombstones **entirely**, filtering them out before
/// grouping. Correct against a concurrent branch, wrong against the writer's
/// own history: live at `(1, 1)` then a tombstone at `(1, 2)` is an ordinary
/// retirement, and resurrecting it hands a recovering user a remote location
/// that no longer holds the object.
///
/// The third compared clocks numerically and called the larger one dominant.
/// That reads a COUNTER as a causal clock. These records arrive flattened
/// across every valid fork branch, and a writer restarted from a stale
/// predecessor publishes a tombstone with a higher `writer_epoch` without ever
/// having seen the sibling branch — whose live assertion may be the only one
/// there is. The numeric comparison then filtered it out.
///
/// What is left is the comparison the clock can actually justify: same
/// `writer_epoch`, higher `seq` — one writer's own ordering, on one branch.
///
/// # What that costs, and why it is the right cost
///
/// A retirement that crosses a restart is not honoured, so a stale custody
/// record can survive a merge. That is the safe direction and the one this
/// whole file is arranged around: a duplicate custody record costs a wasted
/// lookup, and a dropped one costs the only address of bytes whose original may
/// already be destroyed. Honouring cross-branch retirement needs branch
/// ancestry carried into the reduction — the pointer chain has it, this
/// signature does not — and that is a merge contract for whoever wires the
/// publisher, not something to infer from a counter.
pub fn merge_custody(branches: &[Vec<Publication<CustodyRecord>>]) -> Vec<CustodyRecord> {
    let by_key = group_by(branches, |r: &CustodyRecord| {
        (r.key.clone(), r.target.get())
    });

    let mut live: Vec<CustodyRecord> = Vec::new();
    for (_, group) in by_key {
        // A live assertion survives unless some tombstone PROVABLY FOLLOWS it.
        //
        // "Provably" is doing the work, and what counts as proof has changed.
        // It used to be `same writer_epoch && higher seq`, on the reasoning
        // that within one epoch the ordering is that writer's own. That reads
        // an epoch as a branch, and this module explicitly supports the case
        // where it is not: a rolled-back local catalog REUSES an epoch, which
        // is why the key carries a uuid at all. Such a writer republishes from
        // a stale predecessor, counts past a sibling branch it never saw, and
        // its tombstone then retired the only live custody record for bytes
        // whose original may already be gone.
        //
        // Ancestry is the proof. A tombstone retires an assertion only when
        // some ONE branch holds both and the tombstone is later on it. Two
        // records sharing no branch are concurrent, and a concurrent tombstone
        // retires nothing — the conservative direction for a class whose whole
        // purpose is being the last address of missing bytes.
        //
        // Dropping the epoch equality is not a loosening: it was never
        // sufficient, and on a shared branch it is not necessary either, since
        // a delete and a re-publication across a restart are one writer's own
        // sequence.
        let retired = |l: &SeenOn<'_, CustodyRecord>| {
            group
                .iter()
                .any(|t| t.record.tombstone && precedes(l, t, l.record.clock, t.record.clock))
        };

        let survivor = group
            .iter()
            .filter(|r| !r.record.tombstone)
            .filter(|r| !retired(r))
            .max_by_key(|r| r.record.clock);

        if let Some(s) = survivor {
            live.push(s.record.clone());
        }
    }

    live
}

/// One segment's durable-config entries, as one branch carries them.
///
/// # Why a publication rather than a record
///
/// This type has now been the subject of three corrections, and each one was a
/// different way of GUESSING which records are the same record. It took a flat
/// list and inferred causality from clock ordering, which is not causality
/// across branches. It took branches and inferred shared history from value
/// equality, which two sibling writers can produce independently. It took a
/// per-record `origin` and inferred record identity from the publishing
/// pointer's hash, which collapses several entries a single segment carried for
/// one entity — a batched edit and its tombstone became just the edit, and a
/// destructive rule came back alive.
///
/// So it stops guessing. A branch is a sequence of publications; a publication
/// is a pointer and the ordered entries its segment held. A record's identity
/// is `(publication id, position)`, which is not an inference at all — the same
/// publication seen from two descendants of a fork carries the same entries in
/// the same order, so equal identities really are one record, and unequal ones
/// really are two.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication<T> {
    /// The publishing pointer's `self_blake3` — a content hash of the pointer,
    /// so two branches naming it really did descend through this publication.
    pub id: String,
    /// The segment's entries of this class, in the order it held them.
    pub records: Vec<T>,
}

impl<T> Publication<T> {
    pub fn new(id: impl Into<String>, records: Vec<T>) -> Self {
        Self {
            id: id.into(),
            records,
        }
    }
}

/// One record of any bundle class, and the branches it was seen on.
///
/// Shared by both reducers because the question they ask of ancestry is the
/// same one: is this record in that record's past, or merely numbered lower?
struct SeenOn<'a, T> {
    record: &'a T,
    /// `(publication id, position)` — see [`Publication`] for why identity is
    /// not the record's value and not the pointer hash alone.
    id: (&'a str, usize),
    branches: BTreeSet<usize>,
}

/// Group one class's records by a caller-chosen key, collapsing each
/// publication seen from several branches into one entry.
fn group_by<'a, T, K: Ord>(
    branches: &'a [Vec<Publication<T>>],
    key_of: impl Fn(&T) -> K,
) -> BTreeMap<K, Vec<SeenOn<'a, T>>> {
    let mut out: BTreeMap<K, Vec<SeenOn<'a, T>>> = BTreeMap::new();
    for (b, branch) in branches.iter().enumerate() {
        for publication in branch {
            for (position, r) in publication.records.iter().enumerate() {
                let group = out.entry(key_of(r)).or_default();
                let id = (publication.id.as_str(), position);
                match group.iter_mut().find(|seen| seen.id == id) {
                    Some(seen) => {
                        seen.branches.insert(b);
                    }
                    None => group.push(SeenOn {
                        record: r,
                        id,
                        branches: BTreeSet::from([b]),
                    }),
                }
            }
        }
    }
    out
}

/// Whether `earlier` is provably in `later`'s past.
///
/// Two records are causally ordered only when some ONE branch holds both — a
/// branch is a chain, and a chain's clocks increase along it. Records sharing
/// no branch are concurrent whatever their numbers say, because a clock is a
/// counter and not a causal order.
fn precedes<T>(
    earlier: &SeenOn<'_, T>,
    later: &SeenOn<'_, T>,
    earlier_clock: LogicalClock,
    later_clock: LogicalClock,
) -> bool {
    earlier_clock < later_clock
        && earlier
            .branches
            .intersection(&later.branches)
            .next()
            .is_some()
}

/// Merge durable-config records across the branches of a chain.
///
/// **Last-writer-wins by `(writer_epoch, seq)` per entity id, with delete-wins
/// on an update-vs-delete conflict.** A union is not a value here: merging
/// "rule R edited on branch A" with "rule R deleted on branch B" has no
/// additive answer, which is why this class needs a different reducer from
/// custody.
///
/// Delete-wins is the conservative direction. It cannot resurrect a rule the
/// user removed, and a resurrected *tiering* rule could tier files the user
/// deliberately excluded.
///
/// # It takes BRANCHES, and that is the correctness argument
///
/// It used to take one flat `&[DurableConfigRecord]`, and flattening is
/// precisely what destroyed the information the reducer needs. `LogicalClock`
/// is totally ordered as a *value* and only partially ordered as *causality*:
/// two records on sibling branches have comparable numbers and no causal
/// relationship at all. Reading the number as the order let a live record at
/// `(epoch 5, seq 10)` beat a concurrent tombstone at `(epoch 3, seq 40)`
/// purely because 5 > 3 — a restarted stale writer republishing without ever
/// seeing the sibling's delete, and disaster recovery resurrecting the rule the
/// user removed.
///
/// So domination is decided by ANCESTRY, and a branch is where ancestry lives:
///
/// * two records **in the same branch** are causally ordered, because a branch
///   is a chain and a chain's clocks increase along it — so a lower clock there
///   really is in the winner's past;
/// * two records that **share no branch** are concurrent, whatever their
///   numbers say, and a concurrent tombstone wins.
///
/// Records before a fork point appear in every branch that descends from it,
/// which is what makes the shared-branch test give the right answer for the
/// common history as well as for the fork.
///
/// # What this preserves
///
/// The earlier reading — "a tombstone in a different writer epoch is
/// concurrent" — was wrong for the ordinary case: `writer_epoch` increments on
/// every daemon START, so a delete in epoch 2 and a re-create in epoch 3 are
/// one writer, on two days, doing the obvious thing, and treating the old
/// tombstone as concurrent suppressed entities the user was actively using.
/// Those two records share a branch, so they stay causally ordered here and the
/// re-creation still wins.
///
/// Records sharing the winner's exact clock remain concurrent with it — a
/// genuine two-writer collision — and delete-wins remains the answer.
pub fn merge_durable_config(
    branches: &[Vec<Publication<DurableConfigRecord>>],
) -> Vec<DurableConfigRecord> {
    // Each entity's records, each tagged with the set of branches carrying it.
    // The key borrows for the same reason the values do: nothing here outlives
    // `branches`. `&str` orders identically to `String`, so the group order —
    // and therefore the order of `out` — is unchanged.
    // Grouped by `(kind, entity_id)`, with each publication collapsed across
    // the branches that descend through it — see [`group_by`].
    let by_entity = group_by(branches, |r: &DurableConfigRecord| {
        (r.kind, r.entity_id.clone())
    });

    let mut out = Vec::new();
    for (_, group) in by_entity {
        // Each branch is reduced to its FRONTIER — its latest record for this
        // entity — before anything is compared across branches.
        //
        // Reducing first is what makes the delete-wins test ask the right
        // question. A branch that deleted the entity and then re-created it has
        // a live frontier and a *superseded* tombstone in its own history; that
        // tombstone is no more current there than a stale edit would be.
        // Comparing raw records let it face a winner from a sibling branch,
        // share no branch with it, and be called concurrent — so recovery
        // dropped an entity whose branches both ended on "alive".
        let branch_ids: BTreeSet<usize> = group
            .iter()
            .flat_map(|seen| seen.branches.iter().copied())
            .collect();
        let frontiers: Vec<&SeenOn<'_, DurableConfigRecord>> = branch_ids
            .iter()
            .filter_map(|b| {
                group
                    .iter()
                    .filter(|seen| seen.branches.contains(b))
                    .max_by_key(|seen| seen.record.clock)
            })
            .collect();

        let Some(winner) = frontiers
            .iter()
            .copied()
            .max_by_key(|seen| seen.record.clock)
        else {
            continue;
        };
        if winner.record.tombstone {
            continue;
        }
        let concurrent_delete = frontiers.iter().any(|seen| {
            if !seen.record.tombstone {
                return false;
            }
            // Dominated — in the winner's past — only if some ONE branch holds
            // both, and this one comes earlier on it. `branches` is where the
            // record APPEARS, not where it is a frontier: a branch that has
            // simply not advanced past the tombstone still shares the winner's
            // ancestry, and that is history rather than a conflict.
            let shares_a_branch = seen
                .branches
                .intersection(&winner.branches)
                .next()
                .is_some();
            !(shares_a_branch && seen.record.clock < winner.record.clock)
        });
        if concurrent_delete {
            continue;
        }
        out.push(winner.record.clone());
    }
    out
}

/// Encode entries as a zstd-compressed JSONL segment.
///
/// JSONL because "append" is not assumed as a primitive on any substrate here —
/// each publication is a new immutable segment, and a line-oriented body keeps
/// a partially-readable segment partially useful to a human doing disaster
/// recovery by hand.
pub fn encode_segment(entries: &[BundleEntry]) -> Result<Vec<u8>, super::chain::ChainError> {
    let mut jsonl = Vec::new();
    for e in entries {
        serde_json::to_writer(&mut jsonl, e).map_err(|err| {
            super::chain::ChainError::Malformed {
                key: "bundle segment".into(),
                detail: err.to_string(),
            }
        })?;
        jsonl.push(b'\n');
    }
    zstd::encode_all(jsonl.as_slice(), 3).map_err(|err| super::chain::ChainError::Malformed {
        key: "bundle segment".into(),
        detail: format!("zstd: {err}"),
    })
}

/// Decode a segment produced by [`encode_segment`].
pub fn decode_segment(body: &[u8]) -> Result<Vec<BundleEntry>, super::chain::ChainError> {
    let jsonl = zstd::decode_all(body).map_err(|err| super::chain::ChainError::Malformed {
        key: "bundle segment".into(),
        detail: format!("zstd: {err}"),
    })?;
    let mut out = Vec::new();
    for (i, line) in jsonl.split(|b| *b == b'\n').enumerate() {
        if line.is_empty() {
            continue;
        }
        let e =
            serde_json::from_slice(line).map_err(|err| super::chain::ChainError::Malformed {
                key: format!("bundle segment line {}", i + 1),
                detail: err.to_string(),
            })?;
        out.push(e);
    }
    Ok(out)
}

#[cfg(test)]
#[path = "bundle_tests.rs"]
mod tests;
