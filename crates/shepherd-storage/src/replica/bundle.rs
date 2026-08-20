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

use std::collections::BTreeMap;

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
/// A tombstone applies **only when no live branch re-asserts the record**. That
/// asymmetry is deliberate and points the same way as everything else on this
/// path: re-asserting a custody record costs a duplicate, honouring a stale
/// tombstone costs the file.
/// A tombstone is therefore **not** applied against a key that any branch still
/// asserts live, no matter how new the tombstone's clock is. Note what that
/// means mechanically: a tombstone contributes nothing at all to the output,
/// and a key tombstoned on every branch simply never enters `live`. An earlier
/// draft of this function kept a separate tombstone set and subtracted it at
/// the end, which quietly implemented *delete-wins* — the custody reducer with
/// the durable-config reducer's rule, and the one direction that can drop the
/// only remaining address of a destroyed file.
pub fn merge_custody(records: &[CustodyRecord]) -> Vec<CustodyRecord> {
    let mut live: BTreeMap<(CustodyKey, i64), CustodyRecord> = BTreeMap::new();

    for r in records.iter().filter(|r| !r.tombstone) {
        let k = (r.key.clone(), r.target.get());
        match live.get(&k) {
            // Highest clock wins among live assertions of the same record;
            // they are the same custody fact, so this only picks the
            // best-attested copy.
            Some(prev) if prev.clock >= r.clock => {}
            _ => {
                live.insert(k, r.clone());
            }
        }
    }

    live.into_values().collect()
}

/// Merge durable-config records across all valid branches.
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
/// The concurrency rule, stated precisely: a tombstone written in a **different
/// writer epoch** from the winning update is treated as concurrent with it and
/// wins regardless of `seq`. Within a single epoch the writer's own ordering is
/// meaningful, so a delete followed by a re-create in the same epoch correctly
/// yields the re-created entity.
pub fn merge_durable_config(records: &[DurableConfigRecord]) -> Vec<DurableConfigRecord> {
    // The key borrows for the same reason the values already do: nothing here
    // outlives `records`. `&str` orders identically to `String`, so the group
    // order — and therefore the order of `out` — is unchanged.
    let mut by_entity: BTreeMap<(ConfigKind, &str), Vec<&DurableConfigRecord>> = BTreeMap::new();
    for r in records {
        by_entity
            .entry((r.kind, r.entity_id.as_str()))
            .or_default()
            .push(r);
    }

    let mut out = Vec::new();
    for (_, group) in by_entity {
        let winner = group.iter().max_by_key(|r| r.clock).copied();
        let Some(winner) = winner else { continue };
        if winner.tombstone {
            continue;
        }
        // Any tombstone from a different epoch is concurrent with the winner.
        let concurrent_delete = group
            .iter()
            .any(|r| r.tombstone && r.clock.writer_epoch != winner.clock.writer_epoch);
        if concurrent_delete {
            continue;
        }
        out.push(winner.clone());
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
