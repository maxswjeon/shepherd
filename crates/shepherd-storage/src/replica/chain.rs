//! OQ-1 — hash-chained immutable records with collision-proof keys.
//!
//! # Read this before changing anything here
//!
//! This is the **third** design for this mechanism and the second time an
//! earlier one was falsified, so the reasoning is recorded rather than assumed.
//!
//! * Iteration 1 required atomic single-object overwrite of a `CURRENT`
//!   pointer. Falsified by a source read of the `smb2` crate:
//!   `build_rename_info_buffer` hardcodes `ReplaceIfExists = false`, so
//!   `Tree::rename()` **cannot** atomically replace an existing target.
//! * Iteration 2 replaced it with **list-and-max**. That removed the
//!   requirement but also removed the only primitive that made collisions
//!   *detectable*, and left pointer allocation unguarded.
//!
//! The hole iteration 2 left is the one this design exists to close:
//!
//! > A restarted writer with a stale LIST computes an already-used sequence
//! > number, PUTs over a well-formed immutable pointer, and silently orphans
//! > that generation's delta segment.
//!
//! A self-checksum cannot catch that — the replacing object is perfectly valid.
//! Segment-then-pointer ordering cannot catch it. **Nothing looked.** And it is
//! not a concurrency bug: a freshly started process reading a stale listing is
//! not a *concurrent* writer, it is the same writer with amnesia, so
//! "v1 is single-writer" does not exclude it.
//!
//! # The two load-bearing properties
//!
//! 1. **Allocation never reads LIST.** [`SequenceAllocator`] returns
//!    `max(persisted local HWM, 0) + 1`, fsync'd *before* the PUT. LIST is used
//!    only for reading and recovery. Separating allocation from reading is the
//!    change everything else rests on — do not collapse it back.
//! 2. **`prev_ptr_blake3` chains the records.** A fork (two records claiming
//!    one predecessor) and a gap (a referenced predecessor no listing returns)
//!    become detectable at read time with nothing but `create` and `list`.
//!    **This cannot be retrofitted onto pointers already written**, which is
//!    why it lands in Phase 2 before the first pointer exists, not in Phase 6.
//!
//! Reading is **merge-all-valid-branches**, never scalar-max — see
//! [`ChainResolution`]. Garbage collection is **disabled in v1** (D-10): a
//! compactor working from a stale LIST can classify a segment as orphaned while
//! an unseen newer pointer references it, manufacturing the exact
//! "pointer to bytes that do not exist" state the ordering rule promises is
//! impossible. Nothing in this module deletes anything.

use std::collections::{BTreeMap, BTreeSet};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use shepherd_core::{Blake3Hash, ObjectKey, TargetId};

use crate::adapter::{ControlKey, CreatePrecondition, StorageAdapter, StorageError, StorageResult};

/// Schema version of the pointer record body.
pub const POINTER_SCHEMA_VERSION: u32 = 1;

/// Where the chain lives, relative to a target's prefix.
pub const CATALOG_PREFIX: &str = "catalog/";

/// What a segment carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SegmentKind {
    /// A full snapshot of the target-scoped catalog.
    Snapshot,
    /// A delta since the previous pointer.
    Delta,
}

impl SegmentKind {
    /// The file extension, including the compression suffix — OQ-1's layout
    /// names these `.sqlite.zst` and `.jsonl.zst`, and this crate really does
    /// compress, so the extension describes the bytes.
    pub fn extension(self) -> &'static str {
        match self {
            SegmentKind::Snapshot => "sqlite.zst",
            SegmentKind::Delta => "jsonl.zst",
        }
    }
}

/// A collision-proof record key: `(writer_epoch, durable_local_sequence, uuid)`.
///
/// | Component | Why |
/// |---|---|
/// | `epoch` | Persisted locally, incremented once per daemon start, fsync'd before first use. Two lifetimes of one writer can never share a namespace |
/// | `seq` | `target.replica_hwm`, persisted **before** the PUT. Monotonic within an epoch; never derived from LIST |
/// | `uuid` | Random per record. Closes the residual case of a rolled-back local DB reusing an epoch |
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct RecordKey {
    pub epoch: u64,
    pub seq: u64,
    pub uuid: String,
}

impl RecordKey {
    /// A key for `(epoch, seq)` with a fresh random uuid.
    ///
    /// The uuid lives here rather than in each [`SequenceAllocator`] because
    /// its job is narrow and easy to get wrong: it closes the residual case of
    /// a **rolled-back local database reusing an epoch**. An allocator author
    /// reading only the trait would reasonably supply something derived from
    /// `(epoch, seq)` — which is precisely the case the uuid exists to cover,
    /// since a rolled-back database reproduces both.
    pub fn new(epoch: u64, seq: u64) -> Self {
        Self {
            epoch,
            seq,
            uuid: uuid::Uuid::new_v4().to_string(),
        }
    }

    pub fn pointer_name(&self) -> String {
        format!("ptr-{}-{}-{}.json", self.epoch, self.seq, self.uuid)
    }

    pub fn segment_name(&self, kind: SegmentKind) -> String {
        format!(
            "seg-{}-{}-{}.{}",
            self.epoch,
            self.seq,
            self.uuid,
            kind.extension()
        )
    }

    /// `_shepherd/catalog/ptr-…json`
    pub fn pointer_key(&self) -> ControlKey {
        ControlKey::under(format!("{CATALOG_PREFIX}{}", self.pointer_name()))
    }

    pub fn segment_key(&self, kind: SegmentKind) -> ControlKey {
        ControlKey::under(format!("{CATALOG_PREFIX}{}", self.segment_name(kind)))
    }

    /// Recover the key components from a pointer object name.
    ///
    /// Used only to *filter* a listing down to pointer objects. The authority
    /// for a record's epoch and seq is the validated body, never the name — a
    /// name is attacker- and bug-writable, a `self_blake3`-checked body is not.
    pub fn parse_pointer(name: &str) -> Option<Self> {
        let base = name.rsplit('/').next()?;
        let rest = base.strip_prefix("ptr-")?.strip_suffix(".json")?;
        let mut it = rest.splitn(3, '-');
        let epoch = it.next()?.parse().ok()?;
        let seq = it.next()?.parse().ok()?;
        let uuid = it.next()?.to_owned();
        (!uuid.is_empty()).then_some(Self { epoch, seq, uuid })
    }
}

/// The immutable, hash-chained pointer record.
///
/// Hashes are hex strings rather than byte arrays because this is a
/// **disaster-recovery artifact**. The scenario it exists for is a user with a
/// target URL, some credentials and no working machine; a record they can open
/// and read is worth more than one that is marginally cheaper to parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PointerRecord {
    pub epoch: u64,
    pub seq: u64,
    pub uuid: String,
    pub schema_version: u32,
    /// Hash of the pointer this one extends — the chain link. `None` only for
    /// the genesis record.
    pub prev_ptr_blake3: Option<String>,
    /// The segment this pointer publishes.
    pub segment_blake3: String,
    pub segment_key: String,
    /// Hash of the full logical state after applying this record.
    pub cumulative_state_blake3: String,
    /// Over every field above. Empty until [`PointerRecord::seal`].
    pub self_blake3: String,
}

/// What went wrong reading or writing a chain.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ChainError {
    #[error("pointer {key}: {detail}")]
    Malformed { key: String, detail: String },

    #[error("pointer {key}: self_blake3 does not match its body")]
    SelfHashMismatch { key: String },

    #[error("allocator failed for {target}: {detail}")]
    Allocation { target: String, detail: String },

    #[error(transparent)]
    Storage(#[from] StorageError),
}

impl PointerRecord {
    /// Canonical bytes for hashing.
    ///
    /// Routed through `serde_json::Value`, whose object type is a `BTreeMap`,
    /// so keys come out in alphabetical order with no whitespace **regardless
    /// of struct declaration order**. That matters because a reader validates a
    /// hash over bytes it re-serialized itself: if canonicalization depended on
    /// field order, adding a field would silently invalidate every pointer ever
    /// written. `signing_bytes` omits `self_blake3`, since a hash cannot cover
    /// itself.
    fn signing_bytes(&self) -> Result<Vec<u8>, ChainError> {
        let mut v = serde_json::to_value(self).map_err(|e| ChainError::Malformed {
            key: self.uuid.clone(),
            detail: e.to_string(),
        })?;
        if let Some(obj) = v.as_object_mut() {
            obj.remove("self_blake3");
        }
        serde_json::to_vec(&v).map_err(|e| ChainError::Malformed {
            key: self.uuid.clone(),
            detail: e.to_string(),
        })
    }

    /// The hash this record's `self_blake3` must equal.
    pub fn compute_self_hash(&self) -> Result<Blake3Hash, ChainError> {
        let bytes = self.signing_bytes()?;
        Ok(Blake3Hash::from_bytes(*blake3::hash(&bytes).as_bytes()))
    }

    /// Stamp `self_blake3`. Call once, immediately before the create.
    pub fn seal(mut self) -> Result<Self, ChainError> {
        self.self_blake3 = self.compute_self_hash()?.to_hex();
        Ok(self)
    }

    /// Verify the record is internally consistent and well-formed.
    pub fn validate(&self) -> Result<(), ChainError> {
        let name = self.key().pointer_name();
        if self.schema_version > POINTER_SCHEMA_VERSION {
            return Err(ChainError::Malformed {
                key: name,
                detail: format!(
                    "schema_version {} is newer than this build understands ({POINTER_SCHEMA_VERSION})",
                    self.schema_version
                ),
            });
        }
        for (field, hex) in [
            ("segment_blake3", Some(&self.segment_blake3)),
            (
                "cumulative_state_blake3",
                Some(&self.cumulative_state_blake3),
            ),
            ("prev_ptr_blake3", self.prev_ptr_blake3.as_ref()),
        ] {
            if let Some(h) = hex
                && Blake3Hash::from_hex(h).is_none()
            {
                return Err(ChainError::Malformed {
                    key: name,
                    detail: format!("{field} is not 64 hex characters"),
                });
            }
        }
        let expect = self.compute_self_hash()?;
        match Blake3Hash::from_hex(&self.self_blake3) {
            Some(got) if got == expect => Ok(()),
            _ => Err(ChainError::SelfHashMismatch { key: name }),
        }
    }

    pub fn key(&self) -> RecordKey {
        RecordKey {
            epoch: self.epoch,
            seq: self.seq,
            uuid: self.uuid.clone(),
        }
    }

    /// Logical ordering: `(epoch, seq)`.
    fn clock(&self) -> (u64, u64) {
        (self.epoch, self.seq)
    }
}

/// Allocates collision-proof record keys, implemented by `shepherd-catalog`.
///
/// **Contract, and the whole point of OQ-1:** `allocate` must bump
/// `target.replica_hwm` and **fsync it before returning**, and it must **never
/// consult a LIST**. An implementation that derives the next sequence from a
/// listing reintroduces exactly the silent-overwrite hole this design exists to
/// close, and it will pass every test that does not restart the writer.
#[async_trait::async_trait]
pub trait SequenceAllocator: Send + Sync {
    /// The next `(epoch, seq, uuid)` for `target`, durable before it returns.
    async fn allocate(&self, target: TargetId) -> Result<RecordKey, ChainError>;

    /// Record the validated chain tip (`target.replica_head_ptr_blake3`).
    async fn record_head(&self, target: TargetId, head: Blake3Hash) -> Result<(), ChainError>;
}

/// Publishes segments and the pointers that reference them.
pub struct ChainWriter<'a> {
    pub adapter: &'a dyn StorageAdapter,
    pub allocator: &'a dyn SequenceAllocator,
    pub target: TargetId,
}

impl<'a> ChainWriter<'a> {
    pub fn new(
        adapter: &'a dyn StorageAdapter,
        allocator: &'a dyn SequenceAllocator,
        target: TargetId,
    ) -> Self {
        Self {
            adapter,
            allocator,
            target,
        }
    }

    /// Publish `segment` and the pointer that names it.
    ///
    /// **Segment-then-pointer, always.** The segment is created and its hash
    /// confirmed before the pointer that publishes it exists, so a crash leaves
    /// an orphaned but harmless segment — never a pointer to bytes that are not
    /// there.
    ///
    /// Where the provider offers exclusive create, it is used and **a failure
    /// is a hard error**. OQ-1 corrects iteration 2 on exactly this point: it
    /// is not "defense in depth, an optimization" but the difference between
    /// detecting an epoch collision at write time and discovering it at
    /// recovery.
    pub async fn publish(
        &self,
        kind: SegmentKind,
        segment: Bytes,
        prev: Option<Blake3Hash>,
        cumulative_state: Blake3Hash,
    ) -> Result<PointerRecord, ChainError> {
        let key = self.allocator.allocate(self.target).await?;
        let segment_blake3 = Blake3Hash::from_bytes(*blake3::hash(&segment).as_bytes());
        let segment_key = key.segment_key(kind);

        let precondition = if self.adapter.capabilities().conditional_create {
            CreatePrecondition::IfAbsent
        } else {
            CreatePrecondition::Unconditional
        };

        self.adapter
            .create(segment_key.as_key(), segment, precondition)
            .await?;

        let record = PointerRecord {
            epoch: key.epoch,
            seq: key.seq,
            uuid: key.uuid.clone(),
            schema_version: POINTER_SCHEMA_VERSION,
            prev_ptr_blake3: prev.map(|h| h.to_hex()),
            segment_blake3: segment_blake3.to_hex(),
            segment_key: segment_key.as_key().as_str().to_owned(),
            cumulative_state_blake3: cumulative_state.to_hex(),
            self_blake3: String::new(),
        }
        .seal()?;

        let body = serde_json::to_vec(&record).map_err(|e| ChainError::Malformed {
            key: key.pointer_name(),
            detail: e.to_string(),
        })?;
        self.adapter
            .create(key.pointer_key().as_key(), Bytes::from(body), precondition)
            .await?;

        let head = record.compute_self_hash()?;
        self.allocator.record_head(self.target, head).await?;
        Ok(record)
    }
}

/// How a listing resolved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainStatus {
    /// One unbroken chain.
    Single,
    /// Two or more records claim the same predecessor, or there are multiple
    /// genesis records. Merged deterministically, but the target is **not**
    /// custody-eligible until a human acknowledges it.
    Fork { branch_tips: Vec<String> },
    /// A referenced predecessor that no listing returned. The replica is
    /// `incomplete` and **refuses to act as a custody authority**.
    Gap { missing: Vec<String> },
}

/// The result of reading a chain.
///
/// Returned as data rather than logged, because upper layers gate real
/// decisions on it: `target.custody_eligible`, the `replica-fork` alert, and
/// whether the user is asked to review merged configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainResolution {
    pub status: ChainStatus,
    /// **All** valid records, deterministically ordered by `(epoch, seq, uuid)`.
    ///
    /// Merge-all-valid-branches, never scalar-max: a scalar maximum silently
    /// discards a branch, and the branch it discards may be the one holding the
    /// only custody record for a file whose original is already gone.
    pub records: Vec<PointerRecord>,
    /// Records that failed validation, with the reason. Reported, never
    /// silently skipped.
    pub invalid: Vec<(String, String)>,
    /// The chain tip, when there is exactly one.
    pub head: Option<Blake3Hash>,
}

impl ChainResolution {
    /// Whether this replica may authorize destroying a sole local copy.
    ///
    /// Only an unforked, gapless chain qualifies. §OQ-1: until a fork is
    /// acknowledged the target is `custody_eligible = false`, and a gap makes
    /// the replica `incomplete`, which "refuses to be treated as a custody
    /// authority".
    ///
    /// **An empty chain is not an unbroken one.** `resolve_chain(&[])` finds
    /// nothing to fork and no predecessor to be missing, so it reports
    /// `Single` with no invalid records — a shape indistinguishable, to the
    /// first two clauses alone, from a healthy chain. It is not one: there is
    /// no genesis pointer, no segment and no recovery state at all, which is
    /// what a newly configured target and a target whose listing came back
    /// empty both look like. Since this predicate authorizes destroying a sole
    /// local copy, answering yes there is the fail-open direction on the one
    /// path that cannot be undone, so at least one valid record and a concrete
    /// head are required. The head clause is not redundant with the record
    /// clause: `Single` with records but no lone tip means the chain closed on
    /// itself, and a replay has nowhere to start.
    pub fn custody_eligible(&self) -> bool {
        matches!(self.status, ChainStatus::Single)
            && self.invalid.is_empty()
            && !self.records.is_empty()
            && self.head.is_some()
    }
}

/// Reconstruct the chain from a set of fetched pointer bodies.
///
/// The caller is responsible for **exhausting pagination** before calling this
/// (OQ-1: "pagination exhausted, not first-page"). A truncated input is
/// indistinguishable here from a genuine gap — which is the safe direction, but
/// it means a first-page listing would report spurious gaps rather than silent
/// data loss.
pub fn resolve_chain(bodies: &[(String, PointerRecord)]) -> ChainResolution {
    let mut valid: Vec<PointerRecord> = Vec::new();
    let mut invalid: Vec<(String, String)> = Vec::new();

    for (key, rec) in bodies {
        match rec.validate() {
            Ok(()) => valid.push(rec.clone()),
            Err(e) => invalid.push((key.clone(), e.to_string())),
        }
    }

    // Index by self hash. A duplicate self hash is a byte-identical duplicate
    // record, which is harmless — the same record listed twice.
    let mut by_hash: BTreeMap<String, &PointerRecord> = BTreeMap::new();
    for r in &valid {
        by_hash.insert(r.self_blake3.clone(), r);
    }

    // Fork: more than one record claiming the same predecessor (including more
    // than one genesis).
    let mut children: BTreeMap<Option<String>, Vec<&PointerRecord>> = BTreeMap::new();
    for r in &valid {
        children
            .entry(r.prev_ptr_blake3.clone())
            .or_default()
            .push(r);
    }
    let has_fork = children.values().any(|v| v.len() > 1);

    // Gap: a referenced predecessor nothing in the listing provides.
    let missing: BTreeSet<String> = valid
        .iter()
        .filter_map(|r| r.prev_ptr_blake3.clone())
        .filter(|h| !by_hash.contains_key(h))
        .collect();

    // Tips: records that are nobody's predecessor. Collected as owned hashes so
    // the ordering pass below can take `valid` mutably.
    let referenced: BTreeSet<String> = valid
        .iter()
        .filter_map(|r| r.prev_ptr_blake3.clone())
        .collect();
    let mut tips: Vec<String> = valid
        .iter()
        .filter(|r| !referenced.contains(&r.self_blake3))
        .map(|r| r.self_blake3.clone())
        .collect();
    tips.sort();

    // Deterministic order for replay, independent of listing order — SMB and
    // NFS directory reads carry no ordering guarantee at all.
    valid.sort_by(|a, b| a.clock().cmp(&b.clock()).then_with(|| a.uuid.cmp(&b.uuid)));

    // The lone tip, if there is exactly one — captured before `tips` moves.
    let sole_tip = (tips.len() == 1).then(|| tips[0].clone());

    // A gap is reported ahead of a fork: an incomplete listing cannot be
    // trusted to have shown us every branch, so calling it merely a fork would
    // understate the problem.
    let status = if !missing.is_empty() {
        ChainStatus::Gap {
            missing: missing.into_iter().collect(),
        }
    } else if has_fork || tips.len() > 1 {
        ChainStatus::Fork { branch_tips: tips }
    } else {
        ChainStatus::Single
    };

    let head = match &status {
        ChainStatus::Single => sole_tip.as_deref().and_then(Blake3Hash::from_hex),
        _ => None,
    };

    ChainResolution {
        status,
        records: valid,
        invalid,
        head,
    }
}

/// Fetch and resolve the whole chain, exhausting pagination.
pub async fn read_chain(adapter: &dyn StorageAdapter) -> StorageResult<ChainResolution> {
    let prefix = format!("{}{CATALOG_PREFIX}", shepherd_core::CONTROL_PREFIX);
    let mut keys: Vec<ObjectKey> = Vec::new();
    let mut page = None;
    loop {
        let p = adapter.list(&prefix, page.as_ref()).await?;
        keys.extend(p.keys);
        match p.next {
            // OQ-1 requires pagination exhausted, not first-page.
            Some(t) => page = Some(t),
            None => break,
        }
    }

    let mut bodies = Vec::new();
    for k in keys {
        if RecordKey::parse_pointer(k.as_str()).is_none() {
            continue; // a segment, not a pointer
        }
        let meta = adapter.head(&k).await?;
        let Some(meta) = meta else { continue };
        let raw = adapter
            .get_range(
                &k,
                crate::adapter::ByteRange {
                    offset: 0,
                    len: meta.size,
                },
            )
            .await?;
        match serde_json::from_slice::<PointerRecord>(&raw) {
            Ok(r) => bodies.push((k.as_str().to_owned(), r)),
            Err(e) => {
                return Err(StorageError::Provider {
                    provider: adapter.capabilities().provider,
                    op: "read_chain".into(),
                    detail: format!("pointer {} is not a pointer record: {e}", k.as_str()),
                });
            }
        }
    }
    Ok(resolve_chain(&bodies))
}

#[cfg(test)]
#[path = "chain_tests.rs"]
mod tests;
