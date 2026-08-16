//! Part planning and crash-safe part reconciliation.
//!
//! spec:89 requires **every** transfer to be multipart and resumable, which is
//! why §4.5 chose `aws-sdk-s3` over `opendal` in the first place. This module
//! holds the two pieces of that which are pure arithmetic over durable state,
//! so they can be tested exhaustively without a provider: deciding the part
//! layout, and deciding — after a crash — which parts must be re-sent.
//!
//! # The reconciliation rule, and why it is deliberately pessimistic
//!
//! AC-2 is "kill the daemon mid-upload of a 50 GB file, restart, resume without
//! re-sending verified parts". The temptation is to trust the provider's
//! `ListParts` as the source of truth and skip every part it reports. **That is
//! wrong, and the reason is §4.5's opaque-token rule.**
//!
//! An ETag is not a content hash. When the provider says "I hold part 7", it is
//! not saying "I hold *your* part 7" — it may hold part 7 from an earlier
//! attempt against a source file that has since changed, or from a part whose
//! upload landed while the checkpoint write did not. Nothing in an opaque token
//! lets Shepherd tell those apart.
//!
//! So a part is skipped only when **both** sides agree: the durable local
//! checkpoint records the ETag the provider returned *and* the provider still
//! reports that same ETag at that same size. Anything else is re-sent. That
//! makes the crash-after-upload-before-checkpoint window cost one re-sent part
//! rather than a silently corrupt object, and it is the direction that cannot
//! lose data.

use serde::{Deserialize, Serialize};

use crate::adapter::{
    AdapterCapabilities, ByteRange, OpaqueToken, PartReceipt, StorageError, StorageResult,
};

/// Default part size. 16 MiB keeps a 50 GB object at 3 200 parts — comfortably
/// inside S3's 10 000 limit, with room for the plan to grow the part size on
/// larger objects rather than run out of part numbers.
pub const DEFAULT_PART_SIZE: u64 = 16 * 1024 * 1024;

/// How an object is cut into parts.
///
/// Persisted with the session: on resume the part boundaries must be **exactly**
/// the ones the earlier attempt used, or the offsets recorded in each checkpoint
/// address different bytes than they did before the crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartPlan {
    pub total_size: u64,
    pub part_size: u64,
    pub part_count: u32,
}

impl PartPlan {
    /// Cut `total_size` into parts that satisfy `caps`.
    ///
    /// `preferred` is a hint. It is raised when the object is too large to fit
    /// in `caps.max_parts` at that size — a 5 TB object at 16 MiB would need
    /// 327 680 parts, so the part size grows to `ceil(total / max_parts)`
    /// instead of the plan failing.
    pub fn new(total_size: u64, caps: &AdapterCapabilities, preferred: u64) -> StorageResult<Self> {
        // Clamp the hint into the provider's legal band FIRST. A preferred size
        // above `max_part_size` is a hint to be ignored, not an error — the
        // final part of a small object is legitimately shorter than
        // `min_part_size` too, which is why the floor is applied to the part
        // size and never to the object.
        let mut part_size = preferred.max(caps.min_part_size).min(caps.max_part_size);

        // Grow the part size until the object fits in the provider's part-number
        // budget. `div_ceil` so a remainder still gets its own part.
        let needed = total_size.div_ceil(part_size);
        if needed > u64::from(caps.max_parts) {
            part_size = total_size.div_ceil(u64::from(caps.max_parts));
        }
        // Only now can this be a real failure: the object needs bigger parts
        // than the provider accepts, at the provider's own part-number ceiling.
        if part_size > caps.max_part_size {
            return Err(StorageError::Unsupported {
                provider: caps.provider,
                what: format!(
                    "an object of {total_size} B needs {part_size} B parts at the {}-part \
                     ceiling, above the {} B maximum, so it cannot be uploaded to this target",
                    caps.max_parts, caps.max_part_size
                ),
            });
        }

        // A zero-byte object is still one (empty) part: a multipart upload with
        // no parts at all is not completable.
        let part_count = u32::try_from(total_size.div_ceil(part_size).max(1)).map_err(|_| {
            StorageError::Unsupported {
                provider: caps.provider,
                what: format!("{total_size} B does not fit in a u32 part count"),
            }
        })?;

        Ok(Self {
            total_size,
            part_size,
            part_count,
        })
    }

    /// The byte range for a 1-based part number, or `None` if out of range.
    ///
    /// Part numbers are 1-based because S3's are; using 0-based numbers
    /// internally and converting at the edge is exactly the sort of off-by-one
    /// that would silently truncate the first part of every object.
    pub fn range_of(&self, part_no: u32) -> Option<ByteRange> {
        if part_no == 0 || part_no > self.part_count {
            return None;
        }
        let offset = u64::from(part_no - 1) * self.part_size;
        let len = self.part_size.min(self.total_size.saturating_sub(offset));
        Some(ByteRange { offset, len })
    }

    /// Every part, in ascending order.
    pub fn ranges(&self) -> impl Iterator<Item = (u32, ByteRange)> + '_ {
        (1..=self.part_count).filter_map(|n| self.range_of(n).map(|r| (n, r)))
    }
}

/// The durable record of one part.
///
/// §4.4's `transfer_part(job_id, upload_id, part_no, etag, bytes, verified_at)`
/// is the row this maps onto, plus the per-part **local** BLAKE3 that the row
/// does not carry. That hash is what lets a resumed transfer prove it is
/// re-reading the same source bytes it hashed before the crash, rather than
/// assuming the file did not move under it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PartCheckpoint {
    pub part_no: u32,
    pub offset: u64,
    pub len: u64,
    /// BLAKE3 of this part's *source* bytes, computed locally as it was read.
    pub local_blake3: shepherd_core::Blake3Hash,
    /// The provider's opaque receipt, present only once the upload returned
    /// **and** this checkpoint was durably committed.
    pub etag: Option<OpaqueToken>,
}

impl PartCheckpoint {
    /// Whether this part has a durably recorded provider receipt.
    pub fn is_acknowledged(&self) -> bool {
        self.etag.is_some()
    }
}

/// What resume must do with one part.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartAction {
    /// Durable checkpoint and provider agree. Do not re-send — this is the
    /// property AC-2 measures.
    Skip,
    /// Re-read from source and upload.
    Send,
}

/// The outcome of reconciling durable checkpoints against provider state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reconciliation {
    /// One entry per part, indexed by `part_no - 1`.
    pub actions: Vec<PartAction>,
    /// Bytes that will not be re-sent. This is the number AC-2's test asserts
    /// is greater than zero after a mid-upload kill.
    pub bytes_skipped: u64,
    /// Parts the provider reports that no durable checkpoint claims.
    ///
    /// **Never adopted**, only counted. An unmatched remote part is either
    /// residue from a previous attempt epoch or a part whose upload outran its
    /// checkpoint; an opaque ETag cannot distinguish those, so it is re-sent
    /// and the provider's copy is overwritten by part number.
    pub orphan_remote_parts: u32,
}

/// Decide, per part, whether resume may skip the upload.
///
/// `local` need not be complete or sorted; parts with no checkpoint are
/// [`PartAction::Send`].
pub fn reconcile_parts(
    plan: &PartPlan,
    local: &[PartCheckpoint],
    remote: &[PartReceipt],
) -> Reconciliation {
    let mut actions = vec![PartAction::Send; plan.part_count as usize];
    let mut bytes_skipped = 0u64;
    let mut matched_remote = 0u32;

    for cp in local {
        let Some(slot) = plan
            .range_of(cp.part_no)
            .and_then(|_| actions.get_mut(cp.part_no as usize - 1))
        else {
            // A checkpoint outside the current plan is stale — the object size
            // or part size changed. Ignore it; the part gets re-sent.
            continue;
        };
        let Some(etag) = cp.etag.as_ref() else {
            // Uploaded-but-not-checkpointed, or never uploaded. Either way the
            // durable record does not prove the provider holds our bytes.
            continue;
        };
        // Both sides must agree, on the same part number, the same opaque token
        // AND the same length.
        let agreed = remote
            .iter()
            .any(|r| r.part_no == cp.part_no && r.etag == *etag && r.size == cp.len);
        if agreed {
            *slot = PartAction::Skip;
            bytes_skipped += cp.len;
            matched_remote += 1;
        }
    }

    Reconciliation {
        actions,
        bytes_skipped,
        orphan_remote_parts: u32::try_from(remote.len())
            .unwrap_or(u32::MAX)
            .saturating_sub(matched_remote),
    }
}

impl Reconciliation {
    /// Parts still to send.
    pub fn pending(&self) -> impl Iterator<Item = u32> + '_ {
        self.actions
            .iter()
            .enumerate()
            .filter(|(_, a)| **a == PartAction::Send)
            .map(|(i, _)| u32::try_from(i + 1).unwrap_or(u32::MAX))
    }

    /// Whether every part is already durably acknowledged.
    pub fn is_complete(&self) -> bool {
        self.actions.iter().all(|a| *a == PartAction::Skip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shepherd_core::Blake3Hash;

    fn caps() -> AdapterCapabilities {
        AdapterCapabilities {
            provider: "test",
            conditional_create: true,
            min_part_size: 5 * 1024 * 1024,
            max_part_size: 5 * 1024 * 1024 * 1024,
            max_parts: 10_000,
            list_visibility: crate::adapter::ListVisibility::Strong,
        }
    }

    fn h(seed: u8) -> Blake3Hash {
        Blake3Hash::from_bytes([seed; 32])
    }

    #[test]
    fn fifty_gb_fits_inside_the_part_number_budget() {
        let fifty_gb = 50 * 1024 * 1024 * 1024;
        let plan = PartPlan::new(fifty_gb, &caps(), DEFAULT_PART_SIZE).unwrap();
        assert_eq!(plan.part_size, DEFAULT_PART_SIZE);
        assert_eq!(plan.part_count, 3200);
        assert!(u64::from(plan.part_count) <= u64::from(caps().max_parts));
    }

    #[test]
    fn part_size_grows_rather_than_exhausting_part_numbers() {
        // 5 TB at the preferred 16 MiB would need 327 680 parts.
        let five_tb = 5 * 1024 * 1024 * 1024 * 1024;
        let plan = PartPlan::new(five_tb, &caps(), DEFAULT_PART_SIZE).unwrap();
        assert!(plan.part_count <= caps().max_parts, "{}", plan.part_count);
        assert!(plan.part_size > DEFAULT_PART_SIZE);
        // Still covers every byte.
        let covered: u64 = plan.ranges().map(|(_, r)| r.len).sum();
        assert_eq!(covered, five_tb);
    }

    #[test]
    fn ranges_are_contiguous_gapless_and_cover_exactly_the_object() {
        let total = 40 * 1024 * 1024 + 12345;
        let plan = PartPlan::new(total, &caps(), 16 * 1024 * 1024).unwrap();
        let mut next = 0u64;
        for (no, r) in plan.ranges() {
            assert_eq!(r.offset, next, "gap or overlap before part {no}");
            next += r.len;
        }
        assert_eq!(next, total);
        assert_eq!(plan.range_of(0), None, "part numbers are 1-based");
        assert_eq!(plan.range_of(plan.part_count + 1), None);
    }

    #[test]
    fn a_zero_byte_object_is_one_empty_part() {
        let plan = PartPlan::new(0, &caps(), DEFAULT_PART_SIZE).unwrap();
        assert_eq!(plan.part_count, 1);
        assert_eq!(plan.range_of(1), Some(ByteRange { offset: 0, len: 0 }));
    }

    #[test]
    fn resume_skips_only_parts_both_sides_agree_on() {
        let plan = PartPlan::new(3 * 5 * 1024 * 1024, &caps(), 5 * 1024 * 1024).unwrap();
        assert_eq!(plan.part_count, 3);
        let len = 5 * 1024 * 1024;

        let local = vec![
            // 1: uploaded and checkpointed.
            PartCheckpoint {
                part_no: 1,
                offset: 0,
                len,
                local_blake3: h(1),
                etag: Some(OpaqueToken::new("e1")),
            },
            // 2: crashed after the upload, before the checkpoint commit.
            PartCheckpoint {
                part_no: 2,
                offset: len,
                len,
                local_blake3: h(2),
                etag: None,
            },
        ];
        let remote = vec![
            PartReceipt {
                part_no: 1,
                size: len,
                etag: OpaqueToken::new("e1"),
                checksum: None,
            },
            // The provider really does hold part 2 — but no durable record
            // proves it is ours, so it must not be adopted.
            PartReceipt {
                part_no: 2,
                size: len,
                etag: OpaqueToken::new("e2"),
                checksum: None,
            },
        ];

        let r = reconcile_parts(&plan, &local, &remote);
        assert_eq!(r.actions[0], PartAction::Skip);
        assert_eq!(r.actions[1], PartAction::Send);
        assert_eq!(r.actions[2], PartAction::Send);
        assert_eq!(r.bytes_skipped, len);
        assert_eq!(r.orphan_remote_parts, 1);
        assert_eq!(r.pending().collect::<Vec<_>>(), vec![2, 3]);
        assert!(!r.is_complete());
    }

    #[test]
    fn a_changed_etag_or_size_forces_a_resend() {
        let plan = PartPlan::new(5 * 1024 * 1024, &caps(), 5 * 1024 * 1024).unwrap();
        let len = 5 * 1024 * 1024;
        let cp = |etag: &str| {
            vec![PartCheckpoint {
                part_no: 1,
                offset: 0,
                len,
                local_blake3: h(1),
                etag: Some(OpaqueToken::new(etag)),
            }]
        };

        // Provider reports a different token for the same part number: the
        // object under that part is not the one we checkpointed.
        let remote_wrong_tag = vec![PartReceipt {
            part_no: 1,
            size: len,
            etag: OpaqueToken::new("other"),
            checksum: None,
        }];
        assert_eq!(
            reconcile_parts(&plan, &cp("mine"), &remote_wrong_tag).actions[0],
            PartAction::Send
        );

        // Same token, truncated part.
        let remote_short = vec![PartReceipt {
            part_no: 1,
            size: len - 1,
            etag: OpaqueToken::new("mine"),
            checksum: None,
        }];
        assert_eq!(
            reconcile_parts(&plan, &cp("mine"), &remote_short).actions[0],
            PartAction::Send
        );
    }

    #[test]
    fn an_empty_provider_listing_resends_everything() {
        let plan = PartPlan::new(2 * 5 * 1024 * 1024, &caps(), 5 * 1024 * 1024).unwrap();
        let local = vec![PartCheckpoint {
            part_no: 1,
            offset: 0,
            len: 5 * 1024 * 1024,
            local_blake3: h(1),
            etag: Some(OpaqueToken::new("e1")),
        }];
        // Session expired and the provider dropped the parts.
        let r = reconcile_parts(&plan, &local, &[]);
        assert!(r.actions.iter().all(|a| *a == PartAction::Send));
        assert_eq!(r.bytes_skipped, 0);
    }

    #[test]
    fn stale_checkpoints_outside_the_plan_are_ignored_not_panicked_on() {
        let plan = PartPlan::new(5 * 1024 * 1024, &caps(), 5 * 1024 * 1024).unwrap();
        let local = vec![PartCheckpoint {
            part_no: 99,
            offset: 0,
            len: 1,
            local_blake3: h(9),
            etag: Some(OpaqueToken::new("e")),
        }];
        let r = reconcile_parts(&plan, &local, &[]);
        assert_eq!(r.actions.len(), 1);
        assert_eq!(r.actions[0], PartAction::Send);
    }

    #[test]
    fn a_fully_acknowledged_transfer_reports_complete() {
        let plan = PartPlan::new(5 * 1024 * 1024, &caps(), 5 * 1024 * 1024).unwrap();
        let len = 5 * 1024 * 1024;
        let local = vec![PartCheckpoint {
            part_no: 1,
            offset: 0,
            len,
            local_blake3: h(1),
            etag: Some(OpaqueToken::new("e1")),
        }];
        let remote = vec![PartReceipt {
            part_no: 1,
            size: len,
            etag: OpaqueToken::new("e1"),
            checksum: None,
        }];
        assert!(reconcile_parts(&plan, &local, &remote).is_complete());
    }
}
