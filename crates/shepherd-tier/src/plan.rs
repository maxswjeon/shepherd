//! Turning rule decisions into tier work.
//!
//! # Deliberately thin
//!
//! `shepherd-rules::Engine` decides *which* files and *what* action;
//! `shepherd-storage`'s `PartPlan` decides *how* an object is cut up. This
//! module does neither. It takes the engine's output as **values** and produces
//! the per-file work items the upload path consumes, which keeps the whole
//! selection story in one crate rather than half here and half there.
//!
//! # Keys are derived here, once, and are content-addressed
//!
//! §4.9 is explicit that keys must never be path-derived: ext4 holds
//! `Report.txt` and `report.txt` as two files, an SMB or OneDrive target folds
//! them to one object, and the second upload silently overwrites the first —
//! whose local original may already have been destroyed. So the key is
//! `<prefix>/objects/<b3[0:2]>/<b3[2:4]>/<b3>` and nothing else, and
//! [`derive_object_key`] is the only place it is built.
//!
//! That also buys AC-47's hash dedup: two files with identical content
//! legitimately share one object. Which is precisely why the upload path
//! serializes on the **remote key** as well as `fs_id` — see [`crate::upload`].

use shepherd_core::{Blake3Hash, FileId, ObjectKey, TargetId};

/// One file the tier path will move.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TierItem {
    pub file: FileId,
    /// Absolute local path. The upload reads from here.
    pub path: String,
    pub size: u64,
    /// Required. A file with no hash cannot be planned, because AC-1 makes a
    /// hash match the precondition for ever destroying the original — see
    /// [`PlanRefusal::Unhashed`].
    pub blake3: Blake3Hash,
    pub target: TargetId,
    /// Content-addressed per §4.9.
    pub remote_key: ObjectKey,
}

/// Why a file could not be planned.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PlanRefusal {
    /// The file has no BLAKE3 yet.
    ///
    /// Not an error — §6 Phase 1 makes hashing "its own job class (never a scan
    /// prerequisite)", so a freshly walked file legitimately has no hash. It is
    /// simply not plannable yet, and saying so is better than planning it
    /// against a key that would have to change.
    Unhashed { file: FileId },
    /// A tiering rule with no destinations. Refused rather than treated as
    /// "nowhere", because a rule that moves files to no target and then permits
    /// their destruction is the worst possible reading of an empty list.
    NoDestination { file: FileId },
}

/// The content-addressed remote key for `hash` under `prefix`.
///
/// The two-level fan-out keeps any single listing prefix small on providers
/// whose LIST cost grows with directory width.
pub fn derive_object_key(prefix: &str, hash: Blake3Hash) -> ObjectKey {
    let h = hash.to_hex();
    let prefix = prefix.trim_end_matches('/');
    if prefix.is_empty() {
        ObjectKey::new(format!("objects/{}/{}/{}", &h[0..2], &h[2..4], h))
    } else {
        ObjectKey::new(format!("{prefix}/objects/{}/{}/{}", &h[0..2], &h[2..4], h))
    }
}

/// What a planning pass produced.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct TierPlan {
    pub items: Vec<TierItem>,
    /// Files that matched a rule but could not be planned, each with a reason.
    /// Reported rather than dropped: a file silently missing from a plan looks
    /// identical to a file the rule never matched.
    pub refused: Vec<PlanRefusal>,
}

impl TierPlan {
    /// Distinct objects this plan will create.
    ///
    /// Lower than `items.len()` when two files share content — that is AC-47's
    /// dedup working, not a bug, and the caller needs the distinction to report
    /// bytes-to-transfer honestly.
    pub fn distinct_objects(&self) -> usize {
        let mut keys: Vec<&str> = self.items.iter().map(|i| i.remote_key.as_str()).collect();
        keys.sort_unstable();
        keys.dedup();
        keys.len()
    }
}

/// A file the engine selected, as the caller holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelectedFile {
    pub file: FileId,
    pub path: String,
    pub size: u64,
    pub blake3: Option<Blake3Hash>,
}

/// Build a tier plan from the files a rule selected.
///
/// Takes selections as values — the engine produces them, this consumes them,
/// and neither needs to know about the other's internals.
pub fn plan_tier(selected: &[SelectedFile], destinations: &[TargetId], prefix: &str) -> TierPlan {
    let mut plan = TierPlan::default();
    for s in selected {
        let Some(hash) = s.blake3 else {
            plan.refused.push(PlanRefusal::Unhashed { file: s.file });
            continue;
        };
        if destinations.is_empty() {
            plan.refused
                .push(PlanRefusal::NoDestination { file: s.file });
            continue;
        }
        // One item per destination: a rule asking for two targets is two
        // uploads, and §4.10.2's predicate requires EVERY location the rule
        // asked for to have been reached before the original may be destroyed.
        for target in destinations {
            plan.items.push(TierItem {
                file: s.file,
                path: s.path.clone(),
                size: s.size,
                blake3: hash,
                target: *target,
                remote_key: derive_object_key(prefix, hash),
            });
        }
    }
    plan
}

#[cfg(test)]
#[path = "plan_tests.rs"]
mod tests;
