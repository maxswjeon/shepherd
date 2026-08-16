//! The hard safety floors (AC-8).
//!
//! # Two gates, one evaluator
//!
//! §4.10 draws a line this module makes explicit in its API: **"AC-8 decides
//! what is *tierable*, this decides what may be *destroyed right now*."**
//!
//! * [`FloorContext::ScanTime`] — eligibility. Answers "should this file ever
//!   be considered for tiering?"
//! * [`FloorContext::Acquisition`] — the hard gate on the irreversible path,
//!   evaluated **immediately before** the destroy path takes the file. It adds
//!   OQ-J's open-handle precondition.
//!
//! They share one function on purpose. §4.10 says all four floors —
//! open/locked, `nlink > 1`, sparse and symlink — are **mutable between the two
//! moments**, so acquisition must *re-evaluate*, not reuse a scan-time verdict.
//! Two near-identical functions would drift; one function with an explicit
//! context cannot.
//!
//! # Fail closed
//!
//! Every "cannot determine" answers *refuse*. OQ-J states it for the open-handle
//! check — **"cannot determine" is treated as "open"** — and the same posture
//! applies to a missing `st_blocks` or an unreadable stat. On this path the cost
//! of wrongly refusing is a file that stays local; the cost of wrongly allowing
//! is a file that is gone.
//!
//! # What this does not close
//!
//! The acquisition gate **narrows** the population at risk; it does not
//! eliminate the race. A handle opened between this check and the rename is
//! still possible — that is OQ-J's accepted residual, ~10–100 ms wide, tracked
//! as D-8/D-15/R-21. Nothing here should be read as closing it.

use std::path::{Path, PathBuf};
use std::time::Duration;

use shepherd_core::{FsId, Timestamp};

/// Which gate is being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FloorContext {
    /// Scan-time eligibility. Cheap; runs per catalogued file.
    ScanTime,
    /// Immediately before the destroy path acquires the file. Adds the
    /// open-handle precondition, which is far too expensive per scan row and is
    /// meaningless that far ahead of the syscall anyway.
    Acquisition,
}

/// Tunable floors. Everything else in this module is not tunable by design.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FloorPolicy {
    pub min_size: u64,
    pub min_age: Duration,
}

impl Default for FloorPolicy {
    fn default() -> Self {
        Self {
            // Below this, the catalog row and the remote object cost more than
            // the bytes reclaimed.
            min_size: 64 * 1024,
            // A file younger than this is plausibly still being written.
            min_age: Duration::from_secs(7 * 24 * 60 * 60),
        }
    }
}

/// What the caller observed. Supplied rather than gathered so this module stays
/// pure and property-testable (§8.1: "Unit — pure logic, no I/O").
///
/// `age` is **resolved by the caller**, not computed here. §4.12 makes the
/// min-age floor read `first_seen_at` where mtime is untrusted or in the
/// future, and that fallback belongs in one place — the catalog — rather than
/// being re-derived by every consumer.
#[derive(Debug, Clone)]
pub struct FloorInput {
    pub path: PathBuf,
    pub size: u64,
    pub age: Duration,
    /// Hard-link count. `> 1` means another name reaches these bytes, so
    /// destroying this one does not free them and restoring it does not restore
    /// the other name's view.
    pub nlink: u64,
    pub is_symlink: bool,
    /// `st_blocks * 512`. `None` where the platform did not report it, which
    /// fails closed rather than assuming dense.
    pub allocated_bytes: Option<u64>,
    pub fs_id: Option<FsId>,
    pub observed_at: Timestamp,
}

/// Which floor refused, and with what detail. An enum rather than a bool
/// because AC-14's dry-run preview must state *why* a file was excluded, and
/// T8's audit record wants the same string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FloorRefusal {
    BelowMinSize {
        size: u64,
        min: u64,
    },
    BelowMinAge {
        age_secs: u64,
        min_secs: u64,
    },
    /// `nlink > 1`.
    Hardlinked {
        nlink: u64,
    },
    Sparse {
        allocated: u64,
        logical: u64,
    },
    /// Symlinks are not tiered: the bytes belong to the target, and the link
    /// itself is metadata that costs nothing to keep.
    Symlink,
    /// OQ-J's precondition. Also the answer when the check could not run.
    HeldOpen {
        by: OpenEvidence,
    },
    /// A floor could not be evaluated at all.
    Undetermined {
        detail: String,
    },
}

impl FloorRefusal {
    /// Stable identifier for previews, audit records and metrics.
    pub fn code(&self) -> &'static str {
        match self {
            FloorRefusal::BelowMinSize { .. } => "below-min-size",
            FloorRefusal::BelowMinAge { .. } => "below-min-age",
            FloorRefusal::Hardlinked { .. } => "hardlinked",
            FloorRefusal::Sparse { .. } => "sparse",
            FloorRefusal::Symlink => "symlink",
            FloorRefusal::HeldOpen { .. } => "held-open",
            FloorRefusal::Undetermined { .. } => "undetermined",
        }
    }
}

/// Record a refusal against the `destroy_skipped_total{reason}` counter.
///
/// The label is [`FloorRefusal::code`] — the *same string* as the preview text
/// and the audit record, rather than three values that drift. §4.10.1 requires
/// this metric by name because "a user whose files mysteriously never tier must
/// be able to find out why", and the two refusals most likely to be invisible
/// are `held-open` on a busy machine and `sparse` on a compressing filesystem.
pub fn record_skip(registry: &shepherd_obs::Registry, refusal: &FloorRefusal) {
    registry
        .counter(&format!("destroy_skipped_total.{}", refusal.code()))
        .incr();
}

/// How the open-handle question was answered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OpenEvidence {
    /// Descriptors were found. `pids` may be empty if the scan saw a match but
    /// could not attribute it.
    Descriptors { pids: Vec<u32> },
    /// The check could not run. Treated as open (OQ-J), never as closed.
    CouldNotDetermine { detail: String },
}

/// What the verdict was based on.
///
/// Returned on **both** outcomes, and deliberately so: §4.10's revalidation
/// compares acquisition-time identity against destroy-time identity, which
/// needs the observation, not just the answer. Cheap now, awkward to retrofit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorEvidence {
    pub observed_at: Timestamp,
    pub size: u64,
    pub nlink: u64,
    pub is_symlink: bool,
    pub allocated_bytes: Option<u64>,
    pub fs_id: Option<FsId>,
    pub context: FloorContext,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    Eligible(FloorEvidence),
    Refused {
        reason: FloorRefusal,
        evidence: FloorEvidence,
    },
}

impl Verdict {
    pub fn is_eligible(&self) -> bool {
        matches!(self, Verdict::Eligible(_))
    }
    pub fn refusal(&self) -> Option<&FloorRefusal> {
        match self {
            Verdict::Refused { reason, .. } => Some(reason),
            Verdict::Eligible(_) => None,
        }
    }
    pub fn evidence(&self) -> &FloorEvidence {
        match self {
            Verdict::Eligible(e) => e,
            Verdict::Refused { evidence, .. } => evidence,
        }
    }
}

/// Slack allowed before calling a file sparse.
///
/// Filesystems round allocation up to block size, so a small dense file reports
/// *more* allocated than logical, and exact comparison would be noise. One page
/// of slack absorbs that.
///
/// **Known false positive — tracked as a risk, not only as a comment.** A
/// transparently compressing filesystem (btrfs with `compress`, ZFS with
/// `compression=on`) reports allocation below logical size for perfectly dense
/// files, so every such file is refused as sparse. Fail-closed is the right
/// direction — the file stays local — but the consequence is that **a user on a
/// compressing filesystem may find that nothing tiers at all**, with no
/// explanation unless one is surfaced.
///
/// Two things make it visible rather than mysterious: [`FloorRefusal::code`]
/// returns the stable string `"sparse"`, which is the same value used for the
/// `destroy_skipped_total{reason}` metric, the dry-run preview text and the
/// audit record; and the risk is recorded in §7 with the resolution named —
/// per-platform `FIEMAP` (Linux) / `SEEK_HOLE` to distinguish holes from
/// compression, which is real work and not a floor tweak.
const SPARSE_SLACK_BYTES: u64 = 4096;

/// Evaluate every floor for `input` under `ctx`.
///
/// Order matters only for which refusal is reported first; all of them refuse.
/// The cheap, always-available checks run before the ones that touch the system.
pub fn evaluate(policy: &FloorPolicy, input: &FloorInput, ctx: FloorContext) -> Verdict {
    let evidence = FloorEvidence {
        observed_at: input.observed_at,
        size: input.size,
        nlink: input.nlink,
        is_symlink: input.is_symlink,
        allocated_bytes: input.allocated_bytes,
        fs_id: input.fs_id.clone(),
        context: ctx,
    };
    let refuse = |reason| Verdict::Refused {
        reason,
        evidence: evidence.clone(),
    };

    if input.is_symlink {
        return refuse(FloorRefusal::Symlink);
    }
    if input.nlink > 1 {
        return refuse(FloorRefusal::Hardlinked { nlink: input.nlink });
    }
    if input.size < policy.min_size {
        return refuse(FloorRefusal::BelowMinSize {
            size: input.size,
            min: policy.min_size,
        });
    }
    if input.age < policy.min_age {
        return refuse(FloorRefusal::BelowMinAge {
            age_secs: input.age.as_secs(),
            min_secs: policy.min_age.as_secs(),
        });
    }
    match input.allocated_bytes {
        None => {
            return refuse(FloorRefusal::Undetermined {
                detail: "allocated size unavailable, cannot rule out a sparse file".into(),
            });
        }
        Some(allocated) if allocated + SPARSE_SLACK_BYTES < input.size => {
            return refuse(FloorRefusal::Sparse {
                allocated,
                logical: input.size,
            });
        }
        Some(_) => {}
    }

    if ctx == FloorContext::Acquisition {
        match open_handles(&input.path) {
            OpenCheck::None => {}
            OpenCheck::Held(by) => return refuse(FloorRefusal::HeldOpen { by }),
        }
    }

    Verdict::Eligible(evidence)
}

enum OpenCheck {
    None,
    Held(OpenEvidence),
}

/// Whether any process holds `path` open.
///
/// Linux scans `/proc/*/fd` for descriptors resolving to the same path.
/// Everything else answers `CouldNotDetermine`, which OQ-J defines as "open" —
/// so on a platform without an implementation, acquisition refuses rather than
/// proceeds. macOS needs `libproc` (`proc_pidfdinfo`) and Windows needs a
/// handle enumeration; both are Phase 3.
///
/// **Cost and honesty.** This is O(processes × descriptors) and reads a lot of
/// `/proc`. That is affordable once per acquisition and absurd per scan row,
/// which is the other reason [`FloorContext::ScanTime`] skips it. It is also
/// inherently racy: it narrows the window, and OQ-J's ~10–100 ms residual
/// (D-8, D-15, R-21) remains open behind it.
fn open_handles(path: &Path) -> OpenCheck {
    #[cfg(target_os = "linux")]
    {
        linux_open_handles(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        OpenCheck::Held(OpenEvidence::CouldNotDetermine {
            detail: format!(
                "open-handle detection is not implemented on {} (Phase 3); \
                 OQ-J requires this to be treated as held-open",
                std::env::consts::OS
            ),
        })
    }
}

#[cfg(target_os = "linux")]
fn linux_open_handles(path: &Path) -> OpenCheck {
    let Ok(target) = path.canonicalize() else {
        return OpenCheck::Held(OpenEvidence::CouldNotDetermine {
            detail: format!("cannot canonicalize {}", path.display()),
        });
    };
    let Ok(procs) = std::fs::read_dir("/proc") else {
        return OpenCheck::Held(OpenEvidence::CouldNotDetermine {
            detail: "cannot read /proc".into(),
        });
    };

    let mut pids = Vec::new();
    for entry in procs.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        // A process that exits mid-scan is not evidence of anything, so an
        // unreadable fd directory is skipped rather than failing the whole
        // check closed. Permission-denied on another user's process is the
        // common case here and would otherwise make every acquisition refuse.
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path()).is_ok_and(|l| l == target) {
                pids.push(pid);
                break;
            }
        }
    }

    if pids.is_empty() {
        OpenCheck::None
    } else {
        OpenCheck::Held(OpenEvidence::Descriptors { pids })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> FloorInput {
        FloorInput {
            path: PathBuf::from("/data/big.raw"),
            size: 10 * 1024 * 1024,
            age: Duration::from_secs(30 * 24 * 60 * 60),
            nlink: 1,
            is_symlink: false,
            allocated_bytes: Some(10 * 1024 * 1024),
            fs_id: None,
            observed_at: Timestamp::from_nanos(1),
        }
    }

    fn scan(i: &FloorInput) -> Verdict {
        evaluate(&FloorPolicy::default(), i, FloorContext::ScanTime)
    }

    #[test]
    fn a_plain_large_old_file_is_eligible() {
        assert!(scan(&base()).is_eligible());
    }

    #[test]
    fn below_min_size_is_refused() {
        let mut i = base();
        i.size = 1024;
        i.allocated_bytes = Some(4096);
        let v = scan(&i);
        assert_eq!(v.refusal().unwrap().code(), "below-min-size");
    }

    #[test]
    fn below_min_age_is_refused() {
        let mut i = base();
        i.age = Duration::from_secs(60);
        assert_eq!(scan(&i).refusal().unwrap().code(), "below-min-age");
    }

    /// `nlink > 1` means another name reaches the same bytes: destroying this
    /// name frees nothing and restoring it does not restore the other view.
    #[test]
    fn hardlinked_files_are_refused() {
        let mut i = base();
        i.nlink = 2;
        assert_eq!(
            scan(&i).refusal().unwrap(),
            &FloorRefusal::Hardlinked { nlink: 2 }
        );
    }

    #[test]
    fn symlinks_are_refused() {
        let mut i = base();
        i.is_symlink = true;
        assert_eq!(scan(&i).refusal().unwrap(), &FloorRefusal::Symlink);
    }

    #[test]
    fn sparse_files_are_refused() {
        let mut i = base();
        i.allocated_bytes = Some(4096); // 10 MB logical, one page allocated
        assert_eq!(scan(&i).refusal().unwrap().code(), "sparse");
    }

    /// Block rounding must not make every small dense file look sparse.
    #[test]
    fn block_rounding_slack_does_not_misfire() {
        let mut i = base();
        i.size = 100 * 1024;
        i.allocated_bytes = Some(100 * 1024); // exactly dense
        assert!(scan(&i).is_eligible());
        // One page short, i.e. within slack.
        i.allocated_bytes = Some(100 * 1024 - 4000);
        assert!(scan(&i).is_eligible());
    }

    /// Fail closed: an unknown allocation cannot rule out holes.
    #[test]
    fn unknown_allocation_is_refused_not_assumed_dense() {
        let mut i = base();
        i.allocated_bytes = None;
        assert_eq!(scan(&i).refusal().unwrap().code(), "undetermined");
    }

    /// A real file this process holds a descriptor to, so the open-handle
    /// check has something true to find. `/proc/self/exe` was tried first and
    /// does NOT work — an executing binary is mapped, not necessarily held as
    /// an open descriptor, so the scan finds nothing and the test passes for
    /// the wrong reason.
    #[cfg(target_os = "linux")]
    struct HeldOpen {
        dir: PathBuf,
        path: PathBuf,
        _handle: std::fs::File,
    }

    #[cfg(target_os = "linux")]
    impl HeldOpen {
        fn new(tag: &str) -> Self {
            let dir =
                std::env::temp_dir().join(format!("shepherd-floor-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("held.bin");
            std::fs::write(&path, vec![0u8; 1024]).unwrap();
            let handle = std::fs::File::open(&path).unwrap();
            Self {
                dir,
                path,
                _handle: handle,
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for HeldOpen {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    /// Scan-time does not run the open-handle check — it is far too expensive
    /// per row, and meaningless that far ahead of the syscall.
    #[cfg(target_os = "linux")]
    #[test]
    fn scan_time_does_not_consult_open_handles() {
        let held = HeldOpen::new("scan");
        let mut i = base();
        i.path = held.path.clone();
        assert!(
            scan(&i).is_eligible(),
            "ScanTime must not pay for, or depend on, the open-handle scan"
        );
    }

    /// The evidence is returned on BOTH outcomes, because §4.10's revalidation
    /// compares acquisition-time identity against destroy-time identity.
    #[test]
    fn evidence_is_returned_on_refusal_too() {
        let mut i = base();
        i.nlink = 3;
        let v = scan(&i);
        assert!(!v.is_eligible());
        assert_eq!(v.evidence().nlink, 3);
        assert_eq!(v.evidence().context, FloorContext::ScanTime);
        assert_eq!(v.evidence().observed_at, Timestamp::from_nanos(1));
    }

    /// The same input can be eligible at scan time and refused at acquisition.
    /// That asymmetry IS the point: §4.10 requires re-validation because every
    /// floor is mutable between the two moments, and OQ-J's open-handle
    /// precondition exists only on the irreversible path.
    #[cfg(target_os = "linux")]
    #[test]
    fn acquisition_is_a_second_gate_not_a_cached_verdict() {
        let held = HeldOpen::new("acq");
        let mut i = base();
        i.path = held.path.clone();
        assert!(scan(&i).is_eligible(), "eligible as a tiering candidate…");

        let v = evaluate(&FloorPolicy::default(), &i, FloorContext::Acquisition);
        assert!(
            !v.is_eligible(),
            "…and refused for destruction right now, because this process holds \
             it open"
        );
        assert_eq!(v.refusal().unwrap().code(), "held-open");
        assert_eq!(v.evidence().context, FloorContext::Acquisition);

        match v.refusal().unwrap() {
            FloorRefusal::HeldOpen {
                by: OpenEvidence::Descriptors { pids },
            } => assert!(
                pids.contains(&std::process::id()),
                "the holder should be attributed to this process: {pids:?}"
            ),
            other => panic!("expected descriptor evidence, got {other:?}"),
        }
    }

    /// A file nobody holds open passes the acquisition gate. Without this, the
    /// test above would also pass if `open_handles` simply always refused.
    #[cfg(target_os = "linux")]
    #[test]
    fn acquisition_allows_a_file_no_one_holds_open() {
        let held = HeldOpen::new("free");
        let free = held.dir.join("free.bin");
        std::fs::write(&free, vec![0u8; 1024]).unwrap();
        let mut i = base();
        i.path = free;
        let v = evaluate(&FloorPolicy::default(), &i, FloorContext::Acquisition);
        assert!(
            v.is_eligible(),
            "the gate must discriminate, not blanket-refuse: {:?}",
            v.refusal()
        );
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn platforms_without_detection_refuse_rather_than_allow() {
        let v = evaluate(&FloorPolicy::default(), &base(), FloorContext::Acquisition);
        assert_eq!(
            v.refusal().unwrap().code(),
            "held-open",
            "OQ-J: cannot-determine is treated as open"
        );
    }

    #[test]
    fn refusal_codes_are_stable_strings() {
        // These appear in previews, audit records and metrics; renaming one is
        // a user-visible change, not a refactor.
        for (r, code) in [
            (FloorRefusal::Symlink, "symlink"),
            (FloorRefusal::Hardlinked { nlink: 2 }, "hardlinked"),
            (
                FloorRefusal::Sparse {
                    allocated: 0,
                    logical: 1,
                },
                "sparse",
            ),
        ] {
            assert_eq!(r.code(), code);
        }
    }
}

#[cfg(test)]
mod metric_tests {
    use super::*;

    /// The metric label and the refusal code are ONE string, not two that
    /// drift. §4.10.1 requires `destroy_skipped_total{reason}` by name so a
    /// user whose corpus never tiers can find out why.
    #[test]
    fn skips_are_counted_under_their_refusal_code() {
        let r = shepherd_obs::Registry::new();
        record_skip(
            &r,
            &FloorRefusal::Sparse {
                allocated: 4096,
                logical: 1 << 30,
            },
        );
        record_skip(&r, &FloorRefusal::Symlink);
        record_skip(&r, &FloorRefusal::Symlink);

        let s = r.snapshot();
        assert_eq!(s.counters.get("destroy_skipped_total.sparse"), Some(&1));
        assert_eq!(s.counters.get("destroy_skipped_total.symlink"), Some(&2));
    }

    /// A compressing filesystem is the case most likely to be invisible: dense
    /// files refused as sparse, and nothing tiers. The counter is what makes it
    /// diagnosable rather than mysterious.
    #[test]
    fn a_compressing_filesystem_shows_up_as_sparse_skips() {
        let r = shepherd_obs::Registry::new();
        let mut i = FloorInput {
            path: PathBuf::from("/data/dense-but-compressed.bin"),
            size: 10 * 1024 * 1024,
            age: Duration::from_secs(1 << 24),
            nlink: 1,
            is_symlink: false,
            // btrfs with compress: dense content, half the allocation.
            allocated_bytes: Some(5 * 1024 * 1024),
            fs_id: None,
            observed_at: Timestamp::from_nanos(1),
        };
        for _ in 0..3 {
            let v = evaluate(&FloorPolicy::default(), &i, FloorContext::ScanTime);
            record_skip(&r, v.refusal().expect("refused as sparse"));
            i.size += 1;
        }
        assert_eq!(
            r.snapshot().counters.get("destroy_skipped_total.sparse"),
            Some(&3)
        );
    }
}
