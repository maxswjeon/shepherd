//! §4.12 — `atime` fidelity detection, per root.
//!
//! # Why this is safety work, not rules polish
//!
//! On a volume where last-access updates are disabled, `atime` never advances.
//! So a rule like *"not accessed in 1 year"* does not merely under-match — it
//! eventually matches **everything**, including files in daily use. That is a
//! mass-tiering trigger, and on a `discard` policy a mass-destruction one.
//!
//! Last-access time is unreliable by default on two of three platforms: Linux
//! mounts default to `relatime` and permit `noatime`/`lazytime`; Windows has
//! disabled last-access updates by default since Vista; macOS can suppress or
//! defer them. Shepherd's own hash and extraction reads can also refresh the
//! signal, tainting it.
//!
//! The response is three-part, and only the first part lives here:
//!
//! 1. **detect fidelity per volume** — this module, recorded in
//!    `scan_root.atime_mode`;
//! 2. maintain `file.last_observed_access`, a Shepherd-owned signal fed by
//!    hydrations, restores and served opens — the column exists in the schema,
//!    the feeding is Phase 3/4 work;
//! 3. fall back `last_observed_access` → `atime` (only where `reliable`) →
//!    `mtime`, recording which actually drove each match in
//!    `file.access_signal_src` — the rule engine's job, Phase 2.
//!
//! §4.12 also requires that a **destructive rule relying solely on
//! disabled/unknown atime is rejected**, not merely warned about. That
//! predicate is the rules engine's; [`AtimeMode::supports_destructive_age_rule`]
//! is where the decision is written down so both sides agree on it.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// Fidelity of the OS last-access signal on one volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AtimeMode {
    /// Updates on every access. `strictatime`, or a probe that observed a real
    /// advance.
    Reliable,
    /// Updates only when the previous atime is older than mtime/ctime or older
    /// than a day. Usable as a coarse signal, useless as a precise one.
    Relatime,
    /// Never updates. `noatime`, or Windows with `NtfsDisableLastAccessUpdate`.
    Disabled,
    /// Not determined. Treated exactly as `Disabled` for safety decisions.
    Unknown,
}

impl AtimeMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AtimeMode::Reliable => "reliable",
            AtimeMode::Relatime => "relatime",
            AtimeMode::Disabled => "disabled",
            AtimeMode::Unknown => "unknown",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "reliable" => AtimeMode::Reliable,
            "relatime" => AtimeMode::Relatime,
            "disabled" => AtimeMode::Disabled,
            "unknown" => AtimeMode::Unknown,
            _ => return None,
        })
    }

    /// Whether OS `atime` may be folded into `last_observed_access` at all.
    ///
    /// §4.12: "OS atime deltas are folded in **only** where fidelity is
    /// `reliable`."
    pub fn may_fold_into_observed_access(self) -> bool {
        matches!(self, AtimeMode::Reliable)
    }

    /// Whether a **destructive** rule may rest solely on an `atime` predicate.
    ///
    /// §4.12 rule 4: a destructive rule relying solely on disabled or unknown
    /// atime is **rejected**, not warned about. `Relatime` is permitted but the
    /// dry-run preview must state which signal actually drove each match.
    ///
    /// `Unknown` is grouped with `Disabled` deliberately: "we could not tell"
    /// and "it never updates" have the same consequence for a rule that would
    /// otherwise match every file on the volume.
    pub fn supports_destructive_age_rule(self) -> bool {
        matches!(self, AtimeMode::Reliable | AtimeMode::Relatime)
    }
}

/// Classify a volume from its mount option string.
///
/// Pure, so it is testable on fixture strings rather than on whatever the test
/// machine happens to have mounted. The precedence follows the kernel's: an
/// explicit `noatime` wins over everything, `strictatime` means genuinely every
/// access, and Linux's default when nothing is said is `relatime`.
///
/// `lazytime` is not an atime policy — it defers *writeback* of timestamps, not
/// their update — so it is transparent here and deliberately ignored.
pub fn classify_mount_options(options: &str) -> AtimeMode {
    let mut opts = options.split(',').map(str::trim);
    // `nodiratime` only suppresses directory atime, so it does not disqualify
    // file atime and is not consulted.
    if opts.clone().any(|o| o == "noatime") {
        return AtimeMode::Disabled;
    }
    if opts.clone().any(|o| o == "strictatime") {
        return AtimeMode::Reliable;
    }
    if opts.any(|o| o == "relatime") {
        return AtimeMode::Relatime;
    }
    // Linux mounts default to relatime when no atime option is present.
    AtimeMode::Relatime
}

/// Detect the atime fidelity of the volume containing `path`.
///
/// Linux reads `/proc/self/mountinfo` and classifies both the per-mount and the
/// per-superblock option strings, taking the stricter of the two — a bind mount
/// can carry `relatime` while its superblock carries `noatime`, and the
/// filesystem wins.
///
/// Windows and macOS return [`AtimeMode::Unknown`] today, and `Unknown` is
/// treated as `Disabled` by every safety predicate above. §4.12 requires macOS
/// to be **verified by probe rather than assumed** and Windows to read
/// `NtfsDisableLastAccessUpdate`; both are Phase 3, and reporting `Unknown`
/// until then is the honest state rather than a guess that would silently
/// authorise destructive age rules.
pub fn detect(path: &Path) -> AtimeMode {
    #[cfg(target_os = "linux")]
    {
        detect_linux(path).unwrap_or(AtimeMode::Unknown)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        AtimeMode::Unknown
    }
}

#[cfg(target_os = "linux")]
fn detect_linux(path: &Path) -> Option<AtimeMode> {
    let canonical = path.canonicalize().ok()?;
    let text = std::fs::read_to_string("/proc/self/mountinfo").ok()?;
    let (options, super_options) =
        crate::volume::linux_mountinfo(&text, &canonical.to_string_lossy())?;
    Some(stricter(
        classify_mount_options(&options),
        classify_mount_options(&super_options),
    ))
}

/// The more conservative of two classifications.
///
/// Used because a bind mount and its superblock can disagree, and believing the
/// laxer one is how a `noatime` filesystem gets treated as `reliable`.
pub fn stricter(a: AtimeMode, b: AtimeMode) -> AtimeMode {
    let rank = |m: AtimeMode| match m {
        AtimeMode::Disabled => 0,
        AtimeMode::Unknown => 1,
        AtimeMode::Relatime => 2,
        AtimeMode::Reliable => 3,
    };
    if rank(a) <= rank(b) { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_noatime_disables() {
        assert_eq!(
            classify_mount_options("rw,noatime,nodev"),
            AtimeMode::Disabled
        );
        // `noatime` wins even when relatime is also listed.
        assert_eq!(
            classify_mount_options("rw,relatime,noatime"),
            AtimeMode::Disabled
        );
    }

    #[test]
    fn strictatime_is_the_only_reliable_option() {
        assert_eq!(
            classify_mount_options("rw,strictatime"),
            AtimeMode::Reliable
        );
    }

    #[test]
    fn relatime_is_explicit_or_the_default() {
        assert_eq!(classify_mount_options("rw,relatime"), AtimeMode::Relatime);
        assert_eq!(
            classify_mount_options("rw,errors=remount-ro"),
            AtimeMode::Relatime,
            "Linux defaults to relatime when nothing is said"
        );
    }

    #[test]
    fn lazytime_and_nodiratime_do_not_change_file_atime_fidelity() {
        // lazytime defers writeback, it does not stop the update.
        assert_eq!(classify_mount_options("rw,lazytime"), AtimeMode::Relatime);
        // nodiratime suppresses only directory atime.
        assert_eq!(
            classify_mount_options("rw,nodiratime,strictatime"),
            AtimeMode::Reliable
        );
    }

    #[test]
    fn a_substring_is_not_an_option() {
        // "norelatime" is not an option, and must not be read as "relatime".
        // Splitting on ',' rather than substring-searching is what makes this
        // hold; the check-deps rule-4 work taught the same lesson.
        assert_eq!(
            classify_mount_options("rw,strictatime,some_noatime_lookalike"),
            AtimeMode::Reliable
        );
    }

    #[test]
    fn the_stricter_classification_wins_when_mount_and_superblock_disagree() {
        assert_eq!(
            stricter(AtimeMode::Relatime, AtimeMode::Disabled),
            AtimeMode::Disabled
        );
        assert_eq!(
            stricter(AtimeMode::Reliable, AtimeMode::Relatime),
            AtimeMode::Relatime
        );
        assert_eq!(
            stricter(AtimeMode::Unknown, AtimeMode::Reliable),
            AtimeMode::Unknown
        );
    }

    /// The §4.12 rule-4 predicate. `unknown` must behave exactly like
    /// `disabled`: both mean a year-old-atime rule could match everything.
    #[test]
    fn destructive_age_rules_are_rejected_on_disabled_and_unknown() {
        assert!(AtimeMode::Reliable.supports_destructive_age_rule());
        assert!(AtimeMode::Relatime.supports_destructive_age_rule());
        assert!(!AtimeMode::Disabled.supports_destructive_age_rule());
        assert!(
            !AtimeMode::Unknown.supports_destructive_age_rule(),
            "'could not tell' and 'never updates' have the same consequence"
        );
    }

    #[test]
    fn only_reliable_atime_may_feed_the_observed_access_signal() {
        assert!(AtimeMode::Reliable.may_fold_into_observed_access());
        for m in [AtimeMode::Relatime, AtimeMode::Disabled, AtimeMode::Unknown] {
            assert!(!m.may_fold_into_observed_access(), "{m:?}");
        }
    }

    #[test]
    fn string_forms_round_trip_with_the_schema_check_constraint() {
        for m in [
            AtimeMode::Reliable,
            AtimeMode::Relatime,
            AtimeMode::Disabled,
            AtimeMode::Unknown,
        ] {
            assert_eq!(AtimeMode::parse(m.as_str()), Some(m));
        }
        assert_eq!(AtimeMode::parse("nonsense"), None);
    }
}
