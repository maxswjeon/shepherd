//! §4.9 — identity and naming semantics.
//!
//! Every guard in §4.10 protects the *moment* of destruction. This module
//! protects what the **names** mean, and it exists because a destroy can be
//! individually correct at every step and still lose data when two different
//! files resolve to one identity. §4.9 is blunt about the consequence: **no
//! runtime predicate can catch these**, so they are design-time decisions.
//!
//! The failure it prevents, concretely. ext4 holds `Report.txt` and `report.txt`
//! as two distinct files; an SMB or OneDrive target folds them to one object. If
//! keys derived from paths: file A tiers, verifies, and is destroyed locally.
//! File B later tiers to the **same key**, silently overwriting A's object — and
//! B's verify honestly passes, against B's own bytes. **A is now gone
//! everywhere, and A's destroy was correct when it happened.**
//!
//! Retrofitting this after Phase 2 destroys files is exactly the scenario §4.9
//! exists to prevent, which is why it lands here in Phase 1 rather than beside
//! the code that would have needed it.

use std::path::Path;

use serde::{Deserialize, Serialize};
use shepherd_core::{Blake3Hash, ObjectKey};
use unicode_normalization::UnicodeNormalization;

// ---------------------------------------------------------------------------
// Remote key derivation
// ---------------------------------------------------------------------------

/// Derive the remote object key for content with hash `hash`.
///
/// ```text
/// <prefix>/objects/<blake3[0:2]>/<blake3[2:4]>/<blake3>
/// ```
///
/// **The path is not an input, and cannot become one.** This function takes a
/// hash, not a file: content-addressing makes collision *impossible rather than
/// unlikely*, and gives hash-dedup (AC-47) for free — two files with identical
/// content legitimately share one object, with the location set tracking both
/// referents and a refcount so destroying one file never removes an object
/// another still needs.
///
/// The two fan-out levels exist because providers degrade on flat prefixes with
/// millions of keys; they are derived from the hash, so they add no identity.
pub fn content_key(prefix: &str, hash: Blake3Hash) -> ObjectKey {
    let hex = hash.to_hex();
    let prefix = prefix.trim_end_matches('/');
    ObjectKey::new(format!(
        "{prefix}/objects/{}/{}/{hex}",
        &hex[0..2],
        &hex[2..4]
    ))
}

/// The catalog-ID-addressed alternative, for providers that require a
/// human-navigable layout (§4.9).
///
/// Still never path-derived: `file_id` is a catalog identity, and the hash keeps
/// the leaf unique across content changes at the same id.
pub fn id_key(prefix: &str, file_id: i64, hash: Blake3Hash) -> ObjectKey {
    let prefix = prefix.trim_end_matches('/');
    ObjectKey::new(format!("{prefix}/objects/{file_id}/{}", hash.to_hex()))
}

// ---------------------------------------------------------------------------
// Per-root path policy
// ---------------------------------------------------------------------------

/// Whether the root's filesystem distinguishes `Report.txt` from `report.txt`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathCasePolicy {
    Sensitive,
    Insensitive,
}

/// What the root's filesystem does to Unicode composition.
///
/// macOS emits NFD; Linux preserves the bytes it was given; SMB varies by
/// server. §4.9 requires this to be **probed, not assumed**.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PathNormPolicy {
    Nfc,
    Nfd,
    Preserve,
}

impl PathCasePolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            PathCasePolicy::Sensitive => "sensitive",
            PathCasePolicy::Insensitive => "insensitive",
        }
    }
}

impl PathNormPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            PathNormPolicy::Nfc => "nfc",
            PathNormPolicy::Nfd => "nfd",
            PathNormPolicy::Preserve => "preserve",
        }
    }
}

/// The key watcher events match against.
///
/// A catalog lookup on `(root_id, rel_path)` against an event delivered in a
/// different normalization returns **false absence** — and PM-3 shows false
/// absence is discard-trigger territory. `norm_key` is what closes that.
///
/// Case folding uses `str::to_lowercase`, which is Unicode's full lowercase
/// mapping. That is an **approximation** of any given server's folding table:
/// SMB servers fold per an internal uppercase table that is not exactly
/// Unicode's, and Windows folds per-codepage for some legacy ranges. The
/// approximation is acceptable precisely because it is not load-bearing on its
/// own — the enrollment probe is ground truth for *whether* a root folds, and a
/// `norm_key` collision between two genuinely distinct files still leaves them
/// as two rows with two distinct `rel_path`s and two distinct content keys.
pub fn norm_key(rel_path: &str, case: PathCasePolicy, norm: PathNormPolicy) -> String {
    let normalized: String = match norm {
        PathNormPolicy::Nfc => rel_path.nfc().collect(),
        PathNormPolicy::Nfd => rel_path.nfd().collect(),
        PathNormPolicy::Preserve => rel_path.to_string(),
    };
    // Separators are unified so a Windows-authored `a\b.txt` and a
    // Linux-authored `a/b.txt` under the same root do not read as two files.
    let unified = normalized.replace('\\', "/");
    match case {
        PathCasePolicy::Sensitive => unified,
        PathCasePolicy::Insensitive => unified.to_lowercase(),
    }
}

/// Result of probing a root at enrollment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PathPolicies {
    pub case: PathCasePolicy,
    pub norm: PathNormPolicy,
    /// `true` when the probe could not run (read-only root, permission denied)
    /// and platform defaults were assumed instead.
    pub assumed: bool,
}

/// Probe a root's case and normalization behaviour by creating throwaway files.
///
/// §4.9 requires probing rather than assuming. The probe writes two dotfiles
/// with deliberately awkward names and observes what comes back:
///
/// * **case** — write `.shepherd-probe-CASE`, then test whether
///   `.shepherd-probe-case` resolves to it.
/// * **normalization** — write a name containing `é` as NFC (`U+00E9`), then
///   read the directory back and see which form the filesystem reports.
///
/// Both probe files are removed on every exit path, including the error ones.
///
/// On a read-only root the probe cannot run. It then returns platform defaults
/// with `assumed: true` rather than failing enrollment — a root you can only
/// read is still a root worth cataloguing, and the caller records the
/// distinction. It never silently reports a probed result it did not obtain.
pub fn probe_path_policies(root: &Path) -> PathPolicies {
    let probe = ProbeFiles::new(root);
    let case = probe.case().unwrap_or_else(platform_default_case);
    let norm = probe.norm().unwrap_or_else(platform_default_norm);
    PathPolicies {
        case,
        norm,
        assumed: probe.failed(),
    }
}

fn platform_default_case() -> PathCasePolicy {
    if cfg!(target_os = "linux") {
        PathCasePolicy::Sensitive
    } else {
        // Windows is case-insensitive; macOS APFS defaults to insensitive
        // (case-preserving). Assuming insensitive is the safe direction: it
        // folds more paths together, so two files that ARE distinct get two
        // rows anyway via rel_path, whereas wrongly assuming sensitive would
        // let a genuine fold go unnoticed.
        PathCasePolicy::Insensitive
    }
}

fn platform_default_norm() -> PathNormPolicy {
    if cfg!(target_os = "macos") {
        PathNormPolicy::Nfd
    } else {
        PathNormPolicy::Preserve
    }
}

/// RAII holder for the probe files, so no path returns without cleaning up.
struct ProbeFiles {
    upper: Option<std::path::PathBuf>,
    nfc: Option<std::path::PathBuf>,
    root: std::path::PathBuf,
    failed: bool,
}

/// `é` as a single precomposed codepoint (NFC).
const NFC_E_ACUTE: &str = "\u{00e9}";

impl ProbeFiles {
    fn new(root: &Path) -> Self {
        let upper = root.join(".shepherd-probe-CASE");
        let nfc = root.join(format!(".shepherd-probe-{NFC_E_ACUTE}"));
        let mut failed = false;
        let upper = match std::fs::write(&upper, b"") {
            Ok(()) => Some(upper),
            Err(_) => {
                failed = true;
                None
            }
        };
        let nfc = match std::fs::write(&nfc, b"") {
            Ok(()) => Some(nfc),
            Err(_) => {
                failed = true;
                None
            }
        };
        Self {
            upper,
            nfc,
            root: root.to_path_buf(),
            failed,
        }
    }

    fn failed(&self) -> bool {
        self.failed
    }

    fn case(&self) -> Option<PathCasePolicy> {
        self.upper.as_ref()?;
        let lower = self.root.join(".shepherd-probe-case");
        Some(if lower.exists() {
            PathCasePolicy::Insensitive
        } else {
            PathCasePolicy::Sensitive
        })
    }

    fn norm(&self) -> Option<PathNormPolicy> {
        self.nfc.as_ref()?;
        let entries = std::fs::read_dir(&self.root).ok()?;
        for e in entries.flatten() {
            let name = e.file_name();
            let name = name.to_string_lossy();
            if !name.starts_with(".shepherd-probe-") || name.contains("CASE") {
                continue;
            }
            let tail = &name[".shepherd-probe-".len()..];
            let nfc: String = tail.nfc().collect();
            let nfd: String = tail.nfd().collect();
            // Reported in decomposed form though it was written composed: the
            // filesystem normalises to NFD.
            if tail == nfd && tail != nfc {
                return Some(PathNormPolicy::Nfd);
            }
            if tail == NFC_E_ACUTE {
                // Came back exactly as written. That is "preserve", not "nfc":
                // the filesystem did nothing, which is a different property from
                // actively composing.
                return Some(PathNormPolicy::Preserve);
            }
            return Some(PathNormPolicy::Nfc);
        }
        None
    }
}

impl Drop for ProbeFiles {
    fn drop(&mut self) {
        for p in [self.upper.take(), self.nfc.take()].into_iter().flatten() {
            let _ = std::fs::remove_file(p);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §4.9 collision test. Two files whose paths differ only in case get
    /// the SAME key when their content is identical, and DIFFERENT keys when
    /// their content differs — because the path is not an input at all.
    #[test]
    fn path_never_enters_the_key() {
        let a = Blake3Hash::from_bytes([0xAB; 32]);
        let b = Blake3Hash::from_bytes([0xCD; 32]);
        // `Report.txt` and `report.txt`, same bytes -> one object, by design.
        assert_eq!(content_key("t", a), content_key("t", a));
        // Different bytes -> different objects, whatever the paths were.
        assert_ne!(content_key("t", a), content_key("t", b));
    }

    #[test]
    fn key_layout_fans_out_on_the_hash() {
        let h = Blake3Hash::from_hex(&"ab".repeat(32)).unwrap();
        let k = content_key("shepherd", h);
        assert_eq!(
            k.as_str(),
            format!("shepherd/objects/ab/ab/{}", "ab".repeat(32))
        );
        assert!(!k.is_control_object());
    }

    #[test]
    fn trailing_slash_in_prefix_does_not_double() {
        let h = Blake3Hash::from_bytes([1; 32]);
        assert_eq!(content_key("p/", h).as_str(), content_key("p", h).as_str());
    }

    /// NFC and NFD spellings of the same name must produce ONE norm_key under
    /// an nfc-normalizing root, or a macOS watcher event never matches the row
    /// a Linux scan wrote — false absence, which PM-3 calls discard-trigger
    /// territory.
    #[test]
    fn nfd_and_nfc_fold_to_one_norm_key() {
        let nfc = "caf\u{00e9}/notes.txt"; // é precomposed
        let nfd = "cafe\u{0301}/notes.txt"; // e + combining acute
        assert_ne!(nfc, nfd, "the two spellings differ as bytes");
        let a = norm_key(nfc, PathCasePolicy::Sensitive, PathNormPolicy::Nfc);
        let b = norm_key(nfd, PathCasePolicy::Sensitive, PathNormPolicy::Nfc);
        assert_eq!(a, b);
        // Same under NFD normalization — either target form works, so long as
        // both spellings land on it.
        let a = norm_key(nfc, PathCasePolicy::Sensitive, PathNormPolicy::Nfd);
        let b = norm_key(nfd, PathCasePolicy::Sensitive, PathNormPolicy::Nfd);
        assert_eq!(a, b);
    }

    /// `preserve` deliberately does NOT fold them. A root that preserves bytes
    /// has two distinct names, and pretending otherwise would merge two files.
    #[test]
    fn preserve_keeps_the_two_spellings_apart() {
        let nfc = "caf\u{00e9}.txt";
        let nfd = "cafe\u{0301}.txt";
        assert_ne!(
            norm_key(nfc, PathCasePolicy::Sensitive, PathNormPolicy::Preserve),
            norm_key(nfd, PathCasePolicy::Sensitive, PathNormPolicy::Preserve)
        );
    }

    #[test]
    fn case_folding_follows_the_root_policy() {
        let (a, b) = ("Dir/Report.TXT", "dir/report.txt");
        assert_ne!(
            norm_key(a, PathCasePolicy::Sensitive, PathNormPolicy::Preserve),
            norm_key(b, PathCasePolicy::Sensitive, PathNormPolicy::Preserve),
            "a case-sensitive root keeps them apart"
        );
        assert_eq!(
            norm_key(a, PathCasePolicy::Insensitive, PathNormPolicy::Preserve),
            norm_key(b, PathCasePolicy::Insensitive, PathNormPolicy::Preserve),
            "an insensitive root folds them, which is what SMB/OneDrive do"
        );
    }

    #[test]
    fn separators_are_unified() {
        assert_eq!(
            norm_key(
                "a\\b.txt",
                PathCasePolicy::Sensitive,
                PathNormPolicy::Preserve
            ),
            norm_key(
                "a/b.txt",
                PathCasePolicy::Sensitive,
                PathNormPolicy::Preserve
            )
        );
    }

    #[test]
    fn probe_detects_this_filesystem_and_cleans_up_after_itself() {
        let dir = std::env::temp_dir().join(format!("shepherd-probe-t-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = probe_path_policies(&dir);
        assert!(!p.assumed, "probe should have run in a writable temp dir");
        // Every probe file is gone, so enrollment does not leave litter in a
        // user's scan root.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().to_string())
            .collect();
        assert!(
            leftovers.is_empty(),
            "probe left files behind: {leftovers:?}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn probe_on_a_missing_root_assumes_rather_than_failing() {
        let missing = std::env::temp_dir().join("shepherd-probe-does-not-exist-xyz");
        std::fs::remove_dir_all(&missing).ok();
        let p = probe_path_policies(&missing);
        assert!(p.assumed, "an unprobeable root must report `assumed`");
    }
}
