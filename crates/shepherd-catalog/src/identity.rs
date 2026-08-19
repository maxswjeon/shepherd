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
    let normalized = apply_norm(rel_path, norm);
    // Separators are unified so a Windows-authored `a\b.txt` and a
    // Linux-authored `a/b.txt` under the same root do not read as two files.
    let unified = normalized.replace('\\', "/");
    match case {
        PathCasePolicy::Sensitive => unified,
        // NORMALISED AGAIN AFTER FOLDING, and that second pass is load-bearing.
        //
        // `to_lowercase` is not closed over a normalisation form: it can emit a
        // sequence that was not composable before folding and is afterwards. The
        // corpus in `proptests` found the case — `ᾼ` (U+1FBC) followed by a
        // combining grave normalises to `Ὰ` + U+0345, whose lowercase is
        // `ὰ` + U+0345, and THAT composes to `ᾲ` (U+1FB2).
        //
        // Normalising only before the fold therefore let two spellings of one
        // case-folded name produce two different keys: a root holding `Ὰ`+U+0345
        // and one holding the precomposed `ᾲ` are the same file to a
        // case-insensitive filesystem, and got two catalog identities. That is
        // precisely the **false absence** this function exists to close, and
        // PM-3 calls false absence discard-trigger territory.
        //
        // It also made `norm_key` non-idempotent, so a key re-derived from a
        // stored key stopped matching itself.
        PathCasePolicy::Insensitive => apply_norm(&unified.to_lowercase(), norm),
    }
}

/// The normalisation half of [`norm_key`], applied both before and after case
/// folding. `Preserve` is deliberately the identity: a root that preserves
/// bytes must not have composition forced on it by the second pass either.
fn apply_norm(s: &str, norm: PathNormPolicy) -> String {
    match norm {
        PathNormPolicy::Nfc => s.nfc().collect(),
        PathNormPolicy::Nfd => s.nfd().collect(),
        PathNormPolicy::Preserve => s.to_string(),
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

    /// REGRESSION, found by the `proptests` corpus and not by any example.
    ///
    /// `norm_key` normalised only BEFORE folding case. `to_lowercase` is not
    /// closed over a normalisation form, so folding could produce a sequence
    /// that composes further — and two spellings of one case-folded name then
    /// got two different keys.
    ///
    /// Pinned as an explicit example as well as a law because the corpus draws
    /// from a seeded RNG: a future change to the generator could stop producing
    /// this shape, and the defect would silently lose its guard.
    #[test]
    fn folding_can_compose_further_and_must_not_split_one_name() {
        // The same name on a case-insensitive, NFC-normalising root: once
        // spelled with the capital and a separate ypogegrammeni, once as the
        // precomposed lowercase character.
        let upper = "\u{1FBA}\u{0345}"; // Ὰ + combining ypogegrammeni
        let lower = "\u{1FB2}"; // ᾲ  precomposed
        assert_ne!(upper, lower, "the two spellings differ as bytes");
        assert_eq!(
            norm_key(upper, PathCasePolicy::Insensitive, PathNormPolicy::Nfc),
            norm_key(lower, PathCasePolicy::Insensitive, PathNormPolicy::Nfc),
            "one case-folded name must not acquire two catalog identities"
        );
    }

    /// The idempotence half of the same defect: a key re-derived from a stored
    /// key must equal it, or any re-index or migration silently stops matching.
    #[test]
    fn a_norm_key_is_stable_when_derived_from_itself() {
        let s = "\u{1FBC}\u{0300}"; // ᾼ + combining grave — the shrunk input
        let once = norm_key(s, PathCasePolicy::Insensitive, PathNormPolicy::Nfc);
        let twice = norm_key(&once, PathCasePolicy::Insensitive, PathNormPolicy::Nfc);
        assert_eq!(once, twice, "norm_key must be a fixed point of itself");
    }

    #[test]
    fn probe_on_a_missing_root_assumes_rather_than_failing() {
        let missing = std::env::temp_dir().join("shepherd-probe-does-not-exist-xyz");
        std::fs::remove_dir_all(&missing).ok();
        let p = probe_path_policies(&missing);
        assert!(p.assumed, "an unprobeable root must report `assumed`");
    }
}

// ---------------------------------------------------------------------------
// §9's `case/normalization fuzz corpus`
// ---------------------------------------------------------------------------

/// Generated-input laws for §4.9 identity.
///
/// # Why this module is separate from `tests`
///
/// Everything in `tests` above is an EXAMPLE, and every one of those examples
/// was chosen by the same hand that wrote the assertion it satisfies. That is a
/// closed loop: it can only ever confirm the shapes its author already had in
/// mind. §9 does not ask for more examples, it asks for a `fuzz corpus`, and
/// the distinction is the whole point — the defect a corpus finds is the
/// COMPOSITION nobody thought to write down.
///
/// So the assertions here are deliberately not of the form `key(a) == b` for
/// literal `a` and `b`. They are **laws** quantified over generated input:
/// agreement, idempotence, refinement. A law can be checked against a string
/// its author never saw, which is exactly what an example cannot do.
///
/// # What is generated
///
/// Uniform `any::<String>()` alone is close to useless for this: the hazardous
/// codepoints are a vanishing fraction of the 1.1M-codepoint space, and a
/// uniform sampler will essentially never emit `İ` followed by two combining
/// marks. So sampling is mixed (`prop_oneof!`) between uniform strings and
/// dense draws from the families that are known to break naive
/// case/normalization code:
///
/// * **dotted/dotless i** — `İ U+0130` lowercases to TWO codepoints
///   (`i` + `U+0307`), so case folding changes length; `ı U+0131` is its
///   Turkish counterpart with no dot at all.
/// * **singleton decompositions** — `K U+212A` (Kelvin) and `Å U+212B`
///   (Angstrom) canonically decompose to ordinary letters, so NFC/NFD change
///   the character's IDENTITY rather than merely its composition.
/// * **final sigma** — `Σ` lowercases to `σ` or `ς` depending on what
///   surrounds it, so lowercasing is context-sensitive and not a per-character
///   map.
/// * **Hangul** — `한 U+D55C` decomposes to three jamo, a 1→3 length change
///   under NFD that no Latin example exercises.
/// * **multi-mark clusters** — a base with two to five combining marks drawn
///   from `U+0300..=U+036F`, which stresses canonical ORDERING (the marks are
///   emitted in generated order, not canonical order, so NFC/NFD must reorder
///   them).
#[cfg(test)]
mod proptests {
    use super::*;
    use proptest::prelude::*;

    /// Codepoints whose case or normalisation behaviour is irregular enough
    /// that a uniform sampler would never find them in useful density.
    const HAZARDS: &[char] = &[
        // Dotted/dotless i: the Turkish family. `İ`.to_lowercase() is two
        // codepoints, so case folding is not length-preserving.
        '\u{0130}', // İ  capital I with dot above
        '\u{0131}', // ı  dotless small i
        'i',
        'I',
        '\u{0307}', // combining dot above, the tail of İ's lowercase
        // Singleton canonical decompositions: normalisation swaps the char.
        '\u{212A}', // K  KELVIN SIGN -> U+004B
        '\u{212B}', // Å  ANGSTROM SIGN -> U+00C5
        '\u{2126}', // Ω  OHM SIGN -> U+03A9
        // Greek, incl. the context-sensitive final sigma.
        '\u{03A3}', // Σ
        '\u{03C3}', // σ
        '\u{03C2}', // ς
        '\u{0345}', // combining ypogegrammeni (iota subscript)
        '\u{1FBC}', // ᾼ  decomposes to Α + U+0345
        // German sharp s: uppercase/lowercase are not a bijection.
        '\u{00DF}', // ß
        '\u{1E9E}', // ẞ  capital sharp s
        '\u{1E9B}', // ẛ  long s with dot above (a classic NFC/NFD stress case)
        // Precomposed Latin with a canonical decomposition.
        '\u{00E9}', // é
        '\u{00C9}', // É
        '\u{0301}', // combining acute
        '\u{0323}', // combining dot below (reorders past U+0301 under NFC)
        // Hangul: a 1 -> 3 codepoint decomposition.
        '\u{D55C}', // 한
        '\u{AC00}', // 가
        // Cherokee: added with case mappings late, and folds "upward".
        '\u{13A0}', //
        '\u{AB70}', //
        // Deseret and other supplementary-plane cased letters.
        '\u{10400}', //
        '\u{10428}', //
        // ASCII structure that norm_key itself manipulates.
        '/',
        '\\',
        '.',
    ];

    /// A base character plus zero to four combining marks, emitted in
    /// GENERATED order so canonical reordering is exercised rather than
    /// assumed.
    fn cluster() -> impl Strategy<Value = String> {
        (
            prop_oneof![
                proptest::sample::select(HAZARDS),
                any::<char>(),
                proptest::char::range('a', 'z'),
            ],
            prop::collection::vec(
                (0x0300u32..=0x036Fu32).prop_map(|c| char::from_u32(c).unwrap()),
                0..=4,
            ),
        )
            .prop_map(|(base, marks)| {
                let mut s = String::new();
                s.push(base);
                s.extend(marks);
                s
            })
    }

    /// A path-shaped string built from hazardous clusters.
    fn hazardous_path() -> impl Strategy<Value = String> {
        prop::collection::vec(prop::collection::vec(cluster(), 1..=4), 1..=3).prop_map(|segs| {
            segs.into_iter()
                .map(|cs| cs.concat())
                .collect::<Vec<_>>()
                .join("/")
        })
    }

    /// Characters that are guaranteed to differ between NFC and NFD, so the
    /// `Preserve` negative below has something to be negative ABOUT.
    ///
    /// Drawing these from `corpus()` and filtering with `prop_assume!` does not
    /// work: most generated strings are already normalisation-stable, so the
    /// filter rejects far more than it keeps and proptest aborts on the reject
    /// cap having proven nothing. Generating the property's precondition is the
    /// fix; assuming it is what fails.
    const DECOMPOSABLE: &[char] = &[
        '\u{00E9}', // é   -> e + U+0301
        '\u{00C5}', // Å   -> A + U+030A
        '\u{1E9B}', // ẛ   -> ſ + U+0307
        '\u{1FBC}', // ᾼ   -> Α + U+0345
        '\u{D55C}', // 한  -> three jamo (1 -> 3, a length change)
        '\u{AC00}', // 가  -> two jamo
        '\u{01D5}', // Ǖ   -> a three-way decomposition
        '\u{0958}', // क़   -> Devanagari with nukta
    ];

    /// A string containing at least one character whose NFC and NFD spellings
    /// genuinely differ.
    fn decomposable_string() -> impl Strategy<Value = String> {
        (
            prop::collection::vec(proptest::sample::select(DECOMPOSABLE), 1..=3),
            prop::collection::vec(cluster(), 0..=2),
        )
            .prop_map(|(hot, rest)| {
                let mut s: String = hot.into_iter().collect();
                s.push_str(&rest.concat());
                s
            })
    }

    /// The corpus: uniform strings mixed with dense hazardous ones.
    ///
    /// Both halves matter. The uniform half can find a defect in a family
    /// nobody listed in `HAZARDS` — which is the failure mode `HAZARDS` itself
    /// has, being another hand-written list. The hazardous half is what gives
    /// the known-difficult families enough density to actually appear.
    fn corpus() -> impl Strategy<Value = String> {
        prop_oneof![
            3 => hazardous_path(),
            2 => cluster(),
            1 => any::<String>(),
        ]
    }

    /// Every `(case, norm)` pair a root can be probed into.
    const POLICIES: &[(PathCasePolicy, PathNormPolicy)] = &[
        (PathCasePolicy::Sensitive, PathNormPolicy::Nfc),
        (PathCasePolicy::Sensitive, PathNormPolicy::Nfd),
        (PathCasePolicy::Sensitive, PathNormPolicy::Preserve),
        (PathCasePolicy::Insensitive, PathNormPolicy::Nfc),
        (PathCasePolicy::Insensitive, PathNormPolicy::Nfd),
        (PathCasePolicy::Insensitive, PathNormPolicy::Preserve),
    ];

    fn nfc_of(s: &str) -> String {
        s.nfc().collect()
    }
    fn nfd_of(s: &str) -> String {
        s.nfd().collect()
    }

    proptest! {
        #![proptest_config(ProptestConfig {
            cases: 4096,
            max_shrink_iters: 8192,
            ..ProptestConfig::default()
        })]

        /// THE §4.9 LAW, generalised off its one example.
        ///
        /// `nfd_and_nfc_fold_to_one_norm_key` proves this for `café`. The law
        /// is that it holds for EVERY string: two canonically-equivalent
        /// spellings of one name must produce one `norm_key` under a
        /// normalising policy, or a macOS watcher event never matches the row a
        /// Linux scan wrote — false absence, which PM-3 calls discard-trigger
        /// territory.
        ///
        /// Quantified over both normalising policies and both case policies,
        /// because a fold that worked under `Nfc`/`Sensitive` and failed under
        /// `Nfd`/`Insensitive` would still lose files on exactly one platform.
        #[test]
        fn canonically_equivalent_spellings_agree_under_a_normalising_policy(
            s in corpus()
        ) {
            let (nfc, nfd) = (nfc_of(&s), nfd_of(&s));
            for &(case, norm) in POLICIES {
                if norm == PathNormPolicy::Preserve {
                    continue; // Preserve deliberately does not fold; see below.
                }
                prop_assert_eq!(
                    norm_key(&nfc, case, norm),
                    norm_key(&nfd, case, norm),
                    "spellings disagree under {:?}/{:?} for {:?}",
                    case, norm, s
                );
            }
        }

        /// The negative that gives the fold its meaning, generalised.
        ///
        /// `preserve_keeps_the_two_spellings_apart` proves this for one pair.
        /// The law: whenever two spellings genuinely differ as bytes, a
        /// byte-preserving root must keep them apart. Without this, an
        /// implementation that folded everything unconditionally would satisfy
        /// the agreement law above while destroying the distinction on the
        /// filesystems that keep it.
        #[test]
        fn preserve_never_folds_two_genuinely_distinct_spellings(
            s in decomposable_string()
        ) {
            let (nfc, nfd) = (nfc_of(&s), nfd_of(&s));
            // Retained as a guard, not as the filter: `decomposable_string`
            // is built to satisfy this, so a reject here means the GENERATOR
            // regressed and the property stopped being tested.
            prop_assume!(nfc != nfd);
            prop_assert_ne!(
                norm_key(&nfc, PathCasePolicy::Sensitive, PathNormPolicy::Preserve),
                norm_key(&nfd, PathCasePolicy::Sensitive, PathNormPolicy::Preserve),
                "Preserve folded two distinct spellings of {:?}", s
            );
        }

        /// Idempotence: a key is a fixed point of its own derivation.
        ///
        /// This is not decoration. `norm_key` is applied to a path at scan
        /// time and again to a watcher event's path; anywhere a stored key is
        /// re-normalised — a migration, a re-index, a comparison against an
        /// already-normalised value — a non-idempotent key silently stops
        /// matching itself.
        ///
        /// It is also the law most likely to break, because `norm_key`
        /// lowercases AFTER normalising, and `to_lowercase` is not guaranteed
        /// to emit its result in the normalisation form it was given.
        #[test]
        fn norm_key_is_a_fixed_point_of_itself(s in corpus()) {
            for &(case, norm) in POLICIES {
                let once = norm_key(&s, case, norm);
                let twice = norm_key(&once, case, norm);
                prop_assert_eq!(
                    &once, &twice,
                    "norm_key not idempotent under {:?}/{:?} for {:?}",
                    case, norm, s
                );
            }
        }

        /// Refinement: an insensitive root folds strictly MORE than a
        /// sensitive one, never less.
        ///
        /// The interesting direction is the one asserted. If two paths already
        /// collide on a case-sensitive root they are the same name, and an
        /// insensitive root must agree; an insensitive root that separated them
        /// would mean case folding had introduced a distinction rather than
        /// removed one, and the catalog would hold two rows for one file.
        #[test]
        fn insensitive_is_coarser_than_sensitive(a in corpus(), b in corpus()) {
            for norm in [PathNormPolicy::Nfc, PathNormPolicy::Nfd, PathNormPolicy::Preserve] {
                let sens_eq = norm_key(&a, PathCasePolicy::Sensitive, norm)
                    == norm_key(&b, PathCasePolicy::Sensitive, norm);
                if sens_eq {
                    prop_assert_eq!(
                        norm_key(&a, PathCasePolicy::Insensitive, norm),
                        norm_key(&b, PathCasePolicy::Insensitive, norm),
                        "case folding SPLIT two paths that a sensitive root merged, under {:?}",
                        norm
                    );
                }
            }
        }

        /// The content-addressed half of §9's sentence, over generated hashes.
        ///
        /// `path_never_enters_the_key` proves the key ignores the path by
        /// inspection — the path is not a parameter. What a corpus adds is
        /// INJECTIVITY: for a fixed prefix, distinct content must never share
        /// an object key, because a collision here is the §4.9 catastrophe
        /// (file B overwrites A's object, B's verify passes against B's own
        /// bytes, A is gone everywhere).
        #[test]
        fn content_keys_are_collision_free_over_distinct_hashes(
            a in any::<[u8; 32]>(),
            b in any::<[u8; 32]>(),
            prefix in corpus(),
        ) {
            let (ka, kb) = (
                content_key(&prefix, Blake3Hash::from_bytes(a)),
                content_key(&prefix, Blake3Hash::from_bytes(b)),
            );
            if a == b {
                prop_assert_eq!(ka, kb, "identical content must share one object");
            } else {
                prop_assert_ne!(ka, kb, "distinct content collided on one key");
            }
        }

        /// The same, for the id-addressed layout: `(file_id, hash)` must be
        /// injective, or a catalog-ID-addressed target overwrites objects the
        /// way §4.9's path-derived keys would have.
        #[test]
        fn id_keys_are_collision_free_over_distinct_ids(
            id_a in any::<i64>(),
            id_b in any::<i64>(),
            h in any::<[u8; 32]>(),
        ) {
            let (ka, kb) = (
                id_key("t", id_a, Blake3Hash::from_bytes(h)),
                id_key("t", id_b, Blake3Hash::from_bytes(h)),
            );
            prop_assert_eq!(id_a == id_b, ka == kb);
        }
    }
}
