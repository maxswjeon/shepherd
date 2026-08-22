//! The built-in deny-list (AC-7).
//!
//! Paths Shepherd refuses to catalogue at all. This is not the user's ignore
//! file — that is [`crate::ignore`], is per-root, and is the user's to edit.
//! This list is Shepherd's own, applies everywhere, and exists because tiering
//! any of these is either useless or actively harmful.
//!
//! # Matching is on path COMPONENTS, never substrings
//!
//! `mygit/` must not match `.git`, and `my_node_modules/` must not match
//! `node_modules`. Substring matching here would silently prune a user's real
//! data, and a directory that is never walked is a directory whose files are
//! never catalogued, never tiered, and — from the catalog's point of view —
//! absent. Absence is what PM-3 calls discard-trigger territory.
//!
//! # Pruning is at the directory level
//!
//! When a directory matches, the walker does not descend into it at all. That
//! is both the correctness property (nothing inside a `.git` is eligible) and
//! the performance story: at 10M files, the cost of the deny-list is the cost
//! of *not* visiting most of the tree.

use std::collections::BTreeSet;
use std::path::Path;

/// Why a path was denied. Carried through to `rule preview` so AC-14's dry-run
/// can state *why* a file was excluded rather than silently omitting it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenyReason {
    /// Operating-system and application-bundle internals.
    SystemPath,
    /// `.app`, `.framework`, `.bundle` — a macOS bundle is one artifact that
    /// happens to be a directory. Tiering files out of its middle breaks it.
    Bundle,
    /// Version-control metadata. Rebuildable, small, and losing it loses
    /// history the working tree cannot reconstruct.
    VersionControl,
    /// Package manager output. Rebuildable by definition, and enormous.
    PackageCache,
    /// Virtual-machine and container images: single files in the tens of GB
    /// that are written in place, so a tiered copy is stale the moment a VM
    /// boots.
    VmImage,
    /// Another sync engine's tree (iCloud, Dropbox, OneDrive, Google Drive).
    ///
    /// The most important entry here, and the least obvious. These directories
    /// are already managed by a provider that has its own placeholder and
    /// eviction semantics. Tiering a file out from under one is two systems
    /// both believing they own whether the bytes are local — and the failure
    /// mode is not a merge conflict, it is one engine restoring a file the
    /// other just destroyed, indefinitely.
    ForeignSyncRoot,
    /// Shepherd's own staging directory (§4.10, R-26). Deny-listed from scan
    /// and watch so the destroy path's own renames are never mistaken for user
    /// activity.
    ShepherdInternal,
}

impl DenyReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DenyReason::SystemPath => "system-path",
            DenyReason::Bundle => "bundle",
            DenyReason::VersionControl => "version-control",
            DenyReason::PackageCache => "package-cache",
            DenyReason::VmImage => "vm-image",
            DenyReason::ForeignSyncRoot => "foreign-sync-root",
            DenyReason::ShepherdInternal => "shepherd-internal",
        }
    }
}

/// Shepherd's staging directory name (§4.10, R-26).
///
/// Shared with `shepherd-tier`, which creates these per mount. It is deny-listed
/// here so the walker never sees a file mid-destruction and reports it as user
/// data — and never sees it vanish and reports that as an absence.
pub const STAGING_DIR_NAME: &str = ".shepherd-staging";

/// The built-in deny-list.
#[derive(Debug, Clone)]
pub struct DenyList {
    /// Exact directory-component names.
    names: Vec<(&'static str, DenyReason)>,
    /// Directory-component suffixes, for macOS bundles.
    suffixes: Vec<(&'static str, DenyReason)>,
    /// Absolute path prefixes, compared component-wise.
    abs_prefixes: Vec<(&'static str, DenyReason)>,
    /// File extensions denied wherever they appear.
    file_exts: Vec<(&'static str, DenyReason)>,
    /// User additions, kept separate so `builtin()` stays auditable.
    extra_names: BTreeSet<String>,
    /// Absolute paths denied by identity rather than by name, for directories
    /// only known at run time — the daemon's own state directory above all.
    /// Kept separate from `abs_prefixes` for the same auditability reason, and
    /// because those are `&'static`.
    extra_paths: Vec<String>,
    /// Whether component names match without regard to case.
    ///
    /// Set from the root's PROBED case policy, never assumed: on a
    /// case-insensitive volume `.GIT` and `Node_Modules` resolve to the same
    /// directories as `.git` and `node_modules`, so a bytewise comparison let
    /// a version-control or package-cache tree through on its spelling alone —
    /// and a deny-list entry that can be evaded by pressing shift is not a
    /// safety policy. Left off on case-sensitive roots, where `.GIT` really is
    /// a different directory and denying it would prune a user's own.
    case_insensitive: bool,
}

impl Default for DenyList {
    fn default() -> Self {
        Self::builtin()
    }
}

impl DenyList {
    pub fn builtin() -> Self {
        use DenyReason::*;
        Self {
            names: vec![
                (STAGING_DIR_NAME, ShepherdInternal),
                // Version control.
                (".git", VersionControl),
                (".hg", VersionControl),
                (".svn", VersionControl),
                // Package caches and build output.
                ("node_modules", PackageCache),
                (".cargo", PackageCache),
                (".gradle", PackageCache),
                (".m2", PackageCache),
                (".npm", PackageCache),
                (".pnpm-store", PackageCache),
                (".yarn", PackageCache),
                ("__pycache__", PackageCache),
                (".venv", PackageCache),
                ("site-packages", PackageCache),
                // Foreign sync engines. See DenyReason::ForeignSyncRoot.
                (".dropbox.cache", ForeignSyncRoot),
                (".dropbox", ForeignSyncRoot),
                ("com~apple~CloudDocs", ForeignSyncRoot),
                (".Trash", SystemPath),
                ("$RECYCLE.BIN", SystemPath),
                ("System Volume Information", SystemPath),
                ("lost+found", SystemPath),
            ],
            suffixes: vec![
                (".app", Bundle),
                (".framework", Bundle),
                (".bundle", Bundle),
                (".photoslibrary", Bundle),
                (".xcodeproj", Bundle),
                // A DIRECTORY, despite being a disk image — which is why it is
                // here and not only in `file_exts`, where the walk would never
                // consult it: a bundle is reached as a directory and descended
                // before any extension rule runs. `VmImage`, not `Bundle`,
                // because that is what it is.
                (".sparsebundle", VmImage),
            ],
            abs_prefixes: vec![
                // Unix system trees.
                ("/proc", SystemPath),
                ("/sys", SystemPath),
                ("/dev", SystemPath),
                ("/run", SystemPath),
                ("/System", SystemPath),
                ("/Library/Caches", SystemPath),
                ("/private/var", SystemPath),
                // Windows system trees.
                ("C:/Windows", SystemPath),
                ("C:/Program Files", SystemPath),
                ("C:/Program Files (x86)", SystemPath),
                ("C:/ProgramData", SystemPath),
            ],
            file_exts: vec![
                ("vmdk", VmImage),
                ("vdi", VmImage),
                ("qcow2", VmImage),
                ("vhdx", VmImage),
                ("hds", VmImage),
                ("sparsebundle", VmImage),
            ],
            extra_names: BTreeSet::new(),
            extra_paths: Vec::new(),
            case_insensitive: false,
        }
    }

    /// An empty deny-list. Tests only — production always starts from
    /// [`DenyList::builtin`].
    pub fn empty() -> Self {
        Self {
            names: Vec::new(),
            suffixes: Vec::new(),
            abs_prefixes: Vec::new(),
            file_exts: Vec::new(),
            extra_names: BTreeSet::new(),
            extra_paths: Vec::new(),
            case_insensitive: false,
        }
    }

    /// Match component names without regard to case, for a root whose probed
    /// policy says the filesystem does.
    ///
    /// ASCII folding: every name and suffix on the builtin list is ASCII, so
    /// there is no non-ASCII spelling of `.git` to miss, and full Unicode
    /// folding would bring its own surprises to a safety predicate.
    pub fn case_insensitive(mut self, yes: bool) -> Self {
        self.case_insensitive = yes;
        self
    }

    pub fn with_extra_dir(mut self, name: impl Into<String>) -> Self {
        self.extra_names.insert(name.into());
        self
    }

    /// Deny one absolute path and everything under it.
    ///
    /// By path, not by name: the daemon's state directory has no distinctive
    /// basename, and denying `shepherd` everywhere would exclude a user's own
    /// directory of that name from their own backup.
    ///
    /// Canonicalized when it can be, because the walk reports the path it
    /// reached the directory by. A symlinked state directory that cannot be
    /// resolved falls back to the literal path — matching the raw form is
    /// strictly better than matching nothing.
    ///
    /// ponytail: string prefix comparison, like `abs_prefixes`. A bind mount or
    /// a hard-linked directory reaches the same inode by a path this will not
    /// match; identity comparison via `dev`/`ino` is the upgrade if that turns
    /// up in practice.
    pub fn with_extra_path(mut self, path: &Path) -> Self {
        let resolved = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        for p in [path.to_path_buf(), resolved] {
            let norm = p.to_normalized_string();
            if !norm.is_empty() && !self.extra_paths.contains(&norm) {
                self.extra_paths.push(norm);
            }
        }
        self
    }

    /// Whether the walker should refuse to descend into this directory.
    ///
    /// `component` is the directory's own name; `abs` its absolute path.
    pub fn deny_dir(&self, component: &str, abs: &Path) -> Option<DenyReason> {
        let eq = |a: &str, b: &str| {
            if self.case_insensitive {
                a.eq_ignore_ascii_case(b)
            } else {
                a == b
            }
        };
        // BYTES, not a string slice. `hay[hay.len() - tail.len()..]` panics when
        // that offset is not a UTF-8 boundary — `€€` against `.app` is four
        // bytes into a three-byte scalar — so an ordinary filename on a
        // case-insensitive root killed the scan worker and left its job stuck
        // in `running`. Every suffix on the list is ASCII, and
        // `eq_ignore_ascii_case` is defined on `[u8]`, so comparing the tail
        // bytes asks the same question without needing the offset to be a
        // boundary at all.
        let ends_with = |hay: &str, tail: &str| {
            if self.case_insensitive {
                let (hay, tail) = (hay.as_bytes(), tail.as_bytes());
                hay.len() >= tail.len() && hay[hay.len() - tail.len()..].eq_ignore_ascii_case(tail)
            } else {
                hay.ends_with(tail)
            }
        };

        if self.extra_names.iter().any(|n| eq(n, component)) {
            return Some(DenyReason::SystemPath);
        }
        for (name, why) in &self.names {
            if eq(component, name) {
                return Some(*why);
            }
        }
        for (suffix, why) in &self.suffixes {
            // A component that IS the suffix (a directory literally named
            // ".app") is not a bundle; a bundle is "Something.app".
            if component.len() > suffix.len() && ends_with(component, suffix) {
                return Some(*why);
            }
        }
        let norm = abs.to_normalized_string();
        for (prefix, why) in &self.abs_prefixes {
            if path_has_prefix(&norm, prefix, self.case_insensitive) {
                return Some(*why);
            }
        }
        for prefix in &self.extra_paths {
            if path_has_prefix(&norm, prefix, self.case_insensitive) {
                return Some(DenyReason::ShepherdInternal);
            }
        }
        None
    }

    /// Whether this file is denied, on its extension or on its path.
    ///
    /// The path half is why this takes `abs` as well as `name`. A path added
    /// with [`Self::with_extra_path`] used to be consulted only by
    /// [`Self::deny_dir`], so a denied path that names a FILE rather than a
    /// directory was not denied at all — and the daemon's socket lock is
    /// exactly that: one ordinary file, in a directory that can sit inside a
    /// scan root, which the daemon created for itself.
    pub fn deny_file(&self, name: &str, abs: &Path) -> Option<DenyReason> {
        let norm = abs.to_normalized_string();
        if self
            .extra_paths
            .iter()
            .any(|prefix| path_has_prefix(&norm, prefix, self.case_insensitive))
        {
            return Some(DenyReason::ShepherdInternal);
        }
        let ext = name.rfind('.').filter(|&i| i > 0).map(|i| &name[i + 1..]);
        let ext = ext?.to_ascii_lowercase();
        self.file_exts
            .iter()
            .find(|(e, _)| *e == ext)
            .map(|(_, why)| *why)
    }
}

/// Prefix comparison that respects component boundaries.
///
/// `/proc` must match `/proc/1/fd` but not `/proctor/notes.txt`.
///
/// `fold` follows the ROOT's probed case policy and is not a free "be
/// generous". Folding unconditionally on a case-sensitive filesystem makes
/// `/home/u/Shepherd` — a state directory, say — also exclude the user's own
/// `/home/u/shepherd/`, and the files under it are then never catalogued and
/// never backed up. A deny list that silently swallows a subtree is worse than
/// one that misses a case variant of a system path, because nothing surfaces
/// it: the scan reports success, and the absence looks like an empty
/// directory.
/// A path as a string with separators folded to `/` — **on Windows only**.
///
/// `\` is an ordinary character in a Unix filename, and converting it there
/// turns `/data/shepherd\notes.txt` into a path beneath a denied
/// `/data/shepherd`, silently omitting unrelated user data from the scan. The
/// conversion exists for Windows, where `\` really is a separator and the
/// comparisons below are written in terms of `/`.
///
/// This is the fourth site in this PR to get the same correction, and the
/// pattern is always the shape: a normalisation written to be portable that is
/// only correct on one platform.
trait NormalizedPath {
    fn to_normalized_string(&self) -> String;
}

impl NormalizedPath for Path {
    fn to_normalized_string(&self) -> String {
        let s = self.to_string_lossy();
        if cfg!(windows) {
            s.replace('\\', "/")
        } else {
            s.into_owned()
        }
    }
}

fn path_has_prefix(path: &str, prefix: &str, fold: bool) -> bool {
    if !fold {
        if path == prefix {
            return true;
        }
        return match path.strip_prefix(prefix) {
            Some(rest) => rest.starts_with('/'),
            None => false,
        };
    }
    let path_l = path.to_ascii_lowercase();
    let prefix_l = prefix.to_ascii_lowercase();
    if path_l == prefix_l {
        return true;
    }
    match path_l.strip_prefix(&prefix_l) {
        Some(rest) => rest.starts_with('/'),
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn p(s: &str) -> PathBuf {
        PathBuf::from(s)
    }

    #[test]
    fn exact_component_names_match() {
        let d = DenyList::builtin();
        assert_eq!(
            d.deny_dir(".git", &p("/home/u/proj/.git")),
            Some(DenyReason::VersionControl)
        );
        assert_eq!(
            d.deny_dir("node_modules", &p("/home/u/proj/node_modules")),
            Some(DenyReason::PackageCache)
        );
    }

    /// The daemon's state directory is denied by PATH, and nothing else is.
    ///
    /// Under a `$HOME` root the state directory is inside the tree being
    /// walked, so without this the walk catalogued the live `catalog.db`, its
    /// WAL companions and any `secrets.json`. Denying the *name* would have
    /// been the cheaper fix and the wrong one: a user's own directory called
    /// `shepherd` would have vanished from their own backup.
    #[test]
    fn an_extra_path_denies_that_directory_and_only_that_one() {
        let state = p("/home/u/.local/state/shepherd");
        let d = DenyList::builtin().with_extra_path(&state);

        assert_eq!(
            d.deny_dir("shepherd", &state),
            Some(DenyReason::ShepherdInternal)
        );
        assert_eq!(
            d.deny_dir("sessions", &p("/home/u/.local/state/shepherd/sessions")),
            Some(DenyReason::ShepherdInternal),
            "everything under it too"
        );

        // A directory of the same NAME elsewhere is the user's own.
        assert_eq!(d.deny_dir("shepherd", &p("/home/u/code/shepherd")), None);
        // And a sibling that merely shares a prefix is not under it.
        assert_eq!(
            d.deny_dir("shepherd-notes", &p("/home/u/.local/state/shepherd-notes")),
            None
        );
    }

    /// On a case-insensitive volume, `.GIT` is the `.git`.
    ///
    /// macOS and Windows roots resolve `.GIT`, `Node_Modules` and `.Git` to the
    /// same directories as their lowercase spellings, so a bytewise comparison
    /// let a version-control or package-cache tree through on nothing but its
    /// preserved capitalisation — a safety policy evaded by pressing shift.
    ///
    /// Both directions are asserted. On a case-SENSITIVE root `.GIT` really is
    /// a different directory, and denying it would prune one of the user's own.
    /// The same policy governs PATH exclusions, which folded unconditionally.
    ///
    /// A runtime exclusion is an absolute path — the state directory, the
    /// socket's lock file — and folding it on a case-sensitive root makes
    /// `/home/u/Shepherd` also exclude the user's own `/home/u/shepherd/`.
    /// Those files are then never catalogued and never backed up, and nothing
    /// surfaces it: the scan reports success and the subtree just looks empty.
    #[test]
    fn absolute_path_exclusions_follow_the_roots_policy_too() {
        let sensitive = DenyList::builtin().with_extra_path(&p("/home/u/Shepherd"));
        let insensitive = DenyList::builtin()
            .case_insensitive(true)
            .with_extra_path(&p("/home/u/Shepherd"));

        // The exact path is excluded under either policy — that is the point of
        // adding it.
        for d in [&sensitive, &insensitive] {
            assert!(d.deny_dir("Shepherd", &p("/home/u/Shepherd")).is_some());
            assert!(d.deny_dir("sub", &p("/home/u/Shepherd/sub")).is_some());
        }

        // A DIFFERENT directory that merely differs in case is the user's own
        // on a case-sensitive root, and the same directory on an insensitive
        // one.
        assert_eq!(
            sensitive.deny_dir("shepherd", &p("/home/u/shepherd")),
            None,
            "`/home/u/shepherd` is not `/home/u/Shepherd` on a case-sensitive root; \
             excluding it silently drops the user's files from every backup"
        );
        assert_eq!(
            sensitive.deny_file("notes.txt", &p("/home/u/shepherd/notes.txt")),
            None
        );
        assert!(
            insensitive
                .deny_dir("shepherd", &p("/home/u/shepherd"))
                .is_some(),
            "on a case-insensitive root the two names ARE one directory"
        );
        assert!(
            insensitive
                .deny_file("notes.txt", &p("/home/u/shepherd/notes.txt"))
                .is_some()
        );
    }

    #[test]
    fn case_folding_follows_the_roots_policy() {
        let sensitive = DenyList::builtin();
        let insensitive = DenyList::builtin().case_insensitive(true);

        for (component, path) in [
            (".GIT", "/home/u/proj/.GIT"),
            (".Git", "/home/u/proj/.Git"),
            ("Node_Modules", "/home/u/proj/Node_Modules"),
            ("NODE_MODULES", "/home/u/proj/NODE_MODULES"),
        ] {
            assert_eq!(
                sensitive.deny_dir(component, &p(path)),
                None,
                "`{component}` is a different directory on a case-sensitive root"
            );
            assert!(
                insensitive.deny_dir(component, &p(path)).is_some(),
                "`{component}` resolves to a denied tree on a case-insensitive root"
            );
        }

        // The exact spellings are denied either way.
        assert!(
            sensitive
                .deny_dir(".git", &p("/home/u/proj/.git"))
                .is_some()
        );
        assert!(
            insensitive
                .deny_dir(".git", &p("/home/u/proj/.git"))
                .is_some()
        );

        // Suffix rules fold too — a macOS bundle is the case that motivates
        // them, and macOS is where insensitivity lives.
        assert_eq!(sensitive.deny_dir("Photos.APP", &p("/x/Photos.APP")), None);
        assert_eq!(
            insensitive.deny_dir("Photos.APP", &p("/x/Photos.APP")),
            Some(DenyReason::Bundle)
        );
        // And a component that IS the suffix is still not a bundle.
        assert_eq!(insensitive.deny_dir(".APP", &p("/x/.APP")), None);
    }

    /// A non-ASCII directory name must not panic the case-insensitive matcher.
    ///
    /// The suffix comparison sliced the name at `len - suffix.len()`, which is
    /// not a UTF-8 boundary for a name like `€€` tested against `.app` — four
    /// bytes into a three-byte scalar. That panics, and the panic lands in the
    /// scan worker, which leaves its job stuck in `running`. An ordinary
    /// filename should not be able to do that.
    #[test]
    fn a_non_ascii_name_does_not_panic_the_case_insensitive_matcher() {
        let d = DenyList::builtin().case_insensitive(true);

        // Names whose byte length lands mid-scalar for at least one suffix.
        for name in ["€€", "€", "café", "日本語", "a€", "€.app", "ünïcödé"] {
            let path = p(&format!("/home/u/{name}"));
            // The assertion is that this RETURNS. Panicking is the bug.
            let _ = d.deny_dir(name, &path);
        }

        // And it still answers correctly for the case it exists to catch.
        assert_eq!(
            d.deny_dir("Photos.APP", &p("/x/Photos.APP")),
            Some(DenyReason::Bundle)
        );
        // A multi-byte name that genuinely ends with a bundle suffix folds too.
        assert_eq!(
            d.deny_dir("café.APP", &p("/x/café.APP")),
            Some(DenyReason::Bundle)
        );
        // And one that does not is left alone.
        assert_eq!(d.deny_dir("€€", &p("/x/€€")), None);
    }

    /// The lesson this codebase has now learned three times: match on
    /// boundaries, not substrings. A substring match here prunes a user's real
    /// directory, and a pruned directory is an absent one.
    #[test]
    fn a_substring_is_not_a_component() {
        let d = DenyList::builtin();
        assert_eq!(d.deny_dir("mygit", &p("/home/u/mygit")), None);
        assert_eq!(d.deny_dir(".gitignore", &p("/home/u/.gitignore")), None);
        assert_eq!(
            d.deny_dir("my_node_modules", &p("/home/u/my_node_modules")),
            None
        );
        assert_eq!(d.deny_dir("git", &p("/home/u/git")), None);
    }

    #[test]
    fn bundles_match_by_suffix_but_a_bare_suffix_is_not_a_bundle() {
        let d = DenyList::builtin();
        assert_eq!(
            d.deny_dir("Xcode.app", &p("/Applications/Xcode.app")),
            Some(DenyReason::Bundle)
        );
        assert_eq!(
            d.deny_dir(
                "Photos.photoslibrary",
                &p("/Users/u/Pictures/Photos.photoslibrary")
            ),
            Some(DenyReason::Bundle)
        );
        // A directory the user literally named ".app" is theirs, not a bundle.
        assert_eq!(d.deny_dir(".app", &p("/home/u/.app")), None);
    }

    /// A sparse bundle is a DIRECTORY, so the extension list never sees it.
    ///
    /// `file_exts` is consulted only for non-directory entries. Listing
    /// `sparsebundle` there and nowhere else meant the walker descended into
    /// `Backup.sparsebundle` and catalogued its band files one by one — the
    /// disk image `VmImage` exists to exclude, admitted as a few thousand
    /// opaque fragments instead.
    #[test]
    fn a_sparse_bundle_is_denied_as_a_directory_not_only_as_an_extension() {
        let d = DenyList::builtin();
        assert_eq!(
            d.deny_dir("Backup.sparsebundle", &p("/Users/u/Backup.sparsebundle")),
            Some(DenyReason::VmImage),
            "the walk reaches a sparse bundle as a directory, and this is the only \
             hook that runs before it descends"
        );
        // Still denied by extension, for the spelling that is a plain file.
        assert_eq!(
            d.deny_file("disk.sparsebundle", &p("/Users/u/disk.sparsebundle")),
            Some(DenyReason::VmImage)
        );
        // And the bare suffix is a user's own directory, as with every other.
        assert_eq!(
            d.deny_dir(".sparsebundle", &p("/home/u/.sparsebundle")),
            None
        );
    }

    #[test]
    fn absolute_prefixes_respect_component_boundaries() {
        let d = DenyList::builtin();
        assert_eq!(
            d.deny_dir("fd", &p("/proc/1/fd")),
            Some(DenyReason::SystemPath)
        );
        // `/proctor` is not `/proc`.
        assert_eq!(d.deny_dir("notes", &p("/proctor/notes")), None);
        // ON WINDOWS ONLY, and that is the point rather than a portability
        // dodge: there `\` is a separator and the comparison folds it, so the
        // system path is recognised. On unix the same string is a single
        // legal filename, and treating it as a path would be the confusion
        // that lets a file named `shepherd\notes.txt` count as beneath a
        // denied `shepherd` directory.
        #[cfg(windows)]
        assert_eq!(
            d.deny_dir("anything", &p("C:\\Windows\\System32")),
            Some(DenyReason::SystemPath),
            "backslash separators normalise before comparison"
        );
        #[cfg(unix)]
        assert_eq!(
            d.deny_dir("anything", &p("C:\\Windows\\System32")),
            None,
            "on unix this is one filename, not three components"
        );
    }

    /// Tiering out of another sync engine's tree is two systems both believing
    /// they decide whether the bytes are local.
    #[test]
    fn foreign_sync_roots_are_denied() {
        let d = DenyList::builtin();
        assert_eq!(
            d.deny_dir(
                "com~apple~CloudDocs",
                &p("/Users/u/Library/Mobile Documents/com~apple~CloudDocs")
            ),
            Some(DenyReason::ForeignSyncRoot)
        );
        assert_eq!(
            d.deny_dir(".dropbox.cache", &p("/home/u/Dropbox/.dropbox.cache")),
            Some(DenyReason::ForeignSyncRoot)
        );
    }

    /// R-26: the destroy path's staging directory must never appear to the
    /// walker, or its renames read as user activity and its absences as
    /// deletions.
    #[test]
    fn the_staging_directory_is_denied() {
        let d = DenyList::builtin();
        assert_eq!(
            d.deny_dir(STAGING_DIR_NAME, &p("/data/.shepherd-staging")),
            Some(DenyReason::ShepherdInternal)
        );
    }

    #[test]
    fn vm_images_are_denied_by_extension_case_insensitively() {
        let d = DenyList::builtin();
        assert_eq!(
            d.deny_file("disk.vmdk", Path::new("/srv/disk.vmdk")),
            Some(DenyReason::VmImage)
        );
        assert_eq!(
            d.deny_file("Disk.QCOW2", Path::new("/srv/Disk.QCOW2")),
            Some(DenyReason::VmImage)
        );
        assert_eq!(d.deny_file("notes.txt", Path::new("/srv/notes.txt")), None);
        // A dotfile has no extension, so it cannot be denied by one.
        assert_eq!(d.deny_file(".vmdk", Path::new("/srv/.vmdk")), None);
    }

    #[test]
    fn an_empty_list_denies_nothing() {
        let d = DenyList::empty();
        assert_eq!(d.deny_dir(".git", &p("/home/u/.git")), None);
        assert_eq!(d.deny_file("disk.vmdk", Path::new("/srv/disk.vmdk")), None);
    }

    /// A backslash in a Unix filename does not put a file inside a denied
    /// directory.
    ///
    /// The normalisation was unconditional, so `/data/shepherd\notes.txt` —
    /// one root-level file with an unusual name — folded into
    /// `/data/shepherd/notes.txt` and was silently omitted from the scan as
    /// daemon-internal. Unrelated user data, dropped without a word.
    #[cfg(unix)]
    #[test]
    fn a_backslash_in_a_unix_name_is_not_a_denied_prefix() {
        let d = DenyList::builtin().with_extra_path(&p("/data/shepherd"));

        assert_eq!(
            d.deny_file("shepherd\\notes.txt", &p("/data/shepherd\\notes.txt")),
            None,
            "a backslash is a legal filename character here, not a boundary"
        );
        // AND THE REAL PREFIX still denies, so this is not a hole in the other
        // direction.
        assert_eq!(
            d.deny_file("daemon.sock", &p("/data/shepherd/daemon.sock")),
            Some(DenyReason::ShepherdInternal)
        );
        assert_eq!(
            d.deny_dir("shepherd", &p("/data/shepherd")),
            Some(DenyReason::ShepherdInternal)
        );
    }
}
