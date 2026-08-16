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
        }
    }

    pub fn with_extra_dir(mut self, name: impl Into<String>) -> Self {
        self.extra_names.insert(name.into());
        self
    }

    /// Whether the walker should refuse to descend into this directory.
    ///
    /// `component` is the directory's own name; `abs` its absolute path.
    pub fn deny_dir(&self, component: &str, abs: &Path) -> Option<DenyReason> {
        if self.extra_names.contains(component) {
            return Some(DenyReason::SystemPath);
        }
        for (name, why) in &self.names {
            if component == *name {
                return Some(*why);
            }
        }
        for (suffix, why) in &self.suffixes {
            // A component that IS the suffix (a directory literally named
            // ".app") is not a bundle; a bundle is "Something.app".
            if component.len() > suffix.len() && component.ends_with(suffix) {
                return Some(*why);
            }
        }
        let norm = abs.to_string_lossy().replace('\\', "/");
        for (prefix, why) in &self.abs_prefixes {
            if path_has_prefix(&norm, prefix) {
                return Some(*why);
            }
        }
        None
    }

    /// Whether this file is denied on its own name.
    pub fn deny_file(&self, name: &str) -> Option<DenyReason> {
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
fn path_has_prefix(path: &str, prefix: &str) -> bool {
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

    #[test]
    fn absolute_prefixes_respect_component_boundaries() {
        let d = DenyList::builtin();
        assert_eq!(
            d.deny_dir("fd", &p("/proc/1/fd")),
            Some(DenyReason::SystemPath)
        );
        // `/proctor` is not `/proc`.
        assert_eq!(d.deny_dir("notes", &p("/proctor/notes")), None);
        assert_eq!(
            d.deny_dir("anything", &p("C:\\Windows\\System32")),
            Some(DenyReason::SystemPath),
            "backslash separators normalise before comparison"
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
        assert_eq!(d.deny_file("disk.vmdk"), Some(DenyReason::VmImage));
        assert_eq!(d.deny_file("Disk.QCOW2"), Some(DenyReason::VmImage));
        assert_eq!(d.deny_file("notes.txt"), None);
        // A dotfile has no extension, so it cannot be denied by one.
        assert_eq!(d.deny_file(".vmdk"), None);
    }

    #[test]
    fn an_empty_list_denies_nothing() {
        let d = DenyList::empty();
        assert_eq!(d.deny_dir(".git", &p("/home/u/.git")), None);
        assert_eq!(d.deny_file("disk.vmdk"), None);
    }
}
