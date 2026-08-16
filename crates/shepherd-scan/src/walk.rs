//! The filesystem walker.
//!
//! # The cycle guard — two layers, and they do different jobs
//!
//! §6 Phase 1 names "a symlink/junction cycle guard in the walker" as a
//! deliverable. It is two mechanisms, deliberately:
//!
//! 1. **No symlink or junction is ever followed.** A symlinked directory is
//!    reported as [`Skip::SymlinkedDir`] and not descended. This is what makes
//!    a symlink cycle *impossible* rather than merely *detected* — `a/b -> a`
//!    cannot loop if the link is never traversed. It also happens to be the
//!    right answer on its own terms: the contents belong to whatever the link
//!    points at, which is either outside the root or already walked.
//!
//! 2. **Directory identity — `(dev, ino)`, not paths.** This catches what layer
//!    1 cannot: a bind mount makes one directory reachable at two unrelated
//!    paths with *no symlink anywhere*, and a canonicalised-path set sees two
//!    distinct strings and descends twice. Hard links to directories, where a
//!    platform permits them, land here too.
//!
//! Layer 1 alone would satisfy the letter of the deliverable. Layer 2 is there
//! because "no cycles exist because we never follow the one kind of link we
//! thought of" is a property that breaks the first time someone adds an
//! option to follow them.
//!
//! # `symlink_metadata`, never `metadata`
//!
//! Every stat in this module is `symlink_metadata`, which describes the link
//! itself. `metadata` follows the link and would report the *target's* size and
//! type — so a 4-byte symlink pointing at a 40 GB file would look like a 40 GB
//! tiering candidate, and the floors would never see a symlink to refuse.
//!
//! # What the walker does not do
//!
//! It does not normalise paths. `norm_key` is computed catalog-side from the
//! root's probed policy (§4.9), and baking one normalization into a layer that
//! serves every root would be exactly the assumption §4.9 forbids.
//!
//! It does not hash. §6 makes BLAKE3 its own job class, "never a scan
//! prerequisite" — a full pass over 50 TB would otherwise gate cataloguing
//! behind days of I/O. Emitted rows carry `blake3: None`.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use shepherd_core::{FileStat, RootId, Timestamp};

use crate::denylist::{DenyList, DenyReason};
use crate::ignore::IgnoreSet;

/// Identity of a directory, for cycle detection.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum DirId {
    /// `(dev, ino)` — the real thing.
    Inode(u64, u64),
    /// Fallback where the platform does not expose inodes. Weaker: it catches
    /// symlink loops but not bind-mount aliases.
    Canonical(PathBuf),
}

/// Why the walker skipped something. Reported rather than swallowed, so a scan
/// summary can say what it did not look at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Skip {
    Denied {
        path: PathBuf,
        reason: DenyReason,
    },
    /// A directory already visited under another path. Reported because a cycle
    /// in a user's tree is worth surfacing, not silently absorbing.
    Cycle {
        path: PathBuf,
    },
    /// Excluded by the user's ignore patterns (AC-9).
    Ignored {
        path: PathBuf,
    },
    /// A symlinked directory. Emitted as an entry, never descended: its
    /// contents belong to whatever it points at, which is either outside the
    /// root or already walked. This is also the absolute guarantee against a
    /// symlink cycle — no symlink is ever followed, so no loop can form.
    SymlinkedDir {
        path: PathBuf,
    },
    Unreadable {
        path: PathBuf,
        detail: String,
    },
}

/// One scan's output.
#[derive(Debug, Default)]
pub struct WalkOutput {
    pub files: Vec<FileStat>,
    pub skipped: Vec<Skip>,
    pub dirs_visited: usize,
}

/// Walk `root`, emitting one [`FileStat`] per regular file and per symlink.
///
/// Symlinks are **emitted, not followed**: the floors refuse them (AC-8), and
/// the catalog is better off knowing a link exists than silently missing it.
/// Symlinked *directories* are not descended — their contents belong to
/// whatever they point at, which is either outside the root or already walked.
pub fn walk(
    root_id: RootId,
    root: &Path,
    deny: &DenyList,
    ignores: &IgnoreSet,
    now: Timestamp,
) -> std::io::Result<WalkOutput> {
    let mut out = WalkOutput::default();
    let mut seen: HashSet<DirId> = HashSet::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    if let Some(id) = dir_id(root) {
        seen.insert(id);
    }

    while let Some(dir) = stack.pop() {
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) => {
                out.skipped.push(Skip::Unreadable {
                    path: dir,
                    detail: e.to_string(),
                });
                continue;
            }
        };
        out.dirs_visited += 1;

        for entry in entries {
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    out.skipped.push(Skip::Unreadable {
                        path: dir.clone(),
                        detail: e.to_string(),
                    });
                    continue;
                }
            };
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();

            // `symlink_metadata`: describe the entry, not what it points at.
            let md = match std::fs::symlink_metadata(&path) {
                Ok(m) => m,
                Err(e) => {
                    out.skipped.push(Skip::Unreadable {
                        path,
                        detail: e.to_string(),
                    });
                    continue;
                }
            };

            // A symlink is never followed, whatever it points at. Checked
            // before `is_dir()` because `symlink_metadata` reports a symlinked
            // directory as a symlink, and the ordering should be a decision
            // rather than an accident of which branch runs first.
            if md.is_symlink() {
                let target_is_dir = std::fs::metadata(&path)
                    .map(|m| m.is_dir())
                    .unwrap_or(false);
                if target_is_dir {
                    out.skipped.push(Skip::SymlinkedDir { path });
                    continue;
                }
            }

            if md.is_dir() {
                if let Some(reason) = deny.deny_dir(&name, &path) {
                    out.skipped.push(Skip::Denied { path, reason });
                    continue;
                }
                // Pruning, not filtering. This is what makes git's rule hold:
                // a negation cannot re-include a file whose parent directory
                // was excluded, because an excluded directory is never
                // descended and its contents are never reconsidered. The
                // matcher alone does NOT provide that — see `crate::ignore`.
                if ignores.is_ignored(&path, true) {
                    out.skipped.push(Skip::Ignored { path });
                    continue;
                }
                match dir_id(&path) {
                    Some(id) => {
                        if seen.insert(id) {
                            stack.push(path);
                        } else {
                            // Already walked under another name: a symlink loop
                            // or a bind-mount alias.
                            out.skipped.push(Skip::Cycle { path });
                        }
                    }
                    None => out.skipped.push(Skip::Unreadable {
                        path,
                        detail: "cannot identify directory for cycle detection".into(),
                    }),
                }
                continue;
            }

            // A symlink is emitted (the floors refuse it) but never descended.
            if !md.is_file() && !md.is_symlink() {
                continue; // sockets, fifos, devices
            }
            if let Some(reason) = deny.deny_file(&name) {
                out.skipped.push(Skip::Denied { path, reason });
                continue;
            }
            if ignores.is_ignored(&path, false) {
                out.skipped.push(Skip::Ignored { path });
                continue;
            }

            let Some(rel) = rel_path(root, &path) else {
                out.skipped.push(Skip::Unreadable {
                    path,
                    detail: "entry is not under the scan root".into(),
                });
                continue;
            };

            out.files.push(FileStat {
                root: root_id,
                rel_path: rel,
                size: md.len(),
                mtime: sys_time(md.modified().ok()),
                ctime: ctime_of(&md, now),
                atime: md.accessed().ok().map(|t| sys_time(Some(t))),
                // §6: hashing is its own job class, never a scan prerequisite.
                blake3: None,
            });
        }
    }

    Ok(out)
}

/// Path relative to the root, with separators left exactly as the OS gave them.
/// Normalization is the catalog's job (§4.9).
fn rel_path(root: &Path, path: &Path) -> Option<String> {
    path.strip_prefix(root)
        .ok()
        .map(|p| p.to_string_lossy().to_string())
}

fn dir_id(path: &Path) -> Option<DirId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // `metadata`, not `symlink_metadata`: we want the identity of the
        // directory being entered, which for a symlinked directory is the
        // target's. That is precisely what makes the loop detectable.
        if let Ok(md) = std::fs::metadata(path) {
            return Some(DirId::Inode(md.dev(), md.ino()));
        }
    }
    std::fs::canonicalize(path).ok().map(DirId::Canonical)
}

fn sys_time(t: Option<std::time::SystemTime>) -> Timestamp {
    t.and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|d| Timestamp::from_nanos(d.as_nanos() as i64))
        .unwrap_or(Timestamp::EPOCH)
}

/// Inode change time.
///
/// Unix reports it directly. Windows has no `ctime` in this sense — its
/// creation time is a different quantity — so the caller's scan timestamp
/// stands in, and §4.12's age fallback (`first_seen_at`) is what actually
/// protects the min-age floor there.
fn ctime_of(md: &std::fs::Metadata, fallback: Timestamp) -> Timestamp {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let _ = fallback;
        Timestamp::from_nanos(md.ctime() * 1_000_000_000 + md.ctime_nsec())
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        fallback
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let d =
                std::env::temp_dir().join(format!("shepherd-walk-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
        fn file(&self, rel: &str, bytes: &[u8]) {
            let p = self.0.join(rel);
            std::fs::create_dir_all(p.parent().unwrap()).unwrap();
            std::fs::write(p, bytes).unwrap();
        }
        fn dir(&self, rel: &str) {
            std::fs::create_dir_all(self.0.join(rel)).unwrap();
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn go(t: &Tmp, deny: &DenyList) -> WalkOutput {
        let ig = IgnoreSet::empty(&t.0).unwrap();
        walk(RootId::new(1), &t.0, deny, &ig, Timestamp::from_nanos(1)).unwrap()
    }

    fn go_ignoring(t: &Tmp, patterns: &[&str]) -> WalkOutput {
        let pats: Vec<String> = patterns.iter().map(|s| s.to_string()).collect();
        let ig = IgnoreSet::new(&t.0, &pats).unwrap();
        walk(
            RootId::new(1),
            &t.0,
            &DenyList::empty(),
            &ig,
            Timestamp::from_nanos(1),
        )
        .unwrap()
    }

    #[test]
    fn emits_regular_files_with_relative_paths_and_no_hash() {
        let t = Tmp::new("basic");
        t.file("a.txt", b"hello");
        t.file("sub/b.txt", b"world");
        let out = go(&t, &DenyList::empty());

        let mut paths: Vec<_> = out.files.iter().map(|f| f.rel_path.clone()).collect();
        paths.sort();
        assert_eq!(paths, vec!["a.txt", "sub/b.txt"]);
        assert_eq!(out.files[0].size, 5);
        assert!(
            out.files.iter().all(|f| f.blake3.is_none()),
            "hashing is its own job class, never a scan prerequisite"
        );
    }

    /// The named §6 deliverable. A symlink cycle must terminate and must not
    /// multiply emissions. It holds because the link is never followed at all,
    /// which is a stronger property than detecting the loop after entering it.
    #[cfg(unix)]
    #[test]
    fn a_symlink_cycle_terminates_without_multiplying_emissions() {
        let t = Tmp::new("cycle");
        t.dir("a/b");
        t.file("a/b/deep.txt", b"x");
        // a/b/loop -> a  : following this even once re-enters `a`.
        std::os::unix::fs::symlink(t.0.join("a"), t.0.join("a/b/loop")).unwrap();

        let out = go(&t, &DenyList::empty());

        assert_eq!(
            out.files
                .iter()
                .filter(|f| f.rel_path.ends_with("deep.txt"))
                .count(),
            1,
            "the cycle must not multiply emissions"
        );
        assert!(
            out.skipped
                .iter()
                .any(|s| matches!(s, Skip::SymlinkedDir { .. })),
            "the loop link is reported, not silently absorbed: {:?}",
            out.skipped
        );
    }

    /// Layer 2 of the guard, unit-tested directly because no test can create a
    /// bind mount without privileges. Two different paths that resolve to one
    /// directory must produce one identity — that equality is the whole
    /// mechanism, and without a test it is a claim rather than a property.
    #[cfg(unix)]
    #[test]
    fn two_paths_to_one_directory_share_an_identity() {
        let t = Tmp::new("dirid");
        t.dir("real");
        std::os::unix::fs::symlink(t.0.join("real"), t.0.join("alias")).unwrap();

        let a = dir_id(&t.0.join("real")).expect("real has an identity");
        let b = dir_id(&t.0.join("alias")).expect("alias resolves to the same dir");
        assert_eq!(
            a, b,
            "identity must be (dev, ino), not the path — otherwise a bind-mount \
             alias is walked twice"
        );

        let mut seen = HashSet::new();
        assert!(seen.insert(a));
        assert!(!seen.insert(b), "the second reach must be refused");
    }

    /// A symlink to a large file must not be reported with the target's size —
    /// that is what `metadata` would do, and it would make a 4-byte link look
    /// like a tiering candidate.
    #[cfg(unix)]
    #[test]
    fn symlinks_are_emitted_with_their_own_metadata_not_the_targets() {
        let t = Tmp::new("link");
        t.file("big.bin", &vec![0u8; 100_000]);
        std::os::unix::fs::symlink(t.0.join("big.bin"), t.0.join("link.bin")).unwrap();

        let out = go(&t, &DenyList::empty());
        let link = out
            .files
            .iter()
            .find(|f| f.rel_path == "link.bin")
            .expect("symlink is emitted");
        assert!(
            link.size < 1000,
            "symlink reported with target's size ({}) — symlink_metadata was not used",
            link.size
        );
    }

    /// A symlinked directory is reported but never descended: its contents
    /// belong to whatever it points at.
    #[cfg(unix)]
    #[test]
    fn symlinked_directories_outside_the_root_are_not_descended_twice() {
        let t = Tmp::new("dirlink");
        t.file("real/x.txt", b"x");
        t.dir("other");
        std::os::unix::fs::symlink(t.0.join("real"), t.0.join("other/alias")).unwrap();

        let out = go(&t, &DenyList::empty());
        assert_eq!(
            out.files
                .iter()
                .filter(|f| f.rel_path.ends_with("x.txt"))
                .count(),
            1,
            "the same file must not appear under both real/ and other/alias/"
        );
    }

    #[test]
    fn denied_directories_are_not_descended_and_are_reported() {
        let t = Tmp::new("deny");
        t.file("keep.txt", b"k");
        t.file(".git/objects/abc", b"g");
        t.file("node_modules/pkg/index.js", b"j");

        let out = go(&t, &DenyList::builtin());
        let paths: Vec<_> = out.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(paths, vec!["keep.txt"]);
        assert_eq!(
            out.skipped
                .iter()
                .filter(|s| matches!(s, Skip::Denied { .. }))
                .count(),
            2
        );
    }

    #[test]
    fn an_unreadable_directory_is_reported_not_fatal() {
        let t = Tmp::new("unreadable");
        t.file("ok.txt", b"o");
        let ig = IgnoreSet::empty(&t.0).unwrap();
        let out = walk(
            RootId::new(1),
            &t.0.join("does-not-exist"),
            &DenyList::empty(),
            &ig,
            Timestamp::from_nanos(1),
        )
        .unwrap();
        assert!(out.files.is_empty());
        assert!(matches!(out.skipped[0], Skip::Unreadable { .. }));
    }

    #[test]
    fn an_empty_root_yields_nothing_and_does_not_error() {
        let t = Tmp::new("empty");
        let out = go(&t, &DenyList::empty());
        assert!(out.files.is_empty());
        assert_eq!(out.dirs_visited, 1);
    }

    /// AC-9 through the walker. Pruning is what supplies git's rule that a
    /// negation cannot re-include a file under an excluded directory — the
    /// matcher alone reports that file as whitelisted (see `crate::ignore`).
    #[test]
    fn an_excluded_directory_is_pruned_so_a_negation_inside_it_does_not_apply() {
        let t = Tmp::new("ignore-prune");
        t.file("keep.txt", b"k");
        t.file("secret/keep.txt", b"s");
        t.file("secret/deep/other.txt", b"s");

        let out = go_ignoring(&t, &["secret/", "!secret/keep.txt"]);

        let paths: Vec<_> = out.files.iter().map(|f| f.rel_path.as_str()).collect();
        assert_eq!(
            paths,
            vec!["keep.txt"],
            "nothing under an excluded directory may be emitted, negation or not"
        );
        assert!(
            out.skipped
                .iter()
                .any(|s| matches!(s, Skip::Ignored { .. })),
            "the exclusion is reported: {:?}",
            out.skipped
        );
    }

    #[test]
    fn ignored_files_are_excluded_and_negations_still_work() {
        let t = Tmp::new("ignore-file");
        t.file("a.log", b"a");
        t.file("keep.log", b"k");
        t.file("b.txt", b"b");

        let out = go_ignoring(&t, &["*.log", "!keep.log"]);
        let mut paths: Vec<_> = out.files.iter().map(|f| f.rel_path.clone()).collect();
        paths.sort();
        assert_eq!(paths, vec!["b.txt", "keep.log"]);
    }
}
