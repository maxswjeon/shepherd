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

use shepherd_core::{FileStat, InodeSighting, RootId, Timestamp};

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
    /// A name this catalog cannot represent without losing it.
    ///
    /// `rel_path` is a `String` — it is a `TEXT` column with a
    /// `UNIQUE(root_id, rel_path)` on it, it is the wire type, and `norm_key`
    /// is derived from it. On Unix a filename is bytes, not UTF-8, so two
    /// distinct real files whose names contain *different* invalid sequences
    /// both render as the same replacement-character string. Catalogued, they
    /// collide on that UNIQUE and one silently overwrites the other's
    /// metadata — and neither row can reconstruct the original name for
    /// hashing, tiering or restore.
    ///
    /// Reported and skipped rather than stored lossily. Refusing costs the user
    /// a file that is not backed up and SAYS SO in the scan summary; storing it
    /// costs a file that is silently wrong about which bytes it names, on a
    /// path that later destroys originals. Representing them properly means a
    /// reversible byte encoding for `rel_path` and `norm_key`, which is a §4.9
    /// change rather than a walker one.
    Unrepresentable {
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
///
/// The deny list is applied to `root` before anything is opened — to the path
/// as given and, when the root is a symlink, to its target as well. A root that
/// is itself a denied tree, or points at one, yields no files and one
/// [`Skip::Denied`]. See [`deny_root`].
pub fn walk(
    root_id: RootId,
    root: &Path,
    deny: &DenyList,
    ignores: &IgnoreSet,
    now: Timestamp,
) -> std::io::Result<WalkOutput> {
    let mut out = WalkOutput::default();

    // AC-7 applies to the root ITSELF, not only to what is found beneath it.
    // Seeding the traversal with `root` and consulting `deny_dir` from the
    // second directory onwards left every denied tree catalogueable by
    // registering it directly — hand Shepherd a `.git`, a
    // `com~apple~CloudDocs` or a `/Library/Caches` and the list whose whole
    // job is to make those uncatalogueable was never asked.
    //
    // Checked BEFORE `read_dir`, deliberately: a denied root is not opened at
    // all, which is the fail-closed direction and also makes the answer
    // independent of whether the path happens to exist on this machine.
    //
    // Reported as a `Skip` rather than returned as an `Err`, matching how a
    // root that cannot be read is handled — the walker's contract is that a
    // bad root produces an empty output that says why, not an I/O error.
    //
    // A root with no final component (`/`, or a bare relative path) yields an
    // empty name, which matches no entry in `names` or `suffixes` while the
    // absolute-prefix comparison still runs. That is the right degradation:
    // `/` is not itself denied, but a root under `/proc` is.
    //
    // The root is also the ONE symlink this walker ever follows. Every
    // symlinked directory *inside* the walk is reported as
    // [`Skip::SymlinkedDir`] and never descended, but `read_dir` on a symlinked
    // root traverses it — so an innocent name pointing at a `.git` walked the
    // whole tree, which is the same harm the deny list exists to prevent and
    // not a separate one. Deny-checking the root's target completes the
    // walker's existing no-symlink doctrine rather than adding a second one.
    //
    // Canonicalized for the DENY DECISION ONLY. The walk root stays exactly
    // what the caller handed in, so `rel_path` and everything downstream are
    // unchanged — this is a second reading of one path for one purpose, not a
    // redefinition of the root.
    //
    // Canonicalized whenever the result DIFFERS from the literal path, not only
    // when the final component is a symlink — the same rule `dispatch::root_add`
    // applies, and it has to be applied HERE TOO rather than once at
    // registration. Roots are stored under their literal spelling, so an
    // ancestor alias can be retargeted after enrollment: `<alias>/objects`
    // pointed at a safe tree when it was registered and at a `.git` by the time
    // the scan runs. `symlink_metadata` answers about the leaf alone and
    // reports an ordinary directory in both cases, so a leaf-only check let the
    // second one through and catalogued the denied tree.
    //
    // The LITERAL check runs first and on its own, because it must not depend
    // on the path existing: `/Library/Caches` is denied on Linux, where it does
    // not exist, and `a_denied_absolute_prefix_as_the_root_is_refused_without_
    // being_opened` pins exactly that. Canonicalization needs a real path, so
    // ordering it ahead of this check would answer `Unreadable` for a root the
    // deny list has an opinion about.
    if let Some((path, reason)) = deny_root(deny, root, None) {
        out.skipped.push(Skip::Denied { path, reason });
        return Ok(out);
    }
    let canonical = match std::fs::canonicalize(root) {
        Ok(c) if c != root => Some(c),
        // Already canonical: nothing to check twice.
        Ok(_) => None,
        // Innocent by its literal name and unresolvable: not walked on the
        // strength of a check that never ran. `read_dir` can still succeed
        // after a failure here, and that window is exactly what returning
        // rather than falling through closes.
        Err(e) => {
            out.skipped.push(Skip::Unreadable {
                path: root.to_path_buf(),
                detail: format!("cannot resolve the root for the deny check: {e}"),
            });
            return Ok(out);
        }
    };
    if let Some((path, reason)) = deny_root(deny, root, canonical.as_deref()) {
        out.skipped.push(Skip::Denied { path, reason });
        return Ok(out);
    }

    let mut seen: HashSet<DirId> = HashSet::new();
    let mut stack: Vec<PathBuf> = vec![root.to_path_buf()];

    // The root's own filesystem, for the nested-mount check on every entry
    // below. See `on_root_volume`.
    let root_dev = std::fs::metadata(root).ok().and_then(|md| dev_of(&md));

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

            let rel = match rel_path(root, &path) {
                RelPath::Ok(rel) => rel,
                RelPath::NotUnderRoot => {
                    out.skipped.push(Skip::Unreadable {
                        path,
                        detail: "entry is not under the scan root".into(),
                    });
                    continue;
                }
                RelPath::NotUtf8 => {
                    out.skipped.push(Skip::Unrepresentable {
                        path,
                        detail: "the name is not valid UTF-8; the catalog stores `rel_path` as \
                                 text with a uniqueness constraint, so storing it lossily \
                                 would let it collide with another file's row"
                            .into(),
                    });
                    continue;
                }
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
                ino: sighting(&md, root_dev),
            });
        }
    }

    Ok(out)
}

/// The inode from metadata already read, never a second `stat`.
#[cfg(unix)]
fn ino_of(md: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(md.ino())
}

#[cfg(not(unix))]
fn ino_of(_md: &std::fs::Metadata) -> Option<u64> {
    None
}

/// What this walk can tell the catalog about the entry's identity.
///
/// The foreign-mount case is [`InodeSighting::ForeignVolume`] rather than
/// "no inode", and the difference is not cosmetic: a path that was scanned
/// before a nested mount covered it already HAS an `fs_id`, derived from the
/// root's volume and the inode of the file that used to be there. "No inode"
/// tells `upsert_file` to keep that, which leaves the upload and destruction
/// locks — and the rename-versus-replacement decision — keyed to a file that
/// is no longer at the path. `ForeignVolume` tells it to clear.
fn sighting(md: &std::fs::Metadata, root_dev: Option<u64>) -> InodeSighting {
    match ino_of(md) {
        Some(ino) if on_root_volume(md, root_dev) => InodeSighting::Known(ino),
        Some(_) => InodeSighting::ForeignVolume,
        None => InodeSighting::Unknown,
    }
}

/// This entry's `st_dev`, for the nested-mount check.
#[cfg(unix)]
fn dev_of(md: &std::fs::Metadata) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    Some(md.dev())
}

#[cfg(not(unix))]
fn dev_of(_md: &std::fs::Metadata) -> Option<u64> {
    None
}

/// Whether this entry lives on the same filesystem as the scan root.
///
/// The catalog pairs an inode with the ROOT's `volume_id` to form `fs_id`, and
/// an inode is unique only within its own filesystem. A registered root that
/// crosses into a nested mount therefore produced two different files with the
/// same `<root-volume>:<inode>` — colliding the very lock that serializes
/// upload against destruction — while the nested file lost the remount-stable
/// identity it was supposed to have.
///
/// So a nested-mount entry reports **no inode**, and the catalog records no
/// `fs_id` for it. Half an identity is worse than none: `fs_id` is what
/// `FileLocks` keys on and what tells a rename from a replacement, and a value
/// that names a different file is a lock that protects the wrong thing. A NULL
/// there fails closed — the destroy path requires the catalog's `fs_id`.
///
/// The file is still catalogued, listed and searchable; only its identity is
/// withheld. Giving nested mounts a real identity means resolving each file's
/// own volume id, which is `volume::volume_id` per mount point rather than per
/// root — a §4.9 change, not a walker one.
fn on_root_volume(md: &std::fs::Metadata, root_dev: Option<u64>) -> bool {
    match (dev_of(md), root_dev) {
        (Some(d), Some(r)) => d == r,
        // No device numbers on this platform: nothing to contradict, and
        // `ino_of` already answers `None` there.
        _ => true,
    }
}

/// The deny decision for the walk root, over **both** names it has.
///
/// `literal` is what the caller registered; `canonical` is its resolved target,
/// present only when the root is a symlink. Both are checked, and the order is
/// deliberate:
///
/// * **Literal first.** A link *named* `.git` pointing at ordinary data is
///   refused on its own name. The deny list is about names as much as trees —
///   `.Trash`, `System Volume Information` and `lost+found` are denied for what
///   the name means, not what the bytes are — and permitting it would regress a
///   refusal that already held before symlinks were considered at all. The two
///   directions are not symmetrically expensive either: a wrong refusal costs
///   one re-registration by the real path, a wrong permit catalogues a tree the
///   policy promises never to touch.
/// * **Canonical second**, so an innocent name pointing at a denied tree cannot
///   buy a walk of it.
///
/// The returned path is the one that was actually denied, so the reported
/// [`Skip::Denied`] names the thing the operator has to look at rather than the
/// alias they typed.
///
/// # What this does NOT close
///
/// A root reached through a symlinked *ancestor* — `/tmp/x/sub` where
/// `x -> /home/u/.git`. Canonicalizing unconditionally would not close it
/// either: [`DenyList::deny_dir`] matches `names`/`suffixes` against the FINAL
/// component only, and the final component there is `sub`. Closing it properly
/// means testing every component of the canonical path, which is a wider policy
/// decision than this one.
fn deny_root(
    deny: &DenyList,
    literal: &Path,
    canonical: Option<&Path>,
) -> Option<(PathBuf, DenyReason)> {
    if let Some(hit) = deny_any_component(deny, literal) {
        return Some(hit);
    }
    deny_any_component(deny, canonical?)
}

/// [`DenyList::deny_dir`] applied to a path **and to each of its parents**.
///
/// The leaf alone is not the question. `<repo>/.git/objects` has an innocent
/// final component and is inside a denied tree, and after canonicalization that
/// is exactly the shape an aliased root takes: the alias resolves to a path
/// whose *ancestor* is the `.git`, never its last component. A leaf-only check
/// therefore passed the resolved path it had just gone to the trouble of
/// resolving.
///
/// `Path::ancestors` yields the path itself first and each parent after it, so
/// the **deepest** match is reported — `/repo/.git/objects` names `/repo/.git`,
/// the directory the rule is actually about. Each ancestor is passed as its own
/// `abs`, so the absolute-prefix rules are asked the question they are phrased
/// for ("is THIS directory inside `/proc`") rather than being re-asked about
/// the leaf every time. The filesystem root yields an empty component, which
/// matches no name or suffix while the prefix comparison still runs.
///
/// Public because `shepherd-daemon`'s registration boundary asks the identical
/// question about the identical paths, and two copies of a safety predicate is
/// two chances to answer differently.
pub fn deny_any_component(deny: &DenyList, path: &Path) -> Option<(PathBuf, DenyReason)> {
    path.ancestors().find_map(|a| {
        let component = a
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();
        deny.deny_dir(&component, a).map(|r| (a.to_path_buf(), r))
    })
}

/// Why a path has no `rel_path`, so the two reasons stay distinguishable.
enum RelPath {
    Ok(String),
    NotUnderRoot,
    /// Not valid UTF-8. See [`Skip::Unrepresentable`] — `to_string_lossy` here
    /// mapped distinct real filenames onto one string, and the catalog's
    /// `UNIQUE(root_id, rel_path)` then merged two files into one row.
    NotUtf8,
}

/// Path relative to the root, with separators left exactly as the OS gave them.
/// Normalization is the catalog's job (§4.9).
fn rel_path(root: &Path, path: &Path) -> RelPath {
    let Ok(rel) = path.strip_prefix(root) else {
        return RelPath::NotUnderRoot;
    };
    match rel.to_str() {
        Some(s) => RelPath::Ok(s.to_string()),
        None => RelPath::NotUtf8,
    }
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

/// A filesystem timestamp as nanoseconds since the epoch, **clamped** rather
/// than wrapped.
///
/// `Duration::as_nanos` is a `u128` and `Timestamp` is an `i64`, so any mtime
/// after 2262 overflowed the `as i64` cast — and the wrap does not merely
/// report a wrong date, it reports the OPPOSITE one. A file dated 2300 became
/// a large negative timestamp, i.e. apparently ancient, and `match.rs` computes
/// age as `now - at`: an `mtime_older_than_days` rule would then match a
/// future-dated file and, once tiering is served, authorise destroying it. This
/// is the same conversion `restore.rs::from_system_time` already got right.
///
/// `None` — the platform or the filesystem did not report the time at all —
/// stays [`Timestamp::EPOCH`], which is a different statement from "before the
/// epoch" and is what the caller has always meant by it.
fn sys_time(t: Option<std::time::SystemTime>) -> Timestamp {
    let Some(t) = t else {
        return Timestamp::EPOCH;
    };
    match t.duration_since(std::time::UNIX_EPOCH) {
        Ok(d) => Timestamp::from_nanos(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)),
        // Before the epoch. Genuinely old, and saying so is safe in the
        // direction that matters: an age computed from it is large and
        // positive, which is what such a file is.
        Err(e) => {
            Timestamp::from_nanos(i64::try_from(e.duration().as_nanos()).map_or(i64::MIN, |n| -n))
        }
    }
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
        // Saturating for the same reason `sys_time` clamps: `ctime` is seconds
        // and the multiply overflows `i64` past 2262, which in release wraps to
        // a timestamp of the opposite sign.
        Timestamp::from_nanos(
            md.ctime()
                .saturating_mul(1_000_000_000)
                .saturating_add(md.ctime_nsec()),
        )
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
        /// A fixture root under the build directory, **not** under
        /// `std::env::temp_dir()`.
        ///
        /// Every test in this module hands its fixture to `DenyList::builtin()`,
        /// and on macOS `$TMPDIR` is `/var/folders/…`, whose canonical form is
        /// `/private/var/…` — which that list denies as a `SystemPath`, and
        /// correctly so. Under a temp-dir fixture the accepting tests then
        /// failed for a reason that had nothing to do with what they measure,
        /// and the refusing ones passed for the same wrong reason, which is
        /// worse: they would have gone on passing with the rule they exist to
        /// pin deleted.
        ///
        /// `target/` is inside the workspace, so it is denied by nothing on any
        /// of the three platforms, and it is already the directory Cargo hands
        /// integration tests through `CARGO_TARGET_TMPDIR` — which unit tests
        /// inside `src/` do not get, hence deriving it here.
        fn new(tag: &str) -> Self {
            let base = match std::env::var_os("CARGO_TARGET_DIR") {
                Some(dir) => PathBuf::from(dir),
                None => PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("..")
                    .join("..")
                    .join("target"),
            };
            let d = base
                .join("walk-fixtures")
                .join(format!("shepherd-walk-{}-{tag}", std::process::id()));
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

    /// Walk an arbitrary path as the registered root, rather than the temp
    /// directory itself. The deny list's treatment of the root is only
    /// observable this way.
    fn go_root(root: &Path, deny: &DenyList) -> WalkOutput {
        let ig = IgnoreSet::empty(root).unwrap();
        walk(RootId::new(1), root, deny, &ig, Timestamp::from_nanos(1)).unwrap()
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
        // `rel_path` documents "separators left exactly as the OS gave them",
        // and normalisation is the catalog's job (§4.9). So the expectation is
        // built with the OS separator rather than a hardcoded `/`: the previous
        // literal asserted a POSIX layout as though it were the contract, passed
        // on unix, and failed on Windows against a function behaving exactly as
        // documented. A test that contradicts the doc comment of the function it
        // covers is testing its author's assumption, not the code.
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(paths, vec!["a.txt".to_string(), format!("sub{sep}b.txt")]);
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    #[cfg(unix)]
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
    /// AC-7 promises certain trees are never catalogued. That promise held only
    /// for *children*: the traversal was seeded with the root and `deny_dir`
    /// was consulted from the second directory onwards, so registering the
    /// denied tree itself walked it in full.
    ///
    /// The three shapes are tested separately because they take three different
    /// routes through `DenyList::deny_dir` — an exact component name, a foreign
    /// sync-engine name, and an absolute prefix — and one cannot stand for the
    /// others.
    #[test]
    fn a_denied_component_as_the_root_is_refused_rather_than_walked() {
        let t = Tmp::new("deny-root-component");
        t.file(".git/objects/abc", b"g");
        let root = t.0.join(".git");

        let out = go_root(&root, &DenyList::builtin());

        assert!(
            out.files.is_empty(),
            "a root that IS the denied tree must yield nothing: {:?}",
            out.files
        );
        assert_eq!(out.dirs_visited, 0, "a denied root must not even be opened");
        assert_eq!(
            out.skipped,
            vec![Skip::Denied {
                path: root,
                reason: DenyReason::VersionControl,
            }],
            "the refusal is reported, not silent"
        );
    }

    /// The foreign-sync case, and the one with the worst failure mode: two sync
    /// engines both believing they decide whether the bytes are local.
    #[test]
    fn a_foreign_sync_tree_registered_as_the_root_is_refused() {
        let t = Tmp::new("deny-root-sync");
        t.file("com~apple~CloudDocs/Documents/notes.txt", b"n");
        let root = t.0.join("com~apple~CloudDocs");

        let out = go_root(&root, &DenyList::builtin());

        assert!(out.files.is_empty(), "{:?}", out.files);
        assert_eq!(
            out.skipped,
            vec![Skip::Denied {
                path: root,
                reason: DenyReason::ForeignSyncRoot,
            }]
        );
    }

    /// The absolute-prefix route. No fixture: the guard runs *before*
    /// `read_dir`, so the answer does not depend on this machine having a
    /// `/Library/Caches`. That is also what the assertion pins — a guard placed
    /// after the open would report `Unreadable` here instead, on the very
    /// platform where the path is real.
    #[test]
    fn a_denied_absolute_prefix_as_the_root_is_refused_without_being_opened() {
        let root = PathBuf::from("/Library/Caches");

        let out = go_root(&root, &DenyList::builtin());

        assert_eq!(out.dirs_visited, 0);
        assert_eq!(
            out.skipped,
            vec![Skip::Denied {
                path: root,
                reason: DenyReason::SystemPath,
            }]
        );
    }

    /// The accepting direction, and the reason it is not optional: a guard that
    /// refuses every root would pass all three tests above. `denylist::
    /// a_substring_is_not_a_component` fixed the same mistake one layer down —
    /// matching is on components, so `mygit` and `.gitignore` are the user's.
    #[test]
    fn a_root_that_merely_contains_a_denied_string_still_walks() {
        let t = Tmp::new("deny-root-substring");
        t.file("mygit/a.txt", b"a");
        t.file(".gitignore/b.txt", b"b");

        for name in ["mygit", ".gitignore"] {
            let root = t.0.join(name);
            let out = go_root(&root, &DenyList::builtin());
            assert_eq!(
                out.files.len(),
                1,
                "`{name}` is the user's directory, not a denied one: {:?} {:?}",
                out.files,
                out.skipped
            );
            assert!(out.skipped.is_empty(), "{:?}", out.skipped);
            assert_eq!(out.dirs_visited, 1);
        }
    }
    /// The hole the root-component guard did not close, and it is the same
    /// finding: "the user can register and tier exactly the version-control,
    /// foreign-sync, or system tree the built-in policy promises never to
    /// catalogue." An innocent *name* pointing at a denied tree did exactly
    /// that.
    ///
    /// The root is the ONE symlink this walker follows — `read_dir` traverses
    /// it, while every symlinked directory inside the walk is reported as
    /// `Skip::SymlinkedDir` and never descended. So it is the one link whose
    /// target has to meet the deny list.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_root_pointing_at_a_denied_tree_is_refused() {
        let t = Tmp::new("deny-root-symlink-vcs");
        t.file(".git/objects/abc", b"g");
        let link = t.0.join("innocent");
        std::os::unix::fs::symlink(t.0.join(".git"), &link).unwrap();

        let out = go_root(&link, &DenyList::builtin());

        assert!(
            out.files.is_empty(),
            "an innocent name must not buy a walk of a denied tree: {:?}",
            out.files
        );
        assert_eq!(out.dirs_visited, 0);
        // The RESOLVED path is reported, not the link: the operator needs to
        // see what their root actually is.
        assert_eq!(
            out.skipped,
            vec![Skip::Denied {
                path: std::fs::canonicalize(t.0.join(".git")).unwrap(),
                reason: DenyReason::VersionControl,
            }]
        );
    }

    /// The foreign-sync shape through the same route.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_root_pointing_at_a_foreign_sync_tree_is_refused() {
        let t = Tmp::new("deny-root-symlink-sync");
        t.file("com~apple~CloudDocs/Documents/notes.txt", b"n");
        let link = t.0.join("my-cloud");
        std::os::unix::fs::symlink(t.0.join("com~apple~CloudDocs"), &link).unwrap();

        let out = go_root(&link, &DenyList::builtin());

        assert!(out.files.is_empty(), "{:?}", out.files);
        assert_eq!(
            out.skipped,
            vec![Skip::Denied {
                path: std::fs::canonicalize(t.0.join("com~apple~CloudDocs")).unwrap(),
                reason: DenyReason::ForeignSyncRoot,
            }]
        );
    }

    /// The other direction of the same question: a link *named* `.git` whose
    /// target is ordinary data. Refused, on the link's own name.
    ///
    /// The deny list is about names as much as trees — `.Trash`,
    /// `System Volume Information` and `lost+found` are denied because of what
    /// the name means, not what the bytes are. Permitting this would also
    /// *regress* a refusal that already holds, since the literal check reads
    /// `root.file_name()` whether or not the root is a link. And the two
    /// directions are not symmetrically expensive: a wrong refusal costs one
    /// re-registration by the real path, a wrong permit catalogues a tree the
    /// policy promises never to touch.
    #[cfg(unix)]
    #[test]
    fn a_root_link_named_for_a_denied_tree_is_refused_on_its_own_name() {
        let t = Tmp::new("deny-root-symlink-name");
        t.file("ordinary/a.txt", b"a");
        let link = t.0.join(".git");
        std::os::unix::fs::symlink(t.0.join("ordinary"), &link).unwrap();

        let out = go_root(&link, &DenyList::builtin());

        assert!(out.files.is_empty(), "{:?}", out.files);
        assert_eq!(
            out.skipped,
            vec![Skip::Denied {
                path: link,
                reason: DenyReason::VersionControl,
            }],
            "the LINK's path is reported: it is the link's own name that was denied"
        );
    }

    /// The third shape, and the one that cannot be built here: `canonicalize`
    /// requires the target to exist, and `/Library/Caches` does not exist on
    /// Linux. So the decision is exercised directly — which is why it is a
    /// function rather than an inline block.
    ///
    /// This also pins the ordering and both accepting directions in one place.
    #[test]
    fn the_root_deny_decision_reads_both_names_and_prefers_the_literal() {
        let d = DenyList::builtin();
        let pb = PathBuf::from;

        // Innocent name, denied absolute prefix behind it.
        assert_eq!(
            deny_root(&d, &pb("/home/u/cache"), Some(&pb("/Library/Caches"))),
            Some((pb("/Library/Caches"), DenyReason::SystemPath)),
            "the resolved target is what gets reported"
        );

        // Denied name, innocent target: the literal wins, and reports the
        // literal path.
        assert_eq!(
            deny_root(&d, &pb("/home/u/.git"), Some(&pb("/mnt/big/ordinary"))),
            Some((pb("/home/u/.git"), DenyReason::VersionControl))
        );

        // Accepting: innocent both ways — the `~/data -> /mnt/big/data` case
        // that must keep working.
        assert_eq!(
            deny_root(&d, &pb("/home/u/data"), Some(&pb("/mnt/big/data"))),
            None
        );

        // Accepting: a plain directory has no target to consult.
        assert_eq!(deny_root(&d, &pb("/home/u/data"), None), None);

        // Round 1's component rule survives the second reading: a substring is
        // still not a component, on either name.
        assert_eq!(
            deny_root(&d, &pb("/home/u/mygit"), Some(&pb("/mnt/mygit"))),
            None
        );
    }

    /// A symlinked root whose target does not resolve. Reported rather than
    /// walked: `read_dir` can still succeed after `canonicalize` fails, and
    /// falling through would leave a window where the walk proceeds on the
    /// strength of a deny check that never ran.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_root_that_will_not_resolve_is_reported_not_walked() {
        let t = Tmp::new("deny-root-symlink-dangling");
        let link = t.0.join("dangling");
        std::os::unix::fs::symlink(t.0.join("nowhere"), &link).unwrap();

        let out = go_root(&link, &DenyList::builtin());

        assert!(out.files.is_empty());
        assert_eq!(out.dirs_visited, 0);
        match &out.skipped[..] {
            [Skip::Unreadable { path, detail }] => {
                assert_eq!(path, &link);
                assert!(
                    detail.contains("deny check"),
                    "the reason must name what could not be decided: {detail}"
                );
            }
            other => panic!("expected one Unreadable, got {other:?}"),
        }
    }

    /// A denied tree reached through a symlinked ANCESTOR is refused at SCAN
    /// time, not only at registration.
    ///
    /// Roots are stored under their literal spelling, so an ancestor alias can
    /// be retargeted after enrollment: `<alias>/objects` pointed somewhere
    /// harmless when the user registered it and at a `.git` by the time the
    /// scan runs. `symlink_metadata` answers about the LEAF, which is an
    /// ordinary directory in both cases, so the walk's leaf-only check let the
    /// retargeted one through and catalogued the denied tree — registration
    /// having done the right thing once, months earlier, on a different target.
    #[cfg(unix)]
    #[test]
    fn a_root_under_a_retargeted_symlinked_ancestor_is_refused_at_scan_time() {
        let t = Tmp::new("ancestor-retarget");
        t.file("safe/objects/a.txt", b"a");
        t.file("repo/.git/objects/pack.idx", b"idx");

        let alias = t.0.join("alias");
        std::os::unix::fs::symlink(t.0.join("safe"), &alias).unwrap();
        let root = alias.join("objects");

        // As registered: innocent, and walked.
        let out = go_root(&root, &DenyList::builtin());
        assert_eq!(out.files.len(), 1, "{:?}", out.skipped);
        assert!(out.skipped.is_empty(), "{:?}", out.skipped);

        // The alias is repointed at a `.git`. The literal root string has not
        // changed, and neither has the leaf's own type.
        std::fs::remove_file(&alias).unwrap();
        std::os::unix::fs::symlink(t.0.join("repo/.git"), &alias).unwrap();
        assert!(
            !std::fs::symlink_metadata(&root).unwrap().is_symlink(),
            "the leaf must be an ordinary directory, or this tests the old path"
        );

        let out = go_root(&root, &DenyList::builtin());
        assert!(
            out.files.is_empty(),
            "a `.git` reached through a retargeted alias was catalogued: {:?}",
            out.files
        );
        assert!(
            matches!(
                out.skipped.as_slice(),
                [Skip::Denied {
                    reason: DenyReason::VersionControl,
                    ..
                }]
            ),
            "{:?}",
            out.skipped
        );
    }

    /// Two files whose names are different invalid UTF-8 are not catalogued as
    /// one file.
    ///
    /// `to_string_lossy` maps every invalid byte to U+FFFD, so distinct real
    /// filenames collapse to the same `rel_path` — and the catalog's
    /// `UNIQUE(root_id, rel_path)` then merges them, one file silently
    /// overwriting the other's metadata, with neither row able to reconstruct
    /// the original name for hashing, tiering or restore.
    ///
    /// Refused and REPORTED rather than stored lossily: a file that is not
    /// backed up and says so is recoverable by a human; a row that is silently
    /// wrong about which bytes it names is on the path that later destroys
    /// originals.
    #[cfg(unix)]
    #[test]
    fn names_that_are_not_utf8_are_skipped_rather_than_merged() {
        use std::os::unix::ffi::OsStrExt;

        let t = Tmp::new("nonutf8");
        // Two DIFFERENT invalid sequences. Both render as the same lossy
        // string, which is the whole bug.
        let a = t.0.join(std::ffi::OsStr::from_bytes(b"bad-\xff.bin"));
        let b = t.0.join(std::ffi::OsStr::from_bytes(b"bad-\xfe.bin"));
        std::fs::write(&a, b"a").unwrap();
        std::fs::write(&b, b"b").unwrap();
        assert_eq!(
            a.to_string_lossy(),
            b.to_string_lossy(),
            "the fixture must actually collide under lossy conversion, or this tests nothing"
        );
        // And one ordinary file, so the walk is not simply refusing everything.
        t.file("fine.txt", b"ok");

        let out = go(&t, &DenyList::builtin());

        let paths: Vec<_> = out.files.iter().map(|f| f.rel_path.clone()).collect();
        assert_eq!(
            paths,
            vec!["fine.txt".to_string()],
            "a name the catalog cannot represent must not be catalogued: {paths:?}"
        );
        let unrepresentable: Vec<_> = out
            .skipped
            .iter()
            .filter(|s| matches!(s, Skip::Unrepresentable { .. }))
            .collect();
        assert_eq!(
            unrepresentable.len(),
            2,
            "both must be reported, or the user cannot know what was left out: {:?}",
            out.skipped
        );
    }

    /// A far-future filesystem timestamp clamps instead of wrapping into the
    /// past.
    ///
    /// `Duration::as_nanos` is a `u128`; `Timestamp` is an `i64`. The `as i64`
    /// cast turned an mtime after 2262 into a large NEGATIVE value — not a
    /// wrong date but the opposite one — and `match.rs` computes age as
    /// `now - at`, so an `mtime_older_than_days` rule would match a
    /// future-dated file and, once tiering is served, authorise destroying it.
    #[test]
    fn a_far_future_timestamp_clamps_rather_than_wrapping_negative() {
        // Year ~2300, comfortably past the i64-nanosecond ceiling of 2262.
        let far = std::time::UNIX_EPOCH + std::time::Duration::from_secs(10_400_000_000);
        let t = sys_time(Some(far));
        assert!(
            t.as_nanos() > 0,
            "a file dated 2300 must not read as ancient: {}",
            t.as_nanos()
        );
        assert_eq!(t.as_nanos(), i64::MAX, "and it clamps at the ceiling");

        // The representable range is untouched.
        let ordinary = std::time::UNIX_EPOCH + std::time::Duration::from_secs(1_700_000_000);
        assert_eq!(
            sys_time(Some(ordinary)).as_nanos(),
            1_700_000_000_000_000_000
        );

        // No time at all is still EPOCH, which is a different statement from
        // "before the epoch".
        assert_eq!(sys_time(None), Timestamp::EPOCH);
    }

    /// A file on a NESTED MOUNT reports no inode, so the catalog records no
    /// `fs_id` for it.
    ///
    /// The catalog pairs this inode with the ROOT's `volume_id`, and an inode
    /// is unique only within its own filesystem — so a root that crosses into
    /// another mount produced two different files with one
    /// `<root-volume>:<inode>`, colliding the lock that serializes upload
    /// against destruction, while the nested file lost the remount-stable
    /// identity it was supposed to have.
    ///
    /// Driven against a real mount boundary where one is available and skipped
    /// where it is not: `/proc` is a different filesystem on every Linux host
    /// and needs no privileges to observe. The check under test is a `st_dev`
    /// comparison, so any second filesystem exercises it.
    #[cfg(target_os = "linux")]
    #[test]
    fn a_file_on_a_nested_mount_carries_no_inode() {
        let t = Tmp::new("nested-mount");
        t.file("own.txt", b"mine");

        let root_dev = dev_of(&std::fs::metadata(&t.0).unwrap()).unwrap();
        let proc_dev = match std::fs::metadata("/proc/self/status") {
            Ok(md) => dev_of(&md).unwrap(),
            // No /proc: nothing to compare against.
            Err(_) => return,
        };
        if proc_dev == root_dev {
            return; // the fixture and /proc share a filesystem: nothing to test
        }

        // The root's own file keeps its inode.
        let out = go(&t, &DenyList::builtin());
        let own = out
            .files
            .iter()
            .find(|f| f.rel_path.ends_with("own.txt"))
            .expect("the root's own file is walked");
        assert!(
            matches!(own.ino, InodeSighting::Known(_)),
            "a file on the root's own filesystem must carry its identity"
        );

        // And the predicate itself refuses a foreign device, which is the one
        // decision the catalog depends on.
        let foreign = std::fs::metadata("/proc/self/status").unwrap();
        assert!(
            !on_root_volume(&foreign, Some(root_dev)),
            "an entry on another filesystem must not be stamped with the root's volume"
        );
        assert!(
            on_root_volume(
                &std::fs::metadata(t.0.join("own.txt")).unwrap(),
                Some(root_dev)
            ),
            "and one on the root's own filesystem must be"
        );
    }

    /// The accepting direction, and the lead's explicit prohibition: registering
    /// through a symlink is legitimate and common (`~/data -> /mnt/big/data`).
    /// "Refuse every symlinked root" would pass all three refusal tests above.
    #[cfg(unix)]
    #[test]
    fn an_innocent_symlinked_root_still_walks() {
        let t = Tmp::new("deny-root-symlink-ok");
        t.file("real/a.txt", b"a");
        t.file("real/sub/b.txt", b"b");
        let link = t.0.join("data");
        std::os::unix::fs::symlink(t.0.join("real"), &link).unwrap();

        let out = go_root(&link, &DenyList::builtin());

        let mut paths: Vec<_> = out.files.iter().map(|f| f.rel_path.clone()).collect();
        paths.sort();
        let sep = std::path::MAIN_SEPARATOR;
        assert_eq!(
            paths,
            vec!["a.txt".to_string(), format!("sub{sep}b.txt")],
            "skipped={:?}",
            out.skipped
        );
        // The walk root stayed the caller's path, so `rel_path` is relative to
        // the LINK. Canonicalization is for the deny decision only.
        assert!(out.skipped.is_empty(), "{:?}", out.skipped);
    }
}
