//! Stable volume identity and `fs_id` (§4.4, §4.9, PM-3 #2).
//!
//! `file.fs_id` pairs an inode with a **stable volume identifier**. §4.4 states
//! the prohibition in capitals: **NEVER `st_dev`**.
//!
//! Why it matters more than it looks. `st_dev` is assigned by the kernel at
//! mount time and is not stable across remounts — unplug a USB disk and plug it
//! back in and it can differ. If `fs_id` embedded `st_dev`, every row under that
//! root would stop matching its file after a remount. The catalog would then see
//! a root full of files it has no rows for, and rows whose files it cannot find
//! — and "a row whose file cannot be found" is exactly the false absence PM-3
//! calls discard-trigger territory. A removable disk being replugged must not be
//! able to look like the user deleted everything on it.
//!
//! # Platform coverage, stated plainly
//!
//! Linux is implemented and tested here. Windows and macOS compile on every CI
//! leg and return [`VolumeError::Unsupported`] — they are Phase 3 work
//! (`FILE_ID_INFO` + volume serial on Windows, `getattrlist` volume UUID on
//! macOS). A stub that returned a *plausible* id would be worse than one that
//! refuses: it would let a root enroll with an identity that silently fails to
//! survive a remount.

use std::path::Path;

use shepherd_core::FsId;

#[derive(Debug, thiserror::Error)]
pub enum VolumeError {
    #[error("cannot stat {path}: {detail}")]
    Stat { path: String, detail: String },
    #[error("no stable volume identifier for {path}: {detail}")]
    NoStableId { path: String, detail: String },
    #[error("stable volume identity is not implemented on this platform yet ({0})")]
    Unsupported(&'static str),
}

pub type Result<T> = std::result::Result<T, VolumeError>;

/// A stable, remount-surviving identifier for the volume containing `path`.
///
/// On Linux this is the filesystem UUID, resolved by matching the path's mount
/// point against `/proc/self/mountinfo` and then the mount source against
/// `/dev/disk/by-uuid`.
pub fn volume_id(path: &Path) -> Result<String> {
    #[cfg(target_os = "linux")]
    {
        linux::volume_id(path)
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = path;
        Err(VolumeError::Unsupported(std::env::consts::OS))
    }
}

/// `(volume_id, inode)` packed for storage in `file.fs_id`.
///
/// Rendered as `"<volume_id>:<inode>"`. Both halves are needed: an inode alone
/// is only unique within one filesystem, and a volume alone identifies no file.
pub fn fs_id(path: &Path, volume_id: &str) -> Result<FsId> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(path).map_err(|e| VolumeError::Stat {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        Ok(fs_id_from_ino(volume_id, md.ino()))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, volume_id);
        Err(VolumeError::Unsupported(std::env::consts::OS))
    }
}

/// A directory's own identity, for a root whose volume may have no id.
///
/// `fs_id` needs a volume id because a file's identity has to be unique across
/// volumes. A registered ROOT is a different question — "is this still the
/// directory that was enrolled" — and the inode alone answers it: distinct per
/// directory within a filesystem, and unchanged across a remount, which is the
/// reason neither form uses `st_dev`.
///
/// So the volume qualifies the answer where it is known, and the inode carries
/// it where it is not. The unqualified form is PREFIXED so it can never compare
/// equal to a volume-qualified one: a root enrolled before a UUID appeared must
/// not look like the same root afterwards.
///
/// # What the unqualified form cannot answer
///
/// An inode is unique **within one filesystem**, so `ino-only:` answers "is
/// this still the same directory *on the same filesystem*" and nothing more.
/// At a MOUNT POINT that is not enough: the inode is then the filesystem's own
/// root inode, drawn from a tiny reused set — `2` on ext4, `1` on many others
/// — so an unrelated no-id filesystem (tmpfs, overlay, some FUSE) mounted at
/// the enrolled path can produce the identical value and be accepted as the
/// enrolled root. Claiming a match there would be worse than claiming nothing,
/// so a mount root gets `None`: **unverifiable, not verified**.
///
/// Only the unqualified form degrades. Where a volume id is known it is what
/// distinguishes filesystems, and a mount root is perfectly identifiable.
///
/// `None` off unix, and where the directory cannot be stat'd. That is the same
/// posture `fs_id` takes — Windows needs `FILE_ID_INFO` and that lands with the
/// rest of the platform in Phase 3 — so a caller gets "unknown", never a wrong
/// answer.
pub fn directory_identity(path: &Path, volume_id: Option<&str>) -> Option<String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let md = std::fs::metadata(path).ok()?;
        match volume_id {
            Some(vol) => Some(fs_id_from_ino(vol, md.ino()).as_str().to_owned()),
            None if is_mount_root(path, &md) => None,
            None => Some(format!("ino-only:{}", md.ino())),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, volume_id);
        None
    }
}

/// Is `path` the root of a mounted filesystem?
///
/// `mountpoint(1)`'s rule, both halves. The familiar one is that `..` crosses
/// back into the parent filesystem, so the devices differ. The second is what
/// makes it correct at `/`, where `..` IS `/` — same device, same inode — and
/// a device comparison alone reports the one filesystem root that matters most
/// as an ordinary directory.
///
/// `st_dev` is read here and never stored. §4.4's prohibition is on building an
/// **identity** out of it, because it does not survive a remount; comparing two
/// devices observed a microsecond apart asks a question that does not outlive
/// the call, which is the same thing the scan's `dev_before`/`dev_after` guard
/// does.
#[cfg(unix)]
fn is_mount_root(path: &Path, md: &std::fs::Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    // Unreadable parent: treat it as a mount root, because the question could
    // not be answered and this function's `false` is the answer that mints an
    // identity.
    let Ok(parent) = std::fs::metadata(path.join("..")) else {
        return true;
    };
    md.dev() != parent.dev() || md.ino() == parent.ino()
}

/// The same packing, from an inode already in hand.
///
/// The scan reads `st_ino` while it is walking, and the catalog write happens
/// inside the single-writer actor, which must not touch the filesystem. One
/// function so the two producers cannot disagree about the format — a mismatch
/// there is silent, and `FileLocks` keys on this string.
pub fn fs_id_from_ino(volume_id: &str, ino: u64) -> FsId {
    FsId::new(format!("{volume_id}:{ino}"))
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Result, VolumeError};
    use std::path::Path;

    /// One `/proc/self/mountinfo` entry, reduced to what identity needs.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) struct MountEntry {
        pub mount_point: String,
        pub source: String,
        pub fs_type: String,
        pub options: String,
        pub super_options: String,
    }

    /// Parse `/proc/self/mountinfo`.
    ///
    /// Format: fields 0..5 are fixed, then optional tagged fields, then a `-`
    /// separator, then fstype, source and super-options. The separator is why
    /// this cannot be a fixed-index split — the optional fields vary in count.
    pub(crate) fn parse_mountinfo(text: &str) -> Vec<MountEntry> {
        let mut out = Vec::new();
        for line in text.lines() {
            let Some(sep) = line.find(" - ") else {
                continue;
            };
            let (head, tail) = line.split_at(sep);
            let head: Vec<&str> = head.split_whitespace().collect();
            let tail: Vec<&str> = tail[3..].split_whitespace().collect();
            if head.len() < 6 || tail.len() < 2 {
                continue;
            }
            out.push(MountEntry {
                mount_point: unescape_octal(head[4]),
                options: head[5].to_string(),
                fs_type: tail[0].to_string(),
                source: unescape_octal(tail[1]),
                super_options: tail.get(2).unwrap_or(&"").to_string(),
            });
        }
        out
    }

    /// mountinfo escapes space, tab, newline and backslash as `\040` etc.
    ///
    /// Decoded into BYTES and converted to UTF-8 once at the end. Pushing each
    /// byte as its own `char` is a latin-1 decode: every byte above 0x7F became
    /// its own scalar, so a mount point containing `é` (`0xC3 0xA9`) came back
    /// as `Ã©`. That entry then matches no registered path, `entry_for` falls
    /// back to a parent filesystem, and the root is assigned the WRONG
    /// volume's UUID — which is the value `fs_id` pairs with an inode, so
    /// catalog locking and replacement detection end up keyed on another
    /// filesystem's identity.
    ///
    /// Lossy only at the very end, and only for a mount point that is not valid
    /// UTF-8 at all — a real possibility on Linux, where a mount point is
    /// bytes. Such an entry cannot match a `str` path anyway, so a lossy
    /// rendering costs nothing that was reachable.
    fn unescape_octal(s: &str) -> String {
        let b = s.as_bytes();
        let mut out: Vec<u8> = Vec::with_capacity(b.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\'
                && i + 3 < b.len()
                && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8)
            {
                out.push(v);
                i += 4;
                continue;
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8_lossy(&out).into_owned()
    }

    /// The mount entry governing `path`: the longest mount point that is a
    /// prefix of it. Longest wins because mounts nest — `/home` and
    /// `/home/user/data` can both be prefixes, and the deeper one governs.
    pub(crate) fn entry_for<'a>(entries: &'a [MountEntry], path: &str) -> Option<&'a MountEntry> {
        entries
            .iter()
            .filter(|e| {
                path == e.mount_point
                    || path.starts_with(&format!("{}/", e.mount_point.trim_end_matches('/')))
                    || e.mount_point == "/"
            })
            .max_by_key(|e| e.mount_point.len())
    }

    /// The `(options, super_options)` pair governing `path`, for
    /// [`crate::atime`]. Takes the mountinfo text as an argument so the caller
    /// — and the tests — decide where it came from.
    pub(crate) fn options_for(text: &str, path: &str) -> Option<(String, String)> {
        let entries = parse_mountinfo(text);
        let e = entry_for(&entries, path)?;
        Some((e.options.clone(), e.super_options.clone()))
    }

    pub(crate) fn volume_id(path: &Path) -> Result<String> {
        let canonical = path.canonicalize().map_err(|e| VolumeError::Stat {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        let text = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| {
            VolumeError::NoStableId {
                path: path.display().to_string(),
                detail: format!("cannot read /proc/self/mountinfo: {e}"),
            }
        })?;
        let entries = parse_mountinfo(&text);
        let entry = entry_for(&entries, &canonical.to_string_lossy()).ok_or_else(|| {
            VolumeError::NoStableId {
                path: path.display().to_string(),
                detail: "no mountinfo entry covers this path".into(),
            }
        })?;

        if let Some(uuid) = uuid_for_source(&entry.source) {
            return Ok(format!("uuid:{uuid}"));
        }

        // Virtual and network filesystems have no block device and therefore no
        // UUID: tmpfs, overlay, nfs, cifs, fuse. §4.4 wants a STABLE id, and for
        // these the stable thing available is the mount source plus fs type —
        // an NFS export `server:/vol` is stable across remounts in the way that
        // matters, where `st_dev` is not.
        //
        // Reported with its own scheme rather than silently blended in, so a
        // caller (and a human reading the column) can tell a UUID-backed
        // identity from a weaker one.
        Err(VolumeError::NoStableId {
            path: path.display().to_string(),
            detail: format!(
                "mount source `{}` (fstype {}) has no /dev/disk/by-uuid entry; \
                 use `volume_id_fallback` and record that this root's identity is \
                 source-derived, not UUID-derived",
                entry.source, entry.fs_type
            ),
        })
    }

    /// The weaker, explicitly-labelled identity for volumes with no UUID.
    ///
    /// Weaker, not arbitrary: it is offered only for sources that name the
    /// volume itself rather than the slot it was plugged into. An NFS export
    /// `server:/vol` and a CIFS share `//server/share` reach the same
    /// filesystem after a remount, a reboot, or from another client, which is
    /// the property §4.4 actually asks of a volume id.
    ///
    /// `/dev/loop3`, `/dev/sdb1` and `tmpfs` do not have it, and minting an id
    /// from one is worse than having none. A loop-backed or removable
    /// filesystem that momentarily has no `/dev/disk/by-uuid` entry would be
    /// enrolled as `src:ext4:/dev/loop3`; reattached under another device node
    /// it becomes `src:ext4:/dev/loop7`, every reconstructed `fs_id` stops
    /// matching the catalog rows for the same files, and the identity-based
    /// serialization that upload and destruction lock on silently stops
    /// colliding — two operations on one file each believing they hold it
    /// alone. A NULL volume id is a degradation the callers already handle; a
    /// wrong one is a lie they cannot detect.
    pub fn volume_id_fallback(path: &Path) -> Result<String> {
        let canonical = path.canonicalize().map_err(|e| VolumeError::Stat {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        let text = std::fs::read_to_string("/proc/self/mountinfo").map_err(|e| {
            VolumeError::NoStableId {
                path: path.display().to_string(),
                detail: e.to_string(),
            }
        })?;
        let entries = parse_mountinfo(&text);
        let entry = entry_for(&entries, &canonical.to_string_lossy()).ok_or_else(|| {
            VolumeError::NoStableId {
                path: path.display().to_string(),
                detail: "no mountinfo entry covers this path".into(),
            }
        })?;
        if !source_is_remount_stable(&entry.source) {
            return Err(VolumeError::NoStableId {
                path: path.display().to_string(),
                detail: format!(
                    "mount source `{}` (fstype {}) is assigned at mount time, not carried by \
                     the volume, so `src:{}:{}` would change under this root the next time it \
                     is mounted; refusing to mint an identity that silently stops matching \
                     the catalog",
                    entry.source, entry.fs_type, entry.fs_type, entry.source
                ),
            });
        }
        Ok(format!("src:{}:{}", entry.fs_type, entry.source))
    }

    /// Does this mount source name the volume, or the slot it is in?
    ///
    /// Two shapes name the volume: `//server/share` (CIFS/SMB) and
    /// `host:/export` (NFS, and `user@host:/path` for fuse.sshfs). Both encode
    /// where the data lives, so the same string reaches the same filesystem
    /// after any remount.
    ///
    /// Everything else is refused, and the refusal is deliberately the default
    /// rather than a device-path blocklist: an unrecognised source is one whose
    /// stability nobody here has reasoned about, and the safe answer for those
    /// is the NULL identity callers already degrade to. That covers device
    /// nodes (`/dev/loop3`), bind sources, and the pseudo-sources of virtual
    /// filesystems — `tmpfs` and `overlay` are not merely unstable but
    /// *ambiguous*, since every tmpfs mount on the box reports the same source
    /// and would be handed the same volume id, colliding `fs_id` across
    /// genuinely different filesystems.
    pub(crate) fn source_is_remount_stable(source: &str) -> bool {
        if let Some(rest) = source.strip_prefix("//") {
            // `//server/share`: both halves must be there. `//server` alone
            // names a host and no filesystem on it.
            return match rest.split_once('/') {
                Some((host, share)) => !host.is_empty() && !share.is_empty(),
                None => false,
            };
        }
        if source.starts_with('/') {
            // An absolute path is a device node or a bind source; both are
            // named by where they were attached this time.
            return false;
        }
        // `host:/export`. The export half must be absolute — `tmpfs` and
        // friends have no colon at all, and a colon with a relative tail is
        // not a mount source shape this understands.
        match source.split_once(':') {
            Some((host, export)) => !host.is_empty() && export.starts_with('/'),
            None => false,
        }
    }

    /// Resolve a block device to its filesystem UUID via `/dev/disk/by-uuid`,
    /// whose entries are symlinks pointing back at the device node.
    fn uuid_for_source(source: &str) -> Option<String> {
        let target = std::fs::canonicalize(source).ok()?;
        for e in std::fs::read_dir("/dev/disk/by-uuid").ok()?.flatten() {
            // A dangling link SKIPS, it does not abandon the search. `?` here
            // returned `None` for the whole directory the moment one entry
            // could not be resolved — routine during removable-device churn —
            // so a valid UUID link later in the listing was never reached.
            // Root registration then stored no volume id at all, and every file
            // under that root lost the stable identity that upload and
            // destruction lock on.
            let Ok(resolved) = std::fs::canonicalize(e.path()) else {
                continue;
            };
            if resolved == target {
                return Some(e.file_name().to_string_lossy().to_string());
            }
        }
        None
    }
}

/// The best stable identity available for `path`, or `None` if there is none.
///
/// The UUID where the filesystem has one; the labelled `src:` fallback where
/// the source names the volume itself; nothing otherwise — including on every
/// platform whose implementation is Phase 3's.
///
/// One function because two callers must not disagree about what a root's
/// identity IS. Enrollment stores this; the scan compares against it, and a
/// scan deriving the value a second way would refuse or admit roots on nothing
/// but the difference between two spellings of the same intent.
pub fn current_volume_id(path: &Path) -> Option<String> {
    match volume_id(path) {
        Ok(id) => Some(id),
        Err(VolumeError::NoStableId { .. }) => volume_id_fallback(path).ok(),
        Err(_) => None,
    }
}

#[cfg(target_os = "linux")]
pub use linux::volume_id_fallback;

#[cfg(target_os = "linux")]
pub(crate) use linux::options_for as linux_mountinfo;

/// Stub for platforms whose stable-identity implementation is Phase 3.
#[cfg(not(target_os = "linux"))]
pub fn volume_id_fallback(path: &Path) -> Result<String> {
    let _ = path;
    Err(VolumeError::Unsupported(std::env::consts::OS))
}

#[cfg(all(test, target_os = "linux"))]
mod remount_tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    /// WHY THIS TEST IS NOT "MOUNT AT TWO POINTS AND ASSERT ONE fs_id".
    ///
    /// That is the obvious shape, and it does not discriminate. Mounting one
    /// block device at two mount points gives both mounts the SAME superblock,
    /// so `st_dev` is identical at both — measured on this box, 7:0 and 7:0.
    /// An implementation that derived `fs_id` from `st_dev` — the one thing
    /// §4.4 forbids in capitals — passes that test. It would be a check that is
    /// present but not load-bearing.
    ///
    /// What §4.4 actually claims is that `st_dev` is assigned at MOUNT TIME and
    /// varies across a remount, while `fs_id` must not. So the test has to make
    /// `st_dev` actually change and assert `fs_id` did not. Detaching the
    /// loopback device and re-attaching the same backing file on a different
    /// loop number does exactly that: the filesystem UUID and the inode are
    /// on-disk and survive, the device number does not.
    ///
    /// The `st_dev` change is asserted as a PRECONDITION rather than assumed. If
    /// the remount happened to reuse the same device number, the test would be
    /// vacuous, so it fails saying the *simulation* failed rather than reporting
    /// a green it did not earn.
    ///
    /// Ignored because it needs root. §9 rule 1 forbids a gate being satisfied
    /// by a skipped test, so it is cited with `ignored = true` and run
    /// explicitly — the opposite of being skipped.
    #[test]
    #[ignore = "needs root: builds a loopback ext4 filesystem and mounts it"]
    fn fs_id_survives_a_remount_that_changes_st_dev() {
        let fixture = Fixture::new();

        // --- Leg 1: the weak property, kept because it is the row's literal
        // sentence — one filesystem at two mount points is one identity.
        let a = fixture.mount("a");
        let b = fixture.mount("b");
        let file_a = a.join(FILE);
        std::fs::write(&file_a, b"payload").expect("write into the fresh fs");
        let file_b = b.join(FILE);

        let vol_a = volume_id(&file_a).expect("volume_id at mount point a");
        let vol_b = volume_id(&file_b).expect("volume_id at mount point b");
        let id_a = fs_id(&file_a, &vol_a).expect("fs_id at mount point a");
        let id_b = fs_id(&file_b, &vol_b).expect("fs_id at mount point b");
        assert_eq!(
            id_a, id_b,
            "one filesystem reached by two mount points is one identity; the \
             mount POINT must not enter fs_id"
        );

        // The UUID is what makes that true, so assert the identity is actually
        // UUID-derived. Without this the test would pass on a weaker identity
        // it never meant to bless — and for a loop device there is now no
        // weaker identity at all, because the fallback refuses `/dev/loopN`
        // outright (see `the_fallback_refuses_a_device_path_source`).
        assert!(
            vol_a.starts_with("uuid:"),
            "expected a UUID-derived volume id, got {vol_a:?} — for a loop \
             device there is no second option, so this fixture is broken"
        );

        let dev_before = std::fs::metadata(&file_a).expect("stat before").dev();
        let ino_before = std::fs::metadata(&file_a).expect("stat before").ino();

        // --- Leg 2: the actual remount. Detach and re-attach the same backing
        // file so the kernel hands out a different device number.
        fixture.unmount_all();
        fixture.reattach_on_a_different_loop_device();
        let c = fixture.mount("c");
        let file_c = c.join(FILE);

        let dev_after = std::fs::metadata(&file_c).expect("stat after").dev();
        let ino_after = std::fs::metadata(&file_c).expect("stat after").ino();

        // THE PRECONDITION. Without this the rest is vacuous.
        assert_ne!(
            dev_before, dev_after,
            "the remount did not change st_dev ({dev_before}), so this run \
             proves nothing about remount stability — the SIMULATION failed, \
             not fs_id"
        );
        assert_eq!(
            ino_before, ino_after,
            "the inode is on-disk and must survive; if it did not, the fixture \
             is wrong rather than the code"
        );

        // --- The property §9 names.
        let vol_c = volume_id(&file_c).expect("volume_id after remount");
        let id_c = fs_id(&file_c, &vol_c).expect("fs_id after remount");
        assert_eq!(
            vol_a, vol_c,
            "volume_id changed across a remount; it is derived from the \
             filesystem UUID precisely so it cannot"
        );
        assert_eq!(
            id_a, id_c,
            "fs_id changed across a remount while st_dev went {dev_before} -> \
             {dev_after}. Every catalog row under this root would stop matching \
             its file, which PM-3 calls discard-trigger territory"
        );
    }

    /// The negative that gives the assertion above its meaning: the fallback
    /// REFUSES a device-path source, because an id derived from one would
    /// change under the very remount `fs_id` exists to survive.
    ///
    /// This test used to assert the opposite — that the fallback returned two
    /// DIFFERENT ids across the remount — and called that acceptable because
    /// the id was labelled `src:`. It is not acceptable: nothing consuming the
    /// column branches on the label, so the loop-backed root was enrolled as
    /// `src:ext4:/dev/loopN`, came back as `/dev/loopM`, and every
    /// reconstructed `fs_id` quietly stopped matching its catalog row. The
    /// label documented the hazard instead of preventing it.
    ///
    /// So the property is now the refusal, and the old assertion survives as
    /// its justification: the two ids the fallback WOULD have minted are shown
    /// to differ, which is exactly why neither is offered.
    #[test]
    #[ignore = "needs root: builds a loopback ext4 filesystem and mounts it"]
    fn the_fallback_refuses_a_device_path_source() {
        let fixture = Fixture::new();
        let a = fixture.mount("a");
        std::fs::write(a.join(FILE), b"payload").expect("write into the fresh fs");
        let dev_before = mount_source(&a.join(FILE));
        let refused = volume_id_fallback(&a.join(FILE));

        fixture.unmount_all();
        fixture.reattach_on_a_different_loop_device();
        let c = fixture.mount("c");
        let dev_after = mount_source(&c.join(FILE));

        // THE PRECONDITION. If the reattachment reused the device node, this
        // run says nothing about instability and the refusal below would be
        // asserting an unrelated thing.
        assert_ne!(
            dev_before, dev_after,
            "the reattachment reused {dev_before}, so the SIMULATION failed — \
             this run proves nothing about device-path instability"
        );

        let Err(VolumeError::NoStableId { detail, .. }) = refused else {
            panic!(
                "the fallback minted an identity from {dev_before}, which the \
                 assertion above just showed becomes {dev_after}: got {refused:?}"
            );
        };
        assert!(
            detail.contains(&dev_before),
            "the refusal must name the source it refused, got {detail:?}"
        );
    }

    /// The mount source `/proc/self/mountinfo` reports for a path.
    fn mount_source(path: &Path) -> String {
        let canonical = path.canonicalize().expect("canonicalize");
        let text = std::fs::read_to_string("/proc/self/mountinfo").expect("mountinfo");
        let entries = super::linux::parse_mountinfo(&text);
        super::linux::entry_for(&entries, &canonical.to_string_lossy())
            .expect("a mountinfo entry covers the fixture")
            .source
            .clone()
    }

    const FILE: &str = "payload.bin";

    /// Owns the image, the loop device and the mount points, and tears all of
    /// them down on unwind so a panicking assertion cannot leak a mounted
    /// filesystem or a loop device onto the machine running the suite.
    struct Fixture {
        dir: PathBuf,
        img: PathBuf,
        loop_dev: std::cell::RefCell<Option<String>>,
        parked: std::cell::RefCell<Vec<String>>,
        mounted: std::cell::RefCell<Vec<PathBuf>>,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!(
                "shepherd-fsid-{}-{:?}",
                std::process::id(),
                std::thread::current().id()
            ));
            std::fs::create_dir_all(&dir).expect("create fixture dir");
            let img = dir.join("disk.img");
            // 32 MiB is the smallest an ext4 with a sane inode table fits in.
            let f = std::fs::File::create(&img).expect("create backing file");
            f.set_len(32 * 1024 * 1024).expect("size backing file");
            drop(f);
            // No sudo needed to mkfs a plain file.
            run("/usr/sbin/mkfs.ext4", &["-q", "-F", &img.to_string_lossy()]);
            let me = Self {
                dir,
                img,
                loop_dev: std::cell::RefCell::new(None),
                parked: std::cell::RefCell::new(Vec::new()),
                mounted: std::cell::RefCell::new(Vec::new()),
            };
            *me.loop_dev.borrow_mut() = Some(me.attach());
            me
        }

        fn attach(&self) -> String {
            let out = sudo(
                "/usr/sbin/losetup",
                &["--find", "--show", &self.img.to_string_lossy()],
            );
            let dev = out.trim().to_string();
            assert!(
                dev.starts_with("/dev/loop"),
                "unexpected losetup output {out:?}"
            );
            // udev needs a moment to publish /dev/disk/by-uuid, which
            // `volume_id` resolves the source through.
            for _ in 0..50 {
                if std::path::Path::new("/dev/disk/by-uuid")
                    .read_dir()
                    .into_iter()
                    .flatten()
                    .flatten()
                    .any(|e| {
                        std::fs::canonicalize(e.path()).ok() == std::fs::canonicalize(&dev).ok()
                    })
                {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            dev
        }

        fn mount(&self, name: &str) -> PathBuf {
            let mp = self.dir.join(name);
            std::fs::create_dir_all(&mp).expect("create mount point");
            let dev = self
                .loop_dev
                .borrow()
                .clone()
                .expect("a loop device is attached");
            sudo("/usr/bin/mount", &[&dev, &mp.to_string_lossy()]);
            // The test writes as an unprivileged user into a filesystem whose
            // root is owned by root.
            sudo("/usr/bin/chmod", &["0777", &mp.to_string_lossy()]);
            self.mounted.borrow_mut().push(mp.clone());
            mp
        }

        fn unmount_all(&self) {
            for mp in self.mounted.borrow_mut().drain(..) {
                sudo("/usr/bin/umount", &[&mp.to_string_lossy()]);
            }
        }

        /// Detach and re-attach the backing file, guaranteeing a DIFFERENT loop
        /// device number — which is what makes `st_dev` change.
        ///
        /// `losetup --find` hands out the lowest free number, so re-attaching
        /// immediately would usually reclaim the number just released. The
        /// released device is therefore parked (kept attached) so the next
        /// `--find` is forced onto a different one. Deterministic, rather than
        /// relying on a race to hand us a different number.
        fn reattach_on_a_different_loop_device(&self) {
            let old = self.loop_dev.borrow().clone().expect("attached");
            sudo("/usr/sbin/losetup", &["-d", &old]);
            let mut new = self.attach();
            if new == old {
                // Reclaimed the same number. Park it; the next attach cannot
                // reuse an occupied device.
                self.parked.borrow_mut().push(new.clone());
                new = self.attach();
            }
            assert_ne!(new, old, "failed to force a different loop device");
            *self.loop_dev.borrow_mut() = Some(new);
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            for mp in self.mounted.borrow_mut().drain(..) {
                let _ = try_sudo("/usr/bin/umount", &[&mp.to_string_lossy()]);
            }
            for dev in self
                .loop_dev
                .borrow_mut()
                .take()
                .into_iter()
                .chain(self.parked.borrow_mut().drain(..))
            {
                let _ = try_sudo("/usr/sbin/losetup", &["-d", &dev]);
            }
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn run(bin: &str, args: &[&str]) -> String {
        let out = Command::new(bin)
            .args(args)
            .output()
            .unwrap_or_else(|e| panic!("cannot execute {bin}: {e}"));
        assert!(
            out.status.success(),
            "{bin} {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        String::from_utf8_lossy(&out.stdout).to_string()
    }

    /// `sudo -n`: never prompt. A test that blocked on a password would hang the
    /// suite, and one that SKIPPED on a missing password would report a green it
    /// did not earn — so a missing privilege is a loud failure.
    fn sudo(bin: &str, args: &[&str]) -> String {
        let mut a = vec!["-n", bin];
        a.extend_from_slice(args);
        run("/usr/bin/sudo", &a)
    }

    fn try_sudo(bin: &str, args: &[&str]) -> std::io::Result<std::process::Output> {
        let mut a = vec!["-n", bin];
        a.extend_from_slice(args);
        Command::new("/usr/bin/sudo").args(&a).output()
    }

    /// Keeps `Path` in scope for the signatures above without an unused import.
    #[allow(dead_code)]
    fn _typecheck(p: &Path) -> Option<&std::ffi::OsStr> {
        p.file_name()
    }
}

#[cfg(all(test, unix))]
mod identity_tests {
    use super::*;

    /// A filesystem root's inode identifies no filesystem.
    ///
    /// Root inodes are a tiny, reused set — `2` on ext4, `1` on many others —
    /// so `ino-only:` at a mount point says the same thing about every
    /// unrelated filesystem that could be mounted there. Claiming a match on
    /// it would let a swapped no-id mount (tmpfs, overlay, some FUSE) be
    /// accepted as the enrolled root, after which the scan updates the
    /// same-path rows and sweeps the rest as missing.
    #[test]
    fn a_mount_root_has_no_unqualified_identity() {
        assert_eq!(
            directory_identity(Path::new("/"), None),
            None,
            "the root of a filesystem must read as unverifiable, not as a match"
        );
    }

    /// And an ordinary directory still gets one — the retarget case the
    /// unqualified form exists for. Without this the fix above passes by
    /// returning `None` everywhere.
    #[test]
    fn an_ordinary_directory_still_has_an_unqualified_identity() {
        let dir = std::env::temp_dir().join(format!("shepherd-ident-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let id = directory_identity(&dir, None);
        std::fs::remove_dir_all(&dir).ok();
        assert!(
            id.is_some_and(|s| s.starts_with("ino-only:")),
            "a directory inside a filesystem is distinct within it, which is exactly \
             what this form is for"
        );
    }

    /// The volume-qualified form is unaffected: the volume id is what
    /// distinguishes filesystems, so a mount root is perfectly identifiable
    /// once one is known.
    #[test]
    fn a_mount_root_keeps_its_volume_qualified_identity() {
        // Asserted on the SHAPE: the root inode differs per filesystem, and
        // the point is that the volume id carries the answer the inode cannot.
        let id = directory_identity(Path::new("/"), Some("uuid:abc"))
            .expect("a volume-qualified identity does not depend on the inode being unique");
        assert!(id.starts_with("uuid:abc:"), "{id}");
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::linux::*;

    /// Which mount sources may back a `src:` volume id.
    ///
    /// The accept list is the point: an id minted from a mount-time name
    /// changes under a remount, and nothing downstream branches on the `src:`
    /// label to notice. Two of the reject cases are the ones that bite —
    /// `/dev/loopN` for a loop-backed archive disk, and `tmpfs`, whose source
    /// is not merely unstable but shared by every tmpfs on the box, so two
    /// unrelated filesystems would be handed one identity.
    #[test]
    fn only_sources_that_name_the_volume_may_back_an_identity() {
        for stable in [
            "nas:/export/photos",
            "10.0.0.4:/vol0",
            "//nas/share",
            "//nas/deep/share",
            "user@host:/srv/media",
        ] {
            assert!(
                source_is_remount_stable(stable),
                "{stable} names the volume itself and must be usable"
            );
        }
        for unstable in [
            "/dev/loop3",
            "/dev/sdb1",
            "/dev/mapper/vg-lv",
            "/srv/bind-source",
            "tmpfs",
            "overlay",
            "none",
            "cgroup2",
            "//nas",
            "//nas/",
            "//",
            "host:relative/path",
            "host:",
            ":/export",
            "",
        ] {
            assert!(
                !source_is_remount_stable(unstable),
                "{unstable} is assigned at mount time (or shared between mounts) \
                 and must not back a volume id"
            );
        }
    }

    /// A mount point with a non-ASCII character survives mountinfo decoding.
    ///
    /// The escape decoder pushed each BYTE as its own `char`, which is a
    /// latin-1 decode: `é` (`0xC3 0xA9`) came back as `Ã©`. That entry then
    /// matches no registered path, `entry_for` falls back to a parent
    /// filesystem, and the root is assigned the WRONG volume's UUID — the value
    /// `fs_id` pairs with an inode, so catalog locking and replacement
    /// detection end up keyed on another filesystem's identity.
    #[test]
    fn a_non_ascii_mount_point_is_decoded_as_utf8() {
        // `/mnt/café photos` — the space is octal-escaped by mountinfo, the
        // `é` is not.
        let text = "\
36 35 98:0 / /mnt/café\\040photos rw,relatime shared:1 - ext4 /dev/sda1 rw
";
        let entries = parse_mountinfo(text);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            entries[0].mount_point, "/mnt/café photos",
            "the escape decode must not turn UTF-8 into latin-1"
        );

        // And the entry is therefore FINDABLE, which is the consequence that
        // matters: an unmatched entry sends `entry_for` to a parent filesystem
        // and the root gets another volume's UUID.
        let found = entry_for(&entries, "/mnt/café photos/a.raw")
            .expect("the mount entry must match the path it governs");
        assert_eq!(found.source, "/dev/sda1");
    }

    /// Fixture lines, not the live mount table: a test that reads /proc passes
    /// or fails according to the machine it runs on, which is not a test.
    const FIXTURE: &str = "\
25 30 8:2 / / rw,relatime shared:1 - ext4 /dev/sda2 rw,errors=remount-ro
26 25 0:22 / /proc rw,nosuid,nodev,noexec,relatime shared:14 - proc proc rw
31 25 0:26 / /tmp rw,nosuid,nodev shared:5 - tmpfs tmpfs rw,size=8G
40 25 8:17 / /home/user/data rw,noatime shared:33 - ext4 /dev/sdb1 rw
41 25 0:55 / /mnt/my\\040share rw,relatime - cifs //nas/share rw,vers=3.1.1
";

    #[test]
    fn mountinfo_parses_past_the_variable_optional_fields() {
        let e = parse_mountinfo(FIXTURE);
        assert_eq!(e.len(), 5);
        assert_eq!(e[0].mount_point, "/");
        assert_eq!(e[0].fs_type, "ext4");
        assert_eq!(e[0].source, "/dev/sda2");
        // This line has NO optional tagged field before the separator, which is
        // why fixed-index splitting cannot work.
        assert_eq!(e[4].fs_type, "cifs");
        assert_eq!(e[4].source, "//nas/share");
    }

    #[test]
    fn octal_escapes_are_decoded() {
        let e = parse_mountinfo(FIXTURE);
        assert_eq!(e[4].mount_point, "/mnt/my share");
    }

    #[test]
    fn the_longest_matching_mount_point_governs() {
        let e = parse_mountinfo(FIXTURE);
        // Nested mounts: both `/` and `/home/user/data` are prefixes.
        let got = entry_for(&e, "/home/user/data/photos/a.raw").unwrap();
        assert_eq!(got.mount_point, "/home/user/data");
        assert_eq!(got.source, "/dev/sdb1");
        // A path under no deeper mount falls back to the root filesystem.
        let got = entry_for(&e, "/var/log/syslog").unwrap();
        assert_eq!(got.mount_point, "/");
    }

    #[test]
    fn a_mount_point_prefix_must_end_at_a_separator() {
        let e = parse_mountinfo(FIXTURE);
        // `/tmp` must not capture `/tmpfoo`, which is a different directory on
        // the root filesystem.
        let got = entry_for(&e, "/tmpfoo/x").unwrap();
        assert_eq!(got.mount_point, "/");
    }
}
