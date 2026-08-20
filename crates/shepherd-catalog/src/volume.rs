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
    fn unescape_octal(s: &str) -> String {
        let b = s.as_bytes();
        let mut out = String::with_capacity(s.len());
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'\\'
                && i + 3 < b.len()
                && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8)
            {
                out.push(v as char);
                i += 4;
                continue;
            }
            out.push(b[i] as char);
            i += 1;
        }
        out
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
        Ok(format!("src:{}:{}", entry.fs_type, entry.source))
    }

    /// Resolve a block device to its filesystem UUID via `/dev/disk/by-uuid`,
    /// whose entries are symlinks pointing back at the device node.
    fn uuid_for_source(source: &str) -> Option<String> {
        let target = std::fs::canonicalize(source).ok()?;
        for e in std::fs::read_dir("/dev/disk/by-uuid").ok()?.flatten() {
            if std::fs::canonicalize(e.path()).ok()? == target {
                return Some(e.file_name().to_string_lossy().to_string());
            }
        }
        None
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
        // UUID-derived. Without this the test would also pass for the
        // `src:<fstype>:<source>` fallback, whose source is `/dev/loopN` and
        // therefore does NOT survive the remount below.
        assert!(
            vol_a.starts_with("uuid:"),
            "expected a UUID-derived volume id, got {vol_a:?} — the fallback is \
             device-path-derived and is not remount-stable"
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

    /// The negative that gives the assertion above its meaning: the documented
    /// fallback identity is NOT remount-stable, so a caller may not treat it as
    /// interchangeable with the UUID-derived one.
    ///
    /// Without this, `volume_id_fallback` reads like a harmless second option.
    /// It is not: its source is `/dev/loopN`, which is exactly the mount-time
    /// assignment §4.4 forbids relying on.
    #[test]
    #[ignore = "needs root: builds a loopback ext4 filesystem and mounts it"]
    fn the_fallback_identity_is_explicitly_not_remount_stable() {
        let fixture = Fixture::new();
        let a = fixture.mount("a");
        std::fs::write(a.join(FILE), b"payload").expect("write into the fresh fs");
        let before = volume_id_fallback(&a.join(FILE)).expect("fallback before");

        fixture.unmount_all();
        fixture.reattach_on_a_different_loop_device();
        let c = fixture.mount("c");
        let after = volume_id_fallback(&c.join(FILE)).expect("fallback after");

        assert_ne!(
            before, after,
            "the fallback is device-path-derived; if it ever became stable the \
             comment calling it WEAKER is what is now wrong"
        );
        // And it is labelled, so a human reading the column can tell which kind
        // of identity a row holds.
        assert!(before.starts_with("src:"), "unlabelled fallback: {before}");
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::linux::*;

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
