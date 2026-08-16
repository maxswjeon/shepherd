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
        Ok(FsId::new(format!("{volume_id}:{}", md.ino())))
    }
    #[cfg(not(unix))]
    {
        let _ = (path, volume_id);
        Err(VolumeError::Unsupported(std::env::consts::OS))
    }
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
