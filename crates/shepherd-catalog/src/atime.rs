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
/// explicit `noatime` wins over everything, and `strictatime` means genuinely
/// every access.
///
/// **What the kernel says when nothing is said is NOT `relatime`** — it is
/// `strictatime`, recorded as the absence of any atime flag. This function
/// still answers `Relatime` there, on purpose; the reasoning is at the final
/// arm, and it is the difference between a fail-safe imprecision and a guess.
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
    // NO ATIME OPTION MEANS `strictatime`, NOT `relatime` — and this returns
    // `Relatime` anyway, deliberately.
    //
    // The kernel names `noatime` and `relatime` in `/proc/self/mountinfo` and
    // names `strictatime` NOWHERE; strict behaviour is recorded as the absence
    // of a flag. Measured on both tmpfs and ext4 (2026-08-19):
    //
    //     mount -o strictatime -> "rw"              <- the strict case
    //     mount -o relatime    -> "rw,relatime"
    //     mount -o noatime     -> "rw,noatime"
    //
    // Two consequences, both stated because the previous comment here asserted
    // the opposite and would have misled anyone who trusted it:
    //
    // 1. The `strictatime` arm above CANNOT FIRE from real mountinfo. It is
    //    reachable only from a hand-written option string, which is how the
    //    unit tests reach it. It is kept because the option is legal input and
    //    silently dropping a case the classifier claims to handle is worse than
    //    an arm that rarely fires — but nobody should read its presence as
    //    evidence that `Reliable` is achievable on Linux.
    // 2. THEREFORE `AtimeMode::Reliable` IS CURRENTLY UNREACHABLE ON LINUX via
    //    `detect()`, and `only_reliable_atime_may_feed_the_observed_access_signal`
    //    can never be satisfied here. A genuinely strict mount is classified
    //    `Relatime`, which REFUSES to feed `last_observed_access` and still
    //    permits destructive age rules. That is fail-safe and imprecise, not
    //    fail-open.
    //
    // The honest fix is macOS's: PROBE the no-flag case rather than infer it —
    // backdate an atime, read, and see whether it advanced. macOS does exactly
    // that and maps its own no-flag case to `Relatime` on the evidence. Until
    // Linux does the same, inferring `Reliable` from an absent flag would be
    // deciding a destructive-rule input by assumption, which is the one
    // direction this module must not guess in.
    AtimeMode::Relatime
}

/// Detect the atime fidelity of the volume containing `path`.
///
/// Linux reads `/proc/self/mountinfo` and classifies both the per-mount and the
/// per-superblock option strings, taking the stricter of the two — a bind mount
/// can carry `relatime` while its superblock carries `noatime`, and the
/// filesystem wins.
///
/// macOS reads the volume's `statfs` flags — see [`classify_statfs_flags`],
/// whose default case §4.12 requires to be **verified by probe rather than
/// assumed**, and was.
///
/// Windows reads `NtfsDisableLastAccessUpdate` — see
/// [`classify_ntfs_disable_last_access`] — but only after confirming the volume
/// is NTFS, because that setting governs nothing on any other filesystem.
///
/// Every platform funnels a failed probe to [`AtimeMode::Unknown`], which every
/// safety predicate above treats as `Disabled`. A probe that cannot answer
/// therefore refuses destructive age rules rather than guessing.
pub fn detect(path: &Path) -> AtimeMode {
    #[cfg(target_os = "linux")]
    {
        detect_linux(path).unwrap_or(AtimeMode::Unknown)
    }
    #[cfg(target_os = "macos")]
    {
        detect_macos(path).unwrap_or(AtimeMode::Unknown)
    }
    #[cfg(target_os = "windows")]
    {
        detect_windows(path).unwrap_or(AtimeMode::Unknown)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
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

/// `MNT_STRICTATIME` from `<sys/mount.h>`.
///
/// `libc` exposes `MNT_NOATIME` for Apple targets but not `MNT_STRICTATIME`, so
/// the header's own value is written out here. Checked against
/// `MacOSX.sdk/usr/include/sys/mount.h` on macOS 26.5.2:
/// `#define MNT_STRICTATIME 0x80000000`.
#[cfg(target_os = "macos")]
const MNT_STRICTATIME: u32 = 0x8000_0000;

/// Classify a macOS volume from its `statfs` `f_flags` bitfield.
///
/// Pure, so the mapping is testable on fixture bitfields rather than on
/// whatever the test machine happens to have mounted — the same split
/// [`classify_mount_options`] uses for Linux option strings.
///
/// macOS spells the same three policies Linux does, with flags instead of an
/// option string:
///
/// * `MNT_NOATIME` — last-access updates are off. `Disabled`.
/// * `MNT_STRICTATIME` — every access updates. `Reliable`.
/// * neither — the default, which is **relatime-like, not strict**.
///
/// # The default case was probed, not assumed
///
/// §4.12 requires macOS fidelity to be verified by probe, and the default case
/// is the one that matters because it is what every ordinary volume reports.
/// On this project's macOS 26.5.2 arm64 host, the APFS data volume reports
/// `f_flags=0x04909080` — neither flag set. A file there whose atime was
/// backdated to 2020 had its atime advanced to now by a single `read`, and a
/// second `read` three seconds later did **not** advance it again.
///
/// That is exactly Linux's `relatime` rule — refresh a stale atime, otherwise
/// leave it alone — so the default maps to `Relatime`.
///
/// Mapping the default to `Reliable` would be the dangerous error, and it is
/// the one a "macOS updates atime by default" assumption leads to: `Reliable`
/// is the only value that both authorises a destructive "not accessed in a
/// year" rule *and* lets OS atime feed `last_observed_access`, on a signal that
/// in fact only advances once it is already stale.
#[cfg(target_os = "macos")]
pub fn classify_statfs_flags(flags: u32) -> AtimeMode {
    // `noatime` takes precedence if a volume somehow carries both, for the same
    // reason the Linux classifier gives it precedence: the stricter reading of
    // a contradictory mount is the safe one.
    if (flags & libc::MNT_NOATIME as u32) != 0 {
        return AtimeMode::Disabled;
    }
    if (flags & MNT_STRICTATIME) != 0 {
        return AtimeMode::Reliable;
    }
    AtimeMode::Relatime
}

/// Read the `statfs` flags of the volume containing `path` and classify them.
///
/// `None` when `statfs` fails — a missing path, or one the process cannot
/// traverse. [`detect`] turns that into `Unknown`, which every safety predicate
/// treats as `Disabled`, so a failed probe refuses destructive age rules rather
/// than guessing.
#[cfg(target_os = "macos")]
fn detect_macos(path: &Path) -> Option<AtimeMode> {
    use std::os::unix::ffi::OsStrExt;

    // A path containing an interior NUL cannot name a real file; `None` here
    // lands on the same fail-closed `Unknown` as a failed `statfs`.
    let c_path = std::ffi::CString::new(path.as_os_str().as_bytes()).ok()?;
    let mut buf = std::mem::MaybeUninit::<libc::statfs>::uninit();
    // SAFETY: `c_path` is a valid NUL-terminated C string that outlives the
    // call, and `buf` is a correctly sized, writable `statfs` allocation.
    let rc = unsafe { libc::statfs(c_path.as_ptr(), buf.as_mut_ptr()) };
    if rc != 0 {
        return None;
    }
    // SAFETY: `statfs` returned 0, so the kernel initialised `buf` fully.
    let buf = unsafe { buf.assume_init() };
    Some(classify_statfs_flags(buf.f_flags))
}

/// Classify a Windows volume from the raw `NtfsDisableLastAccessUpdate` DWORD.
///
/// Pure, and deliberately *not* `cfg`-gated, so the mapping is exercised by the
/// Linux CI leg on fixture values rather than only on whatever the one Windows
/// machine happens to be set to — the same split [`classify_mount_options`]
/// uses for Linux option strings.
///
/// # The value has four states, not two, and carries a flag bit
///
/// Since Windows 10 1809 / Server 2019 the setting is two independent bits:
///
/// | `fsutil` value | bit 1 — who decides | bit 0 — updates |
/// |---|---|---|
/// | 0 | user managed | **enabled** |
/// | 1 | user managed | disabled |
/// | 2 | system managed (the default) | **enabled** |
/// | 3 | system managed | disabled |
///
/// The registry DWORD additionally carries `0x8000_0000`, which `fsutil` does
/// not display. This machine reads `2147483651` = `0x8000_0003` while `fsutil
/// behavior query disablelastaccess` prints `3`. Older systems and Group Policy
/// can write the bare `0`-`3` form, so both encodings are accepted.
///
/// The table above is transcribed from `fsutil behavior set disablelastaccess`
/// run on the probe host, not from the reference page:
/// `learn.microsoft.com/.../fsutil-behavior` still documents only
/// `disablelastaccess {1|0}`, so it cannot be the source for a four-state
/// mapping. The tool also notes that group policy, when it controls the
/// setting, suppresses the "System Managed" state entirely.
///
/// # Why the mapping is not the obvious one
///
/// **A bare `& 1` mask is deliberately avoided.** The accepted encodings are
/// listed explicitly, and anything else — including the `0x8000_0004` that has
/// been seen in the wild — is `Unknown`. A mask would silently classify
/// garbage, which is the failure this project keeps finding: a check that runs
/// but cannot fail.
///
/// **`2` maps to `Unknown`, not to `Relatime`.** It means "updates are on
/// *right now*, and the OS may turn them off whenever it likes, without asking
/// anyone". [`detect`] runs once, at `target.add`, and the answer is persisted
/// in `scan_root.atime_mode`; nothing re-runs it. So a recorded `Relatime`
/// would outlive the condition that justified it. `2` is also the Windows
/// default, so mapping it optimistically would silently authorise destructive
/// age rules on every out-of-the-box Windows host — precisely the §4.12
/// catastrophe. `0` is different in kind: it takes a deliberate `fsutil
/// behavior set disablelastaccess 0`, which is an administrator opting in.
///
/// **`0` maps to `Relatime`, not to `Reliable`.** NTFS may defer a last-access
/// update to disk for up to an hour, so the persisted value a scan reads days
/// later is coarse rather than exact. `Reliable` is also the only mode that
/// lets OS `atime` feed `last_observed_access`
/// ([`AtimeMode::may_fold_into_observed_access`]), and that stronger claim was
/// **not measured**: the probe host sits in state `3`, and moving it to `0`
/// would have meant changing a shared machine's global filesystem policy to
/// suit a test. `Relatime` still permits a destructive age rule, so the opt-in
/// path stays open without claiming a fidelity nobody observed. If state `0`
/// is ever probed and atime is seen advancing on every read, promoting this
/// arm to `Reliable` is a one-line change with a measurement behind it.
pub fn classify_ntfs_disable_last_access(raw: u32) -> AtimeMode {
    match raw {
        // User managed, updates enabled — an explicit administrative opt-in.
        0x0000_0000 | 0x8000_0000 => AtimeMode::Relatime,
        // User managed, updates disabled.
        0x0000_0001 | 0x8000_0001 => AtimeMode::Disabled,
        // System managed, updates enabled *for now*. See above.
        0x0000_0002 | 0x8000_0002 => AtimeMode::Unknown,
        // System managed, updates disabled.
        0x0000_0003 | 0x8000_0003 => AtimeMode::Disabled,
        // Anything else is a value this mapping does not understand.
        _ => AtimeMode::Unknown,
    }
}

/// Whether `NtfsDisableLastAccessUpdate` governs this filesystem at all.
///
/// It is an NTFS setting. On FAT32, exFAT, ReFS or a network redirector it
/// decides nothing, so reading it there and reporting the answer would be a
/// check that runs and means nothing. Compared case-insensitively because
/// `GetVolumeInformationW` is not contractually upper-case.
pub fn windows_fs_honours_last_access_setting(fs_name: &str) -> bool {
    fs_name.eq_ignore_ascii_case("NTFS")
}

/// Minimal Win32 declarations for [`detect_windows`].
///
/// Written out by hand rather than pulled from `windows-sys`, for the same
/// reason `MNT_STRICTATIME` above is written out rather than sourced from
/// `libc`: three imports do not justify a dependency, and adding one would mean
/// editing the shared workspace manifest.
#[cfg(target_os = "windows")]
mod win32 {
    use std::ffi::c_void;

    /// `HKEY_LOCAL_MACHINE`.
    pub const HKEY_LOCAL_MACHINE: isize = 0x8000_0002u32 as i32 as isize;
    /// `RRF_RT_REG_DWORD` — fail with `ERROR_UNSUPPORTED_TYPE` rather than
    /// coerce if the value is not a `REG_DWORD`.
    ///
    /// `0x18` would be wrong here despite working: that is `RRF_RT_DWORD`,
    /// `REG_BINARY | REG_DWORD`, which also accepts a four-byte blob of any
    /// meaning. The strict single-type flag is what the sentence above claims,
    /// so it is what is used.
    pub const RRF_RT_REG_DWORD: u32 = 0x0000_0010;
    /// `ERROR_SUCCESS`.
    pub const ERROR_SUCCESS: i32 = 0;
    /// `DRIVE_REMOTE` — a network redirector, whether reached by UNC path or by
    /// a mapped drive letter.
    pub const DRIVE_REMOTE: u32 = 4;

    #[link(name = "kernel32")]
    unsafe extern "system" {
        pub fn GetVolumePathNameW(
            lpszFileName: *const u16,
            lpszVolumePathName: *mut u16,
            cchBufferLength: u32,
        ) -> i32;

        /// `DRIVE_REMOTE` is the case that matters here; see
        /// [`super::detect_windows`].
        pub fn GetDriveTypeW(lpRootPathName: *const u16) -> u32;

        pub fn GetVolumeInformationW(
            lpRootPathName: *const u16,
            lpVolumeNameBuffer: *mut u16,
            nVolumeNameSize: u32,
            lpVolumeSerialNumber: *mut u32,
            lpMaximumComponentLength: *mut u32,
            lpFileSystemFlags: *mut u32,
            lpFileSystemNameBuffer: *mut u16,
            nFileSystemNameSize: u32,
        ) -> i32;
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        pub fn RegGetValueW(
            hkey: isize,
            lpSubKey: *const u16,
            lpValue: *const u16,
            dwFlags: u32,
            pdwType: *mut u32,
            pvData: *mut c_void,
            pcbData: *mut u32,
        ) -> i32;
    }

    /// A NUL-terminated UTF-16 buffer, which is what every call above wants.
    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }
}

/// The volume root of `path` and that volume's filesystem name — e.g.
/// `("C:\\", "NTFS")`.
///
/// The root is returned as well as the name because [`detect_windows`] needs it
/// to ask `GetDriveTypeW` whether the volume is remote.
///
/// `None` when the path cannot be resolved to a volume or the volume cannot be
/// interrogated — [`detect_windows`] turns that into `Unknown`.
#[cfg(target_os = "windows")]
fn windows_volume_filesystem(path: &Path) -> Option<(Vec<u16>, String)> {
    use std::os::windows::ffi::OsStrExt;

    // An interior NUL cannot name a real file, and would silently truncate the
    // path handed to Win32.
    let mut wide_path: Vec<u16> = path.as_os_str().encode_wide().collect();
    if wide_path.contains(&0) {
        return None;
    }
    wide_path.push(0);

    // MAX_PATH + 1. The volume mount point of a path is never longer.
    let mut root = [0u16; 261];
    // SAFETY: `wide_path` is NUL-terminated and outlives the call; `root` is a
    // writable buffer whose length is passed honestly.
    let ok = unsafe {
        win32::GetVolumePathNameW(wide_path.as_ptr(), root.as_mut_ptr(), root.len() as u32)
    };
    if ok == 0 {
        return None;
    }

    let mut fs_name = [0u16; 261];
    // SAFETY: `root` is the NUL-terminated volume root Win32 just wrote;
    // `fs_name` is writable and its length is passed honestly. Every optional
    // out-parameter this call does not need is null, which the API permits.
    let ok = unsafe {
        win32::GetVolumeInformationW(
            root.as_ptr(),
            std::ptr::null_mut(),
            0,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            fs_name.as_mut_ptr(),
            fs_name.len() as u32,
        )
    };
    if ok == 0 {
        return None;
    }

    let len = fs_name
        .iter()
        .position(|&c| c == 0)
        .unwrap_or(fs_name.len());
    // The root is handed straight back to `GetDriveTypeW`, so it must keep its
    // terminator. A buffer with no NUL in it cannot have been written by a
    // successful `GetVolumePathNameW`; treating that as "could not tell" is
    // both the safe answer and the only sound one, since the alternative is
    // passing an unterminated string to Win32.
    let root_nul = root.iter().position(|&c| c == 0)?;
    Some((
        root[..=root_nul].to_vec(),
        String::from_utf16_lossy(&fs_name[..len]),
    ))
}

/// Read `HKLM\SYSTEM\CurrentControlSet\Control\FileSystem`'s
/// `NtfsDisableLastAccessUpdate`.
///
/// `None` when the value is absent or is not a `REG_DWORD`. Absent is not
/// silently treated as "the default": the default has itself changed across
/// Windows releases, so a missing value is a genuine "could not tell" and lands
/// on `Unknown`.
#[cfg(target_os = "windows")]
fn windows_disable_last_access_raw() -> Option<u32> {
    let sub = win32::wide(r"SYSTEM\CurrentControlSet\Control\FileSystem");
    let val = win32::wide("NtfsDisableLastAccessUpdate");
    let mut data: u32 = 0;
    let mut size = std::mem::size_of::<u32>() as u32;
    // SAFETY: both key strings are NUL-terminated and outlive the call, and
    // `size` truthfully describes `data`. `RRF_RT_REG_DWORD` makes the call
    // fail rather than write a differently-typed value into a `u32`.
    let rc = unsafe {
        win32::RegGetValueW(
            win32::HKEY_LOCAL_MACHINE,
            sub.as_ptr(),
            val.as_ptr(),
            win32::RRF_RT_REG_DWORD,
            std::ptr::null_mut(),
            &mut data as *mut u32 as *mut std::ffi::c_void,
            &mut size,
        )
    };
    if rc != win32::ERROR_SUCCESS {
        return None;
    }
    Some(data)
}

/// Detect the atime fidelity of the Windows volume containing `path`.
///
/// Three conditions, and the volume checks come first: the registry value is
/// machine-wide and **local**, but it governs **NTFS only** and only on **this**
/// machine. Applying it to a FAT32 or ReFS volume, or to an SMB share of a
/// remote NTFS volume, would be a classification with nothing behind it.
///
/// # What this reads, and what it does not
///
/// `fsutil behavior set disablelastaccess` states *"This operation takes effect
/// immediately (no reboot required)"*, so the registry and the running kernel
/// do not drift apart. (`learn.microsoft.com` says the opposite — "You must
/// restart your computer for this parameter to take effect" — on the same page
/// that documents only two states. The shipping tool was believed over it, and
/// the behavioural check below is why.)
///
/// What does go stale is **this crate's record of the answer**. [`detect`] runs
/// once, at `target.add`, and the result is persisted in
/// `scan_root.atime_mode`; nothing re-runs it if the machine's policy later
/// changes. That is the reasoning behind mapping `2` to `Unknown` in
/// [`classify_ntfs_disable_last_access`].
///
/// This is a policy read, not a behavioural probe. It does not write a file and
/// watch whether its timestamp moves — that is [`AtimeMode::Reliable`]'s "or a
/// probe that observed a real advance", and is not what this function is. The
/// two were nonetheless cross-checked once by hand: on the probe host, which
/// reports state `3`, a file whose last-access time was backdated to 2020 was
/// read twice and its timestamp did not move. The classification and the
/// filesystem's actual behaviour agreed.
#[cfg(target_os = "windows")]
fn detect_windows(path: &Path) -> Option<AtimeMode> {
    let (root, fs) = windows_volume_filesystem(path)?;

    // A remote volume is governed by the *server's* policy, and this registry
    // value is the client's. An SMB share of a remote NTFS volume reports
    // `"NTFS"` and would otherwise be classified from a setting that has no
    // authority over it — a check that runs and means nothing. Both spellings
    // of "remote" are covered, UNC and mapped drive letter, because
    // `GetDriveTypeW` does not distinguish them.
    //
    // SAFETY: `root` is the NUL-terminated volume root Win32 wrote.
    if unsafe { win32::GetDriveTypeW(root.as_ptr()) } == win32::DRIVE_REMOTE {
        return Some(AtimeMode::Unknown);
    }

    if !windows_fs_honours_last_access_setting(&fs) {
        return Some(AtimeMode::Unknown);
    }
    Some(classify_ntfs_disable_last_access(
        windows_disable_last_access_raw()?,
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

    // --- §4.12 Windows: `NtfsDisableLastAccessUpdate` ----------------------
    //
    // These run on every CI leg, not only the Windows one, because
    // `classify_ntfs_disable_last_access` is pure. That is deliberate: a
    // mapping only checked on Windows would be checked nowhere until the
    // Windows leg is green, and it is not.

    /// The value this project's Windows Server 2022 probe host actually
    /// carries. `fsutil behavior query disablelastaccess` on that host prints
    /// `DisableLastAccess = 3  (System Managed, Last Access Time Updates
    /// DISABLED)` while the registry holds `2147483651`. Both readings must
    /// land on `Disabled`, and the 32nd bit must not derail it.
    #[test]
    fn the_probe_hosts_real_registry_value_reads_as_disabled() {
        assert_eq!(
            classify_ntfs_disable_last_access(2_147_483_651),
            AtimeMode::Disabled
        );
        assert_eq!(2_147_483_651u32, 0x8000_0003);
        // The same policy without the undisplayed flag bit.
        assert_eq!(classify_ntfs_disable_last_access(3), AtimeMode::Disabled);
    }

    #[test]
    fn both_disabled_states_are_disabled_whichever_encoding() {
        for raw in [0x0000_0001, 0x8000_0001, 0x0000_0003, 0x8000_0003] {
            assert_eq!(
                classify_ntfs_disable_last_access(raw),
                AtimeMode::Disabled,
                "0x{raw:08X}"
            );
        }
    }

    /// `0` is an administrator's explicit opt-in, so it is usable — but only as
    /// a coarse signal, because NTFS may defer the on-disk update for an hour.
    /// `Reliable` would additionally authorise folding OS atime into
    /// `last_observed_access`, which nothing here measured.
    #[test]
    fn user_managed_enabled_is_coarse_not_reliable() {
        for raw in [0x0000_0000, 0x8000_0000] {
            assert_eq!(
                classify_ntfs_disable_last_access(raw),
                AtimeMode::Relatime,
                "0x{raw:08X}"
            );
        }
        assert!(AtimeMode::Relatime.supports_destructive_age_rule());
        assert!(!AtimeMode::Relatime.may_fold_into_observed_access());
    }

    /// The Windows default. Updates are on *now*, and the OS may switch them
    /// off on its own. `detect` runs once at `target.add` and the answer is
    /// persisted, so an optimistic reading here would outlive its own
    /// justification on every out-of-the-box Windows host.
    #[test]
    fn system_managed_enabled_is_unknown_because_the_os_may_flip_it() {
        for raw in [0x0000_0002, 0x8000_0002] {
            assert_eq!(
                classify_ntfs_disable_last_access(raw),
                AtimeMode::Unknown,
                "0x{raw:08X}"
            );
        }
        assert!(!AtimeMode::Unknown.supports_destructive_age_rule());
    }

    /// A mask (`raw & 1`) would pass every case above and still be wrong: it
    /// would read `0x8000_0004` — a value seen in the wild — as "enabled", and
    /// any garbage DWORD as a policy. The allowlist is what makes this check
    /// able to fail.
    #[test]
    fn unrecognised_encodings_are_unknown_rather_than_masked() {
        for raw in [0x0000_0004, 0x8000_0004, 0x0000_00FF, 0x4000_0003, u32::MAX] {
            assert_eq!(
                classify_ntfs_disable_last_access(raw),
                AtimeMode::Unknown,
                "0x{raw:08X}"
            );
        }
        // Spelled out so the intent survives a refactor: `& 1` would have said
        // "enabled" for this one.
        assert_ne!(
            classify_ntfs_disable_last_access(0x8000_0004),
            classify_ntfs_disable_last_access(0x8000_0000)
        );
    }

    /// The setting is NTFS-only. The probe host has a FAT32 volume alongside its
    /// NTFS ones (unlettered — it is the EFI system partition), so a non-NTFS
    /// filesystem on a Windows box is not a hypothetical, and a network
    /// redirector reached by UNC path is the case that will arrive first.
    #[test]
    fn only_ntfs_is_governed_by_the_setting() {
        assert!(windows_fs_honours_last_access_setting("NTFS"));
        // `GetVolumeInformationW` does not promise a case.
        assert!(windows_fs_honours_last_access_setting("ntfs"));
        for fs in ["FAT32", "exFAT", "ReFS", "CDFS", "NFS", ""] {
            assert!(!windows_fs_honours_last_access_setting(fs), "{fs}");
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

/// macOS-only, because the flag mapping and the syscall only exist there. The
/// fixture cases use the literal `<sys/mount.h>` values rather than the `libc`
/// constant the implementation uses, so a wrong constant in the implementation
/// is caught rather than agreed with.
#[cfg(all(test, target_os = "macos"))]
mod macos_tests {
    use super::*;

    /// Header values, written out independently of the implementation.
    const NOATIME: u32 = 0x1000_0000;
    const STRICTATIME: u32 = 0x8000_0000;
    /// The real `f_flags` of this host's APFS data volume, captured by probe.
    const OBSERVED_APFS_DATA: u32 = 0x0490_9080;

    #[test]
    fn the_libc_constant_is_the_header_constant() {
        assert_eq!(libc::MNT_NOATIME as u32, NOATIME);
        assert_eq!(MNT_STRICTATIME, STRICTATIME);
    }

    #[test]
    fn noatime_disables_and_beats_strictatime() {
        assert_eq!(classify_statfs_flags(NOATIME), AtimeMode::Disabled);
        assert_eq!(
            classify_statfs_flags(NOATIME | STRICTATIME),
            AtimeMode::Disabled,
            "a contradictory mount must read as the stricter of the two"
        );
    }

    #[test]
    fn strictatime_is_the_only_reliable_flag() {
        assert_eq!(classify_statfs_flags(STRICTATIME), AtimeMode::Reliable);
        assert_eq!(
            classify_statfs_flags(OBSERVED_APFS_DATA | STRICTATIME),
            AtimeMode::Reliable
        );
    }

    /// The probed case, and the one that would be unsafe to guess.
    #[test]
    fn the_default_flag_set_is_relatime_and_never_reliable() {
        assert_eq!(classify_statfs_flags(0), AtimeMode::Relatime);
        assert_eq!(
            classify_statfs_flags(OBSERVED_APFS_DATA),
            AtimeMode::Relatime,
            "probe: atime advanced once from a backdated value, then not again"
        );
        // The consequence, stated as the safety property rather than the label:
        // a default macOS volume must not authorise OS atime as a feed into
        // `last_observed_access`.
        assert!(!classify_statfs_flags(OBSERVED_APFS_DATA).may_fold_into_observed_access());
    }

    /// The row this module exists to close: macOS must no longer answer
    /// `Unknown` for a real volume. Asserting "not Unknown" rather than a fixed
    /// mode keeps the test true on a host that mounts `noatime` deliberately.
    #[test]
    fn detect_answers_a_real_volume_instead_of_unknown() {
        let mode = detect(Path::new("/System/Volumes/Data"));
        assert_ne!(
            mode,
            AtimeMode::Unknown,
            "macOS detect() must read statfs, not fall through to Unknown"
        );
        assert!(matches!(
            mode,
            AtimeMode::Disabled | AtimeMode::Relatime | AtimeMode::Reliable
        ));
    }

    /// Fail-closed: a `statfs` that cannot answer must degrade to `Unknown`,
    /// which `supports_destructive_age_rule` already refuses.
    #[test]
    fn a_path_that_does_not_exist_is_unknown_not_a_guess() {
        let mode = detect(Path::new("/no/such/path/shepherd-atime-probe"));
        assert_eq!(mode, AtimeMode::Unknown);
        assert!(!mode.supports_destructive_age_rule());
    }
}

/// Linux `detect()` itself — the composition, not its parts.
///
/// `G-1-ATIME` carried this gap the longest: the mountinfo PARSER and the
/// option CLASSIFIER were both well covered, and `detect_linux` — which
/// canonicalises a path, reads `/proc/self/mountinfo`, resolves the
/// longest-prefix mount and takes the stricter of the mount and superblock
/// classifications — was asserted by nothing on the one platform where every
/// other atime assertion runs. macOS and Windows gained direct coverage when
/// their detectors landed; Linux, which had the detector all along, did not.
#[cfg(all(test, target_os = "linux"))]
mod linux_tests {
    use super::*;
    use std::process::Command;

    /// The composition answers from the real kernel table rather than falling
    /// through to `Unknown`.
    #[test]
    fn detect_answers_a_real_mount_instead_of_unknown() {
        let mode = detect(Path::new("/tmp"));
        assert_ne!(
            mode,
            AtimeMode::Unknown,
            "Linux detect() must read /proc/self/mountinfo and classify, not \
             fall through to Unknown"
        );
        assert!(matches!(
            mode,
            AtimeMode::Disabled | AtimeMode::Relatime | AtimeMode::Reliable
        ));
    }

    /// Fail-closed: `canonicalize` fails, so the whole chain must degrade to
    /// `Unknown` rather than to a default that authorises destruction.
    #[test]
    fn a_path_that_does_not_exist_is_unknown_not_a_guess() {
        let mode = detect(Path::new("/no/such/path/shepherd-atime-probe"));
        assert_eq!(mode, AtimeMode::Unknown);
        assert!(!mode.supports_destructive_age_rule());
    }

    /// Cross-check against `findmnt`, not against our own parser.
    ///
    /// `findmnt` is util-linux: an independent implementation of the same
    /// longest-prefix resolution over the same kernel table. Re-parsing
    /// `/proc/self/mountinfo` here with `linux_mountinfo` would compare the
    /// function to itself and pass on a broken one — the same reason the
    /// launchd uid test checks against `id -u` rather than `getuid()`.
    #[test]
    fn detect_agrees_with_findmnt_about_the_options_in_force() {
        let out = match Command::new("findmnt")
            .args(["-no", "OPTIONS", "--target", "/tmp"])
            .output()
        {
            Ok(o) if o.status.success() => o,
            // util-linux absent: skip rather than assert a tautology in its place.
            _ => return,
        };
        let opts = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(!opts.is_empty(), "findmnt returned no options for /tmp");

        let expected = if opts.split(',').any(|o| o == "noatime") {
            AtimeMode::Disabled
        } else if opts.split(',').any(|o| o == "strictatime") {
            AtimeMode::Reliable
        } else {
            AtimeMode::Relatime
        };

        assert_eq!(
            detect(Path::new("/tmp")),
            expected,
            "detect() disagrees with findmnt, which read the same kernel table \
             by a different implementation. findmnt says: {opts}"
        );
    }

    /// The load-bearing one: drive `detect()` across mounts whose options the
    /// test CONTROLS, and require it to change its answer.
    ///
    /// The three tests above all run against whatever `/tmp` happens to be, so
    /// each of them passes against a `detect()` hardcoded to that one answer.
    /// This one mounts a tmpfs `noatime`, requires `Disabled`, remounts it
    /// `strictatime`, and requires `Reliable` — so a constant return value
    /// fails whichever constant it is. Needs root; `#[ignore]`d for the same
    /// reason as `volume::remount_tests`.
    #[test]
    #[ignore = "needs root to mount tmpfs"]
    fn detect_changes_its_answer_when_the_mount_options_change() {
        let dir = std::env::temp_dir().join("shepherd-atime-mount-probe");
        let _ = Command::new("sudo")
            .args(["umount", "-l"])
            .arg(&dir)
            .output();
        std::fs::create_dir_all(&dir).expect("mkdir probe mountpoint");

        struct Cleanup(std::path::PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = Command::new("sudo")
                    .args(["umount", "-l"])
                    .arg(&self.0)
                    .output();
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let _guard = Cleanup(dir.clone());

        let mount = |opts: &str| {
            let st = Command::new("sudo")
                .args(["mount", "-t", "tmpfs", "-o", opts, "shepherd-atime-probe"])
                .arg(&dir)
                .status()
                .expect("run mount");
            assert!(st.success(), "mount -o {opts} failed");
        };
        let remount = |opts: &str| {
            let st = Command::new("sudo")
                .args(["mount", "-o", &format!("remount,{opts}")])
                .arg(&dir)
                .status()
                .expect("run remount");
            assert!(st.success(), "remount -o {opts} failed");
        };

        mount("noatime");
        assert_eq!(
            detect(&dir),
            AtimeMode::Disabled,
            "a tmpfs mounted noatime must classify as Disabled; detect() is \
             either not reading this mount or not honouring the option"
        );

        // The second leg deliberately asserts `Relatime`, NOT `Reliable`, and
        // the reason is a measured kernel fact rather than a compromise: the
        // kernel names `noatime` and `relatime` in mountinfo and names
        // `strictatime` nowhere, so a strict mount reads as `rw` with no atime
        // option and classifies as `Relatime`. Verified on tmpfs AND ext4.
        // Asserting `Reliable` here would be asserting something Linux cannot
        // currently produce — see `classify_mount_options`.
        //
        // It still catches a constant, which is this test's whole job: the
        // answer MUST CHANGE across the remount, and it must change to the
        // value the kernel table actually justifies.
        remount("strictatime");
        let after = detect(&dir);
        assert_ne!(
            after,
            AtimeMode::Disabled,
            "detect() still says Disabled after the mount stopped being \
             noatime — it is not re-reading the kernel table, or it is caching"
        );
        assert_eq!(
            after,
            AtimeMode::Relatime,
            "a mount with no atime option in mountinfo classifies as Relatime. \
             If this ever reads Reliable, either the kernel began naming \
             strictatime or someone inferred it from an absent flag — the \
             second would be guessing a destructive-rule input"
        );
        assert!(
            !after.may_fold_into_observed_access(),
            "Relatime must not feed last_observed_access"
        );
    }
}
