//! §4.10.6 — the restore fidelity contract.
//!
//! # "Byte-compare identical" is silent about metadata
//!
//! AC-63 asserts bytes. That leaves every other attribute of a file
//! unaddressed, and a restore that returns the right bytes with the wrong
//! `mtime` is not a restore in any sense the user recognises. So the contract
//! names a floor and a disclosure rule:
//!
//! * **Preserved at minimum: bytes, `mtime`, and `mode`.** `mtime` is
//!   preserved **to the resolution the target filesystem can represent**, which
//!   is what the DESTINATION can hold — see `MTIME_GRANULARITIES`. That
//!   narrowing is deliberate and was forced by measurement rather than chosen:
//!   NTFS timestamps are FILETIME ticks, so a file tiered on Linux with a
//!   nanosecond `mtime` cannot be restored bit-identically onto Windows by
//!   anyone. Promising exactness there would be promising something no
//!   implementation can deliver, which is worse than a stated limit. Any
//!   difference the target COULD have represented and did not is still a
//!   breach. **`mode` is preserved only where the target can represent one at
//!   all** — POSIX yes, Windows no, since NTFS has ACLs and a read-only flag
//!   and no mode bits. On Windows `mode` is NOT preserved, and that is stated
//!   here rather than discovered: see `MODE_IS_REPRESENTABLE`, which also
//!   records why mapping owner-write onto the read-only flag was rejected.
//! * Captured where the provider allows: xattrs, POSIX ACLs, macOS resource
//!   forks and Finder tags, NTFS alternate data streams.
//! * **Anything not captured is documented as not preserved** rather than
//!   silently dropped.
//!
//! `mtime` is in the floor for a second reason beyond user expectation: a
//! restored file whose `mtime` is "now" **instantly re-matches an age rule**
//! and is a candidate for re-tiering on the next pass. Getting it wrong turns
//! restore into a loop.
//!
//! # Why the manifest records what it COULD NOT capture
//!
//! The disclosure rule is unsatisfiable if the manifest only records successes.
//! An absent xattr entry would then be ambiguous between "this file had no
//! xattrs" and "this target cannot carry xattrs and we dropped them" — and the
//! user needs the second one to be visible. [`AttrCapture`] therefore has an
//! explicit [`AttrCapture::Unsupported`] arm, and [`FidelityManifest::gaps`]
//! reports them. A silent omission is the failure this type exists to prevent.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use shepherd_core::{Blake3Hash, Timestamp};

/// The floor. Every restore must reproduce all three.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreAttrs {
    pub blake3: Blake3Hash,
    pub size: u64,
    /// Restored so an age rule does not immediately re-match the file.
    pub mtime: Timestamp,
    /// Unix permission bits. On Windows this carries the read-only flag; the
    /// richer ACL story is an optional attribute, not part of the floor.
    pub mode: u32,
}

/// An optional attribute class, and what happened to it at tier time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "capture")]
pub enum AttrCapture {
    /// Captured, with the payload.
    Captured { values: BTreeMap<String, String> },
    /// The source had none. Distinct from `Unsupported`: nothing was lost.
    Absent,
    /// The source had them but this target or platform cannot carry them.
    /// **This is the arm that must reach the user.**
    Unsupported { reason: String },
}

impl AttrCapture {
    /// Whether something existed on the source and did **not** survive.
    pub fn is_gap(&self) -> bool {
        matches!(self, AttrCapture::Unsupported { .. })
    }
}

/// Optional attribute classes, per §4.10.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttrClass {
    Xattrs,
    PosixAcl,
    /// macOS resource fork.
    ResourceFork,
    /// macOS Finder tags.
    FinderTags,
    /// NTFS alternate data streams.
    AlternateDataStreams,
}

impl AttrClass {
    pub fn as_str(self) -> &'static str {
        match self {
            AttrClass::Xattrs => "xattrs",
            AttrClass::PosixAcl => "posix-acl",
            AttrClass::ResourceFork => "resource-fork",
            AttrClass::FinderTags => "finder-tags",
            AttrClass::AlternateDataStreams => "alternate-data-streams",
        }
    }
}

/// The sidecar manifest written at tier time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FidelityManifest {
    pub core: CoreAttrs,
    pub optional: BTreeMap<AttrClass, AttrCapture>,
}

impl FidelityManifest {
    pub fn new(core: CoreAttrs) -> Self {
        Self {
            core,
            optional: BTreeMap::new(),
        }
    }

    pub fn with(mut self, class: AttrClass, capture: AttrCapture) -> Self {
        self.optional.insert(class, capture);
        self
    }

    /// Attribute classes that existed on the source and were **not** preserved.
    ///
    /// This is what §7's DOCUMENT obligation is reported from. An empty result
    /// means full fidelity; a non-empty one is a disclosure the user is owed,
    /// not a warning to swallow.
    pub fn gaps(&self) -> Vec<(AttrClass, &str)> {
        self.optional
            .iter()
            .filter_map(|(class, cap)| match cap {
                AttrCapture::Unsupported { reason } => Some((*class, reason.as_str())),
                _ => None,
            })
            .collect()
    }

    /// Whether every optional class was either captured or genuinely absent.
    pub fn is_full_fidelity(&self) -> bool {
        self.gaps().is_empty()
    }
}

/// What a restore actually produced, read back from disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoredAttrs {
    pub blake3: Blake3Hash,
    pub size: u64,
    pub mtime: Timestamp,
    pub mode: u32,
}

/// A floor attribute that did not survive the round trip.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FidelityBreach {
    Content {
        expected: Blake3Hash,
        actual: Blake3Hash,
    },
    Size {
        expected: u64,
        actual: u64,
    },
    /// Not cosmetic: a wrong `mtime` makes the restored file re-match an age
    /// rule and become a re-tiering candidate on the next pass.
    Mtime {
        expected: Timestamp,
        actual: Timestamp,
    },
    Mode {
        expected: u32,
        actual: u32,
    },
    /// The manifest captured an optional attribute class that the restore did
    /// not put back.
    ///
    /// `restore_file` applies bytes, mode and mtime; nothing applies xattrs,
    /// POSIX ACLs, resource forks, Finder tags or alternate data streams, and
    /// `verify_restore` used to ignore `manifest.optional` entirely. A restore
    /// of a file whose manifest recorded `Captured` xattrs therefore returned
    /// success with every one of them gone — the silent direction, and the one
    /// §4.10.6 exists to prevent. `Unsupported` already reaches the user as a
    /// gap; `Captured`-but-not-applied was the arm with no reader.
    ///
    /// An EMPTY captured map is NOT this: the capture ran and the class had
    /// nothing, which is the same "nothing was lost" `Absent` records, and the
    /// first version of this loop reported it as a breach — failing every
    /// restore of a perfectly ordinary manifest.
    ///
    /// This fails the restore rather than warning, which is the same stance
    /// the mode and mtime breaches take: a restore that reports success is a
    /// claim of fidelity. Nothing produces a non-empty `Captured` yet — the capture side
    /// is unwired, as `AttrCapture`'s own tests are its only source — so this
    /// costs nothing today and refuses on the first day it would have lied.
    OptionalNotRestored {
        class: AttrClass,
        values: usize,
    },
}

/// The finest mtime this platform's filesystems can actually store, in
/// nanoseconds.
///
/// **1 ns on POSIX. 100 ns on Windows**, because NTFS timestamps are FILETIME
/// ticks and `SystemTime` is backed by the same, so a nanosecond value simply
/// cannot be written there — `1700000000123456789` reads back as
/// `1700000000123456700`.
///
/// This exists because the first native Windows CI run of this repository
/// reported four `restore` fidelity breaches, and the test that fired says in
/// its own comment that firing means "a real finding about the filesystem under
/// test, not a flaky test". It was right. The finding is that a file tiered on
/// Linux with nanosecond mtime CANNOT be restored bit-identically onto NTFS,
/// ever, by anyone.
///
/// So the comparison below is against what the TARGET can represent rather than
/// against exact equality. That is a deliberate narrowing of §4.10.6's promise
/// and it is narrowed in the only direction that is honest: shepherd does not
/// claim to preserve precision the storage cannot hold. It still fails on any
/// difference the target COULD have represented and did not — which is the
/// breach the check exists to catch, and on POSIX the behaviour is unchanged
/// because the resolution there is 1 ns.
/// The mtime granularities a destination might actually have, in nanoseconds.
///
/// This was `if cfg!(unix) { 1 } else { 100 }`, and the host OS is the wrong
/// thing to ask. Unix does not imply nanosecond storage: FAT and exFAT mount
/// perfectly well on Linux and macOS and keep 2-second and 10-millisecond
/// timestamps, and ext3 and HFS+ keep whole seconds. On any of those,
/// `set_modified` legitimately quantises the manifest's value, the constant
/// still said 1 ns, and verification reported a breach — after which cleanup
/// removed an otherwise perfect restore.
///
/// * `1` — ext4 with large inodes, xfs, btrfs, APFS.
/// * `100` — NTFS, whose timestamps are FILETIME ticks.
/// * `10_000_000` — exFAT.
/// * `1_000_000_000` — ext3, HFS+, older UFS.
/// * `2_000_000_000` — FAT32.
const MTIME_GRANULARITIES: [i64; 5] = [1, 100, 10_000_000, 1_000_000_000, 2_000_000_000];

/// Whether this platform's filesystems can represent a POSIX `mode` at all.
///
/// **True on POSIX. False on Windows**, which has ACLs and a read-only flag and
/// no mode bits. A restore onto NTFS reads back `mode: 0` against a manifest
/// recording `0o644`, so an unconditional comparison reports a breach for
/// something the target cannot hold — the same shape as the `mtime` limit above
/// and, again, found by the first native Windows CI run rather than by reading.
///
/// **`mode` is therefore NOT preserved on Windows, and this constant is where
/// that is written down.** The alternative considered and rejected was mapping
/// the owner-write bit onto the read-only flag: that would preserve one bit of
/// nine while reporting success, which claims more fidelity than it delivers.
/// This module's own third rule is that anything not captured is DOCUMENTED as
/// not preserved rather than silently dropped, and a partial mapping dressed as
/// a pass is exactly the silent drop it forbids.
const MODE_IS_REPRESENTABLE: bool = cfg!(unix);

/// Whether a restored mtime is as faithful as the destination allows.
///
/// # The read-back IS the probe
///
/// There is no need to ask the filesystem its resolution, and no portable way
/// to: what came back through the handle already says what the destination
/// stored. What is needed is a rule that tells QUANTISATION from ERROR, and
/// exact landing on a tick boundary is that rule. A value the destination
/// truncated or rounded to its own granularity is a multiple of it and within
/// one tick of the original; a restore that wrote the wrong time is neither,
/// because being off by minutes and landing exactly on a two-second boundary
/// within two seconds of the manifest is not a thing a wrong write does.
///
/// Both conditions, and the boundary one is what keeps this tight. Accepting
/// anything within one tick of the coarsest granularity would accept two
/// seconds of drift on a nanosecond filesystem, which is the promise this check
/// exists to keep rather than to widen.
///
/// The identity case is covered by `1`: every integer is a multiple of one, so
/// the granularity-1 arm passes exactly when the values are equal, and a
/// nanosecond destination behaves as it always did.
///
/// §4.10.6's stated reason for putting mtime in the floor — a restored file
/// whose mtime is "now" instantly re-matches an age rule — is untouched by any
/// of this. Two seconds does not re-match an age rule; two hundred days does,
/// and that still fails every arm.
fn mtime_is_faithful(expected: Timestamp, actual: Timestamp) -> bool {
    let (e, a) = (expected.as_nanos(), actual.as_nanos());
    MTIME_GRANULARITIES
        .iter()
        // `rem_euclid`, not `%`: timestamps before 1970 are negative, and `%`
        // takes the sign of the dividend, so a value exactly on a tick would
        // fail the boundary test for being negative.
        .any(|&g| a.rem_euclid(g) == 0 && (e - a).abs() < g)
}

/// Check a restore against its manifest's floor.
///
/// Returns **every** breach rather than the first, so one restore report names
/// everything that went wrong.
pub fn verify_restore(
    manifest: &FidelityManifest,
    actual: &RestoredAttrs,
) -> Result<(), Vec<FidelityBreach>> {
    let mut breaches = Vec::new();
    let c = &manifest.core;

    if actual.blake3 != c.blake3 {
        breaches.push(FidelityBreach::Content {
            expected: c.blake3,
            actual: actual.blake3,
        });
    }
    if actual.size != c.size {
        breaches.push(FidelityBreach::Size {
            expected: c.size,
            actual: actual.size,
        });
    }
    if !mtime_is_faithful(c.mtime, actual.mtime) {
        breaches.push(FidelityBreach::Mtime {
            expected: c.mtime,
            actual: actual.mtime,
        });
    }
    if MODE_IS_REPRESENTABLE && actual.mode != c.mode {
        breaches.push(FidelityBreach::Mode {
            expected: c.mode,
            actual: actual.mode,
        });
    }

    // Every captured optional class, because none of them are applied.
    //
    // Stated as a breach per CLASS rather than one summary breach: the caller's
    // remedy differs — xattrs are re-settable from the manifest, a resource
    // fork is not — and a single "optional attributes lost" line cannot say
    // which. `Absent` and `Unsupported` are deliberately not here: nothing was
    // lost in the first, and the second is already a declared gap carried
    // through `AttrCapture::is_gap`.
    for (class, capture) in &manifest.optional {
        // An EMPTY captured map is not a loss, and reporting it as one was a
        // regression: `Captured { values: {} }` is a legal manifest — the
        // capture ran, the class had nothing — and `AttrCapture::is_gap`
        // already says so. Every restore of such a manifest failed
        // verification and had its otherwise perfect output cleaned up.
        //
        // Skipped here rather than normalised to `Absent` at construction: the
        // manifest is a sidecar with a pinned serialisation, so rewriting what
        // `with()` stores would change what old and new builds read from each
        // other's files for no gain.
        if let AttrCapture::Captured { values } = capture
            && !values.is_empty()
        {
            breaches.push(FidelityBreach::OptionalNotRestored {
                class: *class,
                values: values.len(),
            });
        }
    }

    if breaches.is_empty() {
        Ok(())
    } else {
        Err(breaches)
    }
}

/// Where a restore may write.
///
/// §4.10.5: "Restore and hydration writes are exclusive-create, never replace.
/// Restoring to a path now occupied by a newer file uses a conflict name and
/// alerts. **Shepherd never destroys data by writing**, only by the audited
/// destroy path."
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestoreTarget {
    /// The original path, which is free.
    Original(String),
    /// Occupied by something else, so the restore lands beside it under a
    /// conflict name and raises an alert. The occupant may be a file the user
    /// created while this one was gone, and it is not ours to overwrite.
    Conflict { original: String, chosen: String },
    /// Every conflict name up to the ceiling is taken, so there is no name to
    /// restore under.
    ///
    /// A distinct outcome rather than a `Conflict` carrying the last candidate.
    /// The loop used to return `(restored 10001)` without ever testing it, so
    /// `restore_file` failed with `AlreadyExists` on a path it had never
    /// probed, and every retry re-walked all ten thousand names to arrive at
    /// the same occupied one — a file that could never be restored, reported as
    /// a race that never happened.
    Exhausted { original: String, ceiling: u32 },
}

/// Choose a restore path without ever replacing an existing file.
///
/// `exists` is injected rather than probed so the occupied case is testable
/// without a filesystem — and because the caller has already had to stat the
/// path, so probing again would widen the race rather than narrow it.
pub fn choose_restore_path(original: &str, exists: &dyn Fn(&str) -> bool) -> RestoreTarget {
    if !exists(original) {
        return RestoreTarget::Original(original.to_owned());
    }
    // Split off the extension so `photo.raw` becomes `photo (restored 1).raw`
    // rather than `photo.raw (restored 1)`, which some tools would stop
    // recognising as a raw file.
    // The dot must be searched for INSIDE THE FILE NAME, not across the whole
    // path, and must not be its first character. Searching the whole path sends
    // `/root/.bashrc` to `/root (restored 1).bashrc` — which does not merely
    // pick an odd name, it writes into a **different directory**. A dotfile has
    // no extension, and a dot in a parent directory is not one either.
    // Platform-aware, via `std::path::is_separator`: `\\` separates on Windows
    // and is an ORDINARY CHARACTER in a Unix filename, so a fixed two-character
    // set is wrong on one platform or the other. Searching only for `/` sent
    // `C:\\Users\\foo.bar\\README` to `C:\\Users\\foo (restored 1).bar\\README`,
    // which is not an odd name but a different, usually nonexistent
    // DIRECTORY — the same class of bug as the whole-path dot search below,
    // and the reason both are one lookup now.
    let name_start = original.rfind(std::path::is_separator).map_or(0, |i| i + 1);
    let name = &original[name_start..];
    let (stem, ext) = match name.rfind('.') {
        // `i > 0` is relative to the NAME, so `.bashrc` (i == 0) is excluded.
        Some(i) if i > 0 => (&original[..name_start + i], &name[i..]),
        _ => (original, ""),
    };
    let mut n = 1u32;
    loop {
        let candidate = format!("{stem} (restored {n}){ext}");
        if !exists(&candidate) {
            return RestoreTarget::Conflict {
                original: original.to_owned(),
                chosen: candidate,
            };
        }
        n += 1;
        // Astronomically unlikely, but a loop that cannot terminate on a
        // destructive path is not something to leave to optimism.
        //
        // REFUSING, not returning the next name. Handing back
        // `(restored 10001)` without probing it was worse than the loop it
        // guarded: the caller created it exclusively, got `AlreadyExists`, and
        // reported a race — while the real state of the world was "there is no
        // free name here", which no number of retries would change.
        if n > CONFLICT_NAME_CEILING {
            return RestoreTarget::Exhausted {
                original: original.to_owned(),
                ceiling: CONFLICT_NAME_CEILING,
            };
        }
    }
}

/// How many `(restored N)` names are tried before giving up.
///
/// Not a tuning knob so much as the point at which "the directory is in a state
/// no automatic choice will fix" is a better answer than another probe.
pub const CONFLICT_NAME_CEILING: u32 = 10_000;

#[cfg(test)]
#[path = "fidelity_tests.rs"]
mod tests;
