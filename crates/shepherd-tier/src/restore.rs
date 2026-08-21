//! Restore — exclusive-create, then prove the fidelity contract held.
//!
//! # Restore never overwrites, and the primitive matters
//!
//! §4.10.5: "Restore and hydration writes are exclusive-create, never replace.
//! **Shepherd never destroys data by writing**, only by the audited destroy
//! path." Locally that means `O_EXCL` — [`std::fs::File::create_new`] — and
//! **not** a `metadata()` check followed by a `create()`. The check-then-create
//! pair is a TOCTOU: something can appear in the gap, and the loser of that
//! race is a file the user made while this one was gone.
//!
//! [`crate::fidelity::choose_restore_path`] picks the name; this module does
//! the write, and re-checks exclusivity at the syscall because the name may
//! have been taken between the two.
//!
//! # mtime is restored, then read back
//!
//! §4.10.6 puts `mtime` in the floor, partly so a restored file does not
//! instantly re-match an age rule. But *setting* an mtime and *having it stick*
//! are different claims: some filesystems quantise the value on write, so the
//! read-back can differ from what the manifest asked for. That is exactly the
//! kind of gap a pure-logic comparison cannot see, so [`restore_file`] writes,
//! sets, re-reads, and verifies against the manifest — and its test runs
//! against a real temp file rather than a fake.
//!
//! # Verification is bound to the INODE, not to the name
//!
//! `create_new` returning a handle proves the name was ours **at that syscall**.
//! It proves nothing about the moment after. So every step that follows works
//! through the handle rather than through the path: `fchmod` via
//! [`std::fs::File::set_permissions`], `futimens` via `File::set_modified`, and
//! a read-back that seeks the handle to zero and `fstat`s it
//! ([`read_back_through`]). A pathname `chmod` in that window edits **whatever
//! is at the name**, which on a replaced destination is a file this restore did
//! not create; a pathname read-back then *verifies that same replacement*, so a
//! restore that published nothing can report success — and will, if the
//! replacement happens to match the manifest.
//!
//! Working through the handle makes the bytes and metadata claims true of the
//! right inode, and it cannot make the last claim at all: that the inode is
//! **reachable at the destination**. That one needs a name lookup, so
//! [`still_names_the_created_inode`] is the final act before returning — a
//! `(dev, ino)` comparison against the value captured from the handle at
//! creation. Failing it is [`RestoreError::Displaced`]: an error, and the
//! created inode is left wherever the replacer put it rather than chased. The
//! error routes through the same [`discard_failed_attempt`] as every other
//! failure, which stats the path, finds a foreign inode and **leaves it alone**
//! — so the replacement survives a failure caused by its own arrival.
//!
//! # A failed attempt cleans up after itself, by INODE
//!
//! `create_new` succeeding is not the same fact as the restore succeeding.
//! `ENOSPC` on the write, a failed `sync_all`, a metadata call the filesystem
//! refuses, a read-back that will not read, a fidelity breach — every one of
//! them used to return with the file Shepherd had just created still occupying
//! the destination. The next attempt then found the original path taken, read
//! it as a **user-owned conflict**, and restored the file beside itself while
//! alerting the operator about a collision with Shepherd's own wreckage.
//!
//! The cleanup is bound to the **exact inode this attempt created**, never to
//! the path. Unlinking by path would delete whatever is at the name at cleanup
//! time, and the whole reason `create_new` is used above is that something else
//! can appear at that name — so a path-keyed cleanup would reintroduce, on the
//! error path, precisely the data loss `O_EXCL` closes on the success path.
//! [`discard_failed_attempt`] compares `(dev, ino)` and leaves anything that
//! is not ours alone.
//!
//! ## Why not stage-then-publish
//!
//! Writing to a private staging file and publishing it exclusively is the
//! stronger shape, and it does not fit here. The exclusive publish primitive is
//! `renameat2(RENAME_NOREPLACE)` / `renamex_np(RENAME_EXCL)`, which already
//! exists in `shepherd-placeholder::delete_mode` and is private to it; this
//! crate has no `libc` dependency, so adopting it would mean a second copy of
//! exactly the primitive the workspace centralises. `std::fs::rename` cannot
//! substitute — it **replaces**, which is §4.10.5's prohibition verbatim — and
//! `std::fs::hard_link`, the only exclusive publish in `std`, is unsupported on
//! vfat/exFAT, i.e. on the removable disks §4.4 goes out of its way to keep
//! working. `delete_mode` itself refuses rather than falling back when
//! `RENAME_NOREPLACE` is unavailable; taking the same line here would make
//! restore — a non-destructive operation — start refusing on those
//! filesystems. So the cleanup is inode-bound instead, which the finding names
//! as the alternative.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use shepherd_core::{Blake3Hash, Timestamp};

use crate::fidelity::{
    FidelityBreach, FidelityManifest, RestoreTarget, RestoredAttrs, choose_restore_path,
    verify_restore,
};

#[derive(Debug, thiserror::Error)]
pub enum RestoreError {
    #[error("io error at {path}: {detail}")]
    Io { path: String, detail: String },

    /// The path was taken between choosing it and creating it. Not an error to
    /// paper over: it means something else is writing where we are about to.
    #[error("{path} already exists — restore is exclusive-create, never replace")]
    AlreadyExists { path: String },

    /// The bytes or metadata did not survive the round trip (§4.10.6).
    #[error("restore fidelity breached at {path}: {breaches:?}")]
    FidelityBreached {
        path: String,
        breaches: Vec<FidelityBreach>,
    },

    /// The destination stopped naming the inode this attempt created, some time
    /// between the exclusive create and the final check. The bytes were written
    /// and verified — through the handle — but they are not what the path
    /// resolves to, so **nothing was published** and reporting success would
    /// name a restore that did not happen.
    #[error(
        "{path} no longer names the inode this restore created — something replaced the          destination after the exclusive create, so nothing was published there"
    )]
    Displaced { path: String },

    /// The original path and every `(restored N)` name up to the ceiling are
    /// taken. Distinct from [`RestoreError::AlreadyExists`], which is a race:
    /// this is a directory whose state no automatic choice will resolve, so
    /// retrying is pointless and the message says why rather than naming one
    /// occupied path.
    #[error(
        "{path} is occupied and so are all {ceiling} `(restored N)` names beside it; \
         there is no free name to restore under — move or remove some of them"
    )]
    NoFreeName { path: String, ceiling: u32 },
}

type Result<T> = std::result::Result<T, RestoreError>;

fn to_system_time(ts: Timestamp) -> SystemTime {
    let n = ts.as_nanos();
    if n >= 0 {
        UNIX_EPOCH + Duration::from_nanos(n as u64)
    } else {
        UNIX_EPOCH - Duration::from_nanos(n.unsigned_abs())
    }
}

fn from_system_time(st: SystemTime) -> Timestamp {
    match st.duration_since(UNIX_EPOCH) {
        Ok(d) => Timestamp::from_nanos(i64::try_from(d.as_nanos()).unwrap_or(i64::MAX)),
        Err(e) => {
            Timestamp::from_nanos(-i64::try_from(e.duration().as_nanos()).unwrap_or(i64::MAX))
        }
    }
}

/// What a restore produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RestoreOutcome {
    /// Where it actually landed. A [`RestoreTarget::Conflict`] means the
    /// original path was occupied and the caller owes the user an alert.
    pub target: RestoreTarget,
    pub attrs: RestoredAttrs,
}

impl RestoreOutcome {
    pub fn path(&self) -> &str {
        match &self.target {
            RestoreTarget::Original(p) => p,
            RestoreTarget::Conflict { chosen, .. } => chosen,
            // Unreachable: `restore_file` turns exhaustion into
            // `RestoreError::NoFreeName` and never builds an outcome from it.
            // Kept as the original path rather than an `unreachable!` — a
            // panic in a getter is not worth an impossible branch.
            RestoreTarget::Exhausted { original, .. } => original,
        }
    }

    /// Whether the user must be told the file did not land where it came from.
    pub fn needs_conflict_alert(&self) -> bool {
        matches!(self.target, RestoreTarget::Conflict { .. })
    }
}

/// Write `bytes` back, honouring the fidelity contract.
///
/// A convenience over [`restore_stream`] for callers that already hold the
/// whole object — the tests, and nothing else. **A caller restoring a large
/// object must use `restore_stream`**: `&[u8]` requires the entire object in
/// memory before the first byte reaches disk, which for the 50 GB objects the
/// tier path exists for is more than the daemon has.
pub fn restore_file(
    original: &Path,
    bytes: &[u8],
    manifest: &FidelityManifest,
) -> Result<RestoreOutcome> {
    restore_stream(original, &mut &bytes[..], manifest)
}

/// Stream `src` back, honouring the fidelity contract.
///
/// Exclusive-create at the syscall, then `mtime` and `mode`, then a read-back
/// verified against `manifest`. Returns the breaches rather than a bare failure
/// so a restore report can name what did not survive.
///
/// # Why a reader
///
/// The read-back streams — it was changed to, precisely so a 50 GB restore
/// does not need a 50 GB buffer to VERIFY — and the input side still demanded
/// one to WRITE. Half a fix: the allocation was moved out of the second half
/// of the function and left in every caller.
///
/// `std::io::Read` rather than a ranged-fetch trait: the copy below is
/// synchronous file I/O, and an async caller supplies a reader over its own
/// ranged fetches, which is the shape `verify_full_content_of` already uses on
/// the other side. Choosing the async abstraction now would be designing for a
/// caller that does not exist — `restore_stream` has no production caller yet,
/// and §4.10.5's hydration path is where it lands.
pub fn restore_stream(
    original: &Path,
    src: &mut dyn std::io::Read,
    manifest: &FidelityManifest,
) -> Result<RestoreOutcome> {
    let original_s = original.to_string_lossy().to_string();
    // `symlink_metadata`, not `exists`. `exists` FOLLOWS the link, so a
    // DANGLING symlink at the original path answers "nothing is here" — and
    // then `create_new` correctly refuses, because a directory entry very much
    // is there. The restore fails, and every retry fails identically, instead
    // of landing beside the occupant the way every other occupied path does.
    //
    // The question this predicate is asked is "is the NAME taken", and a name
    // is taken by any directory entry whatever it points at.
    let target = choose_restore_path(&original_s, &|p| {
        std::fs::symlink_metadata(Path::new(p)).is_ok()
    });
    let chosen = PathBuf::from(match &target {
        RestoreTarget::Original(p) => p.clone(),
        RestoreTarget::Conflict { chosen, .. } => chosen.clone(),
        RestoreTarget::Exhausted { original, ceiling } => {
            return Err(RestoreError::NoFreeName {
                path: original.clone(),
                ceiling: *ceiling,
            });
        }
    });

    // O_EXCL, not exists()-then-create. The gap between a check and a create is
    // a window in which the user's own new file can appear, and overwriting it
    // would be Shepherd destroying data by writing.
    //
    // Owner-only AT CREATION, not afterwards. `File::create_new` asks for 0666
    // and the umask trims it to 0644 on an ordinary login, so a private file
    // was published world-readable for the whole of `write_and_verify` — every
    // byte written and fsynced — before the manifest's mode was applied. Any
    // account that can traverse the directory could open it inside that window
    // and keep the descriptor afterwards; a chmod does not close a file
    // somebody already has open. Restoring a `0600` file has to mean it was
    // never readable, not that it stopped being readable.
    let f = create_owner_only(&chosen).map_err(|e| {
        if e.kind() == std::io::ErrorKind::AlreadyExists {
            RestoreError::AlreadyExists {
                path: chosen.display().to_string(),
            }
        } else {
            RestoreError::Io {
                path: chosen.display().to_string(),
                detail: e.to_string(),
            }
        }
    })?;

    // Captured from the HANDLE, before anything can go wrong, because this is
    // the only moment at which "the inode at `chosen`" and "the inode this
    // attempt created" are known to be the same thing. `None` means the
    // platform (or a failing `fstat`) cannot name it, and a cleanup that cannot
    // prove ownership does nothing — see [`discard_failed_attempt`].
    let created = f.metadata().ok().and_then(|md| inode_of(&md));

    // Every failure from here on goes through the cleanup. Nothing is returned
    // early: an error path that skipped it is exactly the defect this shape
    // exists to make unreachable.
    match write_and_verify(f, &chosen, src, manifest, created) {
        Ok(attrs) => Ok(RestoreOutcome { target, attrs }),
        Err(e) => {
            discard_failed_attempt(&chosen, created);
            Err(e)
        }
    }
}

/// Exclusive-create a file that is owner-only from its first instant.
///
/// The mode is a request, not a guarantee: the umask can only REMOVE bits, so
/// the result is `0600` or tighter, never looser. The manifest's real mode is
/// applied later — this is only about what is true in between.
#[cfg(unix)]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    use std::os::unix::fs::OpenOptionsExt;
    // `.read(true)` as well: `File::create_new` opens read-WRITE, and the
    // verification reads every byte back through this same handle. Dropping it
    // turns the read-back into `EBADF`, which is a restore that fails rather
    // than one that lies — but a failure all the same.
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

/// Windows has no umask and no mode bits to leak through one; the inherited
/// ACL is the directory's, which is the platform's own answer to this question.
/// Phase 3 owns Windows ACL fidelity, with the rest of the platform.
#[cfg(not(unix))]
fn create_owner_only(path: &Path) -> std::io::Result<std::fs::File> {
    std::fs::File::create_new(path)
}

/// Everything between the exclusive create and a verified restore.
///
/// Split out so that [`restore_file`] has exactly one error path to clean up
/// after, rather than six `?`s each of which has to remember to.
fn write_and_verify(
    mut f: std::fs::File,
    chosen: &Path,
    src: &mut dyn std::io::Read,
    manifest: &FidelityManifest,
    created: Option<CreatedInode>,
) -> Result<RestoredAttrs> {
    let io = |e: std::io::Error| RestoreError::Io {
        path: chosen.display().to_string(),
        detail: e.to_string(),
    };

    // Copied through a fixed buffer, so the peak is the buffer rather than the
    // object. The length is COUNTED rather than trusted: a source that ends
    // early would otherwise produce a short file whose only complaint is a
    // content breach, and "the download stopped" is a different problem from
    // "the bytes were wrong".
    let mut written = 0u64;
    let mut buf = vec![0u8; RESTORE_CHUNK];
    loop {
        let n = src.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        f.write_all(&buf[..n]).map_err(io)?;
        written += n as u64;
    }
    if written != manifest.core.size {
        return Err(RestoreError::Io {
            path: chosen.display().to_string(),
            detail: format!(
                "the source supplied {written} bytes and the manifest records {}; the restore \
                 was truncated rather than corrupt",
                manifest.core.size
            ),
        });
    }
    f.sync_all().map_err(io)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // `fchmod`, through the held handle — NOT `std::fs::set_permissions`,
        // which takes a name and re-resolves it. `create_new` succeeding says
        // the name was ours at the syscall and says nothing about now, so a
        // pathname chmod here sets the mode of **whatever is at the name**,
        // which on a replaced destination is a file this restore never created.
        // `File::set_permissions` takes `&self` and is the same call without the
        // re-resolution.
        f.set_permissions(std::fs::Permissions::from_mode(manifest.core.mode))
            .map_err(io)?;
    }

    // Set mtime last: writing and chmod both touch it.
    f.set_modified(to_system_time(manifest.core.mtime))
        .map_err(io)?;

    // A SECOND sync, for the metadata this time.
    //
    // The `sync_all` above made the BYTES durable, before the mode and mtime
    // were applied. On a filesystem where inode metadata needs its own fsync, a
    // power loss after this function reports success can leave the right bytes
    // under a reverted mode or mtime — and the in-memory read-back below would
    // have passed, because it reads what the kernel holds rather than what
    // survived. A reverted mtime is not cosmetic either: it can immediately
    // requalify the file for the age-based rule that tiered it.
    //
    // Through the handle, like everything else here, so it cannot land on a
    // file this restore did not create.
    f.sync_all().map_err(io)?;

    // Read back through the SAME handle, for the same reason. A pathname
    // read-back verifies the bytes and metadata of whatever the name resolves
    // to at that instant, so a replacement that happens to match the manifest
    // makes a restore that published nothing report success.
    let attrs = read_back_through(&mut f, chosen)?;
    if let Err(breaches) = verify_restore(manifest, &attrs) {
        return Err(RestoreError::FidelityBreached {
            path: chosen.display().to_string(),
            breaches,
        });
    }

    // Last, and the only claim the handle cannot make on its own: the verified
    // inode is what the destination NAMES. Everything above proves the bytes
    // and metadata are right; this proves they are reachable at the path the
    // caller will be told about. Without it a restore can be internally perfect
    // and externally absent.
    //
    // It is a stat, so it is a TOCTOU in the same sense `discard_failed_attempt`
    // is: a replacement landing after this check is reported as success. Stated
    // rather than hidden — closing it needs an atomic publish primitive, which
    // is the `renameat2` discussion in the module docs. What it does close is
    // the whole interval from `create_new` to here, which spans the write, the
    // fsync, both metadata calls and the read-back.
    still_names_the_created_inode(chosen, created)?;

    // The NAME, made durable. Both `sync_all` calls above are about the inode —
    // its bytes and then its metadata — and on a filesystem where a newly
    // created directory entry needs its parent fsynced, neither of them makes
    // the entry that POINTS at that inode survive a power loss. A restore could
    // therefore report success, and the pathname it reported be gone after a
    // reboot with the bytes still sitting in an unreferenced inode.
    //
    // After the inode-and-name check, deliberately: syncing before it would
    // make durable a name this function had not yet established was ours.
    if let Some(parent) = chosen.parent() {
        sync_dir(parent).map_err(|e| RestoreError::Io {
            path: parent.display().to_string(),
            detail: format!("the restored name is not durable: {e}"),
        })?;
    }

    drop(f);
    Ok(attrs)
}

/// How much of a restore is held in memory at once.
///
/// The same order as the verification chunk on the other side of this function:
/// large enough that the copy is not syscall-bound, small enough that it is a
/// buffer rather than a fraction of the object.
const RESTORE_CHUNK: usize = 8 * 1024 * 1024;

/// fsync a directory, so an entry created in it survives a crash.
///
/// A four-line local rather than a shared utility: `shepherd-placeholder` has
/// the same primitive for the staging rename, and exporting a generic
/// filesystem call across a crate boundary to save four lines would put a
/// dependency edge where there is no shared concept — the two callers agree on
/// `fsync(2)`, not on a Shepherd idea.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    std::fs::File::open(dir)?.sync_all()
}

/// POSIX-only, and a no-op elsewhere rather than an error: opening a directory
/// as a file is not something the Windows API permits, so the durability this
/// buys on unix is not expressible there. Windows durability is Phase 3's.
#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

/// Read a restored file's attributes back **through the handle that created
/// it**, rather than by re-resolving its name.
///
/// The [`read_back`] twin. That one is public and pathname-based because its
/// callers — the fidelity report, the e2e round trip — genuinely want to ask
/// "what is at this path"; this one is the verification step inside a restore,
/// which must ask "what is in the file I made" and must not be satisfiable by a
/// replacement that happens to match.
fn read_back_through(f: &mut std::fs::File, chosen: &Path) -> Result<RestoredAttrs> {
    use std::io::{Read, Seek, SeekFrom};
    let io = |e: std::io::Error| RestoreError::Io {
        path: chosen.display().to_string(),
        detail: e.to_string(),
    };

    // STREAMED, not `read_to_end`. §4.5 sizes this path for 50 GB objects, and
    // reading the restored file whole allocated a second copy of it beside the
    // one the caller is already holding — so verifying a 50 GB restore asked
    // for another 50 GB of resident memory and normally terminated the daemon
    // instead of restoring anything.
    //
    // A fixed buffer plus an incremental hasher answers the same two questions
    // — what the bytes hash to, and how many there are — in constant space.
    // The caller still passes the whole payload in as `bytes`, which is the
    // other half of the same problem and a signature change rather than a fix
    // here; this is the half this function owns.
    f.seek(SeekFrom::Start(0)).map_err(io)?;
    let mut hasher = blake3::Hasher::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }

    // `fstat`, so the mode and mtime describe the same inode as the bytes.
    let md = f.metadata().map_err(io)?;
    let mtime = md.modified().map_err(io)?;

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = u32::from(md.permissions().readonly());

    Ok(RestoredAttrs {
        blake3: Blake3Hash::from_bytes(*hasher.finalize().as_bytes()),
        size,
        mtime: from_system_time(mtime),
        mode,
    })
}

/// Whether `chosen` still resolves to the inode this attempt created.
///
/// `None` for `created` is the same COVERAGE GAP [`discard_failed_attempt`]
/// states: off unix nothing can name the inode, so nothing can check this.
/// Refusing there would make restore — a non-destructive operation — fail on
/// every Windows run, which is a worse answer than a warning. Phase 3 owns it.
fn still_names_the_created_inode(chosen: &Path, created: Option<CreatedInode>) -> Result<()> {
    let Some(created) = created else {
        tracing::warn!(
            path = %chosen.display(),
            "this platform cannot name the inode this restore created, so it cannot be              confirmed that the destination still holds it"
        );
        return Ok(());
    };
    let displaced = || RestoreError::Displaced {
        path: chosen.display().to_string(),
    };
    match std::fs::symlink_metadata(chosen) {
        Ok(md) if inode_of(&md) == Some(created) => Ok(()),
        // A different inode at the name, or no entry at all. Both mean the same
        // thing to the caller: the restored inode is not published there.
        Ok(_) => Err(displaced()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Err(displaced()),
        Err(e) => Err(RestoreError::Io {
            path: chosen.display().to_string(),
            detail: e.to_string(),
        }),
    }
}

/// The exact inode one restore attempt created.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CreatedInode {
    dev: u64,
    ino: u64,
}

/// `(dev, ino)` where the platform has them.
///
/// `None` off unix is a COVERAGE GAP rather than a solved problem, and it is
/// the same one `destroy.rs` states: Windows has `FILE_ID_INFO` plus a volume
/// serial and nobody has written it, so a failed restore there still leaves its
/// file behind. Phase 3 owns Windows; a cleanup that guessed at identity would
/// be worse than one that declines, because it would unlink by path.
fn inode_of(md: &std::fs::Metadata) -> Option<CreatedInode> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Some(CreatedInode {
            dev: md.dev(),
            ino: md.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        let _ = md;
        None
    }
}

/// Remove a failed attempt's file — **only** if the name still holds the inode
/// that attempt created.
///
/// Never unlinks by path alone. Between the failure and this call, the name can
/// have been taken by a file somebody else made, and deleting that would be
/// Shepherd destroying data on the error path of an operation whose whole
/// premise is that it never destroys data. That is the same hazard
/// `identity.rs`'s probe had.
///
/// The `symlink_metadata`-then-`remove_file` pair is itself a TOCTOU, stated
/// rather than hidden: a replacement landing in that window is unlinked. Closing
/// it needs an unlink-by-handle primitive POSIX does not offer, and the window
/// is orders of magnitude smaller than the one this closes — the failed attempt
/// otherwise occupies the path until a human notices.
///
/// Reports rather than returns: the caller already has the real error, and
/// replacing it with a cleanup failure would hide why the restore failed.
fn discard_failed_attempt(chosen: &Path, created: Option<CreatedInode>) {
    let Some(created) = created else {
        tracing::warn!(
            path = %chosen.display(),
            "a failed restore cannot be cleaned up: this platform cannot name the inode \
             it created, so the file is left rather than unlinked by path"
        );
        return;
    };
    match std::fs::symlink_metadata(chosen) {
        Ok(md) if inode_of(&md) == Some(created) => {
            if let Err(e) = std::fs::remove_file(chosen) {
                tracing::error!(
                    path = %chosen.display(),
                    error = %e,
                    "a failed restore could not be cleaned up; the path is occupied by \
                     partial or invalid data and a retry will treat it as a conflict"
                );
                return;
            }
            // The unlink is not finished until the directory that named the
            // entry is durable. `write_and_verify` has already fsynced this
            // file and its metadata, so a power cut here rolls back only the
            // removal — resurrecting the partial or fidelity-invalid file at
            // the original path. The next restore then finds Shepherd's own
            // failed output, calls it a user conflict, and lands the file
            // somewhere else under a `(restored N)` name.
            //
            // Reported, not returned, for the same reason as everything else
            // here: the caller already has the real error and must not have it
            // replaced by a cleanup failure.
            if let Some(parent) = chosen.parent()
                && let Err(e) = sync_dir(parent)
            {
                tracing::error!(
                    path = %chosen.display(),
                    error = %e,
                    "a failed restore was unlinked but its directory could not be synced; \
                     a power loss now can bring the failed output back at this path"
                );
            }
        }
        Ok(_) => tracing::warn!(
            path = %chosen.display(),
            "a failed restore's path now holds a DIFFERENT file; leaving it alone rather \
             than deleting something this attempt did not create"
        ),
        // Already gone. Nothing to do, and not a fault.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => tracing::error!(
            path = %chosen.display(),
            error = %e,
            "a failed restore's path cannot be statted, so its cleanup cannot prove \
             ownership; leaving the file rather than unlinking by path"
        ),
    }
}

/// Read a restored file's attributes back off the filesystem.
///
/// Separate and public because "we asked for this mtime" and "the filesystem
/// kept it" are different claims, and only the read-back settles the second.
pub fn read_back(path: &Path) -> Result<RestoredAttrs> {
    use std::io::Read;
    let io = |e: std::io::Error| RestoreError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    };

    // Streamed for the same reason [`read_back_through`] is: §4.5 sizes this
    // path for 50 GB objects, and `std::fs::read` allocates the whole file.
    let mut f = std::fs::File::open(path).map_err(io)?;
    let mut hasher = blake3::Hasher::new();
    let mut size = 0u64;
    let mut buf = vec![0u8; 1024 * 1024];
    loop {
        let n = f.read(&mut buf).map_err(io)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
        size += n as u64;
    }

    let md = std::fs::metadata(path).map_err(|e| RestoreError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    let mtime = md.modified().map_err(|e| RestoreError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;

    #[cfg(unix)]
    let mode = {
        use std::os::unix::fs::PermissionsExt;
        md.permissions().mode() & 0o7777
    };
    #[cfg(not(unix))]
    let mode = u32::from(md.permissions().readonly());

    Ok(RestoredAttrs {
        blake3: Blake3Hash::from_bytes(*hasher.finalize().as_bytes()),
        size,
        mtime: from_system_time(mtime),
        mode,
    })
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod tests;
