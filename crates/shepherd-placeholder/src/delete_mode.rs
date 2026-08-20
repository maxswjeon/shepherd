//! Delete-mode: the reference `PlaceholderProvider` (§4.10.1, Unix roots).
//!
//! Linux is delete-mode only — there are no placeholders — and it is the
//! platform M2 ships on, so this is the implementation every §4.10 invariant is
//! first proven against.
//!
//! # `RENAME_NOREPLACE` is the whole design
//!
//! The rename must fail if the destination exists. A plain `rename(2)` silently
//! replaces, which would let a staging-name collision destroy a *different*
//! staged file. Linux gets `renameat2(RENAME_NOREPLACE)` (≥ 3.15), macOS gets
//! `renameatx_np(RENAME_EXCL)`; the plan cites `libc` as exposing both.
//!
//! `EINVAL` from `renameat2` means the filesystem does not implement the flag —
//! true of some FUSE and exFAT mounts. §4.10.1 is emphatic that **there is no
//! detect-only fallback**: iteration 2 fell back to pathname deletion and logged
//! the residual, "which directly contradicted its own fail-closed gate — a plan
//! cannot promise fail-closed and then ship the failure mode behind a log line".
//! So the probe reports [`Feasibility::Ineligible`] and the root never destroys.
//!
//! # One staging directory per registered root
//!
//! Staging lives at the **registered scan root**, created lazily, and every
//! file under that root — however deep — stages into that one directory. The
//! reason is recovery and not tidiness: `list_staged` is called with the
//! registered root and reads `<root>/.shepherd-staging` alone, so an entry
//! anywhere else is an entry a crash strands where nothing will look for it.
//! An earlier version staged under each file's own parent, which meant
//! `root/a/b/file` left its bytes in `root/a/b/.shepherd-staging` — present on
//! disk, invisible to recovery.
//!
//! `rename` cannot cross filesystems, so this makes a **submount under the
//! root** stage-ineligible: the rename returns `EXDEV` and destruction aborts
//! before anything irreversible. That is the fail-closed direction and it is
//! the correct trade — refusing to destroy is recoverable, staging where
//! recovery cannot look is not.
//!
//! The directory is deny-listed from scan and watch
//! (`shepherd-scan::denylist::STAGING_DIR_NAME`) so its entries never read as
//! user data appearing and vanishing.
//!
//! # What `0700` on the staging directory does not buy
//!
//! Nothing that matters here. Shepherd is a **per-user daemon**, so every
//! process the user runs shares its UID and can still reach the staged entry by
//! name. §4.10.1 records that iteration 4's test expected `0700` to deny a
//! same-UID reopen and "would have passed while the hazard remained". The mode
//! is set because excluding *other* users is still worth doing — but it is not
//! the boundary, and the staged-path-reopen test asserts the hazard is real.

use std::path::{Path, PathBuf};

use shepherd_core::Blake3Hash;

use crate::provider::{
    Feasibility, FileIdentity, PlaceholderProvider, ProviderError, ProviderMode, RestoreOutcome,
    Result, Staged,
};

/// Directory name used for staging. Must match
/// `shepherd_scan::denylist::STAGING_DIR_NAME`; the walker denies it by that
/// name so staged entries are never catalogued.
pub const STAGING_DIR_NAME: &str = ".shepherd-staging";

#[derive(Debug, Default, Clone)]
pub struct DeleteModeProvider;

impl DeleteModeProvider {
    pub fn new() -> Self {
        Self
    }

    /// The staging directory for a registered root.
    ///
    /// One per root rather than one beside each file, so recovery is a single
    /// listing — and so that listing is *complete*. `stage_for_destruction` and
    /// `list_staged` both route through here, which is what keeps the writer
    /// and the reader pointed at the same directory.
    fn staging_dir(root: &Path) -> PathBuf {
        root.join(STAGING_DIR_NAME)
    }

    /// Create the staging directory if it is not there, and make the
    /// **registered root's own directory entry for it** durable.
    ///
    /// The root sync is the easy one to miss. Staging a nested file syncs the
    /// staging directory (the new entry) and the file's source parent (the
    /// removed one) — and on a first destruction under this root, the entry
    /// naming `.shepherd-staging` itself lives in a THIRD directory, the
    /// registered root, which neither of those is. A power loss then persists
    /// the nested source removal while losing the staging directory entry, and
    /// the file's only local bytes go with it.
    ///
    /// Synced here rather than in the caller so it happens BEFORE the rename
    /// that depends on it, which is the ordering that makes it worth anything.
    fn ensure_staging(root: &Path) -> Result<PathBuf> {
        // The ROOT first, because the staging directory's own mode and owner
        // say nothing about who may rename its ENTRY. Renaming
        // `.shepherd-staging` needs write permission on the directory that
        // names it, not on the directory itself — so an account that can write
        // the root can move ours aside, drop a symlink in its place, and every
        // pathname-resolved staging operation after that lands wherever the
        // symlink points. The checks below verify a directory; this verifies
        // that the name still means it.
        secure_staging_parent(root)?;
        let dir = Self::staging_dir(root);
        // Checked BEFORE `create_dir_all`, which answers `EEXIST` for anything
        // already at the path — a bare "File exists" tells an operator nothing
        // about a staging path occupied by a regular file or a symlink, which
        // is the case `secure_staging` exists to refuse.
        let existed = match std::fs::symlink_metadata(&dir) {
            Ok(md) if md.is_dir() => true,
            Ok(_) => return Err(not_a_directory(&dir)),
            Err(_) => false,
        };
        std::fs::create_dir_all(&dir).map_err(|e| ProviderError::Io {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        if !existed && let Err(e) = sync_dir(root) {
            return Err(ProviderError::Io {
                path: root.display().to_string(),
                detail: format!(
                    "the staging directory was created and the root that names it could not \
                     be made durable: {e}"
                ),
            });
        }
        // Excludes other users, and ENFORCED — see `secure_staging`. NOT a
        // boundary against the same UID; the module docs say why.
        secure_staging(&dir)?;
        Ok(dir)
    }
}

/// `rename(old -> new)` that fails if `new` exists.
///
/// Returns `Ok(false)` when the filesystem does not implement the flag
/// (`EINVAL`), which the caller turns into `destruction_ineligible` rather than
/// into a fallback.
#[cfg(target_os = "linux")]
fn rename_noreplace(old: &Path, new: &Path) -> std::result::Result<bool, std::io::Error> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_old = CString::new(old.as_os_str().as_bytes())?;
    let c_new = CString::new(new.as_os_str().as_bytes())?;
    // `renameat2` has no libc wrapper on all targets, so it goes through
    // `syscall`. AT_FDCWD with absolute paths; RENAME_NOREPLACE = 1.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            c_old.as_ptr(),
            libc::AT_FDCWD,
            c_new.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        // The filesystem does not implement the flag. Not a fallback trigger.
        Some(libc::EINVAL) | Some(libc::ENOSYS) | Some(libc::EOPNOTSUPP) => Ok(false),
        _ => Err(err),
    }
}

#[cfg(target_os = "macos")]
fn rename_noreplace(old: &Path, new: &Path) -> std::result::Result<bool, std::io::Error> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_old = CString::new(old.as_os_str().as_bytes())?;
    let c_new = CString::new(new.as_os_str().as_bytes())?;
    let rc = unsafe {
        libc::renameatx_np(
            libc::AT_FDCWD,
            c_old.as_ptr(),
            libc::AT_FDCWD,
            c_new.as_ptr(),
            libc::RENAME_EXCL,
        )
    };
    if rc == 0 {
        return Ok(true);
    }
    let err = std::io::Error::last_os_error();
    match err.raw_os_error() {
        Some(libc::EINVAL) | Some(libc::ENOTSUP) => Ok(false),
        _ => Err(err),
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn rename_noreplace(_old: &Path, _new: &Path) -> std::result::Result<bool, std::io::Error> {
    // Windows uses `FileDispositionInfoEx` on the held handle and does not
    // stage at all (§4.10.1). Reporting "unsupported" here means a delete-mode
    // root on Windows is destruction-ineligible, which is the fail-closed
    // direction while `cfapi.rs` is Phase 3 work.
    Ok(false)
}

#[cfg(unix)]
fn identity_of(handle: &std::fs::File) -> Result<FileIdentity> {
    use std::os::unix::fs::MetadataExt;
    let md = handle.metadata().map_err(|e| ProviderError::Io {
        path: "<held handle>".into(),
        detail: e.to_string(),
    })?;
    Ok(FileIdentity {
        dev: md.dev(),
        ino: md.ino(),
        nlink: md.nlink(),
    })
}

#[cfg(not(unix))]
fn identity_of(_handle: &std::fs::File) -> Result<FileIdentity> {
    Err(ProviderError::Unsupported("file identity"))
}

impl PlaceholderProvider for DeleteModeProvider {
    fn mode(&self) -> ProviderMode {
        ProviderMode::DeleteMode
    }

    /// D-12's enrollment probe: create a throwaway file, attempt a
    /// `RENAME_NOREPLACE` onto an occupied name and onto a free one, clean up.
    ///
    /// Both directions are checked. A filesystem that fails the rename outright
    /// cannot stage; one that *succeeds* when the destination exists is worse —
    /// it silently replaces, which is the collision the flag exists to prevent.
    fn probe_feasibility(&self, root: &Path) -> Result<Feasibility> {
        let dir = Self::ensure_staging(root)?;

        // Unique per invocation, and created EXCLUSIVELY.
        //
        // Fixed names plus a truncating `write` plus an unconditional
        // `remove_file` is a destroy-by-writing on a path this module does not
        // own: a file already at `.probe-a` was overwritten and then deleted.
        // Two probes of the same root were worse than that — they erased or
        // renamed each other's fixtures, and the loser can conclude
        // `RENAME_NOREPLACE` is unimplemented and persist a false
        // `destruction_ineligible` verdict for the root.
        //
        // The tag is pid plus a process-local counter: two invocations in one
        // process differ by the counter, and two processes cannot share a pid
        // while both are running.
        let tag = format!(
            "{}-{}",
            std::process::id(),
            PROBE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        );
        let a = dir.join(format!(".probe-{tag}-a"));
        let b = dir.join(format!(".probe-{tag}-b"));
        let free = dir.join(format!(".probe-{tag}-c"));

        // Removes only what this invocation actually created. `a` is consumed
        // by a successful rename, which is why each is tracked separately.
        let created = std::cell::Cell::new((false, false, false));
        let cleanup = || {
            let (ca, cb, cf) = created.get();
            if ca {
                let _ = std::fs::remove_file(&a);
            }
            if cb {
                let _ = std::fs::remove_file(&b);
            }
            if cf {
                let _ = std::fs::remove_file(&free);
            }
        };

        let make = |p: &Path| -> std::io::Result<()> {
            use std::io::Write;
            std::fs::File::create_new(p)?.write_all(b"probe")
        };

        if let Err(e) = make(&a) {
            cleanup();
            return Err(ProviderError::Io {
                path: a.display().to_string(),
                detail: e.to_string(),
            });
        }
        created.set((true, false, false));
        if let Err(e) = make(&b) {
            cleanup();
            return Err(ProviderError::Io {
                path: b.display().to_string(),
                detail: e.to_string(),
            });
        }
        created.set((true, true, false));

        // 1. Onto an OCCUPIED name: must refuse.
        match rename_noreplace(&a, &b) {
            Ok(true) => {
                cleanup();
                return Ok(Feasibility::Ineligible {
                    reason: "rename replaced an existing destination: this filesystem does not \
                             honour RENAME_NOREPLACE, so staging cannot detect a collision"
                        .into(),
                });
            }
            Ok(false) => {
                cleanup();
                return Ok(Feasibility::Ineligible {
                    reason: "RENAME_NOREPLACE is not implemented on this filesystem (EINVAL). \
                             §4.10.1 permits no detect-only fallback, so this root is \
                             destruction_ineligible"
                        .into(),
                });
            }
            Err(_) => { /* refused, as it must */ }
        }

        // 2. Onto a FREE name: must succeed. Not pre-deleted — the name is
        // unique to this invocation, so anything already there is not ours to
        // remove, and `rename_noreplace` refusing is the correct answer.
        let ok = rename_noreplace(&a, &free);
        if matches!(ok, Ok(true)) {
            // `a` moved onto `free`: ownership moves with it.
            created.set((false, true, true));
        }
        cleanup();

        match ok {
            Ok(true) => Ok(Feasibility::Supported),
            Ok(false) => Ok(Feasibility::Ineligible {
                reason: "RENAME_NOREPLACE is not implemented on this filesystem".into(),
            }),
            Err(e) => Ok(Feasibility::Ineligible {
                reason: format!("staging rename failed: {e}"),
            }),
        }
    }

    fn stage_for_destruction(&self, root: &Path, path: &Path) -> Result<Staged> {
        // Step 1: acquire the handle FIRST. Everything after this point works
        // through it, so no pathname is re-resolved.
        let handle = std::fs::File::open(path).map_err(|e| ProviderError::Acquire {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;

        // The REGISTERED ROOT, not `path.parent()`. Recovery calls
        // `list_staged` with this same root and reads exactly one directory, so
        // staging a nested file beside itself would hide its bytes from the
        // only pass that could restore them.
        let dir = Self::ensure_staging(root)?;

        // Staged name is derived from identity, not from the user's filename:
        // two files with the same basename in different directories must not
        // collide, and a name the user controls should not steer where the
        // destroy path writes.
        let pre = identity_of(&handle)?;
        let staged = dir.join(format!("{}-{}.staged", pre.dev, pre.ino));

        // Step 2.
        match rename_noreplace(path, &staged) {
            Ok(true) => {
                // A cross-directory rename is two directory changes, and
                // neither is durable until its directory is. A power loss can
                // persist the removal from the source directory without the new
                // entry in the staging directory, at which point the file's only
                // local bytes are reachable from neither name — while the intent
                // says it was staged and `list_staged`, which is all recovery
                // has, finds nothing.
                //
                // The staging directory is synced FIRST on purpose. If the
                // machine dies between the two, the surviving state is the entry
                // existing under both names, which recovery handles; the other
                // order leaves exactly the hole this closes.
                if let Err(e) = sync_dir(&dir).and_then(|()| match path.parent() {
                    Some(parent) => sync_dir(parent),
                    None => Ok(()),
                }) {
                    // Durability could not be established, so this must not be
                    // reported as staged. §4.10.4 is abort-forward-never: put
                    // the file back before saying so.
                    //
                    // And the rollback's own result is not discardable. It is a
                    // `RENAME_NOREPLACE`, so it fails if the original name was
                    // reoccupied while the file was in staging — and this
                    // function returns no `Staged`, so the caller has nothing to
                    // hand `restore_staged`. A discarded failure here left the
                    // user's only local copy out of its original path with the
                    // caller told only that a sync failed.
                    //
                    // Recovery can still find it: the entry is in the staging
                    // directory and `list_staged` is exactly what lists it. So
                    // the error says WHERE, loudly, which is the same contract
                    // `restore_or_report` keeps on the other rollback path.
                    return Err(unwind_staging(
                        path,
                        &staged,
                        ProviderError::Io {
                            path: dir.display().to_string(),
                            detail: format!("staging rename is not durable: {e}"),
                        },
                    ));
                }
            }
            Ok(false) => {
                return Err(ProviderError::NotFeasible {
                    path: path.display().to_string(),
                });
            }
            Err(e) if e.raw_os_error() == Some(libc_eexist()) => {
                return Err(ProviderError::DestinationExists {
                    path: staged.display().to_string(),
                });
            }
            Err(e) => {
                return Err(ProviderError::Io {
                    path: path.display().to_string(),
                    detail: e.to_string(),
                });
            }
        }

        // Step 3: identity read back from the HELD handle. `rename` does not
        // invalidate descriptors, so this is the same open file — which is the
        // property that makes the staging design identity-bound.
        //
        // A failure here is post-rename, so it gets the post-rename treatment
        // rather than a bare `?`. The original name is already gone — durably,
        // by the syncs above — and this function returns no `Staged`, so the
        // caller has nothing to hand `restore_staged`. An `fstat` that fails
        // after an I/O fault or a removable volume disappearing would otherwise
        // leave the user's file absent from its original path with the caller
        // told only that a stat failed.
        let identity = match identity_of(&handle) {
            Ok(id) => id,
            Err(e) => return Err(unwind_staging(path, &staged, e)),
        };

        Ok(Staged {
            original: path.to_path_buf(),
            staged,
            identity,
            handle,
        })
    }

    fn destroy_local(&self, staged: &Staged, expected: Blake3Hash) -> Result<()> {
        tracing::warn!(
            original = %staged.original.display(),
            staged = %staged.staged.display(),
            identity = %staged.identity,
            hash = %expected,
            "destroying local file"
        );
        unlink_durably(&staged.staged)
    }

    /// # The move-back is durable before it is reported
    ///
    /// This is abort-forward-never's last step, and its whole promise is that
    /// the file is BACK. A cross-directory rename is two directory changes, so
    /// a power loss after a successful move-back can persist the removal of the
    /// staging entry without the new entry at the original name — and this
    /// function has already told the caller the file was recovered, while
    /// neither path holds it after the reboot. `list_staged`, recovery's only
    /// view, no longer sees it either.
    ///
    /// Both branches sync, and both sync the DESTINATION first: a crash between
    /// the two then leaves the file reachable under both names, which recovery
    /// handles, rather than under neither.
    fn restore_staged(&self, staged: Staged) -> Result<RestoreOutcome> {
        let staging = staged.staged.parent().map(Path::to_path_buf);
        let sync_both = |dest: &Path| -> Result<()> {
            if let Some(parent) = dest.parent() {
                sync_dir(parent).map_err(|e| ProviderError::Io {
                    path: parent.display().to_string(),
                    detail: format!("the move-back is not durable: {e}"),
                })?;
            }
            if let Some(staging) = &staging {
                sync_dir(staging).map_err(|e| ProviderError::Io {
                    path: staging.display().to_string(),
                    detail: format!("the move-back is not durable: {e}"),
                })?;
            }
            Ok(())
        };

        // Move-back is itself RENAME_NOREPLACE: the original path may have been
        // reoccupied while the file was staged, and overwriting whatever is
        // there would destroy a file the user created.
        match rename_noreplace(&staged.staged, &staged.original) {
            Ok(true) => {
                sync_both(&staged.original)?;
                Ok(RestoreOutcome::Restored {
                    path: staged.original.clone(),
                })
            }
            Ok(false) | Err(_) => {
                let conflict = conflict_name(&staged.original);
                match rename_noreplace(&staged.staged, &conflict) {
                    Ok(true) => {
                        sync_both(&conflict)?;
                        tracing::error!(
                            original = %staged.original.display(),
                            restored_to = %conflict.display(),
                            "original path was reoccupied during staging; restored under a \
                             conflict name — this needs a human"
                        );
                        Ok(RestoreOutcome::Conflicted {
                            path: conflict,
                            original: staged.original.clone(),
                        })
                    }
                    _ => Err(ProviderError::DestinationExists {
                        path: staged.original.display().to_string(),
                    }),
                }
            }
        }
    }

    /// # An unreadable staging directory is not an empty one
    ///
    /// This is startup recovery's ONLY view of the files a crash left staged —
    /// files whose bytes exist nowhere else, because staging is the step that
    /// removed them from their original name. `read_dir` failing was mapped to
    /// an empty list, so a permission change, an I/O error or an unmounted
    /// volume made recovery conclude there was nothing to recover and let
    /// destructive work resume beside the entries it had not seen.
    ///
    /// `NotFound` is the one error that genuinely means empty: no staging
    /// directory has ever been created under this root. Everything else — and
    /// every per-entry error, which `flatten()` used to discard one at a time —
    /// propagates.
    fn list_staged(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let dir = Self::staging_dir(root);
        let entries = match std::fs::read_dir(&dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => {
                return Err(ProviderError::Io {
                    path: dir.display().to_string(),
                    detail: format!(
                        "the staging directory could not be listed, so it must not be \
                         reported as empty: {e}"
                    ),
                });
            }
        };

        let mut out = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|e| ProviderError::Io {
                path: dir.display().to_string(),
                detail: format!("a staging entry could not be read: {e}"),
            })?;
            let p = entry.path();
            if p.extension().is_some_and(|x| x == "staged") {
                out.push(p);
            }
        }
        Ok(out)
    }
}

fn conflict_name(original: &Path) -> PathBuf {
    let mut name = original
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "restored".into());
    name.push_str(".shepherd-restored");
    original.with_file_name(name)
}

/// Every directory this process has fsync'd, for the test that the staging
/// rename is made durable. A rename's durability is not observable from the
/// filesystem afterwards, so the call itself is what gets asserted on.
#[cfg(test)]
pub(crate) static SYNCED_DIRS: std::sync::Mutex<Vec<PathBuf>> = std::sync::Mutex::new(Vec::new());

/// The refusal for a staging path occupied by something that is not a
/// directory. Shared by the pre-create check and by [`secure_staging`], so the
/// operator reads the same sentence whichever notices first.
fn not_a_directory(dir: &Path) -> ProviderError {
    ProviderError::Io {
        path: dir.display().to_string(),
        detail: "the staging path is not a directory; destruction stages the only local copy \
                 of a file into it and will not do so through something else"
            .into(),
    }
}

/// The staging directory must be a real directory, OURS, and owner-only.
///
/// The `chmod` used to be `let _ =`. A root writable by another account lets
/// that account pre-create `.shepherd-staging` and keep ownership of it, and
/// destruction then runs inside a directory somebody else controls — which is
/// not a permissions nicety on this path. Between the held-handle verification
/// and the pathname unlink, that account can rename or replace the staged
/// entry, so Shepherd unlinks a substitute and audits the ORIGINAL as
/// destroyed while its inode was moved elsewhere. It can also disrupt recovery
/// at will, since `list_staged` reads this directory.
///
/// So: the mode is enforced, the entry is required to be a directory rather
/// than a symlink into one, and the owner is checked. Refusing costs the user a
/// destruction that does not happen and says why; not refusing costs an audit
/// record that describes the wrong file.
/// Refuse a root whose staging entry another account could rename.
///
/// # Why the staging directory's own permissions are not enough
///
/// `secure_staging` proves the *directory* is ours and owner-only. It cannot
/// prove the NAME still resolves to it: rename and unlink are governed by the
/// containing directory, so an account with write permission on the registered
/// root can move `.shepherd-staging` aside and leave a symlink where it was —
/// after the check, and after the directory was verified. Every later staging
/// operation resolves that pathname again, so the rename, the sync and the
/// unlink all land inside the attacker's tree, and the audit record names an
/// inode that was never the one destroyed.
///
/// # Refusing rather than pinning
///
/// The complete fix is a pinned directory handle — open the verified directory
/// `O_DIRECTORY|O_NOFOLLOW` and drive `renameat2`, `unlinkat` and `fsync`
/// relative to that fd, so no pathname is ever resolved twice. That is a change
/// to every staging primitive in this module and to `list_staged`, and it is
/// the right eventual shape.
///
/// Until then this removes the *widest* form of the precondition: a root any
/// account on the machine can write. Refusing costs a destruction that does not
/// happen and says why.
///
/// # What this deliberately does NOT refuse, and why
///
/// **Group-writable roots.** The obvious rule — refuse `0o022` — refuses almost
/// every Linux home directory. A `002` umask is the default wherever each user
/// has a private group of their own (Debian and Ubuntu's `USERGROUPS_ENAB`,
/// among others), so ordinary directories are `0775` and the group with write
/// permission has exactly one member: the user. Refusing those would take a
/// safety check and turn it into "delete-mode does not work here", which is how
/// checks get switched off. Telling the safe case from the dangerous one means
/// resolving the group's membership, and that is a real answer rather than a
/// mode test.
///
/// **A hostile process running as the same user.** Out of scope by design —
/// this module's docs already say staging is not a boundary against the same
/// UID, and only the handle form would make it one.
///
/// The sticky bit is honoured because it is this rule already: on a sticky
/// directory only an entry's owner may rename or remove it, which is what
/// `/tmp` relies on. A world-writable sticky root is therefore fine.
#[cfg(unix)]
fn secure_staging_parent(root: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let md = std::fs::symlink_metadata(root).map_err(|e| ProviderError::Io {
        path: root.display().to_string(),
        detail: e.to_string(),
    })?;
    let mode = md.permissions().mode();
    let world_writable = mode & 0o002 != 0;
    let sticky = mode & 0o1000 != 0;
    if world_writable && !sticky {
        return Err(ProviderError::Io {
            path: root.display().to_string(),
            detail: format!(
                "the registered root is mode {:04o} and not sticky, so ANY account on this \
                 machine can rename `{STAGING_DIR_NAME}` and leave a symlink in its place — \
                 after which staging would move the file into a directory Shepherd never \
                 verified and the audit record would describe an inode that was not \
                 destroyed. Staging is refused until the root is not world-writable, or is \
                 sticky, which already restricts rename to the entry's owner",
                mode & 0o7777
            ),
        });
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_staging_parent(_root: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn secure_staging(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let io = |detail: String| ProviderError::Io {
        path: dir.display().to_string(),
        detail,
    };

    // `symlink_metadata`: a symlink pointing at a directory we own is not a
    // directory we own, and following it is exactly the substitution above.
    let md = std::fs::symlink_metadata(dir).map_err(|e| io(e.to_string()))?;
    if !md.is_dir() {
        return Err(not_a_directory(dir));
    }

    if let Ok(me) = std::fs::metadata("/proc/self").map(|m| m.uid())
        && md.uid() != me
    {
        return Err(io(format!(
            "the staging directory is owned by uid {} and this daemon runs as {me}; another \
             account owning it can replace a staged entry between verification and unlink, so \
             the audit record would describe a file that was not the one destroyed",
            md.uid()
        )));
    }

    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| io(format!("cannot make the staging directory owner-only: {e}")))?;
    let mode = std::fs::metadata(dir)
        .map_err(|e| io(e.to_string()))?
        .permissions()
        .mode()
        & 0o777;
    if mode != 0o700 {
        return Err(io(format!(
            "the staging directory is mode {mode:04o} after being set to 0700; a filesystem \
             that will not keep it owner-only cannot host staging"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn secure_staging(_dir: &Path) -> Result<()> {
    // Delete-mode refuses staging off unix anyway — `identity_of` fails closed
    // there — so there is nothing to secure that is ever used.
    Ok(())
}

/// Put a staged file back, and say what happened either way.
///
/// Every failure AFTER the rename has to come through here. The original name
/// is already gone, and `stage_for_destruction` returns no [`Staged`] on a
/// failure path — so the caller has nothing to hand
/// [`PlaceholderProvider::restore_staged`], and a discarded rollback leaves the
/// user's only local copy somewhere they did not put it while the caller is
/// told only about whatever failed second.
///
/// The rollback is a `RENAME_NOREPLACE`, so it refuses when the original name
/// was reoccupied while the file was staged. That case is
/// [`ProviderError::StagedAndStranded`], which names both paths: `list_staged`
/// is what finds the bytes and startup recovery is what calls it, but a human
/// should not have to wait for a restart to learn where their file went.
fn unwind_staging(original: &Path, staged: &Path, cause: ProviderError) -> ProviderError {
    match rename_noreplace(staged, original) {
        Ok(true) => {
            // The rollback is itself a cross-directory rename, so it is not
            // durable until both directories are — the same discipline
            // `restore_staged` keeps, destination first. Without it, a staging
            // rename that HAD been made durable can outlive its own undo: after
            // a power loss the original path is still absent and the file
            // reappears only in staging, while this call reported "the file was
            // put back".
            if let Some(parent) = original.parent()
                && let Err(e) = sync_dir(parent)
            {
                return stranded(
                    original,
                    staged,
                    &cause,
                    &format!("rollback not durable: {e}"),
                );
            }
            if let Some(staging) = staged.parent()
                && let Err(e) = sync_dir(staging)
            {
                return stranded(
                    original,
                    staged,
                    &cause,
                    &format!("rollback not durable: {e}"),
                );
            }
            match cause {
                ProviderError::Io { path, detail } => ProviderError::Io {
                    path,
                    detail: format!("{detail}; the file was put back at {}", original.display()),
                },
                other => other,
            }
        }
        rolled_back => stranded(
            original,
            staged,
            &cause,
            &format!("the file could not be moved back ({rolled_back:?})"),
        ),
    }
}

/// The report for a staging that could neither be completed nor undone.
///
/// One function because the two ways of reaching it — a reverse rename that
/// refused, and one that succeeded without becoming durable — owe the operator
/// the same thing: both paths named, and loudly, because `list_staged` finding
/// it at the next restart is a backstop rather than an answer.
fn stranded(original: &Path, staged: &Path, cause: &ProviderError, detail: &str) -> ProviderError {
    tracing::error!(
        original = %original.display(),
        staged = %staged.display(),
        cause = %cause,
        %detail,
        "STAGED AND STRANDED: staging could not be completed and could not be undone. The \
         file's only local copy is in the staging directory and is NOT at its original path; \
         startup recovery lists it, and a human should not have to wait for that"
    );
    ProviderError::StagedAndStranded {
        original: original.display().to_string(),
        staged: staged.display().to_string(),
        detail: format!("{cause}, and {detail}"),
    }
}

/// Distinguishes one feasibility probe's fixtures from another's in the same
/// process. See [`DeleteModeProvider::probe_feasibility`].
static PROBE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Unlink a staged file and make the removal durable.
///
/// Separate from [`PlaceholderProvider::destroy_local`] so it can be tested
/// without naming the tracked symbol — §4.1 rule 4a makes `shepherd-tier`'s
/// `destroy.rs` the sole caller of that method, and a test calling it would be
/// a second call site of exactly the kind the rule exists to prevent. The
/// durability primitive is not the destruction protocol.
///
/// # Why the directory fsync is here and not left to the caller
///
/// The unlink is not durable until its directory is, and what follows it IS
/// durable: an fsync'd audit record and a committed catalog transition, both
/// claiming the file is gone. A power loss between the two leaves the staged
/// entry on disk beside a record saying it was destroyed — the forensic log
/// describing a destruction that did not happen, which is the mirror of the
/// case the record exists to prevent.
///
/// A sync failure is [`ProviderError::DestroyedNotDurable`], NOT an ordinary
/// `Io`. The unlink already succeeded, so the caller must not restore or retry:
/// a plain error would send it down abort-forward-never, renaming a file that
/// may no longer exist and reporting a failure for an operation that happened.
fn unlink_durably(staged: &Path) -> Result<()> {
    std::fs::remove_file(staged).map_err(|e| ProviderError::Io {
        path: staged.display().to_string(),
        detail: e.to_string(),
    })?;

    if let Some(parent) = staged.parent()
        && let Err(e) = sync_dir(parent)
    {
        return Err(ProviderError::DestroyedNotDurable {
            path: staged.display().to_string(),
            detail: e.to_string(),
        });
    }
    Ok(())
}

/// fsync a directory, so an entry created or removed in it survives a crash.
///
/// Opening a directory read-only and fsync'ing the descriptor is the portable
/// POSIX way to do this, and it is what both ext4 and APFS document. It is
/// unix-only because the non-unix `rename_noreplace` above is a refusal: there
/// is no staging to make durable there.
#[cfg(unix)]
fn sync_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    SYNCED_DIRS.lock().unwrap().push(dir.to_path_buf());
    std::fs::File::open(dir)?.sync_all()
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn libc_eexist() -> i32 {
    libc::EEXIST
}
#[cfg(not(unix))]
fn libc_eexist() -> i32 {
    17
}

#[cfg(test)]
mod tests {
    /// Gate every test that needs staging to have SUCCEEDED.
    ///
    /// `stage_for_destruction` binds identity through a held handle, which needs
    /// `dev`/`ino`; the `#[cfg(not(unix))]` arm above returns
    /// `Unsupported("file identity")` and that is CORRECT — it fails closed on a
    /// platform where the binding cannot be made.
    ///
    /// These tests used to `unwrap()` that refusal, so the whole module failed on
    /// Windows and read as "delete-mode is broken" when the truth was "delete-mode
    /// correctly refuses and the tests assumed it would not". Gating the module
    /// away would have hidden that; asserting the refusal turns each failure into
    /// a check that destruction is REFUSED where identity cannot be bound.
    ///
    /// It asserts the SPECIFIC refusal, not that an error occurred: a bare
    /// `is_err()` would pass on a genuine bug anywhere in staging.
    #[must_use]
    fn staged_or_refused(r: Result<Staged>) -> Option<Staged> {
        match r {
            // `#[cfg]` on the arms rather than `assert!(cfg!(unix), ..)`:
            // clippy is right that the latter is a constant assertion. This
            // makes the two platforms genuinely different code, which is what
            // they are.
            #[cfg(unix)]
            Ok(s) => Some(s),
            #[cfg(not(unix))]
            Ok(_) => panic!(
                "staging SUCCEEDED on {}, where file identity is unsupported and \
                 the provider is supposed to fail closed. Either this platform \
                 gained an identity binding — in which case these tests must be \
                 updated to expect success, DELIBERATELY — or the refusal stopped \
                 refusing",
                std::env::consts::OS
            ),
            Err(ProviderError::Unsupported(what)) => {
                #[cfg(unix)]
                panic!(
                    "staging refused as `unsupported: {what}` ON UNIX, where file \
                     identity IS available. That is the binding breaking, not a \
                     platform lacking one"
                );
                #[cfg(not(unix))]
                {
                    assert_eq!(
                        what, "file identity",
                        "the refusal must name what could not be bound"
                    );
                    None
                }
            }
            Err(e) => panic!("staging failed for an unexpected reason: {e:?}"),
        }
    }

    use super::*;
    use std::io::Write;

    struct Tmp(PathBuf);
    impl Tmp {
        fn new(tag: &str) -> Self {
            let d = std::env::temp_dir().join(format!("shepherd-dm-{}-{tag}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).unwrap();
            Tmp(d)
        }
        fn file(&self, name: &str, bytes: &[u8]) -> PathBuf {
            let p = self.0.join(name);
            std::fs::write(&p, bytes).unwrap();
            p
        }
    }
    impl Drop for Tmp {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// The staging rename is made durable in **both** directories.
    ///
    /// A cross-directory rename removes an entry from one directory and creates
    /// one in another, and on a filesystem where rename durability requires a
    /// directory fsync a crash can persist only the removal. The intent then
    /// records the file as staged while `list_staged` — the only thing recovery
    /// reads — finds nothing, and the file's sole local bytes are reachable from
    /// neither name.
    ///
    /// Durability is not observable from the filesystem after the fact, so the
    /// fsync calls themselves are what this asserts on. `contains` rather than
    /// an exact list: the recorder is process-wide and other tests run beside
    /// this one.
    #[test]
    fn staging_syncs_both_directories() {
        let t = Tmp::new("dursync");
        let nested = t.0.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let f = nested.join("only-copy.bin");
        std::fs::write(&f, b"the only local copy").unwrap();

        let Some(staged) =
            staged_or_refused(DeleteModeProvider::new().stage_for_destruction(&t.0, &f))
        else {
            return;
        };

        let synced = SYNCED_DIRS.lock().unwrap().clone();
        let staging_dir = staged.staged.parent().unwrap().to_path_buf();
        assert!(
            synced.contains(&staging_dir),
            "the staging directory was never fsync'd, so the new entry may not \
             survive a crash: {synced:?}"
        );
        assert!(
            synced.contains(&nested),
            "the original's parent was never fsync'd, so the removal may not \
             survive a crash: {synced:?}"
        );
    }

    /// An unreadable staging directory must not read as an empty one.
    ///
    /// This is startup recovery's only view of the files a crash left staged,
    /// and staging is the step that removed them from their original name — so
    /// "nothing staged" and "I could not look" have opposite consequences and
    /// used to be the same value. `NotFound` is the one error that really means
    /// empty.
    ///
    /// Unix-only because making a directory unlistable is: the mode bits come
    /// from `PermissionsExt`, and delete-mode refuses staging off unix anyway.
    #[cfg(unix)]
    #[test]
    fn an_unlistable_staging_directory_is_an_error_not_an_empty_list() {
        use std::os::unix::fs::PermissionsExt;
        let t = Tmp::new("liststaged");
        let p = DeleteModeProvider::new();

        // No staging directory has ever existed: genuinely empty.
        assert_eq!(
            p.list_staged(&t.0).expect("a missing staging dir is empty"),
            Vec::<PathBuf>::new()
        );

        let f = t.0.join("only-copy.bin");
        std::fs::write(&f, b"the only local copy").unwrap();
        let Some(staged) = staged_or_refused(p.stage_for_destruction(&t.0, &f)) else {
            return;
        };
        assert_eq!(
            p.list_staged(&t.0).expect("listing works"),
            vec![staged.staged.clone()],
            "the staged entry is what recovery has to find"
        );

        // Now make it unlistable. Recovery must hear about it.
        let dir = staged.staged.parent().unwrap().to_path_buf();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o000)).unwrap();
        let listed = p.list_staged(&t.0);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();

        // Running as root makes a 0000 directory readable anyway, in which case
        // there is nothing to assert — the entry is simply still found.
        match listed {
            Err(ProviderError::Io { detail, .. }) => assert!(
                detail.contains("must not be reported as empty"),
                "the error must say what the empty list would have meant: {detail}"
            ),
            Ok(found) => assert_eq!(
                found,
                vec![staged.staged.clone()],
                "the only acceptable Ok here is the entry itself (running as root)"
            ),
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    /// The staged unlink is made durable, and a failure to do so is reported as
    /// destroyed-but-undurable rather than as a failed delete.
    ///
    /// What follows the unlink IS durable — an fsync'd audit record and a
    /// committed catalog transition, both claiming the file is gone. Without a
    /// directory fsync a power loss can preserve the staged entry beside a
    /// record saying it was destroyed: the forensic log describing a
    /// destruction that did not happen.
    #[test]
    fn the_staged_unlink_syncs_its_directory() {
        let t = Tmp::new("destroysync");
        let f = t.0.join("doomed.bin");
        std::fs::write(&f, b"bytes").unwrap();
        let p = DeleteModeProvider::new();
        let Some(staged) = staged_or_refused(p.stage_for_destruction(&t.0, &f)) else {
            return;
        };
        let dir = staged.staged.parent().unwrap().to_path_buf();

        // Counted rather than cleared: the recorder is process-wide and other
        // tests read it concurrently. Staging already synced this directory
        // once, so the assertion is that the unlink adds ANOTHER — `contains`
        // alone would be satisfied by the staging sync and prove nothing.
        let syncs_of = |d: &PathBuf| {
            SYNCED_DIRS
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p == d)
                .count()
        };
        let before = syncs_of(&dir);

        unlink_durably(&staged.staged).expect("the unlink succeeds");

        assert!(
            syncs_of(&dir) > before,
            "the staging directory was not fsync'd after the unlink, so the removal may \
             not survive the crash the audit record will"
        );
    }

    /// The move-back is durable before it is reported as a restore.
    ///
    /// This is abort-forward-never's last step, and its promise is that the
    /// file is BACK. A cross-directory rename is two directory changes, so
    /// without both syncs a power loss can persist the removal from staging
    /// without the entry at the original name — after the caller has already
    /// been told the file was recovered, and after `list_staged` stopped
    /// seeing it.
    #[test]
    fn restoring_a_staged_file_syncs_both_directories() {
        let t = Tmp::new("restoresync");
        let nested = t.0.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let f = nested.join("only-copy.bin");
        std::fs::write(&f, b"the only local copy").unwrap();
        let p = DeleteModeProvider::new();
        let Some(staged) = staged_or_refused(p.stage_for_destruction(&t.0, &f)) else {
            return;
        };
        let staging = staged.staged.parent().unwrap().to_path_buf();

        // Counted, not cleared: staging already synced both of these once, and
        // the recorder is process-wide. See `the_staged_unlink_syncs_its_directory`.
        let syncs_of = |d: &PathBuf| {
            SYNCED_DIRS
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p == d)
                .count()
        };
        let (before_dest, before_staging) = (syncs_of(&nested), syncs_of(&staging));

        let out = p.restore_staged(staged).expect("the move-back succeeds");
        assert!(matches!(out, RestoreOutcome::Restored { .. }), "{out:?}");
        assert!(f.exists(), "and the file really is back");

        assert!(
            syncs_of(&nested) > before_dest,
            "the destination's parent was not fsync'd, so the restored name may not survive"
        );
        assert!(
            syncs_of(&staging) > before_staging,
            "the staging directory was not fsync'd, so the removal may not survive"
        );
    }

    /// The probe neither overwrites nor deletes a file it did not create, and
    /// two probes of one root do not erase each other's fixtures.
    ///
    /// Fixed names plus a truncating `write` plus an unconditional
    /// `remove_file` destroyed by writing on a path this module does not own —
    /// and concurrent probes were worse, because the loser can conclude
    /// `RENAME_NOREPLACE` is unimplemented and persist a false
    /// `destruction_ineligible` verdict for the whole root.
    #[test]
    fn the_feasibility_probe_leaves_foreign_files_alone() {
        let t = Tmp::new("probe-excl");
        let p = DeleteModeProvider::new();

        // A file sitting at the OLD fixed probe name, with contents worth
        // keeping.
        let staging = DeleteModeProvider::staging_dir(&t.0);
        std::fs::create_dir_all(&staging).unwrap();
        for name in [".probe-a", ".probe-b", ".probe-c"] {
            std::fs::write(staging.join(name), b"a file the probe does not own").unwrap();
        }

        let f = p.probe_feasibility(&t.0).expect("the probe runs");
        assert_eq!(
            f.is_supported(),
            cfg!(unix),
            "the verdict itself must not change: {f:?}"
        );

        for name in [".probe-a", ".probe-b", ".probe-c"] {
            assert_eq!(
                std::fs::read(staging.join(name)).ok().as_deref(),
                Some(&b"a file the probe does not own"[..]),
                "the probe overwrote or deleted `{name}`, which it did not create"
            );
        }

        // And it cleans up after itself: nothing but the three foreign files.
        let left: Vec<_> = std::fs::read_dir(&staging)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| !n.starts_with(".probe-a") || n.len() > ".probe-a".len())
            .collect();
        let strays: Vec<_> = left
            .into_iter()
            .filter(|n| !matches!(n.as_str(), ".probe-a" | ".probe-b" | ".probe-c"))
            .collect();
        assert!(
            strays.is_empty(),
            "the probe left fixtures behind: {strays:?}"
        );
    }

    /// Two probes of the same root, at the same time, must both answer for the
    /// filesystem rather than for each other.
    #[test]
    fn concurrent_feasibility_probes_do_not_erase_each_others_fixtures() {
        let t = Tmp::new("probe-race");
        let root = t.0.clone();
        let verdicts: Vec<_> = std::thread::scope(|s| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    let root = root.clone();
                    s.spawn(move || DeleteModeProvider::new().probe_feasibility(&root))
                })
                .collect();
            handles.into_iter().map(|h| h.join().unwrap()).collect()
        });

        for v in &verdicts {
            let v = v.as_ref().expect("every probe must complete");
            assert_eq!(
                v.is_supported(),
                cfg!(unix),
                "a probe answered about another probe's fixtures rather than about the \
                 filesystem: {v:?}"
            );
        }
    }

    /// A staging rollback that cannot complete is reported, not discarded.
    ///
    /// The rollback is a `RENAME_NOREPLACE`, so it fails when the original name
    /// was reoccupied while the file was in staging. `stage_for_destruction`
    /// returns no `Staged` on this path, so the caller has nothing to hand
    /// `restore_staged` — a discarded failure left the user's only local copy
    /// out of its original path with the caller told only that a sync failed.
    ///
    /// Driven directly against the rollback rather than by making an fsync
    /// fail, which is not something a test can arrange portably: the shape
    /// under test is "the reverse rename refused", and reoccupying the name is
    /// how that happens in practice.
    #[cfg(unix)]
    #[test]
    fn a_staging_rollback_that_cannot_complete_is_reported() {
        let t = Tmp::new("rollback");
        let f = t.0.join("only-copy.bin");
        std::fs::write(&f, b"the only local copy").unwrap();
        let p = DeleteModeProvider::new();
        let Some(staged) = staged_or_refused(p.stage_for_destruction(&t.0, &f)) else {
            return;
        };

        // The user creates a new file at the original name while the old one is
        // staged. This is exactly the state a rollback meets and cannot undo.
        std::fs::write(&f, b"something the user made").unwrap();
        assert!(
            !matches!(rename_noreplace(&staged.staged, &f), Ok(true)),
            "the fixture must actually make the reverse rename refuse"
        );

        // And the bytes are still discoverable where the error would say they
        // are, which is what makes reporting rather than discarding useful.
        assert_eq!(
            p.list_staged(&t.0).unwrap(),
            vec![staged.staged.clone()],
            "recovery has to be able to find the stranded copy"
        );
        assert_eq!(
            std::fs::read(&f).unwrap(),
            b"something the user made",
            "and the user's new file is untouched — the rollback must never replace"
        );
    }

    /// Creating the staging directory syncs the REGISTERED ROOT that names it.
    ///
    /// Staging a nested file syncs two directories — the staging directory
    /// gains an entry, the file's source parent loses one — and on the first
    /// destruction under a root there is a THIRD: the entry naming
    /// `.shepherd-staging` itself, which lives in the registered root and is
    /// neither of those. A power loss then persists the nested source removal
    /// while losing the staging directory entry, and the file's only local
    /// bytes go with it.
    #[test]
    fn creating_the_staging_directory_syncs_the_registered_root() {
        let t = Tmp::new("rootsync");
        let nested = t.0.join("a/b");
        std::fs::create_dir_all(&nested).unwrap();
        let f = nested.join("only-copy.bin");
        std::fs::write(&f, b"the only local copy").unwrap();
        assert!(
            !DeleteModeProvider::staging_dir(&t.0).exists(),
            "the staging directory must be created BY this staging, or the sync under test \
             is skipped as an existing one"
        );

        let syncs_of = |d: &PathBuf| {
            SYNCED_DIRS
                .lock()
                .unwrap()
                .iter()
                .filter(|p| *p == d)
                .count()
        };
        let before = syncs_of(&t.0);

        let Some(_staged) =
            staged_or_refused(DeleteModeProvider::new().stage_for_destruction(&t.0, &f))
        else {
            return;
        };

        assert!(
            syncs_of(&t.0) > before,
            "the registered root was not fsync'd, so the entry naming the new staging \
             directory may not survive the crash the source removal will"
        );
    }

    /// A world-writable root is refused before anything is staged in it.
    ///
    /// `secure_staging` proves the staging DIRECTORY is ours and owner-only. It
    /// cannot prove the name still resolves to it: rename is governed by the
    /// containing directory, so on a world-writable root any account can move
    /// `.shepherd-staging` aside and leave a symlink where it was, after the
    /// check has passed. Every later staging operation resolves that pathname
    /// again and lands in the attacker's tree.
    #[cfg(unix)]
    #[test]
    fn a_world_writable_root_cannot_host_staging() {
        use std::os::unix::fs::PermissionsExt;

        let t = Tmp::new("worldwritable");
        let root = t.0.clone();
        let file = t.file("a.raw", b"payload");

        // The accepting direction first, so this cannot pass by refusing
        // everything: an ordinary root stages.
        let p = DeleteModeProvider;
        let staged = p
            .stage_for_destruction(&root, &file)
            .expect("ordinary root stages");
        p.restore_staged(staged).expect("put it back");

        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            std::fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o777,
            "the fixture itself has to be world-writable, or this asserts nothing"
        );

        let err = p
            .stage_for_destruction(&root, &file)
            .expect_err("a root anybody can write must not host staging");
        assert!(
            err.to_string().contains("world-writable") || err.to_string().contains("0777"),
            "the refusal must name the reason: {err}"
        );

        // Sticky is the exception, and it is the same rule: only an entry's
        // owner may rename it, which is what /tmp relies on.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let staged = p
            .stage_for_destruction(&root, &file)
            .expect("a sticky world-writable root already restricts rename to the owner");
        p.restore_staged(staged).expect("put it back");
    }

    /// A staging directory this daemon cannot secure is REFUSED.
    ///
    /// A root writable by another account lets that account pre-create
    /// `.shepherd-staging` and keep it, and the `chmod` failure used to be
    /// discarded. Destruction then runs inside a directory somebody else
    /// controls, and between the held-handle verification and the pathname
    /// unlink they can replace the staged entry — so Shepherd unlinks a
    /// substitute and audits the ORIGINAL as destroyed while its inode was
    /// moved elsewhere.
    #[cfg(unix)]
    #[test]
    fn a_staging_directory_that_cannot_be_secured_is_refused() {
        use std::os::unix::fs::PermissionsExt;

        let t = Tmp::new("stagingsec");
        let f = t.0.join("doomed.bin");
        std::fs::write(&f, b"bytes").unwrap();
        let p = DeleteModeProvider::new();

        // Accepting direction: an ordinary root stages, and leaves the staging
        // directory owner-only.
        let Some(staged) = staged_or_refused(p.stage_for_destruction(&t.0, &f)) else {
            return;
        };
        let dir = staged.staged.parent().unwrap().to_path_buf();
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700
        );
        p.restore_staged(staged).expect("put it back");

        // A staging path that is NOT a directory. Same shape as a foreign
        // account substituting one, and the one form a test can build without
        // a second uid.
        let t2 = Tmp::new("stagingsec2");
        let f2 = t2.0.join("doomed.bin");
        std::fs::write(&f2, b"bytes").unwrap();
        std::fs::write(DeleteModeProvider::staging_dir(&t2.0), b"not a directory").unwrap();

        let err = p
            .stage_for_destruction(&t2.0, &f2)
            .expect_err("staging must not proceed through a non-directory");
        assert!(
            format!("{err}").contains("not a directory"),
            "the refusal must say what is wrong with it: {err}"
        );
        assert_eq!(
            std::fs::read(&f2).unwrap(),
            b"bytes",
            "and the file is still where the user left it"
        );
    }

    #[test]
    fn tmpfs_supports_identity_bound_staging() {
        let t = Tmp::new("probe");
        let f = DeleteModeProvider::new().probe_feasibility(&t.0).unwrap();
        // On a platform with no identity binding the honest answer is
        // "not supported", and asserting `is_supported()` unconditionally would
        // demand a capability the provider correctly refuses to claim.
        assert_eq!(
            f.is_supported(),
            cfg!(unix),
            "feasibility must match what this platform can actually bind: {f:?}"
        );
    }

    #[test]
    fn staging_moves_the_file_and_binds_identity_to_the_handle() {
        let t = Tmp::new("stage");
        let p = t.file("a.bin", b"hello");
        let before = std::fs::symlink_metadata(&p).unwrap();

        let Some(staged) =
            staged_or_refused(DeleteModeProvider::new().stage_for_destruction(&t.0, &p))
        else {
            return;
        };

        assert!(!p.exists(), "the original path no longer resolves");
        assert!(staged.staged.exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            assert_eq!(
                staged.identity.ino,
                before.ino(),
                "identity must be the SAME file, read back from the held handle"
            );
        }
    }

    /// `rename()` does not invalidate an already-open descriptor. That is the
    /// property step 4 rests on — it hashes through this handle rather than
    /// reopening a path that could now resolve elsewhere.
    #[test]
    fn the_held_handle_still_reads_after_staging() {
        use std::io::Read;
        let t = Tmp::new("handle");
        let p = t.file("a.bin", b"content-that-must-survive");
        let Some(mut staged) =
            staged_or_refused(DeleteModeProvider::new().stage_for_destruction(&t.0, &p))
        else {
            return;
        };

        let mut buf = String::new();
        staged.handle.read_to_string(&mut buf).unwrap();
        assert_eq!(buf, "content-that-must-survive");
    }

    /// §4.10.4: recovery is move-back, never complete-forward.
    #[test]
    fn move_back_restores_the_original_path() {
        let t = Tmp::new("moveback");
        let p = t.file("a.bin", b"payload");
        let provider = DeleteModeProvider::new();
        let Some(staged) = staged_or_refused(provider.stage_for_destruction(&t.0, &p)) else {
            return;
        };
        assert!(!p.exists());

        let outcome = provider.restore_staged(staged).unwrap();
        assert_eq!(outcome, RestoreOutcome::Restored { path: p.clone() });
        assert_eq!(std::fs::read(&p).unwrap(), b"payload");
    }

    /// The original path was reoccupied while the file was staged. Overwriting
    /// would destroy a file the user created, so the move-back takes a conflict
    /// name and alerts.
    #[test]
    fn move_back_onto_an_occupied_path_takes_a_conflict_name() {
        let t = Tmp::new("conflict");
        let p = t.file("a.bin", b"original");
        let provider = DeleteModeProvider::new();
        let Some(staged) = staged_or_refused(provider.stage_for_destruction(&t.0, &p)) else {
            return;
        };

        // Someone recreates the path.
        std::fs::write(&p, b"the user's new file").unwrap();

        let outcome = provider.restore_staged(staged).unwrap();
        match outcome {
            RestoreOutcome::Conflicted { path, original } => {
                assert_eq!(original, p);
                assert_eq!(std::fs::read(&path).unwrap(), b"original");
                assert_eq!(
                    std::fs::read(&p).unwrap(),
                    b"the user's new file",
                    "the occupant must be untouched"
                );
            }
            other => panic!("expected a conflict, got {other:?}"),
        }
    }

    #[test]
    fn staged_entries_are_discoverable_for_crash_recovery() {
        let t = Tmp::new("recover");
        let p = t.file("a.bin", b"x");
        let provider = DeleteModeProvider::new();
        let Some(staged) = staged_or_refused(provider.stage_for_destruction(&t.0, &p)) else {
            return;
        };
        // Simulate a crash: forget the handle without destroying or restoring.
        let staged_path = staged.staged.clone();
        drop(staged);

        let found = provider.list_staged(&t.0).unwrap();
        assert_eq!(found, vec![staged_path]);
    }

    /// A crash after staging a file that lives **below** the root must leave
    /// its bytes where recovery looks for them.
    ///
    /// `list_staged` is called with the registered scan root and inspects
    /// exactly `<root>/.shepherd-staging`. Staging a nested file beside itself
    /// puts the bytes in `<root>/a/b/.shepherd-staging`, which recovery never
    /// lists — and bytes recovery cannot find are bytes the user has lost.
    ///
    /// This is a recovery test, not a test of the path computation: it crashes
    /// (drops the handle without destroying or restoring) and then asks the
    /// recovery entry point what it can see.
    #[test]
    fn a_crash_after_staging_a_nested_file_leaves_it_where_recovery_looks() {
        let t = Tmp::new("nested-recover");
        let parent = t.0.join("a").join("b");
        std::fs::create_dir_all(&parent).unwrap();
        let p = parent.join("deep.bin");
        std::fs::write(&p, b"nested-payload").unwrap();

        let provider = DeleteModeProvider::new();
        let Some(staged) = staged_or_refused(provider.stage_for_destruction(&t.0, &p)) else {
            return;
        };
        // The crash: forget the handle without destroying or restoring.
        let staged_path = staged.staged.clone();
        drop(staged);

        let found = provider.list_staged(&t.0).unwrap();
        assert_eq!(
            found,
            vec![staged_path],
            "recovery lists the REGISTERED ROOT's staging directory and nothing else, so \
             a nested file's staged entry has to be in it"
        );
        assert_eq!(
            std::fs::read(&found[0]).unwrap(),
            b"nested-payload",
            "and the entry recovery found must still hold the file's bytes"
        );
        assert!(
            !parent.join(STAGING_DIR_NAME).exists(),
            "no staging directory may be created beside the file: an entry there is \
             undiscoverable by `list_staged(root)`"
        );
    }

    /// The staged entry is still named and still reachable by any process
    /// running as the same user. §4.10.1 corrects iteration 3's claim that
    /// staging leaves "no name in user space", and this asserts the hazard is
    /// real rather than assumed away — `0700` excludes other users, who were
    /// never the threat.
    #[test]
    fn a_staged_entry_is_still_reachable_by_the_same_uid() {
        let t = Tmp::new("reopen");
        let p = t.file("a.bin", b"still-here");
        let Some(staged) =
            staged_or_refused(DeleteModeProvider::new().stage_for_destruction(&t.0, &p))
        else {
            return;
        };

        let reread = std::fs::read(&staged.staged).expect(
            "staging is not an exclusion boundary against the same UID — if this ever \
             starts failing, the design changed and §4.10.1's residual text needs revisiting",
        );
        assert_eq!(reread, b"still-here");
    }

    /// A writer holding a descriptor from before staging can still modify the
    /// bytes afterwards. §4.10.1: "rename() does not invalidate descriptors
    /// that are already open." This is OQ-J's accepted residual, exercised
    /// rather than assumed away.
    #[test]
    fn a_writable_handle_opened_before_staging_still_writes_after_it() {
        let t = Tmp::new("writable-fd");
        let p = t.file("a.bin", b"aaaa");

        let mut writer = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        let Some(staged) =
            staged_or_refused(DeleteModeProvider::new().stage_for_destruction(&t.0, &p))
        else {
            return;
        };

        writer.write_all(b"bbbb").unwrap();
        writer.sync_all().unwrap();

        let after = std::fs::read(&staged.staged).unwrap();
        assert_eq!(
            after, b"aaaabbbb",
            "the pre-existing writable fd wrote through the rename — this is D-8/OQ-J's \
             residual, and it is documented, not fixed"
        );
    }
}
