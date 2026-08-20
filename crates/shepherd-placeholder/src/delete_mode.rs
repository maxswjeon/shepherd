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

    fn ensure_staging(root: &Path) -> Result<PathBuf> {
        let dir = Self::staging_dir(root);
        std::fs::create_dir_all(&dir).map_err(|e| ProviderError::Io {
            path: dir.display().to_string(),
            detail: e.to_string(),
        })?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Excludes other users. NOT a boundary against the same UID — see
            // the module docs.
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
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
        let a = dir.join(".probe-a");
        let b = dir.join(".probe-b");
        let cleanup = || {
            let _ = std::fs::remove_file(&a);
            let _ = std::fs::remove_file(&b);
        };

        if let Err(e) = std::fs::write(&a, b"probe") {
            cleanup();
            return Err(ProviderError::Io {
                path: a.display().to_string(),
                detail: e.to_string(),
            });
        }
        if let Err(e) = std::fs::write(&b, b"probe") {
            cleanup();
            return Err(ProviderError::Io {
                path: b.display().to_string(),
                detail: e.to_string(),
            });
        }

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

        // 2. Onto a FREE name: must succeed.
        let free = dir.join(".probe-c");
        let _ = std::fs::remove_file(&free);
        let ok = rename_noreplace(&a, &free);
        let _ = std::fs::remove_file(&free);
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
                    let _ = rename_noreplace(&staged, path);
                    return Err(ProviderError::Io {
                        path: dir.display().to_string(),
                        detail: format!("staging rename is not durable: {e}"),
                    });
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
        let identity = identity_of(&handle)?;

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
        std::fs::remove_file(&staged.staged).map_err(|e| ProviderError::Io {
            path: staged.staged.display().to_string(),
            detail: e.to_string(),
        })
    }

    fn restore_staged(&self, staged: Staged) -> Result<RestoreOutcome> {
        // Move-back is itself RENAME_NOREPLACE: the original path may have been
        // reoccupied while the file was staged, and overwriting whatever is
        // there would destroy a file the user created.
        match rename_noreplace(&staged.staged, &staged.original) {
            Ok(true) => Ok(RestoreOutcome::Restored {
                path: staged.original.clone(),
            }),
            Ok(false) | Err(_) => {
                let conflict = conflict_name(&staged.original);
                match rename_noreplace(&staged.staged, &conflict) {
                    Ok(true) => {
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

    fn list_staged(&self, root: &Path) -> Result<Vec<PathBuf>> {
        let dir = Self::staging_dir(root);
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Ok(Vec::new());
        };
        Ok(entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "staged"))
            .collect())
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
