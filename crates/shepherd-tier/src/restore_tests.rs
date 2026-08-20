//! Restore tests, against a REAL temp directory.
//!
//! `fidelity.rs` can compare a manifest to an attribute set, but it cannot tell
//! you whether a filesystem actually keeps an mtime you set — which is the
//! claim §4.10.6 depends on. That needs a real file, so these tests use one.

use super::*;
use crate::fidelity::CoreAttrs;

/// A temp directory that cleans itself up. `tempfile` is not a dependency of
/// this crate and one test module does not justify adding one.
struct TempDir(PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let mut p = std::env::temp_dir();
        // Distinct per test and per process, so a parallel run cannot collide.
        p.push(format!("shepherd-restore-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).expect("create temp dir");
        Self(p)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

const BYTES: &[u8] = b"the quick brown fox jumps over the lazy dog";
/// Deliberately not a round number of seconds: a filesystem that quantises to
/// seconds will fail the read-back rather than pass by luck.
const MTIME_NANOS: i64 = 1_700_000_000_123_456_789;

fn manifest_for(bytes: &[u8], mode: u32) -> FidelityManifest {
    FidelityManifest::new(CoreAttrs {
        blake3: Blake3Hash::from_bytes(*blake3::hash(bytes).as_bytes()),
        size: bytes.len() as u64,
        mtime: Timestamp::from_nanos(MTIME_NANOS),
        mode,
    })
}

/// The restored file is never readable by anyone else, not even for the
/// instant between its creation and the manifest's chmod.
///
/// `File::create_new` asks for `0666` and an ordinary `022` umask trims that to
/// `0644`, so a private file used to be published world-readable for the whole
/// of `write_and_verify` — every byte written and fsynced — before its real
/// mode was applied. Any account able to traverse the directory could open it
/// in that window and keep the descriptor afterwards, and a later chmod does
/// not close a file somebody already holds open.
///
/// Asserted on the CREATE, because the window is what the finding is about and
/// the finished file's mode says nothing about it. `mode & 0o077 == 0` rather
/// than `== 0o600`: the umask may only remove bits, so a stricter umask is
/// still a pass and the property is "nobody else, ever".
#[test]
#[cfg(unix)]
fn a_restored_file_is_owner_only_from_its_first_instant() {
    use std::os::unix::fs::PermissionsExt;

    let dir = TempDir::new("perm-window");
    let path = dir.path("secret.bin");
    let f = crate::restore::create_owner_only(&path).expect("create");
    drop(f);

    let mode = std::fs::metadata(&path).expect("stat").permissions().mode() & 0o777;
    assert_eq!(
        mode & 0o077,
        0,
        "the file was published as {mode:04o} before its mode was applied; \
         another account could open it inside that window"
    );

    // And the manifest still governs the FINAL mode, including a deliberately
    // permissive one — the tightening must not become a policy of its own.
    let target = dir.path("public.bin");
    let m = manifest_for(BYTES, 0o644);
    restore_file(&target, BYTES, &m).expect("restore");
    assert_eq!(
        std::fs::metadata(&target)
            .expect("stat")
            .permissions()
            .mode()
            & 0o777,
        0o644,
        "a 0644 manifest must still produce 0644"
    );
}

#[test]
fn a_restore_reproduces_bytes_mtime_and_mode_on_a_real_filesystem() {
    let dir = TempDir::new("happy");
    let target = dir.path("photo.raw");
    let m = manifest_for(BYTES, 0o644);

    let outcome = match restore_file(&target, BYTES, &m) {
        Ok(o) => o,
        Err(RestoreError::FidelityBreached { breaches, .. }) => {
            // If this ever fires it is a real finding about the filesystem
            // under test, not a flaky test — so it says which attribute.
            panic!("the filesystem did not keep what the manifest asked for: {breaches:?}");
        }
        Err(e) => panic!("restore failed: {e}"),
    };

    assert!(!outcome.needs_conflict_alert());
    assert_eq!(outcome.path(), target.to_string_lossy());
    assert_eq!(std::fs::read(&target).expect("read"), BYTES);

    // The read-back is the claim that matters: not "we called set_modified"
    // but "the filesystem kept it".
    let back = read_back(&target).expect("read back");
    // Read back to the resolution the target can hold, for the same reason
    // `fidelity::MTIME_RESOLUTION_NANOS` exists: NTFS quantises to 100 ns, so
    // asserting exact nanoseconds here asserts a POSIX property as universal.
    let slack = if cfg!(unix) { 1 } else { 100 };
    assert!(
        (back.mtime.as_nanos() - MTIME_NANOS).abs() < slack,
        "restored mtime {} is further than one filesystem tick ({slack} ns) from \
         the manifest's {MTIME_NANOS}",
        back.mtime.as_nanos()
    );
    assert_eq!(back.blake3, m.core.blake3);
    #[cfg(unix)]
    // `mode` only where the target has one — see `MODE_IS_REPRESENTABLE`. On
    // NTFS the restored file reads back 0 because there are no mode bits, and
    // demanding 0o644 there demands something the filesystem cannot store.
    if cfg!(unix) {
        assert_eq!(back.mode, 0o644);
    }
}

/// The reason mtime is in the floor at all.
#[test]
fn the_restored_mtime_is_the_original_not_now() {
    let dir = TempDir::new("mtime");
    let target = dir.path("old.raw");
    let m = manifest_for(BYTES, 0o644);
    restore_file(&target, BYTES, &m).expect("restore");

    let back = read_back(&target).expect("read back");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    assert!(
        (now as i64 - back.mtime.as_nanos()).abs() > 86_400 * 1_000_000_000,
        "a restored file whose mtime is 'now' instantly re-matches an age rule; got {}",
        back.mtime.as_nanos()
    );
}

/// §4.10.5: Shepherd never destroys data by writing.
#[test]
fn an_occupied_original_lands_beside_it_and_leaves_the_occupant_untouched() {
    let dir = TempDir::new("conflict");
    let target = dir.path("photo.raw");
    let occupant = b"a file the user created while this one was gone";
    std::fs::write(&target, occupant).expect("seed occupant");

    let m = manifest_for(BYTES, 0o644);
    let outcome = restore_file(&target, BYTES, &m).expect("restore");

    assert!(
        outcome.needs_conflict_alert(),
        "an occupied path must raise a conflict alert, not silently divert"
    );
    assert!(
        outcome.path().ends_with("photo (restored 1).raw"),
        "got {}",
        outcome.path()
    );
    assert_eq!(
        std::fs::read(&target).expect("read occupant"),
        occupant,
        "THE OCCUPANT MUST BE UNTOUCHED"
    );
    assert_eq!(std::fs::read(outcome.path()).expect("read restored"), BYTES);
}

#[test]
fn restore_uses_exclusive_create_rather_than_check_then_write() {
    // Directly exercising the primitive: if the chosen path is taken at the
    // syscall, the write must fail rather than replace. `restore_file` picks a
    // free name first, so this asserts the underlying guarantee that makes the
    // check-then-create TOCTOU impossible.
    let dir = TempDir::new("excl");
    let p = dir.path("taken");
    std::fs::write(&p, b"existing").expect("seed");

    let err = std::fs::File::create_new(&p).expect_err("O_EXCL must refuse");
    assert_eq!(err.kind(), std::io::ErrorKind::AlreadyExists);
    assert_eq!(std::fs::read(&p).expect("read"), b"existing");
}

#[test]
fn a_content_mismatch_is_caught_by_the_read_back() {
    // The manifest describes different bytes than the ones handed over — a
    // corrupted download, or the wrong object. The restore must not report
    // success.
    let dir = TempDir::new("mismatch");
    let target = dir.path("bad.raw");
    let m = manifest_for(b"what the manifest says", 0o644);

    match restore_file(&target, b"what actually arrived", &m) {
        Err(RestoreError::FidelityBreached { breaches, .. }) => {
            assert!(
                breaches
                    .iter()
                    .any(|b| matches!(b, FidelityBreach::Content { .. })),
                "{breaches:?}"
            );
        }
        other => panic!("expected a fidelity breach, got {other:?}"),
    }
}

#[test]
fn timestamps_round_trip_through_system_time_including_before_the_epoch() {
    for nanos in [
        0i64,
        MTIME_NANOS,
        1_000,
        -1_000_000_000,
        1_700_000_000_000_000_000,
    ] {
        let ts = Timestamp::from_nanos(nanos);
        // `SystemTime` is FILETIME on Windows — 100 ns ticks — so a nanosecond
        // value cannot survive the trip there and 1700000000123456789 comes
        // back as ...700. That is the platform, not a defect, and it is the
        // same limit `fidelity::MTIME_RESOLUTION_NANOS` encodes. Asserting
        // exact equality here asserted a POSIX property as though it were
        // universal.
        let back = from_system_time(to_system_time(ts));
        let slack = if cfg!(unix) { 1 } else { 100 };
        assert!(
            (back.as_nanos() - ts.as_nanos()).abs() < slack,
            "round trip failed for {nanos}: got {} (slack {slack} ns)",
            back.as_nanos()
        );
    }
}

/// A DANGLING symlink at the original path is an occupied path.
///
/// `Path::exists` follows the link, so a dangling one answered "nothing is
/// here" and the restore chose the original path — after which `create_new`
/// correctly refused, because a directory entry very much was there. The
/// restore failed, and every retry failed identically, instead of landing
/// beside the occupant the way every other occupied path does.
#[cfg(unix)]
#[test]
fn a_dangling_symlink_is_an_occupied_path() {
    let dir = TempDir::new("dangling");
    let target = dir.path("photo.raw");
    std::os::unix::fs::symlink(dir.path("nothing-here.raw"), &target).unwrap();
    assert!(
        !target.exists() && std::fs::symlink_metadata(&target).is_ok(),
        "the fixture must be a dangling link, or this tests nothing"
    );

    let m = manifest_for(BYTES, 0o644);
    let outcome = restore_file(&target, BYTES, &m).expect("the restore must land somewhere");

    assert!(
        outcome.needs_conflict_alert(),
        "an occupied path is a conflict, and the user is owed the alert: {outcome:?}"
    );
    assert_ne!(outcome.path(), target.to_string_lossy());
    assert!(
        std::fs::symlink_metadata(&target).unwrap().is_symlink(),
        "and the occupant is untouched — restore never replaces"
    );
    assert_eq!(std::fs::read(outcome.path()).unwrap(), BYTES);
}

// --- a failed attempt leaves nothing behind --------------------------------

/// `create_new` succeeding is not the same fact as the restore succeeding.
/// Everything after it — the write, the sync, the metadata, the read-back, the
/// fidelity comparison — can still fail, and until this was fixed each of those
/// returned with the file Shepherd had just created still sitting at the
/// destination.
///
/// # Off unix this asserts the GAP, deliberately
///
/// `restore::inode_of` answers `None` where the platform has no `(dev, ino)`,
/// and `discard_failed_attempt` then declines to unlink — a recorded decision,
/// not an oversight: *"a cleanup that guessed at identity would be worse than
/// one that declines, because it would unlink by path"*. Windows identity is
/// Phase 3's (`FILE_ID_INFO` plus the volume serial).
///
/// So this asserts the cleanup on unix and asserts that the file is **left**
/// elsewhere. Asserting the unix outcome on every platform made CI red for a
/// behaviour the code says in writing it does not provide, which teaches
/// nothing; asserting nothing there would let the gap close silently and never
/// be noticed. This fails the day Windows identity lands, which is when someone
/// should be reading it.
#[test]
fn a_failed_restore_leaves_no_wreckage_at_the_chosen_path() {
    let dir = TempDir::new("wreckage");
    let target = dir.path("photo.raw");
    let m = manifest_for(b"what the manifest says", 0o644);

    let err = restore_file(&target, b"what actually arrived", &m)
        .expect_err("the bytes do not match the manifest");

    if cfg!(unix) {
        assert!(
            !target.exists(),
            "a restore that failed its own fidelity check left {} behind holding \
             known-invalid data; the error was {err}",
            target.display()
        );
    } else {
        assert!(
            target.exists(),
            "the file is expected to be LEFT on a platform that cannot name the inode \
             it created — if this now cleans up, Phase 3's identity has landed and this \
             test and `inode_of`'s coverage-gap note both need updating"
        );
    }
}

/// The consequence the finding names, end to end. A retry after a failed
/// restore must land the file back where it came from — not beside it, and not
/// with an alert telling the user something of theirs is in the way, when the
/// only thing in the way is Shepherd's own failed attempt.
///
/// Unix only, and the restriction is the point rather than a convenience: the
/// diversion this asserts against is downstream of the cleanup, so off unix —
/// where the cleanup declines by design, see the test above — the retry DOES
/// divert, and that user-visible consequence is exactly what Phase 3's Windows
/// identity has to buy. Running it there would assert the fix while measuring
/// the gap.
#[cfg(unix)]
#[test]
fn a_retry_after_a_failed_restore_lands_at_the_original_path() {
    let dir = TempDir::new("retry");
    let target = dir.path("photo.raw");
    let m = manifest_for(BYTES, 0o644);

    // Attempt one: a corrupt download. Caught by the read-back, as it should
    // be — the question is what it leaves behind.
    restore_file(&target, b"a garbled arrival", &m).expect_err("a corrupt download must fail");

    // Attempt two: the bytes arrive intact.
    let outcome = restore_file(&target, BYTES, &m).expect("the retry must succeed");

    assert!(
        !outcome.needs_conflict_alert(),
        "the retry was diverted and the user alerted about a 'conflict' that is \
         Shepherd's own failed attempt, not a file of theirs — landed at {}",
        outcome.path()
    );
    assert_eq!(
        outcome.path(),
        target.to_string_lossy(),
        "the retry must restore the file to where it came from"
    );
    assert_eq!(std::fs::read(&target).expect("read"), BYTES);
}

/// The cleanup's load-bearing half, exercised directly because the window it
/// guards cannot be opened from outside `restore_file`.
///
/// A cleanup that unlinked by path would delete the file in the first half of
/// this test — a file this attempt did not create, on the error path of an
/// operation whose premise is that it never destroys data.
#[cfg(unix)]
#[test]
fn cleanup_removes_only_the_inode_this_attempt_created() {
    let dir = TempDir::new("inode-bound");
    let p = dir.path("photo.raw");

    let f = std::fs::File::create_new(&p).expect("create");
    let ours = inode_of(&f.metadata().expect("fstat")).expect("unix names inodes");
    drop(f);

    // The name is taken over by somebody else's file, as it can be between a
    // failed attempt and its cleanup. Built at another name FIRST and renamed
    // in: an unlink-then-create at the same path lets ext4 hand back the inode
    // number it just freed, and the test would then be asserting nothing.
    let theirs_bytes = b"a file the user created in the window";
    let elsewhere = dir.path("theirs.tmp");
    std::fs::write(&elsewhere, theirs_bytes).expect("seed");
    let theirs =
        inode_of(&std::fs::metadata(&elsewhere).expect("stat")).expect("unix names inodes");
    assert_ne!(
        ours, theirs,
        "precondition: the replacement really is a different inode"
    );
    std::fs::rename(&elsewhere, &p).expect("take the name over");

    discard_failed_attempt(&p, Some(ours));
    assert_eq!(
        std::fs::read(&p).expect("the replacement must survive"),
        theirs_bytes,
        "cleanup deleted a file this attempt did not create"
    );

    // The accepting direction: the inode the attempt DID create is removed, or
    // the cleanup is decorative and the wreckage stays.
    discard_failed_attempt(&p, Some(theirs));
    assert!(
        !p.exists(),
        "the exact inode this attempt created must be removed"
    );
}

// --- verification is bound to the INODE, not to the name -------------------

/// The window `create_new` opens and the verification used to read straight
/// through: between the exclusive create and the read-back, the destination can
/// stop naming the inode this attempt created.
///
/// Exercised against [`write_and_verify`] directly, because that is the only
/// seam at which the swap can be made **deterministic**. Driving `restore_file`
/// and hoping another thread lands its rename in the right microsecond would be
/// a test that passes for timing reasons rather than for the property.
///
/// The replacement is built to survive a PATH-based verification: identical
/// bytes, identical mtime. The only thing that distinguishes it is its **mode**
/// — so a path-based `chmod` is visible as a change to somebody else's file,
/// and a handle-based one is visible as a change to ours. All three assertions
/// below fail against the pathname-bound version, and they fail for three
/// different reasons.
#[cfg(unix)]
#[test]
fn a_destination_swapped_after_the_create_is_named_rather_than_verified() {
    use std::os::unix::fs::PermissionsExt;

    const OURS_BEFORE: u32 = 0o600;
    const THEIRS: u32 = 0o604;
    const MANIFEST: u32 = 0o640;

    let dir = TempDir::new("displaced");
    let chosen = dir.path("photo.raw");
    let m = manifest_for(BYTES, MANIFEST);

    // Exactly what `restore_file` does before it hands over: exclusive-create,
    // then capture the inode from the HANDLE.
    let f = std::fs::File::create_new(&chosen).expect("create");
    std::fs::set_permissions(&chosen, std::fs::Permissions::from_mode(OURS_BEFORE))
        .expect("seed our mode");
    let created = inode_of(&f.metadata().expect("fstat"));
    assert!(created.is_some(), "unix names inodes");

    // The swap. Our inode is renamed aside — it stays alive and reachable, so
    // the test can ask what happened to it — and a file somebody else made
    // takes the name over.
    let ours_moved = dir.path("ours.moved");
    std::fs::rename(&chosen, &ours_moved).expect("move our inode aside");

    // Built elsewhere and renamed in: an unlink-then-create at the same path
    // lets ext4 hand back the inode number it just freed, and the test would
    // then be asserting nothing.
    let staging = dir.path("theirs.tmp");
    std::fs::write(&staging, BYTES).expect("seed replacement");
    std::fs::set_permissions(&staging, std::fs::Permissions::from_mode(THEIRS))
        .expect("seed their mode");
    let touch = std::fs::File::options()
        .write(true)
        .open(&staging)
        .expect("open replacement");
    touch
        .set_modified(to_system_time(Timestamp::from_nanos(MTIME_NANOS)))
        .expect("give the replacement the manifest's mtime");
    drop(touch);
    let theirs = inode_of(&std::fs::metadata(&staging).expect("stat")).expect("unix names inodes");
    assert_ne!(
        created,
        Some(theirs),
        "precondition: the replacement really is a different inode"
    );
    std::fs::rename(&staging, &chosen).expect("take the name over");

    let err = write_and_verify(f, &chosen, BYTES, &m, created).expect_err(
        "the destination no longer names the inode this attempt created, so the \
         restore did not publish anything and must not report success",
    );
    assert!(
        matches!(err, RestoreError::Displaced { .. }),
        "the outcome must name the swap rather than some incidental failure: {err:?}"
    );

    // The replacement is somebody else's file. Nothing this restore did may
    // have touched it — a pathname `chmod` would have set it to the manifest's
    // mode, which is Shepherd editing a file it did not create.
    let theirs_mode = std::fs::metadata(&chosen)
        .expect("stat replacement")
        .permissions()
        .mode()
        & 0o7777;
    assert_eq!(
        theirs_mode, THEIRS,
        "the replacement's permissions were changed by a restore that never owned it"
    );
    assert_eq!(
        std::fs::read(&chosen).expect("read replacement"),
        BYTES,
        "the replacement's bytes were changed"
    );

    // The accepting half, on the same run: the metadata went to OUR inode. If
    // this reads `OURS_BEFORE` the chmod landed on the name instead of the
    // handle, which is the defect from the other side.
    let ours = read_back(&ours_moved).expect("our inode is still reachable");
    assert_eq!(
        ours.mode, MANIFEST,
        "the manifest's mode must be applied through the held handle, to the \
         inode this attempt created"
    );
    assert_eq!(
        ours.blake3, m.core.blake3,
        "our inode holds the restored bytes"
    );
}
