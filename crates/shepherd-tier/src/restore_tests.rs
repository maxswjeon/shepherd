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
