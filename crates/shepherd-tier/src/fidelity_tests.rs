//! Tests for §4.10.6's restore fidelity contract.

use super::*;

fn h(seed: u8) -> Blake3Hash {
    Blake3Hash::from_bytes([seed; 32])
}

fn core() -> CoreAttrs {
    CoreAttrs {
        blake3: h(1),
        size: 4096,
        mtime: Timestamp::from_nanos(1_700_000_000_000_000_000),
        mode: 0o644,
    }
}

fn restored() -> RestoredAttrs {
    RestoredAttrs {
        blake3: h(1),
        size: 4096,
        mtime: Timestamp::from_nanos(1_700_000_000_000_000_000),
        mode: 0o644,
    }
}

#[test]
fn a_faithful_restore_passes() {
    let m = FidelityManifest::new(core());
    assert_eq!(verify_restore(&m, &restored()), Ok(()));
}

#[test]
fn wrong_content_is_a_breach() {
    let m = FidelityManifest::new(core());
    let mut a = restored();
    a.blake3 = h(2);
    let breaches = verify_restore(&m, &a).expect_err("must fail");
    assert!(matches!(breaches[0], FidelityBreach::Content { .. }));
}

/// mtime is in the floor for a reason beyond tidiness.
#[test]
fn a_wrong_mtime_is_a_breach_because_it_would_re_match_an_age_rule() {
    let m = FidelityManifest::new(core());
    let mut a = restored();
    // "now" — what a naive restore leaves behind.
    a.mtime = Timestamp::from_nanos(1_900_000_000_000_000_000);
    let breaches = verify_restore(&m, &a).expect_err("must fail");
    assert!(
        breaches
            .iter()
            .any(|b| matches!(b, FidelityBreach::Mtime { .. })),
        "a restored file whose mtime is now instantly re-matches an age rule: {breaches:?}"
    );
}

/// A wrong mode is a breach WHERE A MODE EXISTS, and is not one where it does
/// not.
///
/// Both halves are asserted, because only asserting the POSIX half would let
/// the Windows behaviour be anything at all — including the mode check silently
/// disappearing on every platform. That is the failure this file is for.
#[test]
fn a_wrong_mode_is_a_breach_where_modes_exist() {
    let m = FidelityManifest::new(core());
    let mut a = restored();
    a.mode = 0o600;
    let breached = verify_restore(&m, &a)
        .err()
        .is_some_and(|bs| bs.iter().any(|b| matches!(b, FidelityBreach::Mode { .. })));
    assert_eq!(
        breached,
        cfg!(unix),
        "a differing mode must breach exactly where the target can represent one \
         — POSIX yes, NTFS no (it has ACLs and a read-only flag, no mode bits). \
         See `MODE_IS_REPRESENTABLE`"
    );
}

#[test]
fn every_breach_is_reported_not_just_the_first() {
    let m = FidelityManifest::new(core());
    let a = RestoredAttrs {
        blake3: h(9),
        size: 1,
        mtime: Timestamp::from_nanos(0),
        mode: 0o600,
    };
    // Four breaches on POSIX: content, size, mtime, mode. Three where `mode`
    // is not representable — the count is derived from the platform rather than
    // hardcoded, so this still fails if a DIFFERENT breach goes missing.
    let expected = if cfg!(unix) { 4 } else { 3 };
    assert_eq!(
        verify_restore(&m, &a).expect_err("must fail").len(),
        expected
    );
}

// --- the disclosure rule ---------------------------------------------------

/// The distinction the whole type exists for.
#[test]
fn absent_and_unsupported_are_different_and_only_one_is_a_gap() {
    let m = FidelityManifest::new(core())
        // The file genuinely had no xattrs — nothing was lost.
        .with(AttrClass::Xattrs, AttrCapture::Absent)
        // The file HAD a resource fork and the target cannot carry it.
        .with(
            AttrClass::ResourceFork,
            AttrCapture::Unsupported {
                reason: "S3 objects carry no resource fork".into(),
            },
        );

    let gaps = m.gaps();
    assert_eq!(gaps.len(), 1, "{gaps:?}");
    assert_eq!(gaps[0].0, AttrClass::ResourceFork);
    assert!(gaps[0].1.contains("resource fork"));
    assert!(!m.is_full_fidelity());
}

#[test]
fn a_manifest_with_nothing_missing_is_full_fidelity() {
    let m = FidelityManifest::new(core())
        .with(AttrClass::Xattrs, AttrCapture::Absent)
        .with(
            AttrClass::PosixAcl,
            AttrCapture::Captured {
                values: BTreeMap::from([("user::rw".into(), "granted".into())]),
            },
        );
    assert!(m.is_full_fidelity());
    assert!(m.gaps().is_empty());
}

#[test]
fn a_manifest_that_records_only_successes_could_not_satisfy_the_rule() {
    // If `Unsupported` did not exist, an omitted class would be ambiguous
    // between "had none" and "had some and we dropped them", and the user needs
    // the second to be visible. This asserts the arms really are distinct.
    assert!(AttrCapture::Unsupported { reason: "x".into() }.is_gap());
    assert!(!AttrCapture::Absent.is_gap());
    assert!(
        !AttrCapture::Captured {
            values: BTreeMap::new()
        }
        .is_gap()
    );
}

#[test]
fn the_manifest_round_trips_through_serde() {
    // It is a sidecar written at tier time and read back at restore time,
    // possibly by a different build.
    let m = FidelityManifest::new(core()).with(
        AttrClass::AlternateDataStreams,
        AttrCapture::Unsupported {
            reason: "not an NTFS volume".into(),
        },
    );
    let json = serde_json::to_string(&m).expect("serialize");
    let back: FidelityManifest = serde_json::from_str(&json).expect("deserialize");
    assert_eq!(back, m);
    assert_eq!(back.gaps().len(), 1);
}

// --- exclusive-create restore ----------------------------------------------

#[test]
fn a_free_path_is_used_directly() {
    let target = choose_restore_path("/root/photo.raw", &|_| false);
    assert_eq!(
        target,
        RestoreTarget::Original("/root/photo.raw".to_string())
    );
}

/// §4.10.5: Shepherd never destroys data by writing.
#[test]
fn an_occupied_path_never_overwrites_and_keeps_the_extension() {
    let target = choose_restore_path("/root/photo.raw", &|p| p == "/root/photo.raw");
    match target {
        RestoreTarget::Conflict { original, chosen } => {
            assert_eq!(original, "/root/photo.raw");
            assert_eq!(chosen, "/root/photo (restored 1).raw");
            assert!(
                chosen.ends_with(".raw"),
                "the extension must survive, or tools stop recognising the file"
            );
        }
        other => panic!("must not overwrite an occupant: {other:?}"),
    }
}

#[test]
fn conflict_names_keep_climbing_until_one_is_free() {
    let occupied = |p: &str| {
        p == "/root/a.txt" || p == "/root/a (restored 1).txt" || p == "/root/a (restored 2).txt"
    };
    match choose_restore_path("/root/a.txt", &occupied) {
        RestoreTarget::Conflict { chosen, .. } => {
            assert_eq!(chosen, "/root/a (restored 3).txt");
        }
        other => panic!("expected a conflict name: {other:?}"),
    }
}

/// Running out of names is REFUSED, not answered with an untested one.
///
/// The ceiling used to return `(restored 10001)` without probing it. The caller
/// then created it exclusively, got `AlreadyExists`, and reported a race that
/// had not happened — while the truth was "there is no free name here", which
/// no retry could change. Every attempt re-walked all ten thousand probes to
/// reach the same occupied path, so that file could never be restored.
#[test]
fn exhausting_every_conflict_name_refuses_instead_of_guessing() {
    // Everything is taken, including well past the ceiling.
    let all_taken = |_: &str| true;
    match choose_restore_path("/root/a.txt", &all_taken) {
        RestoreTarget::Exhausted { original, ceiling } => {
            assert_eq!(original, "/root/a.txt");
            assert_eq!(ceiling, crate::fidelity::CONFLICT_NAME_CEILING);
        }
        other => panic!("a name it never probed is not an answer: {other:?}"),
    }

    // The boundary, so the ceiling is not off by one in the other direction:
    // the LAST candidate below it is still returned when it is free.
    let last = format!(
        "/root/a (restored {}).txt",
        crate::fidelity::CONFLICT_NAME_CEILING
    );
    let all_but_last = |p: &str| p != last;
    match choose_restore_path("/root/a.txt", &all_but_last) {
        RestoreTarget::Conflict { chosen, .. } => assert_eq!(chosen, last),
        other => panic!("the last candidate under the ceiling is usable: {other:?}"),
    }
}

/// A backslash separates on Windows and is an ordinary filename character on
/// Unix, so the split has to ask the platform rather than assume.
///
/// Searching only for `/` sent `C:\\Users\\foo.bar\\README` to
/// `C:\\Users\\foo (restored 1).bar\\README` — not an odd name but a different,
/// usually nonexistent DIRECTORY, so the restore failed instead of landing
/// beside the file it conflicted with.
#[test]
#[cfg(windows)]
fn a_windows_path_splits_on_the_backslash() {
    let occupied = |p: &str| p == r"C:\Users\foo.bar\README";
    match choose_restore_path(r"C:\Users\foo.bar\README", &occupied) {
        RestoreTarget::Conflict { chosen, .. } => {
            assert_eq!(chosen, r"C:\Users\foo.bar\README (restored 1)");
        }
        other => panic!("expected a conflict name: {other:?}"),
    }
}

/// The other half of the same rule: on Unix a backslash is part of the NAME,
/// so it must not be treated as a separator.
#[test]
#[cfg(unix)]
fn a_backslash_is_an_ordinary_character_in_a_unix_filename() {
    let name = r"/root/weird\name.txt";
    match choose_restore_path(name, &|p| p == name) {
        RestoreTarget::Conflict { chosen, .. } => {
            assert_eq!(chosen, r"/root/weird\name (restored 1).txt");
        }
        other => panic!("expected a conflict name: {other:?}"),
    }
}

#[test]
fn an_extensionless_path_still_gets_a_conflict_name() {
    match choose_restore_path("/root/README", &|p| p == "/root/README") {
        RestoreTarget::Conflict { chosen, .. } => {
            assert_eq!(chosen, "/root/README (restored 1)");
        }
        other => panic!("expected a conflict name: {other:?}"),
    }
}

#[test]
fn a_dotfile_is_not_mistaken_for_an_extension() {
    // `.bashrc` is a name, not an extension — splitting it would produce
    // ` (restored 1).bashrc` with an empty stem.
    match choose_restore_path("/root/.bashrc", &|p| p == "/root/.bashrc") {
        RestoreTarget::Conflict { chosen, .. } => {
            assert!(
                chosen.contains(".bashrc"),
                "the name must survive intact: {chosen}"
            );
            assert!(!chosen.starts_with("/root/ ("), "empty stem: {chosen}");
        }
        other => panic!("expected a conflict name: {other:?}"),
    }
}

#[test]
fn a_dot_in_a_parent_directory_is_not_treated_as_an_extension() {
    // `/root/v1.2/README` has a dot, but not in the file name.
    match choose_restore_path("/root/v1.2/README", &|p| p == "/root/v1.2/README") {
        RestoreTarget::Conflict { chosen, .. } => {
            assert_eq!(chosen, "/root/v1.2/README (restored 1)");
        }
        other => panic!("expected a conflict name: {other:?}"),
    }
}

/// A restore that drops captured attributes must not report success.
///
/// `restore_file` writes bytes, mode and mtime and nothing else, so every
/// `Captured` xattr, ACL, resource fork, Finder tag and alternate data stream
/// in a manifest is lost — and `verify_restore` never looked at
/// `manifest.optional`, so it said `Ok(())` while it happened. §4.10.6's rule
/// is that anything not preserved is DOCUMENTED, and silence is the one
/// outcome it forbids.
///
/// One breach per class, because the remedies differ: xattrs can be re-set
/// from the manifest, a resource fork cannot.
#[test]
fn captured_optional_attributes_that_are_not_restored_are_reported() {
    let m = FidelityManifest::new(core())
        .with(
            AttrClass::Xattrs,
            AttrCapture::Captured {
                values: BTreeMap::from([
                    ("user.tag".into(), "blue".into()),
                    ("user.origin".into(), "camera".into()),
                ]),
            },
        )
        .with(AttrClass::PosixAcl, AttrCapture::Absent)
        .with(
            AttrClass::ResourceFork,
            AttrCapture::Unsupported {
                reason: "the target cannot carry a resource fork".into(),
            },
        );

    let breaches = verify_restore(&m, &restored())
        .expect_err("a restore that silently dropped two xattrs reported full fidelity");
    assert_eq!(
        breaches,
        vec![FidelityBreach::OptionalNotRestored {
            class: AttrClass::Xattrs,
            values: 2,
        }],
        "only the CAPTURED class is a breach: `Absent` lost nothing, and \
         `Unsupported` is already disclosed through `gaps()`"
    );
}

/// The other direction: a manifest with no captured optional attributes is
/// still a clean restore, so the check above cannot be satisfied by refusing
/// everything.
#[test]
fn a_manifest_with_no_captured_optionals_still_passes() {
    let m = FidelityManifest::new(core())
        .with(AttrClass::Xattrs, AttrCapture::Absent)
        .with(
            AttrClass::FinderTags,
            AttrCapture::Unsupported {
                reason: "not macOS".into(),
            },
        );
    assert_eq!(verify_restore(&m, &restored()), Ok(()));
}
