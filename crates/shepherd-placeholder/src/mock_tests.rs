//! Tests for the synthetic stub lifecycle.
//!
//! The load-bearing one is `trashing_is_never_a_permanent_delete`. If that
//! distinction collapses, the deferral window insures against nothing — the
//! misclassification it exists for is reading "permanently deleted" when the
//! user only trashed something.

use super::*;

fn p(s: &str) -> PathBuf {
    PathBuf::from(s)
}

#[test]
fn trashing_is_never_a_permanent_delete() {
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a.raw");
    m.emit_trashed("/root/a.raw").expect("trash");

    assert_eq!(
        m.state_of(&p("/root/a.raw")),
        Some(StubState::TrashedPending)
    );
    assert!(
        !StubState::TrashedPending.is_permanent_delete(),
        "a trashed stub must never confirm a permanent delete"
    );
}

#[test]
fn an_undelete_after_a_trash_restores_rather_than_destroying() {
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a.raw");
    m.emit_trashed("/root/a.raw").unwrap();
    m.emit_undeleted("/root/a.raw").expect("undelete");

    assert_eq!(m.state_of(&p("/root/a.raw")), Some(StubState::Restored));
    assert!(!m.state_of(&p("/root/a.raw")).unwrap().is_permanent_delete());
}

#[test]
fn a_trash_followed_by_a_permanent_delete_does_confirm() {
    // The legitimate path to a discard: emptied from the trash.
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a.raw");
    m.emit_trashed("/root/a.raw").unwrap();
    m.emit_deleted("/root/a.raw");

    assert_eq!(
        m.state_of(&p("/root/a.raw")),
        Some(StubState::PermanentlyDeleted)
    );
    assert!(m.state_of(&p("/root/a.raw")).unwrap().is_permanent_delete());
}

#[test]
fn undeleting_something_that_was_not_trashed_is_refused() {
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a.raw");
    let err = m.emit_undeleted("/root/a.raw").expect_err("must refuse");
    assert!(matches!(err, MockError::NotTrashed { .. }));

    // And a permanently deleted stub cannot be trashed back into existence.
    m.emit_deleted("/root/a.raw");
    assert!(matches!(
        m.emit_trashed("/root/a.raw").expect_err("must refuse"),
        MockError::AlreadyPermanentlyDeleted { .. }
    ));
}

/// **AC-4's mock leg.** A rename is not a delete of the old path.
#[test]
fn a_rename_carries_state_to_the_new_path_and_is_not_an_absence() {
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/old.raw");
    m.emit_trashed("/root/old.raw").unwrap();
    m.emit_renamed("/root/old.raw", "/root/new.raw")
        .expect("rename");

    assert_eq!(m.state_of(&p("/root/old.raw")), None);
    assert_eq!(
        m.state_of(&p("/root/new.raw")),
        Some(StubState::TrashedPending),
        "state must follow the file, not stay with the path"
    );
    assert_eq!(
        m.events().last(),
        Some(&StubLifecycleEvent::Renamed {
            from: p("/root/old.raw"),
            to: p("/root/new.raw"),
        })
    );
}

#[test]
fn a_rename_never_synthesizes_a_delete_event() {
    // PM-3: a rename read as an absence is discard-trigger territory.
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/old.raw");
    m.emit_renamed("/root/old.raw", "/root/new.raw").unwrap();

    assert!(
        !m.events()
            .iter()
            .any(|e| matches!(e, StubLifecycleEvent::Deleted { .. })),
        "a move must not look like a deletion: {:?}",
        m.events()
    );
    assert_eq!(m.state_of(&p("/root/new.raw")), Some(StubState::Present));
}

#[test]
fn renaming_an_unknown_stub_is_refused_rather_than_inventing_one() {
    let m = MockPlaceholderProvider::new();
    assert!(matches!(
        m.emit_renamed("/root/ghost.raw", "/root/x.raw")
            .expect_err("must refuse"),
        MockError::UnknownStub { .. }
    ));
}

#[test]
fn events_are_recorded_in_order() {
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a");
    m.emit_trashed("/root/a").unwrap();
    m.emit_undeleted("/root/a").unwrap();
    m.emit_deleted("/root/a");

    let kinds: Vec<&str> = m
        .events()
        .iter()
        .map(|e| match e {
            StubLifecycleEvent::Created { .. } => "created",
            StubLifecycleEvent::Renamed { .. } => "renamed",
            StubLifecycleEvent::Deleted { .. } => "deleted",
            StubLifecycleEvent::Trashed { .. } => "trashed",
            StubLifecycleEvent::Undeleted { .. } => "undeleted",
        })
        .collect();
    assert_eq!(kinds, ["created", "trashed", "undeleted", "deleted"]);
}

#[test]
fn the_full_lifecycle_is_representable_not_just_deletion() {
    // Iteration 2 scoped this mock to stub-DELETED events only, which left AC-4
    // owned by a phase that could not exercise it. All five must exist.
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a");
    m.emit_renamed("/root/a", "/root/b").unwrap();
    m.emit_trashed("/root/b").unwrap();
    m.emit_undeleted("/root/b").unwrap();
    m.emit_deleted("/root/b");
    assert_eq!(m.events().len(), 5);
}

#[test]
fn the_mock_reports_delete_mode_rather_than_pretending_to_be_a_stub_platform() {
    // Its destructive path really is delete-mode's, and saying otherwise would
    // let a Phase 2 test claim a platform leg it never exercised.
    let m = MockPlaceholderProvider::new();
    assert_eq!(m.mode(), ProviderMode::DeleteMode);
}

#[test]
fn nothing_is_destroyed_merely_by_emitting_events() {
    // Events are signals, not actions. Only `destroy_local` destroys, and it
    // goes through the real delete-mode primitive.
    let m = MockPlaceholderProvider::new();
    m.emit_created("/root/a");
    m.emit_trashed("/root/a").unwrap();
    m.emit_deleted("/root/a");
    assert!(
        m.destroyed().is_empty(),
        "a synthetic event must never itself unlink anything"
    );
}
