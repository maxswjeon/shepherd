//! `MockPlaceholderProvider` — synthetic stub lifecycle events for Phase 2.
//!
//! # Why this exists
//!
//! M2 ships on Linux, and **on Linux delete-mode there are no stubs**. So the
//! events that drive AC-3's discard trigger, AC-4's rename-pointer path and
//! AC-10's mode switching cannot occur on the platform where Phase 2 is
//! developed and gated. This provider synthesizes them, so the delete-policy
//! engine, the discard apparatus and the bulk breaker are exercised in Phase 2
//! rather than first meeting a real event in Phase 3.
//!
//! **These are mock legs only.** §9's Phase 2 gate is explicit that it "does
//! not claim any of the three complete"; final ownership of AC-3, AC-4 and
//! AC-10 is Phase 3, against real stubs. Exactly one gate may claim a complete
//! AC, and this is not it.
//!
//! # Scope, and the defect that widened it
//!
//! Iteration 2 scoped this mock to stub-**deleted** events only. That left AC-4
//! — rename/move of a stub — owned by a phase that could not exercise it, the
//! third instance of the plan's recurring defect class (a fix landing in one
//! place while its consequences stayed stale elsewhere). So the event set is
//! the full lifecycle: created, **renamed/moved**, deleted, trashed, undeleted.
//!
//! # The distinction this type exists to protect
//!
//! **Trashed is not deleted.** §4.10.3's per-platform table turns on exactly
//! that: Windows `NOTIFY_DELETE` *with* `CF_CALLBACK_DELETE_FLAG_IS_UNDELETE`
//! is an undelete, macOS's `.trashContainer` reparent is a trash and its
//! `deleteItem` is "delete an item forever". Collapsing the two would make the
//! deferral window insure against nothing, because the misclassification it
//! insures against is precisely reading "permanently deleted" when the user
//! only trashed something.
//!
//! So the mock runs the state machine §4.10.3 specifies —
//! `present → trashed_pending → restored | permanently_deleted` — and reports
//! [`StubState`]. It does **not** produce a `PermanentDeleteConfirmation`: that
//! translation is `shepherd-tier`'s, which is the crate permitted to see both
//! this one and the policy engine. Keeping it out of here is what lets
//! `shepherd-rules` stay free of any edge to this crate (§4.1 rule 2).

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use shepherd_core::Blake3Hash;

use crate::delete_mode::DeleteModeProvider;
use crate::provider::{
    Feasibility, PlaceholderProvider, ProviderError, ProviderMode, RestoreOutcome, Result, Staged,
};

/// A synthetic stub lifecycle event, as a real provider would deliver it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StubLifecycleEvent {
    /// A placeholder appeared.
    Created { path: PathBuf },
    /// **AC-4.** The stub was renamed or moved; the catalog must follow the
    /// file rather than treating the old path as an absence.
    Renamed { from: PathBuf, to: PathBuf },
    /// A **permanent** deletion. Windows `NOTIFY_DELETE` without
    /// `IS_UNDELETE`; macOS `deleteItem`.
    Deleted { path: PathBuf },
    /// Moved to the trash — **reversible, and not a permanent delete**.
    Trashed { path: PathBuf },
    /// Restored from the trash. Windows `IS_UNDELETE`; macOS a reparent out of
    /// `.trashContainer`. Cancels any deferral.
    Undeleted { path: PathBuf },
}

/// §4.10.3's per-file state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StubState {
    Present,
    /// In the trash. The user can still change their mind.
    TrashedPending,
    /// Came back out of the trash.
    Restored,
    /// Confirmed permanently deleted. **Only this state may start a discard
    /// deferral.**
    PermanentlyDeleted,
}

impl StubState {
    /// Whether this state is a provider-confirmed *permanent* deletion.
    ///
    /// [`StubState::TrashedPending`] is deliberately false. That is the whole
    /// point of the type.
    pub fn is_permanent_delete(self) -> bool {
        matches!(self, StubState::PermanentlyDeleted)
    }
}

/// What the mock refused to do, when a caller drives an impossible transition.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MockError {
    #[error("cannot undelete {path}: it is not in the trash (state: {state:?})")]
    NotTrashed { path: String, state: StubState },
    #[error("cannot rename {from}: no such stub")]
    UnknownStub { from: String },
    #[error("cannot act on {path}: it was already permanently deleted")]
    AlreadyPermanentlyDeleted { path: String },
}

/// A `PlaceholderProvider` that behaves like delete-mode but also emits
/// synthetic stub lifecycle events.
///
/// Staging, feasibility probing and move-back all delegate to
/// [`DeleteModeProvider`] rather than being reimplemented: a mock that
/// hand-rolled its own staging would be testing itself instead of the code
/// Phase 2 actually ships, and §4.10.1's identity-bound staging is the part
/// most worth exercising honestly.
///
/// `destroy_local` is the single exception — see the note on that method.
#[derive(Debug)]
pub struct MockPlaceholderProvider {
    inner: DeleteModeProvider,
    state: Mutex<MockState>,
}

#[derive(Debug, Default)]
struct MockState {
    events: Vec<StubLifecycleEvent>,
    stubs: HashMap<PathBuf, StubState>,
    /// Paths passed to `destroy_local`, so tier tests can assert what was
    /// actually destroyed rather than inferring it.
    destroyed: Vec<PathBuf>,
    /// One-shot: make the next `destroy_local` fail, so §4.10.4's
    /// abort-forward-never recovery is reachable in a test.
    fail_next_destroy: bool,
}

impl Default for MockPlaceholderProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl MockPlaceholderProvider {
    pub fn new() -> Self {
        Self {
            inner: DeleteModeProvider::new(),
            state: Mutex::new(MockState::default()),
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, MockState> {
        self.state.lock().expect("mock state mutex poisoned")
    }

    /// Every event emitted so far, in order.
    pub fn events(&self) -> Vec<StubLifecycleEvent> {
        self.lock().events.clone()
    }

    /// Current state of one stub, if it is known.
    pub fn state_of(&self, path: &Path) -> Option<StubState> {
        self.lock().stubs.get(path).copied()
    }

    /// Paths that reached the irreversible primitive.
    pub fn destroyed(&self) -> Vec<PathBuf> {
        self.lock().destroyed.clone()
    }

    /// Make the next `destroy_local` fail once.
    pub fn fail_next_destroy(&self) {
        self.lock().fail_next_destroy = true;
    }

    /// A placeholder appeared.
    pub fn emit_created(&self, path: impl Into<PathBuf>) {
        let path = path.into();
        let mut s = self.lock();
        s.stubs.insert(path.clone(), StubState::Present);
        s.events.push(StubLifecycleEvent::Created { path });
    }

    /// **AC-4.** Rename or move a stub, carrying its state to the new path.
    ///
    /// The state moves with the file. A rename is emphatically *not* a delete
    /// of the old path — treating it as one is exactly the false absence PM-3
    /// shows is discard-trigger territory.
    pub fn emit_renamed(
        &self,
        from: impl Into<PathBuf>,
        to: impl Into<PathBuf>,
    ) -> std::result::Result<(), MockError> {
        let (from, to) = (from.into(), to.into());
        let mut s = self.lock();
        let state = s
            .stubs
            .remove(&from)
            .ok_or_else(|| MockError::UnknownStub {
                from: from.display().to_string(),
            })?;
        s.stubs.insert(to.clone(), state);
        s.events.push(StubLifecycleEvent::Renamed { from, to });
        Ok(())
    }

    /// Move a stub to the trash. **Reversible** — this is not a permanent
    /// delete and must never start a discard on its own.
    pub fn emit_trashed(&self, path: impl Into<PathBuf>) -> std::result::Result<(), MockError> {
        let path = path.into();
        let mut s = self.lock();
        if s.stubs.get(&path) == Some(&StubState::PermanentlyDeleted) {
            return Err(MockError::AlreadyPermanentlyDeleted {
                path: path.display().to_string(),
            });
        }
        s.stubs.insert(path.clone(), StubState::TrashedPending);
        s.events.push(StubLifecycleEvent::Trashed { path });
        Ok(())
    }

    /// Restore from the trash. Cancels any deferral the trash event opened.
    pub fn emit_undeleted(&self, path: impl Into<PathBuf>) -> std::result::Result<(), MockError> {
        let path = path.into();
        let mut s = self.lock();
        match s.stubs.get(&path).copied() {
            Some(StubState::TrashedPending) => {
                s.stubs.insert(path.clone(), StubState::Restored);
                s.events.push(StubLifecycleEvent::Undeleted { path });
                Ok(())
            }
            other => Err(MockError::NotTrashed {
                path: path.display().to_string(),
                state: other.unwrap_or(StubState::Present),
            }),
        }
    }

    /// A **permanent** deletion — the only event that may start a discard
    /// deferral.
    pub fn emit_deleted(&self, path: impl Into<PathBuf>) {
        let path = path.into();
        let mut s = self.lock();
        s.stubs.insert(path.clone(), StubState::PermanentlyDeleted);
        s.events.push(StubLifecycleEvent::Deleted { path });
    }
}

impl PlaceholderProvider for MockPlaceholderProvider {
    fn mode(&self) -> ProviderMode {
        // Honest about what it really is: the destructive path below is
        // delete-mode's, not a synthetic one.
        self.inner.mode()
    }

    fn probe_feasibility(&self, root: &Path) -> Result<Feasibility> {
        self.inner.probe_feasibility(root)
    }

    fn stage_for_destruction(&self, path: &Path) -> Result<Staged> {
        self.inner.stage_for_destruction(path)
    }

    /// The one primitive this mock does **not** delegate.
    ///
    /// Two reasons, and the first is a hard constraint. `clippy.toml` lists
    /// `PlaceholderProvider::destroy_local` as a disallowed method, and the only
    /// module permitted `#![allow(clippy::disallowed_methods)]` is
    /// `shepherd-tier::destroy` — so this module may *implement* the method
    /// (rule 4's `implemented_in` covers this crate) but may not *call* it on
    /// the inner provider. Delegating would put a denied call right here.
    ///
    /// The second is that it earns its keep: `fail_next_destroy` lets a tier
    /// test drive §4.10.4's abort-forward-never recovery, which needs the
    /// irreversible step to fail on demand — something a real filesystem will
    /// not do when asked politely.
    fn destroy_local(&self, staged: &Staged, _expected: Blake3Hash) -> Result<()> {
        {
            let mut s = self.lock();
            if std::mem::take(&mut s.fail_next_destroy) {
                return Err(ProviderError::Io {
                    path: staged.staged.display().to_string(),
                    detail: "injected destroy failure".into(),
                });
            }
        }
        // Unlinks the STAGED entry, never the original path — by this point the
        // original name no longer resolves to this file, which is the whole
        // point of §4.10.1's staging step.
        std::fs::remove_file(&staged.staged).map_err(|e| ProviderError::Io {
            path: staged.staged.display().to_string(),
            detail: e.to_string(),
        })?;
        let mut s = self.lock();
        s.destroyed.push(staged.original.clone());
        s.stubs
            .insert(staged.original.clone(), StubState::PermanentlyDeleted);
        Ok(())
    }

    fn restore_staged(&self, staged: Staged) -> Result<RestoreOutcome> {
        let original = staged.original.clone();
        let outcome = self.inner.restore_staged(staged)?;
        self.lock().stubs.insert(original, StubState::Restored);
        Ok(outcome)
    }

    fn list_staged(&self, root: &Path) -> Result<Vec<PathBuf>> {
        self.inner.list_staged(root)
    }
}

/// Convenience for tests that only care that an error was a mock refusal.
impl From<MockError> for ProviderError {
    fn from(e: MockError) -> Self {
        ProviderError::Io {
            path: String::new(),
            detail: e.to_string(),
        }
    }
}

#[cfg(test)]
#[path = "mock_tests.rs"]
mod tests;
