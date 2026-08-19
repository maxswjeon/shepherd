//! **THE DESTROY PATH** — §4.10's invariants.
//!
//! This is the only crate permitted to depend on `shepherd-placeholder`
//! (§4.1 rule 2), and [`destroy`] is the only module permitted to call a
//! destructive primitive (rule 4). `cargo xtask check-deps` fails the build on
//! either violation.
//!
//! | module | role | phase |
//! |---|---|---|
//! | [`destroy`] | §4.10.1's ordering; sole caller of every destructive primitive | 2 (T8) |
//! | [`revalidate`] | §4.10.2 attestation and the N-location destroy predicate | 2 (T8) |
//! | [`audit`] | the append-only forensic record, and the halt it enforces | 2 (T8) |
//! | [`serialize`] | per-file locking, keyed on identity | 2 (T8) |
//! | `plan` / `upload` / `verify` / `discard` / `breaker` / `restore` / `fidelity` | | 2 (T10) |

pub mod audit;
pub mod breaker;
pub mod destroy;
pub mod discard;
pub mod fidelity;
pub mod plan;
pub mod restore;
pub mod revalidate;
pub mod serialize;
pub mod session_store;
pub mod upload;
pub mod verify;

pub use audit::{AuditLog, AuditRecord};
pub use breaker::{
    BreakerLimits, BreakerRefusal, Candidate, Episode, EpisodeState, HoldScope, RateLedger,
    RateWindow, candidate_set_hash,
};
pub use destroy::{LocalDestroyRequest, execute_local_destruction, execute_remote_discard};
pub use discard::{
    DiscardCharge, DiscardRefusals, StubPlatform, confirmation_from_operator,
    confirmation_from_stub, evaluate_discard, execute_discard, hold_blocks, reserve_discard,
};
pub use fidelity::{
    AttrCapture, AttrClass, CoreAttrs, FidelityBreach, FidelityManifest, RestoreTarget,
    RestoredAttrs, choose_restore_path, verify_restore,
};
pub use plan::{PlanRefusal, SelectedFile, TierItem, TierPlan, derive_object_key, plan_tier};
pub use restore::{RestoreError, RestoreOutcome, read_back, restore_file};
pub use revalidate::{ClosingCheck, DestroyRefusal, Location, LocationState, destroy_permitted};
pub use serialize::FileLocks;
pub use session_store::CatalogSessionStore;
pub use upload::{FileSource, hash_file, upload_item};
pub use verify::{VerifiedLocation, verify_upload};
