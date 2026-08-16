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
pub mod destroy;
pub mod revalidate;
pub mod serialize;
#[cfg(test)]
mod test_adapter;

pub use audit::{AuditLog, AuditRecord};
pub use destroy::{LocalDestroyRequest, execute_local_destruction, execute_remote_discard};
pub use revalidate::{ClosingCheck, DestroyRefusal, Location, LocationState, destroy_permitted};
pub use serialize::FileLocks;
