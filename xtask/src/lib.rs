//! Workspace task library.
//!
//! The binary in `src/main.rs` is a thin dispatcher over these modules. They
//! live in a library so `xtask/tests/` can drive them against synthetic
//! fixtures — in particular `tests/rule4.rs`, which proves the §4.1 rule 4
//! scanner catches a forbidden call site. Those fixtures necessarily contain
//! the destructive symbol names as literals, which is exactly why they must sit
//! outside `rule4.scan_roots` in `deps-policy.toml`.

pub mod check_deps;
pub mod claim_ledger;
pub mod gate_audit;
