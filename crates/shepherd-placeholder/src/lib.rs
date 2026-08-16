//! `PlaceholderProvider` and its per-platform implementations.
//!
//! **This crate is reachable only from `shepherd-tier`** (§4.1 rule 2), and
//! `cargo xtask check-deps` fails the build if any other crate draws the edge —
//! across normal, build and dev dependencies alike. That is what makes
//! `shepherd-tier::destroy` the only path to a destructive syscall: Cargo
//! cannot forbid a syscall, but it can forbid an edge.
//!
//! | module | platform | phase |
//! |---|---|---|
//! | [`delete_mode`] | Unix delete-mode roots | 2 — the reference implementation |
//! | `cfapi` | Windows `FileDispositionInfoEx` | 3 |
//! | `fileprovider` | macOS eviction | 3 |
//! | `mock` | synthetic stub lifecycle events | 2 (T10) |

pub mod delete_mode;
pub mod mock;
pub mod provider;

pub use delete_mode::DeleteModeProvider;
pub use provider::{
    Feasibility, FileIdentity, PlaceholderProvider, ProviderError, ProviderMode, RestoreOutcome,
    Staged,
};
