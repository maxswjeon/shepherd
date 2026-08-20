//! Filesystem walker: deny-list, user ignores, hard safety floors and BLAKE3.
//!
//! # The shape of a scan
//!
//! ```text
//! walk ──► denylist (prunes directories)
//!      ──► ignore   (user patterns, .gitignore semantics)
//!      ──► floors   (AC-8 eligibility)
//!      ──► FileStat { blake3: None     ino: None,
//!      ──► FileStat { blake3: None }  ──► catalog
//!                                     ──► `hash` job class, later
//! ```
//!
//! Three things this crate deliberately does **not** do:
//!
//! * **It does not hash during the walk.** §6 Phase 1 makes BLAKE3 its own job
//!   class, "never a scan prerequisite" — a full pass over 50 TB would gate
//!   cataloguing behind days of I/O.
//! * **It does not normalise paths.** `norm_key` is computed catalog-side from
//!   each root's probed policy (§4.9). Baking one normalization into a layer
//!   that serves every root is the assumption §4.9 exists to forbid.
//! * **It does not touch the catalog.** Scan emits, catalog ingests. There is
//!   no `shepherd-catalog` dependency here, and that is intentional rather than
//!   incidental — no `check-deps` rule covers this edge, so it is kept clean by
//!   design.

pub mod denylist;
pub mod floors;
pub mod hash;
pub mod ignore;
pub mod walk;

pub use denylist::{DenyList, DenyReason, STAGING_DIR_NAME};
pub use floors::{FloorContext, FloorInput, FloorPolicy, FloorRefusal, Verdict};
pub use hash::{HashOutcome, hash_bytes, hash_file};
pub use ignore::IgnoreSet;
pub use walk::{Skip, WalkOutput, walk};
