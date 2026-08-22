//! Metadata name index, sharded ANN index, hybrid search and reciprocal-rank fusion.
//!
//! # What exists
//!
//! [`meta`] — the metadata name index: §4.6's 50 ms-bar winner, an in-RAM arena
//! of ASCII-folded paths scanned with `memchr::memmem`. It is deliberately
//! *catalog-agnostic*: rows are pushed in through [`meta::MetaIndexBuilder`] and
//! the caller owns the SQL. That keeps this crate's dependency surface at one
//! third-party crate, lets its tests run against synthetic corpora with no
//! database, and means the arena has no opinion about which table it came from.
//!
//! # What does not exist yet
//!
//! `ann/`, `hybrid.rs` and `rrf.rs` — the vector side — are **Phase 5**, and the
//! §4.6 work that settled `usearch` + i8 quantization is recorded there, not
//! here. Nothing in [`meta`] anticipates them: rank-level fusion needs ranks, and
//! a metadata query has no score to fuse (`SearchHit::score` is documented
//! absent for exactly that reason). The seam is a Phase 5 decision and building
//! for it now would be guessing.

#![forbid(unsafe_code)]

pub mod meta;

pub use meta::{BuildError, Matches, MetaIndex, MetaIndexBuilder, Scope};
