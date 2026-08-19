//! The catalog replica and the disaster-recovery bundle.
//!
//! [`chain`] is OQ-1's mechanism: immutable segments published by hash-chained
//! pointer records with collision-proof, locally-allocated keys, needing only
//! `create` and `list` from the substrate. [`bundle`] is §4.10.3a's four-class
//! content that rides it.
//!
//! They are deliberately one mechanism and two payloads. Phase 6's
//! `SegmentChainReplica` extends this with queryability; it is **not** a second
//! design, and the bundle could not wait for it — Phase 2 performs the first
//! irreversible destruction, and destruction is not permitted until a recovery
//! bundle entry covering the file has been published and confirmed.

pub mod bundle;
pub mod chain;

pub use bundle::{
    BUNDLE_SCHEMA_VERSION, BootstrapRecord, BundleClass, BundleEntry, ConfigKind, CustodyKey,
    CustodyRecord, DurableConfigRecord, LogicalClock, bootstrap_key, bundle_class_of,
    decode_segment, encode_segment, merge_custody, merge_durable_config,
};
pub use chain::{
    CATALOG_PREFIX, ChainError, ChainResolution, ChainStatus, ChainWriter, POINTER_SCHEMA_VERSION,
    PointerRecord, RecordKey, SegmentEvidence, SegmentKind, SequenceAllocator, read_chain,
    resolve_chain, verify_segments,
};
