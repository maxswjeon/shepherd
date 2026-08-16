//! StorageAdapter trait, per-provider adapters and the catalog replica bundle.
//!
//! # The shape of this crate
//!
//! [`adapter`] defines the provider ABI. Everything else here is written
//! against that trait and against `shepherd-core`'s domain types — no module
//! outside `s3.rs` names a provider SDK type. That is not tidiness: it is what
//! lets the transfer state machine and the replica chain, which are the two
//! pieces whose correctness a user's only remaining copy depends on, be tested
//! exhaustively with no network, no credentials and no emulator.
//!
//! | Module | Holds |
//! |---|---|
//! | [`adapter`] | The `create`-not-`put` ABI, opaque provider tokens, attestation modes |
//! | [`multipart`] | Part planning and the crash-safe resume reconciliation |
//! | [`transfer_session`] | The durable `planned → … → committed` state machine |
//! | [`replica`] | OQ-1's hash-chained pointer records and §4.10.3a's four-class recovery bundle |
//! | [`s3`] | The only module that names an AWS SDK type |
//!
//! # What this crate deliberately cannot do
//!
//! There is no `put`, no `rename` and no `move_to_trash` anywhere in the
//! adapter ABI. Overwrite is not filtered out at runtime — it is
//! *inexpressible*, because §4.9's keys are content-addressed and §4.10.5
//! requires that Shepherd never destroy data by writing. The two destructive
//! verbs that exist are split so that `delete_object` (user data) is callable
//! only from `shepherd-tier::destroy`, while `delete_system_object` is confined
//! to the `_shepherd/` prefix by its argument type rather than by convention.
//!
//! `opendal` is not a dependency. §4.5 removed it from every user-data path
//! because its `Writer` cannot resume parts after a disconnection, and spec:89
//! requires all transfers to be resumable.

#![forbid(unsafe_code)]

pub mod adapter;
pub mod multipart;
pub mod replica;
pub mod s3;
pub mod transfer_session;

#[cfg(test)]
mod testing;

pub use adapter::{
    AdapterCapabilities, AttestationMode, ByteRange, ControlKey, CreatePrecondition, CreateReceipt,
    IncompleteUpload, ListPage, ListVisibility, ObjectMeta, OpaqueToken, PartReceipt,
    StorageAdapter, StorageError, StorageResult, VersionGuard, verify_full_content,
};
pub use multipart::{
    DEFAULT_PART_SIZE, PartAction, PartCheckpoint, PartPlan, Reconciliation, reconcile_parts,
};
pub use transfer_session::{
    AbortOutcome, SourceIdentity, SourceReader, TransferDriver, TransferOutcome, TransferSession,
    TransferSessionStore, TransferState,
};
