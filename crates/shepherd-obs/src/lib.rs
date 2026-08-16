//! Observability: tracing setup, the metrics registry, and doctor checks.
//!
//! Phase 0a delivers the skeleton the later phases attach to:
//!
//! * [`tracing`] — one place that configures the subscriber, so the daemon, the
//!   CLI and the test harnesses all emit the same shape.
//! * [`metrics`] — a small in-process registry of counters and gauges. It is
//!   hand-rolled rather than pulled from a crate because the surface Shepherd
//!   needs is this small, and because §9's gates read metric values directly.
//! * [`doctor`] — the check list `shepctl doctor` renders. Phase 1 onward
//!   registers real checks; the harness and the *semantics of a warning* exist
//!   now because OQ-F's headless-Linux lingering path is a check that must
//!   **warn and never modify**, and that distinction has to be representable
//!   before someone writes the check.

pub mod doctor;
/// systemd user-lingering detection (OQ-F): detect, warn, never modify.
pub mod lingering;
pub mod metrics;
pub mod tracing_setup;

pub use doctor::{Check, CheckStatus, Doctor};
pub use metrics::{Counter, Gauge, Registry, Snapshot};
pub use tracing_setup::init_tracing;
