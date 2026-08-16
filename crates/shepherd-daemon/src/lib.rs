//! The always-on daemon: IPC server, job pool host, and service lifecycle.
//!
//! # Why this crate has a library as well as a binary
//!
//! The binary is a thin `main` over these modules. They live in a library so
//! `tests/` can drive them directly — in particular `tests/e2e.rs`, which
//! starts a real `shepherdd` and runs a real `shepctl` against it. A daemon
//! whose only entry point is `fn main` can only be tested by shelling out and
//! guessing at its state.
//!
//! # Layering
//!
//! ```text
//!   main.rs        argv: run | install | uninstall | doctor
//!   server.rs      unix socket, framing, `hello`, per-connection threads
//!   dispatch.rs    the generated `ShepherdApi` impl — the product surface
//!   state.rs       process-wide state shared by every connection
//!   events.rs      fan-out over shepherd-proto's EventBuffer
//!   scan_exec.rs   the `scan` job executor: walk a root, upsert what it finds
//!   paths.rs       where the socket and the catalog live
//!   service/       systemd user unit, launchd LaunchAgent
//! ```

pub mod dispatch;
pub mod events;
pub mod paths;
pub mod scan_exec;
#[cfg(unix)]
pub mod server;
pub mod service;
pub mod state;

pub use paths::{Env, Paths};
pub use state::Daemon;

/// Frames the event hub retains.
pub const EVENT_BUFFER: usize = shepherd_proto::DEFAULT_EVENT_BUFFER_FRAMES;
