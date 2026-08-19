//! IPC wire types and the method table: the single source of truth for the
//! JSON-RPC surface.
//!
//! # The method table is the product surface
//!
//! [`MethodKind`] declares every capability exactly once. The daemon's dispatch
//! table, `shepctl`'s command tree, the committed JSON Schemas and the AC-54
//! inventory manifest are all derived from it — none of them re-declares a
//! method. That is what makes "the UI has no capability the CLI lacks"
//! structural rather than aspirational (§4.3, P3).
//!
//! # Two contracts live in this crate, and they must not be welded together
//!
//! ```text
//!   script  ──jq──►  CliEnvelope { schema_version, ok, data, error, warnings }
//!                        ▲                                    (envelope.rs)
//!                        │  data = the method's result payload, verbatim
//!                        │  code = a stable lower_snake slug
//!                        │
//!   shepctl ────────────►│
//!       │
//!       └──socket──►  RpcRequest / RpcResponse { jsonrpc, id, result|error }
//!                                          (request.rs, response.rs, error.rs)
//! ```
//!
//! The transport frame may be re-shaped within a major version; the envelope may
//! only grow. Iteration 1 of the plan made them the same artifact — "the CLI's
//! `--json` output *is* the IPC response verbatim" — which would have made every
//! framing change a breaking change to AC-56's stable machine-readable output.
//! [`envelope`] carries the full reasoning and the tests that pin the boundary.
//!
//! # Module map
//!
//! | module | contract |
//! |---|---|
//! | [`version`] | handshake, major/minor compatibility, capability negotiation |
//! | [`method`] | the method table, `ShepherdApi`, the registry fingerprint |
//! | [`request`] | JSON-RPC request framing + per-method request payloads |
//! | [`response`] | JSON-RPC response framing + per-method result payloads |
//! | [`error`] | the transport error taxonomy and its stable-slug bridge |
//! | [`event`] | sequence numbers, bounded buffering, resume, snapshot recovery |
//! | [`envelope`] | the stable CLI result envelope (AC-56) |
//!
//! # This crate depends on nothing internal
//!
//! §4.1 rule 1, enforced by `cargo xtask check-deps`. Wire types are therefore
//! plain scalars and proto-local enums rather than `shepherd-core` newtypes —
//! see [`request`] for why that separation is load-bearing rather than
//! incidental.

#![forbid(unsafe_code)]

pub mod envelope;
pub mod error;
pub mod event;
pub mod method;
pub mod request;
pub mod response;
pub mod version;

pub use envelope::{CLI_SCHEMA_VERSION, CliEnvelope, CliError};
pub use error::{ErrorCode, RpcError, UNKNOWN_ERROR_SLUG};
pub use event::{
    DEFAULT_EVENT_BUFFER_FRAMES, EventBuffer, EventFrame, EventPayload, EventStream, ResumeOutcome,
    Seq, SnapshotReason, SubscribeResult,
};
pub use method::{
    DESCRIPTORS, Deprecation, Method, MethodDescriptor, MethodId, MethodKind, MethodResult,
    ShepherdApi, registry_canonical_form, registry_fingerprint,
};
pub use request::{RequestId, RpcRequest, SubscribeRequest};
pub use response::{EVENT_NOTIFICATION_METHOD, RpcNotification, RpcResponse};
pub use version::{
    COMPATIBILITY_POLICY, Capability, Hello, HelloResult, Negotiated, PROTO_VERSION, PeerInfo,
    ProtoVersion, UPGRADE_COMMAND, VersionMismatch, capability, negotiate,
};

#[cfg(test)]
mod tests {
    use super::*;

    /// A tripwire, not a tautology.
    ///
    /// `PROTO_VERSION` is asserted against a literal in exactly one place —
    /// here — so an accidental bump fails a test with an obvious name, while a
    /// deliberate one is a two-line diff next to the minor history in
    /// `version.rs`. Everywhere else compares against the constant, so a
    /// deliberate bump does not ripple.
    #[test]
    fn the_protocol_version_is_what_the_minor_history_says() {
        assert_eq!(
            (PROTO_VERSION.major, PROTO_VERSION.minor),
            (1, 2),
            "if this bump is deliberate, update `version.rs`'s minor history in \
             the same change and set every new method's `since` to the new minor"
        );
    }

    #[test]
    fn the_crate_speaks_one_protocol_version() {
        assert_eq!(PROTO_VERSION.major, 1);
        // Every method in the table must be reachable at the version this build
        // advertises, or the daemon would ship a method it refuses to serve.
        for k in MethodKind::ALL {
            assert!(
                k.available_at(PROTO_VERSION.minor),
                "`{}` has since_minor {} but this build advertises minor {}",
                k.name(),
                k.descriptor().since_minor,
                PROTO_VERSION.minor
            );
        }
    }

    #[test]
    fn the_compatibility_policy_ships_with_the_artifact() {
        // It is embedded in `schemas/ipc-inventory.json` by `xtask codegen`; an
        // empty or truncated constant would silently publish no policy at all.
        assert!(COMPATIBILITY_POLICY.contains("Additive-only"));
        assert!(COMPATIBILITY_POLICY.contains("never reused"));
        assert!(COMPATIBILITY_POLICY.lines().count() > 5);
    }

    #[test]
    fn a_full_call_round_trips_frame_to_envelope() {
        // The whole path in one test: request frame -> typed method -> typed
        // result -> response frame -> CLI envelope. What a script sees at the
        // end must be the result payload and nothing else.
        let req = RpcRequest::new(
            1,
            MethodKind::RootList.name(),
            serde_json::json!({"include_disabled": true}),
        );
        let wire = serde_json::to_string(&req).unwrap();
        let parsed: RpcRequest = serde_json::from_str(&wire).unwrap();

        let call = Method::from_parts(&parsed.method, &parsed.params).unwrap();
        assert_eq!(call.kind(), MethodKind::RootList);

        let result = MethodResult::RootList(response::RootListResult { roots: vec![] });
        let frame = RpcResponse::ok(parsed.id, result.to_value().unwrap());
        let payload = frame.outcome().unwrap();

        let env = CliEnvelope::ok(payload);
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["ok"], serde_json::json!(true));
        assert_eq!(json["data"]["roots"], serde_json::json!([]));
        assert!(json.get("jsonrpc").is_none());
        assert!(json.get("id").is_none());
    }

    #[test]
    fn a_daemon_error_becomes_a_stable_slug_by_the_time_a_script_sees_it() {
        let frame = RpcResponse::failed(
            Some(RequestId::Number(1)),
            RpcError::new(ErrorCode::Refused, "root is awaiting resync"),
        );
        let err = frame.outcome().unwrap_err();
        let env = CliEnvelope::failed(CliError::from(&err));
        let json = serde_json::to_value(&env).unwrap();
        assert_eq!(json["error"]["code"], serde_json::json!("refused"));
        assert_eq!(json["ok"], serde_json::json!(false));
    }
}
