//! The IPC error taxonomy.
//!
//! # Two error vocabularies, deliberately
//!
//! [`RpcError`] is the **transport** error: a JSON-RPC 2.0 `error` object with a
//! numeric `code`. JSON-RPC reserves `-32768..=-32000`, and this taxonomy uses
//! that reserved band for framing faults and a positive band for application
//! faults. Numeric codes are a transport detail: they may be added, subdivided
//! or retired as the protocol evolves across seven phases.
//!
//! [`crate::envelope::CliError`] is the **CLI** error: a stable *string* code
//! that scripts match on. It never carries the numeric code.
//!
//! Keeping them apart is the point of §4.3's correction. Iteration 1 welded the
//! CLI's `--json` output to the IPC response, which made every transport-level
//! renumbering a breaking change to AC-56's stable machine-readable output.
//! [`ErrorCode::stable_slug`] is the one-way bridge: transport code → stable
//! slug. There is deliberately no inverse, because adding a numeric code must
//! never be forced to invent a stable slug, and retiring one must never be
//! blocked by a script that matched on it.
//!
//! # Why `code` is an `i32` on the wire and not an enum
//!
//! Adding an error code is an *additive* change under
//! [`crate::COMPATIBILITY_POLICY`], so a peer built last month must survive
//! receiving one it has never heard of. If `code` deserialized into a closed
//! enum, an older client would fail to parse the error frame and would report a
//! protocol fault instead of the actual failure — turning "target unreachable"
//! into "the daemon is speaking gibberish". The field is therefore the raw
//! integer JSON-RPC specifies, and [`ErrorCode`] is a recognizer over it.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// The stable slug reported for a numeric code this build does not recognise.
///
/// Scripts may match it. It means "the daemon failed for a reason newer than
/// this client", which is actionable (upgrade) in a way a parse failure is not.
pub const UNKNOWN_ERROR_SLUG: &str = "unknown_error";

/// A JSON-RPC 2.0 error object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema, thiserror::Error)]
#[error("[{code}] {message}")]
pub struct RpcError {
    /// The JSON-RPC numeric code. Interpret via [`RpcError::kind`]; an
    /// unrecognised value is a forward-compatibility case, not a fault.
    pub code: i32,
    pub message: String,
    /// Structured detail. Free-form by design: it is diagnostic, not a contract,
    /// and nothing may branch on its shape.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl RpcError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code: code.as_i32(),
            message: message.into(),
            data: None,
        }
    }

    #[must_use]
    pub fn with_data(mut self, data: serde_json::Value) -> Self {
        self.data = Some(data);
        self
    }

    /// The code as this build understands it, or `None` if it postdates it.
    pub fn kind(&self) -> Option<ErrorCode> {
        ErrorCode::from_i32(self.code)
    }

    /// The stable, script-facing slug. Unrecognised codes map to
    /// [`UNKNOWN_ERROR_SLUG`] rather than failing.
    pub fn stable_slug(&self) -> &'static str {
        self.kind()
            .map_or(UNKNOWN_ERROR_SLUG, ErrorCode::stable_slug)
    }

    /// Whether a client may retry the same call unchanged.
    ///
    /// [`ErrorCode::Refused`] and [`ErrorCode::Unprovable`] are never retryable,
    /// mirroring `shepherd_core::CoreError::is_retryable`. §4.10 requires the
    /// destroy path to fail closed; retrying a fail-closed decision is how a
    /// fail-closed system becomes a fail-open one.
    ///
    /// An **unrecognised** code is not retryable. Retrying an unknown failure is
    /// the one guess that can turn a refusal into a loop against the destroy
    /// path, so the unknown case takes the conservative branch.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self.kind(),
            Some(ErrorCode::Busy | ErrorCode::Io | ErrorCode::TargetUnreachable)
        )
    }
}

/// Transport-level error codes this build knows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum ErrorCode {
    // --- JSON-RPC 2.0 reserved band ----------------------------------------
    /// Malformed JSON. The frame could not be parsed at all.
    ParseError,
    /// Well-formed JSON that is not a valid JSON-RPC 2.0 request.
    InvalidRequest,
    /// `method` names nothing in the registry — or names a method whose
    /// `since_minor` is above the connection's negotiated minor, which from the
    /// caller's point of view is the same condition.
    MethodNotFound,
    /// `params` did not deserialize into the method's request type.
    InvalidParams,
    /// An unhandled fault inside the daemon. Always a bug.
    InternalError,

    // --- Shepherd application band -----------------------------------------
    /// The method is registered but this build does not serve it yet.
    ///
    /// This exists because the method table is intentionally ahead of the
    /// implementation: `tier.*` and `restore` are declared at Phase 1 and served
    /// at Phase 2. Without a distinct code, an unimplemented method would be
    /// indistinguishable from a typo (`MethodNotFound`) or a crash
    /// (`InternalError`).
    MethodNotImplemented,
    /// The handshake was rejected. `data` carries [`crate::VersionMismatch`].
    VersionMismatch,
    /// A required entity does not exist.
    NotFound,
    /// The request was well-formed but violates an invariant of its own values.
    Invalid,
    /// Legal but refused by policy: a safety floor, a deny-list entry, a user
    /// ignore rule, a disabled capability, `resync_required` on the root.
    Refused,
    /// Identity could not be proven, so the daemon did **not** proceed (§4.10).
    Unprovable,
    /// A precondition of a multi-step operation no longer holds — the classic
    /// case being a rule enabled after its dry-run preview went stale (AC-14).
    Precondition,
    /// The daemon is at capacity or the resource is locked. Retryable.
    Busy,
    /// A local I/O failure. Retryable.
    Io,
    /// A configured storage target could not be reached. Retryable.
    TargetUnreachable,
    /// The subscription's resume cursor has fallen out of the daemon's bounded
    /// event buffer. The client must take a snapshot; see
    /// [`crate::event::ResumeOutcome`].
    EventCursorLost,
}

impl ErrorCode {
    /// Every code, newest last. Also the emission order for
    /// `schemas/error-codes.json`.
    pub const ALL: &'static [ErrorCode] = &[
        ErrorCode::ParseError,
        ErrorCode::InvalidRequest,
        ErrorCode::MethodNotFound,
        ErrorCode::InvalidParams,
        ErrorCode::InternalError,
        ErrorCode::MethodNotImplemented,
        ErrorCode::VersionMismatch,
        ErrorCode::NotFound,
        ErrorCode::Invalid,
        ErrorCode::Refused,
        ErrorCode::Unprovable,
        ErrorCode::Precondition,
        ErrorCode::Busy,
        ErrorCode::Io,
        ErrorCode::TargetUnreachable,
        ErrorCode::EventCursorLost,
    ];

    /// The wire value. Permanent: a code is never renumbered or reused.
    pub const fn as_i32(self) -> i32 {
        match self {
            ErrorCode::ParseError => -32700,
            ErrorCode::InvalidRequest => -32600,
            ErrorCode::MethodNotFound => -32601,
            ErrorCode::InvalidParams => -32602,
            ErrorCode::InternalError => -32603,
            ErrorCode::MethodNotImplemented => 1001,
            ErrorCode::VersionMismatch => 1002,
            ErrorCode::NotFound => 1003,
            ErrorCode::Invalid => 1004,
            ErrorCode::Refused => 1005,
            ErrorCode::Unprovable => 1006,
            ErrorCode::Precondition => 1007,
            ErrorCode::Busy => 1008,
            ErrorCode::Io => 1009,
            ErrorCode::TargetUnreachable => 1010,
            ErrorCode::EventCursorLost => 1011,
        }
    }

    pub fn from_i32(v: i32) -> Option<Self> {
        ErrorCode::ALL.iter().copied().find(|c| c.as_i32() == v)
    }

    /// The stable, script-facing slug for this code.
    ///
    /// **This mapping is the AC-56 contract.** A slug may never change its
    /// meaning and may never be removed while any code maps to it. Several
    /// transport codes may share one slug — that is the compression that lets
    /// the numeric band be subdivided later without a CLI-visible change.
    pub const fn stable_slug(self) -> &'static str {
        match self {
            // Both framing faults present identically to a script: the request
            // never reached a handler. Publishing the distinction would offer a
            // difference the CLI cannot act on.
            ErrorCode::ParseError | ErrorCode::InvalidRequest => "protocol_error",
            ErrorCode::MethodNotFound => "unknown_command",
            ErrorCode::InvalidParams | ErrorCode::Invalid => "invalid_argument",
            ErrorCode::InternalError => "internal_error",
            ErrorCode::MethodNotImplemented => "not_implemented",
            ErrorCode::VersionMismatch => "version_mismatch",
            ErrorCode::NotFound => "not_found",
            ErrorCode::Refused => "refused",
            ErrorCode::Unprovable => "unprovable",
            ErrorCode::Precondition => "precondition_failed",
            ErrorCode::Busy => "busy",
            ErrorCode::Io => "io_error",
            ErrorCode::TargetUnreachable => "target_unreachable",
            ErrorCode::EventCursorLost => "event_cursor_lost",
        }
    }

    /// One-line description, emitted into `schemas/error-codes.json` so the
    /// committed artifact documents the taxonomy rather than just listing it.
    pub const fn summary(self) -> &'static str {
        match self {
            ErrorCode::ParseError => "the frame was not valid JSON",
            ErrorCode::InvalidRequest => "valid JSON, but not a JSON-RPC 2.0 request",
            ErrorCode::MethodNotFound => "no such method at the negotiated protocol minor",
            ErrorCode::InvalidParams => "params did not match the method's request schema",
            ErrorCode::InternalError => "unhandled daemon fault; always a bug",
            ErrorCode::MethodNotImplemented => "registered method, not served by this build",
            ErrorCode::VersionMismatch => "handshake rejected on protocol major version",
            ErrorCode::NotFound => "the named entity does not exist",
            ErrorCode::Invalid => "the request violates an invariant of its own values",
            ErrorCode::Refused => "legal but refused by policy or a safety floor",
            ErrorCode::Unprovable => "identity could not be proven; failed closed (§4.10)",
            ErrorCode::Precondition => "a precondition of a multi-step operation no longer holds",
            ErrorCode::Busy => "at capacity or locked by another caller",
            ErrorCode::Io => "local I/O failure",
            ErrorCode::TargetUnreachable => "a configured storage target could not be reached",
            ErrorCode::EventCursorLost => "resume cursor evicted from the bounded event buffer",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn codes_are_unique() {
        let seen: BTreeSet<i32> = ErrorCode::ALL.iter().map(|c| c.as_i32()).collect();
        assert_eq!(
            seen.len(),
            ErrorCode::ALL.len(),
            "two ErrorCode variants share a numeric value"
        );
    }

    #[test]
    fn all_is_exhaustive() {
        // A variant added without extending ALL would make `from_i32` and the
        // committed error-code artifact silently incomplete. `stable_slug` is an
        // exhaustive match, so the compiler catches the variant; this catches
        // the list.
        for c in ErrorCode::ALL {
            assert_eq!(ErrorCode::from_i32(c.as_i32()), Some(*c));
        }
        assert_eq!(ErrorCode::ALL.len(), 16);
    }

    #[test]
    fn every_code_has_a_script_matchable_slug() {
        for c in ErrorCode::ALL {
            let s = c.stable_slug();
            assert!(!s.is_empty(), "{c:?}");
            assert!(
                s.chars().all(|ch| ch.is_ascii_lowercase() || ch == '_'),
                "slug `{s}` must be lower_snake so scripts can match it literally"
            );
            assert!(!c.summary().is_empty(), "{c:?}");
        }
    }

    #[test]
    fn fail_closed_codes_are_never_retryable() {
        for c in [ErrorCode::Unprovable, ErrorCode::Refused] {
            assert!(!RpcError::new(c, "x").is_retryable(), "{c:?}");
        }
        assert!(RpcError::new(ErrorCode::Io, "x").is_retryable());
    }

    #[test]
    fn code_is_the_bare_integer_and_absent_data_is_not_emitted() {
        let e = RpcError::new(ErrorCode::MethodNotFound, "nope");
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["code"], serde_json::json!(-32601));
        assert!(j.get("data").is_none());
        assert_eq!(serde_json::from_value::<RpcError>(j).unwrap(), e);
    }

    #[test]
    fn a_code_from_a_newer_daemon_parses_and_degrades() {
        // The additive case: this build has never heard of 1099. It must still
        // surface the daemon's message rather than reporting a protocol fault.
        let e: RpcError = serde_json::from_str(r#"{"code":1099,"message":"quota exceeded"}"#)
            .expect("an unknown code must not break parsing");
        assert_eq!(e.kind(), None);
        assert_eq!(e.stable_slug(), UNKNOWN_ERROR_SLUG);
        assert_eq!(e.to_string(), "[1099] quota exceeded");
        assert!(
            !e.is_retryable(),
            "an unrecognised failure must take the conservative branch"
        );
    }

    #[test]
    fn error_frames_ignore_unknown_fields() {
        let e: RpcError =
            serde_json::from_str(r#"{"code":1003,"message":"m","invented_later":1}"#).unwrap();
        assert_eq!(e.kind(), Some(ErrorCode::NotFound));
    }
}
