//! The stable CLI result envelope (AC-56).
//!
//! # This file exists to keep two contracts apart
//!
//! Iteration 1 of the plan said the CLI's `--json` output *is* the IPC response
//! verbatim. §4.3 corrects it, and the correction is worth restating because it
//! is easy to re-introduce by accident:
//!
//! > it means any JSON-RPC framing change is a breaking CLI change, and AC-56
//! > promises *stable machine-readable output*.
//!
//! Two contracts, one artifact:
//!
//! | | [`CliEnvelope`] | [`crate::request::RpcRequest`] / [`crate::response::RpcResponse`] |
//! |---|---|---|
//! | audience | user scripts | the daemon and its clients |
//! | stability | additive-only, forever | additive within a major; may re-frame |
//! | version | [`CLI_SCHEMA_VERSION`], bumped on its own | [`crate::PROTO_VERSION`] |
//! | error id | stable string slug | JSON-RPC numeric code |
//! | carries | `data`, `error`, `warnings` | `jsonrpc`, `id`, `method`, `params` |
//!
//! The envelope has **no** `id`, no `jsonrpc` and no numeric code. That absence
//! is the mechanism: a script cannot come to depend on a transport field it
//! never sees. `data` is the method's result payload and nothing else, so the
//! per-method JSON Schemas in `schemas/method/` describe exactly what a script
//! finds there.
//!
//! Separating them costs one extra serialization per CLI invocation — once, on
//! a value already in memory, in a process that is about to exit. §4.3 traded
//! that for the ability to change the wire frame without breaking `jq`.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::RpcError;

/// The version of the envelope itself.
///
/// Independent of [`crate::PROTO_VERSION`] on purpose — that is the whole
/// point. It is bumped only by a change to the envelope's own shape, which is
/// permitted to be additive only. It has never been bumped.
pub const CLI_SCHEMA_VERSION: u32 = 1;

/// What every `shepctl <command> --json` invocation prints, exactly once, on
/// stdout.
///
/// Success and failure use the same shape so a script parses one thing:
/// `.ok` is the branch, and `.error` is populated iff `ok` is `false`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct CliEnvelope {
    /// [`CLI_SCHEMA_VERSION`]. Present on every envelope including failures, so
    /// a script can branch on it before it branches on anything else.
    pub schema_version: u32,
    pub ok: bool,
    /// The method's result payload. `null` on failure.
    ///
    /// Not `skip_serializing_if`: a script may read `.data` unconditionally, and
    /// an absent key and a `null` key are different things to `jq`.
    pub data: Option<serde_json::Value>,
    /// Populated iff `ok` is `false`.
    pub error: Option<CliError>,
    /// Non-fatal notices. Always present, possibly empty — again so `jq` can
    /// iterate it without a guard.
    pub warnings: Vec<String>,
}

impl CliEnvelope {
    pub fn ok(data: serde_json::Value) -> Self {
        Self {
            schema_version: CLI_SCHEMA_VERSION,
            ok: true,
            data: Some(data),
            error: None,
            warnings: Vec::new(),
        }
    }

    pub fn failed(error: CliError) -> Self {
        Self {
            schema_version: CLI_SCHEMA_VERSION,
            ok: false,
            data: None,
            error: Some(error),
            warnings: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_warnings(mut self, warnings: Vec<String>) -> Self {
        self.warnings = warnings;
        self
    }
}

/// The script-facing error.
///
/// `code` is [`crate::ErrorCode::stable_slug`], never the numeric JSON-RPC code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct CliError {
    /// A stable `lower_snake` slug. Match on this.
    pub code: String,
    pub message: String,
    /// What the user can do about it.
    ///
    /// AC-61 requires the daemon-down error to name the socket path, the service
    /// registration state and the platform start command rather than a bare
    /// "connection refused". This is where that text goes.
    pub hint: Option<String>,
}

impl CliError {
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            hint: None,
        }
    }

    #[must_use]
    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

impl From<&RpcError> for CliError {
    /// The one-way bridge: transport error → stable CLI error.
    ///
    /// `data` is deliberately dropped. It is diagnostic and free-form, and
    /// copying it into the stable envelope would publish a shape the CLI has
    /// not promised to keep — the exact coupling this module exists to prevent.
    fn from(e: &RpcError) -> Self {
        CliError::new(e.stable_slug(), e.message.clone())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::{ErrorCode, UNKNOWN_ERROR_SLUG};

    #[test]
    fn success_envelope_shape_is_what_a_script_expects() {
        let e = CliEnvelope::ok(serde_json::json!({"root_id": 3}));
        let j = serde_json::to_value(&e).unwrap();
        assert_eq!(j["schema_version"], serde_json::json!(1));
        assert_eq!(j["ok"], serde_json::json!(true));
        assert_eq!(j["data"]["root_id"], serde_json::json!(3));
        assert_eq!(j["error"], serde_json::Value::Null);
        assert_eq!(j["warnings"], serde_json::json!([]));
    }

    #[test]
    fn failure_envelope_keeps_the_same_keys() {
        // One shape for both branches: `jq '.data.x'` on a failure yields null,
        // not a missing-key error.
        let ok = serde_json::to_value(CliEnvelope::ok(serde_json::json!({}))).unwrap();
        let bad = serde_json::to_value(CliEnvelope::failed(CliError::new(
            "not_found",
            "no such root",
        )))
        .unwrap();
        let keys = |v: &serde_json::Value| {
            v.as_object()
                .unwrap()
                .keys()
                .cloned()
                .collect::<Vec<String>>()
        };
        assert_eq!(keys(&ok), keys(&bad));
        assert_eq!(bad["ok"], serde_json::json!(false));
        assert_eq!(bad["error"]["code"], serde_json::json!("not_found"));
    }

    #[test]
    fn the_envelope_carries_no_transport_fields() {
        // The mechanism, asserted rather than described: a script cannot come
        // to depend on a JSON-RPC field it never sees.
        let j = serde_json::to_value(CliEnvelope::ok(serde_json::json!({"a": 1}))).unwrap();
        let obj = j.as_object().unwrap();
        for forbidden in ["jsonrpc", "id", "result", "method", "params"] {
            assert!(
                !obj.contains_key(forbidden),
                "`{forbidden}` is JSON-RPC framing and must never reach the CLI envelope"
            );
        }
        let err = serde_json::to_value(CliError::from(&RpcError::new(
            ErrorCode::NotFound,
            "no such root",
        )))
        .unwrap();
        assert!(
            err.as_object().unwrap().get("code").unwrap().is_string(),
            "the CLI error code must be the stable slug, never the numeric code"
        );
    }

    #[test]
    fn rpc_errors_map_to_slugs_and_drop_diagnostic_data() {
        let rpc = RpcError::new(ErrorCode::Unprovable, "remote version is gone")
            .with_data(serde_json::json!({"internal": "shape"}));
        let cli = CliError::from(&rpc);
        assert_eq!(cli.code, "unprovable");
        assert_eq!(cli.message, "remote version is gone");
        let j = serde_json::to_value(&cli).unwrap();
        assert!(j.get("data").is_none());
    }

    #[test]
    fn a_transport_code_this_build_does_not_know_still_yields_a_usable_envelope() {
        let rpc: RpcError =
            serde_json::from_str(r#"{"code":1099,"message":"quota exceeded"}"#).unwrap();
        let env = CliEnvelope::failed(CliError::from(&rpc));
        assert_eq!(env.error.as_ref().unwrap().code, UNKNOWN_ERROR_SLUG);
        assert_eq!(env.error.unwrap().message, "quota exceeded");
    }

    #[test]
    fn envelope_ignores_unknown_fields_when_read_back() {
        // A script's own round-trip, and a newer shepctl writing a field this
        // build has not learned yet. Additive-only means both must parse.
        let e: CliEnvelope = serde_json::from_str(
            r#"{"schema_version":1,"ok":true,"data":{"x":1},"error":null,
                "warnings":[],"elapsed_ms":12}"#,
        )
        .unwrap();
        assert!(e.ok);
        assert_eq!(e.data.unwrap()["x"], serde_json::json!(1));
    }
}
