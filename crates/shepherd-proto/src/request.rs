//! JSON-RPC request framing and the per-method request payloads.
//!
//! # Wire types are not domain types
//!
//! Nothing here mentions `shepherd_core::FileId`, `RootId` or `Blake3Hash`.
//! §4.1 rule 1 forbids the dependency, and the prohibition is load-bearing: if a
//! request field were typed as a domain newtype, renaming or retyping that
//! newtype during a refactor would silently change the wire format, and the
//! only place it would surface is a `codegen --check` diff someone might read as
//! noise. Ids cross the wire as `i64`, hashes as lowercase hex `String`,
//! timestamps as nanoseconds-since-epoch `i64`. The daemon converts at its
//! boundary.
//!
//! # Every field here obeys the additive rules
//!
//! No type in this module carries `deny_unknown_fields`, and every optional or
//! defaultable field carries `#[serde(default)]`. Both are required by
//! [`crate::COMPATIBILITY_POLICY`] and both are asserted by tests at the bottom
//! of this file — a `deny_unknown_fields` added later would make an older daemon
//! reject a newer client's request outright.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::event::{EventStream, Seq};

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 framing
// ---------------------------------------------------------------------------

/// The `"2.0"` literal, as a type.
///
/// A `String` field would let a peer send `"1.0"` and have it parse. This
/// rejects anything else at deserialization, which is where
/// [`crate::ErrorCode::InvalidRequest`] belongs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, JsonSchema)]
pub struct JsonRpcV2;

impl Serialize for JsonRpcV2 {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str("2.0")
    }
}

impl<'de> Deserialize<'de> for JsonRpcV2 {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let v = String::deserialize(d)?;
        if v == "2.0" {
            Ok(JsonRpcV2)
        } else {
            Err(serde::de::Error::custom(format!(
                "expected jsonrpc \"2.0\", got {v:?}"
            )))
        }
    }
}

/// A JSON-RPC request id. The spec permits a string or a number; both are
/// accepted so a client may use whichever its language makes natural.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    Text(String),
}

impl From<i64> for RequestId {
    fn from(v: i64) -> Self {
        RequestId::Number(v)
    }
}

/// One request frame. Newline-delimited on the socket (§4.3).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RpcRequest {
    pub jsonrpc: JsonRpcV2,
    pub id: RequestId,
    /// The registered method name, e.g. `"root.add"`.
    pub method: String,
    /// The method's request payload, always a JSON object.
    pub params: serde_json::Value,
}

impl RpcRequest {
    pub fn new(
        id: impl Into<RequestId>,
        method: impl Into<String>,
        params: serde_json::Value,
    ) -> Self {
        Self {
            jsonrpc: JsonRpcV2,
            id: id.into(),
            method: method.into(),
            params,
        }
    }
}

// ---------------------------------------------------------------------------
// Shared wire enums
// ---------------------------------------------------------------------------

/// Proto-local mirror of the per-root stub mode.
///
/// A mirror rather than a re-export, because `shepherd_core::StubMode` is a
/// domain type this crate may not depend on. The serde representations must
/// agree, and `shepherd-cli` is where the two are compared — it is the only
/// crate that legitimately depends on both.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum StubMode {
    Dehydrate,
    Delete,
}

/// How a search should be executed.
///
/// `Hybrid` and `Semantic` are declared at Phase 1 and served at Phase 5. A
/// Phase 1 daemon answers them with [`crate::ErrorCode::MethodNotImplemented`]
/// or degrades to `Metadata` and says so in
/// [`crate::response::SearchResult::degraded`]. Declaring them now is the
/// additive-evolution design point: the *enum* grows without a major bump only
/// if the values that already exist keep their meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum SearchMode {
    /// Catalog metadata only. The only mode a Phase 1 daemon serves.
    #[default]
    Metadata,
    /// Vector similarity over embeddings (Phase 5).
    Semantic,
    /// Reciprocal-rank fusion of both (Phase 5).
    Hybrid,
}

/// A file's local materialization state, as the catalog records it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum FileState {
    Local,
    Stub,
    Remote,
    Missing,
}

/// Narrowing predicates for [`SearchRequest`].
///
/// A nested object rather than fifteen flattened fields: it is passed unchanged
/// to `shepherd-rules`' matcher shape, and flattening would make every future
/// predicate a top-level CLI flag. `shepctl` renders it as a single
/// `--filters <JSON>` argument, which is the documented handling for any
/// non-scalar request field.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct SearchFilters {
    /// Extensions without the dot, e.g. `["pdf", "docx"]`.
    #[serde(default)]
    pub ext: Vec<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub path_glob: Option<String>,
    #[serde(default)]
    pub min_size: Option<u64>,
    #[serde(default)]
    pub max_size: Option<u64>,
    /// Nanoseconds since the Unix epoch.
    #[serde(default)]
    pub modified_after: Option<i64>,
    #[serde(default)]
    pub modified_before: Option<i64>,
    #[serde(default)]
    pub state: Option<FileState>,
    #[serde(default)]
    pub root_id: Option<i64>,
}

// ---------------------------------------------------------------------------
// Per-method request payloads
// ---------------------------------------------------------------------------

/// `root.add` — register a scan root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootAddRequest {
    /// Absolute path. Sent as the platform writes it; the daemon probes the
    /// root's case and normalization policy (§4.9) rather than guessing here.
    pub path: String,
    /// What happens to a file's bytes locally once it is durably remote.
    pub stub_mode: StubMode,
    /// Whether files under this root may be sent to a hosted inference provider.
    /// Defaults to `false`: consent is opt-in per root.
    #[serde(default)]
    pub hosted_optin: bool,
    /// `.gitignore`-syntax patterns excluding paths under this root from scan
    /// **and** tier (AC-9). Later patterns win, as in `.gitignore`.
    ///
    /// Added at proto 1.2, and it is the field AC-9's `**User**` was always
    /// about: `scan_root.ignore_patterns_json` has existed since schema 0001
    /// and `shepherd-scan::IgnoreSet` has honoured whatever it was handed, but
    /// until this field there was no way for a client to hand it anything, so
    /// every scan ran against `'[]'`.
    ///
    /// Empty is the pre-1.2 behaviour exactly, which is why this is a `Vec`
    /// defaulting to empty rather than an `Option`: "the client did not say"
    /// and "the client said nothing is ignored" must produce the same scan.
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
}

/// `root.list`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct RootListRequest {
    /// Include roots that are registered but currently disabled.
    #[serde(default)]
    pub include_disabled: bool,
}

/// `root.remove` — deregister a scan root.
///
/// Never touches file bytes. `forget_catalog` drops the *rows*, and dropping
/// rows for a root that holds `Custody`-class files destroys the only address of
/// data that no longer exists locally — so the daemon refuses with
/// [`crate::ErrorCode::Refused`] unless `force` is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootRemoveRequest {
    /// The root to deregister.
    pub root_id: i64,
    /// Also drop the root's catalog rows. File bytes are never touched.
    #[serde(default)]
    pub forget_catalog: bool,
    /// Proceed even when dropping rows would discard `Custody`-class records —
    /// the only address of bytes that no longer exist locally.
    #[serde(default)]
    pub force: bool,
}

/// `scan.start`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ScanStartRequest {
    /// The root to scan. Omit to scan every enabled root.
    #[serde(default)]
    pub root_id: Option<i64>,
    /// Ignore the change-journal cursor and re-walk from scratch.
    #[serde(default)]
    pub full: bool,
}

/// `scan.status`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct ScanStatusRequest {
    /// The root to report on. Omit for every root.
    #[serde(default)]
    pub root_id: Option<i64>,
}

/// `search`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SearchRequest {
    /// The query text. Matched against name and path in `metadata` mode.
    pub query: String,
    /// Narrowing predicates, as a JSON object.
    #[serde(default)]
    pub filters: SearchFilters,
    /// How to execute the search. Only `metadata` is served before Phase 5.
    #[serde(default)]
    pub mode: SearchMode,
    /// Maximum hits to return.
    #[serde(default = "default_search_limit")]
    pub limit: u32,
    /// Hits to skip, for paging.
    #[serde(default)]
    pub offset: u32,
}

fn default_search_limit() -> u32 {
    50
}

/// `status`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct StatusRequest {}

/// `target.add`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TargetAddRequest {
    /// A unique name for this target.
    pub name: String,
    /// Adapter id, e.g. `"s3"`. Adapters are registered by `shepherd-storage`;
    /// this crate deliberately does not enumerate them, so adding one in a later
    /// phase is not a proto change.
    pub adapter: String,
    /// Adapter-specific configuration. Opaque here and validated by the adapter.
    #[serde(default)]
    pub config: serde_json::Value,
    /// A handle into the OS keychain, never a secret. §4.1 keeps credential
    /// material out of the IPC surface entirely.
    #[serde(default)]
    pub credentials_ref: Option<String>,
}

/// `target.list`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct TargetListRequest {}

/// `target.test` — a reachability and permissions probe. Writes and removes one
/// object under the `_shepherd/` control prefix; never touches user data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TargetTestRequest {
    /// The target to probe.
    pub target_id: i64,
}

/// `rule.list`.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct RuleListRequest {
    /// Include rules that exist but are not enabled.
    #[serde(default)]
    pub include_disabled: bool,
}

/// `rule.preview` — the mandatory dry run (AC-14).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RulePreviewRequest {
    /// The rule to dry-run.
    pub rule_id: i64,
    /// How many matched rows to return as a sample. The counts are exact
    /// regardless.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `tier.plan` — compute a candidate set. Read-only; moves nothing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TierPlanRequest {
    /// The rule that selects candidates.
    pub rule_id: i64,
    /// Where the candidates would be sent.
    pub target_id: i64,
    /// Cap the candidate set. The returned counts describe the capped set.
    #[serde(default)]
    pub limit: Option<u32>,
}

/// `tier.run` — execute a plan.
///
/// `candidate_set_hash` is not a convenience. §4.10's bulk breaker confirms
/// against the hash of the candidate set the *user saw*: if the set changed
/// between plan and run, the daemon must refuse rather than act on a set nobody
/// approved. Making the field required puts that confirmation in the type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TierRunRequest {
    /// The plan returned by `tier.plan`.
    pub plan_id: String,
    /// Lowercase hex BLAKE3 of the candidate set, as returned by `tier.plan`.
    pub candidate_set_hash: String,
}

/// `restore` — bring bytes back from a target.
///
/// Exactly one of `file_id` or `path` must be set; the daemon answers
/// [`crate::ErrorCode::Invalid`] otherwise. Expressing "exactly one of" in JSON
/// Schema is possible but unreadable, and a `oneOf` in the committed artifact
/// would be harder to review than the daemon-side check it replaces.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct RestoreRequest {
    /// The catalog id of the file to restore. Mutually exclusive with `path`.
    #[serde(default)]
    pub file_id: Option<i64>,
    /// The path of the file to restore. Mutually exclusive with `file_id`.
    #[serde(default)]
    pub path: Option<String>,
    /// Where to write. `None` restores in place, which is the AC-5 fidelity
    /// case: bytes, mtime and mode must all match the original.
    #[serde(default)]
    pub destination: Option<String>,
    /// Without this, restore uses an exclusive create and fails if anything is
    /// already at the destination (§4.10).
    #[serde(default)]
    pub overwrite: bool,
}

/// `doctor` — run the daemon's self-checks.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct DoctorRequest {}

/// `events.subscribe` — see [`crate::event`] for the resume and overflow
/// contract.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize, JsonSchema)]
pub struct SubscribeRequest {
    /// Empty subscribes to every stream. Naming streams explicitly is how a
    /// client avoids paying for traffic it discards.
    #[serde(default)]
    pub streams: Vec<EventStream>,
    /// Resume after this sequence number. `None` starts from the next event
    /// produced.
    #[serde(default)]
    pub resume_from: Option<Seq>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jsonrpc_version_is_pinned_to_2_0() {
        let f = RpcRequest::new(1, "status", serde_json::json!({}));
        let j = serde_json::to_value(&f).unwrap();
        assert_eq!(j["jsonrpc"], serde_json::json!("2.0"));
        assert!(
            serde_json::from_str::<RpcRequest>(
                r#"{"jsonrpc":"1.0","id":1,"method":"status","params":{}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn request_ids_may_be_numbers_or_strings() {
        let n: RpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":7,"method":"status","params":{}}"#)
                .unwrap();
        assert_eq!(n.id, RequestId::Number(7));
        let s: RpcRequest =
            serde_json::from_str(r#"{"jsonrpc":"2.0","id":"a7","method":"status","params":{}}"#)
                .unwrap();
        assert_eq!(s.id, RequestId::Text("a7".into()));
    }

    #[test]
    fn optional_request_fields_may_be_omitted_entirely() {
        // The additive rule in practice: a client written against 1.0 omits
        // every field 1.1 added, and the request still parses.
        let r: RootAddRequest =
            serde_json::from_str(r#"{"path":"/srv/data","stub_mode":"delete"}"#).unwrap();
        assert!(!r.hosted_optin);
        assert!(
            r.ignore_patterns.is_empty(),
            "1.2's field, omitted by a 1.1 client"
        );

        let s: SearchRequest = serde_json::from_str(r#"{"query":"report"}"#).unwrap();
        assert_eq!(s.limit, 50, "defaulted, not zero");
        assert_eq!(s.mode, SearchMode::Metadata);
        assert_eq!(s.filters, SearchFilters::default());
    }

    /// The paired half of the assertion above.
    ///
    /// `ignore_patterns` defaulting to empty is indistinguishable from the
    /// field not existing at all — which is exactly the state AC-9 was in
    /// before 1.2, and exactly why an "it defaults to empty" test alone proves
    /// nothing. Supplying a list and reading it back **in order** is what
    /// separates "the field is wired" from "the field is declared".
    #[test]
    fn supplied_ignore_patterns_survive_the_wire_in_order() {
        let r: RootAddRequest = serde_json::from_str(
            r#"{"path":"/srv/data","stub_mode":"delete",
                "ignore_patterns":["*.tmp","!keep.tmp","build/"]}"#,
        )
        .unwrap();
        // Order is semantic, not cosmetic: `.gitignore` is last-match-wins, so
        // a list that round-trips as a set would silently invert a negation.
        assert_eq!(r.ignore_patterns, ["*.tmp", "!keep.tmp", "build/"]);

        let back: RootAddRequest =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn no_request_type_denies_unknown_fields() {
        // Asserted by construction on a representative of each shape: a newer
        // client's extra field must be ignored, not rejected. `deny_unknown_fields`
        // anywhere in this module would fail here.
        let a: RootAddRequest = serde_json::from_str(
            r#"{"path":"/x","stub_mode":"delete","hosted_optin":false,"added_in_1_4":"?"}"#,
        )
        .unwrap();
        assert_eq!(a.path, "/x");

        let f: SearchFilters =
            serde_json::from_str(r#"{"ext":["pdf"],"predicate_from_the_future":true}"#).unwrap();
        assert_eq!(f.ext, vec!["pdf".to_string()]);

        let t: TierRunRequest =
            serde_json::from_str(r#"{"plan_id":"p1","candidate_set_hash":"ab","extra":null}"#)
                .unwrap();
        assert_eq!(t.plan_id, "p1");
    }

    #[test]
    fn stub_mode_wire_form_matches_the_domain_enum() {
        // shepherd-core serializes StubMode as snake_case. This crate may not
        // depend on it (§4.1 rule 1), so this pins the wire side and
        // `shepherd-cli` holds the cross-crate comparison.
        assert_eq!(
            serde_json::to_string(&StubMode::Dehydrate).unwrap(),
            "\"dehydrate\""
        );
        assert_eq!(
            serde_json::to_string(&StubMode::Delete).unwrap(),
            "\"delete\""
        );
    }

    #[test]
    fn search_mode_defaults_to_the_only_mode_phase_1_serves() {
        assert_eq!(SearchMode::default(), SearchMode::Metadata);
    }
}
