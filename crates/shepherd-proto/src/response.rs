//! JSON-RPC response framing and the per-method result payloads.
//!
//! The same wire-types-are-not-domain-types rule as [`crate::request`] applies:
//! ids are `i64`, hashes are lowercase hex `String`, timestamps are nanoseconds
//! since the Unix epoch.
//!
//! # `RpcResponse` is not what `shepctl --json` prints
//!
//! A result payload here becomes the `data` member of a
//! [`crate::envelope::CliEnvelope`]. The frame around it — `jsonrpc`, `id`,
//! `result`/`error` — never reaches a script. See [`crate::envelope`] for why.

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use crate::error::RpcError;
use crate::event::EventFrame;
use crate::request::{FileState, JsonRpcV2, RequestId, StubMode};

// ---------------------------------------------------------------------------
// JSON-RPC 2.0 framing
// ---------------------------------------------------------------------------

/// One response frame. Newline-delimited on the socket (§4.3).
///
/// Exactly one of `result` and `error` is present, per JSON-RPC 2.0. That is a
/// spec invariant rather than a type invariant here, because a peer may violate
/// it and the parse must survive long enough to report which peer did.
/// [`RpcResponse::outcome`] is the checked accessor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RpcResponse {
    pub jsonrpc: JsonRpcV2,
    /// `None` only when the request could not be parsed well enough to recover
    /// its id, which JSON-RPC 2.0 renders as `null`.
    pub id: Option<RequestId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl RpcResponse {
    pub fn ok(id: RequestId, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: JsonRpcV2,
            id: Some(id),
            result: Some(result),
            error: None,
        }
    }

    pub fn failed(id: Option<RequestId>, error: RpcError) -> Self {
        Self {
            jsonrpc: JsonRpcV2,
            id,
            result: None,
            error: Some(error),
        }
    }

    /// The frame's outcome, or `Err(RpcError)` describing a malformed frame.
    pub fn outcome(self) -> Result<serde_json::Value, RpcError> {
        match (self.result, self.error) {
            (Some(_), Some(e)) => Err(RpcError::new(
                crate::ErrorCode::InvalidRequest,
                format!(
                    "peer sent a frame carrying both `result` and `error`; \
                     the error was: {}",
                    e.message
                ),
            )),
            (Some(r), None) => Ok(r),
            (None, Some(e)) => Err(e),
            (None, None) => Err(RpcError::new(
                crate::ErrorCode::InvalidRequest,
                "peer sent a frame carrying neither `result` nor `error`",
            )),
        }
    }
}

/// A server-initiated notification: an event, with no id and no reply.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RpcNotification {
    pub jsonrpc: JsonRpcV2,
    /// Always [`EVENT_NOTIFICATION_METHOD`].
    pub method: String,
    pub params: EventFrame,
}

/// The method name every event notification carries.
///
/// A single name with the stream inside the payload, rather than one method per
/// stream: a client dispatches on `params.stream` after one parse, and adding a
/// stream does not add a method a client must learn to ignore.
pub const EVENT_NOTIFICATION_METHOD: &str = "event";

impl RpcNotification {
    pub fn new(frame: EventFrame) -> Self {
        Self {
            jsonrpc: JsonRpcV2,
            method: EVENT_NOTIFICATION_METHOD.to_string(),
            params: frame,
        }
    }
}

/// The last frame a dropped subscriber receives, before the socket closes.
///
/// The daemon closes a connection whose subscriber fell behind its queue,
/// deliberately, so that EOF means "frames were lost". But EOF also means "the
/// daemon is shutting down", and a client cannot tell those apart from the
/// socket alone — so `shepctl events subscribe` reported a stream that had
/// dropped frames as a clean exit, which is the one outcome a monitoring script
/// cannot detect.
///
/// A notification rather than an error response: there is no request to answer,
/// and a client that does not know this method ignores it exactly as it ignores
/// any other unknown notification, which is the additive-evolution rule.
pub const SUBSCRIPTION_DROPPED_METHOD: &str = "subscription.dropped";

/// The payload of a [`SUBSCRIPTION_DROPPED_METHOD`] notification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SubscriptionDropped {
    pub subscription_id: u64,
    /// Why the subscription ended. `queue_overflow` today; a value a client
    /// does not recognise still means "this subscription ended and events were
    /// missed".
    pub reason: String,
    /// How many frames the subscriber's queue holds, so the message can say
    /// what was fallen behind.
    pub queue_capacity: u64,
}

/// A server-initiated notification that a subscription has been dropped.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DroppedNotification {
    pub jsonrpc: JsonRpcV2,
    /// Always [`SUBSCRIPTION_DROPPED_METHOD`].
    pub method: String,
    pub params: SubscriptionDropped,
}

impl DroppedNotification {
    pub fn queue_overflow(subscription_id: u64, queue_capacity: u64) -> Self {
        Self {
            jsonrpc: JsonRpcV2,
            method: SUBSCRIPTION_DROPPED_METHOD.to_string(),
            params: SubscriptionDropped {
                subscription_id,
                reason: "queue_overflow".into(),
                queue_capacity,
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Shared result fragments
// ---------------------------------------------------------------------------

/// How a root's paths compare (§4.9, probed at enrollment, never assumed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathCasePolicy {
    Sensitive,
    Insensitive,
}

/// How a root's paths are Unicode-normalized (§4.9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum PathNormPolicy {
    Nfc,
    Nfd,
    Preserve,
}

/// How much to trust this root's atime (§4.12).
///
/// Surfaced on the wire because it changes what a *user* should believe about a
/// rule that matches on last access: under `relatime` an atime can be a day
/// stale, and under `disabled` it is not an access signal at all.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum AtimeMode {
    Reliable,
    Relatime,
    Disabled,
    Unknown,
}

/// Whether a root is currently reachable (§4.9 PM-3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum RootAvailability {
    Available,
    Unavailable,
    Unmounted,
}

/// One registered scan root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootSummary {
    pub root_id: i64,
    pub path: String,
    pub enabled: bool,
    pub stub_mode: StubMode,
    pub hosted_optin: bool,
    pub availability: RootAvailability,
    /// When true, every tier, destroy and discard operation for this root is
    /// gated off until a resync completes (§4.9 PM-3). Surfaced because a user
    /// whose rules have silently stopped acting deserves to see why.
    pub resync_required: bool,
    pub path_case_policy: PathCasePolicy,
    pub path_norm_policy: PathNormPolicy,
    pub atime_mode: AtimeMode,
    /// The `.gitignore`-syntax exclusions **as stored**, not as sent.
    ///
    /// Echoed because the additive rule makes the write side silent in the one
    /// direction that matters: a 1.1 daemon ignores a 1.2 client's
    /// `root.add.ignore_patterns` rather than rejecting it, and the user's
    /// exclusions simply do not exist. Reading the stored list back is what
    /// turns that into something a client can detect.
    #[serde(default)]
    pub ignore_patterns: Vec<String>,
    pub file_count: u64,
    pub bytes_total: u64,
}

/// Progress of one root's scan.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScanState {
    pub root_id: i64,
    pub running: bool,
    pub files_seen: u64,
    pub bytes_seen: u64,
    #[serde(default)]
    pub started_at: Option<i64>,
    #[serde(default)]
    pub finished_at: Option<i64>,
    #[serde(default)]
    pub last_error: Option<String>,
}

/// One search hit.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SearchHit {
    pub file_id: i64,
    pub root_id: i64,
    pub rel_path: String,
    pub size: u64,
    pub mtime: i64,
    pub state: FileState,
    /// Lowercase hex BLAKE3, or `None` while the file is still unhashed —
    /// hashing is its own job class and never gates cataloguing (§6 Phase 1).
    #[serde(default)]
    pub blake3: Option<String>,
    #[serde(default)]
    pub tags: Vec<String>,
    /// Relevance, higher is better. Absent for a pure metadata query, where
    /// ordering is by the requested sort and a score would be invented.
    #[serde(default)]
    pub score: Option<f64>,
}

/// One configured storage target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TargetSummary {
    pub target_id: i64,
    pub name: String,
    pub adapter: String,
    pub enabled: bool,
    /// True for any WASM-plugin-backed target.
    pub is_third_party: bool,
    /// §4.4's CHECK-constrained invariant: `is_third_party` implies
    /// `!custody_eligible`. There is no API that can set both true. It is on the
    /// wire so a UI can *show* why a third-party target cannot hold the only
    /// copy of anything.
    pub custody_eligible: bool,
    #[serde(default)]
    pub last_health_at: Option<i64>,
    #[serde(default)]
    pub reachable: Option<bool>,
}

/// One rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RuleSummary {
    pub rule_id: i64,
    pub name: String,
    pub enabled: bool,
    pub action: String,
    /// Nanoseconds since the epoch, or `None` if the rule has never been
    /// previewed. AC-14 rejects enabling a rule in that state, so `None` here
    /// with `enabled: true` is a contradiction the daemon must never produce.
    #[serde(default)]
    pub last_preview_at: Option<i64>,
    #[serde(default)]
    pub last_preview_hash: Option<String>,
}

// ---------------------------------------------------------------------------
// Per-method result payloads
// ---------------------------------------------------------------------------

/// `root.add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootAddResult {
    pub root: RootSummary,
    /// Non-fatal notices raised while enrolling — an unreliable atime, a
    /// case-insensitive volume, a root nested under an existing one.
    #[serde(default)]
    pub warnings: Vec<String>,
}

/// `root.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootListResult {
    pub roots: Vec<RootSummary>,
}

/// `root.remove`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RootRemoveResult {
    pub root_id: i64,
    pub catalog_rows_dropped: u64,
    /// How many dropped rows were `Custody` class — the only address of bytes
    /// that no longer exist locally. Reported rather than merely counted,
    /// because it is the number that makes a `--force` regrettable.
    pub custody_rows_dropped: u64,
}

/// `scan.start`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScanStartResult {
    pub job_ids: Vec<i64>,
    pub roots_started: Vec<i64>,
    /// Roots whose scan job could not be enqueued, with the catalog's error.
    //
    // The line above is the wire contract and is kept to one sentence because
    // `JsonSchema` copies it verbatim into `schemas/method/scan.start.result.json`.
    // The record of what it used to say belongs here, where it is read by
    // whoever changes this file rather than by every client:
    //
    // It said "Roots skipped, with the reason — disabled, unmounted, already
    // scanning", and named none of the three correctly. `Session::scan_start`
    // pushes to this vector in exactly one place, the error arm of
    // `Queue::enqueue`, so the reason is always a `CatalogError` from a job
    // INSERT. The three it advertised each resolve somewhere else:
    //
    //   * disabled — never reaches the loop. The all-roots branch selects via
    //     `list_roots(.., include_disabled = false)`, so a disabled root is
    //     omitted silently rather than reported here; naming a root by id
    //     skips the `enabled` check altogether.
    //   * unmounted — enqueued, and reported in `roots_started`. PM-3's
    //     refusal is at job-run time in `scan_exec`, deliberately: an
    //     availability read at request time is stale before the walk starts.
    //   * already scanning — not detected at all. Nothing de-duplicates a
    //     concurrent scan of one root.
    //
    // Narrowed rather than implemented: each of those is a behaviour change,
    // and one of them would duplicate a safety check that is placed later on
    // purpose.
    #[serde(default)]
    pub skipped: Vec<SkippedRoot>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct SkippedRoot {
    pub root_id: i64,
    pub reason: String,
}

/// `scan.status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ScanStatusResult {
    pub scans: Vec<ScanState>,
}

/// `search`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct SearchResult {
    pub hits: Vec<SearchHit>,
    /// Total matches, which may exceed `hits.len()` when `limit` truncated.
    pub total: u64,
    pub took_ms: u64,
    /// Set when the daemon could not serve the requested
    /// [`crate::request::SearchMode`] and answered with a weaker one — a Phase 1
    /// daemon asked for `hybrid`, or a Phase 5 daemon whose ANN shard is
    /// rebuilding. A silent downgrade would make an incomplete result look
    /// authoritative, so the reason travels with the result.
    #[serde(default)]
    pub degraded: Option<String>,
}

/// `status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct StatusResult {
    /// The daemon's build version, e.g. `"0.1.0"`.
    pub build: String,
    /// The daemon's protocol version, and the minor this connection negotiated.
    pub proto_version: crate::version::ProtoVersion,
    pub negotiated_minor: u16,
    pub capabilities: Vec<crate::version::Capability>,
    pub uptime_secs: u64,
    pub roots: u64,
    pub files_catalogued: u64,
    pub bytes_catalogued: u64,
    /// Queue depth per job class.
    pub jobs_pending: Vec<JobClassDepth>,
    /// Bytes that are tiered and awaiting the end of their deferral window.
    ///
    /// AC-49 surfaces this on the Dashboard for a specific reason recorded in
    /// §9: with OQ-H's 14-day default, a user who deleted files to free space
    /// sees no reduction for two weeks, and without this number the overhang is
    /// mysterious.
    pub bytes_pending_discard: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct JobClassDepth {
    pub class: String,
    pub pending: u64,
    pub running: u64,
    pub failed: u64,
}

/// `target.add`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TargetAddResult {
    pub target: TargetSummary,
}

/// `target.list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TargetListResult {
    pub targets: Vec<TargetSummary>,
}

/// `target.test`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TargetTestResult {
    pub target_id: i64,
    pub reachable: bool,
    /// Whether the probe could write and then remove a `_shepherd/` control
    /// object. Reachable-but-read-only is a distinct and common misconfiguration.
    pub writable: bool,
    #[serde(default)]
    pub latency_ms: Option<u64>,
    #[serde(default)]
    pub detail: Option<String>,
}

/// `rule.list`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RuleListResult {
    pub rules: Vec<RuleSummary>,
}

/// `rule.preview` — the dry run AC-14 makes mandatory before enabling a rule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct RulePreviewResult {
    pub rule_id: i64,
    pub matched: u64,
    pub bytes_matched: u64,
    /// A bounded sample of the matches, for the user to eyeball.
    pub sample: Vec<SearchHit>,
    /// Lowercase hex BLAKE3 over the matched set. Recorded as
    /// `rule.last_preview_hash`, and the value a later enable is checked
    /// against.
    pub preview_hash: String,
    pub previewed_at: i64,
}

/// `tier.plan`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, JsonSchema)]
pub struct TierPlanResult {
    pub plan_id: String,
    pub rule_id: i64,
    pub target_id: i64,
    pub candidate_count: u64,
    pub bytes_total: u64,
    /// Lowercase hex BLAKE3 over the candidate set. `tier.run` must echo it
    /// back; §4.10's bulk breaker confirms against the set the user saw.
    pub candidate_set_hash: String,
    pub sample: Vec<SearchHit>,
    /// Candidates excluded by a safety floor, with the floor named. Present
    /// even when empty: "nothing was excluded" and "exclusions were not computed"
    /// must not look alike.
    #[serde(default)]
    pub excluded: Vec<ExcludedCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct ExcludedCandidate {
    pub file_id: i64,
    pub rel_path: String,
    /// The floor or policy that excluded it.
    pub reason: String,
}

/// `tier.run`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct TierRunResult {
    pub plan_id: String,
    pub job_id: i64,
    pub accepted: u64,
}

/// The outcome of one `doctor` check.
///
/// `Warn` is not a failure. §4.2's lingering check is the reason: on a headless
/// Linux node with lingering disabled the daemon correctly does not start, and
/// OQ-F forbids Shepherd from enabling it. If a warning made `doctor` unclean,
/// the pressure to get a green doctor would become pressure to change a user's
/// system setting on their behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    Ok,
    Warn,
    Fail,
    NotApplicable,
}

/// One named self-check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    /// What was observed. Empty for a plain `ok`.
    #[serde(default)]
    pub detail: Option<String>,
    /// A command the **user** may choose to run. Shepherd never runs it — see
    /// OQ-F and `shepherd_obs::lingering`.
    #[serde(default)]
    pub remediation: Option<String>,
}

/// `doctor`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct DoctorResult {
    pub checks: Vec<DoctorCheck>,
    /// True when nothing failed. Warnings do not make it false.
    pub clean: bool,
    /// Whether these checks came from a running daemon or were run locally by
    /// the client because the daemon was unreachable.
    ///
    /// The distinction matters: an offline run can only see what a client
    /// process can see, so a clean offline result is a much weaker statement
    /// than a clean online one, and a reader must be able to tell them apart.
    pub source: DoctorSource,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum DoctorSource {
    Daemon,
    /// Produced by `shepctl` with no daemon reachable.
    OfflineClient,
}

/// `restore`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
pub struct RestoreResult {
    pub job_id: i64,
    pub file_id: i64,
    pub destination: String,
    pub bytes: u64,
}

pub use crate::event::SubscribeResult;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ErrorCode;

    #[test]
    fn a_success_frame_omits_the_error_member() {
        let r = RpcResponse::ok(RequestId::Number(1), serde_json::json!({"ok": 1}));
        let j = serde_json::to_value(&r).unwrap();
        assert!(j.get("error").is_none());
        assert_eq!(j["jsonrpc"], serde_json::json!("2.0"));
        assert_eq!(r.outcome().unwrap()["ok"], serde_json::json!(1));
    }

    #[test]
    fn a_failure_frame_omits_the_result_member() {
        let r = RpcResponse::failed(
            Some(RequestId::Number(1)),
            RpcError::new(ErrorCode::NotFound, "no such root"),
        );
        let j = serde_json::to_value(&r).unwrap();
        assert!(j.get("result").is_none());
        assert_eq!(r.outcome().unwrap_err().kind(), Some(ErrorCode::NotFound));
    }

    #[test]
    fn a_frame_with_both_members_is_rejected_rather_than_guessed() {
        // A peer bug. Picking one silently would make the daemon's behaviour
        // depend on which member a future serde ordering emitted first.
        let r: RpcResponse = serde_json::from_str(
            r#"{"jsonrpc":"2.0","id":1,"result":{},"error":{"code":1003,"message":"m"}}"#,
        )
        .unwrap();
        let e = r.outcome().unwrap_err();
        assert_eq!(e.kind(), Some(ErrorCode::InvalidRequest));
        assert!(e.message.contains("both"), "{}", e.message);
    }

    #[test]
    fn a_frame_with_neither_member_is_rejected() {
        let r: RpcResponse = serde_json::from_str(r#"{"jsonrpc":"2.0","id":1}"#).unwrap();
        assert_eq!(
            r.outcome().unwrap_err().kind(),
            Some(ErrorCode::InvalidRequest)
        );
    }

    #[test]
    fn a_parse_failure_may_answer_with_a_null_id() {
        let r = RpcResponse::failed(None, RpcError::new(ErrorCode::ParseError, "bad json"));
        let j = serde_json::to_value(&r).unwrap();
        assert_eq!(j["id"], serde_json::Value::Null);
    }

    #[test]
    fn results_ignore_unknown_fields() {
        let r: RootRemoveResult = serde_json::from_str(
            r#"{"root_id":1,"catalog_rows_dropped":2,"custody_rows_dropped":0,"added_later":1}"#,
        )
        .unwrap();
        assert_eq!(r.root_id, 1);
    }

    #[test]
    fn event_notifications_carry_no_id() {
        use crate::event::{EventPayload, EventStream, Seq};
        let n = RpcNotification::new(EventFrame {
            seq: Seq(1),
            stream: EventStream::Scan,
            emitted_at: 0,
            payload: EventPayload::ScanProgress {
                root_id: 1,
                files_seen: 10,
                bytes_seen: 20,
                current_path: None,
                done: false,
            },
        });
        let j = serde_json::to_value(&n).unwrap();
        assert!(
            j.get("id").is_none(),
            "a notification must not be answerable"
        );
        assert_eq!(j["method"], serde_json::json!(EVENT_NOTIFICATION_METHOD));
        assert_eq!(j["params"]["seq"], serde_json::json!(1));
    }
}
