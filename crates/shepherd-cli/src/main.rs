//! `shepctl` — the command-line client.
//!
//! # The command tree is not written here; it is derived
//!
//! Every subcommand comes from `shepherd_proto::MethodKind::ALL`, and every
//! argument comes from the method's request JSON Schema. There is no list of
//! commands in this file and no `#[derive(Parser)]` struct mirroring one.
//!
//! That is AC-54's `CLI == registered_methods` half, held **by construction**
//! rather than by a check: `shepctl` cannot expose a command the registry lacks,
//! because it has no other source of commands, and it cannot omit one, because
//! it iterates the whole table. `ac54_cli_equals_registered_methods` asserts the
//! bijection anyway — by-construction properties are the ones that quietly stop
//! being true when someone adds a special case, so CI states it out loud.
//!
//! The other half, `UI ⊆ CLI`, is Phase 8's and needs a different mechanism: a
//! Rust trait cannot type-check a TypeScript `invoke()` call site. See
//! `shepherd_proto::method` for the note the Phase 8 owner inherits.
//!
//! # What is scaffolded
//!
//! `shepherd-daemon` (task T6) is still a skeleton, so **no command here has
//! been run against a live daemon**. Argument parsing, request construction, the
//! envelope and the unreachable-daemon path are covered by the tests at the
//! bottom of this file; the socket exchange itself is not, and cannot be until
//! T6 lands.
//!
//! # Exit codes
//!
//! Stable, because scripts branch on them:
//!
//! | code | meaning |
//! |---|---|
//! | 0 | success |
//! | 1 | the daemon answered with an error |
//! | 2 | usage error (clap's own convention) |
//! | 3 | the daemon could not be reached |
//! | 4 | the method is registered but not served here |
//!
//! # One command does not return promptly
//!
//! `events subscribe` follows its stream: it prints each event as it arrives
//! and returns only when the daemon closes the connection (exit 0) or the user
//! interrupts it. Every other command is one request and one response. There is
//! deliberately no `--count` or `--for` flag to bound it — the argument tree
//! above is derived from each method's request schema, and a client-only
//! argument would be the first thing to break that. See `stream_events`.

mod client;

use std::collections::BTreeMap;
use std::process::ExitCode;
use std::time::Duration;

use clap::builder::PossibleValuesParser;
use clap::{Arg, ArgAction, ArgMatches, Command, value_parser};
use shepherd_proto::response::{CheckStatus, DoctorCheck, DoctorResult, DoctorSource};
use shepherd_proto::{CliEnvelope, CliError, ErrorCode, MethodKind, PROTO_VERSION};

const EXIT_OK: u8 = 0;
const EXIT_DAEMON_ERROR: u8 = 1;
const EXIT_UNREACHABLE: u8 = 3;
const EXIT_NOT_IMPLEMENTED: u8 = 4;

fn main() -> ExitCode {
    let matches = build_cli().get_matches();
    let json = matches.get_flag("json");

    // A streaming command's `--json` output is NDJSON — one compact JSON value
    // per line — and its closing envelope has to be one too. Pretty-printing it
    // spanned several lines, so a consumer reading the documented stream
    // line-by-line parsed every event correctly and then failed on the first
    // line of the summary.
    //
    // Only the streaming commands, rather than making every `--json` output
    // compact: a one-shot `shepctl status --json` is read by people as often as
    // by scripts, and the pretty form is the reason it is legible. The
    // difference is a property of the OUTPUT SHAPE — a stream versus a
    // document — not a preference.
    let style = match resolve_method(&matches) {
        Some((MethodKind::EventsSubscribe, _)) => JsonStyle::Ndjson,
        _ => JsonStyle::Document,
    };

    match run(&matches) {
        Ok(data) => {
            emit(&CliEnvelope::ok(data), json, style);
            ExitCode::from(EXIT_OK)
        }
        Err(failure) => {
            emit(&CliEnvelope::failed(failure.error.clone()), json, style);
            ExitCode::from(failure.exit)
        }
    }
}

/// How `--json` output is shaped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JsonStyle {
    /// One document, pretty-printed, for a command that answers once.
    Document,
    /// One compact value per line, for a command that streams — the closing
    /// envelope included, or the stream is not NDJSON.
    Ndjson,
}

struct Failure {
    error: CliError,
    exit: u8,
}

fn run(matches: &ArgMatches) -> Result<serde_json::Value, Failure> {
    let (kind, leaf) = resolve_method(matches).ok_or_else(|| Failure {
        // Unreachable through clap, which requires a subcommand. Kept as a
        // typed outcome rather than an `unwrap`, because a panic would print a
        // backtrace where a script expects an envelope.
        error: CliError::new("unknown_command", "no method selected"),
        exit: 2,
    })?;

    let params = params_from_matches(kind, leaf).map_err(|m| Failure {
        error: CliError::new("invalid_argument", m),
        exit: 2,
    })?;

    let socket = matches.get_one::<String>("socket").map(String::as_str);
    let timeout = matches
        .get_one::<u64>("timeout")
        .map_or(client::DEFAULT_TIMEOUT, |s| Duration::from_secs(*s));

    // `events.subscribe` is the one method whose answer is not the point. The
    // daemon replies, then pumps notifications down the same socket; a client
    // that returns after the reply closes the socket and renders nothing. See
    // `client::subscribe`.
    if kind == MethodKind::EventsSubscribe {
        return stream_events(socket, timeout, params, matches.get_flag("json"));
    }

    match client::call(socket, timeout, kind.name(), params) {
        Ok(data) => Ok(data),
        // `doctor` is the one method that must answer when the daemon is
        // unreachable — see `offline_doctor`.
        Err(client::ClientError::NotRunning { detail }) if kind == MethodKind::Doctor => {
            Ok(offline_doctor(&detail))
        }
        Err(e) => Err(rpc_failure(&e)),
    }
}

/// Render `events subscribe` as a stream, and return once it ends.
///
/// # This command is long-running, and the others are not
///
/// Every other `shepctl` invocation is one request and one response. This one
/// subscribes and then **follows**, printing each event as it arrives, until
/// the daemon closes the connection or the user interrupts it. That is a
/// deliberate behaviour change: the previous version used the same one-response
/// path as every ordinary RPC, so it read the `SubscribeResult`, dropped the
/// connection, and never rendered a single event — replayed or live. It
/// reported success for a subscription that had already been reaped.
///
/// Events are printed as they arrive rather than accumulated, because a
/// follow command that shows nothing until it exits is not a follow command.
/// With `--json` each event is one compact line — NDJSON, which is what a
/// script piping this can consume incrementally — and the ordinary envelope
/// still closes the run. Rust's stdout is line-buffered, so a line is on the
/// pipe as soon as it is written.
///
/// The returned value is the subscription itself plus the count, so
/// `--json` consumers get a final record of what the run covered rather than
/// having to infer it.
fn stream_events(
    socket: Option<&str>,
    timeout: Duration,
    params: serde_json::Value,
    json: bool,
) -> Result<serde_json::Value, Failure> {
    let sub = client::subscribe(
        socket,
        timeout,
        params,
        // BEFORE the first event, not after the last. `snapshot_required` says
        // the client's belief about the past is invalid, and a follow command
        // that only mentioned it once the stream ended would never mention it
        // at all — the stream ends when the user interrupts it.
        |result| {
            if result.get("resume").and_then(|r| r.get("outcome"))
                == Some(&serde_json::json!("snapshot_required"))
            {
                if json {
                    println!(
                        "{}",
                        serde_json::to_string(&serde_json::json!({
                            "warning": "snapshot_required",
                            "detail": "the resume cursor is unusable; re-read state through \
                                       the ordinary methods before trusting this stream",
                            "resume": result.get("resume"),
                        }))
                        .unwrap_or_default()
                    );
                } else {
                    eprintln!(
                        "warning: the resume cursor is unusable ({}). Events from here are \
                         live, but anything you believe about the past is not — re-read \
                         state through the ordinary methods.",
                        result
                            .get("resume")
                            .and_then(|r| r.get("reason"))
                            .and_then(serde_json::Value::as_str)
                            .unwrap_or("snapshot_required")
                    );
                }
            }
        },
        |event| {
            if json {
                println!(
                    "{}",
                    serde_json::to_string(event)
                        .unwrap_or_else(|e| format!("{{\"error\":\"{e}\"}}"))
                );
            } else {
                print!("{}", render_human(event, 0));
            }
        },
    )
    .map_err(|e| rpc_failure(&e))?;

    // Read out before `sub.result` is consumed below: the dropped-subscription
    // hint needs it to tell the client what to resume WITH, and a cursor
    // without its epoch is one the daemon now refuses.
    let epoch = sub
        .result
        .get("epoch")
        .and_then(serde_json::Value::as_str)
        .unwrap_or("<epoch>")
        .to_owned();

    let mut summary = serde_json::Map::new();
    if let serde_json::Value::Object(map) = sub.result {
        summary.extend(map);
    }
    summary.insert("events_rendered".into(), serde_json::json!(sub.rendered));
    summary.insert("last_seq".into(), serde_json::json!(sub.last_seq));

    // The daemon closed the socket, which is the only way this loop ends —
    // this command stops by being interrupted, never by deciding a
    // subscription is over. `server::pump_events` closes deliberately when a
    // subscriber falls behind its queue, so EOF is how "frames were lost,
    // resume" is signalled. Reporting exit 0 turned that into a silent end to
    // monitoring, which is the one outcome a `--json` consumer cannot detect.
    // An ordinary EOF stays exit 0: this is a follow command, and a daemon
    // shutting down or a user interrupting is how one ends. Only the daemon
    // SAYING it dropped us is a failure — that is a loss of events, and
    // reporting it as success is what left a monitoring script unable to tell
    // that its stream had stopped covering anything.
    match sub.ended {
        client::StreamEnd::DaemonClosed => {
            summary.insert("ended".into(), serde_json::json!("daemon_closed"));
            Ok(serde_json::Value::Object(summary))
        }
        client::StreamEnd::Dropped(params) => Err(Failure {
            error: CliError::new(
                "subscription_dropped",
                format!(
                    "the daemon dropped this subscription after {} event(s): it fell behind \
                     its {}-frame queue, and every event after the drained ones was lost",
                    sub.rendered,
                    params
                        .get("queue_capacity")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0)
                ),
            )
            .with_hint(match sub.last_seq {
                // The EPOCH is part of the cursor, not an optional extra. A
                // sequence number means nothing without the run that issued it
                // — numbering restarts at 1 every time the daemon starts — and
                // the daemon now treats a cursor without one as stale, which is
                // the honest answer rather than a replay against unrelated
                // numbers. A hint that named only `--resume-from` was teaching
                // the shape that gets refused.
                Some(seq) => format!(
                    "resume with `--resume-from {seq} --resume-epoch {epoch}`; the epoch is \
                     required — a cursor without it is treated as stale, because sequence \
                     numbers restart at 1 on every daemon start. If the daemon answers \
                     `snapshot_required` rather than `resumed`, re-read state through the \
                     ordinary methods before trusting the stream"
                ),
                None => "no event was delivered, so there is no cursor; re-subscribe and \
                         consume faster, or narrow the streams"
                    .into(),
            }),
            exit: 3,
        }),
    }
}

/// Answer `doctor` from the client when no daemon is listening.
///
/// The §9 Phase 1 gate exercises a seatless VM on which the daemon **correctly
/// does not start** — lingering is disabled and OQ-F forbids Shepherd from
/// enabling it — and requires `shepctl doctor` to report that state anyway. So
/// the one thing a client cannot do here is fail with "daemon unreachable":
/// the daemon being down is the condition being diagnosed, not an obstacle to
/// diagnosing it.
///
/// The result is marked [`DoctorSource::OfflineClient`], because a clean
/// offline result is a much weaker statement than a clean online one — it only
/// covers what a client process can see — and a reader has to be able to tell
/// them apart.
///
/// Exit status is 0. A warning is not a failure; if it were, the pressure to
/// get a green doctor would become pressure to enable lingering on the user's
/// behalf, which is the decision OQ-F records against.
fn offline_doctor(unreachable_detail: &str) -> serde_json::Value {
    let user = shepherd_obs::lingering::current_user();
    let state = shepherd_obs::lingering::probe(&user);

    let mut checks = vec![
        // Shared with the daemon and with `shepherdd doctor`: one
        // implementation of the OQ-F wording, three callers.
        to_wire(shepherd_obs::lingering::check(
            &state,
            shepherd_obs::lingering::looks_seated(),
            &user,
        )),
        DoctorCheck {
            name: "daemon".into(),
            status: CheckStatus::Warn,
            detail: Some(unreachable_detail.to_string()),
            remediation: Some("shepherdd run".into()),
        },
    ];
    checks.push(DoctorCheck {
        name: "checks not run".into(),
        status: CheckStatus::NotApplicable,
        detail: Some(
            "the catalog, the job queue and the IPC socket are only inspectable by a running \
             daemon. Start it and re-run to see those."
                .into(),
        ),
        remediation: None,
    });

    let result = DoctorResult {
        clean: !checks.iter().any(|c| c.status == CheckStatus::Fail),
        checks,
        source: DoctorSource::OfflineClient,
    };
    serde_json::to_value(result).unwrap_or(serde_json::Value::Null)
}

/// `shepherd_obs::doctor::Check` -> the wire type.
///
/// Duplicated from the daemon's `state::convert` on purpose: importing
/// `shepherd-daemon` here would drag `rusqlite` and a bundled SQLite into a CLI
/// that needs neither, and would make `shepctl` unbuildable anywhere the daemon
/// is not. Fifteen lines of mapping is the cheaper coupling.
fn to_wire(c: shepherd_obs::doctor::Check) -> DoctorCheck {
    use shepherd_obs::doctor::CheckStatus as S;
    let (status, detail, remediation) = match c.status {
        S::Ok => (CheckStatus::Ok, None, None),
        S::Warn {
            detail,
            remediation,
        } => (CheckStatus::Warn, Some(detail), remediation),
        S::Fail { detail } => (CheckStatus::Fail, Some(detail), None),
        S::NotApplicable { reason } => (CheckStatus::NotApplicable, Some(reason), None),
    };
    DoctorCheck {
        name: c.name,
        status,
        detail,
        remediation,
    }
}

fn rpc_failure(e: &client::ClientError) -> Failure {
    {
        let exit = match &e {
            client::ClientError::NotRunning { .. } => EXIT_UNREACHABLE,
            client::ClientError::Unsupported(_) => EXIT_NOT_IMPLEMENTED,
            client::ClientError::Rpc(r) if r.kind() == Some(ErrorCode::MethodNotImplemented) => {
                EXIT_NOT_IMPLEMENTED
            }
            _ => EXIT_DAEMON_ERROR,
        };
        Failure {
            error: client::to_cli_error(e),
            exit,
        }
    }
}

fn emit(envelope: &CliEnvelope, json: bool, style: JsonStyle) {
    if json {
        let rendered = match style {
            JsonStyle::Document => serde_json::to_string_pretty(envelope),
            JsonStyle::Ndjson => serde_json::to_string(envelope),
        };
        println!(
            "{}",
            rendered
                .unwrap_or_else(|e| format!("{{\"schema_version\":1,\"ok\":false,\"error\":{{\"code\":\"internal_error\",\"message\":\"{e}\"}}}}"))
        );
        return;
    }
    match (&envelope.error, &envelope.data) {
        (Some(err), _) => {
            eprintln!("error: {}", err.message);
            if let Some(hint) = &err.hint {
                eprintln!("{hint}");
            }
        }
        (None, Some(data)) => print!("{}", render_human(data, 0)),
        (None, None) => {}
    }
    for w in &envelope.warnings {
        eprintln!("warning: {w}");
    }
}

// ---------------------------------------------------------------------------
// The command tree
// ---------------------------------------------------------------------------

/// A prefix tree over the registry's CLI paths.
#[derive(Default)]
struct Node {
    children: BTreeMap<String, Node>,
    leaf: Option<MethodKind>,
}

fn method_tree() -> Node {
    let mut root = Node::default();
    for kind in MethodKind::ALL {
        let mut node = &mut root;
        for segment in kind.cli_path() {
            node = node.children.entry((*segment).to_string()).or_default();
        }
        node.leaf = Some(*kind);
    }
    root
}

/// The whole `shepctl` command tree.
pub fn build_cli() -> Command {
    let mut cmd = Command::new("shepctl")
        .version(env!("CARGO_PKG_VERSION"))
        .about("Shepherd command-line client")
        .long_about(format!(
            "Shepherd command-line client.\n\n\
             Every command below is generated from the protocol method table \
             (proto {PROTO_VERSION}), so this tree and the daemon's dispatch table cannot \
             disagree. `--json` prints a stable envelope described by \
             `schemas/cli-envelope.json`; the payload under `.data` is described by \
             `schemas/method/<method>.result.json`."
        ))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("json")
                .long("json")
                .global(true)
                .action(ArgAction::SetTrue)
                .help("Print the stable machine-readable envelope"),
        )
        .arg(
            Arg::new("socket")
                .long("socket")
                .global(true)
                .value_name("PATH")
                .help("Override the daemon socket path"),
        )
        .arg(
            Arg::new("timeout")
                .long("timeout")
                .global(true)
                .value_name("SECONDS")
                .value_parser(value_parser!(u64))
                .help(format!(
                    "Seconds to wait for the daemon [default: {}]",
                    client::DEFAULT_TIMEOUT.as_secs()
                )),
        );

    for (name, node) in method_tree().children {
        cmd = cmd.subcommand(build_node(&name, &node));
    }
    cmd
}

fn build_node(name: &str, node: &Node) -> Command {
    let mut cmd = Command::new(name.to_string());

    if let Some(kind) = node.leaf {
        let d = kind.descriptor();
        cmd = cmd.about(d.summary.to_string()).long_about(format!(
            "{}\n\nJSON-RPC method `{}` (id {}, since protocol minor {}).{}",
            d.summary,
            d.name,
            d.id,
            d.since_minor,
            match &d.deprecated {
                None => String::new(),
                Some(x) => format!(
                    "\n\nDEPRECATED since minor {}: {}{}",
                    x.since_minor,
                    x.note,
                    x.replacement
                        .map(|r| format!(" Use `{r}` instead."))
                        .unwrap_or_default()
                ),
            }
        ));
        for arg in arg_specs(kind) {
            cmd = cmd.arg(arg.to_clap());
        }
    } else {
        cmd = cmd
            .about(format!("`{name}` commands"))
            .subcommand_required(true)
            .arg_required_else_help(true);
    }

    for (child_name, child) in &node.children {
        cmd = cmd.subcommand(build_node(child_name, child));
    }
    cmd
}

/// Walk the parsed matches down to the selected method.
fn resolve_method(matches: &ArgMatches) -> Option<(MethodKind, &ArgMatches)> {
    let mut path: Vec<&str> = Vec::new();
    let mut current = matches;
    loop {
        let (name, sub) = current.subcommand()?;
        path.push(name);
        current = sub;
        if let Some(kind) = MethodKind::ALL
            .iter()
            .find(|k| k.cli_path() == path.as_slice())
        {
            return Some((*kind, current));
        }
    }
}

// ---------------------------------------------------------------------------
// Arguments, derived from each method's request schema
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
enum ArgKind {
    /// A `bool` that defaults to `false`: a presence flag.
    Flag,
    Text,
    Int,
    Uint,
    Number,
    Choice(Vec<String>),
    /// An array. Repeatable.
    List,
    /// Anything structured. Taken as a JSON literal, which is the only honest
    /// rendering of a nested object on a command line.
    Json,
}

#[derive(Debug, Clone)]
struct ArgSpec {
    /// The request field name, e.g. `root_id`.
    field: String,
    /// The flag name, e.g. `root-id`. Ignored when `positional`.
    flag: String,
    kind: ArgKind,
    required: bool,
    positional: bool,
    help: String,
}

impl ArgSpec {
    fn to_clap(&self) -> Arg {
        let mut arg = Arg::new(self.field.clone()).help(self.help.clone());
        match &self.kind {
            ArgKind::Flag => arg = arg.action(ArgAction::SetTrue),
            ArgKind::List => {
                arg = arg
                    .action(ArgAction::Append)
                    .value_name("VALUE")
                    .num_args(1);
            }
            ArgKind::Choice(values) => {
                arg = arg
                    .value_name("VALUE")
                    .value_parser(PossibleValuesParser::new(values))
                    .num_args(1);
            }
            ArgKind::Json => arg = arg.value_name("JSON").num_args(1),
            _ => arg = arg.value_name("VALUE").num_args(1),
        }
        // After the kind, not before: the kind arm sets a generic value name and
        // would otherwise overwrite the field-derived one, printing `<VALUE>`
        // where `shepctl search <QUERY>` is what the user needs to read.
        if self.positional {
            arg = arg.value_name(self.field.to_uppercase()).index(1);
        } else {
            arg = arg.long(self.flag.clone());
        }
        if self.required && self.kind != ArgKind::Flag {
            arg = arg.required(true);
        }
        arg
    }
}

/// Which request field, if any, this command takes positionally.
///
/// **Exhaustive on purpose.** A method added to the table stops this file
/// compiling until someone decides how it is spelled — which is the one CLI
/// decision the protocol table has no business making. It affects only spelling:
/// a method left as `None` still gets every field as a `--flag`, so a forgotten
/// entry degrades ergonomics, never coverage.
fn positional_field(kind: MethodKind) -> Option<&'static str> {
    match kind {
        // §6 Phase 1's M1 demo is literally `shepctl search "report" --json`.
        MethodKind::Search => Some("query"),
        MethodKind::RootAdd => Some("path"),
        MethodKind::RootList
        | MethodKind::RootRemove
        | MethodKind::ScanStart
        | MethodKind::ScanStatus
        | MethodKind::Status
        | MethodKind::TargetAdd
        | MethodKind::TargetList
        | MethodKind::TargetTest
        | MethodKind::RuleList
        | MethodKind::RulePreview
        | MethodKind::TierPlan
        | MethodKind::TierRun
        | MethodKind::Restore
        | MethodKind::Doctor
        | MethodKind::EventsSubscribe => None,
    }
}

/// Derive the argument list for one method from its request schema.
fn arg_specs(kind: MethodKind) -> Vec<ArgSpec> {
    let schema = kind.request_schema();
    let defs = schema
        .get("$defs")
        .and_then(|d| d.as_object())
        .cloned()
        .unwrap_or_default();
    let required: Vec<&str> = schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
        .unwrap_or_default();
    let Some(props) = schema.get("properties").and_then(|p| p.as_object()) else {
        return Vec::new();
    };

    let pos = positional_field(kind);
    let mut specs: Vec<ArgSpec> = props
        .iter()
        .map(|(field, prop)| {
            let (arg_kind, nullable) = resolve_kind(prop, &defs, 0);
            ArgSpec {
                field: field.clone(),
                flag: field.replace('_', "-"),
                kind: arg_kind,
                required: required.contains(&field.as_str()) && !nullable,
                positional: pos == Some(field.as_str()),
                help: describe(prop),
            }
        })
        .collect();

    // Positional first, then flags alphabetically, so `--help` is stable output.
    specs.sort_by(|a, b| b.positional.cmp(&a.positional).then(a.field.cmp(&b.field)));
    specs
}

/// The one-paragraph help text for an argument, taken from the request type's
/// doc comment.
///
/// Newlines are collapsed rather than truncated at the first one. Taking only
/// the first line cut sentences mid-clause, because a doc comment is wrapped for
/// source width, not for a terminal — clap's `wrap_help` re-wraps it correctly
/// once it is one paragraph.
fn describe(prop: &serde_json::Value) -> String {
    let Some(text) = prop.get("description").and_then(|d| d.as_str()) else {
        return String::new();
    };
    // A blank line ends the summary paragraph; the rest is detail that belongs
    // in the schema, not in `--help`.
    let summary = text.split("\n\n").next().unwrap_or(text);
    summary.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Map one JSON Schema property onto a command-line argument kind.
///
/// Returns `(kind, nullable)`. `nullable` marks an `Option<T>` field, which is
/// never a required argument even when the schema lists it — schemars includes
/// a field in `required` when serde will always emit it, which is not the same
/// question as whether a user must supply it.
///
/// `depth` bounds `$ref` following. A self-referential request type would
/// otherwise loop; it degrades to a JSON literal, which is correct for a
/// recursive shape anyway.
fn resolve_kind(
    prop: &serde_json::Value,
    defs: &serde_json::Map<String, serde_json::Value>,
    depth: u8,
) -> (ArgKind, bool) {
    if depth > 4 {
        return (ArgKind::Json, true);
    }

    // `$ref` into `$defs` — how schemars emits every named enum and struct.
    if let Some(reference) = prop.get("$ref").and_then(|r| r.as_str()) {
        let name = reference.rsplit('/').next().unwrap_or_default();
        return match defs.get(name) {
            Some(target) => resolve_kind(target, defs, depth + 1),
            None => (ArgKind::Json, true),
        };
    }

    // `Option<T>` arrives as `anyOf: [T, {"type":"null"}]` or as a type array
    // containing `"null"`, depending on the shape of T.
    for key in ["anyOf", "oneOf"] {
        if let Some(variants) = prop.get(key).and_then(|v| v.as_array()) {
            let nullable = variants.iter().any(is_null_schema);
            let concrete: Vec<&serde_json::Value> =
                variants.iter().filter(|v| !is_null_schema(v)).collect();

            // A documented unit-variant enum: `oneOf: [{const: "a"}, ...]`.
            let consts: Vec<String> = concrete
                .iter()
                .filter_map(|v| v.get("const").and_then(|c| c.as_str()))
                .map(String::from)
                .collect();
            if consts.len() == concrete.len() && !consts.is_empty() {
                return (ArgKind::Choice(consts), nullable);
            }
            if concrete.len() == 1 {
                let (k, _) = resolve_kind(concrete[0], defs, depth + 1);
                return (k, nullable);
            }
            return (ArgKind::Json, nullable);
        }
    }

    // An undocumented unit-variant enum: `enum: ["a", "b"]`.
    if let Some(values) = prop.get("enum").and_then(|v| v.as_array()) {
        let (nulls, rest): (Vec<_>, Vec<_>) = values.iter().partition(|v| v.is_null());
        let choices: Vec<String> = rest
            .iter()
            .filter_map(|v| v.as_str())
            .map(String::from)
            .collect();
        if choices.len() == rest.len() && !choices.is_empty() {
            return (ArgKind::Choice(choices), !nulls.is_empty());
        }
        return (ArgKind::Json, !nulls.is_empty());
    }

    let (type_names, nullable) = type_names(prop);
    let primary = type_names.iter().find(|t| *t != "null").map(String::as_str);
    let kind = match primary {
        Some("string") => ArgKind::Text,
        Some("boolean") => ArgKind::Flag,
        Some("integer") => {
            let unsigned = prop
                .get("format")
                .and_then(|f| f.as_str())
                .is_some_and(|f| f.starts_with("uint"))
                || prop.get("minimum").and_then(|m| m.as_i64()) == Some(0);
            if unsigned {
                ArgKind::Uint
            } else {
                ArgKind::Int
            }
        }
        Some("number") => ArgKind::Number,
        Some("array") => ArgKind::List,
        // "object", `true`, or an absent `type`: anything structured.
        _ => ArgKind::Json,
    };
    (kind, nullable)
}

fn is_null_schema(v: &serde_json::Value) -> bool {
    v.get("type").and_then(|t| t.as_str()) == Some("null")
}

/// `type` may be a string or an array of strings.
fn type_names(prop: &serde_json::Value) -> (Vec<String>, bool) {
    match prop.get("type") {
        Some(serde_json::Value::String(s)) => (vec![s.clone()], false),
        Some(serde_json::Value::Array(a)) => {
            let names: Vec<String> = a
                .iter()
                .filter_map(|v| v.as_str())
                .map(String::from)
                .collect();
            let nullable = names.iter().any(|n| n == "null");
            (names, nullable)
        }
        _ => (Vec::new(), true),
    }
}

/// Build the `params` object from what the user actually supplied.
///
/// Absent optional arguments are **omitted**, never sent as `null`: the request
/// types carry `#[serde(default)]`, and a default is the daemon's to choose. A
/// CLI that sent `{"limit": null}` would override a default with an absence.
fn params_from_matches(
    kind: MethodKind,
    matches: &ArgMatches,
) -> Result<serde_json::Value, String> {
    let mut params = serde_json::Map::new();
    for spec in arg_specs(kind) {
        let id = spec.field.as_str();
        let value = match &spec.kind {
            ArgKind::Flag => {
                // Only a set flag is sent; an unset one leaves the default alone.
                if matches.get_flag(id) {
                    Some(serde_json::Value::Bool(true))
                } else {
                    None
                }
            }
            ArgKind::List => {
                let items: Vec<serde_json::Value> = matches
                    .get_many::<String>(id)
                    .map(|vals| vals.map(|v| serde_json::Value::String(v.clone())).collect())
                    .unwrap_or_default();
                (!items.is_empty()).then_some(serde_json::Value::Array(items))
            }
            ArgKind::Text | ArgKind::Choice(_) => matches
                .get_one::<String>(id)
                .map(|v| serde_json::Value::String(v.clone())),
            ArgKind::Int => match matches.get_one::<String>(id) {
                None => None,
                Some(raw) => Some(serde_json::Value::from(raw.parse::<i64>().map_err(
                    |_| format!("`--{}` expects a whole number, got `{raw}`", spec.flag),
                )?)),
            },
            ArgKind::Uint => match matches.get_one::<String>(id) {
                None => None,
                Some(raw) => Some(serde_json::Value::from(raw.parse::<u64>().map_err(
                    |_| {
                        format!(
                            "`--{}` expects a non-negative whole number, got `{raw}`",
                            spec.flag
                        )
                    },
                )?)),
            },
            ArgKind::Number => match matches.get_one::<String>(id) {
                None => None,
                Some(raw) => Some(serde_json::Value::from(raw.parse::<f64>().map_err(
                    |_| format!("`--{}` expects a number, got `{raw}`", spec.flag),
                )?)),
            },
            ArgKind::Json => match matches.get_one::<String>(id) {
                None => None,
                Some(raw) => Some(
                    serde_json::from_str(raw)
                        .map_err(|e| format!("`--{}` expects a JSON value: {e}", spec.flag))?,
                ),
            },
        };
        if let Some(v) = value {
            params.insert(spec.field, v);
        }
    }
    Ok(serde_json::Value::Object(params))
}

// ---------------------------------------------------------------------------
// Human-readable rendering
// ---------------------------------------------------------------------------

/// Render a result payload for a terminal.
///
/// Generic rather than per-method: `--json` is the contract (AC-56) and this is
/// the convenience. A per-method formatter for each of sixteen methods would be
/// sixteen more places to drift from the schema, for output nothing may parse.
fn render_human(value: &serde_json::Value, indent: usize) -> String {
    let pad = "  ".repeat(indent);
    match value {
        serde_json::Value::Object(map) => {
            let mut s = String::new();
            for (k, v) in map {
                match v {
                    serde_json::Value::Array(items) if !items.is_empty() => {
                        s.push_str(&format!("{pad}{k}:\n"));
                        for item in items {
                            s.push_str(&render_human(item, indent + 1));
                        }
                    }
                    serde_json::Value::Object(_) => {
                        s.push_str(&format!("{pad}{k}:\n"));
                        s.push_str(&render_human(v, indent + 1));
                    }
                    _ => s.push_str(&format!("{pad}{k}: {}\n", scalar(v))),
                }
            }
            s
        }
        serde_json::Value::Array(items) => items
            .iter()
            .map(|i| render_human(i, indent))
            .collect::<String>(),
        other => format!("{pad}{}\n", scalar(other)),
    }
}

fn scalar(v: &serde_json::Value) -> String {
    match v {
        serde_json::Value::String(s) => s.clone(),
        serde_json::Value::Null => "-".into(),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn spec(kind: MethodKind, field: &str) -> ArgSpec {
        arg_specs(kind)
            .into_iter()
            .find(|s| s.field == field)
            .unwrap_or_else(|| panic!("{} has no field `{field}`", kind.name()))
    }

    #[test]
    fn the_tree_is_built_only_from_the_registry() {
        build_cli().debug_assert();
    }

    /// Collect every leaf command path in the built tree.
    fn cli_leaf_paths() -> std::collections::BTreeSet<Vec<String>> {
        fn walk(
            cmd: &Command,
            prefix: &mut Vec<String>,
            out: &mut std::collections::BTreeSet<Vec<String>>,
        ) {
            let subs: Vec<&Command> = cmd.get_subcommands().collect();
            if subs.is_empty() {
                if !prefix.is_empty() {
                    out.insert(prefix.clone());
                }
                return;
            }
            for sub in subs {
                prefix.push(sub.get_name().to_string());
                walk(sub, prefix, out);
                prefix.pop();
            }
        }
        let mut out = std::collections::BTreeSet::new();
        walk(&build_cli(), &mut Vec::new(), &mut out);
        out
    }

    /// **AC-54, the `CLI == registered_methods` half, run in CI from Phase 1.**
    ///
    /// The §9 Phase 1 gate names this check explicitly. It is a bijection with
    /// no exemption list: `shepctl` has no command that is not a method, which
    /// is why the assertion can be equality rather than containment. If a
    /// convenience subcommand is ever added, this test fails, and that failure
    /// is the design working — the exemption has to be argued in review rather
    /// than appear in a diff nobody reads.
    #[test]
    fn ac54_cli_equals_registered_methods() {
        let from_cli = cli_leaf_paths();
        let from_registry: std::collections::BTreeSet<Vec<String>> = MethodKind::ALL
            .iter()
            .map(|k| k.cli_path().iter().map(|s| (*s).to_string()).collect())
            .collect();

        let cli_only: Vec<_> = from_cli.difference(&from_registry).collect();
        let registry_only: Vec<_> = from_registry.difference(&from_cli).collect();
        assert!(
            cli_only.is_empty(),
            "shepctl exposes commands that are not registered methods: {cli_only:?}"
        );
        assert!(
            registry_only.is_empty(),
            "registered methods with no shepctl command: {registry_only:?}"
        );
        assert_eq!(from_cli.len(), MethodKind::ALL.len());
    }

    /// The wire enum and the domain enum must agree, and no single crate can
    /// assert it: `shepherd-proto` may not depend on `shepherd-core` (§4.1
    /// rule 1) and `shepherd-core` knows nothing of the wire. `shepherd-cli`
    /// depends on both, so the agreement is checkable exactly here.
    ///
    /// Without this, a rename on either side would produce a daemon that
    /// silently reads `"dehydrate"` as an unknown mode — on the enum that
    /// decides whether a file's bytes are removed.
    #[test]
    fn the_wire_stub_mode_and_the_domain_stub_mode_serialize_identically() {
        use shepherd_core::StubMode as Domain;
        use shepherd_proto::request::StubMode as Wire;
        for (domain, wire) in [
            (Domain::Dehydrate, Wire::Dehydrate),
            (Domain::Delete, Wire::Delete),
        ] {
            assert_eq!(
                serde_json::to_value(domain).unwrap(),
                serde_json::to_value(wire).unwrap(),
                "the wire and domain StubMode have drifted apart"
            );
        }
    }

    #[test]
    fn scalar_fields_become_typed_flags() {
        assert_eq!(spec(MethodKind::RootRemove, "root_id").kind, ArgKind::Int);
        assert_eq!(spec(MethodKind::RootRemove, "force").kind, ArgKind::Flag);
        assert_eq!(spec(MethodKind::TierRun, "plan_id").kind, ArgKind::Text);
        assert_eq!(spec(MethodKind::Search, "limit").kind, ArgKind::Uint);
    }

    #[test]
    fn an_enum_field_becomes_a_constrained_choice() {
        // `stub_mode` reaches the schema as a `$ref` into `$defs`. If the
        // resolver stopped at the `$ref` it would degrade to a JSON blob and
        // `shepctl root add --stub-mode delete` would need quoting. This is the
        // assertion that keeps the `$ref` hop working.
        match spec(MethodKind::RootAdd, "stub_mode").kind {
            ArgKind::Choice(values) => {
                assert!(values.contains(&"delete".to_string()), "{values:?}");
                assert!(values.contains(&"dehydrate".to_string()), "{values:?}");
            }
            other => panic!("expected a choice, got {other:?}"),
        }
    }

    /// AC-9's reachability leg on the CLI side.
    ///
    /// The whole of AC-9's gap was that no client could supply an ignore
    /// pattern. `--ignore-patterns` is derived from the schema rather than
    /// hand-written, so what needs asserting is that the derivation produced a
    /// **repeatable** flag carrying an ordered array, not a single string or a
    /// JSON blob the user would have to quote.
    #[test]
    fn ignore_patterns_becomes_a_repeatable_flag_carrying_an_ordered_array() {
        assert_eq!(
            spec(MethodKind::RootAdd, "ignore_patterns").kind,
            ArgKind::List
        );
        assert!(!spec(MethodKind::RootAdd, "ignore_patterns").required);

        let m = build_cli()
            .try_get_matches_from([
                "shepctl",
                "root",
                "add",
                "/srv/data",
                "--stub-mode",
                "delete",
                "--ignore-patterns",
                "build/",
                "--ignore-patterns",
                "!build/keep.txt",
            ])
            .expect("root add with patterns");
        let (kind, leaf) = resolve_method(&m).unwrap();
        let params = params_from_matches(kind, leaf).unwrap();
        // Order preserved: `.gitignore` is last-match-wins, so a flag that
        // reordered or de-duplicated would invert the negation.
        assert_eq!(
            params["ignore_patterns"],
            serde_json::json!(["build/", "!build/keep.txt"])
        );

        // The paired negative: unset must send nothing, so a 1.2 client that
        // omits the flag leaves the daemon's `'[]'` alone rather than
        // overwriting it with an explicit empty list.
        let bare = build_cli()
            .try_get_matches_from([
                "shepctl",
                "root",
                "add",
                "/srv/data",
                "--stub-mode",
                "delete",
            ])
            .expect("root add");
        let (kind, leaf) = resolve_method(&bare).unwrap();
        assert!(
            params_from_matches(kind, leaf)
                .unwrap()
                .get("ignore_patterns")
                .is_none(),
            "an unset list flag must not appear in the request"
        );
    }

    #[test]
    fn a_nested_object_degrades_to_a_json_literal() {
        assert_eq!(spec(MethodKind::Search, "filters").kind, ArgKind::Json);
    }

    #[test]
    fn optional_fields_are_never_required_arguments() {
        assert!(!spec(MethodKind::RulePreview, "limit").required);
        assert!(!spec(MethodKind::ScanStart, "root_id").required);
        assert!(spec(MethodKind::TierRun, "candidate_set_hash").required);
    }

    #[test]
    fn the_m1_demo_commands_parse() {
        // §6 Phase 1's M1 demo, verbatim, as a parse test.
        let cli = build_cli();
        let m = cli
            .clone()
            .try_get_matches_from([
                "shepctl",
                "root",
                "add",
                "./corpus-1m",
                "--stub-mode",
                "delete",
            ])
            .expect("root add");
        let (kind, leaf) = resolve_method(&m).unwrap();
        assert_eq!(kind, MethodKind::RootAdd);
        let params = params_from_matches(kind, leaf).unwrap();
        assert_eq!(params["path"], serde_json::json!("./corpus-1m"));
        assert_eq!(params["stub_mode"], serde_json::json!("delete"));
        assert!(
            params.get("hosted_optin").is_none(),
            "an unset flag must leave the daemon's default alone"
        );

        let m = cli
            .clone()
            .try_get_matches_from(["shepctl", "search", "report", "--json"])
            .expect("search");
        assert!(m.get_flag("json"));
        let (kind, leaf) = resolve_method(&m).unwrap();
        assert_eq!(kind, MethodKind::Search);
        assert_eq!(
            params_from_matches(kind, leaf).unwrap()["query"],
            serde_json::json!("report")
        );

        let m = cli
            .clone()
            .try_get_matches_from(["shepctl", "scan", "start"])
            .expect("scan start");
        let (kind, _) = resolve_method(&m).unwrap();
        assert_eq!(kind, MethodKind::ScanStart);
    }

    #[test]
    fn a_set_flag_is_sent_and_an_unset_one_is_omitted() {
        let m = build_cli()
            .try_get_matches_from(["shepctl", "root", "remove", "--root-id", "4", "--force"])
            .unwrap();
        let (kind, leaf) = resolve_method(&m).unwrap();
        let p = params_from_matches(kind, leaf).unwrap();
        assert_eq!(p["root_id"], serde_json::json!(4));
        assert_eq!(p["force"], serde_json::json!(true));
        assert!(p.get("forget_catalog").is_none());
    }

    #[test]
    fn a_json_argument_is_parsed_not_stringified() {
        let m = build_cli()
            .try_get_matches_from([
                "shepctl",
                "search",
                "q",
                "--filters",
                r#"{"ext":["pdf"],"min_size":100}"#,
            ])
            .unwrap();
        let (kind, leaf) = resolve_method(&m).unwrap();
        let p = params_from_matches(kind, leaf).unwrap();
        assert_eq!(p["filters"]["ext"], serde_json::json!(["pdf"]));
        assert_eq!(p["filters"]["min_size"], serde_json::json!(100));
    }

    #[test]
    fn malformed_json_and_numbers_are_reported_before_the_socket_is_touched() {
        let m = build_cli()
            .try_get_matches_from(["shepctl", "search", "q", "--filters", "{not json"])
            .unwrap();
        let (kind, leaf) = resolve_method(&m).unwrap();
        let err = params_from_matches(kind, leaf).unwrap_err();
        assert!(err.contains("--filters"), "{err}");
    }

    #[test]
    fn an_unconstrained_enum_value_is_rejected_by_the_parser() {
        let e = build_cli()
            .try_get_matches_from(["shepctl", "root", "add", "/x", "--stub-mode", "vaporize"])
            .unwrap_err();
        assert_eq!(e.kind(), clap::error::ErrorKind::InvalidValue);
    }

    #[test]
    fn every_params_object_this_cli_builds_is_accepted_by_the_registry() {
        // The end-to-end property: whatever `shepctl` constructs from a valid
        // command line must deserialize into the method's request type. This is
        // what would catch a resolver that emitted a string where the schema
        // wanted an integer.
        use shepherd_proto::Method;
        let cases: Vec<Vec<&str>> = vec![
            vec!["shepctl", "root", "add", "/x", "--stub-mode", "dehydrate"],
            vec!["shepctl", "root", "list"],
            vec!["shepctl", "root", "remove", "--root-id", "1"],
            vec!["shepctl", "scan", "start", "--root-id", "2", "--full"],
            vec!["shepctl", "scan", "status"],
            vec![
                "shepctl", "search", "q", "--limit", "10", "--mode", "metadata",
            ],
            vec!["shepctl", "status"],
            vec!["shepctl", "target", "add", "--name", "t", "--adapter", "s3"],
            vec!["shepctl", "target", "list"],
            vec!["shepctl", "target", "test", "--target-id", "1"],
            vec!["shepctl", "rule", "list"],
            vec![
                "shepctl",
                "rule",
                "preview",
                "--rule-id",
                "1",
                "--limit",
                "5",
            ],
            vec![
                "shepctl",
                "tier",
                "plan",
                "--rule-id",
                "1",
                "--target-id",
                "1",
            ],
            vec![
                "shepctl",
                "tier",
                "run",
                "--plan-id",
                "p",
                "--candidate-set-hash",
                "ab",
            ],
            vec!["shepctl", "restore", "--file-id", "9"],
            vec!["shepctl", "events", "subscribe", "--resume-from", "12"],
            vec!["shepctl", "doctor"],
        ];
        assert_eq!(
            cases.len(),
            MethodKind::ALL.len(),
            "every registered method needs a case here"
        );
        for argv in cases {
            let m = build_cli()
                .try_get_matches_from(&argv)
                .unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            let (kind, leaf) = resolve_method(&m).unwrap();
            let params =
                params_from_matches(kind, leaf).unwrap_or_else(|e| panic!("{argv:?}: {e}"));
            Method::from_parts(kind.name(), &params)
                .unwrap_or_else(|e| panic!("{argv:?} -> {params}: {e}"));
        }
    }

    #[test]
    fn the_unreachable_daemon_message_is_actionable() {
        let msg = client::not_running_message(
            &["/run/user/1000/shepherd/daemon.sock".into()],
            "No such file or directory",
        );
        assert!(msg.contains("/run/user/1000/shepherd/daemon.sock"), "{msg}");
        assert!(msg.contains("service registration"), "{msg}");
        assert!(msg.contains(client::start_command()), "{msg}");
    }

    #[test]
    fn human_rendering_reads_as_lines_not_json() {
        let out = render_human(
            &serde_json::json!({"roots": [{"root_id": 1, "path": "/srv"}], "total": 1}),
            0,
        );
        assert!(out.contains("root_id: 1"), "{out}");
        assert!(out.contains("path: /srv"), "{out}");
        assert!(!out.contains('{'), "{out}");
    }
}
