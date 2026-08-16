//! End-to-end tests of `shepctl` against a mock daemon.
//!
//! # Why a mock and not the real daemon
//!
//! `shepherd-daemon` is task T6 and does not exist yet, but the transport is
//! task T5's and every claim about it is otherwise untestable. So these tests
//! stand up a Unix socket that speaks the §4.3 framing, run the **real
//! `shepctl` binary** against it as a subprocess, and assert on its stdout and
//! exit status.
//!
//! What that actually proves, as distinct from what it does not:
//!
//! * proven — the client connects, sends a `hello` preamble followed by one
//!   request, both newline-delimited and both valid JSON-RPC 2.0; it parses the
//!   response frame; it maps a result into the stable CLI envelope; it maps a
//!   transport error onto a stable slug and a documented exit code;
//! * not proven — anything about a real daemon's behaviour, concurrency,
//!   permissions on the socket, or the Windows named pipe.
//!
//! The mock asserts on what it receives, so a client that sent a malformed
//! frame or skipped the handshake fails here rather than passing quietly.
//!
//! Unix only. §4.3's Windows transport is a named pipe whose DACL is Phase 3
//! work; `client.rs` documents why it is not stubbed in.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::PathBuf;
use std::process::{Command, Output};

/// What the mock should answer the method call with.
enum Reply {
    Result(serde_json::Value),
    Error { code: i32, message: &'static str },
}

/// What the mock observed, returned so the test can assert on the client's
/// side of the conversation.
struct Observed {
    hello: serde_json::Value,
    request: serde_json::Value,
}

fn socket_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("shepctl-{}-{tag}.sock", std::process::id()))
}

/// Run `shepctl <args>` against a one-shot mock daemon.
fn run_against_mock(tag: &str, args: &[&str], reply: Reply) -> (Output, Observed) {
    let path = socket_path(tag);
    let _ = std::fs::remove_file(&path);
    let listener = UnixListener::bind(&path).expect("bind the mock socket");

    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept");
        let mut reader = BufReader::new(stream.try_clone().expect("clone"));
        let mut writer: UnixStream = stream;

        let hello = read_frame(&mut reader);
        // Accept the handshake. `hello` is not a table method (see
        // `shepherd_proto::version`), so it is answered here by name.
        write_frame(
            &mut writer,
            &serde_json::json!({
                "jsonrpc": "2.0",
                "id": hello["id"],
                "result": {
                    "proto_version": {"major": 1, "minor": 0},
                    "server": {"name": "mock-shepherdd", "build": "0.0.0"},
                    "capabilities": [],
                    "negotiated": {
                        "minor": 0,
                        "capabilities": [],
                        "unsupported_client_capabilities": []
                    }
                }
            }),
        );

        let request = read_frame(&mut reader);
        let frame = match reply {
            Reply::Result(value) => serde_json::json!({
                "jsonrpc": "2.0", "id": request["id"], "result": value
            }),
            Reply::Error { code, message } => serde_json::json!({
                "jsonrpc": "2.0", "id": request["id"],
                "error": {"code": code, "message": message}
            }),
        };
        write_frame(&mut writer, &frame);
        Observed { hello, request }
    });

    let mut argv: Vec<String> = vec!["--socket".into(), path.display().to_string()];
    argv.extend(args.iter().map(|a| (*a).to_string()));
    let output = Command::new(env!("CARGO_BIN_EXE_shepctl"))
        .args(&argv)
        .output()
        .expect("run shepctl");

    let observed = server.join().expect("the mock daemon panicked");
    let _ = std::fs::remove_file(&path);
    (output, observed)
}

fn read_frame(reader: &mut BufReader<UnixStream>) -> serde_json::Value {
    let mut line = String::new();
    let n = reader.read_line(&mut line).expect("read a frame");
    assert!(n > 0, "the client closed the connection without sending");
    assert!(
        line.ends_with('\n'),
        "§4.3 framing is newline-delimited; got {line:?}"
    );
    serde_json::from_str(&line).unwrap_or_else(|e| panic!("client sent non-JSON {line:?}: {e}"))
}

fn write_frame(writer: &mut UnixStream, value: &serde_json::Value) {
    let mut line = serde_json::to_string(value).expect("encode");
    line.push('\n');
    writer.write_all(line.as_bytes()).expect("write");
    writer.flush().expect("flush");
}

fn envelope(output: &Output) -> serde_json::Value {
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&text).unwrap_or_else(|e| panic!("stdout is not an envelope: {e}\n{text}"))
}

// ---------------------------------------------------------------------------

#[test]
fn a_successful_call_produces_the_stable_envelope_and_exit_zero() {
    let (output, observed) = run_against_mock(
        "ok",
        &["root", "list", "--json"],
        Reply::Result(serde_json::json!({
            "roots": [{
                "root_id": 1,
                "path": "/srv/data",
                "enabled": true,
                "stub_mode": "delete",
                "hosted_optin": false,
                "availability": "available",
                "resync_required": false,
                "path_case_policy": "sensitive",
                "path_norm_policy": "preserve",
                "atime_mode": "relatime",
                "file_count": 12,
                "bytes_total": 4096
            }]
        })),
    );

    // The client's side of the conversation.
    assert_eq!(observed.hello["jsonrpc"], serde_json::json!("2.0"));
    assert_eq!(observed.hello["method"], serde_json::json!("hello"));
    // Against `PROTO_VERSION`, not a literal: the property is "the client
    // announces what this build actually speaks". A literal here would have to
    // be edited on every additive minor bump, and a test edited that often
    // stops being read. The literal is pinned once, in `shepherd-proto`, where
    // an accidental bump is the thing being guarded.
    assert_eq!(
        observed.hello["params"]["proto_version"],
        serde_json::json!({
            "major": shepherd_proto::PROTO_VERSION.major,
            "minor": shepherd_proto::PROTO_VERSION.minor,
        })
    );
    assert_eq!(
        observed.hello["params"]["client"]["name"],
        serde_json::json!("shepctl")
    );
    assert_eq!(observed.request["method"], serde_json::json!("root.list"));
    assert!(
        observed.request["params"].is_object(),
        "params must be an object even when empty: {}",
        observed.request["params"]
    );

    // The envelope the script sees.
    assert_eq!(output.status.code(), Some(0));
    let env = envelope(&output);
    assert_eq!(env["schema_version"], serde_json::json!(1));
    assert_eq!(env["ok"], serde_json::json!(true));
    assert_eq!(
        env["data"]["roots"][0]["path"],
        serde_json::json!("/srv/data")
    );
    assert_eq!(env["error"], serde_json::Value::Null);
    assert_eq!(env["warnings"], serde_json::json!([]));

    // The §4.3 correction, observed at the boundary rather than asserted in a
    // unit test: no JSON-RPC framing reaches the script.
    for framing in ["jsonrpc", "id", "result", "method", "params"] {
        assert!(
            env.get(framing).is_none(),
            "`{framing}` leaked from the transport into the CLI envelope"
        );
    }
}

#[test]
fn arguments_reach_the_daemon_as_the_typed_request_the_schema_describes() {
    let (_, observed) = run_against_mock(
        "args",
        &[
            "root",
            "add",
            "/srv/photos",
            "--stub-mode",
            "dehydrate",
            "--hosted-optin",
            "--json",
        ],
        Reply::Result(serde_json::json!({"root": null, "warnings": []})),
    );
    let params = &observed.request["params"];
    assert_eq!(observed.request["method"], serde_json::json!("root.add"));
    assert_eq!(params["path"], serde_json::json!("/srv/photos"));
    assert_eq!(params["stub_mode"], serde_json::json!("dehydrate"));
    assert_eq!(params["hosted_optin"], serde_json::json!(true));

    // The params the CLI built must deserialize into the registered request
    // type. The daemon will do exactly this, so a mismatch here is a bug the
    // daemon would hit first.
    shepherd_proto::Method::from_parts("root.add", params).expect("params match the schema");
}

#[test]
fn a_daemon_error_becomes_a_stable_slug_and_exit_one() {
    let (output, _) = run_against_mock(
        "err",
        &["root", "remove", "--root-id", "9", "--json"],
        Reply::Error {
            // 1003 = NotFound.
            code: 1003,
            message: "no root with id 9",
        },
    );
    assert_eq!(output.status.code(), Some(1));
    let env = envelope(&output);
    assert_eq!(env["ok"], serde_json::json!(false));
    assert_eq!(env["error"]["code"], serde_json::json!("not_found"));
    assert_eq!(
        env["error"]["message"],
        serde_json::json!("no root with id 9")
    );
    assert_eq!(env["data"], serde_json::Value::Null);
}

#[test]
fn an_unimplemented_method_is_distinguishable_from_every_other_failure() {
    // The Phase 1/Phase 2 seam: `tier.run` is registered now and served later.
    // A script must be able to tell "not built yet" from "you typed it wrong"
    // and from "it failed", which is why the code has its own exit status.
    let (output, _) = run_against_mock(
        "notimpl",
        &[
            "tier",
            "run",
            "--plan-id",
            "p1",
            "--candidate-set-hash",
            "ab",
            "--json",
        ],
        Reply::Error {
            // 1001 = MethodNotImplemented.
            code: 1001,
            message: "tier.run lands in Phase 2",
        },
    );
    assert_eq!(output.status.code(), Some(4));
    let env = envelope(&output);
    assert_eq!(env["error"]["code"], serde_json::json!("not_implemented"));
    assert!(
        env["error"]["hint"]
            .as_str()
            .unwrap()
            .contains("not served"),
        "{}",
        env["error"]["hint"]
    );
}

#[test]
fn an_error_code_this_client_has_never_heard_of_still_produces_an_envelope() {
    // Forward compatibility at the process boundary: a daemon newer than this
    // build must not turn into "the daemon is speaking gibberish".
    let (output, _) = run_against_mock(
        "future",
        &["status", "--json"],
        Reply::Error {
            code: 1099,
            message: "spend cap exceeded",
        },
    );
    assert_eq!(output.status.code(), Some(1));
    let env = envelope(&output);
    assert_eq!(env["error"]["code"], serde_json::json!("unknown_error"));
    assert_eq!(
        env["error"]["message"],
        serde_json::json!("spend cap exceeded")
    );
}

#[test]
fn a_result_field_this_client_has_never_heard_of_is_passed_through() {
    // The envelope's `data` is the daemon's payload verbatim. A newer daemon's
    // extra field must reach `jq`, not be filtered by the client's idea of the
    // schema.
    let (output, _) = run_against_mock(
        "extra",
        &["scan", "status", "--json"],
        Reply::Result(serde_json::json!({
            "scans": [],
            "added_in_a_later_minor": {"nested": 1}
        })),
    );
    assert_eq!(output.status.code(), Some(0));
    let env = envelope(&output);
    assert_eq!(
        env["data"]["added_in_a_later_minor"]["nested"],
        serde_json::json!(1)
    );
}

#[test]
fn a_usage_error_never_reaches_the_socket() {
    // No mock at all: the socket path does not exist. A bad argument must fail
    // at parse time with clap's exit code 2, not as an unreachable-daemon
    // error, or a typo would be reported as an outage.
    let output = Command::new(env!("CARGO_BIN_EXE_shepctl"))
        .args([
            "--socket",
            "/tmp/shepctl-nonexistent-usage-test.sock",
            "root",
            "add",
            "/x",
            "--stub-mode",
            "vaporize",
        ])
        .output()
        .expect("run shepctl");
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("vaporize"), "{stderr}");
}
