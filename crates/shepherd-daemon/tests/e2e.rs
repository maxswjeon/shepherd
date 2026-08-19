//! End-to-end: a real `shepherdd` process, driven by a real client.
//!
//! This is the test that retires T5's standing caveat — "shepctl has never
//! spoken to a real daemon". Two clients exercise the same daemon:
//!
//! 1. a **typed client** built from `shepherd-proto`, which is what most of the
//!    assertions use because it can inspect frames the CLI deliberately hides;
//! 2. the **real `shepctl` binary**, so the whole path — argv → clap tree →
//!    request → socket → daemon → response → stable envelope → exit code — is
//!    covered by something no unit test can fake.
//!
//! What it does not prove: anything about macOS or Windows (Unix-only, and the
//! Windows transport is Phase 3), and nothing about behaviour under a real
//! `kill -9` (the queue's own `kill_and_resume_of_a_checkpointed_job` covers
//! the durable-state half of that).

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use shepherd_proto::request::RpcRequest;
use shepherd_proto::response::RpcResponse;
use shepherd_proto::{Hello, PROTO_VERSION, PeerInfo, ProtoVersion, RequestId};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A running daemon in its own state directory, killed on drop.
struct Daemon {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
}

impl Daemon {
    fn start(tag: &str) -> Daemon {
        let dir = std::env::temp_dir().join(format!("shepherdd-e2e-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let socket = dir.join("daemon.sock");

        let child = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
            .arg("run")
            .env("SHEPHERD_STATE_DIR", &dir)
            .env("SHEPHERD_SOCKET", &socket)
            .spawn()
            .expect("spawn shepherdd");

        let d = Daemon { child, dir, socket };
        d.wait_until_listening();
        d
    }

    fn wait_until_listening(&self) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if UnixStream::connect(&self.socket).is_ok() {
                return;
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        panic!(
            "shepherdd did not start listening on {} within 20s",
            self.socket.display()
        );
    }

    fn connect(&self) -> Client {
        Client::connect(&self.socket)
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// A typed client: handshake, then one call at a time.
struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: i64,
    hello: serde_json::Value,
}

impl Client {
    fn connect(socket: &Path) -> Client {
        Self::connect_as(socket, PROTO_VERSION)
    }

    /// Connect announcing a specific protocol version, for the skew tests.
    fn connect_as(socket: &Path, version: ProtoVersion) -> Client {
        let stream = UnixStream::connect(socket).expect("connect");
        stream
            .set_read_timeout(Some(Duration::from_secs(20)))
            .unwrap();
        let mut c = Client {
            reader: BufReader::new(stream.try_clone().unwrap()),
            writer: stream,
            next_id: 0,
            hello: serde_json::Value::Null,
        };
        let hello = Hello {
            proto_version: version,
            client: PeerInfo {
                name: "e2e".into(),
                build: "0".into(),
            },
            capabilities: vec![],
        };
        c.hello = c.raw("hello", serde_json::to_value(hello).unwrap());
        c
    }

    /// Send a frame and read the reply, returning the whole response object.
    fn raw(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        self.next_id += 1;
        let req = RpcRequest::new(RequestId::Number(self.next_id), method, params);
        let mut line = serde_json::to_string(&req).unwrap();
        line.push('\n');
        self.writer.write_all(line.as_bytes()).unwrap();
        self.writer.flush().unwrap();
        self.read_frame()
    }

    fn read_frame(&mut self) -> serde_json::Value {
        let mut buf = String::new();
        let n = self.reader.read_line(&mut buf).expect("read");
        assert!(n > 0, "the daemon closed the connection");
        serde_json::from_str(&buf).unwrap_or_else(|e| panic!("not JSON: {e}\n{buf}"))
    }

    /// Widen the socket read timeout for a corpus that is not nine files.
    ///
    /// The twenty seconds in `connect_as` is sized for a daemon holding a
    /// handful of rows. At M1 scale a single `search` can ask the dispatcher to
    /// hydrate tens of thousands of rows and serialise several megabytes of
    /// JSON before the first byte comes back, and the response is built whole
    /// rather than streamed — so the client's first `read` waits out the entire
    /// server-side cost. A timeout tuned to the small tests turns that into
    /// "the daemon closed the connection", which is a false red about a daemon
    /// that was working. This does not relax any deadline that means anything:
    /// scan progress is still bounded by `SCAN_STALL_BUDGET`.
    fn set_read_timeout(&mut self, t: Duration) {
        self.writer.set_read_timeout(Some(t)).unwrap();
        self.reader.get_ref().set_read_timeout(Some(t)).unwrap();
    }

    /// Call and require success.
    fn call(&mut self, method: &str, params: serde_json::Value) -> serde_json::Value {
        let frame = self.raw(method, params);
        let parsed: RpcResponse = serde_json::from_value(frame.clone()).unwrap();
        parsed
            .outcome()
            .unwrap_or_else(|e| panic!("{method} failed: {e}\n{frame}"))
    }

    /// Call and require failure, returning the error object.
    fn call_err(&mut self, method: &str, params: serde_json::Value) -> shepherd_proto::RpcError {
        let frame = self.raw(method, params);
        let parsed: RpcResponse = serde_json::from_value(frame).unwrap();
        parsed
            .outcome()
            .expect_err(&format!("{method} unexpectedly succeeded"))
    }
}

/// Locate `shepctl`, building it if this test run did not.
///
/// `CARGO_BIN_EXE_*` only covers binaries of *this* package, so the sibling has
/// to be found. Building on demand rather than skipping: a test that quietly
/// does nothing when a binary is missing is the vacuous pass this project keeps
/// finding in its own gates.
fn shepctl() -> PathBuf {
    let mine = PathBuf::from(env!("CARGO_BIN_EXE_shepherdd"));
    let target_dir = mine.parent().expect("binary has a parent directory");
    let candidate = target_dir.join("shepctl");
    if candidate.exists() {
        return candidate;
    }
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-p", "shepherd-cli", "--bin", "shepctl"])
        .output()
        .expect("build shepctl");
    assert!(
        candidate.exists(),
        "shepctl was not built at {}: {}",
        candidate.display(),
        String::from_utf8_lossy(&out.stderr)
    );
    candidate
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[test]
fn the_daemon_handshakes_and_reports_status() {
    let d = Daemon::start("status");
    let mut c = d.connect();

    let hello: RpcResponse = serde_json::from_value(c.hello.clone()).unwrap();
    let result = hello.outcome().expect("handshake accepted");
    assert_eq!(result["server"]["name"], serde_json::json!("shepherdd"));
    assert_eq!(
        result["proto_version"],
        serde_json::json!({"major": PROTO_VERSION.major, "minor": PROTO_VERSION.minor})
    );
    assert_eq!(
        result["negotiated"]["minor"],
        serde_json::json!(PROTO_VERSION.minor)
    );

    let status = c.call("status", serde_json::json!({}));
    assert_eq!(status["roots"], serde_json::json!(0));
    assert_eq!(status["files_catalogued"], serde_json::json!(0));
    assert_eq!(
        status["negotiated_minor"],
        serde_json::json!(PROTO_VERSION.minor)
    );
    assert!(
        status["jobs_pending"].is_array(),
        "queue depth must be present even when empty"
    );
}

/// §4.3: the connection opens with `hello`. Until it has, the negotiated minor
/// is unknown, so no method can be gated correctly.
#[test]
fn a_connection_that_skips_the_handshake_is_refused() {
    let d = Daemon::start("nohello");
    let stream = UnixStream::connect(&d.socket).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let req = RpcRequest::new(RequestId::Number(1), "status", serde_json::json!({}));
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    writer.write_all(line.as_bytes()).unwrap();
    writer.flush().unwrap();

    let mut buf = String::new();
    reader.read_line(&mut buf).unwrap();
    let frame: RpcResponse = serde_json::from_str(&buf).unwrap();
    let err = frame.outcome().unwrap_err();
    assert_eq!(err.kind(), Some(shepherd_proto::ErrorCode::InvalidRequest));
    assert!(err.message.contains("hello"), "{}", err.message);
}

/// The skew case §4.3 calls the most common one, end to end.
#[test]
fn a_major_version_mismatch_is_rejected_with_both_versions_named() {
    let d = Daemon::start("skew");
    let stream = UnixStream::connect(&d.socket).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let hello = Hello {
        proto_version: ProtoVersion::new(PROTO_VERSION.major + 1, 0),
        client: PeerInfo {
            name: "from-the-future".into(),
            build: "9".into(),
        },
        capabilities: vec![],
    };
    let req = RpcRequest::new(
        RequestId::Number(1),
        "hello",
        serde_json::to_value(hello).unwrap(),
    );
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    writer.write_all(line.as_bytes()).unwrap();
    writer.flush().unwrap();

    let mut buf = String::new();
    reader.read_line(&mut buf).unwrap();
    let frame: RpcResponse = serde_json::from_str(&buf).unwrap();
    let err = frame.outcome().unwrap_err();
    assert_eq!(err.kind(), Some(shepherd_proto::ErrorCode::VersionMismatch));
    assert!(
        err.message.contains(&PROTO_VERSION.to_string()),
        "{}",
        err.message
    );
    assert!(err.message.contains(shepherd_proto::UPGRADE_COMMAND));
    // The structured half, for a UI that wants to render it.
    let data = err.data.expect("VersionMismatch travels as data");
    assert_eq!(
        data["server"]["major"],
        serde_json::json!(PROTO_VERSION.major)
    );
}

/// The additive machinery, proven against a live daemon rather than a unit
/// test: `doctor` is `since = 1`, so a client that negotiated minor 0 must not
/// see it — and must be told it does not exist, not that it is forbidden.
#[test]
fn a_method_above_the_negotiated_minor_is_invisible() {
    let d = Daemon::start("gating");

    let mut old = Client::connect_as(&d.socket, ProtoVersion::new(PROTO_VERSION.major, 0));
    let err = old.call_err("doctor", serde_json::json!({}));
    assert_eq!(err.kind(), Some(shepherd_proto::ErrorCode::MethodNotFound));
    assert!(
        !err.message.to_lowercase().contains("minor"),
        "the newer surface must not be leaked to a client that cannot use it: {}",
        err.message
    );
    // The same daemon, a current client: served.
    let mut current = d.connect();
    let out = current.call("doctor", serde_json::json!({}));
    assert_eq!(out["source"], serde_json::json!("daemon"));
}

#[test]
fn roots_can_be_added_listed_and_removed() {
    let d = Daemon::start("roots");
    let mut c = d.connect();
    let root_dir = d.dir.join("corpus");
    std::fs::create_dir_all(root_dir.join("nested")).unwrap();
    std::fs::write(root_dir.join("a.txt"), b"hello").unwrap();

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    assert_eq!(
        added["root"]["path"],
        serde_json::json!(root_dir.to_str().unwrap())
    );
    // §4.9: probed at enrollment, never assumed.
    assert!(added["root"]["path_case_policy"].is_string());
    assert!(added["root"]["atime_mode"].is_string());

    let listed = c.call("root.list", serde_json::json!({}));
    assert_eq!(listed["roots"].as_array().unwrap().len(), 1);

    let status = c.call("status", serde_json::json!({}));
    assert_eq!(status["roots"], serde_json::json!(1));

    let removed = c.call("root.remove", serde_json::json!({"root_id": root_id}));
    assert_eq!(removed["root_id"], serde_json::json!(root_id));
    assert_eq!(
        c.call("root.list", serde_json::json!({}))["roots"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
}

#[test]
fn adding_a_root_that_is_not_a_directory_is_refused_before_anything_is_written() {
    let d = Daemon::start("badroot");
    let mut c = d.connect();

    let err = c.call_err(
        "root.add",
        serde_json::json!({"path": "relative/path", "stub_mode": "delete"}),
    );
    assert_eq!(err.kind(), Some(shepherd_proto::ErrorCode::Invalid));

    let err = c.call_err(
        "root.add",
        serde_json::json!({"path": "/nonexistent-xyzzy-4242", "stub_mode": "delete"}),
    );
    assert_eq!(err.kind(), Some(shepherd_proto::ErrorCode::NotFound));

    assert_eq!(
        c.call("status", serde_json::json!({}))["roots"],
        serde_json::json!(0),
        "a refused root.add must not have created anything"
    );
}

/// §3: Linux is delete-mode only. Accepting `dehydrate` here would enroll a
/// root whose stub mode nothing on this platform can honour.
#[cfg(target_os = "linux")]
#[test]
fn dehydrate_mode_is_refused_on_linux() {
    let d = Daemon::start("stubmode");
    let mut c = d.connect();
    let root_dir = d.dir.join("corpus2");
    std::fs::create_dir_all(&root_dir).unwrap();

    let err = c.call_err(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "dehydrate"}),
    );
    assert_eq!(err.kind(), Some(shepherd_proto::ErrorCode::Refused));
    assert!(err.message.contains("delete-mode only"), "{}", err.message);
}

#[test]
fn scan_start_enqueues_a_job_and_scan_status_reports_it() {
    let d = Daemon::start("scan");
    let mut c = d.connect();
    let root_dir = d.dir.join("corpus3");
    std::fs::create_dir_all(&root_dir).unwrap();
    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();

    let started = c.call("scan.start", serde_json::json!({}));
    assert_eq!(started["roots_started"], serde_json::json!([root_id]));
    assert_eq!(started["job_ids"].as_array().unwrap().len(), 1);

    let state = c.call("scan.status", serde_json::json!({}));
    let scans = state["scans"].as_array().unwrap();
    assert_eq!(scans.len(), 1);
    assert_eq!(scans[0]["root_id"], serde_json::json!(root_id));

    // No scan executor is registered at Phase 1, so the job must remain queued
    // rather than being failed — otherwise it would burn its retry budget
    // against a build that was never going to run it.
    let status = c.call("status", serde_json::json!({}));
    let scan_depth = status["jobs_pending"]
        .as_array()
        .unwrap()
        .iter()
        .find(|d| d["class"] == serde_json::json!("scan"))
        .expect("a scan class row");
    assert_eq!(scan_depth["failed"], serde_json::json!(0));
}

/// The Phase 1/Phase 2 seam, over a real socket.
/// Params that reach each method's **handler**, so the probe below measures
/// whether a method is served rather than whether its payload parsed.
///
/// The distinction is the whole test. A refused method still deserializes its
/// request before the handler refuses it, so a probe sending `{}` to
/// `tier.run` gets `InvalidParams` — and a probe that treated that as "not a
/// refusal" would classify an unserved method as served. That is a false
/// green, and false greens are what this file exists to prevent.
///
/// Values are deliberately ones that do not need setup: ids that will not
/// exist, a path that will not exist. A served method answering `NotFound` has
/// been *reached*, which is what is being measured.
///
/// Exhaustive by construction: an unhandled method panics naming itself, so
/// adding a method to the registry fails here until someone decides how to
/// probe it. A `_ => json!({})` arm would have made this list rot silently.
fn probe_params(method: &str) -> serde_json::Value {
    match method {
        "root.add" => serde_json::json!({
            // `delete`, not `dehydrate`: dehydrate is refused on Linux, and a
            // refusal is still "reached", but using the mode with its own
            // refusal test would make this probe depend on that one's verdict.
            "path": "/nonexistent/shepherd-reachability-probe",
            "stub_mode": "delete",
        }),
        "root.list" => serde_json::json!({}),
        "root.remove" => serde_json::json!({"root_id": 999_999}),
        "scan.start" => serde_json::json!({}),
        "scan.status" => serde_json::json!({}),
        "search" => serde_json::json!({"query": "probe"}),
        "status" => serde_json::json!({}),
        "target.add" => serde_json::json!({"name": "probe", "adapter": "s3"}),
        "target.list" => serde_json::json!({}),
        "target.test" => serde_json::json!({"target_id": 999_999}),
        "rule.list" => serde_json::json!({}),
        "rule.preview" => serde_json::json!({"rule_id": 999_999}),
        "tier.plan" => serde_json::json!({"rule_id": 999_999, "target_id": 999_999}),
        "tier.run" => serde_json::json!({"plan_id": "probe", "candidate_set_hash": "ab"}),
        "restore" => serde_json::json!({"file_id": 999_999}),
        "doctor" => serde_json::json!({}),
        "events.subscribe" => serde_json::json!({}),
        other => panic!(
            "`{other}` is in the method registry and this probe does not know how to call it. \
             Add params that reach its handler — not `{{}}`, unless its request has no required \
             fields. Until then the reachability probe covers {} of the registry, and a probe \
             that silently skipped a method would report a smaller, cleaner, wrong answer",
            shepherd_proto::MethodKind::ALL.len() - 1
        ),
    }
}

/// **Every method in the registry, called over the real IPC surface, and the
/// refused set asserted by identity.**
///
/// This replaces a hand-kept list of four methods that asserted only that those
/// four refuse. Two things that list could not do, and this does:
///
/// * It covered four of the eight unserved methods. `target.add`,
///   `target.test`, `rule.preview` and `tier.plan` were refused by the daemon
///   and named by no test at all.
/// * A method that **stopped** being served would not have failed it. That is
///   the direction that produces a false green: a regression unwiring a method
///   from the daemon reads as no change, because the list only knew about
///   methods someone had thought to add to it.
///
/// The set is derived from `MethodKind::ALL` rather than typed out, so the
/// registry is the authority here exactly as it is in `codegen` and in
/// `xtask`'s static scan. `xtask gate --audit` reads the same fact out of
/// `dispatch.rs`'s source; this reads it out of the daemon's actual answers,
/// which is the only version that catches a method wired to a stub.
///
/// **When this fails because a method started being served, that is the good
/// failure**: move it out of `UNSERVED` and Phase 2 gets closer to reachable.
#[test]
fn every_registry_method_is_probed_and_exactly_the_recorded_ones_are_refused() {
    use shepherd_proto::{ErrorCode, MethodKind};
    use std::collections::BTreeSet;

    /// The refusals `dispatch.rs` records today, all naming Phase 2.
    /// `search.filters.path_glob` is a capability rather than a method and is
    /// asserted separately below.
    ///
    /// **`target.add` carries an ordering constraint, and this is the only place
    /// anyone is forced to read it.** `S3Config::multipart_checksum` decides
    /// whether an S3 upload requests a **whole-object** checksum, and `s3.rs`'s
    /// own doc says the value must be probed *at registration* because a
    /// checksum not requested at upload **cannot be retrofitted without
    /// re-uploading the object**. Serving `target.add` without probing would
    /// permanently fix every object written through that target into the
    /// no-checksum configuration — measured at ADR 0b §3 as **$441/month
    /// against $0.68** on a 50 TB corpus, 649x, per object, irreversible.
    ///
    /// That has been harmless only because `target.add` is refused: with no way
    /// to register a target there are no objects to strand.
    ///
    /// **The producer now exists** — `shepherd_storage::s3::probe_multipart_checksum`
    /// (E-5's settled design: probe at registration, adopt the first of
    /// CRC64NVME → CRC32C → CRC32 that round-trips, record the outcome **with
    /// its evidence** rather than as a boolean). So the constraint is no longer
    /// "a probe must be written" but "the probe must be CALLED":
    ///
    /// > Whoever deletes `"target.add"` from this list owes a call to
    /// > `probe_multipart_checksum` on the registration path, and must persist
    /// > its `ChecksumProbe` — including the per-algorithm reasons behind a
    /// > negative. `Ok(adopted: None)` is a legitimate provider answer;
    /// > `Err(_)` means the provider was never reached and must fail the
    /// > registration rather than be stored as "supports nothing", because a
    /// > false negative there is silent, permanent and indistinguishable from a
    /// > real measurement.
    ///
    /// Serving it also needs a Phase-2 registration path that does not exist:
    /// `shepherd-daemon` has no `tokio` runtime and no `shepherd-storage` edge,
    /// and nothing parses `TargetAddRequest::config` or resolves
    /// `credentials_ref`. That is why this row still stands.
    const UNSERVED: &[&str] = &[
        "restore",
        "rule.list",
        "rule.preview",
        // See the ordering constraint above before serving this one.
        "target.add",
        "target.list",
        "target.test",
        "tier.plan",
        "tier.run",
    ];

    let d = Daemon::start("reachability");

    let mut refused: BTreeSet<&str> = BTreeSet::new();
    let mut reached: BTreeSet<&str> = BTreeSet::new();

    for kind in MethodKind::ALL {
        let name = kind.name();
        // A fresh connection per method. `events.subscribe` puts its connection
        // into a streaming state, so a shared connection would have the next
        // method's reply read an event frame instead — a cross-talk failure
        // that would look like the method misbehaving.
        let mut c = d.connect();
        let frame = c.raw(name, probe_params(name));
        let parsed: RpcResponse = serde_json::from_value(frame.clone())
            .unwrap_or_else(|e| panic!("{name}: {e}\n{frame}"));

        match parsed.outcome() {
            Ok(_) => {
                reached.insert(name);
            }
            Err(e) => {
                // Two error codes mean the probe itself is broken, and both
                // would otherwise silently classify an unserved method as
                // served. They are assertions, not classifications.
                assert_ne!(
                    e.kind(),
                    Some(ErrorCode::InvalidParams),
                    "{name}: the probe's params did not deserialize, so this call never reached \
                     the handler and says nothing about whether the method is served. Fix \
                     `probe_params`; do not let it count as reached. ({})",
                    e.message
                );
                assert_ne!(
                    e.kind(),
                    Some(ErrorCode::MethodNotFound),
                    "{name}: the daemon does not know this method at the negotiated protocol \
                     version, so this probe is measuring a surface the client cannot see"
                );
                if e.kind() == Some(ErrorCode::MethodNotImplemented) {
                    assert!(
                        e.message.contains("Phase"),
                        "{name} is refused without saying when it lands: {}. A refusal that \
                         names its owning phase is a promise; one that does not is a permanent \
                         hole, and `xtask gate --phase` cannot attribute it to any gate",
                        e.message
                    );
                    refused.insert(name);
                } else {
                    reached.insert(name);
                }
            }
        }
    }

    // The count assertion. Everything above is per-method; this is what makes
    // the whole set a fact rather than a sample.
    assert_eq!(
        refused.len() + reached.len(),
        MethodKind::ALL.len(),
        "{} of {} registry methods were classified — a probe that skipped one would report a \
         cleaner answer over a smaller set",
        refused.len() + reached.len(),
        MethodKind::ALL.len()
    );
    let recorded: BTreeSet<&str> = UNSERVED.iter().copied().collect();
    assert_eq!(
        refused, recorded,
        "the set of methods the daemon refuses is not the recorded one.\n  refused now: {:?}\
         \n  recorded:    {:?}\nIf a method started being served, delete it from UNSERVED — that \
         is the good direction. If one stopped, something unwired it from the daemon and no \
         per-AC test would have noticed.\n\
         \nIF THE CHANGE IS `target.add`, READ THIS FIRST: serving it requires the registration \
         path to CALL `shepherd_storage::s3::probe_multipart_checksum` and persist the \
         `ChecksumProbe` it returns. A checksum not requested at upload cannot be retrofitted \
         without re-uploading, so every object written through an unprobed target is permanently \
         in the no-checksum configuration — $441/month against $0.68 on 50 TB, 649x (ADR 0b §3). \
         The probe adopts the first of CRC64NVME -> CRC32C -> CRC32 that round-trips and records \
         per-algorithm evidence rather than a boolean. `Ok(adopted: None)` is a real provider \
         answer and is safe; `Err(_)` means the provider was never reached and MUST fail the \
         registration, never be stored as `unsupported`. See open-questions E-5.",
        refused, recorded
    );
    assert!(
        !reached.is_empty() && !refused.is_empty(),
        "both sets must be non-empty or the probe measured nothing"
    );
}

/// A capability refused **inside a served method** is unreachable too.
///
/// `search` answers normally and refuses its `path_glob` filter, naming Phase
/// 2. Nothing method-level sees this: `search` is served, its tests pass, and a
/// user asking for a glob gets `MethodNotImplemented`. It is the ninth Phase-2
/// refusal, and the one a method-granularity check passes cleanly.
#[test]
fn a_capability_refused_inside_a_served_method_is_still_unreachable() {
    let d = Daemon::start("reachability-cap");
    let mut c = d.connect();

    // The control: without the filter, search is served. Without this the test
    // below would also pass against a daemon that had stopped serving `search`
    // altogether, which is a different and worse fact.
    let ok = c.raw("search", serde_json::json!({"query": "probe"}));
    let ok: RpcResponse = serde_json::from_value(ok).unwrap();
    assert!(ok.outcome().is_ok(), "search itself must be served");

    let err = c.call_err(
        "search",
        serde_json::json!({"query": "probe", "filters": {"path_glob": "*.rs"}}),
    );
    assert_eq!(
        err.kind(),
        Some(shepherd_proto::ErrorCode::MethodNotImplemented),
        "the glob filter is refused, not silently ignored — a silently dropped filter would \
         return MORE results than the user asked for, which is the failure shape a destructive \
         rule cannot afford: {}",
        err.message
    );
    assert!(
        err.message.contains("Phase 2"),
        "the refusal must name its owning phase: {}",
        err.message
    );
}

// ---------------------------------------------------------------------------
// The M1 demo: root add -> scan -> search
// ---------------------------------------------------------------------------

/// Wait for the root's scan to finish, then assert it catalogued `expect` files.
///
/// Waiting matters more than it looks: a search racing an unfinished scan
/// returns *fewer* hits, and a smaller number is exactly the shape of a passing
/// test. Asserting the catalogued count here means every search assertion below
/// runs against a corpus of known size. `wait_for_scan` is the scan executor's
/// own helper, reused so there is one definition of "the scan is done".
fn scan_and_expect(c: &mut Client, root_id: i64, expect: u64) {
    let scan = wait_for_scan(c, root_id);
    assert!(scan["last_error"].is_null(), "the scan failed: {scan}");
    assert_eq!(
        scan["files_seen"],
        serde_json::json!(expect),
        "the scan walked a different number of files than were written: {scan}"
    );
    let status = c.call("status", serde_json::json!({}));
    assert_eq!(
        status["files_catalogued"],
        serde_json::json!(expect),
        "the walk saw {expect} files but the catalog holds a different number: {status}"
    );
}

fn write_file(dir: &Path, rel: &str, body: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, body).unwrap();
}

/// §6 Phase 1's M1 demo, over a real socket, with the counts asserted.
///
/// **The point of this test is the pair of numbers, not the exit code.** The
/// recurring defect it is written against is instance #3 — an index that
/// benchmarked beautifully while matching zero documents. A `search` that always
/// returned `[]` would pass any assertion that only checks the call succeeded,
/// so every needle here asserts an exact hit count, and each is paired with a
/// needle in the same corpus that must return exactly zero.
#[test]
fn search_finds_scanned_files_and_misses_absent_ones() {
    let d = Daemon::start("search");
    let mut c = d.connect();
    let corpus = d.dir.join("corpus");

    // Nine files. `report` is in two filenames, in one directory name, and in
    // no others — so the right answer is 2, an answer of 0 is a broken index and
    // an answer of 9 is a broken scope check.
    write_file(&corpus, "notes/quarterly-report.pdf", "a");
    write_file(&corpus, "notes/alpha.md", "b");
    write_file(&corpus, "notes/beta.txt", "c");
    write_file(&corpus, "docs/Annual_REPORTING_2025.docx", "d");
    write_file(&corpus, "reports/summary.csv", "e");
    write_file(&corpus, "docs/gamma.txt", "f");
    write_file(&corpus, "docs/delta.txt", "g");
    write_file(&corpus, "archive/epsilon.log", "h");
    write_file(&corpus, "archive/zeta.log", "i");

    // The empty-catalog control, BEFORE the root exists. If this returned hits
    // the index would be matching something other than this daemon's catalog.
    let before = c.call("search", serde_json::json!({"query": "report"}));
    assert_eq!(
        before["total"],
        serde_json::json!(0),
        "an empty catalog cannot contain `report`: {before}"
    );
    assert_eq!(before["hits"].as_array().unwrap().len(), 0);

    // The plan writes this leg as `shepctl root add ./corpus`. Two corrections,
    // both reported to the lead: the path must be absolute (the daemon rejects
    // relative paths, and its cwd is not the caller's), and the scan command is
    // `scan start` — a bare `scan` leaf cannot exist, because proto's own
    // `no_cli_path_is_a_prefix_of_another` test forbids it.
    let added = c.call(
        "root.add",
        serde_json::json!({"path": corpus.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    c.call("scan.start", serde_json::json!({}));
    scan_and_expect(&mut c, root_id, 9);

    // --- the demo query -------------------------------------------------
    let hit = c.call("search", serde_json::json!({"query": "report"}));
    assert_eq!(
        hit["total"],
        serde_json::json!(2),
        "expected quarterly-report.pdf and Annual_REPORTING_2025.docx: {hit}"
    );
    let paths: Vec<&str> = hit["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["rel_path"].as_str().unwrap())
        .collect();
    assert!(paths.contains(&"notes/quarterly-report.pdf"), "{paths:?}");
    assert!(
        paths.contains(&"docs/Annual_REPORTING_2025.docx"),
        "case-insensitive matching is part of AC-40: {paths:?}"
    );
    assert!(
        !paths.contains(&"reports/summary.csv"),
        "`reports/` is a directory; a name query must not return everything under it: {paths:?}"
    );
    assert_eq!(hit["degraded"], serde_json::Value::Null);

    // A hydrated hit carries the catalog's view of the file, not just its name.
    let first = &hit["hits"][0];
    assert_eq!(first["root_id"], serde_json::json!(root_id));
    assert_eq!(first["state"], serde_json::json!("local"));
    assert_eq!(first["size"], serde_json::json!(1));
    assert!(first["file_id"].as_i64().unwrap() > 0);
    // Hashing is its own job class and never gates cataloguing (§6 Phase 1), so
    // an unhashed file is `null` here rather than an invented value.
    assert!(first["blake3"].is_null() || first["blake3"].is_string());

    // --- the negative controls, same daemon, same index -----------------
    for absent in ["zzzz-no-such-file", "report.pdf.bak", "quarterly-reports"] {
        let miss = c.call("search", serde_json::json!({"query": absent}));
        assert_eq!(
            miss["total"],
            serde_json::json!(0),
            "`{absent}` is in no filename in the corpus: {miss}"
        );
    }

    // A path-scoped query reaches directory components; the same text without
    // the separator is a name query and finds nothing.
    let scoped = c.call("search", serde_json::json!({"query": "archive/"}));
    assert_eq!(scoped["total"], serde_json::json!(2), "{scoped}");
    let unscoped = c.call("search", serde_json::json!({"query": "archive"}));
    assert_eq!(unscoped["total"], serde_json::json!(0), "{unscoped}");

    // --- limit, offset and their honesty --------------------------------
    let page = c.call("search", serde_json::json!({"query": ".txt", "limit": 2}));
    assert_eq!(page["hits"].as_array().unwrap().len(), 2);
    assert_eq!(
        page["total"],
        serde_json::json!(2),
        "`limit` caps the page; three .txt files exist but only two were requested"
    );
    assert!(
        page["degraded"].as_str().unwrap().contains("lower bound"),
        "a capped scan must say its total is a floor: {page}"
    );
    let all_txt = c.call("search", serde_json::json!({"query": ".txt", "limit": 50}));
    assert_eq!(all_txt["total"], serde_json::json!(3), "{all_txt}");
    assert_eq!(all_txt["degraded"], serde_json::Value::Null);

    // Paging does not repeat or skip.
    let p0 = c.call(
        "search",
        serde_json::json!({"query": ".txt", "limit": 2, "offset": 0}),
    );
    let p1 = c.call(
        "search",
        serde_json::json!({"query": ".txt", "limit": 2, "offset": 2}),
    );
    let ids0: Vec<i64> = p0["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["file_id"].as_i64().unwrap())
        .collect();
    let ids1: Vec<i64> = p1["hits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|h| h["file_id"].as_i64().unwrap())
        .collect();
    assert_eq!(ids0.len(), 2);
    assert_eq!(ids1.len(), 1);
    assert!(
        ids1.iter().all(|id| !ids0.contains(id)),
        "page 2 repeated a row from page 1: {ids0:?} then {ids1:?}"
    );

    // --- filters narrow, and are applied to the catalog ------------------
    let filtered = c.call(
        "search",
        serde_json::json!({"query": ".txt", "filters": {"ext": ["txt"]}}),
    );
    assert_eq!(filtered["total"], serde_json::json!(3), "{filtered}");
    let none = c.call(
        "search",
        serde_json::json!({"query": ".txt", "filters": {"ext": ["pdf"]}}),
    );
    assert_eq!(
        none["total"],
        serde_json::json!(0),
        "no .txt file has extension pdf: {none}"
    );
    let by_state = c.call(
        "search",
        serde_json::json!({"query": ".txt", "filters": {"state": "remote"}}),
    );
    assert_eq!(
        by_state["total"],
        serde_json::json!(0),
        "nothing is tiered at Phase 1, so no file is `remote`: {by_state}"
    );

    // --- the modes that are declared but not served ----------------------
    let semantic = c.call(
        "search",
        serde_json::json!({"query": "report", "mode": "semantic"}),
    );
    assert_eq!(
        semantic["total"],
        serde_json::json!(2),
        "a degraded search still answers: {semantic}"
    );
    assert!(
        semantic["degraded"].as_str().unwrap().contains("Phase 5"),
        "a downgrade must travel with the result: {semantic}"
    );

    // --- refusals ---------------------------------------------------------
    let empty = c.call_err("search", serde_json::json!({"query": ""}));
    assert_eq!(empty.kind(), Some(shepherd_proto::ErrorCode::Invalid));
    let glob = c.call_err(
        "search",
        serde_json::json!({"query": "a", "filters": {"path_glob": "**/*.txt"}}),
    );
    assert_eq!(
        glob.kind(),
        Some(shepherd_proto::ErrorCode::MethodNotImplemented)
    );

    // --- doctor sees the index -------------------------------------------
    let doc = c.call("doctor", serde_json::json!({}));
    let index_check = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == serde_json::json!("metadata index"))
        .expect("doctor must report on the metadata index");
    assert_eq!(index_check["status"], serde_json::json!("ok"));
    assert!(
        index_check["detail"]
            .as_str()
            .unwrap()
            .contains("9 entries"),
        "doctor must report the real entry count, not a health colour: {index_check}"
    );
}

/// The CLI leg of the demo, through the real `shepctl` binary.
///
/// The typed client above proves the daemon; this proves the path a user
/// actually types, including `--json`'s stable envelope.
#[test]
fn shepctl_search_returns_json_a_script_can_read() {
    let d = Daemon::start("cli-search");
    let mut c = d.connect();
    let corpus = d.dir.join("corpus");
    write_file(&corpus, "q1-report.pdf", "x");
    write_file(&corpus, "q2-report.pdf", "y");
    write_file(&corpus, "unrelated.bin", "z");

    let run = |args: &[&str]| -> serde_json::Value {
        let out = Command::new(shepctl())
            .arg("--socket")
            .arg(&d.socket)
            .args(args)
            .output()
            .expect("run shepctl");
        assert!(
            out.status.success(),
            "shepctl {args:?} exited {:?}: {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice(&out.stdout).expect("shepctl --json emits one JSON document")
    };

    run(&[
        "root",
        "add",
        corpus.to_str().unwrap(),
        "--stub-mode",
        "delete",
        "--json",
    ]);
    let started = run(&["scan", "start", "--json"]);
    let root_id = started["data"]["roots_started"][0].as_i64().unwrap();
    scan_and_expect(&mut c, root_id, 3);

    let env = run(&["search", "report", "--json"]);
    assert_eq!(env["ok"], serde_json::json!(true), "{env}");
    assert_eq!(
        env["data"]["total"],
        serde_json::json!(2),
        "two of the three files are reports: {env}"
    );
    // The control, through the same binary and the same envelope.
    let miss = run(&["search", "nothing-matches-this", "--json"]);
    assert_eq!(miss["data"]["total"], serde_json::json!(0), "{miss}");
}

#[test]
fn doctor_reports_the_lingering_check_and_never_changes_it() {
    let d = Daemon::start("doctor");
    let mut c = d.connect();
    let out = c.call("doctor", serde_json::json!({}));

    let checks = out["checks"].as_array().unwrap();
    let lingering = checks
        .iter()
        .find(|c| c["name"] == serde_json::json!("systemd lingering"))
        .expect("the lingering check is always present");

    // Whatever this machine reports, the verdict must never be `fail` — OQ-F
    // makes lingering-off correct behaviour, not a fault.
    assert_ne!(lingering["status"], serde_json::json!("fail"));
    if lingering["status"] == serde_json::json!("warn") {
        let remediation = lingering["remediation"].as_str().unwrap_or_default();
        assert!(
            remediation.contains("loginctl"),
            "a warning must name the command: {remediation}"
        );
    }
    assert!(
        checks
            .iter()
            .any(|c| c["name"] == serde_json::json!("catalog")),
        "doctor must report on the catalog"
    );
}

#[test]
fn events_subscribe_answers_with_an_epoch_and_a_cursor() {
    let d = Daemon::start("events");
    let mut c = d.connect();
    let out = c.call("events.subscribe", serde_json::json!({}));
    assert!(out["subscription_id"].as_u64().unwrap() >= 1);
    assert!(!out["epoch"].as_str().unwrap().is_empty());
    assert_eq!(out["resume"]["outcome"], serde_json::json!("fresh"));
    assert!(out["next_seq"].as_u64().is_some());
    assert_eq!(
        out["streams"].as_array().unwrap().len(),
        6,
        "an empty request subscribes to every stream"
    );
}

/// A malformed frame must not kill the connection: the daemon answers and keeps
/// serving, or one bad `jq` pipeline would drop a UI's whole session.
#[test]
fn a_malformed_frame_is_answered_and_the_connection_survives() {
    let d = Daemon::start("malformed");
    let mut c = d.connect();

    c.writer.write_all(b"{not json at all\n").unwrap();
    c.writer.flush().unwrap();
    let frame = c.read_frame();
    let parsed: RpcResponse = serde_json::from_value(frame).unwrap();
    assert_eq!(
        parsed.outcome().unwrap_err().kind(),
        Some(shepherd_proto::ErrorCode::ParseError)
    );

    // Still usable.
    let status = c.call("status", serde_json::json!({}));
    assert!(status["build"].is_string());
}

#[test]
fn two_clients_are_served_concurrently() {
    let d = Daemon::start("concurrent");
    let mut a = d.connect();
    let mut b = d.connect();
    let root_dir = d.dir.join("corpus4");
    std::fs::create_dir_all(&root_dir).unwrap();

    a.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    // The second connection sees the first's write — the writer actor
    // serialises them, so there is one catalog and one answer.
    assert_eq!(
        b.call("root.list", serde_json::json!({}))["roots"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
}

/// The socket is the whole authorization model (§4.3), so its mode is asserted
/// against a live daemon, not only in a unit test.
#[test]
fn the_live_socket_is_owner_only() {
    use std::os::unix::fs::PermissionsExt;
    let d = Daemon::start("perms");
    let mode = std::fs::metadata(&d.socket).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600, "socket mode is {mode:04o}");
}

// ---------------------------------------------------------------------------
// The real CLI against the real daemon
// ---------------------------------------------------------------------------

/// **The test T5 could not write.** Every layer, both binaries, no mocks.
#[test]
fn shepctl_drives_a_real_daemon_end_to_end() {
    let d = Daemon::start("shepctl");
    let shepctl = shepctl();
    let root_dir = d.dir.join("corpus5");
    std::fs::create_dir_all(&root_dir).unwrap();
    std::fs::write(root_dir.join("report.txt"), b"x").unwrap();

    let run = |args: &[&str]| -> (i32, serde_json::Value, String) {
        let out = Command::new(&shepctl)
            .arg("--socket")
            .arg(&d.socket)
            .args(args)
            .output()
            .expect("run shepctl");
        let stdout = String::from_utf8_lossy(&out.stdout).to_string();
        let json = serde_json::from_str(&stdout).unwrap_or(serde_json::Value::Null);
        (out.status.code().unwrap_or(-1), json, stdout)
    };

    // status
    let (code, env, raw) = run(&["status", "--json"]);
    assert_eq!(code, 0, "{raw}");
    assert_eq!(env["ok"], serde_json::json!(true));
    assert_eq!(env["schema_version"], serde_json::json!(1));
    assert_eq!(env["data"]["roots"], serde_json::json!(0));
    // The §4.3 correction, at the outermost boundary there is: no JSON-RPC
    // framing reaches a script, even though a real daemon produced the payload.
    for framing in ["jsonrpc", "id", "result", "method", "params"] {
        assert!(env.get(framing).is_none(), "`{framing}` leaked: {raw}");
    }

    // root add — positional path, the M1 demo's shape
    let (code, env, raw) = run(&[
        "root",
        "add",
        root_dir.to_str().unwrap(),
        "--stub-mode",
        "delete",
        "--json",
    ]);
    assert_eq!(code, 0, "{raw}");
    assert_eq!(
        env["data"]["root"]["path"],
        serde_json::json!(root_dir.to_str().unwrap())
    );

    // scan start
    let (code, env, raw) = run(&["scan", "start", "--json"]);
    assert_eq!(code, 0, "{raw}");
    assert_eq!(env["data"]["job_ids"].as_array().unwrap().len(), 1);

    // doctor — the method added at 1.1, reached through the real CLI
    let (code, env, raw) = run(&["doctor", "--json"]);
    assert_eq!(code, 0, "{raw}");
    assert_eq!(env["data"]["source"], serde_json::json!("daemon"));

    // An unserved method: stable slug, and the documented exit code 4.
    //
    // This used to be `search`, which is now served (T7's metadata index).
    // `target list` inherits the role rather than the assertion being deleted —
    // exit code 4 is a documented part of the CLI contract and something has to
    // keep proving it reaches a script.
    let (code, env, raw) = run(&["target", "list", "--json"]);
    assert_eq!(code, 4, "{raw}");
    assert_eq!(env["ok"], serde_json::json!(false));
    assert_eq!(env["error"]["code"], serde_json::json!("not_implemented"));

    // `search` now succeeds through the same path. The *counts* are asserted by
    // `shepctl_search_returns_json_a_script_can_read`, which waits for the scan
    // first; this call deliberately does not wait, so it asserts only what is
    // true regardless of scan progress — that the method is served and the
    // envelope is well-formed.
    let (code, env, raw) = run(&["search", "report", "--json"]);
    assert_eq!(code, 0, "{raw}");
    assert_eq!(env["ok"], serde_json::json!(true), "{raw}");
    assert!(env["data"]["total"].is_u64(), "{raw}");
    assert!(env["data"]["hits"].is_array(), "{raw}");

    // Human output is not JSON and does not crash.
    let (code, _, raw) = run(&["root", "list"]);
    assert_eq!(code, 0);
    assert!(raw.contains("path:"), "{raw}");
}

/// `shepherdd doctor` with no daemon running — the §9 gate's seatless-VM shape.
///
/// The gate exercises this on a VM with lingering disabled, where the daemon
/// legitimately never starts. What is proven here is the half that does not
/// need a special VM: with nothing listening, the checks still run and still
/// report lingering — and, per AC-61, the message names the three things a
/// user needs in order to act: the socket path actually tried, the service
/// registration state (naming the real unit-file location, not a hardcoded
/// word), and the exact command to start the daemon — plus a stable, specific
/// exit code.
///
/// `HOME` and `XDG_CONFIG_HOME` are pinned to an empty directory under `dir`
/// so the registration state is deterministic regardless of whatever is
/// actually installed on the machine running this test — otherwise a dev box
/// with a real `shepherd.service` would flip both the text and the
/// remediation command and this test would go flaky.
#[test]
fn shepherdd_doctor_works_with_no_daemon_running() {
    let dir = std::env::temp_dir().join(format!("shepherdd-e2e-offline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = dir.join("home");
    let config = home.join(".config");
    std::fs::create_dir_all(&config).unwrap();
    let socket = dir.join("nothing.sock");
    // The exact path `shepherd-daemon::service::systemd::unit_path()` would
    // resolve given `XDG_CONFIG_HOME=config` — computed independently here
    // from the documented env-var contract, not by calling that function,
    // so this assertion cannot pass by tautology.
    let unit_path = config.join("systemd/user/shepherd.service");

    let run_doctor = || {
        Command::new(env!("CARGO_BIN_EXE_shepherdd"))
            .arg("doctor")
            .env("SHEPHERD_STATE_DIR", &dir)
            .env("SHEPHERD_SOCKET", &socket)
            .env("HOME", &home)
            .env("XDG_CONFIG_HOME", &config)
            .output()
            .expect("run shepherdd doctor")
    };

    let out = run_doctor();
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains("systemd lingering"),
        "the lingering check must run without a daemon: {text}"
    );

    // AC-61, 1 of 3: the socket path actually tried — not just the word
    // "daemon", which is the substring trap the AC calls out by name.
    assert!(
        text.contains(socket.to_str().unwrap()),
        "the message must name the exact socket path it tried: {text}"
    );
    // AC-61, 2 of 3: the registration state, naming the real unit-file
    // location this process would use.
    // `shepherdd_doctor_reports_the_daemon_as_registered_when_a_unit_file_exists`
    // proves this same line flips to "registered" once that file exists,
    // which is what makes this a load-bearing check rather than fixed text.
    assert!(
        text.contains(unit_path.to_str().unwrap()) && text.contains("not registered"),
        "the message must name the real unit path and say it is unregistered: {text}"
    );
    // AC-61, 3 of 3: a start command a user could paste.
    assert!(
        text.contains("shepherdd run"),
        "an unregistered daemon's remediation must be the foreground command: {text}"
    );

    // AC-61's "stable exit code": one observation of `success()` proves
    // nothing about stability, and would still pass if the code silently
    // changed from 0 to some other success-ish value. Two identical
    // invocations must return the same, specific code, and that code must
    // differ from a genuine failure's — otherwise the code carries no
    // information about which case the user is in.
    let code = out.status.code();
    assert_eq!(
        code,
        Some(0),
        "daemon-down is a warning, not a failure: {text}"
    );
    assert_eq!(
        code,
        run_doctor().status.code(),
        "the exit code must be stable across invocations of the same condition"
    );

    let failure = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
        .arg("doctor")
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .output()
        .expect("run shepherdd doctor with no environment");
    assert_eq!(
        failure.status.code(),
        Some(1),
        "an actual failure (no state directory can be resolved) must exit differently \
         from daemon-down: {}",
        String::from_utf8_lossy(&failure.stdout)
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// The registration line in `shepherdd doctor`'s daemon-down message is
/// load-bearing: it names whichever service unit actually exists on disk,
/// not a fixed string that would say "not registered" even with a unit file
/// sitting right there. Linux-only because it targets the systemd unit path;
/// `shepherdd_doctor_works_with_no_daemon_running` covers the unregistered
/// case, which is portable.
///
/// The expected path is built by hand from the same env-var contract the
/// unregistered test uses, not by calling `service::systemd::unit_path()` —
/// asserting against the output of the function under test would make this
/// pass even if that function's own path computation were wrong.
#[cfg(target_os = "linux")]
#[test]
fn shepherdd_doctor_reports_the_daemon_as_registered_when_a_unit_file_exists() {
    let dir = std::env::temp_dir().join(format!("shepherdd-e2e-registered-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let home = dir.join("home");
    let config = home.join(".config");
    let unit_dir = config.join("systemd/user");
    std::fs::create_dir_all(&unit_dir).unwrap();
    let unit_path = unit_dir.join("shepherd.service");
    std::fs::write(&unit_path, "[Unit]\n").unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
        .arg("doctor")
        .env("SHEPHERD_STATE_DIR", &dir)
        .env("SHEPHERD_SOCKET", dir.join("nothing.sock"))
        .env("HOME", &home)
        .env("XDG_CONFIG_HOME", &config)
        .output()
        .expect("run shepherdd doctor");
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains(unit_path.to_str().unwrap()) && text.contains("registered:"),
        "a unit file on disk must flip the check to registered, naming its real path: {text}"
    );
    assert!(
        text.contains("systemctl --user start shepherd"),
        "a registered service must be started through systemctl, not `shepherdd run`: {text}"
    );

    std::fs::remove_dir_all(&dir).ok();
}

/// OQ-F as an observable property of the shipped binaries: running the daemon
/// and its doctor must not change the lingering setting.
#[test]
fn nothing_the_daemon_runs_enables_lingering() {
    let before = shepherd_obs::lingering::probe(&shepherd_obs::lingering::current_user());
    {
        let d = Daemon::start("oqf");
        let mut c = d.connect();
        c.call("doctor", serde_json::json!({}));
        c.call("status", serde_json::json!({}));
    }
    let after = shepherd_obs::lingering::probe(&shepherd_obs::lingering::current_user());
    assert_eq!(
        before, after,
        "OQ-F: Shepherd must never change the lingering setting"
    );
}

// ---------------------------------------------------------------------------
// The scan executor
// ---------------------------------------------------------------------------

/// Poll `scan.status` until the root's scan stops running, or give up.
fn wait_for_scan(c: &mut Client, root_id: i64) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = serde_json::Value::Null;
    while Instant::now() < deadline {
        let state = c.call("scan.status", serde_json::json!({"root_id": root_id}));
        if let Some(scan) = state["scans"].as_array().and_then(|a| a.first()) {
            last = scan.clone();
            // `running` false with a finish timestamp means the job left the
            // queue; a queued job has neither.
            if scan["running"] == serde_json::json!(false) && !scan["finished_at"].is_null() {
                return last;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the scan never finished; last status was {last}");
}

/// **§6 Phase 1's M1 demo, minus the search leg.**
///
/// `shepctl root add && shepctl scan` now reaches the catalog: the walker runs,
/// rows land, and `status` counts them. The third leg (`shepctl search`) needs
/// T7's index and still answers `MethodNotImplemented`.
#[test]
fn a_scan_walks_the_root_and_the_files_land_in_the_catalog() {
    let d = Daemon::start("scanexec");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-m1");
    std::fs::create_dir_all(root_dir.join("nested/deeper")).unwrap();
    std::fs::write(root_dir.join("report.txt"), b"0123456789").unwrap();
    std::fs::write(root_dir.join("nested/notes.md"), b"abc").unwrap();
    std::fs::write(root_dir.join("nested/deeper/data.csv"), b"xy").unwrap();

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();

    let started = c.call("scan.start", serde_json::json!({"root_id": root_id}));
    assert_eq!(started["job_ids"].as_array().unwrap().len(), 1);

    let scan = wait_for_scan(&mut c, root_id);
    assert_eq!(
        scan["files_seen"],
        serde_json::json!(3),
        "three files were written, three should be seen: {scan}"
    );
    assert_eq!(
        scan["bytes_seen"],
        serde_json::json!(15),
        "10 + 3 + 2 bytes: {scan}"
    );
    assert!(scan["last_error"].is_null(), "{scan}");

    // The rows really landed, not just the counter.
    let status = c.call("status", serde_json::json!({}));
    assert_eq!(status["files_catalogued"], serde_json::json!(3));
    assert_eq!(status["bytes_catalogued"], serde_json::json!(15));

    let listed = c.call("root.list", serde_json::json!({}));
    assert_eq!(listed["roots"][0]["file_count"], serde_json::json!(3));

    // And the job is done, not failed or stuck.
    let scan_depth = status["jobs_pending"]
        .as_array()
        .unwrap()
        .iter()
        .find(|x| x["class"] == serde_json::json!("scan"))
        .expect("a scan row");
    assert_eq!(scan_depth["failed"], serde_json::json!(0), "{status}");
    assert_eq!(scan_depth["pending"], serde_json::json!(0), "{status}");
}

/// Re-scanning must converge, not duplicate. `upsert_file` is
/// `ON CONFLICT DO UPDATE`, which is exactly what makes the executor's
/// "restart re-walks from the beginning" position safe.
#[test]
fn scanning_twice_converges_rather_than_duplicating() {
    let d = Daemon::start("rescan");
    let mut c = d.connect();
    let root_dir = d.dir.join("corpus-rescan");
    std::fs::create_dir_all(&root_dir).unwrap();
    std::fs::write(root_dir.join("a.txt"), b"aa").unwrap();
    std::fs::write(root_dir.join("b.txt"), b"bbb").unwrap();

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();

    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    wait_for_scan(&mut c, root_id);
    assert_eq!(
        c.call("status", serde_json::json!({}))["files_catalogued"],
        serde_json::json!(2)
    );

    // A file appears between scans; the second scan must pick it up and must
    // not double-count the first two.
    std::fs::write(root_dir.join("c.txt"), b"c").unwrap();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    std::thread::sleep(Duration::from_millis(200));
    wait_for_scan(&mut c, root_id);

    let status = c.call("status", serde_json::json!({}));
    assert_eq!(
        status["files_catalogued"],
        serde_json::json!(3),
        "re-scan must converge on 3 rows, not accumulate 5: {status}"
    );
}

/// A scan subscriber sees progress events, ending with `done`.
#[test]
fn a_scan_publishes_progress_events_ending_in_done() {
    let d = Daemon::start("scanevents");
    let mut sub = d.connect();
    sub.call("events.subscribe", serde_json::json!({"streams": ["scan"]}));

    let mut c = d.connect();
    let root_dir = d.dir.join("corpus-events");
    std::fs::create_dir_all(&root_dir).unwrap();
    std::fs::write(root_dir.join("x.bin"), b"1234").unwrap();
    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    wait_for_scan(&mut c, root_id);

    // Drain the notifications the subscriber received.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut saw_done = false;
    let mut seqs: Vec<u64> = Vec::new();
    while Instant::now() < deadline && !saw_done {
        let frame = sub.read_frame();
        assert_eq!(frame["method"], serde_json::json!("event"), "{frame}");
        let params = &frame["params"];
        assert_eq!(params["stream"], serde_json::json!("scan"));
        seqs.push(params["seq"].as_u64().unwrap());
        if params["payload"]["done"] == serde_json::json!(true) {
            saw_done = true;
            assert_eq!(params["payload"]["files_seen"], serde_json::json!(1));
        }
    }
    assert!(saw_done, "the scan never published a done event");
    assert!(
        seqs.windows(2).all(|w| w[0] < w[1]),
        "sequence numbers must be strictly increasing: {seqs:?}"
    );
}

// ---------------------------------------------------------------------------
// M1's functional leg at a million files
// ---------------------------------------------------------------------------
//
// §9's Phase 1 row asks for M1 twice, and the two halves are deliberately
// decoupled:
//
//   * the **scale** half is `shepherd-bench`'s 10M-row injected catalog, where
//     no filesystem is involved so that the < 50 ms p95 measures the index;
//   * the **functional** half is this test: the whole pipeline — `root add`,
//     `scan start`, `search` — over a real tree of a million real files.
//
// Everything above this line runs at nine files, which proves the wiring and
// nothing about six orders of magnitude more of it. This is the test that says
// whether the walker, the deny-list, the symlink guard, the batched catalog
// writer and the arena rebuild still agree at 1M.
//
// # `#[ignore]`, and why the corpus is not generated here
//
// The corpus is ~100 GB of inodes' worth of metadata operations and lives
// wherever the operator has room — on this project's bench machine, a NAS. A
// test that generated it would be a test that takes an hour and cannot run
// twice. So the corpus is built once:
//
//     shepherd-bench gen-files --dest <dir> --files 1000000
//     SHEPHERD_M1_CORPUS=<dir> cargo test -p shepherd-daemon --release \
//         --test e2e -- --ignored --nocapture million
//
// and this test refuses to run rather than inventing a smaller one. A 100k-file
// run reported as if it were the 1M requirement is precisely the defect class
// the corpus is shaped to catch.
//
// # What this test does NOT measure
//
// **Scan throughput is not the M1 scale bar.** The rate printed at the end is a
// property of the filesystem the corpus happens to sit on; over NFS every
// `stat` is a network round trip. It is reported labelled, as a fact about the
// run, and it must never be quoted against `< 50 ms p95`.

/// The corpus size §9's Phase 1 row names for M1's functional leg. Not a
/// tunable: the 10M-file corpus is Phase 0d and the 10M-*row* injected catalog
/// is this milestone's separate scale leg.
const M1_REQUIRED_FILES: u64 = 1_000_000;

/// How long the scan may report no progress before the run is called stuck.
///
/// Generous on purpose, and it is a *stall* budget rather than a deadline.
/// `shepherd_scan::walk` returns the entire `Vec<FileStat>` before the executor
/// upserts anything, so `files_seen` is pinned at zero for the whole walk —
/// which over a network filesystem is a million round trips. A wall-clock
/// deadline would fail a scan that was working perfectly.
const SCAN_STALL_BUDGET: Duration = Duration::from_secs(1_800);

/// Ground truth, as written by `shepherd-bench gen-files`.
struct Corpus {
    dir: PathBuf,
    m: serde_json::Value,
}

impl Corpus {
    /// `None` when the operator has not pointed at a corpus, which is the
    /// normal case in CI.
    fn from_env() -> Option<Corpus> {
        let dir = PathBuf::from(std::env::var_os("SHEPHERD_M1_CORPUS")?);
        let text = std::fs::read_to_string(dir.join("manifest.json")).unwrap_or_else(|e| {
            panic!(
                "SHEPHERD_M1_CORPUS={} has no readable manifest.json: {e}. \
                 Generate it with `shepherd-bench gen-files --dest {} --files 1000000`.",
                dir.display(),
                dir.display()
            )
        });
        let m: serde_json::Value = serde_json::from_str(&text).expect("manifest.json is JSON");
        Some(Corpus { dir, m })
    }

    fn root(&self) -> &str {
        self.m["root"].as_str().expect("manifest.root")
    }

    fn n(&self, key: &str) -> u64 {
        self.m[key]
            .as_u64()
            .unwrap_or_else(|| panic!("manifest has no numeric `{key}`"))
    }

    fn needles(&self) -> Vec<(String, u64, String)> {
        self.m["needles"]
            .as_array()
            .expect("manifest.needles")
            .iter()
            .map(|n| {
                (
                    n["query"].as_str().unwrap().to_string(),
                    n["expect"].as_u64().unwrap(),
                    n["note"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn absent(&self) -> Vec<(String, String)> {
        self.m["absent"]
            .as_array()
            .expect("manifest.absent")
            .iter()
            .map(|a| {
                (
                    a["query"].as_str().unwrap().to_string(),
                    a["why"].as_str().unwrap_or("").to_string(),
                )
            })
            .collect()
    }

    fn samples(&self) -> Vec<(String, u64)> {
        self.m["samples"]
            .as_array()
            .expect("manifest.samples")
            .iter()
            .map(|s| {
                (
                    s["rel_path"].as_str().unwrap().to_string(),
                    s["size"].as_u64().unwrap(),
                )
            })
            .collect()
    }
}

/// Peak and current resident size of another process, from `/proc`.
///
/// The daemon is a child process, so its memory cannot be read from
/// `/proc/self`. `VmHWM` is the high-water mark and never falls, which is the
/// number the `Vec<FileStat>` ceiling documented in `scan_exec.rs` shows up in.
fn proc_kb(pid: u32, key: &str) -> u64 {
    std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

/// Samples the WAL's size for as long as it is held.
///
/// E-4 asks for the write-ahead log to be shown **bounded across a scan**, not
/// merely for a checkpointing connection to exist. A single reading at the end
/// cannot distinguish a WAL that stayed small from one that grew to gigabytes
/// and was checkpointed a second before the test looked.
struct WalSampler {
    stop: std::sync::Arc<std::sync::atomic::AtomicBool>,
    handle: Option<std::thread::JoinHandle<Vec<(f64, u64)>>>,
}

impl WalSampler {
    fn start(wal: PathBuf) -> WalSampler {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let flag = stop.clone();
        let t0 = Instant::now();
        let handle = std::thread::spawn(move || {
            let mut out = Vec::new();
            while !flag.load(std::sync::atomic::Ordering::Relaxed) {
                let n = std::fs::metadata(&wal).map(|m| m.len()).unwrap_or(0);
                out.push((t0.elapsed().as_secs_f64(), n));
                std::thread::sleep(Duration::from_millis(1_000));
            }
            out
        });
        WalSampler {
            stop,
            handle: Some(handle),
        }
    }

    fn finish(mut self) -> Vec<(f64, u64)> {
        self.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        self.handle.take().map(|h| h.join().unwrap()).unwrap()
    }
}

/// Wait for a scan whose duration is not known in advance.
///
/// `wait_for_scan`'s thirty seconds is right for nine files and wrong for a
/// million, and the failure it produces — "the scan never finished" — would be
/// a lie about a scan that was progressing perfectly well. So the deadline here
/// is on *progress*: the scan may take as long as it likes provided
/// `files_seen` keeps moving.
fn wait_for_scan_with_progress(c: &mut Client, root_id: i64, stall: Duration) -> serde_json::Value {
    let mut last_seen = 0u64;
    let mut last_move = Instant::now();
    let mut last = serde_json::Value::Null;
    let started = Instant::now();
    loop {
        let state = c.call("scan.status", serde_json::json!({"root_id": root_id}));
        if let Some(scan) = state["scans"].as_array().and_then(|a| a.first()) {
            last = scan.clone();
            let seen = scan["files_seen"].as_u64().unwrap_or(0);
            if seen != last_seen {
                last_seen = seen;
                last_move = Instant::now();
                eprintln!(
                    "[m1] {seen} files catalogued after {:.0}s",
                    started.elapsed().as_secs_f64()
                );
            }
            if scan["running"] == serde_json::json!(false) && !scan["finished_at"].is_null() {
                return last;
            }
            if let Some(err) = scan["last_error"].as_str() {
                panic!("the scan failed: {err}\n{scan}");
            }
        }
        assert!(
            last_move.elapsed() < stall,
            "the scan made no progress for {:?} (stuck at {last_seen} files). \
             This is a stall, not a slow filesystem: last status {last}",
            stall
        );
        std::thread::sleep(Duration::from_secs(2));
    }
}

/// The page size a count assertion must ask for to be allowed to fail.
///
/// **A literal `limit` is a scale bug, not a style choice.** For an unfiltered
/// query the dispatcher hands the index `offset + limit` candidates and counts
/// what comes back, so `total` is *capped by the page size*: a class with
/// 18,000 members queried with `limit: 8192` answers `8192`, and an assertion
/// comparing that to 8192 would pass while the index returned less than half
/// the corpus. Every count assertion therefore derives its page from the number
/// the manifest says to expect, so the same line means the same thing at ten
/// thousand files and at ten million.
fn headroom(expect: u64) -> u64 {
    (expect * 2).max(64) + 64
}

/// One search, with the page large enough that `total` is exact.
///
/// `total` is capped at `offset + limit` by the dispatcher, so asking for fewer
/// hits than exist turns an over-count into a silent pass: a needle that should
/// match 1265 files and actually matches 40000 would answer `1265` to a query
/// with `limit: 1265`. Every count assertion here therefore asks for headroom
/// and additionally requires `degraded` to be null, which is the dispatcher's
/// own statement that the number is a total rather than a floor.
fn count_exact(c: &mut Client, query: &str, expect: u64) {
    let limit = headroom(expect);
    let r = c.call(
        "search",
        serde_json::json!({"query": query, "limit": limit}),
    );
    assert_eq!(
        r["total"],
        serde_json::json!(expect),
        "`{query}` should match exactly {expect} files"
    );
    assert_eq!(
        r["degraded"],
        serde_json::Value::Null,
        "`{query}` was answered with headroom, so its total must not be a floor: {}",
        r["degraded"]
    );
    assert_eq!(
        r["hits"].as_array().unwrap().len() as u64,
        expect,
        "`{query}` reported {expect} but returned a different number of hits"
    );
}

#[test]
#[ignore = "needs SHEPHERD_M1_CORPUS; see the module comment above"]
fn the_m1_demo_holds_at_a_million_files() {
    let Some(corpus) = Corpus::from_env() else {
        panic!(
            "SHEPHERD_M1_CORPUS is not set. This test asserts §9 Phase 1's M1 \
             functional leg over a 1M-file corpus and will not substitute a \
             smaller one: build it with `shepherd-bench gen-files --dest <dir> \
             --files 1000000` and point SHEPHERD_M1_CORPUS at <dir>."
        );
    };
    let expected_seen = corpus.n("expected_seen");
    let expected_bytes = corpus.n("expected_bytes");

    // §9 asks for a million. A smaller corpus is a legitimate thing to run —
    // the mutation checks that prove these assertions can fail are done at ten
    // thousand, because deleting a needle and regenerating is seconds there and
    // twenty minutes at full scale — but it is NOT the requirement, and a run
    // that quietly used 100k and reported it as M1 is exactly the defect this
    // whole fixture is shaped against. So a short run must say why, in the same
    // shape `shepherd-bench` already uses for `--rows`, and the reason travels
    // into the evidence file.
    let small_run_reason = std::env::var("SHEPHERD_M1_SMALL_RUN_REASON").ok();
    if expected_seen < M1_REQUIRED_FILES {
        let why = small_run_reason.clone().unwrap_or_else(|| {
            panic!(
                "this corpus holds {expected_seen} files and §9 Phase 1 requires \
                 {M1_REQUIRED_FILES}. Refusing to run: a reduced corpus reported as \
                 M1 is the claim this test exists to prevent. If the small run is \
                 deliberate, set SHEPHERD_M1_SMALL_RUN_REASON to why, and the \
                 reason will be stamped into the result."
            )
        });
        eprintln!("[m1] *** REDUCED SCALE: {expected_seen} files, not {M1_REQUIRED_FILES}. {why}");
    }
    eprintln!(
        "[m1] corpus {} — {expected_seen} files, {} dirs, {:.1} MiB of bodies",
        corpus.dir.display(),
        corpus.n("dirs_created"),
        expected_bytes as f64 / 1048576.0
    );

    let d = Daemon::start("million");
    let pid = d.child.id();
    let mut c = d.connect();
    c.set_read_timeout(Duration::from_secs(120));

    // --- the empty-catalog control, before the root exists ---------------
    //
    // Run first and over every needle, not just one. An index that answered
    // from somewhere other than this daemon's catalog — a stale file, another
    // test's state directory — would show up here and nowhere else.
    for (query, expect, _) in corpus.needles() {
        assert!(expect > 0, "manifest needle `{query}` expects nothing");
        let r = c.call("search", serde_json::json!({"query": query}));
        assert_eq!(
            r["total"],
            serde_json::json!(0),
            "an empty catalog cannot contain `{query}`: {r}"
        );
    }

    // --- scan ------------------------------------------------------------
    let added = c.call(
        "root.add",
        serde_json::json!({"path": corpus.root(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();

    let wal_path = d.dir.join("catalog.db-wal");
    let wal = WalSampler::start(wal_path.clone());
    let t0 = Instant::now();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    let scan = wait_for_scan_with_progress(&mut c, root_id, SCAN_STALL_BUDGET);
    let scan_secs = t0.elapsed().as_secs_f64();
    let wal_samples = wal.finish();

    let hwm_kb = proc_kb(pid, "VmHWM:");
    let rss_kb = proc_kb(pid, "VmRSS:");

    // --- E-4: the write-ahead log is bounded across the scan ---------------
    //
    // §9 asks for the WAL to be shown **bounded across a scan**, and an
    // escalation was open on it because what existed was a checkpointing
    // connection — the mechanism — rather than evidence that it holds. A
    // reading taken after the scan proves nothing either: a WAL that grew to
    // half a gigabyte and was checkpointed one second before the test looked
    // is indistinguishable from one that never grew. Hence the sampler, and
    // hence the assertion on its **maximum**, not its last value.
    //
    // The ceiling is deliberately far above what was measured (7.96 MiB at
    // 1M files, flat from t+60s while eight hundred thousand more rows
    // landed). It is not a tuning target and must not be tightened toward the
    // observed figure: what it has to catch is the WAL tracking the corpus
    // instead of the checkpoint interval, and an uncheckpointed 1M-row scan
    // would put roughly the whole 440 MB catalog through it.
    let wal_max = wal_samples.iter().map(|(_, n)| *n).max().unwrap_or(0);
    const WAL_CEILING_BYTES: u64 = 64 * 1024 * 1024;
    assert!(
        wal_max > 0,
        "the WAL was never observed at a non-zero size, so this check watched \
         the wrong path and would pass however large the log grew"
    );
    assert!(
        wal_max < WAL_CEILING_BYTES,
        "the WAL peaked at {:.1} MiB during a scan of {expected_seen} files. \
         A WAL that scales with the corpus rather than with the checkpoint \
         interval is the E-4 failure: it is unbounded disk growth on a scan \
         that §9 sizes at 50 TB.",
        wal_max as f64 / 1048576.0
    );

    // --- the counts the whole test rests on ------------------------------
    assert!(scan["last_error"].is_null(), "the scan failed: {scan}");
    assert_eq!(
        scan["files_seen"],
        serde_json::json!(expected_seen),
        "the walker and the generator disagree on how many files exist. \
         The generator wrote {expected_seen} catalogable files plus deny-listed \
         and off-root traps; a LARGER number here means a guard let a trap \
         through, a smaller one means the walk missed part of the tree: {scan}"
    );
    assert_eq!(
        scan["bytes_seen"],
        serde_json::json!(expected_bytes),
        "the file count matched but the byte total did not, so the walk saw the \
         right number of the wrong files: {scan}"
    );
    let status = c.call("status", serde_json::json!({}));
    assert_eq!(
        status["files_catalogued"],
        serde_json::json!(expected_seen),
        "the walk saw {expected_seen} files but the catalog holds a different \
         number — a batch was lost between the walker and the writer: {status}"
    );

    // --- every needle class, by exact count ------------------------------
    for (query, expect, note) in corpus.needles() {
        eprintln!("[m1] search {query:?} -> expect {expect} ({note})");
        count_exact(&mut c, &query, expect);
    }

    // --- and every case whose right answer is zero -----------------------
    //
    // Paired with the needles deliberately. A search that returned everything
    // would pass none of these, and a search that returned nothing would pass
    // all of them and none of the ones above.
    for (query, why) in corpus.absent() {
        let r = c.call("search", serde_json::json!({"query": query, "limit": 64}));
        assert_eq!(
            r["total"],
            serde_json::json!(0),
            "`{query}` must match nothing — {why}: {r}"
        );
    }

    // --- path scope, at scale ---------------------------------------------
    //
    // The same token, once with the separator and once without. `zzpathfrag`
    // appears in thousands of directory names and in no filename, so a name
    // query that returned the path count would be a scope check that had
    // quietly stopped applying.
    let frag = corpus
        .needles()
        .into_iter()
        .find(|(q, _, _)| q == "zzpathfrag/")
        .expect("the manifest must carry a path-fragment needle");
    // Scaled to the corpus, so the same floor means the same thing at ten
    // thousand files and at a million.
    let discriminating = (expected_seen / 1000).max(8);
    assert!(
        frag.1 >= discriminating,
        "the path needle landed {} times in a {expected_seen}-file corpus; \
         below {discriminating} the count stops discriminating",
        frag.1
    );
    count_exact(&mut c, "zzpathfrag/", frag.1);
    let unscoped = c.call("search", serde_json::json!({"query": "zzpathfrag"}));
    assert_eq!(
        unscoped["total"],
        serde_json::json!(0),
        "a name-scoped query reached directory components: {unscoped}"
    );

    // --- case folding is a fold, not a coincidence ------------------------
    let lower = corpus.n("case_lower_files");
    let upper = corpus.n("case_upper_files");
    assert!(lower > 0 && upper > 0 && lower != upper);
    for q in ["zzcasemix", "ZZCASEMIX", "ZzCaseMix"] {
        let r = c.call(
            "search",
            serde_json::json!({"query": q, "limit": headroom(lower + upper)}),
        );
        assert_eq!(
            r["total"],
            serde_json::json!(lower + upper),
            "`{q}` must fold to both halves ({lower} lowercase + {upper} \
             uppercase); returning either half alone is a case-SENSITIVE \
             match: {r}"
        );
    }

    // --- filters narrow the same result set -------------------------------
    let ext = corpus
        .needles()
        .into_iter()
        .find(|(q, _, _)| q == ".zzx")
        .expect("the manifest must carry an extension needle");
    let filtered = c.call(
        "search",
        serde_json::json!({"query": ".zzx", "filters": {"ext": ["zzx"]}, "limit": headroom(ext.1)}),
    );
    assert_eq!(
        filtered["total"],
        serde_json::json!(ext.1),
        "every .zzx file has extension zzx: {}",
        filtered["degraded"]
    );
    let wrong_ext = c.call(
        "search",
        serde_json::json!({"query": ".zzx", "filters": {"ext": ["pdf"]}, "limit": headroom(ext.1)}),
    );
    assert_eq!(
        wrong_ext["total"],
        serde_json::json!(0),
        "no .zzx file has extension pdf: {wrong_ext}"
    );
    // The `state` filter, and an honest account of what this pair can and
    // cannot show.
    //
    // `remote -> 0` on its own is a check that CANNOT FAIL. Every row in this
    // catalog holds `'local'`: `upsert_file` writes exactly that on insert and
    // deliberately leaves the column alone on re-scan, and **no code path in
    // the tree ever writes `'stub'` or `'remote'`**, because tiering is Phase
    // 2/3 work. So this query would answer 0 with the filter entirely broken.
    // It was written as if it proved the filter worked; it did not.
    //
    // Pairing it with `local -> everything` is what makes the two together
    // discriminating:
    //
    //   filter ignored altogether  ->  local = 773, remote = 773   (fails below)
    //   filter matches nothing     ->  local = 0                   (fails below)
    //   filter applied correctly   ->  local = 773, remote = 0     (passes)
    //
    // What the pair still cannot show is that the filter selects the RIGHT
    // rows, because the catalog contains exactly one distinct value. That is
    // not a gap in the test — it is a property of the catalog, and it is the
    // second witness to it: `state` having no producer is also why
    // `count_custody_rows`'s `WHERE state IN ('stub','remote')` returns 0 here,
    // which is a safety refusal this corpus cannot make fire. That the refusal
    // is *able* to fire is established away from the corpus, in
    // `dispatch::tests::the_custody_count_is_zero_before_tiering_and_non_zero_after`,
    // which drives the same function to a non-zero answer. Whoever makes
    // tiering real must write `state`, and when they do, this assertion starts
    // discriminating on data instead of on plumbing.
    let by_state = c.call(
        "search",
        serde_json::json!({"query": ".zzx", "filters": {"state": "local"}, "limit": headroom(ext.1)}),
    );
    assert_eq!(
        by_state["total"],
        serde_json::json!(ext.1),
        "every catalogued file is `local` at Phase 1, so the state filter must \
         narrow to all of them rather than to none: {by_state}"
    );
    let by_state = c.call(
        "search",
        serde_json::json!({"query": ".zzx", "filters": {"state": "remote"}, "limit": headroom(ext.1)}),
    );
    assert_eq!(
        by_state["total"],
        serde_json::json!(0),
        "nothing is tiered at Phase 1, so no row is `remote` — this establishes \
         that `state` is uniformly `local`, NOT that the filter discriminates: \
         {by_state}"
    );

    // --- paging over a needle with thousands of hits ----------------------
    //
    // At nine files a page boundary is a formality. Over a class with thousands
    // of members, a rank map that lost its ordering shows up as a repeated or
    // skipped row.
    let (page_query, page_total, _) = corpus
        .needles()
        .into_iter()
        .max_by_key(|(_, n, _)| *n)
        .unwrap();
    assert!(
        page_total >= discriminating,
        "the largest needle ({page_total}) is too small to page over"
    );
    // Three pages that together cover at most three quarters of the class, so
    // the last page is never the short one.
    let per = (page_total / 4).clamp(1, 500);
    let mut seen_ids: std::collections::HashSet<i64> = std::collections::HashSet::new();
    for page in 0..3u64 {
        let r = c.call(
            "search",
            serde_json::json!({"query": page_query, "limit": per, "offset": page * per}),
        );
        let ids: Vec<i64> = r["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["file_id"].as_i64().unwrap())
            .collect();
        assert_eq!(ids.len() as u64, per, "page {page} came back short: {r}");
        for id in ids {
            assert!(
                seen_ids.insert(id),
                "file_id {id} appeared on two pages of `{page_query}`"
            );
        }
    }
    assert_eq!(seen_ids.len() as u64, 3 * per);

    // --- hydration: the row, not just the name ----------------------------
    //
    // Sizes matter here beyond tidiness. Two of the samples are symlinks whose
    // recorded size is the length of their *target string*; a walker that used
    // `metadata` instead of `symlink_metadata` would report the target file's
    // size for one and fail outright on the dangling one.
    for (rel, size) in corpus.samples() {
        let name = rel.rsplit('/').next().unwrap().to_string();
        let stem = name.rsplit_once('.').map(|(s, _)| s).unwrap_or(&name);
        let r = c.call("search", serde_json::json!({"query": stem, "limit": 16}));
        assert_eq!(
            r["total"],
            serde_json::json!(1),
            "`{stem}` names exactly one file in the corpus: {r}"
        );
        let hit = &r["hits"][0];
        assert_eq!(hit["rel_path"], serde_json::json!(rel), "{hit}");
        assert_eq!(
            hit["size"],
            serde_json::json!(size),
            "the catalog's size for {rel} is not the one on disk: {hit}"
        );
        assert_eq!(hit["root_id"], serde_json::json!(root_id));
        assert_eq!(hit["state"], serde_json::json!("local"));
        assert!(hit["file_id"].as_i64().unwrap() > 0);
        assert!(
            hit["blake3"].is_null(),
            "Phase 1 never hashes during a scan"
        );
    }

    // --- doctor reports the real entry count ------------------------------
    let doc = c.call("doctor", serde_json::json!({}));
    let index_check = doc["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["name"] == serde_json::json!("metadata index"))
        .expect("doctor must report on the metadata index");
    assert_eq!(index_check["status"], serde_json::json!("ok"));
    let detail = index_check["detail"].as_str().unwrap().to_string();
    assert!(
        detail.contains(&format!("{expected_seen} entries")),
        "doctor must report the real entry count, not a health colour: {detail}"
    );

    // --- rescan: the same tree twice is the same catalog ------------------
    //
    // `upsert_file` is ON CONFLICT DO UPDATE, so a second scan is supposed to
    // converge rather than duplicate. At nine files that is trivially true; at a
    // million, a norm_key collision or a lost uniqueness constraint would show
    // up as a catalog that grew.
    let t1 = Instant::now();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    let scan2 = wait_for_scan_with_progress(&mut c, root_id, SCAN_STALL_BUDGET);
    let rescan_secs = t1.elapsed().as_secs_f64();
    assert!(scan2["last_error"].is_null(), "the rescan failed: {scan2}");
    assert_eq!(
        scan2["files_seen"],
        serde_json::json!(expected_seen),
        "the second walk saw a different tree: {scan2}"
    );
    let status2 = c.call("status", serde_json::json!({}));
    assert_eq!(
        status2["files_catalogued"],
        serde_json::json!(expected_seen),
        "rescanning an unchanged tree changed the catalog's row count — the \
         upsert is inserting where it should be updating: {status2}"
    );
    for (query, expect, _) in corpus.needles() {
        count_exact(&mut c, &query, expect);
    }

    // --- what the run measured --------------------------------------------
    //
    // Printed, never asserted. None of these is an acceptance criterion for M1:
    // the scan rate is a property of the filesystem under the corpus, and the
    // scale bar is the injected-catalog bench, on purpose.
    let wal_final = std::fs::metadata(&wal_path).map(|m| m.len()).unwrap_or(0);
    let db_bytes = std::fs::metadata(d.dir.join("catalog.db"))
        .map(|m| m.len())
        .unwrap_or(0);
    let report = serde_json::json!({
        "corpus": corpus.dir.display().to_string(),
        "files_catalogued": expected_seen,
        "bytes_catalogued": expected_bytes,
        "scan_seconds": scan_secs,
        "scan_files_per_sec": expected_seen as f64 / scan_secs,
        "rescan_seconds": rescan_secs,
        "scan_rate_caveat":
            "a property of the filesystem holding the corpus, NOT the M1 scale \
             bar; the scale leg is shepherd-bench's injected 10M-row catalog",
        "daemon_vmhwm_bytes": hwm_kb * 1024,
        "daemon_vmrss_after_scan_bytes": rss_kb * 1024,
        "catalog_db_bytes": db_bytes,
        "wal_max_bytes": wal_max,
        "wal_final_bytes": wal_final,
        "wal_samples": wal_samples
            .iter()
            .map(|(t, n)| serde_json::json!([t, n]))
            .collect::<Vec<_>>(),
        "index_detail": detail,
        "m1_required_files": M1_REQUIRED_FILES,
        "small_run_reason": small_run_reason,
    });
    eprintln!(
        "[m1] scan {:.1}s ({:.0} files/s over the corpus filesystem — NOT the \
         scale bar), rescan {:.1}s, daemon VmHWM {:.0} MiB, VmRSS {:.0} MiB, \
         catalog.db {:.0} MiB, WAL max {:.1} MiB / final {:.1} MiB, index: {detail}",
        scan_secs,
        expected_seen as f64 / scan_secs,
        rescan_secs,
        hwm_kb as f64 / 1024.0,
        rss_kb as f64 / 1024.0,
        db_bytes as f64 / 1048576.0,
        wal_max as f64 / 1048576.0,
        wal_final as f64 / 1048576.0,
    );
    if let Some(out) = std::env::var_os("SHEPHERD_M1_REPORT") {
        std::fs::write(&out, serde_json::to_string_pretty(&report).unwrap())
            .unwrap_or_else(|e| panic!("writing the report to {out:?}: {e}"));
        eprintln!("[m1] evidence written to {out:?}");
    }
}

// ---------------------------------------------------------------------------
// AC-9 (`**User**` ignore patterns) and the `hosted_optin` consent flag —
// the two fields `root.add` accepted and then dropped.
// ---------------------------------------------------------------------------

/// **AC-9's scan leg, end to end from a client's request.**
///
/// `shepherd-scan`'s own tests prove the matcher honours the patterns it is
/// handed, and they always did. What no test covered — because until proto 1.2
/// it could not be written — is that a pattern a *user* supplies reaches that
/// matcher: `scan_root.ignore_patterns_json` was read by `scan_exec` and
/// written by nothing, so every scan that had ever run used `'[]'`.
///
/// **Both directions on the same file, deliberately.** A test asserting only
/// that `secrets/` is absent from the catalog passes just as well when the scan
/// found nothing at all, when the walk crashed, or when the root was empty —
/// which is this project's recurring defect in its purest form. So the same
/// daemon scans the same tree twice: once with no patterns, where every file
/// must be present, and once with them, where exactly the named ones must be
/// gone and the rest must remain.
#[test]
fn a_user_supplied_ignore_pattern_reaches_the_scan_and_excludes_only_what_it_names() {
    let d = Daemon::start("ac9-ignore");
    let mut c = d.connect();

    let layout = |root: &Path| {
        write_file(root, "keep/report.txt", "aaaa");
        write_file(root, "build/artifact.o", "bb");
        write_file(root, "notes.tmp", "c");
        write_file(root, "notes.md", "dd");
    };

    // 1. No patterns: all four files land. This is the control, and it is what
    //    makes the exclusions below attributable.
    let open = d.dir.join("corpus-ac9-open");
    layout(&open);
    let open_id = c.call(
        "root.add",
        serde_json::json!({"path": open.to_str().unwrap(), "stub_mode": "delete"}),
    )["root"]["root_id"]
        .as_i64()
        .unwrap();
    c.call("scan.start", serde_json::json!({"root_id": open_id}));
    let open_scan = wait_for_scan(&mut c, open_id);
    assert_eq!(
        open_scan["files_seen"],
        serde_json::json!(4),
        "the control must see every file, or the comparison below proves nothing: {open_scan}"
    );

    // 2. The same tree, with the user's patterns.
    let filtered = d.dir.join("corpus-ac9-filtered");
    layout(&filtered);
    let added = c.call(
        "root.add",
        serde_json::json!({
            "path": filtered.to_str().unwrap(),
            "stub_mode": "delete",
            "ignore_patterns": ["build/", "*.tmp"],
        }),
    );
    let filtered_id = added["root"]["root_id"].as_i64().unwrap();

    // The daemon STORED them. Echoed from the catalog by `root.list`, not from
    // the request — the additive rule means a daemon that ignored the field
    // would answer this request identically otherwise.
    assert_eq!(
        added["root"]["ignore_patterns"],
        serde_json::json!(["build/", "*.tmp"]),
        "root.add must echo the patterns it stored: {added}"
    );

    c.call("scan.start", serde_json::json!({"root_id": filtered_id}));
    let scan = wait_for_scan(&mut c, filtered_id);
    assert!(scan["last_error"].is_null(), "{scan}");
    assert_eq!(
        scan["files_seen"],
        serde_json::json!(2),
        "`build/` and `*.tmp` must exclude exactly two of the four files: {scan}"
    );

    // And it is the RIGHT two, by name. A count alone is satisfied by any
    // pattern that happens to exclude two files.
    let mut hits = |needle: &str| -> Vec<String> {
        let r = c.call(
            "search",
            serde_json::json!({"query": needle, "filters": {"root_id": filtered_id}}),
        );
        r["hits"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["path"].as_str().unwrap_or_default().to_string())
            .collect()
    };
    assert!(
        hits("artifact").is_empty(),
        "`build/` did not exclude the directory: {:?}",
        hits("artifact")
    );
    assert!(
        hits("notes.tmp").is_empty(),
        "`*.tmp` did not exclude the file: {:?}",
        hits("notes.tmp")
    );
    // The paired non-zero on the same mechanism: a search that returned nothing
    // for everything would satisfy both assertions above.
    assert_eq!(hits("report").len(), 1, "{:?}", hits("report"));
    assert_eq!(hits("notes.md").len(), 1, "{:?}", hits("notes.md"));
}

/// An ignore pattern that cannot compile is refused at registration, and the
/// root is not created.
///
/// The backstop in `scan_exec` fails the scan *job*, which is correct but
/// arrives detached from the request that caused it — by then the root exists
/// and the user has a registration that can never scan.
#[test]
fn an_uncompilable_ignore_pattern_is_refused_and_registers_nothing() {
    let d = Daemon::start("ac9-badpattern");
    let mut c = d.connect();
    let root_dir = d.dir.join("corpus-ac9-bad");
    write_file(&root_dir, "a.txt", "a");

    let before = c.call("root.list", serde_json::json!({}))["roots"]
        .as_array()
        .unwrap()
        .len();

    // An inverted character range. Chosen by probing `GitignoreBuilder` rather
    // than assumed: the obvious candidates (`a[b`, `***`, `a/**b`) are all
    // ACCEPTED by the `ignore` crate, so a test built on one of those would
    // have asserted a refusal that never happens.
    let err = c.call_err(
        "root.add",
        serde_json::json!({
            "path": root_dir.to_str().unwrap(),
            "stub_mode": "delete",
            "ignore_patterns": ["[z-a]"],
        }),
    );
    assert_eq!(
        err.kind(),
        Some(shepherd_proto::ErrorCode::Invalid),
        "{err:?}"
    );
    assert!(
        err.message.contains("ignore pattern"),
        "the refusal must name what was wrong: {}",
        err.message
    );

    assert_eq!(
        c.call("root.list", serde_json::json!({}))["roots"]
            .as_array()
            .unwrap()
            .len(),
        before,
        "a refused root.add must not have registered the root"
    );

    // Paired: the same path with a VALID pattern registers, so the refusal
    // above is attributable to the pattern and not to the path or the daemon.
    let ok = c.call(
        "root.add",
        serde_json::json!({
            "path": root_dir.to_str().unwrap(),
            "stub_mode": "delete",
            "ignore_patterns": ["[a-z]*.txt"],
        }),
    );
    assert_eq!(
        ok["root"]["ignore_patterns"],
        serde_json::json!(["[a-z]*.txt"])
    );
}

/// **`hosted_optin` is a consent flag, and the daemon was discarding it.**
///
/// `RootAddRequest` carried it, `roundtrip.rs` proves `shepctl` puts it on the
/// wire, `RootSummary` reported it and `scan_root.hosted_optin` stored it — and
/// `root_add` never passed it to `insert_root`, so the column kept its
/// `DEFAULT 0` and every root read back as "no consent given".
///
/// The failure direction is why this went unnoticed: defaulting a consent flag
/// to *denied* is the safe way to be wrong, and nothing downstream complains
/// about consent it never received. It is still a user's explicit instruction
/// being silently discarded, which is the direction that matters for a flag
/// whose whole purpose is to record that the user was asked.
///
/// **`true` is the load-bearing case.** A test asserting only the `false`
/// default passes unchanged against the broken code, because the broken code
/// produced `false` for everyone.
#[test]
fn hosted_optin_is_stored_as_the_user_set_it_rather_than_defaulted() {
    let d = Daemon::start("hosted-optin");
    let mut c = d.connect();

    let consented = d.dir.join("corpus-consent-yes");
    let withheld = d.dir.join("corpus-consent-no");
    write_file(&consented, "a.txt", "a");
    write_file(&withheld, "b.txt", "b");

    let yes = c.call(
        "root.add",
        serde_json::json!({
            "path": consented.to_str().unwrap(),
            "stub_mode": "delete",
            "hosted_optin": true,
        }),
    );
    assert_eq!(
        yes["root"]["hosted_optin"],
        serde_json::json!(true),
        "the consent the user gave must survive registration: {yes}"
    );

    let no = c.call(
        "root.add",
        serde_json::json!({"path": withheld.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert_eq!(
        no["root"]["hosted_optin"],
        serde_json::json!(false),
        "and consent nobody gave must not appear: {no}"
    );

    // Durable, not just echoed back out of the request that set it. `root.list`
    // reads the column; `root.add`'s own result does too, but a handler that
    // reflected the request would pass that one either way.
    let listed = c.call("root.list", serde_json::json!({}));
    let by_path = |p: &Path| -> bool {
        listed["roots"]
            .as_array()
            .unwrap()
            .iter()
            .find(|r| r["path"] == serde_json::json!(p.to_str().unwrap()))
            .unwrap_or_else(|| panic!("{p:?} is not listed: {listed}"))["hosted_optin"]
            == serde_json::json!(true)
    };
    assert!(by_path(&consented), "{listed}");
    assert!(!by_path(&withheld), "{listed}");
}
