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
#[test]
fn unserved_methods_answer_with_a_distinct_code() {
    let d = Daemon::start("notimpl");
    let mut c = d.connect();
    for (method, params) in [
        // `search` is NOT in this list any more: T7's metadata index landed and
        // the daemon serves it. `search_finds_scanned_files_and_misses_absent_ones`
        // is what replaced this row — if that test is ever deleted, put the row
        // back rather than leaving the method unowned by any test.
        ("target.list", serde_json::json!({})),
        ("rule.list", serde_json::json!({})),
        (
            "tier.run",
            serde_json::json!({"plan_id": "p", "candidate_set_hash": "ab"}),
        ),
        ("restore", serde_json::json!({"file_id": 1})),
    ] {
        let err = c.call_err(method, params);
        assert_eq!(
            err.kind(),
            Some(shepherd_proto::ErrorCode::MethodNotImplemented),
            "{method} answered {:?}",
            err.kind()
        );
        assert!(
            err.message.contains("Phase") || err.message.contains("T7"),
            "an unserved method should say when it lands: {}",
            err.message
        );
    }
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
/// report lingering.
#[test]
fn shepherdd_doctor_works_with_no_daemon_running() {
    let dir = std::env::temp_dir().join(format!("shepherdd-e2e-offline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
        .arg("doctor")
        .env("SHEPHERD_STATE_DIR", &dir)
        .env("SHEPHERD_SOCKET", dir.join("nothing.sock"))
        .output()
        .expect("run shepherdd doctor");
    let text = String::from_utf8_lossy(&out.stdout);

    assert!(
        text.contains("systemd lingering"),
        "the lingering check must run without a daemon: {text}"
    );
    assert!(
        text.contains("daemon"),
        "it must report that no daemon is listening: {text}"
    );
    assert!(
        out.status.success(),
        "no daemon running is a warning, not a failure: {text}"
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
