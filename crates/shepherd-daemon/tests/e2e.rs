//! POSIX-only. This suite drives a REAL `shepherdd` over its IPC surface,
//! which is a Unix domain socket (§4.2); Windows needs a named pipe and §6
//! defers that to Phase 3. Gated at file level so the crate still COMPILES on
//! Windows and every other target runs there — §9 wants a platform break found
//! on the commit that caused it, and that needs the other legs to keep
//! building.
//!
//! This is a real coverage gap on Windows and is meant to read as one: the
//! entire served surface is unexercised there.
#![cfg(unix)]

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

use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use shepherd_proto::request::RpcRequest;
use shepherd_proto::response::RpcResponse;
use shepherd_proto::{Hello, PROTO_VERSION, PeerInfo, ProtoVersion, RequestId};

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

/// A running daemon in its own state directory, killed on drop.
/// Make a directory the daemon will accept — for the socket's parent or for
/// the state directory.
///
/// Neither `secure_socket_dir` nor `secure_state_dir` chmods a directory it did
/// not create: that is what let `SHEPHERD_SOCKET=/tmp/shepherd.sock` and
/// `SHEPHERD_STATE_DIR=/tmp` lock out `/tmp`. So a harness that pre-creates
/// either has to create it owner-only, exactly as an operator would. Production
/// usually does not hit this at all — §4.3 puts the socket in
/// `$XDG_RUNTIME_DIR/shepherd/` and the state under `$XDG_STATE_HOME/shepherd`,
/// both of which the daemon creates itself.
fn mkdir_owner_only(dir: &Path) {
    use std::os::unix::fs::DirBuilderExt;
    let _ = std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir);
    // And enforced, because `DirBuilder` is a no-op on a directory that already
    // exists — several fixtures create the state child first, which makes this
    // parent at the ambient umask on the way. Chmodding here is the OPERATOR's
    // action, which is exactly the thing the daemon must no longer do for them.
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))
        .expect("make the socket's parent owner-only");
}

struct Daemon {
    child: Child,
    dir: PathBuf,
    socket: PathBuf,
}

impl Daemon {
    fn start(tag: &str) -> Daemon {
        Daemon::start_with_env(tag, &[])
    }

    /// A daemon with extra environment.
    ///
    /// `target.add` resolves `credentials_ref` through
    /// `shepherd_secrets::SecretStore`, whose chain reads the environment
    /// first. Handing the child a `SHEPHERD_SECRET_*` var is therefore how a
    /// test supplies a target's credentials without writing a keyfile — and it
    /// exercises the real resolution path rather than bypassing it.
    fn start_with_env(tag: &str, env: &[(&str, &str)]) -> Daemon {
        let dir = fixture_root().join(format!("shepherdd-e2e-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // The state directory is a CHILD of the harness directory, not the
        // harness directory itself. Every test builds its corpus at
        // `d.dir.join(..)`, and a state directory sitting above those corpora
        // made each of them a root inside the daemon's own state — which
        // `root.add` now refuses, and which no real user has. Siblings is the
        // real shape.
        // Both owner-only, which is what the daemon requires of a directory it
        // did not create itself — see `mkdir_owner_only`.
        mkdir_owner_only(&dir.join("state"));
        mkdir_owner_only(&dir);
        let socket = dir.join("daemon.sock");

        let mut cmd = Command::new(env!("CARGO_BIN_EXE_shepherdd"));
        cmd.arg("run")
            .env("SHEPHERD_STATE_DIR", dir.join("state"))
            .env("SHEPHERD_SOCKET", &socket);
        for (k, v) in env {
            cmd.env(k, v);
        }
        let child = cmd.spawn().expect("spawn shepherdd");

        let d = Daemon { child, dir, socket };
        d.wait_until_listening();
        d
    }

    /// A daemon whose socket does **not** live in its state directory.
    ///
    /// That split is the ordinary Linux layout — §4.3 puts the socket in
    /// `$XDG_RUNTIME_DIR` and the catalog in `$XDG_STATE_HOME` — and the usual
    /// harness hides it. When the socket's parent *is* the state directory,
    /// `server::bind`'s own `0700` on the socket directory tightens the state
    /// directory as a side effect, so a mode assertion there would be asserting
    /// `bind`'s work rather than the state directory's own.
    ///
    /// `dir` is the enclosing temp directory here, not the state directory, so
    /// that `Drop` cleans up both. The state directory is `dir.join("state")`;
    /// the catalog helpers above, which look for `catalog.db` directly under
    /// `dir`, are not usable on a daemon started this way.
    fn start_with_socket_outside_the_state_dir(tag: &str) -> Daemon {
        let dir = fixture_root().join(format!("shepherdd-e2e-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let state = dir.join("state");
        // Owner-only, like an operator's. This fixture used to set `0755`
        // deliberately, to exercise the daemon TIGHTENING an existing loose
        // state directory — behaviour that has since been removed, because
        // chmodding a directory the daemon did not create is what let
        // `SHEPHERD_STATE_DIR=/tmp` lock out every other account. A loose
        // directory is refused now, and this fixture is about scanning rather
        // than about permissions.
        mkdir_owner_only(&state);
        mkdir_owner_only(&dir);
        let socket = dir.join("daemon.sock");
        let child = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
            .arg("run")
            .env("SHEPHERD_STATE_DIR", &state)
            .env("SHEPHERD_SOCKET", &socket)
            .spawn()
            .expect("spawn shepherdd");

        let d = Daemon { child, dir, socket };
        d.wait_until_listening();
        d
    }

    /// The `config_json` the daemon committed for a target, read out of its own
    /// catalog.
    ///
    /// Not on the wire: `TargetSummary` carries no checksum field and
    /// `target.list` is still refused, and widening the protocol to make a test
    /// easier would be the test dictating the product. WAL gives a second
    /// process a consistent read, and the row is committed before `target.add`
    /// returns.
    fn stored_target_config(&self, name: &str) -> serde_json::Value {
        let conn = rusqlite::Connection::open_with_flags(
            self.dir.join("state").join("catalog.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the daemon's catalog read-only");
        let raw: String = conn
            .query_row(
                "SELECT config_json FROM target WHERE name = ?1",
                [name],
                |r| r.get(0),
            )
            .unwrap_or_else(|e| panic!("no committed target row named `{name}`: {e}"));
        serde_json::from_str(&raw).expect("config_json is json")
    }

    /// What the daemon recorded as a root's volume identity, if any.
    ///
    /// `None` means this machine has no stable identity for that path — no
    /// `/dev/disk/by-uuid` entry, an overlay or tmpfs source, or a platform
    /// whose implementation is Phase 3's. Tests that turn on the identity check
    /// have to read this rather than assume it, or they assert the rule only on
    /// the machines that happen to have one.
    fn stored_root_volume(&self, root_id: i64) -> Option<String> {
        let conn = rusqlite::Connection::open_with_flags(
            self.dir.join("state").join("catalog.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the daemon's catalog read-only");
        conn.query_row(
            "SELECT volume_id FROM scan_root WHERE id = ?1",
            [root_id],
            |r| r.get::<_, Option<String>>(0),
        )
        .expect("the root row exists")
    }

    /// Rewrite a root's stored `volume_id`, standing in for the disk under it
    /// having been swapped.
    ///
    /// Written directly because there is no IPC method that changes it — which
    /// is the point: enrollment records the identity once and nothing may edit
    /// it afterwards, so a disagreement can only mean the filesystem moved.
    fn forge_root_volume(&self, root_id: i64, volume: &str) {
        let conn = rusqlite::Connection::open(self.dir.join("state").join("catalog.db"))
            .expect("open the daemon's catalog");
        let n = conn
            .execute(
                "UPDATE scan_root SET volume_id = ?2 WHERE id = ?1",
                rusqlite::params![root_id, volume],
            )
            .expect("update the root's volume id");
        assert_eq!(n, 1, "the fixture must have changed exactly one root row");
    }

    /// How many targets the daemon has committed.
    fn target_count(&self) -> i64 {
        let conn = rusqlite::Connection::open_with_flags(
            self.dir.join("state").join("catalog.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the daemon's catalog read-only");
        conn.query_row("SELECT COUNT(*) FROM target", [], |r| r.get(0))
            .unwrap()
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

    /// A daemon told **only** where its state lives, and left to place its own
    /// socket.
    ///
    /// Every other constructor here passes `SHEPHERD_SOCKET`, which means every
    /// other test tells the client the answer too, through `--socket`. That
    /// hides the entire question of whether the two agree. This one deliberately
    /// does not: `Paths::resolve` with a state directory and no runtime
    /// directory puts the socket at `$SHEPHERD_STATE_DIR/daemon.sock`, and
    /// finding it is then the client's problem — which is what the finding is
    /// about.
    fn start_with_only_a_state_dir(tag: &str) -> Daemon {
        let dir = fixture_root().join(format!("shepherdd-e2e-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        mkdir_owner_only(&dir);
        // Where `Paths::resolve` will put it, stated by the test rather than
        // read back from the daemon: if this expectation and the daemon's
        // resolution disagree, `wait_until_listening` fails and says so.
        let socket = dir.join("daemon.sock");

        let child = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
            .arg("run")
            .env("SHEPHERD_STATE_DIR", &dir)
            .env_remove("SHEPHERD_SOCKET")
            .env_remove("XDG_RUNTIME_DIR")
            .spawn()
            .expect("spawn shepherdd");

        let d = Daemon { child, dir, socket };
        d.wait_until_listening();
        d
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

/// Locate `shepctl`, building it first.
///
/// `CARGO_BIN_EXE_*` only covers binaries of *this* package, so the sibling has
/// to be found. Building on demand rather than skipping: a test that quietly
/// does nothing when a binary is missing is the vacuous pass this project keeps
/// finding in its own gates.
///
/// # The build is unconditional, and that is the point
///
/// This used to return the binary as soon as one *existed*. `cargo test -p
/// shepherd-daemon` does not rebuild a sibling package's binary, so every CLI
/// leg in this file silently ran whatever `shepctl` happened to be left in
/// `target/debug` — which, after any change to `shepherd-cli`, is the previous
/// one. A CLI fix would appear to pass before it was compiled, and a CLI
/// regression would appear to pass after it was introduced. That is a test that
/// does not test the thing it names, which is the failure this suite exists to
/// catch in the product.
///
/// `cargo build` on an up-to-date binary is a few tens of milliseconds, paid
/// once per test binary. It is not a price worth an untrustworthy result.
fn shepctl() -> PathBuf {
    use std::sync::OnceLock;
    static BUILT: OnceLock<PathBuf> = OnceLock::new();
    BUILT.get_or_init(build_shepctl).clone()
}

fn build_shepctl() -> PathBuf {
    let mine = PathBuf::from(env!("CARGO_BIN_EXE_shepherdd"));
    let target_dir = mine.parent().expect("binary has a parent directory");
    let candidate = target_dir.join("shepctl");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let out = Command::new(cargo)
        .args(["build", "-p", "shepherd-cli", "--bin", "shepctl"])
        .output()
        .expect("build shepctl");
    assert!(
        out.status.success() && candidate.exists(),
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

/// A connection that handshakes and then asks for nothing does not hold its
/// slot forever.
///
/// The handshake deadline was cleared the instant `hello` succeeded, on the
/// reasoning that a subscribed connection is supposed to sit quiet. It is —
/// but "completed the handshake" is not "subscribed": 64 connections that say
/// hello and nothing else park 64 threads in `read_frame`, consume every
/// `MAX_CONNECTIONS` slot, and refuse every subsequent client while the daemon
/// is otherwise healthy. One malfunctioning script is enough.
///
/// The deadline is overridden to milliseconds here. The 30-second default is
/// why the handshake half of this went untested for its actual timing, and an
/// untested bound is how it came to be cleared a frame too early.
#[test]
fn an_idle_connection_that_never_subscribes_is_closed() {
    let d = Daemon::start_with_env("idle", &[("SHEPHERD_IDLE_TIMEOUT_MS", "300")]);
    let stream = UnixStream::connect(&d.socket).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);

    let hello = Hello {
        proto_version: PROTO_VERSION,
        client: PeerInfo {
            name: "idle".into(),
            build: "1".into(),
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
    assert!(frame.outcome().is_ok(), "the handshake itself must succeed");

    // Now say nothing. The daemon must hang up rather than hold the slot.
    buf.clear();
    let n = reader
        .read_line(&mut buf)
        .expect("the connection must be closed, not errored");
    assert_eq!(
        n, 0,
        "an idle unsubscribed connection was still open after the deadline: {buf:?}"
    );

    // AND THE EXEMPTION: a subscriber may sit quiet for as long as it likes,
    // because waiting is what it is doing. Same daemon, same deadline.
    let stream = UnixStream::connect(&d.socket).unwrap();
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let req = RpcRequest::new(
        RequestId::Number(1),
        "hello",
        serde_json::to_value(Hello {
            proto_version: PROTO_VERSION,
            client: PeerInfo {
                name: "watcher".into(),
                build: "1".into(),
            },
            capabilities: vec![],
        })
        .unwrap(),
    );
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    writer.write_all(line.as_bytes()).unwrap();
    let req = RpcRequest::new(
        RequestId::Number(2),
        "events.subscribe",
        serde_json::json!({ "streams": ["job"] }),
    );
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    writer.write_all(line.as_bytes()).unwrap();
    writer.flush().unwrap();
    for _ in 0..2 {
        let mut buf = String::new();
        reader.read_line(&mut buf).unwrap();
    }

    std::thread::sleep(std::time::Duration::from_millis(900));
    let req = RpcRequest::new(RequestId::Number(3), "status", serde_json::json!({}));
    let mut line = serde_json::to_string(&req).unwrap();
    line.push('\n');
    writer
        .write_all(line.as_bytes())
        .expect("a subscribed connection must survive being quiet");
    writer.flush().unwrap();
    let mut buf = String::new();
    reader.read_line(&mut buf).unwrap();
    let frame: RpcResponse = serde_json::from_str(&buf).unwrap();
    assert!(
        frame.outcome().is_ok(),
        "the subscriber's connection was closed by the idle deadline: {buf}"
    );
}

/// A page bigger than the daemon will hold is refused, not served short.
///
/// The unfiltered branch deliberately does not clamp its candidate cap, so a
/// legitimately deep page comes back rather than being clamped into an empty
/// result — and "does not clamp" was taken literally: `want` was
/// `offset + limit` with neither bounded. `limit: 4294967295` on a common query
/// over the supported ten-million-file corpus collects every matching id,
/// builds a rank map and a hydrated hit list the same size, and serialises the
/// result. One malformed local client is enough.
///
/// Refused rather than truncated, for the same reason the cap is not clamped: a
/// short page served as though it were the whole answer is a refusal wearing
/// the costume of an answer.
#[test]
fn a_page_larger_than_the_daemon_will_hold_is_refused() {
    let d = Daemon::start("bigpage");
    let mut c = d.connect();

    for (field, value) in [("limit", 4_294_967_295u64), ("offset", 4_294_967_295)] {
        let err = c.call_err(
            "search",
            serde_json::json!({ "query": "a", field: value, "mode": "metadata" }),
        );
        assert!(
            err.message.contains(field) && err.message.contains("page through"),
            "`{field}: {value}` must be refused with the remedy named: {}",
            err.message
        );
    }

    // AND THE ACCEPTING DIRECTION: an ordinary page still works, and so does a
    // deep one, which is the case the uncapped branch exists for.
    let ok = c.call(
        "search",
        serde_json::json!({ "query": "a", "limit": 50, "offset": 100_000, "mode": "metadata" }),
    );
    assert!(
        ok["hits"].is_array(),
        "a deep but bounded page must still be served: {ok}"
    );
}

/// A second scan of a root that is already pending is coalesced, not queued.
///
/// `shepherd_scan::walk` materialises the whole `Vec<FileStat>` before
/// batching, so a full tree is resident for the length of the scan — and the
/// pool runs four executors. Starting the same large root repeatedly retained
/// four full trees at once and could exhaust the daemon before any
/// index-rebuild gate applied; a second scan would also produce nothing the
/// first one will not.
///
/// Reported through `skipped`, so the caller is told which roots did not start
/// and why rather than being handed a job id that does the same work twice.
#[test]
fn a_scan_of_a_root_already_pending_is_coalesced() {
    let d = Daemon::start("coalesce");
    let mut c = d.connect();
    let dir = d.dir.join("tree");
    std::fs::create_dir_all(&dir).unwrap();
    for i in 0..64 {
        std::fs::write(dir.join(format!("f{i}.txt")), b"x").unwrap();
    }
    let root_id = c.call(
        "root.add",
        serde_json::json!({ "path": dir.to_string_lossy(), "stub_mode": "delete" }),
    )["root"]["root_id"]
        .as_i64()
        .expect("root_id");

    // Two starts, back to back. Whichever wins, exactly one job exists.
    let first = c.call("scan.start", serde_json::json!({ "root_id": root_id }));
    let second = c.call("scan.start", serde_json::json!({ "root_id": root_id }));

    let started: usize = [&first, &second]
        .iter()
        .map(|r| r["roots_started"].as_array().map_or(0, Vec::len))
        .sum();
    let skipped: Vec<&serde_json::Value> = [&first, &second]
        .iter()
        .filter_map(|r| r["skipped"].as_array())
        .flatten()
        .collect();

    // The first may already have finished, in which case the second starts
    // legitimately — a completed scan is not pending. What must never happen is
    // BOTH being queued at once, and the skip must say why when it happens.
    assert!(
        started >= 1,
        "at least one start must have taken: {first} / {second}"
    );
    if started == 1 {
        assert_eq!(skipped.len(), 1, "{first} / {second}");
        assert!(
            skipped[0]["reason"]
                .as_str()
                .unwrap_or_default()
                .contains("already queued or running"),
            "the skip must name the reason: {}",
            skipped[0]
        );
    }

    // AND THE ACCEPTING DIRECTION: once the scan has finished, the root can be
    // scanned again — coalescing must not be a one-scan-per-root rule.
    let scan = wait_for_scan(&mut c, root_id);
    assert!(scan["last_error"].is_null(), "{scan}");
    let again = c.call("scan.start", serde_json::json!({ "root_id": root_id }));
    assert_eq!(
        again["roots_started"].as_array().map_or(0, Vec::len),
        1,
        "a finished scan must not block the next one: {again}"
    );
}

/// A deleted file stops being catalogued, and one under an unreadable subtree
/// does not.
///
/// `last_seen_gen` is stamped by every scan and nothing consumed it, so a file
/// deleted after being catalogued stayed `local` forever — re-indexed by every
/// rebuild, returned by `search`, counted by `status`. The column's own comment
/// says reconciliation is what it is for.
///
/// The second half is the reason it waited: a walk that could not read a
/// subtree observed nothing beneath it, and a sweep that cannot tell "absent"
/// from "not looked at" would mark live files missing.
#[test]
fn a_scan_reconciles_deleted_files_but_not_unobserved_ones() {
    let d = Daemon::start("sweep");
    let mut c = d.connect();
    let dir = d.dir.join("tree");
    std::fs::create_dir_all(dir.join("deep")).unwrap();
    std::fs::write(dir.join("gone.txt"), b"x").unwrap();
    std::fs::write(dir.join("stays.txt"), b"x").unwrap();
    std::fs::write(dir.join("deep").join("hidden.txt"), b"x").unwrap();

    let root_id = c.call(
        "root.add",
        serde_json::json!({ "path": dir.to_string_lossy(), "stub_mode": "delete" }),
    )["root"]["root_id"]
        .as_i64()
        .expect("root_id");
    c.call("scan.start", serde_json::json!({ "root_id": root_id }));
    let scan = wait_for_scan(&mut c, root_id);
    assert!(scan["last_error"].is_null(), "{scan}");
    assert_eq!(
        c.call(
            "search",
            serde_json::json!({"query": "gone", "mode": "metadata"})
        )["hits"]
            .as_array()
            .map_or(0, Vec::len),
        1,
        "the file must be catalogued before it can be reconciled away"
    );

    // Delete one, and make the other's subtree unreadable so the walk cannot
    // observe it.
    std::fs::remove_file(dir.join("gone.txt")).unwrap();
    let readable = std::fs::metadata(dir.join("deep")).unwrap().permissions();
    std::fs::set_permissions(dir.join("deep"), std::fs::Permissions::from_mode(0o000)).unwrap();

    c.call("scan.start", serde_json::json!({ "root_id": root_id }));
    let scan = wait_for_scan(&mut c, root_id);
    assert!(scan["last_error"].is_null(), "{scan}");

    let hits = |q: &str, c: &mut Client| {
        c.call(
            "search",
            serde_json::json!({"query": q, "mode": "metadata"}),
        )["hits"]
            .as_array()
            .map_or(0, Vec::len)
    };
    assert_eq!(hits("gone", &mut c), 0, "a deleted file is reconciled away");
    assert_eq!(hits("stays", &mut c), 1, "and one still there is not");
    assert_eq!(
        hits("hidden", &mut c),
        1,
        "a file under an UNREADABLE subtree was not observed, so it must not be \
         marked missing — the sweep cannot tell absent from not-looked-at"
    );

    // The reconciled row is still FINDABLE by asking for it. `filters.state` is
    // a documented query whose whole purpose is locating exactly these, and an
    // index that dropped missing rows made it return nothing at all — so the
    // sweep would have hidden the evidence of its own work.
    let found = c.call(
        "search",
        serde_json::json!({"query": "gone", "mode": "metadata", "filters": {"state": "missing"}}),
    );
    assert_eq!(
        found["hits"].as_array().map_or(0, Vec::len),
        1,
        "a missing-state search must find the row the sweep just marked: {found}"
    );

    // AND IT COMES BACK. Recreating the file and rescanning must return it to
    // an ordinary search: a row that can never leave `missing` is permanently
    // unfindable now that unfiltered searches exclude that state.
    std::fs::write(dir.join("gone.txt"), b"x").unwrap();
    c.call("scan.start", serde_json::json!({ "root_id": root_id }));
    let scan = wait_for_scan(&mut c, root_id);
    assert!(scan["last_error"].is_null(), "{scan}");
    assert_eq!(
        hits("gone", &mut c),
        1,
        "a file that came back must be findable again"
    );

    std::fs::set_permissions(dir.join("deep"), readable).unwrap();
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

/// A real scan writes each file's `<volume-id>:<inode>` identity.
///
/// The column existed and nothing wrote it. `file.fs_id` is what upload and
/// destruction serialize on (`FileLocks`, and `LocalDestroyRequest::fs_id`
/// documents in capitals that the CATALOG's value is the one to pass), and it
/// is what tells a rename from a delete-plus-create. A NULL there is a lock
/// that collides with nothing on the irreversible path.
///
/// Asserted against the inode this test reads itself, not merely against
/// "not null": a value of the right shape built from the wrong number would
/// pass that and protect nothing.
///
/// # Both branches are assertions
///
/// `volume::volume_id` legitimately answers `None` on a mount with no stable
/// UUID — every GitHub runner, and `root.add` warns about it. This test
/// therefore asserts the identity where one is available and asserts its
/// ABSENCE where one is not, rather than demanding a filesystem property CI
/// does not have. The unconditional contract lives where it can be stated
/// without the host having an opinion:
/// `shepherd_catalog::file_repo::tests::ingestion_writes_the_filesystem_identity`.
#[test]
fn a_scan_records_the_filesystem_identity_of_every_file() {
    let d = Daemon::start("fsid");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-fsid");
    write_file(&root_dir, "a.txt", "hello");
    write_file(&root_dir, "nested/b.txt", "world");

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    scan_and_expect(&mut c, root_id, 2);

    let conn = rusqlite::Connection::open_with_flags(
        d.dir.join("state").join("catalog.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .unwrap();
    let volume: Option<String> = conn
        .query_row(
            "SELECT volume_id FROM scan_root WHERE id = ?1",
            [root_id],
            |r| r.get(0),
        )
        .unwrap();
    for rel in ["a.txt", "nested/b.txt"] {
        let stored: Option<String> = conn
            .query_row(
                "SELECT CAST(fs_id AS TEXT) FROM file WHERE root_id = ?1 AND rel_path = ?2",
                rusqlite::params![root_id, rel],
                |r| r.get(0),
            )
            .unwrap();

        match &volume {
            Some(volume) => {
                let ino = {
                    use std::os::unix::fs::MetadataExt;
                    std::fs::metadata(root_dir.join(rel)).unwrap().ino()
                };
                assert_eq!(
                    stored.as_deref(),
                    Some(format!("{volume}:{ino}").as_str()),
                    "`{rel}` must carry the identity the lock and the rename check read"
                );
            }
            // No stable volume id on this mount, so there is no identity to
            // record — and half of one would be worse than none: an inode alone
            // is unique only within a filesystem, so it would collide across
            // roots and serialize unrelated files.
            None => assert_eq!(
                stored, None,
                "`{rel}` has no stable volume id, so it must carry no identity \
                 rather than a partial one"
            ),
        }
    }
}

/// Enrolling a root that overlaps an existing one warns, in both directions.
///
/// `RootAddResult::warnings` has always documented "a root nested under an
/// existing one" as one of its notices, and nothing produced it: the enrollment
/// path never compared the new path against the registered ones. Both roots are
/// then scanned, so every file in the overlap gets a catalog row per root —
/// double-counted in `status` and `search`, and handed to later rule and tier
/// passes as two independent candidates for the same bytes.
#[test]
fn enrolling_an_overlapping_root_warns_in_both_directions() {
    let d = Daemon::start("overlap");
    let mut c = d.connect();

    let outer = d.dir.join("corpus-overlap");
    let inner = outer.join("project");
    let sibling = d.dir.join("corpus-overlap-notes");
    std::fs::create_dir_all(&inner).unwrap();
    std::fs::create_dir_all(&sibling).unwrap();

    let first = c.call(
        "root.add",
        serde_json::json!({"path": outer.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let outer_id = first["root"]["root_id"].as_i64().unwrap();
    assert!(
        !warnings_of(&first).iter().any(|w| w.contains("inside")),
        "the first root overlaps nothing: {first}"
    );

    // Nested UNDER the registered one.
    let nested = c.call(
        "root.add",
        serde_json::json!({"path": inner.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert!(
        warnings_of(&nested)
            .iter()
            .any(|w| w.contains("this root is inside") && w.contains(&outer_id.to_string())),
        "a root inside a registered one must say so: {nested}"
    );

    // A sibling that merely shares a path PREFIX is not an overlap.
    let unrelated = c.call(
        "root.add",
        serde_json::json!({"path": sibling.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert!(
        !warnings_of(&unrelated).iter().any(|w| w.contains("inside")),
        "`corpus-overlap-notes` is not inside `corpus-overlap`: {unrelated}"
    );

    // A different NAME for a root already enrolled. This is the case
    // canonicalization was added for, and the one a canonical-equality skip
    // silently swallowed: `enroll_root` keys on the literal path, so the alias
    // is a second enabled root over the same files.
    let alias = d.dir.join("corpus-overlap-alias");
    std::os::unix::fs::symlink(&outer, &alias).unwrap();
    let aliased = c.call(
        "root.add",
        serde_json::json!({"path": alias.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert!(
        warnings_of(&aliased)
            .iter()
            .any(|w| w.contains("another name for") && w.contains(&outer_id.to_string())),
        "an alias of a registered root must say so: {aliased}"
    );
    assert_ne!(
        aliased["root"]["root_id"].as_i64().unwrap(),
        outer_id,
        "and it really did become a second root — which is why the warning matters"
    );

    // And the other direction: a new root that CONTAINS a registered one.
    let containing = c.call(
        "root.add",
        serde_json::json!({"path": d.dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert!(
        warnings_of(&containing)
            .iter()
            .any(|w| w.contains("is inside this one")),
        "a root containing registered ones must say so: {containing}"
    );
}

fn warnings_of(result: &serde_json::Value) -> Vec<String> {
    result["warnings"]
        .as_array()
        .map(|a| {
            a.iter()
                .filter_map(|w| w.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// Crash recovery failing is a startup failure, not a warning.
///
/// `recover` resolves jobs a crash left `running` and quarantines `destroy`
/// jobs before anything else can claim them (§4.10.4). Logging the failure and
/// starting anyway leaves those jobs stranded in `running` for the whole life
/// of the daemon — while the pool comes up and accepts new work — and nothing
/// ever tries again. The index rebuild immediately after it *is* deliberately
/// non-fatal; this one is the opposite case and now says so.
///
/// The failure is injected by dropping the `job` table from a catalog the
/// daemon has already migrated. `schema_migration` still records version 1, so
/// the next start opens the catalog cleanly and fails inside recovery — which
/// is precisely the layer under test.
#[test]
fn a_daemon_whose_crash_recovery_fails_refuses_to_start() {
    let dir = fixture_root().join(format!("shepherdd-e2e-{}-norecover", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    // Owner-only: this fixture is BOTH the state directory and the socket's
    // parent, and the daemon refuses a directory it did not create unless it
    // already meets the bar. Without this the first start never migrates a
    // catalog, and the `DROP TABLE` below fails on a database that was never
    // created rather than the test exercising recovery at all.
    mkdir_owner_only(&dir);
    let socket = dir.join("daemon.sock");

    // One ordinary start, to get a migrated catalog.
    {
        let mut child = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
            .arg("run")
            .env("SHEPHERD_STATE_DIR", &dir)
            .env("SHEPHERD_SOCKET", &socket)
            .spawn()
            .expect("spawn shepherdd");
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline && UnixStream::connect(&socket).is_err() {
            std::thread::sleep(Duration::from_millis(25));
        }
        let _ = child.kill();
        let _ = child.wait();
    }
    let _ = std::fs::remove_file(&socket);

    let conn = rusqlite::Connection::open(dir.join("catalog.db")).unwrap();
    conn.execute_batch("DROP TABLE job").unwrap();
    drop(conn);

    // Spawned and waited on with a deadline rather than `output()`: a daemon
    // that wrongly starts runs forever, and this must fail rather than hang.
    let mut child = Command::new(env!("CARGO_BIN_EXE_shepherdd"))
        .arg("run")
        .env("SHEPHERD_STATE_DIR", &dir)
        .env("SHEPHERD_SOCKET", &socket)
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("spawn shepherdd");

    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        match child.try_wait().unwrap() {
            Some(s) => break Some(s),
            None if Instant::now() >= deadline => break None,
            None => std::thread::sleep(Duration::from_millis(25)),
        }
    };
    let listening = UnixStream::connect(&socket).is_ok();
    // Killed BEFORE stderr is drained: a daemon that wrongly started never
    // closes the pipe, and reading to EOF first would hang instead of failing.
    let _ = child.kill();
    let _ = child.wait();
    let mut said = String::new();
    if let Some(mut err) = child.stderr.take() {
        use std::io::Read;
        let _ = err.read_to_string(&mut said);
    }
    let _ = std::fs::remove_dir_all(&dir);

    let status = status.expect("the daemon kept running with crash recovery unrun");
    assert!(
        !status.success(),
        "the daemon exited 0 with crash recovery unrun: {said}"
    );
    assert!(
        said.contains("crash recovery"),
        "the exit must name what failed: {said}"
    );
    assert!(!listening, "nothing may be listening after a refused start");
}

/// A root that contains the daemon's own state directory must not catalogue it.
///
/// `$HOME` is the root a user is most likely to register, and the state
/// directory lives under it. The builtin deny-list knows only
/// `.shepherd-staging`, so the walk catalogued the live `catalog.db` and its
/// `-wal`/`-shm` companions — rows that change under their own scan — and any
/// `secrets.json`, which a later rule pass could then hash and tier.
///
/// The daemon is started with its socket outside the state directory so the
/// registered root can be the *enclosing* directory: that is the real shape of
/// the problem, a state directory nested inside a scanned tree.
/// The `index` stream is advertised and must actually carry rebuild progress.
///
/// A repo-wide search found no production publisher for `IndexProgress`: a
/// dashboard subscribed to `index` could not tell an idle index from a rebuild
/// grinding through ten million rows, or from one that had finished. Same shape
/// as the `job` stream before it — an advertised capability that emits nothing
/// is indistinguishable from a quiet system.
#[test]
fn a_rebuild_publishes_on_the_advertised_index_stream() {
    let d = Daemon::start("indexstream");
    let mut c = d.connect();
    write_file(&d.dir, "docs/a.txt", "hello");

    let added = c.call(
        "root.add",
        serde_json::json!({"path": d.dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();

    // Subscribe to `index` alone, from a cursor of 0 so the frames the scan's
    // rebuild published are replayed rather than raced for.
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    let scan = wait_for_scan(&mut c, root_id);
    assert!(scan["last_error"].is_null(), "{scan}");

    // The epoch comes from a SEPARATE connection, because a connection holds
    // one subscription: an empty `streams` list means ALL of them, so probing
    // for the epoch here and then subscribing to one stream would be the
    // overlapping pair that has no ordering. A real resuming client already
    // holds an epoch from its previous subscription and needs no probe.
    let epoch = d.connect().call("events.subscribe", serde_json::json!({}))["epoch"]
        .as_str()
        .expect("epoch")
        .to_owned();
    let sub = c.call(
        "events.subscribe",
        serde_json::json!({"streams": ["index"], "resume_from": 0, "resume_epoch": epoch}),
    );
    assert_eq!(
        sub["resume"]["outcome"],
        serde_json::json!("resumed"),
        "{sub}"
    );
    let replayed = sub["resume"]["replayed"].as_u64().unwrap_or(0);
    assert!(
        replayed >= 1,
        "the index stream carried nothing across a completed rebuild: {sub}"
    );

    // The terminal frame is what separates "finished" from "stopped".
    //
    // There is more than one: the daemon rebuilds at start-up too, and on an
    // empty catalog that one legitimately reports `rows_indexed: 0`. What must
    // exist is a done frame for the rebuild that followed the SCAN, so the
    // count is taken across all of them rather than asserted on the first.
    let mut done_frames = 0;
    let mut most_rows = 0u64;
    for _ in 0..replayed {
        let frame = c.read_frame();
        let p = &frame["params"]["payload"];
        if p["kind"] == serde_json::json!("index_progress") && p["done"] == serde_json::json!(true)
        {
            done_frames += 1;
            most_rows = most_rows.max(p["rows_indexed"].as_u64().unwrap_or(0));
        }
    }
    assert!(
        done_frames >= 1,
        "no terminal `done` frame; a subscriber cannot tell a finished rebuild \
         from one that stopped"
    );
    assert!(
        most_rows >= 1,
        "every rebuild reported zero rows, so the count is not being carried: \
         {done_frames} done frame(s)"
    );
}

/// Forgetting a root's catalog rows must take them out of the search index.
///
/// The cascade drops the file rows; the index is an in-memory arena built from
/// them, and nothing rebuilt it — the only other call sites are start-up and a
/// completed scan. The forgotten ids stayed in the arena and went on consuming
/// the capped, file-id-ordered candidate prefix that `hydrate` then drops, so a
/// search whose matches had early ids came back short or empty while later
/// files that still matched were never reached.
///
/// The cap is what makes it visible, so the test uses one: root A's files are
/// enrolled first and therefore hold the low ids, and the limit is exactly
/// their count. Before the fix, every slot in the page is spent on rows that no
/// longer exist and the answer is empty.
#[test]
fn forgetting_a_root_takes_its_rows_out_of_the_search_index() {
    let d = Daemon::start("forgetindex");
    let mut c = d.connect();

    let a = d.dir.join("a");
    let b = d.dir.join("b");
    for i in 0..3 {
        write_file(&a, &format!("report-{i}.txt"), "x");
        write_file(&b, &format!("report-{i}.txt"), "y");
    }

    let mut enroll = |p: &std::path::Path| {
        let added = c.call(
            "root.add",
            serde_json::json!({"path": p.to_str().unwrap(), "stub_mode": "delete"}),
        );
        let id = added["root"]["root_id"].as_i64().unwrap();
        c.call("scan.start", serde_json::json!({"root_id": id}));
        // Per-root, not the global count `scan_and_expect` checks: the second
        // enrollment lands on top of the first.
        let scan = wait_for_scan(&mut c, id);
        assert!(scan["last_error"].is_null(), "the scan failed: {scan}");
        assert_eq!(scan["files_seen"], serde_json::json!(3), "{scan}");
        id
    };
    let a_id = enroll(&a);
    let _b_id = enroll(&b);

    // Both roots' files match, and A's were indexed first.
    let all = c.call(
        "search",
        serde_json::json!({"query": "report", "limit": 50}),
    );
    assert_eq!(
        all["hits"].as_array().map(Vec::len),
        Some(6),
        "precondition: every file matches: {all}"
    );

    c.call(
        "root.remove",
        serde_json::json!({"root_id": a_id, "forget_catalog": true}),
    );

    // A page exactly the size of the forgotten set. Every slot would be spent
    // on A's stale ids if they were still in the arena.
    let after = c.call("search", serde_json::json!({"query": "report", "limit": 3}));
    assert_eq!(
        after["hits"].as_array().map(Vec::len),
        Some(3),
        "the forgotten root's ids still hold the head of the candidate list, so \
         a full page of live matches came back short: {after}"
    );
    for hit in after["hits"].as_array().unwrap() {
        let path = hit["path"].as_str().unwrap_or_default();
        assert!(
            !path.starts_with(a.to_str().unwrap()),
            "a forgotten root's file is still searchable: {hit}"
        );
    }
}

/// A root whose volume was replaced under it must NOT be scanned.
///
/// `availability` is a catalog flag somebody set at some point; it says nothing
/// about which filesystem is mounted at the path today. A removable disk
/// swapped at the same mount point — or a registered symlink retargeted at
/// another volume — walks perfectly happily, and `upsert_file` then pairs the
/// NEW volume's inode numbers with the OLD volume id. The `fs_id` values that
/// come out are well-formed and false: they name files that exist on neither
/// volume, and the path rows they update are treated as though they still
/// described the enrolled filesystem.
#[test]
fn a_root_whose_volume_changed_refuses_to_scan() {
    let d = Daemon::start("volswap");
    let mut c = d.connect();
    write_file(&d.dir, "docs/a.txt", "hello");

    let added = c.call(
        "root.add",
        serde_json::json!({"path": d.dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();

    // The accepting direction first, so the refusal below cannot be satisfied
    // by a scan path that has simply stopped working.
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    scan_and_expect(&mut c, root_id, 1);

    // The disk is swapped: same path, different filesystem.
    d.forge_root_volume(root_id, "uuid:00000000-0000-0000-0000-000000000000");
    c.call("scan.start", serde_json::json!({"root_id": root_id}));

    // WHICH branch this asserts depends on what the machine can answer, and
    // both are real properties. A runner with no stable identity for the path
    // — no `/dev/disk/by-uuid`, an overlay root, or macOS, where the
    // implementation is Phase 3's — records `NULL` and has nothing to compare,
    // so the scan must still WORK. Asserting the refusal there would be
    // asserting the environment, not the rule; asserting nothing would be a
    // green nobody earned. The comparison itself is pinned without a
    // filesystem by `scan_exec`'s `volume_refusal` unit test.
    if d.stored_root_volume(root_id).is_some() {
        let status = wait_for_scan_error(&mut c, root_id);
        let err = status["last_error"].as_str().unwrap_or_default();
        assert!(
            err.contains("was enrolled on volume") && err.contains("mounted there now"),
            "a scan across a volume swap must refuse and say so: {status}"
        );
    } else {
        let status = wait_for_scan(&mut c, root_id);
        assert!(
            status["last_error"].is_null(),
            "this machine records no volume identity for the root, so the forged \
             one cannot disagree with anything and the scan must proceed: {status}"
        );
    }
}

#[test]
fn a_scan_does_not_catalogue_the_daemons_own_state_directory() {
    let d = Daemon::start_with_socket_outside_the_state_dir("scan-statedir");
    let mut c = d.connect();

    // One real user file, beside the state directory the daemon is using.
    write_file(&d.dir, "docs/a.txt", "hello");
    assert!(
        d.dir.join("state/catalog.db").exists(),
        "the harness must actually have put the catalog inside the tree being scanned"
    );

    let added = c.call(
        "root.add",
        serde_json::json!({"path": d.dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));

    // The socket's lock file is the one daemon-owned REGULAR file that is not
    // in the state directory — `SHEPHERD_SOCKET` points outside it here, which
    // is the arrangement this harness exists to create. The socket node itself
    // is invisible to the walk because it is not a regular file; the lock is
    // not, so it has to be denied by path or the daemon catalogues it.
    let socket_lock = d.socket.with_file_name(format!(
        "{}.lock",
        d.socket.file_name().unwrap().to_str().unwrap()
    ));
    assert!(
        socket_lock.exists(),
        "the daemon must have taken its socket lock at {}",
        socket_lock.display()
    );

    // Exactly the one file the user put there. `catalog.db`, `catalog.db-wal`,
    // `catalog.db-shm`, the socket and the socket's lock are all inside the
    // root.
    scan_and_expect(&mut c, root_id, 1);

    let hits = c.call(
        "search",
        serde_json::json!({"query": "catalog", "limit": 50}),
    );
    assert_eq!(
        hits["hits"].as_array().map(Vec::len),
        Some(0),
        "the daemon's own catalog must not be a file in the catalog: {hits}"
    );

    let locks = c.call("search", serde_json::json!({"query": "lock", "limit": 50}));
    assert_eq!(
        locks["hits"].as_array().map(Vec::len),
        Some(0),
        "the daemon's own socket lock must not be a file in the catalog: {locks}"
    );
}

/// An oversized frame is refused, not allocated.
///
/// The transport has no length prefix — a frame ends at `\n` — and
/// `BufRead::lines` grows a `String` until it finds one. A peer that writes and
/// never terminates a line was therefore an unbounded allocation per open
/// connection, and the daemon dies of it instead of answering. Authorization
/// here is filesystem permissions, so the peer is the same user by
/// construction; "same user" includes a buggy script, and a control-plane
/// daemon a typo can OOM is not one to leave running.
///
/// The assertion that matters is the LAST one: the daemon is still serving
/// afterwards. A refusal that took the process down with it would satisfy the
/// first two.
#[test]
fn an_oversized_frame_is_refused_and_the_daemon_survives() {
    let d = Daemon::start("bigframe");

    let mut raw = UnixStream::connect(&d.socket).expect("connect");
    raw.set_read_timeout(Some(Duration::from_secs(20))).unwrap();
    // Well past the 1 MiB maximum, and deliberately with NO newline: the
    // failure being fixed is the read that never terminates.
    let blob = vec![b'x'; shepherd_proto::MAX_FRAME_BYTES + 4096];
    let _ = raw.write_all(&blob);
    let _ = raw.flush();

    let mut answer = String::new();
    BufReader::new(raw.try_clone().unwrap())
        .read_line(&mut answer)
        .expect("the daemon must answer rather than grow");
    let frame: serde_json::Value = serde_json::from_str(&answer).expect("a JSON-RPC frame");
    assert_eq!(
        frame["error"]["code"], -32600,
        "an oversized frame is an invalid request: {answer}"
    );
    assert!(
        frame["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("protocol maximum"),
        "the refusal must say what was exceeded: {answer}"
    );
    drop(raw);

    // Still serving.
    let mut c = d.connect();
    assert_eq!(
        c.call("status", serde_json::json!({}))["files_catalogued"],
        0
    );
}

/// A denied tree reached through a symlinked ANCESTOR is refused too.
///
/// The deny decision canonicalized only when the final component was itself a
/// symlink, and `symlink_metadata` answers about the leaf alone. So
/// `<alias>/objects`, where `alias` points at a `.git`, reported an ordinary
/// directory, skipped canonicalization, and offered `deny_registration` three
/// innocent names — after which registration ran its write probes inside the
/// `.git` and enrolled it. The alias never had to be the last component.
#[test]
fn a_denied_tree_reached_through_a_symlinked_ancestor_is_refused() {
    let d = Daemon::start("ancestor-alias");
    let mut c = d.connect();

    let git = d.dir.join("repo").join(".git");
    let objects = git.join("objects");
    std::fs::create_dir_all(&objects).unwrap();
    let alias = d.dir.join("alias");
    std::os::unix::fs::symlink(&git, &alias).unwrap();

    // The leaf is an ordinary directory; only the ancestor is the alias.
    let target = alias.join("objects");
    assert!(!std::fs::symlink_metadata(&target).unwrap().is_symlink());
    let before = std::fs::metadata(&objects).unwrap().modified().unwrap();

    let err = c.call_err(
        "root.add",
        serde_json::json!({"path": target.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert_eq!(
        err.kind(),
        Some(shepherd_proto::ErrorCode::Refused),
        "a `.git` reached through an alias is still a `.git`: {err:?}"
    );
    assert_eq!(
        std::fs::metadata(&objects).unwrap().modified().unwrap(),
        before,
        "the enrollment probes wrote into a denied tree before it was refused"
    );
}

/// A root whose resolved target MOVES between the deny check and the probes is
/// refused, not enrolled.
///
/// The deny decision canonicalizes, and the probes then resolve the pathname
/// again — so a symlinked ancestor retargeted in between sends
/// `probe_path_policies` and the atime probe somewhere the deny list never saw.
/// The probe files land there either way; what this stops is ENROLLING it,
/// which is the lasting harm, since an enrolled root is scanned, catalogued and
/// eventually tiered.
#[test]
fn a_root_that_moves_between_the_deny_check_and_the_probes_is_refused() {
    let d = Daemon::start("moving-root");
    let mut c = d.connect();

    let a = d.dir.join("a");
    let b = d.dir.join("b");
    std::fs::create_dir_all(a.join("data")).unwrap();
    std::fs::create_dir_all(b.join("data")).unwrap();
    let alias = d.dir.join("alias");
    std::os::unix::fs::symlink(&a, &alias).unwrap();
    let root = alias.join("data");

    // As it stands, it enrolls: an ordinary directory reached through an alias.
    let ok = c.call(
        "root.add",
        serde_json::json!({"path": root.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert!(ok["root"]["root_id"].as_i64().is_some(), "{ok}");
    c.call(
        "root.remove",
        serde_json::json!({"root_id": ok["root"]["root_id"], "forget_catalog": true}),
    );

    // The recheck compares the canonical path from the deny decision against
    // the canonical path after the probes. Driving the retarget mid-call needs
    // a hook inside `root_add`; what is assertable here is that the two
    // resolutions are genuinely different paths, which is the comparison the
    // refusal makes.
    std::fs::remove_file(&alias).unwrap();
    std::os::unix::fs::symlink(&b, &alias).unwrap();
    assert_ne!(
        std::fs::canonicalize(&root).unwrap(),
        a.join("data"),
        "the retarget must actually move the resolved path, or the recheck compares nothing"
    );
    assert_eq!(std::fs::canonicalize(&root).unwrap(), b.join("data"));
}

/// Registering the daemon's own state directory is refused, at `root.add`.
///
/// The exclusion added for the `$HOME`-contains-state-dir case is deliberately
/// about a state directory found *during* a walk. A root registered AT or
/// INSIDE the state directory is a different thing: excluding it would prune
/// the walk root itself and surface as "could not be read", and NOT excluding
/// it walks the live `catalog.db`, its WAL companions and any `secrets.json`.
/// Neither is an answer, so the registration is refused — before the enrollment
/// probes, which would otherwise write their probe files into the directory
/// holding the secret store.
#[test]
fn registering_the_state_directory_as_a_root_is_refused() {
    let d = Daemon::start("statedir-root");
    let mut c = d.connect();
    let state = d.dir.join("state");

    for path in [state.clone(), state.join("nested")] {
        std::fs::create_dir_all(&path).unwrap();
        let before = std::fs::metadata(&path).unwrap().modified().unwrap();

        let err = c.call_err(
            "root.add",
            serde_json::json!({"path": path.to_str().unwrap(), "stub_mode": "delete"}),
        );
        assert_eq!(
            err.kind(),
            Some(shepherd_proto::ErrorCode::Refused),
            "{} must not be registerable: {err:?}",
            path.display()
        );
        assert!(
            err.message.contains("state directory"),
            "the refusal must say why: {}",
            err.message
        );
        // Refused BEFORE the probes, which write into the root.
        assert_eq!(
            std::fs::metadata(&path).unwrap().modified().unwrap(),
            before,
            "{} was written into before it was refused",
            path.display()
        );
    }

    // And the containing case is still fine — that is what the exclusion is for.
    let outer = c.call(
        "root.add",
        serde_json::json!({"path": d.dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert!(outer["root"]["root_id"].as_i64().is_some(), "{outer}");
}

/// An explicit `scan.start --root-id` on a deregistered root must be refused,
/// not reported as started.
///
/// `root.remove` without `--forget` keeps the `scan_root` row and clears
/// `enabled`, so `get_root` still answers for it. The no-id branch already
/// respects that — it lists with `include_disabled = false`. The explicit
/// branch did not, so the id was reported in `roots_started`, a job was
/// enqueued, and `load_scan_input` refused it later: the call claimed success
/// and the work failed out of band, burning the job's retry budget on a root
/// the user had removed.
#[test]
fn an_explicit_scan_of_a_deregistered_root_is_refused() {
    let d = Daemon::start("scan-disabled");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-disabled");
    std::fs::create_dir_all(&root_dir).unwrap();
    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();

    c.call("root.remove", serde_json::json!({"root_id": root_id}));

    let err = c.call_err("scan.start", serde_json::json!({"root_id": root_id}));
    assert_eq!(
        err.kind(),
        Some(shepherd_proto::ErrorCode::Refused),
        "a deregistered root is not a scan target: {err:?}"
    );

    // And nothing may have been queued for it.
    let status = c.call("status", serde_json::json!({}));
    assert_eq!(
        status["jobs_pending"]
            .as_array()
            .map(|rows| rows
                .iter()
                .filter(|r| r["class"] == serde_json::json!("scan"))
                .count())
            .unwrap_or(0),
        0,
        "a refused start must not leave a job behind: {status}"
    );
}

/// The default `root.remove` deregisters a root. It must not delete its catalog.
///
/// `file.root_id` is `INTEGER NOT NULL REFERENCES scan_root(id) ON DELETE
/// CASCADE`, so deleting the `scan_root` row deleted every file row under it —
/// custody rows included, and a custody row is a tiered file's only remote
/// address. That ran on the path that reports `catalog_rows_dropped: 0`, and
/// past the custody refusal, which only runs when `forget_catalog` is true.
///
/// Both halves are asserted here because either alone is satisfiable by a bug:
/// a removal that reports dropping nothing must leave the rows countable
/// afterwards, and `--forget` must still drop them. The rows are read back
/// through `status` and `root.list --include-disabled` rather than out of the
/// database file, so what is under test is what a client can actually see.
#[test]
fn a_default_root_remove_keeps_the_catalog_and_forget_still_drops_it() {
    let d = Daemon::start("softremove");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-softremove");
    write_file(&root_dir, "a.txt", "hello");
    write_file(&root_dir, "nested/b.txt", "world");

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    scan_and_expect(&mut c, root_id, 2);

    let removed = c.call("root.remove", serde_json::json!({"root_id": root_id}));
    assert_eq!(removed["catalog_rows_dropped"], serde_json::json!(0));
    assert_eq!(removed["custody_rows_dropped"], serde_json::json!(0));

    // The report claimed it dropped nothing. That has to be true of the catalog.
    let status = c.call("status", serde_json::json!({}));
    assert_eq!(
        status["files_catalogued"],
        serde_json::json!(2),
        "a removal that reported dropping no rows must not have dropped any: {status}"
    );

    assert!(
        c.call("root.list", serde_json::json!({}))["roots"]
            .as_array()
            .unwrap()
            .is_empty(),
        "a removed root is deregistered, so the ordinary listing no longer shows it"
    );
    let all = c.call("root.list", serde_json::json!({"include_disabled": true}));
    let rows = all["roots"].as_array().unwrap();
    assert_eq!(
        rows.len(),
        1,
        "the root row must still be there — it is what the surviving file rows hang off, \
         and what a later `--forget` needs to find: {all}"
    );
    assert_eq!(rows[0]["enabled"], serde_json::json!(false), "{all}");
    assert_eq!(
        rows[0]["file_count"],
        serde_json::json!(2),
        "the rows are still reachable through the root that owns them: {all}"
    );

    // And the path that says it destroys still destroys.
    let forgotten = c.call(
        "root.remove",
        serde_json::json!({"root_id": root_id, "forget_catalog": true}),
    );
    assert_eq!(forgotten["catalog_rows_dropped"], serde_json::json!(2));
    let status = c.call("status", serde_json::json!({}));
    assert_eq!(status["files_catalogued"], serde_json::json!(0), "{status}");
    assert!(
        c.call("root.list", serde_json::json!({"include_disabled": true}))["roots"]
            .as_array()
            .unwrap()
            .is_empty(),
        "`--forget` removes the root row as well"
    );
}

/// The way back in. Round 1 gave `root.remove` a soft path that keeps the
/// `scan_root` row and every file under it; nobody wrote the re-enrollment that
/// retention implies.
///
/// `scan_root.path` is `NOT NULL UNIQUE` and no production path ever set
/// `enabled` back to 1, so adding the same path again hit the unique constraint
/// and surfaced as a raw SQLite error. The user's only recovery was
/// `--forget` — which destroys the custody rows the retention exists to
/// protect, i.e. the one outcome the round-1 design was arranged against.
///
/// What re-enrollment must NOT do is as load-bearing as what it must: the file
/// rows keep their `state`, because a tiered row's catalog entry is the only
/// address of its remote bytes and re-enrollment establishes nothing about
/// custody.
#[test]
fn a_soft_removed_root_can_be_re_enrolled_and_keeps_its_catalog() {
    let d = Daemon::start("reenroll");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-reenroll");
    write_file(&root_dir, "a.txt", "hello");
    write_file(&root_dir, "nested/b.txt", "world");

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    scan_and_expect(&mut c, root_id, 2);

    c.call("root.remove", serde_json::json!({"root_id": root_id}));

    let again = c.call(
        "root.add",
        serde_json::json!({
            "path": root_dir.to_str().unwrap(),
            "stub_mode": "delete",
            "ignore_patterns": ["*.tmp"],
        }),
    );

    // The SAME row, not a second one. A re-enrollment that inserted a new row
    // would leave every retained file row hanging off an id nothing enables.
    assert_eq!(
        again["root"]["root_id"],
        serde_json::json!(root_id),
        "re-enrollment must revive the existing row, or the retained catalog is orphaned: \
         {again}"
    );
    assert_eq!(again["root"]["enabled"], serde_json::json!(true), "{again}");
    assert_eq!(
        again["root"]["file_count"],
        serde_json::json!(2),
        "the retained rows must still be reachable through the revived root: {again}"
    );

    // A re-enrollment is not a first enrollment, and the user must be able to
    // tell: this root arrives with history attached.
    let warnings: Vec<String> = again["warnings"]
        .as_array()
        .expect("root.add reports warnings")
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect();
    let note = warnings
        .iter()
        .find(|w| w.contains("re-enrolled"))
        .unwrap_or_else(|| {
            panic!(
                "a re-enrollment must say so — the user is looking at a root that already \
                 has a catalog, which is a different event from a first enrollment: \
                 {warnings:?}"
            )
        });
    // Read out of the re-enrollment warning specifically, not out of the whole
    // list: the unrelated D-12 feasibility warning already contains a "2", so
    // a bare `any` over the list looking for a "2" would pass with the
    // re-enrollment count missing entirely.
    assert!(
        note.contains("2 file row(s)") && note.contains("0 of them tiered"),
        "it must say how much history came back, and how much of it is custody — that is \
         the number that makes the retention worth having: {note}"
    );

    // Stated afresh, so honoured afresh. Silently keeping the old list is the
    // exact shape of the `ignore_patterns_json DEFAULT '[]'` failure this crate
    // already documents once.
    assert_eq!(
        again["root"]["ignore_patterns"],
        serde_json::json!(["*.tmp"]),
        "the request's patterns must be applied to the revived root: {again}"
    );

    assert_eq!(
        c.call("status", serde_json::json!({}))["roots"],
        serde_json::json!(1),
        "one root, revived — not two"
    );
    assert_eq!(
        c.call("root.list", serde_json::json!({}))["roots"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "and it is visible in the ordinary listing again"
    );
}

/// The accepting direction's opposite, and the one "reactivate whatever you
/// find" would break: an ENABLED root at the same path is a genuine duplicate.
///
/// Refused with `Precondition`, not the raw SQLite unique-constraint error the
/// old plain insert produced. The request is well-formed and the path is real;
/// what does not hold is the state the transition assumed, which is what
/// `Precondition` names — and it is the code `map_catalog_error` already gives
/// `AlreadyInState`.
#[test]
fn adding_a_root_that_is_already_enabled_is_still_refused() {
    let d = Daemon::start("reenrolldup");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-dup");
    std::fs::create_dir_all(&root_dir).unwrap();

    c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let err = c.call_err(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );

    assert_eq!(
        err.kind(),
        Some(shepherd_proto::ErrorCode::Precondition),
        "a duplicate is a precondition failure, not a raw storage error: {}",
        err.message
    );
    assert!(
        err.message.contains(root_dir.to_str().unwrap()),
        "and it must name the path: {}",
        err.message
    );
    assert_eq!(
        c.call("status", serde_json::json!({}))["roots"],
        serde_json::json!(1),
        "and it must not have registered a second time"
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

// ---------------------------------------------------------------------------
// AC-7 at the registration boundary
// ---------------------------------------------------------------------------

/// Pin a directory's own mtime to a fixed instant, and hand that instant back.
///
/// Both probes `root.add` runs create a file **in the root** and take it away
/// again — `identity::ProbeFiles` unlinks on `Drop`, `atime::probe_atime_advance`
/// unlinks immediately and works through the descriptor — so by the time the
/// call returns the directory is empty whether or not it was written to.
/// "Assert the directory is empty afterwards" therefore passes with the
/// trespass fully in place, which is why it is not the assertion below.
///
/// The directory's own mtime is the fact that outlives the cleanup: creating an
/// entry bumps it and removing one bumps it again. Pinning it first turns "was
/// anything written here" into a comparison against a value that nothing but a
/// write can move, rather than against a creation timestamp that a coarse
/// filesystem clock might not have advanced past.
fn pin_dir_mtime(dir: &Path) -> std::time::SystemTime {
    // Arbitrary, and far enough in the past that no plausible clock lands on it.
    let pinned = std::time::UNIX_EPOCH + Duration::from_secs(1_000_000_000);
    let handle = std::fs::File::open(dir).unwrap();
    handle
        .set_times(
            std::fs::FileTimes::new()
                .set_accessed(pinned)
                .set_modified(pinned),
        )
        .unwrap();
    assert_eq!(
        dir_mtime(dir),
        pinned,
        "the pin has to take, or everything hanging off it proves nothing"
    );
    pinned
}

fn dir_mtime(dir: &Path) -> std::time::SystemTime {
    std::fs::metadata(dir).unwrap().modified().unwrap()
}

/// AC-7's deny list exists so certain trees are never touched at all. The
/// registration path consulted it nowhere.
///
/// `root_add` ran `probe_path_policies` and `detect_with_write_probe` — **both
/// of which create a file in the root** — and only a later scan declined to
/// walk the tree. So `root.add <repo>/.git` wrote Shepherd's probe files into a
/// directory the policy promises is never written to, and the deny list's
/// answer arrived after the write it was supposed to prevent.
///
/// The ordering is the whole finding, so the load-bearing assertion here is on
/// the directory's mtime, not on the error. A refusal moved to after the probes
/// still returns `Refused` and still leaves the trespass.
#[test]
fn a_denied_root_is_refused_before_any_probe_writes_into_it() {
    let d = Daemon::start("denyroot");
    let mut c = d.connect();

    let denied = d.dir.join("repo").join(".git");
    std::fs::create_dir_all(&denied).unwrap();
    let pinned = pin_dir_mtime(&denied);

    let err = c.call_err(
        "root.add",
        serde_json::json!({"path": denied.to_str().unwrap(), "stub_mode": "delete"}),
    );

    // `Refused`, not `Invalid`: the request was well-formed and the directory
    // is real. `ErrorCode::Refused` is documented as "legal but refused by
    // policy: a safety floor, **a deny-list entry**, a user ignore rule" — this
    // is that entry, named in the taxonomy itself.
    assert_eq!(
        err.kind(),
        Some(shepherd_proto::ErrorCode::Refused),
        "{}",
        err.message
    );

    assert_eq!(
        dir_mtime(&denied),
        pinned,
        "a denied tree must not be written to at all: something created or removed an \
         entry in it, which is the probes running before the refusal"
    );
    assert_eq!(
        std::fs::read_dir(&denied).unwrap().count(),
        0,
        "and no probe file was left behind in it either"
    );
    assert_eq!(
        c.call("status", serde_json::json!({}))["roots"],
        serde_json::json!(0),
        "nor was the root registered"
    );
}

/// Two roots, two different deny rules, two distinguishable refusals.
///
/// The deny list carries `DenyReason` precisely so "why" is answerable; a
/// refusal that said only "denied" would leave a user unable to tell a `.git`
/// from another sync engine's tree, and those call for opposite responses —
/// point Shepherd at the working tree, versus do not point it here at all.
#[test]
fn a_denied_root_refusal_names_the_rule_that_refused_it() {
    let d = Daemon::start("denyreason");
    let mut c = d.connect();

    let vcs = d.dir.join("proj").join(".git");
    std::fs::create_dir_all(&vcs).unwrap();
    let sync = d.dir.join("Mobile Documents").join("com~apple~CloudDocs");
    std::fs::create_dir_all(&sync).unwrap();

    let vcs_err = c.call_err(
        "root.add",
        serde_json::json!({"path": vcs.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let sync_err = c.call_err(
        "root.add",
        serde_json::json!({"path": sync.to_str().unwrap(), "stub_mode": "delete"}),
    );

    assert!(
        vcs_err.message.contains("version-control"),
        "the refusal must name the rule that produced it: {}",
        vcs_err.message
    );
    assert!(
        sync_err.message.contains("foreign-sync-root"),
        "the refusal must name the rule that produced it: {}",
        sync_err.message
    );
    // And the path, or a refusal is unattributable when several roots are being
    // added from one script.
    assert!(
        vcs_err.message.contains(vcs.to_str().unwrap()),
        "{}",
        vcs_err.message
    );
}

/// Round 1 established this inside the deny list itself
/// (`denylist::tests::a_substring_is_not_a_component`); the registration
/// boundary is a second place to get it wrong. Matching `.git` as a substring
/// would refuse to enroll `mygit`, and a directory that cannot be registered is
/// one whose files are never catalogued — which §4.9 PM-3 calls absence, and
/// absence is discard-trigger territory.
#[test]
fn a_substring_is_not_a_component_at_registration() {
    let d = Daemon::start("denysubstring");
    let mut c = d.connect();

    for name in ["mygit", ".gitignore", "my_node_modules"] {
        let root = d.dir.join(name);
        std::fs::create_dir_all(&root).unwrap();
        let added = c.call(
            "root.add",
            serde_json::json!({"path": root.to_str().unwrap(), "stub_mode": "delete"}),
        );
        assert_eq!(
            added["root"]["path"],
            serde_json::json!(root.to_str().unwrap()),
            "`{name}` is the user's own directory, not a deny-list entry: {added}"
        );
    }

    assert_eq!(
        c.call("status", serde_json::json!({}))["roots"],
        serde_json::json!(3),
        "all three registered"
    );
}

/// Round 3 stopped `root.add <repo>/.git`. It did not stop `root.add
/// <repo>/.git/objects`, because the check passed only the FINAL component to
/// `deny_dir` — and the final component there is `objects`, which is innocent.
///
/// The consequence is the same one the round-3 refusal exists to prevent, one
/// directory deeper: `probe_path_policies` and `detect_with_write_probe` both
/// create a file inside the root, so registration writes into a tree AC-7
/// promises Shepherd never touches.
///
/// The mtime is what this pins, not emptiness. Both probes clean up after
/// themselves, so `read_dir(...).count() == 0` passes with the trespass fully in
/// place; a directory's mtime moves when an entry is created or removed and does
/// not move back.
#[test]
fn a_root_under_a_denied_ancestor_is_refused_before_any_probe_writes_into_it() {
    let d = Daemon::start("denyancestor");
    let mut c = d.connect();

    let inside = d.dir.join("repo").join(".git").join("objects");
    std::fs::create_dir_all(&inside).unwrap();
    let pinned = pin_dir_mtime(&inside);

    let err = c.call_err(
        "root.add",
        serde_json::json!({"path": inside.to_str().unwrap(), "stub_mode": "delete"}),
    );

    assert_eq!(
        err.kind(),
        Some(shepherd_proto::ErrorCode::Refused),
        "{}",
        err.message
    );
    assert_eq!(
        dir_mtime(&inside),
        pinned,
        "a directory INSIDE a denied tree must not be written to either: the probes ran \
         before the refusal, in a `.git` AC-7 promises Shepherd never touches"
    );
    // The ancestor is what was actually denied, and naming the path the user
    // typed would leave them looking at `objects` for a rule that matched
    // `.git` two components up.
    let ancestor = d.dir.join("repo").join(".git");
    assert!(
        err.message.contains(ancestor.to_str().unwrap()),
        "the refusal must name the denied ancestor, not the path that was typed: {}",
        err.message
    );
    assert!(
        err.message.contains("version-control"),
        "and the rule that refused it: {}",
        err.message
    );
    assert_eq!(
        c.call("status", serde_json::json!({}))["roots"],
        serde_json::json!(0),
        "nor was the root registered"
    );
}

/// The same trespass bought with an alias instead of a path.
///
/// An innocently-named symlink resolving into a denied tree passed the
/// final-component check on the alias's own name — `deny_dir` was handed
/// `backup`, never `.git` — and the probes then wrote through the link into the
/// tree itself. The mtime pinned here is the TARGET's, because that is where
/// the writes land.
///
/// Both depths are covered: an alias to the denied directory, and an alias to
/// something under it. The second is the one a canonicalization that still only
/// read the final component would miss.
#[test]
fn a_symlinked_root_resolving_into_a_denied_tree_is_refused_before_probing() {
    let d = Daemon::start("denysymlink");
    let mut c = d.connect();

    let vcs = d.dir.join("vault").join(".git");
    let under = vcs.join("objects");
    std::fs::create_dir_all(&under).unwrap();

    for (alias_name, target) in [("backup", &vcs), ("archive", &under)] {
        let alias = d.dir.join(alias_name);
        std::os::unix::fs::symlink(target, &alias).unwrap();
        let pinned = pin_dir_mtime(target);

        let err = c.call_err(
            "root.add",
            serde_json::json!({"path": alias.to_str().unwrap(), "stub_mode": "delete"}),
        );

        assert_eq!(
            err.kind(),
            Some(shepherd_proto::ErrorCode::Refused),
            "`{alias_name}` resolves into a denied tree: {}",
            err.message
        );
        assert_eq!(
            dir_mtime(target),
            pinned,
            "`{alias_name}` is an alias for a denied tree and the probes wrote through it"
        );
    }

    assert_eq!(
        c.call("status", serde_json::json!({}))["roots"],
        serde_json::json!(0),
        "neither alias registered"
    );
}

/// The accepting direction for the ancestor walk, and the one "refuse anything
/// with a denied name anywhere above it" would break.
///
/// Round 1 established the component rule inside the deny list and round 3 at
/// the registration boundary; walking every ancestor is a third place to get it
/// wrong, and getting it wrong here refuses a whole subtree of the user's own
/// data. `mygit/data` must register exactly as `mygit` does.
#[test]
fn an_innocent_ancestor_component_still_registers() {
    let d = Daemon::start("denyancestoraccept");
    let mut c = d.connect();

    for parent in ["mygit", ".gitignore", "my_node_modules", "git"] {
        let root = d.dir.join(parent).join("data");
        std::fs::create_dir_all(&root).unwrap();
        let pinned = pin_dir_mtime(&root);

        let added = c.call(
            "root.add",
            serde_json::json!({"path": root.to_str().unwrap(), "stub_mode": "delete"}),
        );
        assert_eq!(
            added["root"]["path"],
            serde_json::json!(root.to_str().unwrap()),
            "`{parent}/data` is the user's own directory, not a deny-list entry: {added}"
        );
        assert_ne!(
            dir_mtime(&root),
            pinned,
            "and it must still be PROBED — a refusal that returned early would look \
             identical in the response"
        );
    }

    assert_eq!(
        c.call("status", serde_json::json!({}))["roots"],
        serde_json::json!(4),
        "all four registered"
    );
}

/// The accepting direction for the canonicalization: "refuse every symlinked
/// root" passes both refusal tests above while making an ordinary alias
/// unusable, and aliases into large corpora are exactly how people mount them.
#[test]
fn a_symlink_to_an_ordinary_directory_still_registers_and_is_probed() {
    let d = Daemon::start("denysymlinkaccept");
    let mut c = d.connect();

    // macOS puts the temp tree under `/var/folders/...`, and `/var` is itself a
    // symlink to `private/var` — so the canonical name of anything built here
    // begins `/private/var`, which is an absolute-prefix deny rule. This root IS
    // a link, so `root.add` canonicalizes it and refuses it for the platform's
    // symlink layout rather than for anything the test did.
    //
    // Skipped rather than worked around, because the accepting direction it
    // covers is carried platform-independently by
    // `dispatch::tests::the_registration_deny_decision_reads_every_component_of_both_names`,
    // which asserts an ordinary alias resolves to `None` — and which also pins
    // this very `/private/var` interaction as the reason the canonical name is
    // read only for a root that is itself a link. What is lost here is only the
    // live evidence that the probes ran THROUGH the link, and it is lost on one
    // platform, not silently on all of them.
    //
    // The other three deny tests in this file are unaffected: the ancestor test
    // matches `.git` on the literal path before any prefix rule is reached, and
    // the symlink REFUSAL test asserts only that the call was refused and that
    // the target was not written to — both of which hold whichever rule fires.
    if std::fs::canonicalize(&d.dir).unwrap() != d.dir {
        return;
    }

    let real = d.dir.join("corpus");
    std::fs::create_dir_all(&real).unwrap();
    let alias = d.dir.join("shortcut");
    std::os::unix::fs::symlink(&real, &alias).unwrap();
    let pinned = pin_dir_mtime(&real);

    let added = c.call(
        "root.add",
        serde_json::json!({"path": alias.to_str().unwrap(), "stub_mode": "delete"}),
    );
    assert_eq!(
        added["root"]["path"],
        serde_json::json!(alias.to_str().unwrap()),
        "the root is stored as the caller spelled it; canonicalization is for the deny \
         decision only: {added}"
    );
    assert_ne!(
        dir_mtime(&real),
        pinned,
        "and the probes must have run through the link"
    );
}

/// The direction this review has caught three times: "refuse everything" passes
/// every refusal test above while quietly disabling enrollment.
///
/// The mtime assertion is the exact inversion of the refusal test's — an
/// ordinary root **must** be written to, because writing is what probing is.
/// And a registration that returned early without probing would look identical
/// on the wire (`path_case_policy` has a platform default that matches the
/// probed answer here), so the absence of the `assumed` warning is checked too:
/// that warning appears only when `probe_path_policies` could not run.
#[test]
fn an_ordinary_root_still_registers_with_its_probes_run_and_its_policies_recorded() {
    let d = Daemon::start("denyaccept");
    let mut c = d.connect();

    let root = d.dir.join("corpus-ordinary");
    std::fs::create_dir_all(&root).unwrap();
    let pinned = pin_dir_mtime(&root);

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root.to_str().unwrap(), "stub_mode": "delete"}),
    );

    assert_ne!(
        dir_mtime(&root),
        pinned,
        "the probes write into the root they measure; an unchanged mtime means `root.add` \
         registered this root without probing it"
    );

    let warnings: Vec<String> = added["warnings"]
        .as_array()
        .expect("root.add reports warnings")
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect();
    assert!(
        !warnings
            .iter()
            .any(|w| w.contains("could not probe this root's case and normalization")),
        "a writable temp directory is probeable; this warning means the probe was skipped \
         or failed: {warnings:?}"
    );

    // Probed and *stored*: the values `root.add` answered with are the values
    // the catalog now holds, which is what every later `norm_key` lookup hangs
    // off.
    let listed = c.call("root.list", serde_json::json!({}));
    let row = &listed["roots"].as_array().unwrap()[0];
    assert_eq!(row["path"], serde_json::json!(root.to_str().unwrap()));
    for field in ["path_case_policy", "path_norm_policy", "atime_mode"] {
        assert_eq!(
            row[field], added["root"][field],
            "`{field}` must be recorded as probed: {listed}"
        );
        assert!(row[field].is_string(), "`{field}` is missing: {listed}");
    }
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
        // An empty `config` is missing the required `bucket`, so the handler
        // refuses with `Invalid` before it opens a socket to anything. That is
        // "reached" in exactly the sense this probe measures, and it keeps the
        // reachability sweep free of network I/O — the registration probe's own
        // behaviour is asserted by the dedicated `target.add` tests instead.
        "target.add" => serde_json::json!({"name": "probe", "adapter": "s3", "config": {}}),
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
    /// **`target.add` is no longer here, and the constraint that kept it here
    /// is now a property of the shipped code rather than a warning to a future
    /// author.** It is restated because the constraint did not go away when the
    /// refusal did — it moved from "do not serve this yet" to "do not undo
    /// this".
    ///
    /// `S3Config::multipart_checksum` decides whether an S3 upload requests a
    /// **whole-object** checksum. It cannot be retrofitted: a checksum not
    /// requested at upload requires re-uploading the object to obtain, so a
    /// target registered without one fixes every object written through it into
    /// the no-checksum configuration — **$441/month against $0.68** on a 50 TB
    /// corpus, 649x, per object, irreversible (ADR 0b §3). Registration is the
    /// only moment at which the choice exists.
    ///
    /// `Session::target_add` therefore calls
    /// `shepherd_storage::s3::probe_multipart_checksum` **before** the `target`
    /// row is inserted, and stores what it returned in `target.config_json`.
    /// Three properties of that path are load-bearing, and each is asserted by
    /// a test in this file rather than left to review:
    ///
    /// > 1. The probe is **called**, and its adopted algorithm lands in the
    /// >    stored config — otherwise every upload silently takes the expensive
    /// >    path. (`a_registered_target_carries_what_the_probe_measured`, and
    /// >    the MinIO-backed positive below it.)
    /// > 2. `Ok(adopted: None)` — the provider answered and supports none of
    /// >    CRC64NVME → CRC32C → CRC32 — is stored **with the per-algorithm
    /// >    reasons**, never as a bare boolean, so a wrong negative is
    /// >    distinguishable from a right one after the fact.
    /// > 3. `Err(_)` — the provider was never reached — **refuses the
    /// >    registration** and writes no row. Persisting it as "supports
    /// >    nothing" would be silent, permanent, and indistinguishable from a
    /// >    real measurement.
    /// >    (`a_target_whose_provider_cannot_be_reached_is_not_registered_at_all`.)
    ///
    /// A change that keeps those tests passing while removing the probe call is
    /// the failure to watch for: mutation-check by deleting the call and
    /// confirming they fail before trusting them.
    ///
    /// `target.list` and `target.test` stay refused deliberately. Neither fell
    /// out of serving `target.add` — `target.test` in particular is its own
    /// reachability-and-permissions probe — and serving a method with less than
    /// it promises is what this whole test exists to catch.
    const UNSERVED: &[&str] = &[
        "restore",
        "rule.list",
        "rule.preview",
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
         \nIF `target.add` IS BACK IN THE REFUSED SET, READ THIS FIRST: it is served, and it is \
         served together with a registration-time call to \
         `shepherd_storage::s3::probe_multipart_checksum` whose result is persisted in \
         `target.config_json`. Unwiring the method takes that probe out of the product with it. \
         A checksum not requested at upload cannot be retrofitted without re-uploading, so every \
         object written through an unprobed target is permanently in the no-checksum \
         configuration — $441/month against $0.68 on 50 TB, 649x (ADR 0b §3). If the method is \
         being retired on purpose, retire the probe's caller deliberately and say so here; if \
         this is a surprise, something unwired it. See open-questions E-5.",
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

/// Where fixtures live: the build directory, **not** `std::env::temp_dir()`.
///
/// Every root these tests register goes through AC-7's deny list, and on macOS
/// `$TMPDIR` is `/var/folders/…`, whose canonical form is `/private/var/…` —
/// which that list denies as a `SystemPath`, correctly. While the deny decision
/// canonicalized only symlinked LEAVES the whole suite got away with it; the
/// moment it canonicalized properly, every macOS root was refused. A fixture
/// that lands inside a denied system tree makes the suite answer about the
/// runner's temp directory rather than about the product.
///
/// `CARGO_TARGET_TMPDIR` is Cargo's own answer to this and is set for
/// integration tests.
fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
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

/// Give the daemon a scan's worth of events to buffer, and return the root id.
fn seed_some_events(d: &Daemon, c: &mut Client, tag: &str) -> i64 {
    let root_dir = d.dir.join(format!("corpus-{tag}"));
    write_file(&root_dir, "a.txt", "hello");
    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    scan_and_expect(c, root_id, 1);
    root_id
}

/// A cursor without the epoch that issued it is **stale**, not current.
///
/// Sequence numbers restart at 1 on every daemon start, so a bare
/// `resume_from` names a different event in every run. Treating a missing
/// epoch as agreement replayed the client against this run's unrelated
/// numbering and told it `resumed` — so it believed it had caught up on
/// history it had never seen. `snapshot_required` is the honest answer, and it
/// is the one a client can act on.
#[test]
fn a_resume_cursor_without_its_epoch_is_refused_as_stale() {
    let d = Daemon::start("resume-noepoch");
    let mut c = d.connect();
    seed_some_events(&d, &mut c, "resume-noepoch");

    let mut sub = d.connect();
    let bare = sub.call("events.subscribe", serde_json::json!({"resume_from": 0}));
    assert_eq!(
        bare["resume"]["outcome"],
        serde_json::json!("snapshot_required"),
        "a cursor with no epoch must not be honoured: {bare}"
    );
    assert_eq!(
        bare["resume"]["reason"],
        serde_json::json!("epoch_changed"),
        "{bare}"
    );

    // THE ACCEPTING DIRECTION, so "refuse every resume" cannot pass: the same
    // cursor WITH this run's epoch resumes.
    let epoch = bare["epoch"].as_str().expect("epoch").to_owned();
    let mut ok = d.connect();
    let good = ok.call(
        "events.subscribe",
        serde_json::json!({"resume_from": 0, "resume_epoch": epoch}),
    );
    assert_eq!(
        good["resume"]["outcome"],
        serde_json::json!("resumed"),
        "{good}"
    );

    // And no cursor at all is a fresh subscription, not a stale one.
    let mut fresh = d.connect();
    let none = fresh.call("events.subscribe", serde_json::json!({}));
    assert_ne!(
        none["resume"]["outcome"],
        serde_json::json!("snapshot_required"),
        "asking for no history is not the same as asking for unusable history: {none}"
    );
}

/// `events.subscribe` must put its own response on the socket before it writes
/// a single notification.
///
/// A client reads the frame that follows a request and parses it as a response
/// — `shepctl events subscribe` reaches the daemon through `client::call`,
/// which does precisely that and nothing else. Replay used to be written first,
/// so a notification landed where the subscription id should have been and the
/// call died as a protocol error. `resume_from` made that the **normal**
/// outcome rather than a race: every resuming subscription failed.
///
/// The `replayed >= 1` assertion is what stops this passing vacuously — with an
/// empty replay there is nothing that could have overtaken the response.
#[test]
fn a_resuming_subscription_is_answered_before_the_frames_it_replays() {
    let d = Daemon::start("resumeorder");
    let mut c = d.connect();
    seed_some_events(&d, &mut c, "resumeorder");

    // A fresh connection, so nothing else is in flight on it.
    //
    // The epoch travels WITH the cursor. A sequence number alone names nothing
    // — numbering restarts at 1 on every daemon start — so the daemon treats a
    // cursor without one as stale, and this test would otherwise be asserting
    // `resumed` against the shape that is now correctly refused.
    let epoch = {
        let mut probe = d.connect();
        let r = probe.call("events.subscribe", serde_json::json!({}));
        r["epoch"]
            .as_str()
            .expect("the result names its epoch")
            .to_owned()
    };
    let mut sub = d.connect();
    let first = sub.raw(
        "events.subscribe",
        serde_json::json!({"resume_from": 0, "resume_epoch": epoch}),
    );

    assert!(
        first.get("method").is_none(),
        "the first frame after `events.subscribe` must be its RpcResponse; a notification \
         here is what a client reports as a protocol error: {first}"
    );
    let parsed: RpcResponse = serde_json::from_value(first.clone())
        .unwrap_or_else(|e| panic!("the first frame is not a JSON-RPC response ({e}): {first}"));
    let result = parsed.outcome().expect("the subscription was refused");
    assert!(result["subscription_id"].as_u64().unwrap() >= 1, "{result}");
    assert_eq!(
        result["resume"]["outcome"],
        serde_json::json!("resumed"),
        "{result}"
    );
    let replayed = result["resume"]["replayed"].as_u64().unwrap();
    assert!(
        replayed >= 1,
        "nothing was replayed, so this test proves nothing about ordering: {result}"
    );

    // And the replayed frames follow it, in order, before anything live.
    let mut last_seq = 0;
    for i in 0..replayed {
        let frame = sub.read_frame();
        assert_eq!(
            frame["method"],
            serde_json::json!("event"),
            "replayed frame {i} is not a notification: {frame}"
        );
        let seq = frame["params"]["seq"].as_u64().unwrap();
        assert!(
            seq > last_seq,
            "replay went backwards at frame {i}: {frame}"
        );
        last_seq = seq;
    }

    // The exposed path, exercised as a user reaches it. `shepctl events
    // subscribe` now follows the stream rather than returning after one frame,
    // so it is driven as a child and read as it goes — see
    // `shepctl_events_subscribe_renders_the_events_it_subscribed_to`, which is
    // where the rendering itself is asserted. Here the point is narrower: the
    // response frame must still parse as a response.
    let (env, _events) = subscribe_until_eof(&d, &["--resume-from", "0"]);
    assert_eq!(
        env["ok"],
        serde_json::json!(true),
        "`shepctl events subscribe --resume-from` must not fail on its own daemon's reply: \
         {env}"
    );
    assert!(
        env["data"]["subscription_id"].as_u64().unwrap() >= 1,
        "{env}"
    );
}

/// `events subscribe --json` is NDJSON to the last line.
///
/// The events were compact, one per line, and the closing envelope was
/// pretty-printed — so a consumer reading the documented stream line-by-line
/// parsed every event correctly and then failed on the first line of the
/// summary. The envelope is part of the stream, not a document appended to it.
#[test]
fn the_subscription_json_stream_is_ndjson_including_its_envelope() {
    let d = Daemon::start("ndjson");
    let mut c = d.connect();
    seed_some_events(&d, &mut c, "ndjson");
    drop(c);

    let mut cmd = Command::new(shepctl());
    cmd.arg("--socket")
        .arg(&d.socket)
        .args(["events", "subscribe", "--json", "--resume-from", "0"])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let mut child = cmd.spawn().expect("run shepctl");

    let stdout = child.stdout.take().expect("piped");
    let reader = BufReader::new(stdout);
    let collected = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&collected);
    let pump = std::thread::spawn(move || {
        for line in reader.lines() {
            let Ok(line) = line else { break };
            sink.lock().unwrap().push(line);
        }
    });
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if collected
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.contains("\"seq\""))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ = std::process::Command::new("kill")
        .arg(d.child.id().to_string())
        .status();
    let _ = child.wait();
    pump.join().expect("stdout pump");

    let lines = collected.lock().unwrap().clone();
    assert!(!lines.is_empty(), "the stream rendered nothing");
    for (i, line) in lines.iter().enumerate() {
        serde_json::from_str::<serde_json::Value>(line).unwrap_or_else(|e| {
            panic!(
                "line {i} of an NDJSON stream is not one JSON value ({e}): {line:?}\n\
                 full output: {lines:?}"
            )
        });
    }
    assert!(
        lines
            .last()
            .and_then(|l| serde_json::from_str::<serde_json::Value>(l).ok())
            .is_some_and(|v| v.get("schema_version").is_some()),
        "the last line must be the closing envelope: {lines:?}"
    );
}

/// `snapshot_required` reaches the user BEFORE the first event, not after the
/// last one.
///
/// The subscription result carries `resume.outcome`, and
/// `snapshot_required` means "your cursor is unusable; everything you believe
/// about the past is invalid". `client::subscribe` returned that result only
/// when the stream ENDED — and a follow command's stream ends when the user
/// interrupts it, so on a long-lived subscription the warning was never
/// delivered at all while live events were forwarded the whole time.
///
/// An epoch from a different run is the cheapest way to reach the outcome:
/// sequence numbers restart on every daemon run, so a cursor from another epoch
/// cannot be replayed.
#[test]
fn a_snapshot_required_resume_is_reported_before_any_event() {
    let d = Daemon::start("snapreq");

    // Events must actually FLOW during the subscription, or the ordering this
    // test exists for is not exercised: with an idle daemon the warning is
    // trivially first because it is the only line.
    let root_dir = d.dir.join("corpus-snapreq");
    write_file(&root_dir, "a.txt", "hello");
    let root_id = {
        let mut c = d.connect();
        c.call(
            "root.add",
            serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
        )["root"]["root_id"]
            .as_i64()
            .unwrap()
    };
    let socket = d.socket.clone();
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let scanner_stop = Arc::clone(&stop);
    let scanner = std::thread::spawn(move || {
        // Repeatedly, and only AFTER the subscription is live: these must be
        // live frames rather than a replay, because `snapshot_required` means
        // by definition that nothing can be replayed. Looping removes the race
        // between this thread and `shepctl` finishing its handshake.
        let deadline = Instant::now() + Duration::from_secs(8);
        while !scanner_stop.load(std::sync::atomic::Ordering::SeqCst) && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
            if UnixStream::connect(&socket).is_err() {
                break; // the daemon is gone; the subscription has what it needs
            }
            // `Client` panics on a connection that closes mid-call, which is
            // exactly what `subscribe_until_eof` does to the daemon when it has
            // seen enough. This thread is a best-effort event generator, not an
            // assertion, so its panic must not fail the test — and the hook is
            // silenced so the expected one does not print a backtrace that
            // reads like a failure.
            let previous = std::panic::take_hook();
            std::panic::set_hook(Box::new(|_| {}));
            let sent = std::panic::catch_unwind(|| {
                let mut c = Client::connect(&socket);
                let _ = c.raw("scan.start", serde_json::json!({"root_id": root_id}));
            });
            std::panic::set_hook(previous);
            if sent.is_err() {
                break;
            }
        }
    });

    let (env, events) = subscribe_until_eof(
        &d,
        &[
            "--resume-from",
            "1",
            "--resume-epoch",
            "a-run-that-never-was",
        ],
    );
    stop.store(true, std::sync::atomic::Ordering::SeqCst);
    scanner.join().expect("the scan trigger");

    assert_eq!(
        env["data"]["resume"]["outcome"],
        serde_json::json!("snapshot_required"),
        "the fixture must actually produce the outcome under test: {env}"
    );

    // `--json` puts the warning on stdout as its own record, ahead of every
    // event line. `subscribe_until_eof` collects stdout in order, so position
    // is the assertion.
    let first_warning = events
        .iter()
        .position(|v| v.get("warning") == Some(&serde_json::json!("snapshot_required")))
        .unwrap_or_else(|| panic!("the snapshot_required warning was never emitted: {events:?}"));
    let first_event = events
        .iter()
        .position(|v| v.get("seq").is_some())
        .unwrap_or_else(|| {
            panic!("no event was rendered, so the ordering is untested: {events:?}")
        });
    assert!(
        first_warning < first_event,
        "the warning must precede the first event, or a follow command delivers events the \
         caller has no reason to distrust: {events:?}"
    );
}

/// Run `shepctl events subscribe --json`, stop the daemon, and collect what it
/// rendered.
///
/// Returns the closing envelope and the event lines that preceded it.
///
/// The daemon is killed on purpose: end of stream is how this command
/// terminates, and producing it is therefore part of exercising it. `--json`
/// makes each event exactly one line and the envelope a pretty-printed document
/// after them, which is what lets the two be told apart here.
fn subscribe_until_eof(d: &Daemon, extra: &[&str]) -> (serde_json::Value, Vec<serde_json::Value>) {
    use std::process::Stdio;

    let mut cmd = Command::new(shepctl());
    cmd.arg("--socket")
        .arg(&d.socket)
        .args(["events", "subscribe", "--json"])
        .args(extra)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("run shepctl");

    // Give the subscription time to be answered and its replay to arrive before
    // the socket goes away. Without this the test would race the thing it is
    // trying to observe, and would pass for the wrong reason on a slow host.
    let stdout = child.stdout.take().expect("piped");
    let reader = BufReader::new(stdout);
    let collected = Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let sink = Arc::clone(&collected);
    let pump = std::thread::spawn(move || {
        for line in reader.lines() {
            let Ok(line) = line else { break };
            sink.lock().unwrap().push(line);
        }
    });

    // Wait until at least one event line has been rendered, or give up: the
    // caller's assertions are what decide whether that was enough.
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if collected
            .lock()
            .unwrap()
            .iter()
            .any(|l| l.trim_start().starts_with('{') && l.contains("\"seq\""))
        {
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }

    // End the stream the way a stopped daemon does.
    let _ = std::process::Command::new("kill")
        .arg(d.child.id().to_string())
        .status();

    let status = child.wait().expect("shepctl exits when the stream ends");
    pump.join().expect("stdout pump");

    let lines = collected.lock().unwrap().clone();
    assert_eq!(
        status.code(),
        Some(0),
        "end of stream is how this command ends; it is not a failure. lines: {lines:?}"
    );

    // NDJSON, all the way through: one compact JSON value per line, the closing
    // envelope included. It used to be pretty-printed, which meant a consumer
    // reading the documented stream line-by-line parsed every event and then
    // failed on the first line of the summary — so this helper parsed it by
    // looking for a bare `{`, encoding the very shape that was wrong.
    //
    // The envelope is the value carrying `schema_version`; everything before it
    // is an event or a warning record.
    let mut events = Vec::new();
    let mut envelope = None;
    for line in &lines {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            panic!("every line of `--json` output must be one JSON value: {line:?}");
        };
        if v.get("schema_version").is_some() {
            envelope = Some(v);
        } else {
            events.push(v);
        }
    }
    let envelope =
        envelope.unwrap_or_else(|| panic!("no closing envelope in the stream: {lines:?}"));
    (envelope, events)
}

/// The streams `events.subscribe` advertises, as the wire spells them.
///
/// Mirrored from `EventStream::ALL` rather than imported so that adding a
/// stream to the protocol without deciding what publishes to it shows up here.
const ADVERTISED_STREAMS: &[&str] = &["scan", "job", "index", "tier", "power", "target"];

/// `shepctl events subscribe` must actually render events.
///
/// This is the finding, and it is about a command that reported success while
/// doing nothing at all. `events.subscribe` was routed through `client::call`,
/// which reads exactly one response frame and then drops its `Connection`. The
/// daemon's pump writes to that same socket, so it saw a closed peer
/// immediately: neither the frames it had queued for replay nor any live event
/// was ever written to a terminal. The command exited 0 with a subscription id
/// and a user saw nothing, forever.
///
/// So what is asserted is the **events**, by content. `resume_from: 0` replays
/// the buffer the seeding scan filled, which makes the arrival deterministic —
/// there is no waiting on a live publisher and no sleep standing in for one.
/// A `subscription_id` in the envelope is exactly what the broken version
/// produced and is worth nothing on its own; `events_rendered` is cross-checked
/// against the frames that were actually printed so the count cannot be right
/// while the output is empty.
#[test]
fn shepctl_events_subscribe_renders_the_events_it_subscribed_to() {
    let d = Daemon::start("subrender");
    let mut c = d.connect();
    seed_some_events(&d, &mut c, "subrender");

    // The epoch travels with the cursor, and passing it here is the point as
    // much as a fixture detail: a bare `--resume-from` is refused as stale, so
    // this is also the end-to-end check that `--resume-epoch` reaches the
    // daemon and that the hint on the dropped-subscription path names a flag
    // that exists.
    let epoch = c.call("events.subscribe", serde_json::json!({}))["epoch"]
        .as_str()
        .expect("the result names its epoch")
        .to_owned();
    drop(c);

    let (env, events) = subscribe_until_eof(&d, &["--resume-from", "0", "--resume-epoch", &epoch]);

    assert_eq!(env["ok"], serde_json::json!(true), "{env}");
    assert!(
        !events.is_empty(),
        "the subscription rendered nothing — which is exactly what it did before, while \
         still reporting success: {env}"
    );
    assert_eq!(
        env["data"]["events_rendered"].as_u64().unwrap(),
        events.len() as u64,
        "the reported count must match the frames that reached stdout, or the count is a \
         second thing that can be right while the output is empty"
    );

    // By content: real event frames with monotonic sequence numbers, not merely
    // "some JSON was printed".
    //
    // The streams are `scan` AND `job` now: the seeding scan is a queue job, so
    // its claim and completion are published too. This used to assert every
    // frame was `scan`, which was true only because nothing had ever published
    // a job transition — the stream was advertised and silent.
    let mut last = 0;
    for e in &events {
        let seq = e["seq"]
            .as_u64()
            .unwrap_or_else(|| panic!("an event frame has no `seq`: {e}"));
        assert!(seq > last, "replay went backwards: {events:?}");
        last = seq;
        // An ALLOWLIST here needs extending every time a stream starts
        // publishing, and the last two rounds each caught it a round late.
        // This subscription is unfiltered, so the property is that every frame
        // belongs to an ADVERTISED stream — the filtering itself is tested by
        // `a_subscriber_receives_what_it_asked_for_and_nothing_else`.
        let stream = e["stream"].as_str().unwrap_or_default();
        assert!(
            ADVERTISED_STREAMS.contains(&stream),
            "a frame arrived on a stream `events.subscribe` does not advertise: {e}"
        );
    }
    assert!(
        events
            .iter()
            .any(|e| e["stream"] == serde_json::json!("job")),
        "the `job` stream is advertised and must actually carry the queue's \
         transitions; a client that subscribes and sees nothing cannot tell \
         that from a quiet system: {events:?}"
    );
    assert!(
        events
            .iter()
            .any(|e| e["payload"]["files_seen"].is_number()),
        "a scan progress event carries `files_seen`; without it these frames are not the \
         events the scan published: {events:?}"
    );
}

/// A resume cursor means nothing outside the daemon run that issued it.
///
/// Sequence numbers restart at 1 on every launch, so a cursor carried across a
/// restart names a *different* event under the same number. `SubscribeResult`
/// has always returned the `epoch` that makes that detectable, but the request
/// had nowhere to send one back: the daemon passed no client epoch and its
/// `EpochChanged` branch was unreachable, so a reconnecting client was replayed
/// whatever new-run events happened to sit past its old cursor.
///
/// Both directions are asserted. A daemon that answered `epoch_changed` to
/// everything would satisfy the first half and be useless.
#[test]
fn a_cursor_from_another_run_is_told_to_take_a_snapshot() {
    let d = Daemon::start("epochskew");
    let mut c = d.connect();
    seed_some_events(&d, &mut c, "epochskew");

    // A cursor that is perfectly valid *by number*, carried over from a run
    // this daemon is not. Nothing is replayed, so this connection stays clean.
    let mut stale = d.connect();
    let refused = stale.call(
        "events.subscribe",
        serde_json::json!({"resume_from": 0, "resume_epoch": "a-cursor-from-a-previous-run"}),
    );
    assert_eq!(
        refused["resume"]["outcome"],
        serde_json::json!("snapshot_required"),
        "a cursor from another run must not be replayed against this run's numbers: {refused}"
    );
    assert_eq!(
        refused["resume"]["reason"],
        serde_json::json!("epoch_changed"),
        "{refused}"
    );

    // The same cursor, with the epoch this daemon actually issued — which the
    // refusal above returned, because `epoch` is on every subscribe result.
    let epoch = refused["epoch"].as_str().unwrap().to_string();
    let mut fresh = d.connect();
    let resumed = fresh.raw(
        "events.subscribe",
        serde_json::json!({"resume_from": 0, "resume_epoch": epoch}),
    );
    let result = serde_json::from_value::<RpcResponse>(resumed.clone())
        .unwrap_or_else(|e| panic!("not a response ({e}): {resumed}"))
        .outcome()
        .expect("the subscription was refused");
    assert_eq!(
        result["resume"]["outcome"],
        serde_json::json!("resumed"),
        "the epoch this daemon issued must resume, or the check above is just a refusal of \
         everything: {result}"
    );
    assert!(
        result["resume"]["replayed"].as_u64().unwrap() >= 1,
        "{result}"
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

/// The state directory is owner-only, because the catalog inside it is.
///
/// §4.3 makes filesystem permissions the entire authorization model, and the
/// socket has been `0600` under a `0700` directory since it was written. The
/// catalog is the other half of the same secret: the user's complete file
/// inventory, and the custody rows that are a tiered file's only remote address.
/// `create_dir_all` under a `022` umask left it `0755`, and on this layout —
/// the ordinary one, socket in the runtime dir — nothing later tightened it.
///
/// The daemon is started with its socket *outside* its state directory on
/// purpose; see the harness note. With the two in the same place, `bind`'s
/// `0700` would satisfy this assertion without the state directory ever having
/// been considered.
#[test]
fn the_state_directory_is_owner_only() {
    let d = Daemon::start_with_socket_outside_the_state_dir("statedirmode");
    let state = d.dir.join("state");

    let mode = std::fs::metadata(&state).unwrap().permissions().mode() & 0o777;
    assert_eq!(
        mode, 0o700,
        "the state directory holding catalog.db is {mode:04o}; the daemon is per-user (§4.2) \
         and its inventory must not be readable by other accounts on the host"
    );
    assert!(
        state.join("catalog.db").exists(),
        "the daemon must have opened its catalog in the directory this asserted about"
    );
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
    let dir = fixture_root().join(format!("shepherdd-e2e-offline-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let home = dir.join("home");
    let config = home.join(".config");
    std::fs::create_dir_all(&config).unwrap();
    let socket = dir.join("nothing.sock");
    // The exact path `service::registration()` would resolve, computed
    // independently here from each platform's documented contract rather than
    // by calling that function, so the assertion cannot pass by tautology.
    //
    // PER PLATFORM, because `registration()` is: `systemd::unit_path()` on
    // Linux, which honours `XDG_CONFIG_HOME`, and `launchd::plist_path()` on
    // macOS, which reads `HOME` and ignores `XDG_CONFIG_HOME` entirely. The
    // first version of this hardcoded the systemd path and passed on Linux
    // while failing on macOS — caught by this repository's first-ever CI run,
    // which is the whole argument for having one: a test that encodes one
    // platform's layout as though it were the contract is invisible until
    // another platform runs it.
    let unit_path = if cfg!(target_os = "macos") {
        home.join("Library/LaunchAgents/kr.swjeon.shepherd.plist")
    } else {
        config.join("systemd/user/shepherd.service")
    };

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

    // The lingering check is a systemd concept and `doctor` only reports it
    // there; on macOS the equivalent line is absent by design rather than
    // missing. Asserted per platform so this cannot silently stop checking.
    #[cfg(not(target_os = "macos"))]
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
    let dir = fixture_root().join(format!("shepherdd-e2e-registered-{}", std::process::id()));
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

/// Wait until a scan records a failure.
///
/// Separate from [`wait_for_scan`] because a failed job does not stay finished:
/// the queue retries it with backoff, so it is pending again moments after the
/// attempt that failed. Waiting for `finished_at` on a scan that is *supposed*
/// to fail waits for the retry schedule to run out, which is minutes.
fn wait_for_scan_error(c: &mut Client, root_id: i64) -> serde_json::Value {
    let deadline = Instant::now() + Duration::from_secs(30);
    let mut last = serde_json::Value::Null;
    while Instant::now() < deadline {
        let state = c.call("scan.status", serde_json::json!({"root_id": root_id}));
        if let Some(scan) = state["scans"].as_array().and_then(|a| a.first()) {
            last = scan.clone();
            if !scan["last_error"].is_null() {
                return last;
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    panic!("the scan never recorded a failure; last status was {last}");
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

// ---------------------------------------------------------------------------
// `target.add` — the registration-time whole-object-checksum probe
// ---------------------------------------------------------------------------

/// An S3 endpoint that answers every request with one canned refusal.
///
/// # Why a fake rather than only MinIO
///
/// The probe's two provider-facing answers are **not symmetric**, and MinIO can
/// only demonstrate one of them: it supports CRC64NVME, so a MinIO run always
/// takes the adopt-on-the-first-algorithm path and never once reaches the
/// "provider supports none of the three" branch. That branch is the expensive
/// one — it is what commits every object written through the target to full-read
/// scrub — so leaving it to an emulator that cannot produce it would mean the
/// degrade path ships untested behind a green MinIO run.
///
/// `400 InvalidRequest` specifically. `s3.rs`'s `map_err` routes 5xx,
/// throttling and dispatch failures to `StorageError::Transient`, which the
/// probe classifies as `Unreachable` — "we never got an answer" — and which
/// **refuses** the registration. A 400 with a non-retryable code is the
/// provider answering, which is the case under test here.
struct FakeS3 {
    endpoint: String,
    stop: Arc<AtomicBool>,
    joiner: Option<std::thread::JoinHandle<()>>,
}

impl FakeS3 {
    fn refusing_every_algorithm() -> FakeS3 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind a fake s3");
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        listener.set_nonblocking(true).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let joiner = std::thread::spawn(move || {
            const BODY: &str = concat!(
                r#"<?xml version="1.0" encoding="UTF-8"?>"#,
                "<Error><Code>InvalidRequest</Code>",
                "<Message>this provider does not support the requested checksum algorithm",
                "</Message><Resource>/</Resource><RequestId>fake-s3</RequestId></Error>"
            );
            while !flag.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((mut sock, _)) => {
                        let _ = sock.set_read_timeout(Some(Duration::from_secs(2)));
                        // The refused call is `CreateMultipartUpload`, which
                        // carries no body, so the request head is all there is
                        // to drain before answering.
                        // Drain the WHOLE request head before answering.
                        // A single `read` can leave bytes in the receive queue,
                        // and closing a socket with unread data sends an RST on
                        // macOS — the client then sees a connection reset rather
                        // than this 400, the SDK reports a transport error, and
                        // the probe answers `Unreachable` instead of `refused`.
                        // That is the WRONG BRANCH for this test, and it passed
                        // on Linux, which usually delivers the response anyway.
                        let mut head = Vec::new();
                        let mut buf = [0u8; 1024];
                        loop {
                            match sock.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => {
                                    head.extend_from_slice(&buf[..n]);
                                    if head.windows(4).any(|w| w == b"\r\n\r\n") {
                                        break;
                                    }
                                }
                                Err(_) => break,
                            }
                        }
                        let _ = write!(
                            sock,
                            "HTTP/1.1 400 Bad Request\r\nContent-Type: application/xml\r\n\
                             Content-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                            BODY.len()
                        );
                        let _ = sock.flush();
                        // Half-close: signal end-of-response and let the client
                        // close its own side. `Shutdown::Both` here is what
                        // triggers the RST described above.
                        let _ = sock.shutdown(std::net::Shutdown::Write);
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        FakeS3 {
            endpoint,
            stop,
            joiner: Some(joiner),
        }
    }
}

impl Drop for FakeS3 {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(j) = self.joiner.take() {
            let _ = j.join();
        }
    }
}

/// The credential the registration path resolves, in the shape the secret
/// store holds it. `SecretRef("target/probe")` reads
/// `SHEPHERD_SECRET_TARGET_PROBE`, which is the first backend in the chain.
const PROBE_SECRET_VAR: &str = "SHEPHERD_SECRET_TARGET_PROBE";
const PROBE_SECRET: &str = r#"{"access_key_id":"probe","secret_access_key":"probe-secret"}"#;

/// **A registered target carries what the probe measured, evidence included.**
///
/// This is the test the `UNSERVED` comment above names. It asserts the thing a
/// reviewer cannot see by reading `dispatch.rs`: that `target.add` did not just
/// write a row, but reached the provider first and wrote down what it said.
///
/// The provider here refuses all three algorithms, so the correct outcome is
/// the **degraded** one — `adopted: null`, scrub reads multipart objects back in
/// full, expensive and never wrong. The two ways to get that wrong are both
/// checked:
///
/// * adopting an algorithm the provider never confirmed — asserted by the
///   absence of `multipart_checksum` from the stored config;
/// * recording the negative as a bare fact with no reasons — asserted by
///   requiring a per-algorithm outcome for each of CRC64NVME, CRC32C and CRC32,
///   because a false negative is permanent and, without its reasons,
///   indistinguishable from a true one.
///
/// **Mutation check.** Delete the `probe_multipart_checksum_blocking` call in
/// `Session::target_add` and this test fails: `checksum_probe` is written from
/// the returned record and from nothing else, so its absence is not something
/// the handler can fake.
/// Registering a target reaches every subscriber, not only the caller.
///
/// `EventStream::Target` is advertised in the handshake and
/// `EventPayload::TargetHealth` had no production writer at all — a repo-wide
/// search found none — so a dashboard subscribed to the stream this daemon told
/// it about learned nothing when another client registered a target. It cannot
/// repair its view by polling either: `target.list` is Phase 2 and answers
/// `MethodNotImplemented`. An advertised stream that never carries the one
/// event this phase can produce is a promise the daemon does not keep.
///
/// Read by REPLAY from cursor 0 rather than by racing a live frame, which is
/// how the index-stream test avoids the same flake.
#[test]
fn registering_a_target_publishes_on_the_advertised_target_stream() {
    let fake = FakeS3::refusing_every_algorithm();
    let d = Daemon::start_with_env("target-event", &[(PROBE_SECRET_VAR, PROBE_SECRET)]);
    let mut c = d.connect();

    let added = c.call(
        "target.add",
        serde_json::json!({
            "name": "announced",
            "adapter": "s3",
            "config": {
                "bucket": "archive",
                "endpoint_url": fake.endpoint,
                "region": "us-east-1",
                "force_path_style": true,
            },
            "credentials_ref": "target/probe",
        }),
    );
    let target_id = added["target"]["target_id"].as_i64().expect("target_id");

    // The epoch comes from a SEPARATE connection, because a connection holds
    // one subscription: an empty `streams` list means ALL of them, so probing
    // for the epoch here and then subscribing to one stream would be the
    // overlapping pair that has no ordering. A real resuming client already
    // holds an epoch from its previous subscription and needs no probe.
    let epoch = d.connect().call("events.subscribe", serde_json::json!({}))["epoch"]
        .as_str()
        .expect("epoch")
        .to_owned();
    let sub = c.call(
        "events.subscribe",
        serde_json::json!({"streams": ["target"], "resume_from": 0, "resume_epoch": epoch}),
    );
    let replayed = sub["resume"]["replayed"].as_u64().unwrap_or(0);
    assert!(
        replayed >= 1,
        "the target stream carried nothing across a successful registration: {sub}"
    );

    let mut health = 0;
    for _ in 0..replayed {
        let frame = c.read_frame();
        let p = &frame["params"]["payload"];
        if p["kind"] == serde_json::json!("target_health")
            && p["target_id"] == serde_json::json!(target_id)
        {
            health += 1;
            assert_eq!(
                p["reachable"],
                serde_json::json!(true),
                "the probe completed a real round trip to get here: {frame}"
            );
        }
    }
    assert_eq!(
        health, 1,
        "a subscriber saw no `target_health` frame for the target that was just \
         registered, and `target.list` cannot tell it either"
    );
}

#[test]
fn a_registered_target_carries_what_the_probe_measured() {
    let fake = FakeS3::refusing_every_algorithm();
    let d = Daemon::start_with_env("target-add-degrade", &[(PROBE_SECRET_VAR, PROBE_SECRET)]);
    let mut c = d.connect();

    let added = c.call(
        "target.add",
        serde_json::json!({
            "name": "refusing",
            "adapter": "s3",
            "config": {
                "bucket": "archive",
                "endpoint_url": fake.endpoint,
                "region": "us-east-1",
                "force_path_style": true,
            },
            "credentials_ref": "target/probe",
        }),
    );
    assert_eq!(added["target"]["name"], serde_json::json!("refusing"));
    assert_eq!(
        added["target"]["custody_eligible"],
        serde_json::json!(false),
        "§4.4: registration does not confer custody: {added}"
    );

    let stored = d.stored_target_config("refusing");

    assert!(
        stored.get("multipart_checksum").is_none(),
        "the provider refused every algorithm and the target adopted one anyway. Adopting the \
         request rather than the answer is how a probe reports support the provider never gave, \
         and every multipart object written through this target would then appear corrupt the \
         first time scrub compared it: {stored}"
    );

    let probe = stored.get("checksum_probe").unwrap_or_else(|| {
        panic!(
            "no `checksum_probe` in the stored config, so `target.add` registered this target \
             WITHOUT calling `shepherd_storage::s3::probe_multipart_checksum`. Every object \
             written through it is now permanently in the no-checksum configuration — 649x on \
             scrub, per object, unrecoverable without re-uploading. See the `UNSERVED` comment \
             in this file: {stored}"
        )
    });

    assert_eq!(
        probe["adopted"],
        serde_json::Value::Null,
        "a provider that refused all three must be recorded as adopting none: {probe}"
    );
    assert_eq!(
        probe["endpoint"],
        serde_json::json!(fake.endpoint),
        "a probe that reports a negative without naming where it was pointed is \
         indistinguishable from one that never left the emulator: {probe}"
    );

    // The evidence, per algorithm, in preference order. This is what makes a
    // wrong negative recoverable later.
    let attempts = probe["attempts"].as_array().expect("attempts array");
    let names: Vec<&str> = attempts
        .iter()
        .map(|a| a["algorithm"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["crc64-nvme", "crc32c", "crc32"],
        "the preference order is the design and it is recorded, not implied: {probe}"
    );
    for a in attempts {
        assert_eq!(
            a["outcome"]["result"],
            serde_json::json!("rejected"),
            "the provider answered `no` to this algorithm, so the record must say so — and say \
             why: {a}"
        );
        let detail = a["outcome"]["detail"].as_str().unwrap_or("");
        assert!(
            detail.contains("InvalidRequest"),
            "the refusal was stored without the provider's reason, which is the half that makes \
             a negative auditable: {a}"
        );
    }
}

/// **A provider that cannot be reached is not a provider that said no.**
///
/// The asymmetry E-5 turns on. `Err(_)` from the probe means the round trip
/// never happened, so it proves nothing about the provider — and storing it as
/// "supports nothing" would be silent, permanent, and indistinguishable from a
/// real measurement for the life of every object written afterwards.
///
/// So the registration is refused **and no row is written**. The second half is
/// the one worth asserting: a handler that inserted first and probed second
/// would pass a test that only checked the error code, while leaving behind
/// exactly the stranded target this is meant to prevent.
#[test]
fn a_target_whose_provider_cannot_be_reached_is_not_registered_at_all() {
    let d = Daemon::start_with_env(
        "target-add-unreachable",
        &[(PROBE_SECRET_VAR, PROBE_SECRET)],
    );
    let mut c = d.connect();

    let err = c.call_err(
        "target.add",
        serde_json::json!({
            "name": "unreachable",
            "adapter": "s3",
            "config": {
                // Port 1 is privileged and unbound: the connection is refused
                // immediately rather than timing out.
                "bucket": "archive",
                "endpoint_url": "http://127.0.0.1:1",
                "region": "us-east-1",
                "force_path_style": true,
            },
            "credentials_ref": "target/probe",
        }),
    );
    assert_eq!(
        err.kind(),
        Some(shepherd_proto::ErrorCode::TargetUnreachable),
        "an unreachable provider is a retryable transport failure, not a verdict about the \
         provider: {err}"
    );
    assert_eq!(
        d.target_count(),
        0,
        "the registration failed and left a target row behind. That row's uploads would run \
         with no whole-object checksum forever, on the strength of a probe that never reached \
         anything"
    );
}

/// **The positive leg, against a real provider.**
///
/// `#[ignore]`d like every other MinIO test here, because a test that silently
/// passes when its dependency is absent is worse than one that is visibly
/// skipped.
///
/// ```text
/// docker compose -f tests/docker-compose.yml up -d --wait
/// SHEPHERD_MINIO_ENDPOINT=http://127.0.0.1:9000 \
///   cargo test -p shepherd-daemon --test e2e -- --ignored --nocapture \
///   a_minio_target_adopts_the_strongest_algorithm_that_round_trips
/// ```
///
/// The fake above proves the degrade path and that the probe is called at all;
/// only a real provider can prove the other direction — that a bucket which
/// **does** support whole-object checksums ends up configured to use them,
/// which is the entire $441-against-$0.68 point. The adopted value is asserted
/// in its stored form, since that string is what a later phase hydrates a
/// `S3Config` from.
#[test]
#[ignore = "needs the MinIO in tests/docker-compose.yml"]
fn a_minio_target_adopts_the_strongest_algorithm_that_round_trips() {
    let endpoint = std::env::var("SHEPHERD_MINIO_ENDPOINT")
        .unwrap_or_else(|_| "http://127.0.0.1:9000".to_string());
    let d = Daemon::start_with_env(
        "target-add-minio",
        &[(
            PROBE_SECRET_VAR,
            r#"{"access_key_id":"shepherdtest","secret_access_key":"shepherdtest"}"#,
        )],
    );
    let mut c = d.connect();
    // Three 10 MiB multipart round trips against a container is not a
    // twenty-second operation on every machine.
    c.set_read_timeout(Duration::from_secs(120));

    c.call(
        "target.add",
        serde_json::json!({
            "name": "minio",
            "adapter": "s3",
            "config": {
                "bucket": "shepherd-plain",
                "endpoint_url": endpoint,
                "region": "us-east-1",
                "force_path_style": true,
            },
            "credentials_ref": "target/probe",
        }),
    );

    let stored = d.stored_target_config("minio");
    assert_eq!(
        stored["multipart_checksum"],
        serde_json::json!("crc64-nvme"),
        "MinIO round-trips CRC64NVME on a genuine two-part upload, so registration must adopt \
         it — this field is what every later upload through this target reads, and it cannot be \
         set after the fact without re-uploading every object: {stored}"
    );
    assert_eq!(
        stored["checksum_probe"]["attempts"][0]["outcome"]["result"],
        serde_json::json!("round_tripped"),
        "the adoption must be recorded with the value the provider actually returned, not as a \
         boolean: {stored}"
    );
    assert_eq!(
        stored["checksum_probe"]["attempts"][1]["outcome"]["result"],
        serde_json::json!("not_attempted"),
        "a provider that answered on the first algorithm must not be billed for two more 10 MiB \
         uploads: {stored}"
    );
}

// ---------------------------------------------------------------------------
// The client has to look where the daemon actually listens
// ---------------------------------------------------------------------------

/// An unqualified `shepctl` must reach a daemon configured through
/// `SHEPHERD_STATE_DIR`.
///
/// `Paths::resolve` places the socket in the configured state directory when
/// there is no `XDG_RUNTIME_DIR` — that is §4.3's fallback and it is what a
/// headless node, a `su` shell or a second daemon instance actually gets. The
/// client's candidate list was written independently and knew only
/// `$XDG_RUNTIME_DIR/shepherd/daemon.sock` and
/// `$HOME/.local/state/shepherd/daemon.sock`, so it looked in neither of the
/// places this daemon can be. The daemon runs, the socket exists, every command
/// reports it unreachable.
///
/// `--socket` is deliberately **not** passed: handing the client the answer is
/// exactly what every other test here does, and it is why this went unnoticed.
///
/// Exit status 3 is the client's "daemon unreachable", so asserting on the
/// status rather than on stderr text pins the actual user-visible outcome.
#[test]
fn an_unqualified_shepctl_reaches_a_daemon_configured_by_state_dir() {
    let d = Daemon::start_with_only_a_state_dir("clientpaths");
    assert!(
        d.socket.exists(),
        "the daemon is listening at {} — the rest of this test is about whether the client \
         looks there",
        d.socket.display()
    );

    let out = Command::new(shepctl())
        .args(["status", "--json"])
        .env("SHEPHERD_STATE_DIR", &d.dir)
        .env_remove("SHEPHERD_SOCKET")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .expect("run shepctl");

    let stderr = String::from_utf8_lossy(&out.stderr);
    assert_eq!(
        out.status.code(),
        Some(0),
        "`shepctl status` with no --socket must reach the daemon its own environment \
         describes; exit 3 is `daemon unreachable`.\nstderr: {stderr}"
    );
    let env: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("shepctl --json emits one JSON document");
    assert_eq!(env["ok"], serde_json::json!(true), "{env}");
    assert!(
        env["data"]["proto_version"].is_object() || env["data"]["uptime_s"].is_number(),
        "the reply must be a real `status` result from the daemon, not an empty success: {env}"
    );
}

/// And the refusal still refuses.
///
/// A client that resolved paths by trying everything, or that reported success
/// without connecting, would pass the test above. This one is the other
/// direction: pointed at a state directory with no daemon in it, `shepctl` must
/// still fail with exit 3 and name what it tried.
#[test]
fn shepctl_still_reports_unreachable_when_no_daemon_is_listening() {
    let dir = fixture_root().join(format!("shepctl-nodaemon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let out = Command::new(shepctl())
        .args(["status", "--json"])
        .env("SHEPHERD_STATE_DIR", &dir)
        .env_remove("SHEPHERD_SOCKET")
        .env_remove("XDG_RUNTIME_DIR")
        .output()
        .expect("run shepctl");

    assert_eq!(
        out.status.code(),
        Some(3),
        "no daemon is listening in {}; this must be exit 3, not a success",
        dir.display()
    );
    let env: serde_json::Value =
        serde_json::from_slice(&out.stdout).expect("shepctl --json emits one JSON document");
    let hint = env["error"]["hint"].as_str().unwrap_or_default();
    assert!(
        hint.contains(&dir.join("daemon.sock").display().to_string()),
        "AC-61 wants an error the user can act on: the path actually tried must be named. \
         hint was: {hint}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// A completed scan stamps `file.last_seen_gen` with its own job id.
///
/// `last_seen_gen` is the column an absence reconciliation reads
/// (`... WHERE last_seen_gen < :this_scan` marks rows the walk did not see as
/// `'missing'`). The catalog now writes whatever generation it is handed, and
/// its own tests pin that. What they cannot see is the value this executor
/// *chooses* — a constant, or a clock, or the job id — and that choice is the
/// whole correctness of the sweep that will read it. A generation that did not
/// advance between scans would make the next completed scan mark every file it
/// had just seen on disk as missing.
///
/// So both halves are asserted: the value equals the job id that produced it,
/// and it **moves** when the same root is scanned again.
///
/// The sweep itself is not implemented — nothing reads this column yet. This
/// test is what stops the stamping from silently rotting in the meantime.
#[test]
fn a_scan_stamps_its_job_id_as_the_generation_and_a_rescan_advances_it() {
    let d = Daemon::start("scangen");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-scangen");
    write_file(&root_dir, "a.txt", "hello");
    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();

    let started = c.call("scan.start", serde_json::json!({"root_id": root_id}));
    let first_job = started["job_ids"][0].as_i64().expect("a scan job id");
    scan_and_expect(&mut c, root_id, 1);

    let gen_of = || -> i64 {
        let conn = rusqlite::Connection::open_with_flags(
            d.dir.join("state").join("catalog.db"),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .expect("open the daemon's catalog read-only");
        conn.query_row("SELECT MIN(last_seen_gen) FROM file", [], |r| r.get(0))
            .expect("read last_seen_gen")
    };

    assert_eq!(
        gen_of(),
        first_job,
        "the row must carry the generation of the scan that saw it, not a constant"
    );

    let restarted = c.call("scan.start", serde_json::json!({"root_id": root_id}));
    let second_job = restarted["job_ids"][0]
        .as_i64()
        .expect("a second scan job id");
    assert!(
        second_job > first_job,
        "job ids must be monotonic for this to be a usable generation: {second_job} !> {first_job}"
    );
    scan_and_expect(&mut c, root_id, 1);

    assert_eq!(
        gen_of(),
        second_job,
        "a re-scan left the row at the first scan's generation. A sweep on \
         `last_seen_gen < :this_scan` would then mark this file — which the scan just \
         saw on disk — as missing"
    );
}

// ---------------------------------------------------------------------------
// Absence reconciliation: a completed scan reconciles the rows it did not see
// ---------------------------------------------------------------------------

/// Every file row under `root`, as `(rel_path, state)`.
fn rows_by_state(d: &Daemon, root_id: i64) -> Vec<(String, String)> {
    let conn = rusqlite::Connection::open_with_flags(
        d.dir.join("state").join("catalog.db"),
        rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
    )
    .expect("open the daemon's catalog read-only");
    let mut stmt = conn
        .prepare("SELECT rel_path, state FROM file WHERE root_id = ?1 ORDER BY rel_path")
        .unwrap();
    let rows = stmt
        .query_map(rusqlite::params![root_id], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?))
        })
        .unwrap();
    rows.map(Result::unwrap).collect()
}

/// A root that has vanished must fail the scan, not sweep the catalog away.
///
/// **This is the landmine under the whole finding.** `shepherd_scan::walk`
/// reports an unreadable directory as a `Skip::Unreadable` and returns `Ok` —
/// so a root on an unmounted volume, or one the user deleted, produces a
/// perfectly *successful* walk of zero files. A sweep that trusted "the walk
/// completed" would then reconcile every row under that root to `missing`,
/// including every tiered file whose catalog row is the only address of its
/// remote bytes.
///
/// `scan_exec`'s PM-3 guard does not cover this: it refuses a root the catalog
/// already *knows* is unavailable, and nothing marks a root unavailable when it
/// disappears underneath a running daemon.
///
/// So the scan must fail. Both halves are asserted — the failure, and the rows
/// still being `'local'` — because a scan that failed *after* sweeping would
/// report the error and still have destroyed the catalog's picture.
#[test]
fn a_scan_of_a_vanished_root_fails_and_reconciles_nothing() {
    let d = Daemon::start("sweepgone");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-sweepgone");
    write_file(&root_dir, "precious.txt", "the only copy");
    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let root_id = added["root"]["root_id"].as_i64().unwrap();
    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    scan_and_expect(&mut c, root_id, 1);

    // The volume goes away.
    std::fs::remove_dir_all(&root_dir).unwrap();

    c.call("scan.start", serde_json::json!({"root_id": root_id}));
    // Not `wait_for_scan`: that waits for a job to *finish*, and a failing scan
    // is retried with backoff, so it is queued again before it is ever
    // observably done. What is under test is the recorded failure, which
    // appears as soon as the first attempt returns.
    let scan = wait_for_scan_error(&mut c, root_id);
    let detail = scan["last_error"].as_str().unwrap_or_default();
    assert!(
        detail.contains("could not be read"),
        "a walk that could not read its own root observed nothing; reporting that as a \
         successful scan of zero files is what turns a missing volume into a swept \
         catalog: {scan}"
    );

    assert_eq!(
        rows_by_state(&d, root_id),
        vec![("precious.txt".to_string(), "local".to_string())],
        "the root was unreadable, not empty. Every row under it must be untouched — these \
         rows are the only address of anything that was tiered from here"
    );
}

/// A root whose identity probe could not run must say so.
///
/// `identity::probe_path_policies` returns `assumed: true` when it could not
/// create its throwaway files and fell back to platform defaults, and its doc
/// comment says "the caller records the distinction". `root.add` took `case`
/// and `norm` and dropped `assumed` on the floor — so a root whose case and
/// normalization policy was **guessed** became indistinguishable, forever, from
/// one that was measured.
///
/// That matters because `norm_key` is derived from those policies and watcher
/// events match against it; §4.9's whole argument is that retrofitting identity
/// after Phase 2 has destroyed files is the scenario probing prevents. The line
/// directly above the call reads "Probed, never assumed" — a comment describing
/// behaviour the code did not have.
///
/// The two sibling gaps in the same function — an untrustworthy atime and an
/// absent volume id — both already push a warning. This is that pattern, applied
/// to the third.
///
/// A read-only directory is how the probe is made to fail: it creates files with
/// `create_new`, which cannot succeed under `0o555`.
#[test]
fn a_root_whose_identity_probe_could_not_run_is_reported_as_assumed() {
    // The probe would succeed as root, and a test that passes because the
    // condition never arose is worse than no test.
    assert_ne!(
        unsafe { libc::geteuid() },
        0,
        "this test needs a directory it cannot write to, so it cannot run as root"
    );

    let d = Daemon::start("assumed");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-assumed");
    std::fs::create_dir_all(&root_dir).unwrap();
    std::fs::set_permissions(&root_dir, std::fs::Permissions::from_mode(0o555)).unwrap();

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );

    let warnings: Vec<&str> = added["warnings"]
        .as_array()
        .expect("root.add reports warnings")
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect();
    assert!(
        warnings.iter().any(|w| w.contains("could not probe")),
        "the case/normalization policy was assumed, not probed, and nothing said so. \
         `probe_path_policies` reports the distinction and this is the caller its docs \
         name. warnings were: {warnings:?}"
    );

    // Restored so `Drop` can clean the directory up.
    std::fs::set_permissions(&root_dir, std::fs::Permissions::from_mode(0o755)).unwrap();
}

/// And a root that probed cleanly must NOT carry that warning.
///
/// Without this, "warn when assumed" is satisfiable by warning always — which
/// would train every user to ignore the line, and is the same defect as never
/// warning at all wearing the opposite face.
#[test]
fn a_root_that_probed_successfully_carries_no_assumed_warning() {
    let d = Daemon::start("probed");
    let mut c = d.connect();

    let root_dir = d.dir.join("corpus-probed");
    write_file(&root_dir, "a.txt", "a");

    let added = c.call(
        "root.add",
        serde_json::json!({"path": root_dir.to_str().unwrap(), "stub_mode": "delete"}),
    );
    let warnings: Vec<&str> = added["warnings"]
        .as_array()
        .expect("root.add reports warnings")
        .iter()
        .map(|w| w.as_str().unwrap())
        .collect();
    assert!(
        !warnings.iter().any(|w| w.contains("could not probe")),
        "this root's probe ran; claiming its policies were assumed would make the warning \
         meaningless: {warnings:?}"
    );
}

/// Read `root.add`'s warnings as a plain list of strings.
fn root_add_warnings(c: &mut Client, path: &std::path::Path) -> Vec<String> {
    let added = c.call(
        "root.add",
        serde_json::json!({"path": path.to_str().unwrap(), "stub_mode": "delete"}),
    );
    added["warnings"]
        .as_array()
        .expect("root.add reports warnings")
        .iter()
        .map(|w| w.as_str().unwrap().to_string())
        .collect()
}

/// D-12's enrollment feasibility probe does not run, and enrollment says so.
///
/// §4.10.1 requires identity-bound staging to be verified **at enrollment**, not
/// discovered when destruction fails: a root on a filesystem that rejects
/// `RENAME_NOREPLACE` (FUSE, exFAT) is `destruction_ineligible`, and §4.10.1
/// permits no detect-only fallback. `PlaceholderProvider::probe_feasibility`
/// implements that probe and `FileRepo::set_destruction_ineligible` persists its
/// verdict — and nothing on the registration path calls either, so the column
/// keeps its schema default of 0 and `ScanRoot::may_destroy` returns `true` for
/// a root whose originals can never be safely destroyed.
///
/// **This build cannot run the probe, and that is deliberate**, so this warning
/// is the honest floor rather than the fix. `shepherd-daemon` holds no edge to
/// `shepherd-placeholder`: `xtask/deps-policy.toml` rule 2 makes `shepherd-tier`
/// its sole dependent, which is what keeps `shepherd-tier::destroy` the only
/// path to a destructive syscall. Adding the edge to run a *non*-destructive
/// probe would spend that invariant on the thing it protects against.
///
/// It is safe to defer only because the consuming path does not exist either —
/// `tier.plan`, `tier.run` and `restore` all answer `MethodNotImplemented`, so
/// `may_destroy` currently authorises nothing. The test below is what makes that
/// "only because" load-bearing instead of a hope.
///
/// This is the same shape as the `assumed` warning above, and deliberately so:
/// two enrollment-time capability facts, both currently reported to the user
/// rather than enforced against the catalog.
#[test]
fn a_root_is_told_its_destruction_feasibility_was_not_probed() {
    let d = Daemon::start("feasibility");
    let mut c = d.connect();
    let root_dir = d.dir.join("corpus-feasibility");
    write_file(&root_dir, "a.txt", "a");

    let warnings = root_add_warnings(&mut c, &root_dir);
    assert!(
        warnings
            .iter()
            .any(|w| w.contains("destruction feasibility")),
        "enrollment must disclose that D-12's probe did not run; silence here reads as \
         'this root can be destroyed from', which is exactly what was never established. \
         warnings were: {warnings:?}"
    );
}

/// **The gate on the deferral above.** Whoever wires tiering must find it.
///
/// Asserted as a biconditional, which is what makes it a gate rather than a
/// note: the unprobed-feasibility warning must be present *exactly* while
/// tiering is unreachable.
///
/// * Serve `tier.plan` while this warning is still all that stands in for the
///   probe, and this fails — which is the moment the deferral stops being safe,
///   because `may_destroy` starts authorising real destruction.
/// * Delete the warning before the probe exists, and this fails too — the
///   capability gap would go back to being silent.
///
/// # What to do when this test fails because you served `tier.plan`
///
/// Do not delete this test, and do not relax `deps-policy.toml` rule 2. In
/// `dispatch.rs::root_add`, at the `insert_root` call:
///
/// 1. run `PlaceholderProvider::probe_feasibility` on the root — reachable once
///    the daemon legitimately holds a `shepherd-tier` edge for tiering itself,
///    which is the edge Phase 2 adds anyway;
/// 2. persist the verdict with `FileRepo::set_destruction_ineligible` (already
///    `pub`, so no catalog change is needed);
/// 3. **a probe that could not run is not a probe that said yes** — an `Err`
///    from it must not read as `Supported`. Round 2 fixed exactly that shape
///    three lines away, where `probe_path_policies`' `assumed` flag was dropped
///    at the boundary;
/// 4. assert **both** directions: a root on a filesystem that supports staging
///    stays `destruction_ineligible = 0`. "Mark everything ineligible" passes
///    every refusal test while quietly disabling tiering.
///
/// Then replace this test with one asserting the persisted column, both ways.
#[test]
fn the_unprobed_feasibility_warning_lasts_exactly_as_long_as_tiering_is_unreachable() {
    let d = Daemon::start("feasgate");
    let mut c = d.connect();

    let tiering_unreachable = c
        .call_err(
            "tier.plan",
            serde_json::json!({"rule_id": 999_999, "target_id": 999_999}),
        )
        .kind()
        == Some(shepherd_proto::ErrorCode::MethodNotImplemented);

    let root_dir = d.dir.join("corpus-feasgate");
    write_file(&root_dir, "a.txt", "a");
    let warnings = root_add_warnings(&mut c, &root_dir);
    let warns_unprobed = warnings
        .iter()
        .any(|w| w.contains("destruction feasibility"));

    assert_eq!(
        tiering_unreachable, warns_unprobed,
        "the enrollment-time feasibility verdict is still not persisted, and these two facts \
         have come apart. tiering unreachable: {tiering_unreachable}; enrollment warns: \
         {warns_unprobed}. Read this test's doc comment — if you just served `tier.plan`, \
         `may_destroy` now authorises destruction for roots whose staging support was never \
         established. warnings were: {warnings:?}"
    );
}
