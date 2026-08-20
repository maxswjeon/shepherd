//! The IPC transport: newline-delimited JSON-RPC 2.0 over a Unix socket.
//!
//! # Scope, stated plainly
//!
//! This is a **synchronous** client with two shapes of exchange, and the
//! difference between them is the whole of this module's design:
//!
//! * [`call`] — one request, one response, done. That is the lifetime of an
//!   ordinary `shepctl` invocation, and there is no runtime, no connection pool
//!   and no reconnect loop, because a process that lives for 40 ms needs none.
//! * [`subscribe`] — one request, then **every frame that follows**, until the
//!   stream ends. `events.subscribe` installs a pump on the connection it
//!   arrived on, so a client that returns after the response closes the socket
//!   the events were about to come down. Serving it through `call` is not a
//!   smaller version of subscribing; it is a subscription that renders nothing.
//!
//! This paragraph used to say that no daemon existed and that nothing here had
//! ever met a live socket. That has not been true since T6 landed, and leaving
//! it standing was worse than saying nothing: it is the kind of stale caveat a
//! reader trusts. Both paths are now exercised against a real `shepherdd` — see
//! `shepherd-daemon`'s `tests/e2e.rs`, which drives the real `shepctl` binary
//! over a real socket, including the subscription stream. `tests/` here still
//! covers the parts a mock is better at: the framing, the handshake
//! construction, the envelope mapping and the not-running error path.
//!
//! # Windows
//!
//! §4.3 specifies a named pipe `\\.\pipe\shepherd-{user-sid}` with a DACL
//! granting only the owning user. Constructing that DACL correctly is Win32 FFI
//! work that belongs with the rest of the Windows platform layer in Phase 3, and
//! a pipe opened without it would be a security regression that happens to
//! compile. So the Windows client returns a named error instead. The whole
//! workspace builds on all three platforms from Phase 0a, and this keeps that
//! true without pretending the transport exists.

use std::time::Duration;

use shepherd_proto::{
    ErrorCode, Hello, PROTO_VERSION, PeerInfo, RequestId, RpcError, RpcRequest, RpcResponse,
};

/// How long to wait for the daemon to answer one call.
pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// The handshake's method name.
///
/// Not a table method — see `shepherd_proto::version` for why the connection
/// preamble is deliberately outside the capability registry.
pub const HELLO_METHOD: &str = "hello";

/// Why a call did not produce a result.
#[derive(Debug)]
pub enum ClientError {
    /// The daemon is not listening. `detail` is the whole actionable message,
    /// already naming every path tried and the start command.
    ///
    /// Only the Unix connector constructs it today; on Windows `connect`
    /// returns [`ClientError::Unsupported`] before it can reach a socket. The
    /// variant stays unconditional so the exit-code table is identical on all
    /// three platforms rather than being cfg'd apart.
    #[cfg_attr(not(unix), allow(dead_code))]
    NotRunning { detail: String },
    /// The socket exists but the exchange failed.
    Transport(String),
    /// The daemon answered with a JSON-RPC error.
    Rpc(RpcError),
    /// This platform has no client yet.
    ///
    /// Constructed only on non-Unix targets, so on Unix the variant is read
    /// (by `to_cli_error` and the exit-code mapping) but never built. Keeping
    /// it unconditional means the exit-code table is the same on all three
    /// platforms instead of being cfg'd apart.
    #[cfg_attr(unix, allow(dead_code))]
    Unsupported(String),
}

impl std::fmt::Display for ClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ClientError::NotRunning { detail } => f.write_str(detail),
            ClientError::Transport(m) => write!(f, "IPC transport failure: {m}"),
            ClientError::Rpc(e) => write!(f, "{}", e.message),
            ClientError::Unsupported(m) => f.write_str(m),
        }
    }
}

/// Where the daemon listens.
///
/// Delegated to `shepherd_obs::paths`, which is also what the daemon binds
/// from. That is the whole point and it is not tidiness: this function used to
/// have its own opinion — `$XDG_RUNTIME_DIR/shepherd/daemon.sock` then
/// `$HOME/.local/state/shepherd/daemon.sock`, and nothing else — while
/// `Paths::resolve` also honours `SHEPHERD_SOCKET`, `SHEPHERD_STATE_DIR` and
/// `XDG_STATE_HOME`. A daemon configured through any of those three ran
/// normally and every unqualified `shepctl` reported it unreachable, because
/// the client was looking in two places the daemon could not be.
///
/// The list is still a list, and still ordered: an error can then name every
/// path that was tried, which AC-61 requires, and a client whose environment
/// has skewed from the daemon's (systemd sets `XDG_RUNTIME_DIR`; an `ssh` shell
/// often does not) still has somewhere else to look. The *first* entry is the
/// daemon's own answer, asserted over the whole environment matrix in
/// `shepherd_obs::paths`.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn candidate_socket_paths() -> Vec<String> {
    shepherd_obs::paths::socket_candidates(&shepherd_obs::paths::Env::from_process())
        .into_iter()
        .map(|p| p.display().to_string())
        .collect()
}

/// The platform command that starts the daemon, named in the not-running error.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn start_command() -> &'static str {
    if cfg!(target_os = "macos") {
        "launchctl kickstart -k gui/$UID/kr.swjeon.shepherd"
    } else if cfg!(target_os = "windows") {
        "schtasks /run /tn Shepherd"
    } else {
        "systemctl --user start shepherd"
    }
}

/// The message a user gets when nothing is listening.
///
/// Every element AC-61 asks for: the paths tried, the service-registration state
/// as far as this process can honestly determine it, and the exact start command.
/// The registration line says "not probed" rather than guessing, because
/// querying systemd/launchd is `shepherd-daemon`'s job (T6) and a confident
/// wrong answer here would be worse than an honest gap.
#[cfg_attr(not(unix), allow(dead_code))]
pub fn not_running_message(tried: &[String], cause: &str) -> String {
    let paths = if tried.is_empty() {
        "  (none — neither XDG_RUNTIME_DIR nor HOME is set)".to_string()
    } else {
        tried
            .iter()
            .map(|p| format!("  {p}"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    format!(
        "the Shepherd daemon is not accepting connections ({cause}).\n\
         tried:\n{paths}\n\
         service registration: not probed by shepctl\n\
         start it with: {}",
        start_command()
    )
}

// ---------------------------------------------------------------------------
// Connection
// ---------------------------------------------------------------------------

#[cfg(unix)]
pub use unix_impl::Connection;

#[cfg(unix)]
mod unix_impl {
    use super::*;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::UnixStream;

    /// One newline-delimited JSON-RPC connection.
    pub struct Connection {
        writer: UnixStream,
        reader: BufReader<UnixStream>,
        socket: String,
    }

    impl Connection {
        /// Connect to the first candidate that answers.
        pub fn connect(
            explicit: Option<&str>,
            timeout: Duration,
        ) -> Result<Connection, ClientError> {
            let candidates: Vec<String> = match explicit {
                Some(p) => vec![p.to_string()],
                None => candidate_socket_paths(),
            };
            let mut last = String::from("no socket path to try");
            for path in &candidates {
                match UnixStream::connect(path) {
                    Ok(stream) => {
                        stream
                            .set_read_timeout(Some(timeout))
                            .and_then(|()| stream.set_write_timeout(Some(timeout)))
                            .map_err(|e| ClientError::Transport(e.to_string()))?;
                        let reader = BufReader::new(
                            stream
                                .try_clone()
                                .map_err(|e| ClientError::Transport(e.to_string()))?,
                        );
                        return Ok(Connection {
                            writer: stream,
                            reader,
                            socket: path.clone(),
                        });
                    }
                    Err(e) => last = e.to_string(),
                }
            }
            Err(ClientError::NotRunning {
                detail: not_running_message(&candidates, &last),
            })
        }

        /// The path this connection actually used.
        pub fn socket(&self) -> &str {
            &self.socket
        }

        /// Write one frame, newline-terminated.
        pub fn write_frame(&mut self, value: &serde_json::Value) -> Result<(), ClientError> {
            let mut line = serde_json::to_string(value)
                .map_err(|e| ClientError::Transport(format!("cannot encode a frame: {e}")))?;
            line.push('\n');
            self.writer
                .write_all(line.as_bytes())
                .and_then(|()| self.writer.flush())
                .map_err(|e| ClientError::Transport(e.to_string()))
        }

        /// Read one frame.
        ///
        /// A closed connection is reported as a transport failure rather than as
        /// an empty result: a daemon that hangs up mid-call has not answered, and
        /// treating silence as success is how a CLI reports a tiering run that
        /// never started.
        pub fn read_frame(&mut self) -> Result<serde_json::Value, ClientError> {
            self.read_frame_or_eof()?.ok_or_else(|| {
                ClientError::Transport("the daemon closed the connection without answering".into())
            })
        }

        /// Read one frame, or `None` at end of stream.
        ///
        /// The distinction exists for exactly one caller. For a request/response
        /// call, EOF means the daemon hung up without answering and is a failure
        /// — see [`Self::read_frame`], which is that call's door. For a
        /// subscription, EOF is how the stream **ends**: the daemon stopped, or
        /// was stopped, and the frames that arrived before that were real. Both
        /// readings cannot live in one function, so the raw one is here and the
        /// opinionated one wraps it.
        pub fn read_frame_or_eof(&mut self) -> Result<Option<serde_json::Value>, ClientError> {
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| ClientError::Transport(e.to_string()))?;
            if n == 0 {
                return Ok(None);
            }
            serde_json::from_str(&line).map(Some).map_err(|e| {
                ClientError::Transport(format!("the daemon sent a frame that is not JSON: {e}"))
            })
        }

        /// Stop applying the per-call read timeout to this connection.
        ///
        /// A subscription is idle by design — a quiet system publishes nothing —
        /// so the 30 s deadline that protects a request/response call from a
        /// hung daemon would instead kill a perfectly healthy stream on its
        /// first quiet half-minute. It stays in force for the connect, the
        /// handshake and the subscribe response, which are the parts that can
        /// legitimately hang, and is cleared only once the stream begins.
        pub fn read_without_deadline(&mut self) -> Result<(), ClientError> {
            // On the reader's own descriptor. `try_clone` is a `dup`, so the two
            // share one socket and one `SO_RCVTIMEO`, but naming the descriptor
            // that is actually read leaves nothing resting on that.
            self.reader
                .get_ref()
                .set_read_timeout(None)
                .map_err(|e| ClientError::Transport(e.to_string()))
        }
    }
}

#[cfg(not(unix))]
pub use other_impl::Connection;

#[cfg(not(unix))]
mod other_impl {
    use super::*;

    /// Placeholder so the workspace builds on Windows from Phase 0a.
    pub struct Connection {
        _never: std::convert::Infallible,
    }

    impl Connection {
        pub fn connect(
            _explicit: Option<&str>,
            _timeout: Duration,
        ) -> Result<Connection, ClientError> {
            Err(ClientError::Unsupported(
                "shepctl cannot reach the daemon on this platform yet. §4.3 specifies a named \
                 pipe `\\\\.\\pipe\\shepherd-{user-sid}` with a DACL granting only the owning \
                 user; that DACL is Win32 FFI work scheduled with the rest of the Windows \
                 platform layer in Phase 3. Opening a pipe without it would compile and would \
                 be a security regression."
                    .into(),
            ))
        }

        pub fn socket(&self) -> &str {
            match self._never {}
        }

        pub fn write_frame(&mut self, _v: &serde_json::Value) -> Result<(), ClientError> {
            match self._never {}
        }

        pub fn read_frame(&mut self) -> Result<serde_json::Value, ClientError> {
            match self._never {}
        }

        pub fn read_frame_or_eof(&mut self) -> Result<Option<serde_json::Value>, ClientError> {
            match self._never {}
        }

        pub fn read_without_deadline(&mut self) -> Result<(), ClientError> {
            match self._never {}
        }
    }
}

// ---------------------------------------------------------------------------
// The call sequence
// ---------------------------------------------------------------------------

/// Build the `hello` frame this client opens every connection with.
///
/// Split out from [`call`] so it is testable without a socket: the handshake is
/// where a version-skew bug would live, and it is the one part of this module
/// that can be checked for correctness offline.
pub fn hello_frame(id: i64) -> serde_json::Value {
    let hello = Hello {
        proto_version: PROTO_VERSION,
        client: PeerInfo {
            name: "shepctl".into(),
            build: env!("CARGO_PKG_VERSION").into(),
        },
        capabilities: client_capabilities(),
    };
    serde_json::to_value(RpcRequest::new(
        id,
        HELLO_METHOD,
        serde_json::to_value(hello).expect("Hello is serializable"),
    ))
    .expect("a request frame is serializable")
}

/// What `shepctl` can make use of.
///
/// Deliberately short. A CLI invocation that lives for one call has no use for
/// event resume; `shepctl events subscribe` is the exception and it declares it
/// per-invocation rather than every command claiming it.
pub fn client_capabilities() -> Vec<shepherd_proto::Capability> {
    Vec::new()
}

/// Perform one call: connect, handshake, request, response.
pub fn call(
    socket: Option<&str>,
    timeout: Duration,
    method: &str,
    params: serde_json::Value,
) -> Result<serde_json::Value, ClientError> {
    let mut conn = Connection::connect(socket, timeout)?;
    let path = conn.socket().to_string();
    // Every transport failure past this point names the socket it happened on.
    // A bare "broken pipe" with no path is unactionable when two daemons could
    // plausibly be listening (the XDG one and the HOME fallback).
    let at = |e: ClientError| match e {
        ClientError::Transport(m) => ClientError::Transport(format!("{m} (socket {path})")),
        other => other,
    };

    conn.write_frame(&hello_frame(0)).map_err(&at)?;
    let hello_reply: RpcResponse = parse_frame(conn.read_frame().map_err(&at)?).map_err(&at)?;
    hello_reply.outcome().map_err(ClientError::Rpc)?;

    let request = RpcRequest::new(RequestId::Number(1), method, params);
    let encoded = serde_json::to_value(&request)
        .map_err(|e| ClientError::Transport(format!("cannot encode the request: {e}")))?;
    conn.write_frame(&encoded).map_err(&at)?;
    let reply: RpcResponse = parse_frame(conn.read_frame().map_err(&at)?).map_err(&at)?;
    reply.outcome().map_err(ClientError::Rpc)
}

/// Subscribe, then keep reading until the stream ends.
///
/// # Why this cannot be [`call`]
///
/// `call` reads one response and drops its `Connection`. For every other method
/// that is exactly right. For `events.subscribe` it is the bug: the daemon
/// answers the subscription, then pumps notifications down *the same socket*
/// (see `shepherd_daemon::server::subscribe_on_connection`, which installs the
/// pump on the connection the request arrived on). Returning after one frame
/// closes that socket, the pump's first write fails, and the subscriber is
/// reaped — so neither the replayed frames nor a single live event was ever
/// rendered. The subscription "succeeded" and did nothing, which is the shape
/// of failure this project keeps having to walk back.
///
/// # How it ends
///
/// On **end of stream** — the daemon stopped, or the connection was closed —
/// and on **Ctrl-C**, which needs no code here because the default SIGINT
/// disposition is what a user pressing it expects. There is deliberately no
/// `--count` or `--for` flag: this CLI's arguments are derived from the
/// method's request schema by construction (see `main.rs`), so a client-only
/// argument would be the first thing to break that, and `journalctl -f` and
/// `docker logs -f` have already established EOF-or-interrupt as what a
/// follow command does.
///
/// `on_event` is handed each notification's `params` — one event frame — as it
/// arrives, not collected and returned at the end. A subscriber that rendered
/// nothing until the stream closed would be as useless as the one this replaces.
///
/// Returns the `SubscribeResult`, how many event frames were rendered, and
/// **how the stream ended**.
///
/// # The subscription result is delivered BEFORE the first event
///
/// `on_ready` runs the moment the daemon answers, and it is not a convenience.
/// The result carries `resume.outcome`, which can be
/// [`ResumeOutcome::SnapshotRequired`] — "your cursor is unusable, everything
/// you believe about the past is invalid, re-read state before trusting this
/// stream". Returning it only at the END meant a long-lived subscription never
/// delivered it at all: the caller processed live events indefinitely without
/// ever learning its prior state was incomplete.
///
/// The events are still forwarded. A follow command that refused to print
/// until some snapshot had been "handled" would be refusing to do the one thing
/// it exists for, and this layer has no way to take a snapshot on the caller's
/// behalf. What it owes is that the warning arrives FIRST and cannot be missed,
/// which is what the ordering buys.
pub fn subscribe(
    socket: Option<&str>,
    timeout: Duration,
    params: serde_json::Value,
    on_ready: impl FnOnce(&serde_json::Value),
    mut on_event: impl FnMut(&serde_json::Value),
) -> Result<Subscription, ClientError> {
    let mut conn = Connection::connect(socket, timeout)?;
    let path = conn.socket().to_string();
    let at = |e: ClientError| match e {
        ClientError::Transport(m) => ClientError::Transport(format!("{m} (socket {path})")),
        other => other,
    };

    conn.write_frame(&hello_frame(0)).map_err(&at)?;
    let hello_reply: RpcResponse = parse_frame(conn.read_frame().map_err(&at)?).map_err(&at)?;
    hello_reply.outcome().map_err(ClientError::Rpc)?;

    let request = RpcRequest::new(
        RequestId::Number(1),
        shepherd_proto::MethodKind::EventsSubscribe.name(),
        params,
    );
    let encoded = serde_json::to_value(&request)
        .map_err(|e| ClientError::Transport(format!("cannot encode the request: {e}")))?;
    conn.write_frame(&encoded).map_err(&at)?;
    let reply: RpcResponse = parse_frame(conn.read_frame().map_err(&at)?).map_err(&at)?;
    let result = reply.outcome().map_err(ClientError::Rpc)?;

    // Before a single event is forwarded. See this function's docs.
    on_ready(&result);

    // Only now: everything above can legitimately hang and is worth a deadline.
    // Nothing below is — silence is the normal state of a subscription.
    conn.read_without_deadline().map_err(&at)?;

    let mut rendered = 0u64;
    let mut last_seq = None;
    let mut dropped = None;
    while let Some(frame) = conn.read_frame_or_eof().map_err(&at)? {
        // The daemon sends notifications, which carry `method` and no `id`.
        // Anything else on this socket is not an event and is not ours to
        // render; skipping rather than failing keeps a future frame kind from
        // breaking a running subscriber.
        // The daemon's explicit "you were dropped" frame, which is the last
        // thing it writes before closing an overflowed subscriber's socket.
        // Without it, EOF alone cannot be told apart from an ordinary daemon
        // shutdown, and a subscription that lost frames looked like a clean end.
        if frame.get("method").and_then(serde_json::Value::as_str)
            == Some(shepherd_proto::SUBSCRIPTION_DROPPED_METHOD)
        {
            dropped = frame.get("params").cloned();
            continue;
        }
        if frame.get("method").and_then(serde_json::Value::as_str) == Some("event")
            && let Some(payload) = frame.get("params")
        {
            rendered += 1;
            last_seq = payload
                .get("seq")
                .and_then(serde_json::Value::as_u64)
                .or(last_seq);
            on_event(payload);
        }
    }

    // EOF alone is an ordinary end — a daemon shutting down, or the user
    // interrupting — and this command has always treated that as success.
    // What it could not do was tell that apart from the daemon dropping a
    // subscriber that fell behind, which is a LOSS of events and was reported
    // identically. The terminal frame above is what separates them.
    Ok(Subscription {
        result,
        rendered,
        last_seq,
        ended: match dropped {
            Some(params) => StreamEnd::Dropped(params),
            None => StreamEnd::DaemonClosed,
        },
    })
}

/// What a finished `subscribe` covered, and how it finished.
#[derive(Debug, Clone)]
pub struct Subscription {
    /// The `SubscribeResult` the daemon answered with. Already handed to
    /// `on_ready` before any event; returned again so a caller that only wants
    /// it at the end need not keep it.
    pub result: serde_json::Value,
    pub rendered: u64,
    /// The highest `seq` actually processed — the cursor to resume from.
    pub last_seq: Option<u64>,
    pub ended: StreamEnd,
}

/// Why an event stream stopped.
#[derive(Debug, Clone, PartialEq)]
pub enum StreamEnd {
    /// The socket reached EOF with no explanation: the daemon is shutting down,
    /// or the connection went away. Nothing says events were missed, and a
    /// follow command ending this way is an ordinary end.
    DaemonClosed,
    /// The daemon said so, in a `subscription.dropped` notification, before
    /// closing: this subscriber fell behind its queue and the frames after the
    /// drained ones were never delivered. Carries the notification's params.
    Dropped(serde_json::Value),
}

fn parse_frame(value: serde_json::Value) -> Result<RpcResponse, ClientError> {
    serde_json::from_value(value).map_err(|e| {
        ClientError::Transport(format!(
            "the daemon sent a frame that is not a JSON-RPC 2.0 response: {e}"
        ))
    })
}

/// Map a client failure onto the stable CLI error contract.
pub fn to_cli_error(e: &ClientError) -> shepherd_proto::CliError {
    match e {
        ClientError::NotRunning { detail } => {
            shepherd_proto::CliError::new("daemon_unreachable", "the daemon is not running")
                .with_hint(detail.clone())
        }
        ClientError::Unsupported(m) => shepherd_proto::CliError::new("not_implemented", m.clone()),
        ClientError::Transport(m) => shepherd_proto::CliError::new("protocol_error", m.clone()),
        ClientError::Rpc(err) => {
            let mut cli = shepherd_proto::CliError::from(err);
            if err.kind() == Some(ErrorCode::MethodNotImplemented) {
                cli = cli.with_hint(
                    "this method is registered in the protocol but not served by the running \
                     daemon build",
                );
            }
            cli
        }
    }
}
