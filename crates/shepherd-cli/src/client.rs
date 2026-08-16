//! The IPC transport: newline-delimited JSON-RPC 2.0 over a Unix socket.
//!
//! # Scope, stated plainly
//!
//! This is a **synchronous, one-call-per-connection** client. It connects,
//! shakes hands, sends one request, reads one response and exits — which is
//! exactly the lifetime of a `shepctl` invocation. There is no runtime, no
//! connection pool and no reconnect loop, because a process that lives for
//! 40 ms needs none of them. A long-lived subscriber (the UI relay, or
//! `shepctl events subscribe` once the daemon can serve it) needs a streaming
//! reader on the same framing; that is task T6's, and [`Connection::read_frame`]
//! is the piece it would reuse.
//!
//! **No daemon exists yet.** `shepherd-daemon` is task T6 and is still a
//! skeleton, so nothing here has been exercised against a live socket. What *is*
//! exercised: the framing, the handshake construction, the envelope mapping and
//! the not-running error path, all in `tests/`. The live path is scaffolded, and
//! this paragraph is the honest statement of that.
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

use std::io::{BufRead, BufReader, Write};
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
/// §4.3: `$XDG_RUNTIME_DIR/shepherd/daemon.sock`, falling back to
/// `~/.local/state/shepherd/daemon.sock`. Both are returned so an error can name
/// every path that was tried — AC-61 forbids an error the user cannot act on,
/// and "connection refused" without a path is precisely that.
pub fn candidate_socket_paths() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(runtime) = std::env::var("XDG_RUNTIME_DIR")
        && !runtime.is_empty()
    {
        out.push(format!("{runtime}/shepherd/daemon.sock"));
    }
    if let Ok(home) = std::env::var("HOME")
        && !home.is_empty()
    {
        out.push(format!("{home}/.local/state/shepherd/daemon.sock"));
    }
    out
}

/// The platform command that starts the daemon, named in the not-running error.
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
            let mut line = String::new();
            let n = self
                .reader
                .read_line(&mut line)
                .map_err(|e| ClientError::Transport(e.to_string()))?;
            if n == 0 {
                return Err(ClientError::Transport(
                    "the daemon closed the connection without answering".into(),
                ));
            }
            serde_json::from_str(&line).map_err(|e| {
                ClientError::Transport(format!("the daemon sent a frame that is not JSON: {e}"))
            })
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
