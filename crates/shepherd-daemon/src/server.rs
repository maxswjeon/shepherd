//! The IPC server: newline-delimited JSON-RPC 2.0 over a Unix socket (§4.3).
//!
//! # Authorization is the socket's permissions, and nothing else
//!
//! §4.3: "Authorization is filesystem/pipe permissions only — same user, same
//! machine, not network-exposed." There is no token, no auth method, and no
//! per-caller identity check, because the socket being `0600` under a
//! user-owned directory *is* the control. That makes [`bind`]'s permission
//! handling security-critical rather than housekeeping, which is why the mode
//! is set **before** the listener accepts anything.
//!
//! # `hello` before anything else
//!
//! Every connection opens with `hello`. It is not a table method (see
//! `shepherd_proto::version`), so it is matched by name here, ahead of the
//! generated dispatch. A connection that sends anything else first is answered
//! with an error naming the requirement rather than being silently served —
//! otherwise the negotiated minor would be unknown and method gating could not
//! be applied.
//!
//! # Windows
//!
//! §4.3 specifies a named pipe with a DACL granting only the owning user. That
//! DACL is Phase 3 Win32 work, and a pipe opened without it would compile and
//! be a security regression, so this module is Unix-only and `main` says so on
//! other platforms.

#![cfg(unix)]

use std::io::{BufRead, BufReader, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use shepherd_proto::request::RpcRequest;
use shepherd_proto::response::RpcResponse;
use shepherd_proto::{
    ErrorCode, Hello, Method, MethodKind, PROTO_VERSION, PeerInfo, RequestId, RpcError,
    RpcNotification, ShepherdApi, negotiate,
};

use crate::dispatch::Session;
use crate::state::Daemon;

/// The handshake's method name. Deliberately not in the method table.
pub const HELLO_METHOD: &str = "hello";

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("cannot listen on {path}: {detail}")]
    Bind { path: String, detail: String },
}

/// Bind the listener, creating the directory and clearing a stale socket.
///
/// Three things that each cause a confusing failure if skipped:
///
/// * **the parent directory** may not exist on a first run;
/// * **a stale socket file** from a killed daemon makes `bind` fail with
///   `EADDRINUSE` even though nothing is listening. It is removed only after a
///   connect attempt proves nothing is there — blindly unlinking would let a
///   second daemon steal a live socket out from under the first;
/// * **the mode**, set before accepting, because it is the entire authorization
///   model.
pub fn bind(path: &Path) -> Result<UnixListener, ServerError> {
    let err = |detail: String| ServerError::Bind {
        path: path.display().to_string(),
        detail,
    };

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .map_err(|e| err(format!("cannot create {}: {e}", parent.display())))?;
        // The directory is the outer half of the permission story.
        let _ = std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700));
    }

    if path.exists() {
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(err(
                    "another shepherdd is already listening on this socket".into()
                ));
            }
            // Nothing answered: the file is a leftover from a killed daemon.
            Err(_) => {
                std::fs::remove_file(path)
                    .map_err(|e| err(format!("cannot clear the stale socket: {e}")))?;
            }
        }
    }

    let listener = UnixListener::bind(path).map_err(|e| err(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| err(format!("cannot set mode 0600: {e}")))?;
    Ok(listener)
}

/// Accept connections until `stop` is set.
pub fn serve(listener: UnixListener, daemon: Arc<Daemon>, stop: Arc<AtomicBool>) {
    // A short accept timeout so `stop` is noticed without a self-connect trick.
    listener
        .set_nonblocking(true)
        .expect("a Unix listener supports non-blocking mode");

    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                let daemon = Arc::clone(&daemon);
                if let Err(e) = std::thread::Builder::new()
                    .name("shepherd-conn".into())
                    .spawn(move || {
                        if let Err(e) = handle(stream, daemon) {
                            tracing::debug!(error = %e, "connection ended");
                        }
                    })
                {
                    tracing::warn!(error = %e, "could not spawn a connection thread");
                }
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
            Err(e) => tracing::warn!(error = %e, "accept failed"),
        }
    }
}

/// Serve one connection.
fn handle(stream: UnixStream, daemon: Arc<Daemon>) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    let reader = BufReader::new(stream.try_clone()?);
    // Shared because the event pump writes to the same socket as the responses.
    let writer = Arc::new(std::sync::Mutex::new(stream));

    let mut lines = reader.lines();

    // --- handshake --------------------------------------------------------
    let Some(first) = lines.next() else {
        return Ok(()); // connected and hung up
    };
    let first = first?;
    let negotiated = match handshake(&first, &daemon) {
        Ok((reply, negotiated)) => {
            write_frame(&writer, &reply)?;
            negotiated
        }
        Err(reply) => {
            write_frame(&writer, &reply)?;
            return Ok(());
        }
    };

    let mut session = Session {
        daemon: Arc::clone(&daemon),
        negotiated,
    };

    // --- requests ---------------------------------------------------------
    for line in lines {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        let response = serve_one(&line, &mut session, &writer);
        write_frame(&writer, &response)?;
    }
    Ok(())
}

fn handshake(
    line: &str,
    daemon: &Daemon,
) -> Result<(RpcResponse, shepherd_proto::Negotiated), RpcResponse> {
    let frame: RpcRequest = serde_json::from_str(line).map_err(|e| {
        RpcResponse::failed(
            None,
            RpcError::new(
                ErrorCode::InvalidRequest,
                format!("the first frame must be a JSON-RPC request: {e}"),
            ),
        )
    })?;

    if frame.method != HELLO_METHOD {
        return Err(RpcResponse::failed(
            Some(frame.id),
            RpcError::new(
                ErrorCode::InvalidRequest,
                format!(
                    "every connection must open with `{HELLO_METHOD}`; got `{}`. \
                     Until the handshake completes the protocol minor is unknown, so no \
                     method can be safely served.",
                    frame.method
                ),
            ),
        ));
    }

    let hello: Hello = serde_json::from_value(frame.params.clone()).map_err(|e| {
        RpcResponse::failed(
            Some(frame.id.clone()),
            RpcError::new(ErrorCode::InvalidParams, format!("`hello`: {e}")),
        )
    })?;

    match negotiate(&hello, PROTO_VERSION, &daemon.capabilities) {
        Ok(negotiated) => {
            let result = shepherd_proto::HelloResult {
                proto_version: PROTO_VERSION,
                server: PeerInfo {
                    name: "shepherdd".into(),
                    build: env!("CARGO_PKG_VERSION").into(),
                },
                capabilities: daemon.capabilities.clone(),
                negotiated: negotiated.clone(),
            };
            let value = serde_json::to_value(result).expect("HelloResult is serializable");
            Ok((RpcResponse::ok(frame.id, value), negotiated))
        }
        Err(mismatch) => Err(RpcResponse::failed(
            Some(frame.id),
            RpcError::new(ErrorCode::VersionMismatch, mismatch.to_string()).with_data(
                serde_json::to_value(&mismatch).expect("VersionMismatch is serializable"),
            ),
        )),
    }
}

/// Parse, gate, dispatch, and encode one request.
fn serve_one(
    line: &str,
    session: &mut Session,
    writer: &Arc<std::sync::Mutex<UnixStream>>,
) -> RpcResponse {
    let frame: RpcRequest = match serde_json::from_str(line) {
        Ok(f) => f,
        Err(e) => {
            return RpcResponse::failed(None, RpcError::new(ErrorCode::ParseError, e.to_string()));
        }
    };
    let id = frame.id.clone();

    // A method above the negotiated minor is reported as absent, not as
    // forbidden: from the caller's side "you are too old to see it" and "it
    // does not exist" are the same condition, and distinguishing them leaks the
    // newer surface to a client that cannot use it.
    if let Some(kind) = MethodKind::from_name(&frame.method)
        && !kind.available_at(session.negotiated.minor)
    {
        return RpcResponse::failed(
            Some(id),
            RpcError::new(
                ErrorCode::MethodNotFound,
                format!("no method named `{}`", frame.method),
            ),
        );
    }

    let call = match Method::from_parts(&frame.method, &frame.params) {
        Ok(c) => c,
        Err(e) => return RpcResponse::failed(Some(id), e),
    };

    // `events.subscribe` is the one method whose effect outlives the reply: it
    // installs a pump on this connection. Handled here rather than in
    // `dispatch` because only the connection owns its socket.
    if let Method::EventsSubscribe(req) = &call {
        return subscribe_on_connection(req.clone(), session, writer, id);
    }

    match session.dispatch(call) {
        Ok(result) => match result.to_value() {
            Ok(v) => RpcResponse::ok(id, v),
            Err(e) => RpcResponse::failed(Some(id), e),
        },
        Err(e) => RpcResponse::failed(Some(id), e),
    }
}

/// Register a subscription and start pumping frames to this socket.
fn subscribe_on_connection(
    req: shepherd_proto::SubscribeRequest,
    session: &Session,
    writer: &Arc<std::sync::Mutex<UnixStream>>,
    id: RequestId,
) -> RpcResponse {
    let (result, replay, rx) = session
        .daemon
        .events
        .subscribe(req.streams, req.resume_from, None);

    // Replay first, so the client sees missed frames before live ones and the
    // sequence it observes is monotonic.
    for frame in replay {
        if write_frame(writer, &RpcNotification::new(frame)).is_err() {
            break;
        }
    }

    let sink = Arc::clone(writer);
    let sub = result.subscription_id;
    if let Err(e) = std::thread::Builder::new()
        .name(format!("shepherd-events-{sub}"))
        .spawn(move || {
            // Ends when the hub drops the sender (daemon shutdown) or the
            // socket dies.
            for frame in rx {
                if write_frame(&sink, &RpcNotification::new(frame)).is_err() {
                    break;
                }
            }
        })
    {
        tracing::warn!(error = %e, "could not start the event pump");
        return RpcResponse::failed(
            Some(id),
            RpcError::new(ErrorCode::Busy, "could not start an event pump thread"),
        );
    }

    match serde_json::to_value(&result) {
        Ok(v) => RpcResponse::ok(id, v),
        Err(e) => RpcResponse::failed(
            Some(id),
            RpcError::new(ErrorCode::InternalError, e.to_string()),
        ),
    }
}

/// Write one newline-delimited frame, holding the socket lock for exactly as
/// long as the write.
fn write_frame<T: serde::Serialize>(
    writer: &Arc<std::sync::Mutex<UnixStream>>,
    value: &T,
) -> std::io::Result<()> {
    let mut line = serde_json::to_string(value).map_err(std::io::Error::other)?;
    line.push('\n');
    let mut guard = writer.lock().unwrap_or_else(|e| e.into_inner());
    guard.write_all(line.as_bytes())?;
    guard.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp_socket(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "shepherd-srv-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d.join("daemon.sock")
    }

    /// The whole authorization model, asserted.
    #[test]
    fn the_socket_is_owner_only_and_its_directory_is_created() {
        let path = tmp_socket("mode");
        let listener = bind(&path).unwrap();
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "socket mode is {mode:04o}");
        let dir_mode = std::fs::metadata(path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "socket directory mode is {dir_mode:04o}");
        drop(listener);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// A killed daemon leaves a socket file behind. Without this, every restart
    /// after a hard kill fails with EADDRINUSE and looks like a port conflict.
    #[test]
    fn a_stale_socket_file_is_cleared() {
        let path = tmp_socket("stale");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"not really a socket").unwrap();
        let listener = bind(&path).expect("a leftover file must not block startup");
        drop(listener);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// But a *live* socket must not be stolen: blindly unlinking would let a
    /// second daemon take over and leave the first writing to nothing.
    #[test]
    fn a_live_socket_is_not_stolen_by_a_second_daemon() {
        let path = tmp_socket("live");
        let first = bind(&path).unwrap();
        let err = bind(&path).unwrap_err();
        assert!(err.to_string().contains("already listening"), "{err}");
        drop(first);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
