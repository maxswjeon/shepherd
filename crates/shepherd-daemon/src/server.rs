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
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use shepherd_proto::request::RpcRequest;
use shepherd_proto::response::RpcResponse;
use shepherd_proto::{
    ErrorCode, Hello, MAX_FRAME_BYTES, Method, MethodKind, PROTO_VERSION, PeerInfo, RequestId,
    RpcError, RpcNotification, ShepherdApi, negotiate,
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

/// Name a file type for the refusal message, so the operator knows what is
/// in the way without having to `stat` it themselves.
fn describe_file_type(ft: std::fs::FileType) -> &'static str {
    use std::os::unix::fs::FileTypeExt;
    if ft.is_symlink() {
        "a symbolic link"
    } else if ft.is_dir() {
        "a directory"
    } else if ft.is_file() {
        "a regular file"
    } else if ft.is_fifo() {
        "a FIFO"
    } else if ft.is_block_device() || ft.is_char_device() {
        "a device node"
    } else {
        "not a socket"
    }
}

/// Bind the listener, creating the directory and clearing a stale socket.
///
/// Three things that each cause a confusing failure if skipped:
///
/// * **the parent directory** may not exist on a first run;
/// * **a stale socket file** from a killed daemon makes `bind` fail with
///   `EADDRINUSE` even though nothing is listening. It is removed only after
///   two things are true: the path is a socket node, and a connect attempt
///   proves nothing is there. Both are load-bearing — skipping the connect
///   would let a second daemon steal a live socket out from under the first,
///   and skipping the type check would delete whatever `SHEPHERD_SOCKET`
///   happened to name, because a regular file refuses connections too;
/// * **the mode**, set before accepting, because it is the entire authorization
///   model.
pub fn bind(path: &Path, lock_path: &Path) -> Result<Bound, ServerError> {
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

    // --- one daemon per socket, and the lock says so -----------------------
    //
    // Everything below inspects the socket node and then acts on what it saw,
    // which two starting daemons can interleave: both find the stale node, both
    // fail to connect, the first unlinks and binds, and the SECOND then unlinks
    // that live socket and binds its own. The first daemon goes on running,
    // unreachable, while both drive the same catalog and job queue — the worst
    // shape available, because the unreachable one is still doing work.
    //
    // Making the unlink conditional on the identity that was inspected narrows
    // the window and does not close it, and it says nothing about the catalog.
    // An advisory lock held for the listener's whole life does both: it is the
    // ordinary single-instance primitive, it covers the inspect-then-act
    // sequence as one critical section, and a second daemon is refused at
    // startup rather than after it has begun writing.
    //
    // In the STATE directory, which the caller names, and not beside the socket.
    // Two reasons, and the second is the one that decided it:
    //
    // * the deeper harm is two daemons on one CATALOG and one job queue, and
    //   the state directory is what that is; the socket is only how the loser
    //   is noticed;
    // * a lock file beside the socket is an ordinary file in whatever directory
    //   `SHEPHERD_SOCKET` points at, which can be inside a scan root — and then
    //   the daemon catalogues its own lock. The state directory is already
    //   refused as a root and excluded from every walk.
    let lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(lock_path)
        .map_err(|e| err(format!("cannot open {}: {e}", lock_path.display())))?;
    let _ = std::fs::set_permissions(lock_path, std::fs::Permissions::from_mode(0o600));
    lock.try_lock().map_err(|e| {
        err(format!(
            "another shepherdd already holds {} ({e}); two daemons on one socket would race \
             over it and then drive the same catalog",
            lock_path.display()
        ))
    })?;

    // `symlink_metadata`, not `exists`/`metadata`: a symlink here is not a
    // socket node we may unlink, and a dangling one makes `exists` answer false
    // while `bind` still fails with `EADDRINUSE`.
    if let Ok(md) = std::fs::symlink_metadata(path) {
        if !md.file_type().is_socket() {
            return Err(err(format!(
                "{} already exists and is not a socket ({}); \
                 refusing to delete it — remove it yourself or point the socket elsewhere",
                path.display(),
                describe_file_type(md.file_type()),
            )));
        }
        match UnixStream::connect(path) {
            Ok(_) => {
                return Err(err(
                    "another shepherdd is already listening on this socket".into()
                ));
            }
            // A socket node that answers nothing: a leftover from a killed daemon.
            Err(_) => {
                std::fs::remove_file(path)
                    .map_err(|e| err(format!("cannot clear the stale socket: {e}")))?;
            }
        }
    }

    let listener = UnixListener::bind(path).map_err(|e| err(e.to_string()))?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| err(format!("cannot set mode 0600: {e}")))?;
    Ok(Bound {
        listener,
        _lock: lock,
    })
}

/// A bound listener **and** the startup lock that makes it the only one.
///
/// The lock is a field rather than something the caller is asked to keep alive,
/// because "hold this for the process lifetime" is exactly the instruction a
/// caller forgets. Dropping this drops both together, which is also what makes
/// a test able to release ownership deterministically.
#[derive(Debug)]
pub struct Bound {
    pub listener: UnixListener,
    _lock: std::fs::File,
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

    let mut reader = reader;

    // --- handshake --------------------------------------------------------
    let first = match read_frame(&mut reader)? {
        Frame::Line(l) => l,
        Frame::Eof => return Ok(()), // connected and hung up
        Frame::TooLarge(n) => {
            write_frame(&writer, &oversized(n))?;
            return Ok(());
        }
    };
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
    loop {
        let line = match read_frame(&mut reader)? {
            Frame::Line(l) => l,
            Frame::Eof => break,
            // Not resynchronised: finding the next newline after an oversized
            // frame means reading the rest of it, which is the unbounded read
            // this exists to refuse. The peer is told why and the connection
            // ends.
            Frame::TooLarge(n) => {
                write_frame(&writer, &oversized(n))?;
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        // `None` means the frame is already on the socket. Only
        // `events.subscribe` answers that way, because only it has to write
        // more than one frame and has to write them in a fixed order.
        if let Some(response) = serve_one(&line, &mut session, &writer) {
            write_frame(&writer, &response)?;
        }
    }
    Ok(())
}

/// One frame, or why there is not one.
enum Frame {
    Line(String),
    Eof,
    /// At least this many bytes arrived with no newline among them.
    TooLarge(usize),
}

/// Read one newline-delimited frame, refusing to allocate past
/// [`MAX_FRAME_BYTES`].
///
/// `BufRead::lines` was the whole defect: it grows a `String` until it finds a
/// newline, so a peer that writes and never terminates a line makes the daemon
/// allocate without limit — per open connection. Authorization on this socket
/// is filesystem permissions, so the peer is the same user by construction, but
/// "same user" includes a buggy script, and the failure mode is the service
/// dying rather than answering `InvalidRequest`.
///
/// `take` bounds the read itself rather than checking a length afterwards,
/// which would be checking after the allocation it is meant to prevent.
fn read_frame(reader: &mut BufReader<UnixStream>) -> std::io::Result<Frame> {
    use std::io::Read;

    let mut buf = Vec::new();
    let n = reader
        .take((MAX_FRAME_BYTES + 1) as u64)
        .read_until(b'\n', &mut buf)?;

    if n == 0 {
        return Ok(Frame::Eof);
    }
    if buf.last() != Some(&b'\n') {
        // Either the cap was hit mid-frame, or the peer closed without a
        // trailing newline. The second is a well-formed final frame.
        if n > MAX_FRAME_BYTES {
            return Ok(Frame::TooLarge(n));
        }
    } else {
        buf.pop();
        if buf.last() == Some(&b'\r') {
            buf.pop();
        }
    }

    Ok(Frame::Line(String::from_utf8_lossy(&buf).into_owned()))
}

/// The refusal a peer gets instead of an out-of-memory daemon.
fn oversized(n: usize) -> RpcResponse {
    RpcResponse::failed(
        None,
        RpcError::new(
            ErrorCode::InvalidRequest,
            format!(
                "a frame exceeded the {MAX_FRAME_BYTES}-byte protocol maximum ({n} bytes read \
                 with no newline); the connection is closed rather than resynchronised"
            ),
        ),
    )
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

    // Taken apart once. Each part then has exactly one owner, so the id and
    // the params reach the arms that consume them by move — every arm below
    // either returns or is the last reader of what it names.
    let RpcRequest {
        id, method, params, ..
    } = frame;

    if method != HELLO_METHOD {
        return Err(RpcResponse::failed(
            Some(id),
            RpcError::new(
                ErrorCode::InvalidRequest,
                format!(
                    "every connection must open with `{HELLO_METHOD}`; got `{method}`. \
                     Until the handshake completes the protocol minor is unknown, so no \
                     method can be safely served."
                ),
            ),
        ));
    }

    // `match` rather than `map_err`: a closure would have to *borrow* `id`,
    // which the success path below still owns, and borrowing it there is the
    // only reason it used to be cloned.
    let hello: Hello = match serde_json::from_value(params) {
        Ok(h) => h,
        Err(e) => {
            return Err(RpcResponse::failed(
                Some(id),
                RpcError::new(ErrorCode::InvalidParams, format!("`hello`: {e}")),
            ));
        }
    };

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
            Ok((RpcResponse::ok(id, value), negotiated))
        }
        Err(mismatch) => Err(RpcResponse::failed(
            Some(id),
            RpcError::new(ErrorCode::VersionMismatch, mismatch.to_string()).with_data(
                serde_json::to_value(&mismatch).expect("VersionMismatch is serializable"),
            ),
        )),
    }
}

/// Parse, gate, dispatch, and encode one request.
///
/// `Some` is a frame for the caller to write. `None` means this request has
/// already written its own reply — see [`subscribe_on_connection`], which is
/// the only method that does.
fn serve_one(
    line: &str,
    session: &mut Session,
    writer: &Arc<std::sync::Mutex<UnixStream>>,
) -> Option<RpcResponse> {
    let frame: RpcRequest = match serde_json::from_str(line) {
        Ok(f) => f,
        Err(e) => {
            return Some(RpcResponse::failed(
                None,
                RpcError::new(ErrorCode::ParseError, e.to_string()),
            ));
        }
    };
    // Taken apart once, on the per-request path: exactly one arm below answers,
    // and each moves the id into its own reply rather than every request paying
    // for a copy of one so the later arms can still see it.
    let RpcRequest {
        id, method, params, ..
    } = frame;

    // A method above the negotiated minor is reported as absent, not as
    // forbidden: from the caller's side "you are too old to see it" and "it
    // does not exist" are the same condition, and distinguishing them leaks the
    // newer surface to a client that cannot use it.
    if let Some(kind) = MethodKind::from_name(&method)
        && !kind.available_at(session.negotiated.minor)
    {
        return Some(RpcResponse::failed(
            Some(id),
            RpcError::new(
                ErrorCode::MethodNotFound,
                format!("no method named `{method}`"),
            ),
        ));
    }

    let call = match Method::from_parts(&method, &params) {
        Ok(c) => c,
        Err(e) => return Some(RpcResponse::failed(Some(id), e)),
    };

    // `events.subscribe` is the one method whose effect outlives the reply: it
    // installs a pump on this connection. Handled here rather than in
    // `dispatch` because only the connection owns its socket.
    //
    // Matched by value: the subscribe arm consumes the request, and the rest of
    // the table is handed straight back to `dispatch` untouched.
    let call = match call {
        Method::EventsSubscribe(req) => {
            return subscribe_on_connection(req, session, writer, id);
        }
        other => other,
    };

    Some(match session.dispatch(call) {
        Ok(result) => match result.to_value() {
            Ok(v) => RpcResponse::ok(id, v),
            Err(e) => RpcResponse::failed(Some(id), e),
        },
        Err(e) => RpcResponse::failed(Some(id), e),
    })
}

/// Register a subscription and start pumping frames to this socket.
///
/// # The response frame goes out first, and the pump is held until it has
///
/// `events.subscribe` is answered by an ordinary `RpcResponse`, and a client
/// reads the very next frame and parses it as one — `shepctl events subscribe`
/// reaches the daemon through `client::call`, which does exactly that and
/// nothing else. So a notification arriving first is not an out-of-order event;
/// it is a protocol error on a subscription that was otherwise perfectly fine,
/// and the client never learns its subscription id. Replay made that the
/// **normal** outcome for every `resume_from`, not a race: the loop that wrote
/// the buffered frames ran before this function had returned anything for
/// `handle` to write.
///
/// Hence the order below, which is the whole of the fix:
///
/// 1. **register**, so no event published from this instant on is missed;
/// 2. **write the response**, before any notification can reach the socket;
/// 3. **replay**, so the sequence the client observes is monotonic from its
///    cursor;
/// 4. **release the pump**, and only then does live delivery begin.
///
/// The pump thread is spawned in step 1 parked on `go_rx` rather than spawned
/// last, so a thread-spawn failure is still answerable: the client is told
/// `Busy` instead of being told it is subscribed to a pump that does not exist.
/// Dropping `go_tx` on any early return unparks it into a `RecvError`, it
/// returns, `rx` drops, and the hub reaps the subscriber on its next publish.
fn subscribe_on_connection(
    req: shepherd_proto::SubscribeRequest,
    session: &Session,
    writer: &Arc<std::sync::Mutex<UnixStream>>,
    id: RequestId,
) -> Option<RpcResponse> {
    let (result, replay, rx, overflowed) = session.daemon.events.subscribe(
        req.streams,
        req.resume_from,
        // A cursor without the epoch it was issued under cannot be told from a
        // cursor issued by a previous run, whose numbers start over at 1. The
        // hub's `EpochChanged` branch was unreachable while this was `None`.
        req.resume_epoch.as_deref(),
    );

    // Serialized before the spawn, deliberately — a result that cannot be
    // encoded must not leave a pump thread behind. Only the *value* is built
    // here; the reply frame that owns the id is assembled after the spawn, so
    // the two failure arms below can still answer with that id and it never
    // has to be copied for them.
    let value = match serde_json::to_value(&result) {
        Ok(v) => v,
        Err(e) => {
            return Some(RpcResponse::failed(
                Some(id),
                RpcError::new(ErrorCode::InternalError, e.to_string()),
            ));
        }
    };

    let (go_tx, go_rx) = std::sync::mpsc::channel::<()>();
    let sink = Arc::clone(writer);
    let sub = result.subscription_id;
    if let Err(e) = std::thread::Builder::new()
        .name(format!("shepherd-events-{sub}"))
        .spawn(move || {
            // Parked until the response and the replay are on the socket. An
            // `Err` means that never happened, so there is nothing to pump.
            if go_rx.recv().is_err() {
                return;
            }
            pump_events(rx, &overflowed, &sink, sub);
        })
    {
        tracing::warn!(error = %e, "could not start the event pump");
        return Some(RpcResponse::failed(
            Some(id),
            RpcError::new(ErrorCode::Busy, "could not start an event pump thread"),
        ));
    }

    // The pump is parked on `go_rx` and nothing has reached the socket yet, so
    // building the frame here rather than above changes only who owns the id —
    // step 2 of the ordering in the doc comment still happens next.
    let response = RpcResponse::ok(id, value);
    if write_frame(writer, &response).is_err() {
        return None;
    }
    for frame in replay {
        if write_frame(writer, &RpcNotification::new(frame)).is_err() {
            return None;
        }
    }
    let _ = go_tx.send(());
    None
}

/// Drain one subscription onto its socket, and shut the socket down if the
/// subscription was cut off for falling behind.
///
/// # Why EOF, and not another dropped frame
///
/// The loop ends for one of three reasons: the hub dropped the sender (daemon
/// shutdown), the socket died, or this subscriber overflowed its queue and the
/// hub unregistered it. The first two need nothing from us. The third is the
/// one the client has to be told about, and `overflowed` is the only thing that
/// distinguishes it — all three arrive here as a closed channel.
///
/// It used to be told nothing: the hub dropped frames and kept the subscription
/// alive, on the reasoning that the client would notice the sequence gap. For a
/// filtered subscription it cannot — sequence numbers are global, so gaps from
/// streams it did not request are normal — and if the burst ends after the drop
/// there may be no later frame to reveal one anyway. Shutting the socket turns
/// an ambiguity the client cannot resolve into an EOF it cannot miss.
///
/// The queued frames are written first, deliberately. They are frames the
/// client is entitled to, and delivering them narrows the gap it has to resume
/// across — at the default buffer capacity, often to nothing.
fn pump_events(
    rx: std::sync::mpsc::Receiver<shepherd_proto::event::EventFrame>,
    overflowed: &AtomicBool,
    sink: &Arc<std::sync::Mutex<UnixStream>>,
    sub: u64,
) {
    for frame in rx {
        if write_frame(sink, &RpcNotification::new(frame)).is_err() {
            // The socket is already gone; there is nothing to shut down and
            // nothing to tell anyone.
            return;
        }
    }
    if overflowed.load(Ordering::SeqCst) {
        tracing::warn!(
            subscription = sub,
            "closing this connection: the subscriber fell behind its {} frame queue. It \
             should resume with its cursor.",
            crate::events::SUBSCRIBER_QUEUE
        );
        // One last frame, BEFORE the shutdown, saying why.
        //
        // Closing the socket was already the signal — and it is not a
        // sufficient one, because a daemon shutting down closes the socket too.
        // A client could not tell "frames were dropped, resume" from "the
        // daemon stopped", so `shepctl events subscribe` reported a subscription
        // that had lost events as a clean exit. Best-effort: if this write
        // fails the peer is already gone, and the shutdown below is still the
        // right end.
        let _ = write_frame(
            sink,
            &shepherd_proto::DroppedNotification::queue_overflow(
                sub,
                crate::events::SUBSCRIBER_QUEUE as u64,
            ),
        );
        let guard = sink.lock().unwrap_or_else(|e| e.into_inner());
        let _ = guard.shutdown(std::net::Shutdown::Both);
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

    /// `bind` will not delete something that is not a socket.
    ///
    /// The unlink exists for one case: a socket node left behind by a killed
    /// daemon. `connect` failing does not prove the path *is* that — a regular
    /// file never accepts a connection either, so a mistyped `SHEPHERD_SOCKET`
    /// pointing at a document took the same branch and destroyed it.
    ///
    /// The assertion is on the **bytes still being there**, not on the error:
    /// `bind` returning `Err` was already true before the fix, after the file
    /// had been removed.
    #[test]
    fn bind_refuses_to_unlink_a_non_socket_path() {
        let path = tmp_socket("nonsock");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"a document the user cares about").unwrap();

        let e = bind(&path, &path.with_extension("lock"))
            .expect_err("a regular file is not a stale socket");

        assert_eq!(
            std::fs::read(&path).ok().as_deref(),
            Some(&b"a document the user cares about"[..]),
            "bind deleted a non-socket path: {e}"
        );
    }

    /// A client whose subscription overflows **observes** the disconnect.
    ///
    /// This is the half that makes the fix worth anything. The hub unregistering
    /// a subscriber is invisible from the far side of the socket; what the
    /// client can act on is EOF. So this drives a real `UnixStream` pair and
    /// reads from the client end, exactly as `shepctl events subscribe` does —
    /// asserting on what a client sees, not on a flag the daemon set.
    ///
    /// The frames still queued are delivered before the close, because they are
    /// frames the client is entitled to and they shorten the resume it now has
    /// to perform.
    #[test]
    fn an_overflowing_subscriber_sees_its_connection_close() {
        use crate::events::{EventHub, SUBSCRIBER_QUEUE};
        use shepherd_proto::event::{EventPayload, EventStream};

        let (daemon_side, client_side) = UnixStream::pair().expect("socketpair");
        client_side
            .set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();

        let hub = EventHub::new(4096, "e1");
        let (_, _, rx, overflowed) = hub.subscribe(vec![], None, None);

        // Nothing drains `rx`, so this overflows the queue and the hub drops
        // the subscription.
        for i in 0..(SUBSCRIBER_QUEUE as u64 + 50) {
            hub.publish(
                EventStream::Scan,
                EventPayload::ScanProgress {
                    root_id: 1,
                    files_seen: i,
                    bytes_seen: i,
                    current_path: None,
                    done: false,
                },
            );
        }
        assert!(
            overflowed.load(Ordering::SeqCst),
            "the queue must have overflowed"
        );

        let sink = Arc::new(std::sync::Mutex::new(daemon_side));
        let pump_sink = Arc::clone(&sink);
        let pump = std::thread::spawn(move || pump_events(rx, &overflowed, &pump_sink, 7));

        // What the client sees: some frames, then a notification saying it was
        // dropped, then end of stream.
        let mut reader = BufReader::new(client_side);
        let mut frames = 0;
        let mut dropped: Option<serde_json::Value> = None;
        loop {
            let mut line = String::new();
            let n = reader.read_line(&mut line).expect("read");
            if n == 0 {
                break; // EOF — the signal the whole change exists to produce.
            }
            let v: serde_json::Value = serde_json::from_str(&line).expect("a JSON frame");
            if v["method"] == serde_json::json!(shepherd_proto::SUBSCRIPTION_DROPPED_METHOD) {
                dropped = Some(v);
                continue;
            }
            assert_eq!(v["method"], serde_json::json!("event"), "{line}");
            assert!(
                dropped.is_none(),
                "an event arrived after the drop notification: {line}"
            );
            frames += 1;
        }
        pump.join().unwrap();

        assert!(
            frames > 0,
            "the frames already queued are owed to the client and must be delivered first"
        );
        assert_eq!(
            frames, SUBSCRIBER_QUEUE,
            "exactly the queued frames, then the close"
        );

        // EOF alone cannot carry the reason: a daemon SHUTTING DOWN closes the
        // socket too, so a client that saw only the close reported a
        // subscription that had lost events as a clean exit. The last frame is
        // what tells the two apart.
        let dropped = dropped.expect(
            "the subscriber must be TOLD it was dropped, not merely disconnected — otherwise \
             this is indistinguishable from the daemon shutting down",
        );
        assert_eq!(
            dropped["params"]["reason"],
            serde_json::json!("queue_overflow")
        );
        assert_eq!(dropped["params"]["subscription_id"], serde_json::json!(7));
        assert_eq!(
            dropped["params"]["queue_capacity"],
            serde_json::json!(SUBSCRIBER_QUEUE as u64)
        );
    }

    /// The accepting direction: an ordinary end-of-stream does NOT close the
    /// socket.
    ///
    /// A pump that shut the connection down every time its channel closed would
    /// satisfy the test above and break every clean daemon shutdown — the
    /// connection is shared with request/response traffic, so tearing it down
    /// would kill in-flight calls that have nothing to do with events. Here the
    /// hub is dropped without any overflow, and the socket must survive it.
    #[test]
    fn an_ordinary_end_of_stream_leaves_the_connection_open() {
        use crate::events::EventHub;
        use shepherd_proto::event::{EventPayload, EventStream};

        let (daemon_side, client_side) = UnixStream::pair().expect("socketpair");
        client_side
            .set_read_timeout(Some(std::time::Duration::from_secs(20)))
            .unwrap();

        let hub = EventHub::new(4096, "e1");
        let (_, _, rx, overflowed) = hub.subscribe(vec![], None, None);
        hub.publish(
            EventStream::Scan,
            EventPayload::ScanProgress {
                root_id: 1,
                files_seen: 1,
                bytes_seen: 1,
                current_path: None,
                done: false,
            },
        );
        // Daemon shutdown: the sender goes, the pump's loop ends, and nothing
        // overflowed.
        drop(hub);

        let sink = Arc::new(std::sync::Mutex::new(daemon_side));
        let pump_sink = Arc::clone(&sink);
        let pump = std::thread::spawn(move || pump_events(rx, &overflowed, &pump_sink, 7));
        pump.join().unwrap();

        // The socket was not shut down, so this connection can still carry the
        // request/response traffic it shares with the event stream.
        let wrote = sink.lock().unwrap().write_all(b"{\"still\":\"here\"}\n");
        assert!(
            wrote.is_ok(),
            "a clean end-of-stream must not tear down the connection: {wrote:?}"
        );

        let mut reader = BufReader::new(client_side);
        let mut first = String::new();
        reader.read_line(&mut first).expect("read");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&first).unwrap()["method"],
            serde_json::json!("event"),
            "{first}"
        );
        let mut second = String::new();
        reader.read_line(&mut second).expect("read");
        assert!(
            second.contains("still"),
            "the socket is still usable: {second:?}"
        );
    }

    /// The whole authorization model, asserted.
    #[test]
    fn the_socket_is_owner_only_and_its_directory_is_created() {
        let path = tmp_socket("mode");
        let listener = bind(&path, &path.with_extension("lock")).unwrap();
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
    ///
    /// The leftover is made the way a kill makes one — bind a listener and drop
    /// it, which closes the fd but leaves the socket **node** on disk. It used
    /// to be a `write` of ordinary bytes, which passed for the wrong reason:
    /// the code could not tell that from a document, and neither could this.
    #[test]
    fn a_stale_socket_file_is_cleared() {
        let path = tmp_socket("stale");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        drop(UnixListener::bind(&path).expect("bind the socket a killed daemon left"));
        assert!(path.exists(), "dropping a listener leaves the node behind");

        let listener = bind(&path, &path.with_extension("lock"))
            .expect("a stale socket must not block startup");
        drop(listener);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// But a *live* socket must not be stolen: blindly unlinking would let a
    /// second daemon take over and leave the first writing to nothing.
    ///
    /// Asserted on the PROPERTY rather than on the message. Two refusals now
    /// stand between a second daemon and this socket — the startup lock, and
    /// the connect probe behind it — and which one fires first is an
    /// implementation detail; that the first daemon still owns a working socket
    /// afterwards is not.
    #[test]
    fn a_live_socket_is_not_stolen_by_a_second_daemon() {
        let path = tmp_socket("live");
        let first = bind(&path, &path.with_extension("lock")).unwrap();

        let err = bind(&path, &path.with_extension("lock")).unwrap_err();

        // The first daemon is still reachable at the same socket.
        UnixStream::connect(&path).expect("the first daemon's socket must still accept: {err}");
        let _ = &err;
        drop(first);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }

    /// Two daemons racing over a STALE socket cannot both win.
    ///
    /// This is the case the connect probe alone could not cover: both starts
    /// find the leftover node, both fail to connect, the first unlinks and
    /// binds — and the second then unlinks that live socket and binds its own.
    /// The first goes on running, unreachable, while both drive the same
    /// catalog and job queue.
    ///
    /// The lock is what serializes it, so the assertion is that the loser is
    /// refused and the winner still owns the socket — and then that the socket
    /// is re-bindable once the winner releases, or every restart would be
    /// refused by the previous run's lock file.
    #[test]
    fn two_daemons_racing_over_a_stale_socket_cannot_both_bind() {
        let path = tmp_socket("race");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        // A stale node, exactly as a killed daemon leaves one.
        drop(UnixListener::bind(&path).expect("seed a stale socket"));

        // The other daemon is represented by the lock it holds, not by a second
        // `bind` — and that is the point. A second `bind` here would find a
        // LIVE socket and be turned away by the connect probe, which is the
        // check that already worked; the race this closes is the interval where
        // the socket is still stale for BOTH starts, and only the lock covers
        // it. Holding the lock directly is how that interval is made
        // observable without two processes and a scheduler.
        let other_daemon = std::fs::OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(path.with_extension("lock"))
            .expect("open the lock the way `bind` does");
        other_daemon.try_lock().expect("and hold it");

        let err = bind(&path, &path.with_extension("lock")).expect_err(
            "a second daemon bound a socket that was still stale for both of them; the first \
             is now unreachable while both drive the same catalog",
        );
        assert!(
            err.to_string().contains("already holds"),
            "the refusal must name the lock, not the socket: {err}"
        );

        // The lock is advisory and released with the holder, so an ordinary
        // restart is not blocked by the file the previous run left behind.
        //
        // `unlock` then drop, rather than relying on drop alone: the release
        // has to have happened before the next `bind`, and making it explicit
        // removes the question from a test that would otherwise fail
        // intermittently and be read as a product flake.
        other_daemon.unlock().expect("release the lock");
        drop(other_daemon);
        let restarted = bind(&path, &path.with_extension("lock"))
            .expect("a restart after a clean stop must not be refused");
        UnixStream::connect(&path).expect("and it really is listening");
        drop(restarted);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
