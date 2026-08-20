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

/// The socket's directory must be owner-only and OURS, or there is no
/// authorization model.
///
/// §4.3 says it plainly: "Authorization is filesystem/pipe permissions only".
/// The socket being `0600` is half of it; the other half is that nobody else
/// can unlink the name and put their own listener there. A `let _ =` on the
/// chmod threw that half away — point `SHEPHERD_SOCKET` at an existing
/// group-writable directory owned by someone else and the daemon happily binds
/// inside it, after which any member of that group can replace the socket and
/// impersonate the daemon to every later client.
///
/// So the mode is ENFORCED, and ownership is checked rather than assumed:
/// `chmod` succeeding proves we own the directory on Linux, but a directory we
/// own with a mode we could not tighten, or one owned by someone else, are both
/// refusals rather than warnings. A refusal here costs the operator one
/// `SHEPHERD_SOCKET` change; not refusing costs the whole trust boundary.
fn secure_socket_dir(dir: &Path) -> std::result::Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt};

    // `geteuid`, not `/proc/self`. `/proc` is Linux, this module is `cfg(unix)`,
    // and a missing `/proc` made the lookup return `None` — which SKIPPED the
    // ownership check entirely on macOS. Root binding inside another user's
    // existing `0700` directory then passed both remaining tests, and that user
    // could unlink the socket and answer privileged clients in its place. An
    // authorization check that disables itself where it cannot read a Linux
    // filesystem is worse than one that is absent, because the code reads as
    // though it is present.
    //
    // SAFETY: `geteuid` is infallible per POSIX — no error return, no memory
    // touched. Same call `secure_state_dir` already makes.
    let me = unsafe { libc::geteuid() };

    // Every ANCESTOR, not only the leaf — and BEFORE anything is created, so a
    // path this refuses is left exactly as it was found.
    //
    // The leaf checks below describe the directory the pathname resolves to
    // today. An ancestor a third party can REPLACE defeats all of them: swap
    // `/srv/run` for a directory holding the attacker's socket and clients,
    // which follow the CONFIGURED path, reach them while the leaf this
    // validated is still ours and still `0700`.
    //
    // Round 29 refused any symlinked ancestor outright, which was both too
    // strict and not the property: it made the daemon unstartable on macOS,
    // where `$TMPDIR` and `/tmp` alike sit under `/var -> private/var`, while
    // still permitting a world-writable ancestor that anyone could rename. Who
    // OWNS a link never mattered as much as who can replace it — so both walks
    // ask the one question that does, and a link only we or root can repoint is
    // no weaker than a directory only we or root can rename.
    //
    // Two walks, because either alone has a hole: the configured path judges
    // each symlink by the link itself, and the resolved path covers the
    // directories ABOVE a link's target, which the first walk never names.
    // `canonicalize` needs the path to exist, so it runs on the deepest
    // existing ancestor; nothing below that exists to be substituted yet.
    check_ancestry(dir, me)?;
    let mut deepest = dir;
    while std::fs::symlink_metadata(deepest).is_err() {
        match deepest.parent() {
            Some(p) => deepest = p,
            None => break,
        }
    }
    if let Ok(real) = deepest.canonicalize()
        && real != deepest
    {
        check_ancestry(&real, me)?;
    }

    // CREATE owner-only, or VERIFY — never seize.
    //
    // This used to `chmod 0700` whatever the socket's parent happened to be,
    // and the checks below then passed because the chmod had just made them
    // pass. Point `SHEPHERD_SOCKET` at `/run/shepherd.sock` or
    // `/tmp/shepherd.sock` as root and the daemon locked every other user and
    // service out of `/run` or `/tmp` — the override names a socket FILE, not a
    // directory Shepherd may take over.
    //
    // So the mode is only ever applied to a directory this call creates, where
    // "ours" is true by construction. `DirBuilder` applies it to every level it
    // makes, so an intermediate is never briefly world-readable either. An
    // existing directory is checked and, if it does not already meet the bar,
    // REFUSED with the remedy named: §4.3's own layout is a dedicated
    // `shepherd/` child, which this will happily create.
    let existing = std::fs::symlink_metadata(dir);
    match &existing {
        Ok(md) if md.is_dir() => {}
        Ok(md) => {
            return Err(format!(
                "{} is {} and cannot host the socket",
                dir.display(),
                describe_file_type(md.file_type())
            ));
        }
        Err(_) => {
            std::fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)
                .map_err(|e| format!("cannot create {} as owner-only: {e}", dir.display()))?;
        }
    }

    let md = std::fs::metadata(dir).map_err(|e| format!("cannot stat {}: {e}", dir.display()))?;
    if md.uid() != me {
        return Err(format!(
            "{} is owned by uid {} and this daemon runs as {me}; the socket's directory must \
             be ours, or another user can unlink the socket and answer in its place",
            dir.display(),
            md.uid()
        ));
    }
    let mode = md.permissions().mode() & 0o777;
    if mode != 0o700 {
        return Err(format!(
            "{} is mode {mode:04o}, and the socket's directory must be owner-only — anyone \
             who can write it can unlink the socket and answer in its place. This daemon \
             will NOT chmod a directory it did not create: doing that to `/run` or `/tmp` \
             locks out every other user on the machine. Point `SHEPHERD_SOCKET` at a file \
             inside a dedicated directory, which will be created `0700`, or tighten this one \
             yourself",
            dir.display()
        ));
    }
    Ok(())
}

/// Refuse a path any account but this daemon or root could re-point.
///
/// Asked of every component, of both the configured path and the path it
/// resolves to. Two conditions, and the second is what lets the first stay
/// narrow:
///
/// * **Owner** — a component owned by a third party is one they can replace,
///   whatever it currently points at. `symlink_metadata` deliberately does not
///   follow: for a symlink the question is who owns the LINK, since that is
///   what gets repointed.
/// * **Writability** — a directory anyone may write is one anyone may rename
///   entries in, so ownership of the entry stops mattering. The sticky bit is
///   the exception and the reason `/tmp` and `/var/folders` are usable at all:
///   with it set, only an entry's owner may remove or rename it.
///
/// WORLD-writable, deliberately, and not group-writable. `o+w` is the
/// unambiguous one: it names every account on the machine. `g+w` names a set
/// the operator chose, and on the dominant Linux layout — a per-user primary
/// group under umask 002 — that set is the owner alone, which is why an
/// ordinary `$HOME` tree is `0775` all the way down. Refusing that would have
/// traded a rule that made the daemon unstartable on macOS for one that makes
/// it unstartable on Ubuntu, and this check caught exactly that in CI. Whether
/// a given group has other members is not answerable from a `stat` — primary
/// memberships never appear in `gr_mem` — so the residual is left to the
/// operator and to #3's `openat`, rather than guessed at.
///
/// The residual is unchanged and is issue #3's `openat` work: a component we
/// ourselves own can still move between this check and the bind. Nobody else
/// can move it, which is what this buys.
fn check_ancestry(path: &Path, me: u32) -> std::result::Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let mut walked = std::path::PathBuf::new();
    for part in path.components() {
        walked.push(part);
        // A component that does not exist yet cannot be the one in the way,
        // and will be created `0700` by us.
        let Ok(md) = std::fs::symlink_metadata(&walked) else {
            continue;
        };
        if md.uid() != me && md.uid() != 0 {
            return Err(format!(
                "{} is owned by uid {} on the way to the socket directory, and neither this \
                 daemon ({me}) nor root. An account that can replace a component of this path \
                 can move the socket out from under every client that follows it",
                walked.display(),
                md.uid()
            ));
        }
        let mode = md.mode() & 0o7777;
        if md.is_dir() && mode & 0o002 != 0 && mode & 0o1000 == 0 {
            return Err(format!(
                "{} is mode {mode:04o} on the way to the socket directory: world-writable and \
                 not sticky, so any account may rename what is inside it and put their own \
                 socket at this path. Either set the sticky bit on it, as `/tmp` has, or point \
                 `SHEPHERD_SOCKET` somewhere only this daemon and root can write",
                walked.display()
            ));
        }
    }
    Ok(())
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

/// Subscriptions one connection may hold at once.
///
/// Each costs an OS thread and a bounded channel for the connection's life, so
/// this is a resource bound rather than a policy. Generous against real use:
/// `events.subscribe` takes a LIST of streams, so a client wanting everything
/// needs one subscription, not six — and there are only six streams to ask for.
const MAX_SUBSCRIPTIONS_PER_CONNECTION: usize = 8;

/// Take the state directory's singleton lock.
///
/// # Before the catalog is opened, not after
///
/// This used to happen inside [`bind`], which runs at the END of start-up —
/// after the catalog is open and after crash recovery has already rewritten
/// job rows. A second `shepherdd` started while the first had a live scan
/// therefore read that legitimate `running` row as crash-stranded and requeued
/// it, and only then reached `bind` and lost the lock. The first daemon's
/// workers could claim a second copy of a job whose executor was still
/// running: two concurrent scans of one root, and one attempts budget spent
/// twice.
///
/// So the lock is what the caller takes FIRST, and everything touching the
/// shared catalog happens underneath it. `bind` receives the held file rather
/// than a path, which makes the ordering a type rather than a convention —
/// there is no way to bind without having taken it.
pub fn lock_state_dir(lock_path: &Path) -> Result<std::fs::File, ServerError> {
    let err = |detail: String| ServerError::Bind {
        path: lock_path.display().to_string(),
        detail,
    };
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
            "another shepherdd already holds {} ({e}); two daemons on one catalog would \
             recover each other's live jobs and then race over the socket",
            lock_path.display()
        ))
    })?;
    Ok(lock)
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
pub fn bind(path: &Path, state_lock: std::fs::File) -> Result<Bound, ServerError> {
    let err = |detail: String| ServerError::Bind {
        path: path.display().to_string(),
        detail,
    };

    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        // Creation happens INSIDE `secure_socket_dir`, so a directory this
        // daemon makes is `0700` from its first instant rather than created and
        // then tightened.
        secure_socket_dir(parent).map_err(err)?;
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
    // TWO locks, because there are two resources and one lock cannot key both.
    //
    // The state lock (below) is keyed by the caller's state directory and
    // protects the catalog and the job queue — the deeper harm, and the one
    // that outlives the socket. But two daemons started with DIFFERENT
    // `SHEPHERD_STATE_DIR` values can still resolve to the SAME socket through
    // one `XDG_RUNTIME_DIR`, and they then take different state locks and race
    // over the socket exactly as before: both find the stale node, both fail to
    // connect, and the second unlinks the listener the first just bound.
    //
    // So the socket is locked too, by a file named for the socket itself:
    // `daemon.sock` is guarded by `daemon.sock.lock` beside it. Every process
    // resolving to that socket path resolves to that lock path, whatever state
    // directory it was started with, which is exactly the set that must not
    // overlap.
    //
    // Keyed by the socket PATH, not by its directory. The directory was the
    // first shape of this and it is too coarse: `$XDG_RUNTIME_DIR/shepherd/`
    // holding both a system socket and a second instance's is a legitimate
    // arrangement, and a directory-granular lock refuses the second for a
    // conflict that does not exist. It also put an `flock` on a directory
    // descriptor, which is odd enough territory that it produced an
    // intermittent failure in this crate's own tests.
    //
    // The cost is one small file in whatever directory `SHEPHERD_SOCKET` names,
    // and that directory can sit inside a scan root — the socket itself is
    // invisible to the walk only because it is not a regular file, and this
    // is. So it is denied by path where the state directory already is, in
    // `scan_exec` — which compiles on every platform while this module does
    // not, so both sides name it through `shepherd_obs::paths`.
    //
    // Non-blocking on both locks, so the ordering cannot deadlock — a loser is
    // refused rather than parked.
    let socket_lock_path = shepherd_obs::paths::socket_lock_path(path);
    let socket_lock = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .write(true)
        .truncate(false)
        .open(&socket_lock_path)
        .map_err(|e| err(format!("cannot open {}: {e}", socket_lock_path.display())))?;
    let _ = std::fs::set_permissions(&socket_lock_path, std::fs::Permissions::from_mode(0o600));
    socket_lock.try_lock().map_err(|e| {
        err(format!(
            "another shepherdd already holds the socket lock {} ({e}); two daemons on one \
             socket would race over it",
            socket_lock_path.display()
        ))
    })?;

    // The state lock is taken by the CALLER, before the catalog is opened —
    // see [`lock_state_dir`]. It arrives here already held and is moved into
    // `Bound` so the listener keeps it for the daemon's life.
    let lock = state_lock;

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
        _socket_lock: socket_lock,
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
    /// The state directory's lock: one daemon per catalog and job queue.
    _lock: std::fs::File,
    /// The socket's own lock, `<socket>.lock`: one daemon per socket, whatever
    /// state directory each was started with.
    ///
    /// Never unlinked, including on shutdown — removing a lock file while
    /// another process may be about to open it is how a lock stops locking.
    /// It is an empty file whose only content is the flock on it.
    _socket_lock: std::fs::File,
}

/// Connections served at once.
///
/// Each is an OS thread blocked on `read_frame`, and nothing else bounded them:
/// a same-user process that connects repeatedly and never completes the
/// handshake parked one thread per socket until the daemon ran out, and no
/// legitimate client could connect. The per-connection subscription cap does
/// not reach this path — it is reached only by a connection that got as far as
/// subscribing.
///
/// Generous: §4.2 makes this a per-user agent, so the real population is a few
/// CLI invocations and a UI. What it bounds is a loop.
const MAX_CONNECTIONS: usize = 64;

/// How long a connection may take to send its `hello`.
///
/// The handshake is the first frame on a socket that has just been accepted, so
/// this is a bound on doing nothing rather than on being slow. Without it a
/// connection that never speaks holds its thread for the daemon's life, which
/// is the cheapest way to spend the budget above.
const HANDSHAKE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Accept connections until `stop` is set.
pub fn serve(listener: UnixListener, daemon: Arc<Daemon>, stop: Arc<AtomicBool>) {
    // A short accept timeout so `stop` is noticed without a self-connect trick.
    listener
        .set_nonblocking(true)
        .expect("a Unix listener supports non-blocking mode");

    let live = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    while !stop.load(Ordering::SeqCst) {
        match listener.accept() {
            Ok((stream, _)) => {
                // Counted BEFORE the thread exists, and released by the guard
                // when `handle` returns however it returns. A count taken
                // inside the thread would be a bound the spawn had already
                // exceeded.
                let Some(slot) = ConnectionSlot::take(&live) else {
                    tracing::warn!(
                        live = MAX_CONNECTIONS,
                        "refusing a connection: the daemon is already serving its limit. \
                         A client that connects without completing the handshake holds a \
                         thread until it does, so this bounds that rather than the work"
                    );
                    // Dropped, which closes the socket. The client sees EOF
                    // rather than a silent hang, which is the difference
                    // between a refusal and a leak.
                    drop(stream);
                    continue;
                };
                let daemon = Arc::clone(&daemon);
                if let Err(e) = std::thread::Builder::new()
                    .name("shepherd-conn".into())
                    .spawn(move || {
                        let _slot = slot;
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

/// A served connection, counted for as long as its thread runs.
///
/// A guard rather than a manual increment/decrement pair: `handle` has several
/// exits — EOF, a write failure, an oversized frame, a propagated `Err` — and a
/// decrement that has to be remembered at each of them is one that eventually
/// is not, at which point the daemon stops accepting connections it is not
/// serving.
struct ConnectionSlot(Arc<std::sync::atomic::AtomicUsize>);

impl ConnectionSlot {
    /// One slot, or `None` if the daemon is already at its limit.
    fn take(live: &Arc<std::sync::atomic::AtomicUsize>) -> Option<Self> {
        // `fetch_update`, not load-then-store: two accepts racing on a
        // check-then-increment both pass the check.
        live.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| {
            (n < MAX_CONNECTIONS).then_some(n + 1)
        })
        .ok()
        .map(|_| ConnectionSlot(Arc::clone(live)))
    }
}

impl Drop for ConnectionSlot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serve one connection.
fn handle(stream: UnixStream, daemon: Arc<Daemon>) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    // A deadline on the HANDSHAKE only. A connection that never sends its first
    // frame holds this thread for the daemon's life, which is the cheapest way
    // to exhaust the connection budget; a connection that has said hello is a
    // client the daemon is serving, and `events.subscribe` legitimately waits
    // for hours, so the timeout is cleared below rather than kept.
    stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    // Kept to clear that deadline once the handshake is done. The timeout is a
    // property of the socket, so this handle and the one inside `writer` are
    // the same underlying description either way.
    let deadline_handle = stream.try_clone()?;
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

    // Handshake done: this is a client, not a squatter. The deadline is
    // cleared because a subscribed connection is SUPPOSED to sit quiet — it is
    // waiting for events — and a read timeout would end it.
    deadline_handle.set_read_timeout(None)?;

    let mut session = Session {
        daemon: Arc::clone(&daemon),
        negotiated,
    };

    // --- requests ---------------------------------------------------------
    //
    // Held here, at connection scope, so that EVERY way out of the loop below
    // ends this connection's subscriptions: EOF, an oversized frame, a write
    // that fails, or an `Err` propagated by `?`. A client that hangs up while
    // its streams are quiet is invisible to the hub — see
    // [`subscribe_on_connection`] — and this is what makes it visible.
    let mut guards: Vec<crate::events::SubscriptionGuard> = Vec::new();

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
        if let Some(response) = serve_one(&line, &mut session, &writer, &mut guards) {
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
    guards: &mut Vec<crate::events::SubscriptionGuard>,
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
            return subscribe_on_connection(req, session, writer, id, guards);
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
/// Dropping `go_tx` on any early return unparks it into a `RecvError` and it
/// returns; the guard drops on the same path and takes the subscription with
/// it.
///
/// # The guard belongs to the CONNECTION, not to the pump
///
/// `guards` is the connection's, and that is the whole point. Publishing only
/// probes the senders of subscribers that want the stream being published, so
/// a client subscribed to `target` alone was never touched by scan traffic: it
/// could hang up and leave its pump parked on `recv` forever, holding a thread,
/// a channel, a subscriber entry and a clone of the socket. Only the read side
/// sees that hang-up, so only the read side can end the subscription — `handle`
/// drops these when its loop ends, the channel closes, and the pump falls out.
fn subscribe_on_connection(
    req: shepherd_proto::SubscribeRequest,
    session: &Session,
    writer: &Arc<std::sync::Mutex<UnixStream>>,
    id: RequestId,
    guards: &mut Vec<crate::events::SubscriptionGuard>,
) -> Option<RpcResponse> {
    // BOUNDED BEFORE ANYTHING IS SPAWNED.
    //
    // Nothing stopped a client sending `events.subscribe` in a loop on one
    // connection: each one spawns an OS thread and holds a guard until the
    // connection closes, and pointing them all at a quiet stream leaves every
    // thread parked on `recv`. A malfunctioning dashboard could exhaust the
    // daemon's threads without ever sending an oversized frame, and the next
    // ordinary connection would fail to get one.
    //
    // Per connection rather than globally, deliberately. A global cap makes one
    // busy client refuse service to every other, which is the failure this is
    // meant to prevent rather than a milder version of it; a per-connection cap
    // bounds the client that misbehaves. `MAX_FRAME_BYTES` is the analogous
    // per-connection bound on the other resource.
    //
    // Refused with `Busy`, the same code a failed pump spawn already answers:
    // from the caller's side both are "this connection cannot take another
    // subscription right now".
    if guards.len() >= MAX_SUBSCRIPTIONS_PER_CONNECTION {
        return Some(RpcResponse::failed(
            Some(id),
            RpcError::new(
                ErrorCode::Busy,
                format!(
                    "this connection already holds {MAX_SUBSCRIPTIONS_PER_CONNECTION} \
                     subscriptions, which is the per-connection limit. Each one owns a thread \
                     for the life of the connection; open a second connection, or subscribe \
                     to several streams in one request rather than one request per stream"
                ),
            ),
        ));
    }

    let crate::events::Subscription {
        result,
        replay,
        rx,
        overflowed,
        guard,
    } = session.daemon.events.subscribe(
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
    // Handed over only now. Every early return above drops it instead, which
    // unregisters a subscription whose client will never hear about it.
    guards.push(guard);
    let _ = go_tx.send(());
    None
}

/// Drain one subscription onto its socket, and shut the socket down if the
/// subscription was cut off for falling behind.
///
/// # Why EOF, and not another dropped frame
///
/// The loop ends for one of four reasons: the hub dropped the sender (daemon
/// shutdown), the connection ended and its `SubscriptionGuard` dropped, the
/// socket died, or this subscriber overflowed its queue and the hub
/// unregistered it. The first three need nothing from us — in the second the
/// client is already gone, which is what closed the channel. The fourth is the
/// one the client has to be told about, and `overflowed` is the only thing that
/// distinguishes it — all four arrive here as a closed channel.
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

    /// A unique socket path for one test, kept SHORT on purpose.
    ///
    /// `sun_path` is 104 bytes including the NUL on macOS, and its temp
    /// directory is `/var/folders/<2>/<28>/T/` — 47 of them gone before this
    /// name begins. The old `shepherd-srv-<pid>-<tag>-ThreadId(NN)` left about
    /// eleven characters of headroom, so a descriptive tag was enough to push
    /// `two_state_directories_cannot_share_one_socket` over it and fail with
    /// `path must be shorter than SUN_LEN` on macOS alone. The prefix is now
    /// three characters and the thread id contributes only its digits.
    fn tmp_socket(tag: &str) -> std::path::PathBuf {
        let thread = format!("{:?}", std::thread::current().id());
        let thread: String = thread.chars().filter(char::is_ascii_digit).collect();
        let d = std::env::temp_dir().join(format!("shp-{}-{tag}-{thread}", std::process::id()));
        // Checked against the BUDGET, not against the local path. `/tmp/` costs
        // five bytes and `/var/folders/<2>/<28>/T/` costs forty-nine, so an
        // assertion on the assembled path would pass on Linux for a tag that
        // cannot work on macOS — a green local run and a `SUN_LEN` failure a CI
        // round-trip later, which is exactly how this arrived. What a fixture
        // may spend on its own name plus `/daemon.sock` is 103 - 49 = 54.
        let spend = d.file_name().unwrap_or_default().len() + "/daemon.sock".len();
        assert!(
            spend <= 54,
            "this fixture spends {spend} bytes of the 54 macOS leaves for a socket \
             path under its temp directory; shorten the tag `{tag}`"
        );
        let _ = std::fs::remove_dir_all(&d);
        d.join("daemon.sock")
    }

    /// One connection cannot spawn unbounded pump threads.
    ///
    /// Every `events.subscribe` costs an OS thread and a bounded channel for
    /// the life of the connection, and nothing stopped a client sending them in
    /// a loop. Pointed at a quiet stream, every thread parks on `recv` — so a
    /// malfunctioning dashboard could exhaust the daemon's threads without ever
    /// sending an oversized frame, and the next ordinary connection would not
    /// be served.
    ///
    /// Asserted through `handle` over a real socket pair, because the cap is a
    /// property of the CONNECTION rather than of the hub.
    #[cfg(unix)]
    #[test]
    fn one_connection_cannot_hold_unbounded_subscriptions() {
        let dir = std::env::temp_dir().join(format!(
            "shepherd-subcap-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        mkdir_owner_only(&dir);
        let paths = shepherd_obs::paths::Paths {
            state_dir: dir.clone(),
            socket: dir.join("daemon.sock"),
        };
        let catalog = shepherd_catalog::Catalog::open(&paths.catalog()).unwrap();
        let actor = shepherd_catalog::writer::CatalogActor::start(catalog, None);
        let daemon = Daemon::new(actor, crate::events::EventHub::new(64, "test"), paths);

        let (client, server) = UnixStream::pair().unwrap();
        let conn = std::thread::spawn({
            let daemon = Arc::clone(&daemon);
            move || {
                let _ = handle(server, daemon);
            }
        });

        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut client = client;
        let mut call = |line: String| -> String {
            use std::io::Write;
            client.write_all(line.as_bytes()).unwrap();
            client.write_all(b"\n").unwrap();
            let mut buf = String::new();
            std::io::BufRead::read_line(&mut reader, &mut buf).unwrap();
            buf
        };

        let hello = call(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "hello",
                "params": {
                    "proto_version": shepherd_proto::PROTO_VERSION,
                    "client": {"name": "cap-test", "build": "0"},
                    "capabilities": [],
                }
            })
            .to_string(),
        );
        assert!(hello.contains("\"result\""), "handshake failed: {hello}");

        // Up to the cap, each one succeeds — a cap that refused the first
        // subscription would pass a "must refuse eventually" test while
        // breaking the feature.
        for n in 0..MAX_SUBSCRIPTIONS_PER_CONNECTION {
            let reply = call(
                serde_json::json!({
                    "jsonrpc": "2.0", "id": 100 + n, "method": "events.subscribe",
                    "params": {"streams": ["target"]}
                })
                .to_string(),
            );
            assert!(
                reply.contains("subscription_id"),
                "subscription {n} was refused below the cap: {reply}"
            );
        }
        assert_eq!(
            daemon.events.subscriber_count(),
            MAX_SUBSCRIPTIONS_PER_CONNECTION,
            "the hub must hold exactly the subscriptions that were accepted"
        );

        // One past it is refused, and the connection survives to say so.
        let refused = call(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 999, "method": "events.subscribe",
                "params": {"streams": ["target"]}
            })
            .to_string(),
        );
        assert!(
            refused.contains("per-connection limit"),
            "the refusal must name the reason: {refused}"
        );
        assert_eq!(
            daemon.events.subscriber_count(),
            MAX_SUBSCRIPTIONS_PER_CONNECTION,
            "a refused subscribe must not have registered anything"
        );

        drop(client);
        drop(reader);
        conn.join().expect("the connection thread ends at EOF");
        assert_eq!(
            daemon.events.subscriber_count(),
            0,
            "and all of them are released when the connection closes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The connection, not the pump, is what ends a subscription.
    ///
    /// A client subscribes to `target` alone and hangs up. Nothing publishes a
    /// `target` event — so `publish` never probes its sender, since it only
    /// probes subscribers that want the stream being published — and before the
    /// guard nothing else ever removed it either: the pump stayed parked on
    /// `recv` holding a thread, a channel, a subscriber entry and a clone of
    /// the socket, for the life of the daemon. Ordinary reconnects grew all
    /// four without bound.
    ///
    /// Driven through `handle` over a real socket pair rather than through the
    /// hub, because the hub half already has its own test and it is the *read
    /// side noticing EOF* that this is about. The scan publishes are
    /// load-bearing: without them the reaping-on-publish path would end the
    /// subscription and the test would pass on the wrong mechanism.
    #[test]
    fn a_closed_connection_ends_its_subscription() {
        // `temp_dir` is fine here and only here: this is a STATE directory, not
        // a scan root, so the macOS `/var` -> `/private/var` deny-list problem
        // that moved the scan fixtures to `CARGO_TARGET_TMPDIR` does not apply
        // — and `CARGO_TARGET_TMPDIR` is not set for unit tests anyway.
        let dir = std::env::temp_dir().join(format!(
            "shepherd-subguard-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        mkdir_owner_only(&dir);
        let paths = shepherd_obs::paths::Paths {
            state_dir: dir.clone(),
            socket: dir.join("daemon.sock"),
        };
        let catalog = shepherd_catalog::Catalog::open(&paths.catalog()).unwrap();
        let actor = shepherd_catalog::writer::CatalogActor::start(catalog, None);
        let daemon = Daemon::new(actor, crate::events::EventHub::new(64, "test"), paths);

        let (client, server) = UnixStream::pair().unwrap();
        let conn = std::thread::spawn({
            let daemon = Arc::clone(&daemon);
            move || {
                let _ = handle(server, daemon);
            }
        });

        let mut reader = BufReader::new(client.try_clone().unwrap());
        let mut client = client;
        let mut send = |line: String| {
            use std::io::Write;
            client.write_all(line.as_bytes()).unwrap();
            client.write_all(b"\n").unwrap();
        };
        let mut read_line = || {
            let mut buf = String::new();
            std::io::BufRead::read_line(&mut reader, &mut buf).unwrap();
            buf
        };

        send(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 1, "method": "hello",
                "params": {
                    "proto_version": shepherd_proto::PROTO_VERSION,
                    "client": {"name": "guard-test", "build": "0"},
                    "capabilities": [],
                }
            })
            .to_string(),
        );
        let hello = read_line();
        assert!(hello.contains("\"result\""), "handshake failed: {hello}");

        send(
            serde_json::json!({
                "jsonrpc": "2.0", "id": 2, "method": "events.subscribe",
                "params": {"streams": ["target"]}
            })
            .to_string(),
        );
        let subscribed = read_line();
        assert!(
            subscribed.contains("subscription_id"),
            "subscribe failed: {subscribed}"
        );
        assert_eq!(daemon.events.subscriber_count(), 1);

        // Traffic on a stream this subscriber did not ask for. Its sender is
        // never touched, so nothing here can reap it.
        for i in 1..=10 {
            daemon.events.publish(
                shepherd_proto::event::EventStream::Scan,
                shepherd_proto::event::EventPayload::ScanProgress {
                    root_id: 1,
                    files_seen: i,
                    bytes_seen: i,
                    current_path: None,
                    done: false,
                },
            );
        }
        assert_eq!(
            daemon.events.subscriber_count(),
            1,
            "precondition: an unwanted stream must not reap it, or this test \
             would be measuring the reaping path instead"
        );

        drop(client);
        drop(reader);
        conn.join().expect("the connection thread must end at EOF");

        assert_eq!(
            daemon.events.subscriber_count(),
            0,
            "the client hung up and its subscription outlived the connection"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Create a directory the way the daemon does: owner-only from the start.
    ///
    /// These fixtures used to `create_dir_all` at the ambient umask and lean on
    /// `bind` to tighten it. It no longer does — chmodding a directory it did
    /// not create is what let `SHEPHERD_SOCKET=/tmp/shepherd.sock` lock out
    /// `/tmp` — so a fixture that wants a pre-existing socket directory has to
    /// make one that meets the bar, exactly as an operator would.
    fn mkdir_owner_only(dir: &Path) {
        use std::os::unix::fs::DirBuilderExt;
        let _ = std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir);
    }

    /// `bind`, taking the state lock the way `cmd_run` does.
    ///
    /// Production takes the lock first and hands the held file to `bind`, so
    /// the ordering cannot be got wrong; these tests are about the socket half
    /// and say so in one place rather than at every call.
    fn bind(path: &Path, lock_path: &Path) -> Result<Bound, ServerError> {
        // `secure_state_dir` has already made the state directory in
        // production, which is why `lock_state_dir` does not create it. Here
        // the lock usually sits in the socket's own directory, which `bind`
        // creates — so the fixture stands in for that step.
        if let Some(parent) = lock_path.parent() {
            mkdir_owner_only(parent);
        }
        super::bind(path, take_state_lock(lock_path)?)
    }

    /// The state lock, waited for past this binary's fork window.
    ///
    /// Production takes this lock once, at start-up, and holds it for the
    /// daemon's life. These tests bind repeatedly against one lock path and
    /// release in between, which puts them on the same footing as
    /// [`bind_once_released`]: an `flock` lives on the open file description,
    /// `fork` duplicates every description into the child until it `exec`s, and
    /// this binary's service tests shell out on other threads. A lock released
    /// here can still be alive in somebody else's half-spawned child.
    ///
    /// One second, not five: the window was measured at 3.6ms, and the tests
    /// that want the refusal call [`super::lock_state_dir`] directly rather
    /// than waiting this out.
    fn take_state_lock(lock_path: &Path) -> Result<std::fs::File, ServerError> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(1);
        loop {
            match super::lock_state_dir(lock_path) {
                Ok(f) => return Ok(f),
                Err(e) if std::time::Instant::now() >= deadline => return Err(e),
                Err(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
            }
        }
    }

    /// `bind`, retried until the fork window a TEST BINARY opens has closed.
    ///
    /// Not a weakened assertion and not a product concern — it is a fact about
    /// this process. An `flock` lives on the open file *description*, and
    /// `fork` duplicates every description into the child; Rust marks its file
    /// descriptors close-on-exec, so the duplicate survives only the few
    /// milliseconds between `fork` and `exec`. This binary runs the service
    /// tests, which shell out to `systemctl`, `launchctl` and `id` on other
    /// threads, so a socket lock — or a listening socket — released here can
    /// still be alive inside somebody else's half-spawned child. Measured at
    /// 3.6ms, at roughly one run in six.
    ///
    /// So the property is "the lock is released when its holder is dropped",
    /// not "released within one syscall of it". The wait is bounded tightly and
    /// reports the last refusal if it expires, which is what a real regression
    /// — a lock nobody releases — looks like from here.
    ///
    /// Only for re-binding a path this test just released. A `bind` that must
    /// FAIL is never routed through it: retrying an expected refusal would turn
    /// this into exactly the kind of test that cannot fail.
    fn bind_once_released(path: &Path, lock: &Path, why: &str) -> Bound {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut last = None;
        loop {
            match bind(path, lock) {
                Ok(b) => return b,
                Err(e) if std::time::Instant::now() < deadline => {
                    last = Some(e);
                    std::thread::sleep(std::time::Duration::from_millis(1));
                }
                Err(e) => panic!("{why}: still refused after 5s: {}", last.unwrap_or(e)),
            }
        }
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
        mkdir_owner_only(path.parent().unwrap());
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
        let crate::events::Subscription {
            rx,
            overflowed,
            guard: _guard,
            ..
        } = hub.subscribe(vec![], None, None);

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
        let crate::events::Subscription {
            rx,
            overflowed,
            guard: _guard,
            ..
        } = hub.subscribe(vec![], None, None);
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

    /// An existing shared directory is REFUSED, never taken over.
    ///
    /// `SHEPHERD_SOCKET` names a socket FILE. Pointing it at `/run/shepherd.sock`
    /// or `/tmp/shepherd.sock` as root used to chmod the parent to `0700` — and
    /// the ownership and mode checks then passed because the chmod had just
    /// made them pass — locking every other user and service out of `/run` or
    /// `/tmp`. A directory this daemon did not create is checked, not seized.
    #[cfg(unix)]
    /// A symlink on the way in is judged by who can REPLACE it, not by being
    /// a symlink.
    ///
    /// Round 29 refused any symlinked ancestor outright. That is unsatisfiable
    /// on macOS — `$TMPDIR` and `/tmp` both sit under `/var -> private/var`, so
    /// the daemon could not start and eight unrelated tests failed there while
    /// passing on Linux, which is how the rule's real cost surfaced. A link
    /// only this daemon or root can repoint is no weaker than a directory only
    /// this daemon or root can rename, and refusing it buys nothing.
    ///
    /// The link is deliberately pointed at a SIBLING, so the canonical path
    /// differs from the configured one and both walks have to run: the first
    /// judges the link itself, the second the directories above its target.
    #[test]
    fn a_symlinked_ancestor_this_daemon_owns_is_accepted() {
        let base = tmp_socket("anc").parent().unwrap().to_path_buf();
        let real = base.join("real");
        mkdir_owner_only(&real);
        std::os::unix::fs::symlink(&real, base.join("link")).unwrap();

        let path = base.join("link").join("s").join("daemon.sock");
        let bound = bind(&path, &base.join("d.lock"))
            .expect("a link this daemon owns must not block startup");
        assert!(
            real.join("s").join("daemon.sock").exists(),
            "and the socket lands on the link's target"
        );
        drop(bound);
        let _ = std::fs::remove_dir_all(&base);
    }

    /// An ancestor anyone may write is refused unless it is sticky — and the
    /// refusal creates nothing.
    ///
    /// This is the hole the old symlink rule left open while it was busy
    /// refusing `/var`: ownership of a component stops mattering once the
    /// directory holding it is writable by others, because renaming an entry
    /// needs write permission on the directory, not on the entry. The sticky
    /// bit is the exception, and the reason `/tmp` is usable at all.
    ///
    /// The `0775` case is the other half of the test and not an afterthought:
    /// the first draft of this rule refused group-writable too, which is the
    /// mode an ordinary Ubuntu `$HOME` carries, and it took every e2e test in
    /// the workspace down with it. A group is a set the operator chose; the
    /// world is not.
    #[test]
    fn a_world_writable_ancestor_is_refused_unless_sticky() {
        use std::os::unix::fs::PermissionsExt;

        let base = tmp_socket("wr").parent().unwrap().to_path_buf();
        let open = base.join("open");
        mkdir_owner_only(&open);
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o777)).unwrap();

        let path = open.join("s").join("daemon.sock");
        let err = bind(&path, &base.join("d.lock"))
            .expect_err("a directory anyone may rename inside must not host the socket");
        assert!(
            err.to_string().contains("not sticky"),
            "the refusal must name what is wrong with it: {err}"
        );
        assert!(
            !open.join("s").exists(),
            "and a refused path must be left exactly as it was found"
        );

        // THE ACCEPTING DIRECTIONS: the mode `/tmp` carries, and the mode an
        // ordinary home directory carries.
        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o1777)).unwrap();
        let bound = bind(&path, &base.join("d.lock")).expect("sticky is what `/tmp` has");
        drop(bound);
        let _ = std::fs::remove_dir_all(open.join("s"));

        std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o775)).unwrap();
        let bound = bind(&path, &base.join("d.lock"))
            .expect("group-writable is what an ordinary $HOME carries");
        drop(bound);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn an_existing_shared_directory_is_refused_rather_than_chmodded() {
        use std::os::unix::fs::PermissionsExt;

        let path = tmp_socket("shared-parent");
        let dir = path.parent().unwrap().to_path_buf();
        mkdir_owner_only(&dir);
        // Somebody else's directory, or simply one the operator uses for other
        // things: group- and world-readable, as `/run` and `/tmp` are.
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();

        let err = bind(&path, &dir.join("d.lock"))
            .expect_err("a shared directory must not be taken over");
        assert!(
            err.to_string().contains("did not create"),
            "the refusal must explain why it will not just fix the mode: {err}"
        );
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o755,
            "and it must not have been chmodded on the way to refusing"
        );

        // THE ACCEPTING DIRECTION: a dedicated child, which the daemon creates
        // owner-only from its first instant. This is §4.3's own layout.
        let nested = dir.join("shepherd").join("daemon.sock");
        let bound = bind(&nested, &dir.join("d.lock")).expect("a dedicated child is created");
        assert_eq!(
            std::fs::metadata(nested.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700,
            "created owner-only rather than created and then tightened"
        );
        drop(bound);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The state lock is takeable before anything else, and refuses a second
    /// holder.
    ///
    /// This is the half a test can reach. The ORDERING — that the lock is held
    /// before the catalog is opened and before crash recovery runs — is
    /// enforced by the signature rather than by a test: `bind` takes an
    /// already-held `File`, so there is no way to reach a listener without
    /// having taken the lock first, and `cmd_run` has nowhere else to take it.
    /// Proving the recovery race itself needs two daemons and a live scan job,
    /// which is a fixture this suite cannot hold steady.
    #[cfg(unix)]
    #[test]
    fn the_state_lock_is_exclusive_and_precedes_binding() {
        let path = tmp_socket("statelock");
        mkdir_owner_only(path.parent().unwrap());
        let lock_path = path.with_extension("lock");

        let first = super::lock_state_dir(&lock_path).expect("the first daemon takes it");
        let err = super::lock_state_dir(&lock_path)
            .expect_err("a second daemon must not open the same catalog");
        assert!(
            err.to_string().contains("already holds"),
            "the refusal must name the lock: {err}"
        );

        // And it is what `bind` consumes: released with the holder, so an
        // ordinary restart is not blocked by the previous run's file.
        //
        // Through the waiter, for the fork window `take_state_lock` documents.
        first.unlock().expect("release");
        drop(first);
        let again = take_state_lock(&lock_path).expect("released");
        let bound = super::bind(&path, again).expect("bind under the held lock");
        drop(bound);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
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

    /// A socket directory that cannot be made owner-only is REFUSED, not
    /// warned about.
    ///
    /// §4.3: "Authorization is filesystem/pipe permissions only". The socket
    /// being `0600` is half of it; the other half is that nobody else can
    /// unlink the name and put their own listener there. A `let _ =` on the
    /// chmod discarded that half, so pointing `SHEPHERD_SOCKET` at an existing
    /// group-writable directory owned by someone else bound happily inside it —
    /// after which any member of that group can replace the socket and answer
    /// as the daemon to every later client.
    ///
    /// Driven through a directory whose mode will not stick, which is what an
    /// un-chmod-able directory looks like from here.
    #[test]
    fn a_socket_directory_that_cannot_be_secured_is_refused() {
        let path = tmp_socket("insecure");
        let dir = path.parent().unwrap().to_path_buf();
        mkdir_owner_only(&dir);

        // The accepting direction first: an ordinary owner-only directory binds.
        let ok = bind(&path, &path.with_extension("lock")).expect("an ordinary directory binds");
        assert_eq!(
            std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            0o700,
            "and it is left owner-only"
        );
        drop(ok);
        std::fs::remove_file(&path).ok();

        // A directory whose mode this daemon cannot set at all. Running as
        // root makes every chmod succeed, so the assertion is skipped there —
        // and the accepting half above still ran.
        // SAFETY: infallible per POSIX. `/proc/self` was the old spelling and
        // it does not exist on macOS, where `unwrap_or(0)` then read as root
        // and SKIPPED the refusing half of this test — the same self-disabling
        // check this file removed from `secure_socket_dir`.
        let euid = unsafe { libc::geteuid() };
        if euid == 0 {
            return;
        }
        let foreign = std::path::Path::new("/proc/sys");
        if std::fs::metadata(foreign).is_ok() {
            let err = bind(
                &foreign.join("shepherd-test.sock"),
                &path.with_extension("lock"),
            )
            .expect_err("a directory this daemon cannot secure must not host the socket");
            // The reason changed with the fix and is now the STRONGER one: the
            // daemon no longer tries to chmod a directory it did not create, so
            // `/proc/sys` is refused for being someone else's rather than for a
            // chmod that would not stick. Either sentence is a refusal that
            // names the directory; what must never happen is a bind.
            let msg = err.to_string();
            assert!(
                msg.contains("owned by uid")
                    || msg.contains("must be owner-only")
                    || msg.contains("cannot create"),
                "the refusal must say why the directory is unusable: {err}"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two daemons with DIFFERENT state directories still cannot share a
    /// socket.
    ///
    /// The state lock keys the catalog and the job queue, which is the deeper
    /// harm — and it is not the socket. `SHEPHERD_STATE_DIR` and
    /// `SHEPHERD_SOCKET` are separate settings, so two starts can take
    /// different state locks and resolve to the same socket through one
    /// `XDG_RUNTIME_DIR`, at which point the original race is back untouched.
    ///
    /// The second lock is keyed by the socket PATH — `<socket>.lock` beside it
    /// — so the set that contends is exactly the set that would fight over one
    /// socket. The second half of this test is the other side of that: two
    /// DIFFERENT sockets in one directory are not a conflict, and an earlier
    /// directory-granular version of this lock refused them.
    #[test]
    fn two_state_directories_cannot_share_one_socket() {
        let path = tmp_socket("shared-socket");
        let dir = path.parent().unwrap().to_path_buf();
        mkdir_owner_only(&dir);

        // Two DIFFERENT state locks, as two daemons with different
        // `SHEPHERD_STATE_DIR` values would have.
        let state_a = dir.join("a.lock");
        let state_b = dir.join("b.lock");

        let first = bind(&path, &state_a).expect("the first daemon takes the socket");
        let err = bind(&path, &state_b)
            .expect_err("a second daemon must not take a socket the first is listening on");
        assert!(
            err.to_string().contains("socket lock"),
            "the refusal must be the SOCKET lock, not the state lock — the state locks \
             differ here and would both succeed: {err}"
        );
        UnixStream::connect(&path).expect("and the first is still listening");

        // A different socket in the same directory is a different daemon, not a
        // conflict. `$XDG_RUNTIME_DIR/shepherd/` holding two instances' sockets
        // is a legitimate arrangement and the lock must not refuse it.
        let sibling = dir.join("other.sock");
        let other = bind(&sibling, &state_b)
            .expect("a different socket in the same directory is not a conflict");
        drop(other);

        drop(first);
        let restarted = bind_once_released(
            &path,
            &state_b,
            "once released, another state directory may take it",
        );
        drop(restarted);
        std::fs::remove_dir_all(&dir).ok();
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
        mkdir_owner_only(path.parent().unwrap());
        drop(UnixListener::bind(&path).expect("bind the socket a killed daemon left"));
        assert!(path.exists(), "dropping a listener leaves the node behind");

        let listener = bind_once_released(
            &path,
            &path.with_extension("lock"),
            "a stale socket must not block startup",
        );
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
        mkdir_owner_only(path.parent().unwrap());
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

        // `super::lock_state_dir`, not the waiting shim: this test WANTS the
        // refusal, and waiting a second for a lock somebody is deliberately
        // holding would only make it slow.
        let err = super::lock_state_dir(&path.with_extension("lock")).expect_err(
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
        let restarted = bind_once_released(
            &path,
            &path.with_extension("lock"),
            "a restart after a clean stop must not be refused",
        );
        UnixStream::connect(&path).expect("and it really is listening");
        drop(restarted);
        std::fs::remove_dir_all(path.parent().unwrap()).ok();
    }
}
