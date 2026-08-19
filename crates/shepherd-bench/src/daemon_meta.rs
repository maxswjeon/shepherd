//! The metadata bar, measured **through a live daemon** on an injected catalog.
//!
//! # Why this exists as a separate leg
//!
//! Phase 0b measured the metadata index in-process: the arena was built inside
//! the bench binary and four OS threads queried it directly. `bench-contract.toml`
//! records that substitution explicitly and says why — at 0b there was no
//! daemon, so "against a daemon" could not be honoured without inventing one,
//! and inventing one would have measured the IPC layer rather than the index.
//!
//! Phase 1 ships the daemon (T6). So the substitution's expiry condition has
//! arrived, and the contract's own note names what the 0b number did not
//! include: *"IPC and serialisation cost, which Phase 5's re-run against the
//! real daemon adds"*. This leg adds it, one phase earlier than that sentence
//! anticipated, because §9's M1 leg 2 asks for the bar over a 10M-row catalog
//! **injected by shepherd-bench and queried through the daemon**, and §9 rule 3
//! has the metadata bar re-measured *from* Phase 1 rather than re-read from a
//! Phase 0b artifact.
//!
//! # What is measured, and what that number contains
//!
//! Latency is timed **client-side, send→response**, across a real Unix socket,
//! after a real `hello` handshake. So each sample contains, in order:
//!
//! 1. JSON serialisation of the request and a socket write;
//! 2. the daemon's `MetaIndex::search` over the arena — the *only* part the
//!    in-process `shepherd-index` test measures;
//! 3. **hydration of the candidate ids back into rows through the catalog
//!    writer actor** — and this is the part worth naming in advance, because it
//!    is neither IPC nor index. `dispatch::Session::search` ends in
//!    `self.cat(|cat| hydrate(...))`, and `cat()` routes to
//!    `writer().try_with(..)`: the *writer* actor, which is one thread holding
//!    one connection. Four concurrent clients therefore queue their hydration
//!    behind one another. That queueing is invisible in-process and cannot be
//!    modelled as a fixed IPC constant added to the 0b number, which is the
//!    substantive reason this leg had to be run rather than argued.
//! 4. the response write and the client's read.
//!
//! # The substitution this leg records, in both directions
//!
//! `[execution]` fixes `background_ingest_rows_per_sec = 2000`. The daemon's
//! only write path is `scan.start`, whose rate is a property of the filesystem
//! being walked rather than a number the harness can pin, and whose completion
//! fires a full `rebuild_index` over every row in the catalog. Driving ingest
//! through it would measure a workload `[execution]` does not describe. So
//! ingest is a fifth thread inserting real-schema rows into the daemon's own
//! catalog on its own connection, at exactly the contracted rate.
//!
//! Stated in both directions, because a one-sided note is how a substitution
//! becomes a silent claim:
//!
//! * **this leg adds** what 0b lacked — IPC, JSON, the connection handler, and
//!   the writer-actor hydration queue, all under four genuinely separate socket
//!   connections;
//! * **this leg loses** what 0b had — 0b's ingest thread mutated the very arena
//!   the readers were scanning. Here the arena is immutable for the duration of
//!   a run (the daemon rebuilds it only at start-up and at scan completion), so
//!   the mutation pressure lands on the catalog's WAL and on hydration reads
//!   instead of on the index. Neither is a superset of the other.
//!
//! `[bars]`, `[tiebreak]` and `[query_trace]` are untouched, and this file
//! reads all three rather than restating any of them.

use std::collections::HashSet;
use std::io::{BufRead, BufReader, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use rayon::prelude::*;
use rusqlite::params;

use crate::generate::{self, Row};
use crate::{Args, Contract, Percentiles, RunSet};

/// The scan root every injected row hangs off. A `file` row needs a `root_id`
/// and the FK is real, so the fixture needs a root; the path is never walked.
const ROOT_PATH: &str = "/shepherd-bench/injected-10m";

/// Where the injected state directory lives under `--fixtures`.
pub fn state_dir(fixtures: &Path) -> PathBuf {
    fixtures.join("daemon-state")
}

/// The catalog file name is **not** a choice this harness gets to make: it is
/// `Paths::catalog()`, `state_dir.join("catalog.db")`. Injecting to any other
/// name produces a daemon that starts, builds an empty index, and answers every
/// query with zero hits very quickly — a fast p95 over nothing, which is the
/// exact defect the zero-hit guard below exists to catch.
pub fn catalog_db(fixtures: &Path) -> PathBuf {
    state_dir(fixtures).join("catalog.db")
}

// ---------------------------------------------------------------------------
// Injection
// ---------------------------------------------------------------------------

/// The schema, as a comparable string.
///
/// Read from `sqlite_master` so it reflects what is actually in the file rather
/// than what the DDL was believed to say. Compared against a throwaway database
/// created by `shepherd_catalog::Catalog::open` in [`inject_catalog`] — the
/// point being that the daemon must be reading a catalog indistinguishable from
/// one the product itself created. Dropping and recreating indexes around a
/// bulk insert is a legitimate speed-up only if the end state is identical, and
/// "identical" has to be checked rather than intended.
fn schema_fingerprint(conn: &rusqlite::Connection) -> Result<String, String> {
    let mut stmt = conn
        .prepare(
            "SELECT type, name, tbl_name, COALESCE(sql, '') FROM sqlite_master \
             WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name",
        )
        .map_err(|e| e.to_string())?;
    let rows = stmt
        .query_map([], |r| {
            Ok(format!(
                "{}\t{}\t{}\t{}",
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?
            ))
        })
        .map_err(|e| e.to_string())?;
    let mut out = String::new();
    for r in rows {
        out.push_str(&r.map_err(|e| e.to_string())?);
        out.push('\n');
    }
    Ok(out)
}

/// `file_repo::split_name`, mirrored.
///
/// Mirrored rather than called because it is private to `shepherd-catalog`, and
/// mirrored rather than approximated because `ext` feeds the `(ext, mtime)`
/// index: a fixture whose extensions are spelled differently from the ones the
/// scanner writes would give that index a different shape than production's.
/// The leading-dot rule is the one that actually differs from the obvious
/// implementation — `.gitignore` has no extension.
fn split_name(rel_path: &str) -> (String, Option<String>) {
    let name = rel_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(rel_path)
        .to_string();
    let ext = name
        .rfind('.')
        .filter(|&i| i > 0)
        .map(|i| name[i + 1..].to_lowercase());
    (name, ext)
}

/// The `rel_path` a generated row would have had if a scanner had found it.
fn rel_path_of(r: &Row) -> String {
    format!("{}/{}", r.parent, r.name)
}

/// The six indexes on `file`, dropped for the bulk load and recreated after.
///
/// Recreating `file_root_relpath` is not only a speed-up undone: it is UNIQUE,
/// so the recreate **fails** if the load admitted two rows with one `rel_path`.
/// That is a second, independent check on the de-duplication below — the
/// de-duplicator could be wrong; SQLite's index build cannot be wrong in the
/// same way.
const FILE_INDEXES: &[(&str, &str)] = &[
    (
        "file_root_relpath",
        "CREATE UNIQUE INDEX file_root_relpath ON file(root_id, rel_path)",
    ),
    (
        "file_root_normkey",
        "CREATE INDEX file_root_normkey ON file(root_id, norm_key)",
    ),
    (
        "file_blake3",
        "CREATE INDEX file_blake3       ON file(blake3)",
    ),
    (
        "file_state",
        "CREATE INDEX file_state        ON file(state)",
    ),
    (
        "file_ext_mtime",
        "CREATE INDEX file_ext_mtime    ON file(ext, mtime)",
    ),
    (
        "file_size",
        "CREATE INDEX file_size         ON file(size DESC)",
    ),
];

/// Build a catalog in the **product's** schema, holding `rows` generated rows.
///
/// This is not `gen-catalog`. That one writes a Phase 0b spike table —
/// `file(id, parent, name, ext, size, mtime)` — which the daemon cannot read:
/// `Daemon::rebuild_index` issues `SELECT id, rel_path FROM file ORDER BY id`
/// against the real §4.4 schema. Injecting means writing what the daemon reads.
///
/// Rows come from the same `generate::row(seed, i)` the committed query trace
/// was derived from, so the trace stays valid without regenerating it — a trace
/// whose needles were re-derived to match a new corpus would be a trace fitted
/// to the run.
pub fn inject_catalog(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let rows = a.rows_override.unwrap_or(c.fixture.rows);
    let seed = c.fixture.seed;
    let space = generate::dir_space(rows);

    let dir = state_dir(&a.fixtures);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    // The §4.4 schema carries six indexes and eleven more columns than the 0b
    // spike table, so the 0.10 GiB/M that `gen-catalog` budgets is far too
    // little. Measured at 200k and extrapolated; the guard aborting early beats
    // filling a shared box.
    crate::disk_guard_start(
        &dir,
        c.disk_guard.abort_below_free_gib,
        0.75 * rows as f64 / 1e6,
    )?;

    let db = catalog_db(&a.fixtures);
    for p in [
        &db,
        &db.with_extension("db-wal"),
        &db.with_extension("db-shm"),
    ] {
        let _ = std::fs::remove_file(p);
    }

    // Created by the product's own migrator, pragmas and invariant checks
    // included. A hand-rolled `CREATE TABLE` here would be a second spelling of
    // the schema, free to drift from the one the daemon migrates to.
    {
        let cat = shepherd_catalog::Catalog::open(&db)
            .map_err(|e| format!("creating the injected catalog: {e}"))?;
        drop(cat);
    }

    // The reference to compare against at the end: a catalog this build's
    // migrator just created, untouched by injection.
    let reference = {
        let tmp = dir.join("schema-reference.db");
        let _ = std::fs::remove_file(&tmp);
        let cat = shepherd_catalog::Catalog::open(&tmp)
            .map_err(|e| format!("creating the reference catalog: {e}"))?;
        let fp = schema_fingerprint(cat.conn())?;
        drop(cat);
        for p in [
            &tmp,
            &tmp.with_extension("db-wal"),
            &tmp.with_extension("db-shm"),
        ] {
            let _ = std::fs::remove_file(p);
        }
        fp
    };

    let conn = rusqlite::Connection::open(&db).map_err(|e| e.to_string())?;
    // `synchronous=OFF` for the load only, and it is a property of this
    // connection rather than of the file: the daemon opens its own connection
    // and gets the catalog's own pragmas. A fixture build is re-runnable, so
    // trading crash durability for load speed costs nothing that matters.
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=OFF; PRAGMA cache_size=-262144;",
    )
    .map_err(|e| e.to_string())?;

    conn.execute(
        "INSERT INTO scan_root (id, path, stub_mode, path_case_policy, path_norm_policy, \
                                atime_mode, created_at) \
         VALUES (1, ?1, 'delete', 'sensitive', 'preserve', 'unknown', 0)",
        params![ROOT_PATH],
    )
    .map_err(|e| format!("inserting the fixture scan_root: {e}"))?;

    for (name, _) in FILE_INDEXES {
        conn.execute_batch(&format!("DROP INDEX IF EXISTS {name};"))
            .map_err(|e| format!("dropping {name}: {e}"))?;
    }

    let t0 = Instant::now();
    const BATCH: u64 = 100_000;
    // The de-duplicator. `file` is UNIQUE on (root_id, rel_path) because a real
    // filesystem cannot hold one path twice; the generator has no such
    // constraint and will occasionally derive one `parent/name` twice across
    // 10M draws. 0b never noticed because its spike table had no unique index
    // and its arena was a bag of strings.
    //
    // A duplicate is SKIPPED and the id range EXTENDED, rather than the row
    // being renamed. Renaming would put a string in the corpus that
    // `row(seed, i)` never produced, which would quietly invalidate the
    // committed trace; skipping leaves every retained string a genuine
    // generator product, and the earlier copy of a skipped path is still in the
    // corpus, so a trace query whose source row was skipped still matches.
    let mut seen: HashSet<String> = HashSet::with_capacity(rows as usize * 2);
    let mut accepted = 0u64;
    let mut scanned = 0u64;
    let mut duplicates = 0u64;

    while accepted < rows {
        let batch: Vec<Row> = (scanned..scanned + BATCH)
            .into_par_iter()
            .map(|i| generate::row(seed, i, space))
            .collect();
        scanned += BATCH;

        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        {
            let mut st = tx
                .prepare_cached(
                    "INSERT INTO file \
                       (id, root_id, rel_path, name, ext, size, mtime, ctime, atime, \
                        norm_key, first_seen_at, blake3, updated_at) \
                     VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?6, NULL, ?7, ?8, NULL, ?8)",
                )
                .map_err(|e| e.to_string())?;
            for r in &batch {
                if accepted >= rows {
                    break;
                }
                let rel = rel_path_of(r);
                if !seen.insert(rel.clone()) {
                    duplicates += 1;
                    continue;
                }
                let (name, ext) = split_name(&rel);
                // The root is sensitive/preserve, so `norm_key` differs from
                // `rel_path` only in separator unification — but it is computed
                // by the product's function, not assumed to equal `rel_path`.
                let nk = shepherd_catalog::norm_key(
                    &rel,
                    shepherd_catalog::PathCasePolicy::Sensitive,
                    shepherd_catalog::PathNormPolicy::Preserve,
                );
                accepted += 1;
                st.execute(params![
                    accepted as i64,
                    &rel,
                    &name,
                    &ext,
                    r.size as i64,
                    // The §4.4 schema stores nanoseconds (`Timestamp::as_nanos`);
                    // the generator emits unix seconds.
                    r.mtime * 1_000_000_000,
                    &nk,
                    0i64,
                ])
                .map_err(|e| format!("inserting file id {accepted}: {e}"))?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        if accepted.is_multiple_of(1_000_000) || accepted >= rows {
            eprintln!(
                "[inject-catalog] {accepted}/{rows} rows ({duplicates} duplicate paths skipped), \
                 {:.1}s",
                t0.elapsed().as_secs_f64()
            );
            crate::disk_guard_continue(&dir, c.disk_guard.emergency_free_gib)?;
        }
    }
    let insert_secs = t0.elapsed().as_secs_f64();

    let t_idx = Instant::now();
    for (name, ddl) in FILE_INDEXES {
        conn.execute_batch(&format!("{ddl};")).map_err(|e| {
            format!(
                "recreating {name}: {e}\n(if this is a UNIQUE violation the de-duplicator \
                 admitted two rows with one rel_path — the injected catalog is wrong, not slow)"
            )
        })?;
    }
    let index_secs = t_idx.elapsed().as_secs_f64();

    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| e.to_string())?;

    // The load-bearing check: is this a real catalog?
    let fingerprint = schema_fingerprint(&conn)?;
    if fingerprint != reference {
        return Err(format!(
            "the injected catalog's schema differs from one this build's migrator creates. \
             Dropping and recreating indexes around the bulk load is only legitimate if the \
             end state is identical, and it is not.\n--- injected ---\n{fingerprint}\n\
             --- reference ---\n{reference}"
        ));
    }
    let counted: i64 = conn
        .query_row("SELECT COUNT(*) FROM file", [], |r| r.get(0))
        .map_err(|e| e.to_string())?;
    if counted as u64 != rows {
        return Err(format!(
            "injected {counted} rows, wanted {rows}: the daemon would build an index that \
             disagrees with the catalog and refuse to serve"
        ));
    }
    drop(conn);

    let bytes = crate::path_bytes(&db);
    eprintln!(
        "[inject-catalog] {rows} rows in {:.1}s insert + {:.1}s index, {:.2} GiB on disk, \
         {duplicates} duplicate paths skipped over {scanned} generated",
        insert_secs,
        index_secs,
        bytes as f64 / 1073741824.0
    );

    crate::emit(
        &a.out,
        "injected_catalog",
        serde_json::json!({
            "rows": rows,
            "seed": seed,
            "dir_space": space,
            "insert_seconds": insert_secs,
            "index_build_seconds": index_secs,
            "on_disk_bytes": bytes,
            "generated_rows_scanned": scanned,
            "duplicate_paths_skipped": duplicates,
            "schema_matches_fresh_migrate": true,
            "schema_version": shepherd_catalog::SCHEMA_VERSION,
            "scaled_run_reason": a.scaled_run_reason,
        }),
    )
}

// ---------------------------------------------------------------------------
// A client: one socket, one handshake, N queries
// ---------------------------------------------------------------------------

struct Client {
    reader: BufReader<UnixStream>,
    writer: UnixStream,
    next_id: i64,
}

impl Client {
    /// Connect and complete the `hello` handshake.
    ///
    /// Four clients means four of these — four separate connections, not four
    /// threads sharing one. The daemon serves a connection per thread, so
    /// sharing a socket would serialise at the socket and measure something
    /// with one client's concurrency and four clients' name.
    fn connect(socket: &Path) -> Result<Self, String> {
        let stream = UnixStream::connect(socket).map_err(|e| format!("connect: {e}"))?;
        stream
            .set_read_timeout(Some(Duration::from_secs(60)))
            .map_err(|e| e.to_string())?;
        let mut c = Client {
            reader: BufReader::new(stream.try_clone().map_err(|e| e.to_string())?),
            writer: stream,
            next_id: 0,
        };
        let hello = shepherd_proto::Hello {
            proto_version: shepherd_proto::PROTO_VERSION,
            client: shepherd_proto::PeerInfo {
                name: "shepherd-bench".into(),
                build: env!("CARGO_PKG_VERSION").into(),
            },
            capabilities: vec![],
        };
        let reply = c.call(
            "hello",
            serde_json::to_value(&hello).map_err(|e| e.to_string())?,
        )?;
        if reply.get("error").is_some() {
            return Err(format!("the daemon refused the handshake: {reply}"));
        }
        Ok(c)
    }

    fn call(
        &mut self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, String> {
        self.next_id += 1;
        let req = shepherd_proto::request::RpcRequest::new(
            shepherd_proto::request::RequestId::Number(self.next_id),
            method,
            params,
        );
        let mut line = serde_json::to_string(&req).map_err(|e| e.to_string())?;
        line.push('\n');
        self.writer
            .write_all(line.as_bytes())
            .map_err(|e| format!("write: {e}"))?;
        self.writer.flush().map_err(|e| format!("flush: {e}"))?;
        let mut buf = String::new();
        let n = self
            .reader
            .read_line(&mut buf)
            .map_err(|e| format!("read: {e}"))?;
        if n == 0 {
            return Err("the daemon closed the connection".into());
        }
        serde_json::from_str(&buf).map_err(|e| format!("{e}: {buf}"))
    }

    /// One `search` call, timed. Returns (latency, hits reported).
    fn search(&mut self, q: &str, limit: usize) -> Result<(Duration, usize), String> {
        let params = serde_json::json!({
            "query": q,
            "mode": "metadata",
            "limit": limit,
        });
        let t = Instant::now();
        let reply = self.call("search", params)?;
        let d = t.elapsed();
        if let Some(e) = reply.get("error") {
            return Err(format!("search({q:?}) failed: {e}"));
        }
        let hits = reply
            .get("result")
            .and_then(|r| r.get("hits"))
            .and_then(|h| h.as_array())
            .map(|a| a.len())
            .ok_or_else(|| format!("search({q:?}) returned no `hits` array: {reply}"))?;
        Ok((d, hits))
    }
}

// ---------------------------------------------------------------------------
// The daemon under test
// ---------------------------------------------------------------------------

/// A spawned `shepherdd`, killed on drop.
struct Daemon {
    child: Child,
    socket: PathBuf,
}

impl Daemon {
    /// Spawn and wait until it accepts a connection.
    ///
    /// **Connectable means the index is ready**, and that is a property of the
    /// daemon rather than an assumption: `main.rs` calls `rebuild_index()` and
    /// only then `server::bind()`. So the wait below is the whole cold-start
    /// cost — reading 10M rows out of SQLite and building the arena — and
    /// timing it costs nothing extra.
    fn start(bin: &Path, state: &Path, socket: &Path) -> Result<(Self, Duration), String> {
        let _ = std::fs::remove_file(socket);
        let t = Instant::now();
        let child = Command::new(bin)
            .env("SHEPHERD_STATE_DIR", state)
            .env("SHEPHERD_SOCKET", socket)
            // Inherited so a daemon that fails to build its index says so in
            // this harness's own output rather than dying silently and being
            // reported as a connect timeout.
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| format!("spawning {}: {e}", bin.display()))?;
        let mut d = Daemon {
            child,
            socket: socket.to_path_buf(),
        };
        let deadline = Instant::now() + Duration::from_secs(600);
        loop {
            if let Ok(Some(status)) = d.child.try_wait() {
                return Err(format!("shepherdd exited before listening: {status}"));
            }
            if UnixStream::connect(socket).is_ok() {
                return Ok((d, t.elapsed()));
            }
            if Instant::now() > deadline {
                return Err("shepherdd did not listen within 600s".into());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    /// The cores the kernel will actually run this process on.
    ///
    /// Read from `/proc`, not assumed from the `taskset` on the command line:
    /// the contract pins to 8 cores because 32 would pass a bar the declared
    /// reference machine fails, so "was it actually pinned" is a decision-
    /// integrity question and not a formality. A child inherits its parent's
    /// affinity mask, which is what makes wrapping the harness in `taskset`
    /// sufficient — but inheriting is a thing to verify, not to trust.
    fn cpus_allowed(&self) -> String {
        std::fs::read_to_string(format!("/proc/{}/status", self.child.id()))
            .ok()
            .and_then(|s| {
                s.lines()
                    .find(|l| l.starts_with("Cpus_allowed_list:"))
                    .map(|l| l.split_whitespace().skip(1).collect::<Vec<_>>().join(" "))
            })
            .unwrap_or_else(|| "unknown".into())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.socket);
    }
}

// ---------------------------------------------------------------------------
// Is this machine quiet enough to measure on?
// ---------------------------------------------------------------------------

/// Expand a `taskset`-style core list — `"0-7"`, `"0,2,4"`, `"0-3,8"`.
fn parse_cores(spec: &str) -> Result<Vec<usize>, String> {
    let mut out = Vec::new();
    for part in spec.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        match part.split_once('-') {
            Some((a, b)) => {
                let a: usize = a
                    .trim()
                    .parse()
                    .map_err(|_| format!("bad core range {part}"))?;
                let b: usize = b
                    .trim()
                    .parse()
                    .map_err(|_| format!("bad core range {part}"))?;
                out.extend(a..=b);
            }
            None => out.push(part.parse().map_err(|_| format!("bad core {part}"))?),
        }
    }
    if out.is_empty() {
        return Err(format!("no cores in {spec:?}"));
    }
    Ok(out)
}

/// Mean idle fraction of `cores` over `sample`, from `/proc/stat`.
///
/// `idle + iowait` over the sum of every field, differenced across the window.
fn cpu_idle_fraction(cores: &[usize], sample: Duration) -> Result<f64, String> {
    fn snap(cores: &[usize]) -> Result<Vec<(u64, u64)>, String> {
        let stat = std::fs::read_to_string("/proc/stat").map_err(|e| e.to_string())?;
        cores
            .iter()
            .map(|c| {
                let want = format!("cpu{c} ");
                let line = stat
                    .lines()
                    .find(|l| l.starts_with(&want))
                    .ok_or_else(|| format!("/proc/stat has no cpu{c}"))?;
                let f: Vec<u64> = line
                    .split_whitespace()
                    .skip(1)
                    .filter_map(|v| v.parse().ok())
                    .collect();
                if f.len() < 5 {
                    return Err(format!("/proc/stat cpu{c} is too short"));
                }
                Ok((f[3] + f[4], f.iter().sum::<u64>()))
            })
            .collect()
    }
    let a = snap(cores)?;
    std::thread::sleep(sample);
    let b = snap(cores)?;
    let (mut idle, mut total) = (0u64, 0u64);
    for (x, y) in a.iter().zip(b.iter()) {
        idle += y.0.saturating_sub(x.0);
        total += y.1.saturating_sub(x.1);
    }
    if total == 0 {
        return Err("/proc/stat did not advance".into());
    }
    Ok(idle as f64 / total as f64)
}

/// The cores this process is **actually** allowed to run on.
///
/// Read from `/proc/self/status`, not inferred from the command line, for the
/// same reason the daemon's mask is read back from `/proc`: `taskset` is
/// something a human types and can forget, and forgetting it is not a cosmetic
/// slip here. `[reference_machine]` spells out the consequence — the scan is
/// embarrassingly parallel, so on this 32-vCPU box an unpinned run goes "roughly
/// 4x faster than on the declared 8-core reference machine", which is "enough to
/// pass the 50 ms bar here and fail it on the machine the plan actually
/// specifies". An unpinned run is therefore not a slightly-optimistic number; it
/// is a number that can invert the verdict.
fn actual_pinned_cores() -> Result<String, String> {
    let status = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Cpus_allowed_list:"))
        .map(|v| v.trim().to_string())
        .ok_or_else(|| "/proc/self/status has no Cpus_allowed_list".into())
}

fn loadavg() -> String {
    std::fs::read_to_string("/proc/loadavg")
        .map(|s| s.split_whitespace().take(3).collect::<Vec<_>>().join(" "))
        .unwrap_or_else(|_| "unknown".into())
}

/// The pinned cores must be **idle before the run starts**, or the number this
/// harness produces is not a measurement of the daemon.
///
/// `taskset -c 0-7` pins *this* process tree onto cores 0-7. It does not
/// reserve them: any unpinned process on the box is scheduled across all 32
/// vCPUs, cores 0-7 included. On a shared development machine that is not a
/// hypothetical — this guard was added after a run recorded 84.90 ms warm and
/// 70.73 ms cold, **cold faster than warm**, which is backwards and was the
/// tell. `mpstat` showed cores 0-7 at 0.0% idle with another agent's unpinned
/// `ugrep -rn` holding 733% CPU for eighteen minutes across the whole run.
///
/// A benchmark that runs anyway and prints the number it gets is the defect
/// this project keeps finding: a measurement-shaped artifact that no longer
/// measures what its name says. `[reference_machine]` pins the core count
/// precisely because a wrong core count flips a pass into a fail, and a core
/// that is pinned-but-stolen is a wrong core count that does not show up in
/// `Cpus_allowed_list`. So this **aborts**, and the observed idle fraction goes
/// into the result object either way so a reader can check the claim rather
/// than trust it.
/// # Why 0.84, and not the 0.90 this started at
///
/// 0.90 was chosen before anyone had measured what this machine's floor *is*.
/// It turns out to be above it. Six consecutive 4 s samples of cores 0-7 with
/// nothing of this harness running, on a box with every other worker shut down
/// and the runaway `ugrep` long dead:
///
/// ```text
/// IDLE: 87.9  90.6  89.5  86.3  86.5  89.6     mean 88.4%, range 86.3-90.6
/// ```
///
/// The residue is this host's permanent furniture — a tmux server, five
/// `vscode-server` processes, several agent processes — costing 10-12% of these
/// eight cores continuously and never going away. A 0.90 threshold therefore
/// sits *above* the quietest state this machine has, and rejects most samples
/// taken on a completely empty box.
///
/// **That is not a strict guard, it is an unsatisfiable one.** And an
/// unsatisfiable check is no better than one that always passes: it has traded a
/// false negative for a false positive and stopped discriminating. Both are the
/// same underlying defect this project keeps finding — a check whose outcome is
/// decided by something other than the condition it names.
///
/// 0.84 comes from that measurement rather than from taste: ~2pp below the
/// lowest observed baseline sample, so the machine's own floor passes reliably.
///
/// # THIS THRESHOLD IS NOT CORRECT EITHER, AND HERE IS THE ARITHMETIC
///
/// An earlier draft of this comment claimed both real contention events were
/// "still rejected by a wide margin — a runaway `ugrep -rn /` held these cores
/// at 0.0% idle, and a neighbouring 10M scan sat near 85%". **That sentence
/// refutes itself and the author did not notice.** 85% is above 0.84. A
/// neighbouring 10M scan — which is the single most likely thing to contend
/// with a cell on this box, as two workers proved by colliding — **passes this
/// guard with one percentage point to spare.**
///
/// Set the two distributions side by side:
///
/// ```text
/// empty box (measured, 6 samples):   86.3 - 90.6 % idle
/// box running a neighbouring scan:   ~85 % idle
/// ```
///
/// They are 1.3pp apart at the edges. **No absolute idle threshold can separate
/// them**, because this host's ambient floor (10-12% of these eight cores, and
/// permanent) is the same order of magnitude as the signal being detected.
/// 0.90 was unsatisfiable; 0.84 cannot discriminate. Picking a constant here is
/// choosing which of the two failures to have, and that is a property of the
/// approach rather than of the number.
///
/// So this guard, as written, catches **catastrophic** contention (the `ugrep`
/// at 0.0% is rejected by any threshold at all) and does **not** reliably catch
/// **realistic** contention. It is deliberately left this way rather than
/// re-tuned, because the measurement it admitted has already been taken and
/// changing the guard afterwards to justify a number is the exact move this
/// whole apparatus exists to refuse.
///
/// **The fix is a different guard, not a different constant** — a delta against
/// a baseline sampled at start-up, or detecting competing processes by name
/// rather than by their aggregate CPU shadow. That is a follow-up.
///
/// Consequently a run admitted by this guard is **not** thereby shown to be
/// uncontended. What shows that is the recorded
/// `pinned_core_idle_fraction_before/after_each_run` compared against
/// `measured_host_idle_baseline`: the guard admitted the run, the samples are
/// what justify it, and those are different claims. Only the second survives
/// scrutiny, which is why both are in the artifact.
///
/// Phase 0b's comparable in-process numbers were taken on this same host with
/// this same furniture running. The baseline is therefore part of the reference
/// condition rather than contamination of it, which is the substantive reason
/// this is a recalibration against measurement and not a relaxation for
/// convenience.
const MIN_IDLE_BEFORE_RUN: f64 = 0.84;

/// Settle time before the post-run sample.
///
/// The post-run check fires just after `drop(daemon)`, when this run's own dirty
/// pages are still being flushed by kernel writeback threads — an ingest thread
/// that wrote thousands of rows across six indexes leaves a tail. Sampling
/// immediately charges the run's own I/O to "a neighbour": observed at 89.2%
/// idle, with `Dirty` back to 220 kB and idle back to 90.0% seconds later, and
/// no foreign process on the box at all. Draining first is what makes the sample
/// measure the box instead of the run that just ended.
const POST_RUN_SETTLE: Duration = Duration::from_millis(2000);

/// The sampling window.
///
/// Widened from 1.5 s after the first quiet-box attempt. This machine's
/// irreducible baseline includes `byobu-status` spawning a shell every few
/// seconds, which pins a fraction of a core for a few hundred milliseconds. A
/// 1.5 s window that straddles one of those bursts reports 83% idle for a box
/// whose average over the following thirty seconds is ~95%, and a whole cell is
/// then discarded over noise contributing ~2% of its CPU.
///
/// Deliberately a change to the *sampling*, not to the *threshold*. The
/// threshold is what the check means; the window is how faithfully a sample
/// estimates it, and a wider window estimates the run it authorises more
/// honestly. Lowering the threshold would have been the other thing — agreeing
/// to measure on a busier box because a quiet one was inconvenient — and that is
/// the move this guard exists to refuse.
///
/// **WIDENING IS NOT FREE, AND THE BEFORE/AFTER PAIR IS WHAT PAYS FOR IT.** A 4 s
/// window can average over a 2 s burst at 60% idle and still report ≥90%. What
/// covers that is the *second* sample: a neighbour that arrives mid-run is
/// caught after the run even when the pre-run sample smoothed it away. So the
/// two checks are not redundant and neither is decoration — collapsing this to a
/// single pre-run check would be a regression that reintroduces exactly the
/// false negative the wider window makes possible.
const IDLE_SAMPLE: Duration = Duration::from_millis(4000);

fn require_a_quiet_box(cores: &[usize], pin: &str) -> Result<f64, String> {
    let idle = cpu_idle_fraction(cores, IDLE_SAMPLE)?;
    if idle < MIN_IDLE_BEFORE_RUN {
        return Err(format!(
            "cores {pin} are only {:.1}% idle before this run starts (need {:.0}%), \
             load average {}. Something else on this box is already running on the cores this \
             run is pinned to, so the latency it would record is a measurement of contention, \
             not of the daemon. `taskset` pins this process tree to those cores; it does not \
             reserve them from unpinned processes. Wait for the box, or re-run when it is \
             quiet — do not report a number taken now.",
            idle * 100.0,
            MIN_IDLE_BEFORE_RUN * 100.0,
            loadavg()
        ));
    }
    Ok(idle)
}

// ---------------------------------------------------------------------------
// Background ingest
// ---------------------------------------------------------------------------

/// The fifth thread: `background_ingest_rows_per_sec` real rows into the
/// daemon's own catalog, on its own connection.
///
/// Ids continue at `rows + k` from the same generator, exactly as 0b's ingest
/// did, so an ingested row is still re-derivable from `(seed, i)` and can never
/// collide with a trace query's source row.
#[allow(clippy::too_many_arguments)]
fn spawn_ingest(
    db: &Path,
    seed: u64,
    rows: u64,
    rate: u64,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicUsize>,
    errors: Arc<AtomicUsize>,
) -> Result<std::thread::JoinHandle<()>, String> {
    let space = generate::dir_space(rows);
    let conn = rusqlite::Connection::open(db).map_err(|e| format!("ingest connection: {e}"))?;
    // NORMAL, not OFF: this one is standing in for the daemon's own write
    // discipline (§4.8 pins the catalog to rusqlite + WAL), and the WAL traffic
    // is precisely what the query side is supposed to be contending with.
    conn.execute_batch(
        "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=5000;",
    )
    .map_err(|e| e.to_string())?;
    // RESUME WHERE THE LAST RUN STOPPED, rather than restarting at `rows`.
    //
    // This is spawned once per run against a catalog the previous run already
    // wrote to. Restarting the generator cursor at `rows` every run re-derives
    // paths that are already present, and because the insert is `OR IGNORE`
    // they are swallowed silently at the contracted rate — so runs 1 and 2
    // would spend their whole duration inserting nothing while still carrying
    // the label "under background ingest". A check that cannot fail, inside the
    // harness whose job is to catch them. Found by reading, not by any
    // assertion; the per-run counts emitted alongside are what make the failure
    // visible to a reader from now on.
    let resume: i64 = conn
        .query_row("SELECT COALESCE(MAX(id), 0) FROM file", [], |r| r.get(0))
        .map_err(|e| format!("reading the ingest resume point: {e}"))?;
    // 20 batches a second, matching 0b's cadence, so the ingest is a steady
    // trickle rather than one burst per second that the p95 could step around.
    let batch = (rate / 20).max(1);

    Ok(std::thread::spawn(move || {
        // Generator cursor and id advance together from here. They are not in
        // step with the injection phase — injection consumed extra generator
        // rows for the duplicates it skipped — so a run's first batch
        // re-attempts a short tail of already-present paths and has them
        // ignored. Bounded by the duplicate count, and self-correcting inside
        // the first second.
        let mut i = resume.max(rows as i64) as u64;
        let mut id = resume.max(rows as i64);
        while !stop.load(Ordering::Relaxed) {
            let t = Instant::now();
            if let Ok(tx) = conn.unchecked_transaction() {
                let mut wrote = 0usize;
                for _ in 0..batch {
                    let r = generate::row(seed, i, space);
                    i += 1;
                    id += 1;
                    let rel = format!("{}/{}", r.parent, r.name);
                    let (name, ext) = split_name(&rel);
                    let nk = shepherd_catalog::norm_key(
                        &rel,
                        shepherd_catalog::PathCasePolicy::Sensitive,
                        shepherd_catalog::PathNormPolicy::Preserve,
                    );
                    // OR IGNORE, because the generator can re-derive a path
                    // already in the corpus and a UNIQUE violation would end
                    // the ingest thread mid-run — which would silently turn a
                    // "under background ingest" cell into a quiescent one.
                    // Counted separately from successes so the substitution is
                    // reported at the rate it actually achieved.
                    match tx.execute(
                        "INSERT OR IGNORE INTO file \
                           (id, root_id, rel_path, name, ext, size, mtime, ctime, atime, \
                            norm_key, first_seen_at, blake3, updated_at) \
                         VALUES (?1, 1, ?2, ?3, ?4, ?5, ?6, ?6, NULL, ?7, ?8, NULL, ?8)",
                        params![
                            id,
                            &rel,
                            &name,
                            &ext,
                            r.size as i64,
                            r.mtime * 1_000_000_000,
                            &nk,
                            0i64
                        ],
                    ) {
                        Ok(n) => wrote += n,
                        Err(_) => {
                            errors.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
                if tx.commit().is_ok() {
                    counter.fetch_add(wrote, Ordering::Relaxed);
                } else {
                    errors.fetch_add(1, Ordering::Relaxed);
                }
            }
            let spent = t.elapsed();
            let target = Duration::from_millis(50);
            if spent < target {
                std::thread::sleep(target - spent);
            }
        }
    }))
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ClassStat {
    queries: u64,
    hits: u64,
    zero_hit: u64,
    lat: Vec<Duration>,
}

impl ClassStat {
    fn merge(&mut self, o: ClassStat) {
        self.queries += o.queries;
        self.hits += o.hits;
        self.zero_hit += o.zero_hit;
        self.lat.extend(o.lat);
    }
    fn report(&self) -> serde_json::Value {
        let p = Percentiles::of(self.lat.clone());
        serde_json::json!({
            "queries": self.queries,
            "mean_hits": self.hits as f64 / self.queries.max(1) as f64,
            "zero_hit": self.zero_hit,
            "zero_hit_pct": self.zero_hit as f64 * 100.0 / self.queries.max(1) as f64,
            "p50_ms": p.p50_ms,
            "p95_ms": p.p95_ms,
            "p99_ms": p.p99_ms,
        })
    }
}

/// §9 M1 leg 2: the metadata bar, through the daemon, on the injected catalog.
pub fn bench_daemon(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let rows = a.rows_override.unwrap_or(c.fixture.rows);
    let state = state_dir(&a.fixtures);
    let db = catalog_db(&a.fixtures);
    if !db.exists() {
        return Err(format!(
            "{} missing — run `shepherd-bench inject-catalog` first",
            db.display()
        ));
    }
    let bin = a
        .daemon_bin
        .clone()
        .ok_or("bench-meta-daemon needs --daemon-bin <path to shepherdd>")?;
    if !bin.exists() {
        return Err(format!("{} does not exist", bin.display()));
    }
    let socket = state.join("bench.sock");

    // Lexical slice only. The semantic 10% belongs to the vector leg; mixing
    // them would corrupt both numbers (bench-contract.toml [query_trace]).
    let trace = generate::load_trace(&c)?;
    let lexical: Vec<(String, String)> = trace
        .iter()
        .filter(|(class, _, _)| c.query_trace.lexical_classes.contains(class))
        .map(|(class, q, _)| (class.clone(), q.clone()))
        .collect();
    let need = c.statistics.runs * c.statistics.queries_per_run;
    if lexical.len() < need {
        return Err(format!(
            "trace holds {} lexical queries; {} runs x {} needs {need}",
            lexical.len(),
            c.statistics.runs,
            c.statistics.queries_per_run
        ));
    }

    let limit = c.execution.result_limit;
    // A diagnostic client count never silently becomes the contract's. It
    // changes the emitted key as well as the number, so a supplementary run
    // cannot overwrite the cell a gate would read.
    let clients = a.diagnostic_clients.unwrap_or(c.execution.query_clients);
    let diagnostic = a.diagnostic_clients.is_some();
    let key = if diagnostic {
        format!("meta_daemon_bench_{}__diagnostic_{clients}c", a.cache)
    } else {
        format!("meta_daemon_bench_{}", a.cache)
    };
    let mut run_stats = Vec::new();
    let mut start_secs: Vec<f64> = Vec::new();
    let mut by_class: std::collections::BTreeMap<String, ClassStat> = Default::default();
    let mut total_hits = 0u64;
    let mut zero_hit = 0u64;
    let mut ingest_total = 0usize;
    let mut ingest_errors = 0usize;
    let mut cpus_allowed = String::from("unknown");
    let mut ingest_per_run: Vec<usize> = Vec::new();
    // WHICH CORES THIS RUN IS ON, checked rather than assumed — and checked
    // against the contract rather than against the command that was typed.
    //
    // Until now this harness read the daemon's mask back from `/proc` and
    // *recorded* it. Recording is not a check: a run launched without `taskset`
    // would have written `0-31` into the artifact and reported a p95 that
    // cleared the bar on four times the contracted cores. The contract's own
    // text says that substitution can flip the winner, so it fails here.
    let actual_pin = actual_pinned_cores()?;
    let contract_core_count = parse_cores(&c.reference_machine.pin_to_cores)?.len();
    let actual_core_count = parse_cores(&actual_pin)?.len();
    // A CORE-SET substitution is permitted with a written reason; a core-COUNT
    // substitution is not, at any price. The contract's heading is literally
    // "CORE COUNT IS PINNED", and its rationale is entirely about count: the
    // scan is embarrassingly parallel, so more cores clears a bar the declared
    // 8-core reference machine fails. Which eight is a property of this box's
    // scheduler; how many is the decision-integrity hazard.
    if let Some(reason) = &a.cores_substitution_reason {
        if actual_core_count != contract_core_count {
            return Err(format!(
                "--cores-substitution-reason permits a different core SET, not a different \
                 core COUNT: this run has {actual_core_count} cores ({actual_pin}) against \
                 the contract's {contract_core_count} ({}). The count is the whole point of \
                 the clause. Reason given was: {reason}",
                c.reference_machine.pin_to_cores
            ));
        }
    } else if !diagnostic && actual_pin != c.reference_machine.pin_to_cores {
        return Err(format!(
            "this run is pinned to cores {actual_pin} but bench-contract.toml fixes \
             {}. The metadata scan is embarrassingly parallel, so a wider mask does not \
             make the number slightly optimistic — it can clear a bar the declared 8-core \
             reference machine fails, which is the substitution [reference_machine] pins \
             the core count to prevent. Re-run under `taskset -c {}`.",
            c.reference_machine.pin_to_cores, c.reference_machine.pin_to_cores
        ));
    }
    // Idle is measured on the cores this run will actually use, which for a
    // diagnostic run need not be the contract's.
    let cores = parse_cores(&actual_pin)?;
    let mut idle_before: Vec<f64> = Vec::new();
    let mut idle_after: Vec<f64> = Vec::new();
    let load_at_start = loadavg();

    // EVERY RUN GETS A FRESH DAEMON, and for a cold cell every run drops the
    // page cache first. This is 0b's "every run opens its own index", ported:
    // the daemon's arena has no persisted form, so a fresh process *is* a fresh
    // index. 0b's note on why this matters applies here unchanged — dropping
    // the cache once and running three back-to-back reports [cold, warm, warm]
    // under a cold label, and "cold over budget while warm passes" is an
    // escalation trigger that the defect would suppress.
    for run in 0..c.statistics.runs {
        // Checked per run, not once at the top: a neighbour that starts up
        // between run 1 and run 2 would otherwise be averaged into the median
        // of runs, and median-of-runs is exactly the statistic that hides one
        // anomalous run.
        // ENFORCED for a contract cell; RECORDED for a supplementary
        // diagnostic. A diagnostic is already stamped as never being the basis
        // of a decision (the contract's own language for the 32-core case), and
        // its job is to discriminate a mechanism — "is 1 client much faster
        // than 4" survives moderate noise, where "is the p95 under 50 ms" does
        // not. The idle fraction is written into the artifact either way, so a
        // diagnostic taken on a busy box says so rather than looking clean.
        if diagnostic {
            idle_before.push(cpu_idle_fraction(&cores, IDLE_SAMPLE)?);
        } else {
            idle_before.push(require_a_quiet_box(&cores, &actual_pin)?);
        }
        if a.cache == "cold" {
            crate::drop_page_cache()
                .map_err(|e| format!("{e}\n(refusing to report run {run} as cold)"))?;
        }
        let (daemon, ready) = Daemon::start(&bin, &state, &socket)?;
        start_secs.push(ready.as_secs_f64());
        cpus_allowed = daemon.cpus_allowed();

        let stop = Arc::new(AtomicBool::new(false));
        let ingested = Arc::new(AtomicUsize::new(0));
        let ing_err = Arc::new(AtomicUsize::new(0));
        let ingest = if c.execution.background_ingest {
            Some(spawn_ingest(
                &db,
                c.fixture.seed,
                rows,
                c.execution.background_ingest_rows_per_sec,
                Arc::clone(&stop),
                Arc::clone(&ingested),
                Arc::clone(&ing_err),
            )?)
        } else {
            None
        };

        // Run r executes lexical[r*1000 .. (r+1)*1000] — distinct queries per
        // run, so per-query cache warming cannot inflate a repeat.
        let slice: Arc<Vec<(String, String)>> = Arc::new(
            lexical[run * c.statistics.queries_per_run..(run + 1) * c.statistics.queries_per_run]
                .to_vec(),
        );
        let next = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..clients {
            let slice = Arc::clone(&slice);
            let next = Arc::clone(&next);
            let mut client = Client::connect(&socket)?;
            handles.push(std::thread::spawn(
                move || -> Result<(Vec<Duration>, std::collections::BTreeMap<String, ClassStat>), String> {
                    let mut lat = Vec::with_capacity(slice.len());
                    let mut per: std::collections::BTreeMap<String, ClassStat> = Default::default();
                    loop {
                        let i = next.fetch_add(1, Ordering::Relaxed);
                        if i >= slice.len() {
                            break;
                        }
                        let (class, q) = &slice[i];
                        // Sent raw. `MetaIndex::search` ASCII-folds the needle
                        // itself, and folding here too would measure a query
                        // the product never sees.
                        let (d, hits) = client.search(q, limit)?;
                        lat.push(d);
                        let e = per.entry(class.clone()).or_default();
                        e.queries += 1;
                        e.hits += hits as u64;
                        if hits == 0 {
                            e.zero_hit += 1;
                        }
                        e.lat.push(d);
                    }
                    Ok((lat, per))
                },
            ));
        }
        let mut lat = Vec::new();
        for h in handles {
            let (l, per) = h.join().map_err(|_| "a query client panicked")??;
            lat.extend(l);
            for (k, v) in per {
                total_hits += v.hits;
                zero_hit += v.zero_hit;
                by_class.entry(k).or_default().merge(v);
            }
        }
        stop.store(true, Ordering::Relaxed);
        if let Some(h) = ingest {
            let _ = h.join();
        }
        let this_run = ingested.load(Ordering::Relaxed);
        ingest_per_run.push(this_run);
        ingest_total += this_run;
        ingest_errors += ing_err.load(Ordering::Relaxed);
        drop(daemon);

        // AND AGAIN, NOW THE RUN IS OVER.
        //
        // The pre-run check samples the box at t=0 and the run then lasts tens
        // of seconds; a neighbour that starts five seconds in would land
        // entirely inside the measurement and be invisible to it. That is the
        // same shape as the ingest cursor bug this harness already shipped
        // once — a check whose sampling window does not cover the claim it is
        // used to support.
        //
        // This runs after `drop(daemon)`, so the harness's own load is gone and
        // anything still occupying these cores is somebody else's. Recorded in
        // the artifact either way, and fatal for a contract cell: a run with a
        // neighbour in it is not slower-but-usable, it is void, and the point
        // of failing here is that it is void *before* it reaches a gate.
        std::thread::sleep(POST_RUN_SETTLE);
        let after = cpu_idle_fraction(&cores, IDLE_SAMPLE)?;
        idle_after.push(after);
        if !diagnostic && after < MIN_IDLE_BEFORE_RUN {
            return Err(format!(
                "cores {actual_pin} are only {:.1}% idle immediately after run {run} \
                 finished (need {:.0}%), load average {}. The box was quiet when this run \
                 started, so a neighbour arrived while it was measuring and part of this \
                 run's latency is their CPU time. Discarding rather than reporting it.",
                after * 100.0,
                MIN_IDLE_BEFORE_RUN * 100.0,
                loadavg()
            ));
        }

        let p = Percentiles::of(lat);
        eprintln!(
            "[bench-meta-daemon/{}] run {run}: p50 {:.2}  p95 {:.2}  p99 {:.2}  max {:.2} ms  \
             (daemon start->ready {:.1}s, cpus {cpus_allowed})",
            a.cache, p.p50_ms, p.p95_ms, p.p99_ms, p.max_ms, start_secs[run]
        );
        run_stats.push(p);
    }

    let rs = RunSet::reduce(run_stats, c.statistics.drift_flag_pct);
    let pass = rs.accepted_p95_ms < c.bars.metadata_p95_ms;
    eprintln!(
        "[bench-meta-daemon/{}] ACCEPTED p95 {:.2} ms vs bar {:.0} ms -> {}",
        a.cache,
        rs.accepted_p95_ms,
        c.bars.metadata_p95_ms,
        if pass { "PASS" } else { "FAIL" }
    );

    // Emitted BEFORE the bar is enforced, so a failing run leaves the evidence
    // that shows why it failed rather than only an exit code.
    crate::emit(
        &a.out,
        &key,
        serde_json::json!({
            "measured_through": "live shepherdd over a Unix socket, client-side send->response",
            "supplementary_diagnostic": diagnostic,
            "contract_query_clients": c.execution.query_clients,
            "cache": a.cache,
            "rows": rows,
            "stats": rs,
            "bar_ms": c.bars.metadata_p95_ms,
            "pass": pass,
            "daemon_start_to_ready_seconds_per_run": start_secs,
            "daemon_cpus_allowed_list": cpus_allowed,
            "harness_cpus_allowed_list": actual_pin,
            "contract_pin_to_cores": c.reference_machine.pin_to_cores,
            "cores_substitution_reason": a.cores_substitution_reason,
            "core_count": actual_core_count,
            "contract_core_count": contract_core_count,
            "pinned_core_idle_fraction_before_each_run": idle_before,
            "pinned_core_idle_fraction_after_each_run": idle_after,
            // The window those fractions are averages OF. Without it a reader
            // can check the idle claim but not what it was an average of, and
            // those are two halves of one assertion — the same reason the
            // per-run ingest counts are split out of their total.
            "pinned_core_idle_sample_window_ms": IDLE_SAMPLE.as_millis() as u64,
            "min_idle_fraction_required": MIN_IDLE_BEFORE_RUN,
            // The host's measured at-rest floor on the pinned cores, so a
            // reader can see what the threshold above was calibrated AGAINST
            // rather than having to trust that it was calibrated at all.
            "measured_host_idle_baseline": 0.884,
            "post_run_settle_ms": POST_RUN_SETTLE.as_millis() as u64,
            "loadavg_at_start": load_at_start,
            "query_clients": clients,
            "client_connections": clients,
            "result_limit": limit,
            "background_rows_ingested": ingest_total,
            // Per run, not only the total: a total cannot distinguish three
            // runs ingesting evenly from one run ingesting everything while two
            // ran quiescent under the same label.
            "background_rows_ingested_per_run": ingest_per_run,
            "background_ingest_errors": ingest_errors,
            "background_ingest_rows_per_sec_target": c.execution.background_ingest_rows_per_sec,
            "mean_hits_per_query": total_hits as f64 / need as f64,
            "zero_hit_queries": zero_hit,
            "by_class": by_class
                .iter()
                .map(|(k, v)| (k.clone(), v.report()))
                .collect::<serde_json::Map<_, _>>(),
            "machine": crate::probe_machine(&c.reference_machine.pin_to_cores),
            "scaled_run_reason": a.scaled_run_reason,
        }),
    )?;

    // A zero-hit query is answered by walking the whole arena and finding
    // nothing, which is fast. A run with zero-hit queries in it reports a p95
    // that is partly a measurement of absence, so this fails the leg rather
    // than footnoting it — the tantivy tokenizer that "scored beautifully while
    // matching nothing" is the precedent.
    if zero_hit > 0 {
        return Err(format!(
            "{zero_hit} of {need} lexical queries returned zero hits. Every lexical query in \
             the committed trace is a substring of a row this corpus contains, so a zero hit \
             means the daemon is not searching the injected catalog — the p95 above is a \
             measurement of absence and must not be reported as a latency."
        ));
    }
    if !pass {
        return Err(format!(
            "the metadata bar is not met through the daemon: accepted p95 {:.2} ms >= {:.0} ms \
             ({} cache, {rows} rows). The result object is written; this is a real failure of \
             §9's M1 leg 2, not a harness error.",
            rs.accepted_p95_ms, c.bars.metadata_p95_ms, a.cache
        ));
    }
    Ok(())
}
