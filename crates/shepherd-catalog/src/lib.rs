//! SQLite (WAL) catalog: schema, migrations, repositories and the intent journal.
//!
//! # What this crate is for
//!
//! P1's restated truth model splits the catalog three ways. Most of it is
//! **derived** and can be rebuilt by re-scanning. Some of it is **custody** —
//! the *only address* of a destroyed original, recoverable solely via the
//! replica. The rest is **durable config**, derived from nothing. Losing a
//! derived row costs a re-scan; losing a custody row loses the file.
//!
//! # Single writer, carried by the type system
//!
//! SQLite's WAL model is many-readers/one-writer, and every mutating method
//! takes `&mut self`, so a caller cannot hold two writers without the borrow
//! checker objecting.
//!
//! **The crate does not spawn anything on your behalf.** `Catalog::open` gives
//! you a connection and nothing runs unless you run it.
//! [`writer::CatalogActor::start`] is opt-in, and it is the *same* single-writer
//! invariant `&mut self` enforces within a thread, extended across them — which
//! is why it lives here rather than in whichever crate happened to need it
//! first. `rusqlite` over `sqlx` is an ADR-001 decision for the same
//! reason: `sqlx` silently upgrades a `SELECT` that later writes in the same
//! transaction into an exclusive write transaction, starving the pool.

pub mod atime;
pub mod file_repo;
pub mod identity;
pub mod intent;
pub mod job_repo;
pub mod migrate;
pub mod schema;
pub mod target_repo;
pub mod volume;
pub mod writer;

use std::path::Path;

use rusqlite::Connection;

pub use atime::AtimeMode;
pub use identity::{PathCasePolicy, PathNormPolicy, content_key, norm_key};
pub use schema::SCHEMA_VERSION;

#[derive(Debug, thiserror::Error)]
pub enum CatalogError {
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),
    #[error("schema invariant violated: {0}")]
    Invariant(String),
    #[error("catalog is at schema version {found}, this build expects {expected}")]
    SchemaVersion { found: i64, expected: i64 },
    #[error("{0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, CatalogError>;

/// Connection pragmas, applied on every open.
///
/// * `journal_mode = WAL` — many readers, one writer, and readers never block
///   the writer. The catalog is read by search while a scan is ingesting.
/// * `foreign_keys = ON` — off by default in SQLite. Without it every
///   `REFERENCES` in the schema is documentation.
/// * `synchronous = FULL` — **an invariant, not a tuning choice.** OQ-1's
///   sequence allocator bumps `target.replica_hwm` and must be durable *before*
///   it returns, because the PUT that follows uses the name it just handed out.
///   With a soft fsync a crash replays the allocation, and a **restarted**
///   writer — not a concurrent one — hands out an already-used name, silently
///   overwrites a valid pointer, and orphans a delta segment with no way to
///   detect it. That failure is why the replica design is on its third
///   revision. The same applies to `replica_writer_epoch`, incremented and
///   made durable once per daemon start.
///
///   If you are here because a profile showed `synchronous = FULL` costing
///   write throughput: the answer is to batch fewer, larger transactions, not
///   to relax this. See the comment at `target.replica_hwm` in
///   [`schema::MIGRATION_0001`].
/// * `busy_timeout` — a reader that arrives mid-checkpoint waits rather than
///   returning `SQLITE_BUSY` to a user-facing query.
pub const PRAGMAS: &[(&str, &str)] = &[
    ("journal_mode", "WAL"),
    ("foreign_keys", "ON"),
    ("synchronous", "FULL"),
    ("busy_timeout", "5000"),
];

/// A handle to the catalog database.
#[derive(Debug)]
pub struct Catalog {
    conn: Connection,
}

impl Catalog {
    /// Open (creating if absent), apply pragmas, migrate, and assert invariants.
    pub fn open(path: &Path) -> Result<Self> {
        let conn = Connection::open(path)?;
        Self::from_connection(conn)
    }

    /// An in-memory catalog, for tests.
    pub fn open_in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::from_connection(conn)
    }

    fn from_connection(conn: Connection) -> Result<Self> {
        apply_pragmas(&conn)?;
        let mut cat = Self { conn };
        migrate::migrate(&mut cat.conn)?;
        migrate::assert_invariants(&cat.conn)?;
        Ok(cat)
    }

    /// Read-only access. Any number of these may exist.
    pub fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Write access. `&mut` is the single-writer discipline: the borrow checker
    /// refuses a second concurrent writer rather than SQLite refusing it at
    /// runtime.
    pub fn conn_mut(&mut self) -> &mut Connection {
        &mut self.conn
    }
}

fn apply_pragmas(conn: &Connection) -> Result<()> {
    for (k, v) in PRAGMAS {
        // `journal_mode` returns the resulting mode as a row; the others do not.
        // `pragma_update` errors on a pragma that returns a value, so the query
        // form is used for all of them and the result discarded.
        conn.pragma_update(None, k, v)
            .or_else(|_| conn.query_row(&format!("PRAGMA {k} = {v}"), [], |_| Ok(())))?;
    }
    // A pragma that silently failed to take is worse than one that errored:
    // `synchronous` in particular would leave the allocator's durability claim
    // false while everything still appeared to work.
    let journal: String = conn.query_row("PRAGMA journal_mode", [], |r| r.get(0))?;
    if !journal.eq_ignore_ascii_case("wal") && !journal.eq_ignore_ascii_case("memory") {
        return Err(CatalogError::Invariant(format!(
            "journal_mode is `{journal}`, expected `wal` (or `memory` in tests)"
        )));
    }
    let sync: i64 = conn.query_row("PRAGMA synchronous", [], |r| r.get(0))?;
    // 2 == FULL, 3 == EXTRA. EXTRA is strictly stronger, so it satisfies the
    // durability requirement too.
    if sync < 2 {
        return Err(CatalogError::Invariant(format!(
            "synchronous is {sync}, expected FULL(2) or EXTRA(3) — see PRAGMAS: a soft \
             fsync lets a crash replay a replica sequence allocation and overwrite a \
             valid pointer"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_applies_pragmas_and_migrates() {
        let cat = Catalog::open_in_memory().unwrap();
        let v: i64 = cat
            .conn()
            .query_row("SELECT MAX(version) FROM schema_migration", [], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(v, SCHEMA_VERSION);
        let fk: i64 = cat
            .conn()
            .query_row("PRAGMA foreign_keys", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            fk, 1,
            "foreign_keys is OFF by default and must be turned ON"
        );
    }

    /// The durability requirement is checked, not assumed. A pragma that
    /// silently failed to take would leave the allocator's claim false while
    /// everything still appeared to work.
    #[test]
    fn synchronous_is_full_or_stronger() {
        let cat = Catalog::open_in_memory().unwrap();
        let sync: i64 = cat
            .conn()
            .query_row("PRAGMA synchronous", [], |r| r.get(0))
            .unwrap();
        assert!(
            sync >= 2,
            "synchronous={sync}, expected FULL(2) or EXTRA(3)"
        );
    }

    #[test]
    fn a_file_backed_catalog_uses_wal() {
        let dir = std::env::temp_dir().join(format!("shepherd-cat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("catalog.db");
        {
            let cat = Catalog::open(&db).unwrap();
            let mode: String = cat
                .conn()
                .query_row("PRAGMA journal_mode", [], |r| r.get(0))
                .unwrap();
            assert_eq!(mode.to_lowercase(), "wal");
        }
        std::fs::remove_dir_all(&dir).ok();
    }
}
