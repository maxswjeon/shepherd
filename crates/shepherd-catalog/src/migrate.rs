//! Migration runner and the invariant re-assertion.
//!
//! Migrations are applied inside one transaction each, so a partially-applied
//! schema is not a reachable state, and recorded in `schema_migration` so a
//! second open is a no-op.

use rusqlite::{Connection, params};

use crate::schema::{MIGRATION_0001, SCHEMA_VERSION};
use crate::{CatalogError, Result};

/// Every migration, in order. Adding one is appending a row here; the runner
/// applies whatever is not yet recorded.
/// Every migration, in order. Adding one is appending a row here; the runner
/// applies whatever is not yet recorded.
///
/// **There is one, and while the project is greenfield there will stay one.**
/// Nothing is deployed and no catalog exists outside our own test runs, so a
/// follow-on migration would encode history that never happened — and a
/// migration chain that lies about the past is worse than one that is short.
/// `job.run_after` and `scan_root.destruction_ineligible` briefly lived as 0002
/// and 0003 and were folded back in; that consolidation is deliberate, not an
/// edit to an applied migration.
///
/// This changes at M2. Once a real catalog exists on a real machine, 0001 is
/// frozen and every change is additive.
const MIGRATIONS: &[(i64, &str, &str)] = &[(1, "initial schema (§4.4)", MIGRATION_0001)];

pub fn migrate(conn: &mut Connection) -> Result<()> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_migration (
             version    INTEGER PRIMARY KEY,
             name       TEXT    NOT NULL,
             applied_at INTEGER NOT NULL
         )",
    )?;

    for (version, name, ddl) in MIGRATIONS {
        let already: i64 = conn.query_row(
            "SELECT COUNT(*) FROM schema_migration WHERE version = ?1",
            params![version],
            |r| r.get(0),
        )?;
        if already > 0 {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(ddl)?;
        tx.execute(
            "INSERT INTO schema_migration (version, name, applied_at) VALUES (?1, ?2, ?3)",
            params![version, name, now_nanos()],
        )?;
        tx.commit()?;
        tracing::info!(version, name, "applied catalog migration");
    }

    let found: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_migration",
        [],
        |r| r.get(0),
    )?;
    if found != SCHEMA_VERSION {
        return Err(CatalogError::SchemaVersion {
            found,
            expected: SCHEMA_VERSION,
        });
    }
    Ok(())
}

/// Re-assert the schema invariants that a `CHECK` constraint alone cannot hold.
///
/// §4.4 requires the third-party custody invariant to be re-asserted "on every
/// **load, import, migration and restart**", and the reason is specific: a
/// `CHECK` constrains rows this build writes. It does **not** constrain a
/// database file produced somewhere else — an import, a restore from a backup
/// taken under an older schema, or a row hand-edited with the `sqlite3` CLI
/// while the daemon was stopped. AC-38's gate attacks exactly those four paths.
///
/// So this runs on every open, and it is a hard error rather than a repair: a
/// catalog claiming a plugin-backed target holds sole custody of destroyed
/// files is not something to silently fix and continue from.
pub fn assert_invariants(conn: &Connection) -> Result<()> {
    let violations: i64 = conn.query_row(
        "SELECT COUNT(*) FROM target WHERE is_third_party = 1 AND custody_eligible = 1",
        [],
        |r| r.get(0),
    )?;
    if violations > 0 {
        let names: Vec<String> = conn
            .prepare("SELECT name FROM target WHERE is_third_party = 1 AND custody_eligible = 1")?
            .query_map([], |r| r.get::<_, String>(0))?
            .filter_map(std::result::Result::ok)
            .collect();
        return Err(CatalogError::Invariant(format!(
            "{violations} third-party target(s) marked custody_eligible: {}. \
             §4.4: there is no API, setting, acknowledgement or migration path that may set \
             this. A default can be overridden; an invariant cannot.",
            names.join(", ")
        )));
    }
    Ok(())
}

fn now_nanos() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Catalog;

    #[test]
    fn migration_is_idempotent_across_reopen() {
        let dir = std::env::temp_dir().join(format!("shepherd-mig-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("c.db");
        for _ in 0..3 {
            let cat = Catalog::open(&db).unwrap();
            let rows: i64 = cat
                .conn()
                .query_row("SELECT COUNT(*) FROM schema_migration", [], |r| r.get(0))
                .unwrap();
            assert_eq!(
                rows,
                MIGRATIONS.len() as i64,
                "re-opening must not re-apply a migration"
            );
        }
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn every_table_in_the_sketch_exists() {
        let cat = Catalog::open_in_memory().unwrap();
        // Named explicitly rather than counted, so adding a table does not
        // silently satisfy a count while a different one went missing.
        for t in [
            "scan_root",
            "file",
            "tag",
            "file_tag",
            "embedding",
            "label_prototype",
            "target",
            "remote_object",
            "object_location",
            "rule",
            "delete_policy",
            "job",
            "transfer_session",
            "transfer_part",
            "schedule",
            "destroy_intent",
            "discard_episode",
            "discard_candidate",
            "discard_rate_window",
            "deferral",
            "model",
            "audit_hosted",
            "setting",
        ] {
            let n: i64 = cat
                .conn()
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?1",
                    params![t],
                    |r| r.get(0),
                )
                .unwrap();
            assert_eq!(n, 1, "table `{t}` missing from migration 0001");
        }
    }

    /// The CHECK constraint blocks the row this build would write.
    #[test]
    fn check_constraint_rejects_third_party_custody() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let err = cat.conn_mut().execute(
            "INSERT INTO target (name, adapter, is_third_party, custody_eligible)
             VALUES ('plug', 'wasm', 1, 1)",
            [],
        );
        assert!(err.is_err(), "CHECK must reject third-party + custody");

        // The legal combinations still insert.
        cat.conn_mut()
            .execute(
                "INSERT INTO target (name, adapter, is_third_party, custody_eligible)
                 VALUES ('plug', 'wasm', 1, 0)",
                [],
            )
            .unwrap();
        cat.conn_mut()
            .execute(
                "INSERT INTO target (name, adapter, is_third_party, custody_eligible)
                 VALUES ('s3', 'aws', 0, 1)",
                [],
            )
            .unwrap();
    }

    /// And `assert_invariants` catches what the CHECK cannot: a database that
    /// arrived from somewhere else already holding the forbidden state. This is
    /// the "hand-edited row + restart" leg of AC-38's attack.
    #[test]
    fn assert_invariants_catches_an_imported_violation() {
        let cat = Catalog::open_in_memory().unwrap();
        // Reproduce a foreign database: same schema, no CHECK.
        cat.conn()
            .execute_batch(
                "CREATE TABLE t2 (name TEXT, is_third_party INT, custody_eligible INT);
                 DROP TABLE target;
                 ALTER TABLE t2 RENAME TO target;
                 INSERT INTO target VALUES ('sneaky-plugin', 1, 1);",
            )
            .unwrap();
        let err = assert_invariants(cat.conn()).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("sneaky-plugin"), "{msg}");
        assert!(msg.contains("custody_eligible"), "{msg}");
    }

    #[test]
    fn assert_invariants_passes_on_a_clean_catalog() {
        let cat = Catalog::open_in_memory().unwrap();
        assert_invariants(cat.conn()).unwrap();
    }

    /// A file can hold one deferral per `(target, kind)`, not one in total.
    ///
    /// `file_id PRIMARY KEY` allowed exactly one row per file, while a deferral
    /// is validated as belonging to a specific `(file, target, kind)`. A file
    /// replicated to two targets therefore could not hold independent
    /// remote-discard windows, and a local deferral could not coexist with a
    /// remote one: the second write either failed or replaced the first, and a
    /// pending window disappearing is a deferral expiring early or an operation
    /// refused forever.
    #[test]
    fn deferrals_are_keyed_by_file_target_and_kind() {
        let cat = Catalog::open_in_memory().unwrap();
        cat.conn()
            .execute_batch(
                "INSERT INTO scan_root (id, path, stub_mode, created_at)
                     VALUES (1, '/data', 'delete', 0);
                 INSERT INTO file (id, root_id, rel_path, name, size, mtime, ctime,
                                   norm_key, first_seen_at, updated_at)
                     VALUES (1, 1, 'a', 'a', 0, 0, 0, 'a', 0, 0);
                 INSERT INTO target (id, name, adapter) VALUES (1, 'a', 's3'), (2, 'b', 's3');",
            )
            .unwrap();

        let add = |target: Option<i64>, kind: &str| {
            cat.conn().execute(
                "INSERT INTO deferral (file_id, target_id, trigger_kind, deferred_at,
                                       wall_clock_deadline)
                 VALUES (1, ?1, ?2, 0, 0)",
                rusqlite::params![target, kind],
            )
        };
        add(Some(1), "remote").expect("a window on the first target");
        add(Some(2), "remote").expect("and an independent one on the second");
        add(None, "local").expect("and a local deferral alongside both");

        // The identity is still an identity: the same three fields twice is a
        // duplicate, including the NULL target that a plain multi-column
        // PRIMARY KEY would have treated as distinct every time.
        assert!(
            add(Some(1), "remote").is_err(),
            "duplicate (file, target, kind)"
        );
        assert!(
            add(None, "local").is_err(),
            "two local deferrals for one file are the same deferral twice"
        );

        // Deregistering a target takes its deferrals with it. The window was
        // about discarding an object ON that target, and nulling the column
        // instead would collide two deregistered targets into one identity.
        cat.conn()
            .execute("DELETE FROM target WHERE id = 1", [])
            .unwrap();
        let left: i64 = cat
            .conn()
            .query_row("SELECT COUNT(*) FROM deferral", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            left, 2,
            "target 1's deferral went with it, the others stayed"
        );
    }

    /// The whole-object checksum is stored as a VALUE, not only as a kind.
    ///
    /// `verify_upload` captures a provider checksum specifically so later scrub
    /// passes can compare without egress — that is the entire reason the upload
    /// asks for one. With only `checksum_kind` persisted, the value was lost the
    /// moment the verification result left memory, so after a restart the
    /// advertised checksum-based scrub had nothing to compare and had to re-read
    /// every object, or treat the KIND as evidence of integrity.
    ///
    /// `checksum_algorithm` is not a duplicate of `checksum_kind`: the kind says
    /// what the value is worth (a real content hash, or an opaque ETag), the
    /// algorithm says how to reproduce it. A scrub needs both.
    #[test]
    fn a_remote_object_stores_the_checksum_and_not_only_its_kind() {
        let cat = Catalog::open_in_memory().unwrap();
        cat.conn()
            .execute_batch(
                "INSERT INTO target (id, name, adapter) VALUES (1, 'a', 's3');
                 INSERT INTO remote_object
                     (id, target_id, key, size, checksum_kind, checksum_algorithm, checksum_value)
                     VALUES (1, 1, 'objects/aa/bb/aabb', 10,
                             'provider-content-hash', 'crc32c', 'q1B2Yg==');",
            )
            .unwrap();

        let (kind, algorithm, value): (String, String, String) = cat
            .conn()
            .query_row(
                "SELECT checksum_kind, checksum_algorithm, checksum_value FROM remote_object",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
            .unwrap();
        assert_eq!(kind, "provider-content-hash", "what the value is worth");
        assert_eq!(algorithm, "crc32c", "how to reproduce it");
        assert_eq!(
            value, "q1B2Yg==",
            "and the value itself, which is the point"
        );
    }
}
