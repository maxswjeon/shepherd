//! Reads and writes over `target`, including OQ-1's sequence allocator.

use rusqlite::{OptionalExtension, params};
use shepherd_core::TargetId;

use crate::{Catalog, CatalogError, Result};

#[derive(Debug, Clone)]
pub struct Target {
    pub id: TargetId,
    pub name: String,
    pub adapter: String,
    pub enabled: bool,
    pub is_third_party: bool,
    pub custody_eligible: bool,
    pub replica_writer_epoch: i64,
    pub replica_hwm: i64,
}

pub struct TargetRepo<'a>(pub &'a mut Catalog);

impl<'a> TargetRepo<'a> {
    pub fn new(cat: &'a mut Catalog) -> Self {
        Self(cat)
    }

    /// Insert a target.
    ///
    /// `custody_eligible` is **forced false** for a third-party target rather
    /// than rejected, and both the schema `CHECK` and
    /// [`crate::migrate::assert_invariants`] stand behind it. Three independent
    /// guards for one property is the level §4.4 asks for: "there is no API,
    /// setting, acknowledgement or migration path that can set it true".
    pub fn insert(
        &mut self,
        name: &str,
        adapter: &str,
        is_third_party: bool,
        custody_eligible: bool,
    ) -> Result<TargetId> {
        let custody = custody_eligible && !is_third_party;
        if custody_eligible && is_third_party {
            tracing::warn!(
                target_name = name,
                "custody_eligible requested on a third-party target and refused (§4.4 invariant)"
            );
        }
        self.0.conn_mut().execute(
            "INSERT INTO target (name, adapter, is_third_party, custody_eligible)
             VALUES (?1, ?2, ?3, ?4)",
            params![name, adapter, is_third_party as i64, custody as i64],
        )?;
        Ok(TargetId::new(self.0.conn().last_insert_rowid()))
    }

    pub fn get(&self, id: TargetId) -> Result<Option<Target>> {
        self.0
            .conn()
            .query_row(
                "SELECT id, name, adapter, enabled, is_third_party, custody_eligible,
                        replica_writer_epoch, replica_hwm
                 FROM target WHERE id = ?1",
                params![id.get()],
                |r| {
                    Ok(Target {
                        id: TargetId::new(r.get(0)?),
                        name: r.get(1)?,
                        adapter: r.get(2)?,
                        enabled: r.get::<_, i64>(3)? != 0,
                        is_third_party: r.get::<_, i64>(4)? != 0,
                        custody_eligible: r.get::<_, i64>(5)? != 0,
                        replica_writer_epoch: r.get(6)?,
                        replica_hwm: r.get(7)?,
                    })
                },
            )
            .optional()
            .map_err(CatalogError::from)
    }

    /// OQ-1: bump and durably record the writer epoch. Called **once per daemon
    /// start**, before any replica write.
    ///
    /// The epoch distinguishes "this writer, this run" from a previous run of
    /// the same writer, which is what lets a restarted daemon recognise its own
    /// prior partial work instead of colliding with it.
    pub fn begin_writer_epoch(&mut self, id: TargetId) -> Result<i64> {
        let tx = self.0.conn_mut().transaction()?;
        tx.execute(
            "UPDATE target SET replica_writer_epoch = replica_writer_epoch + 1 WHERE id = ?1",
            params![id.get()],
        )?;
        let epoch: i64 = tx.query_row(
            "SELECT replica_writer_epoch FROM target WHERE id = ?1",
            params![id.get()],
            |r| r.get(0),
        )?;
        // The commit is the fsync. `synchronous = FULL` (see `crate::PRAGMAS`)
        // is what makes it one.
        tx.commit()?;
        Ok(epoch)
    }

    /// OQ-1's sequence allocator. Returns the next replica sequence number,
    /// durably recorded **before** it is returned.
    ///
    /// Two properties, both load-bearing, both easy to break by "optimising":
    ///
    /// 1. **It never reads LIST.** Deriving the next name from what the remote
    ///    currently lists is what the second design did, and a restarted writer
    ///    then re-derived a name that a lost-but-successful PUT had already
    ///    used.
    /// 2. **It is durable before it returns.** The caller PUTs under the name
    ///    it gets back. If the bump is still in a write buffer when the machine
    ///    dies, the next run hands out the same number, overwrites a valid
    ///    pointer, and orphans a delta segment with nothing left to detect it
    ///    by.
    ///
    /// Allocating and then not using a number is harmless — gaps in the
    /// sequence cost nothing. Reusing one is unrecoverable. That asymmetry is
    /// the whole design.
    pub fn allocate_sequence(&mut self, id: TargetId) -> Result<i64> {
        let tx = self.0.conn_mut().transaction()?;
        let updated = tx.execute(
            "UPDATE target SET replica_hwm = replica_hwm + 1 WHERE id = ?1",
            params![id.get()],
        )?;
        if updated == 0 {
            return Err(CatalogError::Invalid(format!("no such target {id}")));
        }
        let hwm: i64 = tx.query_row(
            "SELECT replica_hwm FROM target WHERE id = ?1",
            params![id.get()],
            |r| r.get(0),
        )?;
        tx.commit()?;
        Ok(hwm)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_third_party_target_cannot_be_given_custody_through_the_api() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let id = TargetRepo::new(&mut cat)
            .insert("plugin-backed", "wasm", true, true)
            .unwrap();
        let t = TargetRepo::new(&mut cat).get(id).unwrap().unwrap();
        assert!(t.is_third_party);
        assert!(
            !t.custody_eligible,
            "§4.4: no API path may set custody on a third-party target"
        );
        // And the catalog still passes its own invariant check.
        crate::migrate::assert_invariants(cat.conn()).unwrap();
    }

    #[test]
    fn a_first_party_target_keeps_custody() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let id = TargetRepo::new(&mut cat)
            .insert("s3", "aws", false, true)
            .unwrap();
        assert!(
            TargetRepo::new(&mut cat)
                .get(id)
                .unwrap()
                .unwrap()
                .custody_eligible
        );
    }

    /// The allocator's contract: strictly increasing, never repeating, and
    /// persisted before it returns.
    #[test]
    fn sequence_allocation_is_monotonic_and_never_repeats() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let id = TargetRepo::new(&mut cat)
            .insert("s3", "aws", false, true)
            .unwrap();
        let mut seen = std::collections::BTreeSet::new();
        let mut last = 0;
        for _ in 0..100 {
            let n = TargetRepo::new(&mut cat).allocate_sequence(id).unwrap();
            assert!(
                n > last,
                "allocation must strictly increase: {n} after {last}"
            );
            assert!(seen.insert(n), "allocation {n} handed out twice");
            last = n;
        }
        assert_eq!(last, 100);
    }

    /// The durability half, as far as an in-process test can observe it: the
    /// bump is committed, so it is visible to a fresh read rather than sitting
    /// only in the allocator's return value.
    #[test]
    fn the_high_water_mark_is_persisted_before_it_is_returned() {
        let dir = std::env::temp_dir().join(format!("shepherd-alloc-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("c.db");
        let handed_out = {
            let mut cat = Catalog::open(&db).unwrap();
            let id = TargetRepo::new(&mut cat)
                .insert("s3", "aws", false, true)
                .unwrap();
            TargetRepo::new(&mut cat).allocate_sequence(id).unwrap()
        };
        // Re-open, as a restarted daemon would. The mark must already be there;
        // if it were not, this run would hand out `handed_out` a second time.
        let mut cat = Catalog::open(&db).unwrap();
        let next = TargetRepo::new(&mut cat)
            .allocate_sequence(TargetId::new(1))
            .unwrap();
        assert!(
            next > handed_out,
            "a restarted writer re-issued {handed_out}: this is the collision that \
             orphans a delta segment"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn writer_epoch_increments_once_per_start() {
        let mut cat = Catalog::open_in_memory().unwrap();
        let id = TargetRepo::new(&mut cat)
            .insert("s3", "aws", false, true)
            .unwrap();
        assert_eq!(TargetRepo::new(&mut cat).begin_writer_epoch(id).unwrap(), 1);
        assert_eq!(TargetRepo::new(&mut cat).begin_writer_epoch(id).unwrap(), 2);
    }

    #[test]
    fn allocating_against_a_missing_target_errors_rather_than_returning_zero() {
        let mut cat = Catalog::open_in_memory().unwrap();
        assert!(
            TargetRepo::new(&mut cat)
                .allocate_sequence(TargetId::new(999))
                .is_err()
        );
    }
}
