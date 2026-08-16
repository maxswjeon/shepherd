//! Reads and writes over `scan_root` and `file`.
//!
//! The one thing to understand before changing anything here: **lookups that
//! answer "does this file still exist?" go through `norm_key`, never
//! `rel_path`.** A watcher event arriving in a different Unicode normalization
//! than the scan that wrote the row produces a `rel_path` miss, the miss reads
//! as absence, and PM-3 calls absence discard-trigger territory. `rel_path`
//! remains the unique key for *storage*; `norm_key` is the key for *matching*.

use rusqlite::{OptionalExtension, params};
use shepherd_core::{Blake3Hash, FileStat, RootId, StubMode, Timestamp};

use crate::atime::AtimeMode;
use crate::identity::{PathCasePolicy, PathNormPolicy, norm_key};
use crate::{Catalog, CatalogError, Result};

/// A registered scan root, as far as identity is concerned.
#[derive(Debug, Clone)]
pub struct ScanRoot {
    pub id: RootId,
    pub path: String,
    pub stub_mode: StubMode,
    pub case_policy: PathCasePolicy,
    pub norm_policy: PathNormPolicy,
    pub atime_mode: AtimeMode,
    pub volume_id: Option<String>,
    /// PM-3: while set, ALL tiering, destruction and discard for this root are
    /// refused.
    pub resync_required: bool,
    pub availability: Availability,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Availability {
    Available,
    Unavailable,
    Unmounted,
}

impl Availability {
    pub fn as_str(self) -> &'static str {
        match self {
            Availability::Available => "available",
            Availability::Unavailable => "unavailable",
            Availability::Unmounted => "unmounted",
        }
    }
    fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "available" => Availability::Available,
            "unavailable" => Availability::Unavailable,
            "unmounted" => Availability::Unmounted,
            _ => return None,
        })
    }
}

impl ScanRoot {
    /// Whether this root may take part in any operation that destroys anything.
    ///
    /// Both guards are PM-3's. A root needing resync has a gap in its event
    /// history, so its catalog rows may not reflect the disk. An unavailable
    /// root cannot be observed at all, and §4.4 is explicit that such a root
    /// "processes ZERO absences" — a file missing from an unmounted volume is
    /// not evidence the user deleted it.
    pub fn may_destroy(&self) -> bool {
        !self.resync_required && self.availability == Availability::Available
    }

    /// The `norm_key` for a path under this root, using this root's policies.
    pub fn norm_key(&self, rel_path: &str) -> String {
        norm_key(rel_path, self.case_policy, self.norm_policy)
    }
}

pub struct FileRepo<'a>(pub &'a mut Catalog);

impl<'a> FileRepo<'a> {
    pub fn new(cat: &'a mut Catalog) -> Self {
        Self(cat)
    }

    /// Register a scan root with its probed identity policies.
    #[allow(clippy::too_many_arguments)]
    pub fn insert_root(
        &mut self,
        path: &str,
        stub_mode: StubMode,
        case_policy: PathCasePolicy,
        norm_policy: PathNormPolicy,
        atime_mode: AtimeMode,
        volume_id: Option<&str>,
        now: Timestamp,
    ) -> Result<RootId> {
        let stub = match stub_mode {
            StubMode::Dehydrate => "dehydrate",
            StubMode::Delete => "delete",
        };
        self.0.conn_mut().execute(
            "INSERT INTO scan_root
                 (path, stub_mode, path_case_policy, path_norm_policy, atime_mode,
                  volume_id, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![
                path,
                stub,
                case_policy.as_str(),
                norm_policy.as_str(),
                atime_mode.as_str(),
                volume_id,
                now.as_nanos()
            ],
        )?;
        Ok(RootId::new(self.0.conn().last_insert_rowid()))
    }

    pub fn get_root(&self, id: RootId) -> Result<Option<ScanRoot>> {
        self.0
            .conn()
            .query_row(
                "SELECT id, path, stub_mode, path_case_policy, path_norm_policy,
                        atime_mode, volume_id, resync_required, availability
                 FROM scan_root WHERE id = ?1",
                params![id.get()],
                row_to_root,
            )
            .optional()
            .map_err(CatalogError::from)?
            .transpose()
    }

    /// PM-3: set or clear the resync gate. Setting it is loud on purpose —
    /// journal overflow means the event history has a hole.
    pub fn set_resync_required(&mut self, id: RootId, required: bool) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE scan_root SET resync_required = ?2 WHERE id = ?1",
            params![id.get(), required as i64],
        )?;
        if required {
            tracing::warn!(root = %id, "resync-required set: tier/destroy/discard refused for this root");
        }
        Ok(())
    }

    pub fn set_availability(&mut self, id: RootId, availability: Availability) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE scan_root SET availability = ?2 WHERE id = ?1",
            params![id.get(), availability.as_str()],
        )?;
        Ok(())
    }

    /// Insert or update one file row.
    ///
    /// `norm_key` is computed here from the root's policies rather than taken
    /// from the caller, so no call site can forget it or compute it with the
    /// wrong root's policy.
    pub fn upsert_file(&mut self, root: &ScanRoot, stat: &FileStat, now: Timestamp) -> Result<()> {
        if stat.root != root.id {
            return Err(CatalogError::Invalid(format!(
                "FileStat belongs to {} but was upserted against root {}",
                stat.root, root.id
            )));
        }
        let nk = root.norm_key(&stat.rel_path);
        let (name, ext) = split_name(&stat.rel_path);
        self.0.conn_mut().execute(
            "INSERT INTO file
                 (root_id, rel_path, name, ext, size, mtime, ctime, atime,
                  norm_key, first_seen_at, blake3, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?10)
             ON CONFLICT(root_id, rel_path) DO UPDATE SET
                 name = excluded.name, ext = excluded.ext, size = excluded.size,
                 mtime = excluded.mtime, ctime = excluded.ctime, atime = excluded.atime,
                 norm_key = excluded.norm_key, updated_at = excluded.updated_at,
                 -- first_seen_at is NEVER overwritten: §4.12 makes it the
                 -- min-age floor source where mtime is untrusted or in the
                 -- future, and a re-scan must not reset a file's apparent age.
                 blake3 = COALESCE(excluded.blake3, file.blake3)",
            params![
                root.id.get(),
                stat.rel_path,
                name,
                ext,
                stat.size as i64,
                stat.mtime.as_nanos(),
                stat.ctime.as_nanos(),
                stat.atime.map(|t| t.as_nanos()),
                nk,
                now.as_nanos(),
                stat.blake3.map(|h| h.as_bytes().to_vec()),
            ],
        )?;
        Ok(())
    }

    /// Look up by the **matching** key. This is what watcher events use.
    ///
    /// Returns every row whose `norm_key` matches, which on a case-sensitive
    /// root can legitimately be more than one (`Report.txt` and `report.txt`
    /// under an `insensitive` policy fold together). Returning a `Vec` rather
    /// than an `Option` is deliberate: an event that matches two rows is an
    /// ambiguity the caller must resolve by `fs_id`, not something this layer
    /// should silently pick a winner for.
    pub fn find_by_norm_key(&self, root: &ScanRoot, rel_path: &str) -> Result<Vec<i64>> {
        let nk = root.norm_key(rel_path);
        let mut stmt = self
            .0
            .conn()
            .prepare("SELECT id FROM file WHERE root_id = ?1 AND norm_key = ?2")?;
        let ids = stmt
            .query_map(params![root.id.get(), nk], |r| r.get::<_, i64>(0))?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        Ok(ids)
    }

    /// Record a hash without touching anything else. §6 Phase 1 makes hashing
    /// its own job class, so it arrives after the row exists.
    pub fn set_blake3(&mut self, file_id: i64, hash: Blake3Hash, now: Timestamp) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE file SET blake3 = ?2, updated_at = ?3 WHERE id = ?1",
            params![file_id, hash.as_bytes().to_vec(), now.as_nanos()],
        )?;
        Ok(())
    }

    /// Record a Shepherd-observed access (§4.12 step 2).
    ///
    /// `src` records which signal drove it, so a dry-run preview can state what
    /// actually matched rather than implying `atime` did.
    pub fn note_access(&mut self, file_id: i64, at: Timestamp, src: AccessSignal) -> Result<()> {
        self.0.conn_mut().execute(
            "UPDATE file SET last_observed_access = ?2, access_signal_src = ?3 WHERE id = ?1",
            params![file_id, at.as_nanos(), src.as_str()],
        )?;
        Ok(())
    }
}

/// Which signal drove an access timestamp (§4.12 step 3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessSignal {
    /// Shepherd saw the access itself — a hydration, a restore, a served open.
    Observed,
    /// OS atime, folded in only where fidelity is `reliable`.
    Atime,
    /// Last resort where no access signal exists at all.
    Mtime,
}

impl AccessSignal {
    pub fn as_str(self) -> &'static str {
        match self {
            AccessSignal::Observed => "observed",
            AccessSignal::Atime => "atime",
            AccessSignal::Mtime => "mtime",
        }
    }
}

fn row_to_root(row: &rusqlite::Row<'_>) -> rusqlite::Result<Result<ScanRoot>> {
    let stub: String = row.get(2)?;
    let case: String = row.get(3)?;
    let norm: String = row.get(4)?;
    let at: String = row.get(5)?;
    let avail: String = row.get(8)?;
    Ok((|| {
        Ok(ScanRoot {
            id: RootId::new(row.get(0)?),
            path: row.get(1)?,
            stub_mode: match stub.as_str() {
                "dehydrate" => StubMode::Dehydrate,
                "delete" => StubMode::Delete,
                other => return Err(CatalogError::Invalid(format!("stub_mode `{other}`"))),
            },
            case_policy: match case.as_str() {
                "sensitive" => PathCasePolicy::Sensitive,
                "insensitive" => PathCasePolicy::Insensitive,
                other => return Err(CatalogError::Invalid(format!("path_case_policy `{other}`"))),
            },
            norm_policy: match norm.as_str() {
                "nfc" => PathNormPolicy::Nfc,
                "nfd" => PathNormPolicy::Nfd,
                "preserve" => PathNormPolicy::Preserve,
                other => return Err(CatalogError::Invalid(format!("path_norm_policy `{other}`"))),
            },
            atime_mode: AtimeMode::parse(&at)
                .ok_or_else(|| CatalogError::Invalid(format!("atime_mode `{at}`")))?,
            volume_id: row.get(6)?,
            resync_required: row.get::<_, i64>(7)? != 0,
            availability: Availability::parse(&avail)
                .ok_or_else(|| CatalogError::Invalid(format!("availability `{avail}`")))?,
        })
    })())
}

fn split_name(rel_path: &str) -> (String, Option<String>) {
    let name = rel_path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(rel_path)
        .to_string();
    // A leading dot is not an extension separator: `.gitignore` has no
    // extension, and treating it as one puts every dotfile in the same `ext`
    // bucket, which the (ext, mtime) index then makes useless.
    let ext = name
        .rfind('.')
        .filter(|&i| i > 0)
        .map(|i| name[i + 1..].to_lowercase());
    (name, ext)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stat(root: RootId, rel: &str) -> FileStat {
        FileStat {
            root,
            rel_path: rel.into(),
            size: 10,
            mtime: Timestamp::from_nanos(1),
            ctime: Timestamp::from_nanos(1),
            atime: None,
            blake3: None,
        }
    }

    fn fixture() -> (Catalog, ScanRoot) {
        let mut cat = Catalog::open_in_memory().unwrap();
        let id = FileRepo::new(&mut cat)
            .insert_root(
                "/data",
                StubMode::Delete,
                PathCasePolicy::Sensitive,
                PathNormPolicy::Nfc,
                AtimeMode::Relatime,
                Some("uuid:abc"),
                Timestamp::from_nanos(1),
            )
            .unwrap();
        let root = FileRepo::new(&mut cat).get_root(id).unwrap().unwrap();
        (cat, root)
    }

    /// The whole point of `norm_key`: a watcher event spelled in NFD finds the
    /// row a scan wrote in NFC. Without this the lookup misses, the miss reads
    /// as absence, and absence is discard-trigger territory (PM-3).
    #[test]
    fn an_nfd_event_finds_the_row_written_from_nfc() {
        let (mut cat, root) = fixture();
        let nfc = "caf\u{00e9}/notes.txt";
        let nfd = "cafe\u{0301}/notes.txt";
        FileRepo::new(&mut cat)
            .upsert_file(&root, &stat(root.id, nfc), Timestamp::from_nanos(2))
            .unwrap();

        let repo = FileRepo::new(&mut cat);
        assert_eq!(
            repo.find_by_norm_key(&root, nfd).unwrap().len(),
            1,
            "the NFD spelling must find the NFC row"
        );
        // And the naive lookup is exactly what would have failed.
        let by_path: i64 = cat
            .conn()
            .query_row(
                "SELECT COUNT(*) FROM file WHERE root_id = ?1 AND rel_path = ?2",
                params![root.id.get(), nfd],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            by_path, 0,
            "rel_path lookup misses — this is the bug norm_key fixes"
        );
    }

    #[test]
    fn first_seen_at_survives_a_rescan() {
        let (mut cat, root) = fixture();
        let mut repo = FileRepo::new(&mut cat);
        repo.upsert_file(&root, &stat(root.id, "a.txt"), Timestamp::from_nanos(100))
            .unwrap();
        repo.upsert_file(&root, &stat(root.id, "a.txt"), Timestamp::from_nanos(999))
            .unwrap();
        let first: i64 = cat
            .conn()
            .query_row("SELECT first_seen_at FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(
            first, 100,
            "re-scanning must not reset apparent age — it is the min-age floor source"
        );
    }

    #[test]
    fn a_rescan_without_a_hash_does_not_erase_one() {
        let (mut cat, root) = fixture();
        let mut repo = FileRepo::new(&mut cat);
        let mut s = stat(root.id, "a.txt");
        s.blake3 = Some(Blake3Hash::from_bytes([7; 32]));
        repo.upsert_file(&root, &s, Timestamp::from_nanos(1))
            .unwrap();
        // Hashing is its own job class, so a later metadata-only scan arrives
        // with blake3 = None. It must not clear the hash.
        repo.upsert_file(&root, &stat(root.id, "a.txt"), Timestamp::from_nanos(2))
            .unwrap();
        let h: Option<Vec<u8>> = cat
            .conn()
            .query_row("SELECT blake3 FROM file", [], |r| r.get(0))
            .unwrap();
        assert_eq!(h, Some(vec![7u8; 32]));
    }

    #[test]
    fn a_root_needing_resync_or_unavailable_may_not_destroy() {
        let (mut cat, root) = fixture();
        assert!(root.may_destroy());

        FileRepo::new(&mut cat)
            .set_resync_required(root.id, true)
            .unwrap();
        let r = FileRepo::new(&mut cat).get_root(root.id).unwrap().unwrap();
        assert!(!r.may_destroy(), "PM-3: a resync-required root is gated");

        FileRepo::new(&mut cat)
            .set_resync_required(root.id, false)
            .unwrap();
        FileRepo::new(&mut cat)
            .set_availability(root.id, Availability::Unmounted)
            .unwrap();
        let r = FileRepo::new(&mut cat).get_root(root.id).unwrap().unwrap();
        assert!(
            !r.may_destroy(),
            "PM-3 #2: an unmounted root processes zero absences"
        );
    }

    #[test]
    fn upserting_against_the_wrong_root_is_refused() {
        let (mut cat, root) = fixture();
        let wrong = stat(RootId::new(root.id.get() + 1), "a.txt");
        let err = FileRepo::new(&mut cat).upsert_file(&root, &wrong, Timestamp::from_nanos(1));
        assert!(
            err.is_err(),
            "a row must not be filed under another root's policies"
        );
    }

    #[test]
    fn dotfiles_have_no_extension() {
        assert_eq!(split_name("a/.gitignore"), (".gitignore".into(), None));
        assert_eq!(
            split_name("a/Report.TXT"),
            ("Report.TXT".into(), Some("txt".into()))
        );
        assert_eq!(split_name("noext"), ("noext".into(), None));
    }
}
