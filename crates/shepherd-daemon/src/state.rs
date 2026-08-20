//! Process-wide daemon state, shared by every connection.

use std::sync::{Arc, Mutex, RwLock};
use std::time::Instant;

use shepherd_catalog::writer::{CatalogActor, CatalogWriter};
use shepherd_index::{MetaIndex, MetaIndexBuilder};
use shepherd_proto::response::{CheckStatus, DoctorCheck};
use shepherd_proto::{Capability, ErrorCode, RpcError, capability};
use shepherd_secrets::SecretStore;

use crate::events::EventHub;
use shepherd_obs::paths::Paths;

/// Everything a connection needs that outlives it.
pub struct Daemon {
    pub writer: CatalogWriter,
    pub events: EventHub,
    pub paths: Paths,
    pub started_at: Instant,
    pub capabilities: Vec<Capability>,
    /// Where `credentials_ref` is resolved.
    ///
    /// Read-only from the daemon's point of view: `target.add` looks a handle
    /// up, and no IPC method stores or returns credential material. §4.1 keeps
    /// secrets off the wire and out of the catalog entirely, so this is the one
    /// place in the process that ever holds a resolved value, and it holds it
    /// only for as long as one registration takes.
    ///
    /// Built here rather than per connection so the backend chain — environment
    /// first, then the state directory's keyfile — is one fact about the
    /// process instead of a decision each handler re-makes.
    pub secrets: SecretStore,
    /// The §4.6 metadata name index.
    ///
    /// `Option`, not a default-empty index, and the distinction is the whole
    /// point: a daemon whose index failed to build must *refuse* a search, not
    /// answer it with zero hits. "No matches" and "the thing that finds matches
    /// is not there" look identical to a caller and only one of them is an
    /// answer — this project has already shipped that confusion once, in the
    /// tantivy tokenizer that scored beautifully while matching nothing.
    ///
    /// `RwLock<Option<Arc<_>>>` so a rebuild constructs the new arena off to the
    /// side and swaps it in under a momentary write lock. At 10M rows a rebuild
    /// is seconds; holding a lock across it would stall every concurrent search
    /// for that long, and in-place mutation would expose a half-built arena.
    ///
    /// The generation beside it is what stops a slow rebuild from winning. See
    /// [`Daemon::install_snapshot`].
    index: RwLock<Indexed>,
    /// Hands out the generation numbers that order snapshots.
    ///
    /// Held across pinning the read snapshot, and for nothing else — see
    /// [`Daemon::build_snapshot`]. The `u64` inside is the last ticket issued.
    snapshot_ticket: Mutex<u64>,
    /// Held so the actor and its WAL-checkpoint thread live as long as the
    /// daemon. Never used directly — `writer` is the handle.
    _actor: CatalogActor,
}

/// The installed index, and the generation of the catalog snapshot it was read
/// from.
///
/// The two travel together because they are only meaningful together: the
/// generation exists to answer "is what I just built newer than what is already
/// installed", and a generation stored apart from the index it describes is a
/// second thing to keep in step.
#[derive(Default)]
struct Indexed {
    index: Option<Arc<MetaIndex>>,
    /// 0 before anything is installed, so the first real generation (1) wins.
    generation: u64,
}

/// A built index, tagged with the generation of the snapshot it came from.
///
/// Returned by [`Daemon::build_snapshot`] and consumed by
/// [`Daemon::install_snapshot`], which is what lets a test drive the two halves
/// in an order the scheduler would otherwise have to be bribed to produce.
pub struct IndexSnapshot {
    generation: u64,
    index: MetaIndex,
}

impl IndexSnapshot {
    /// How many entries the built index holds.
    ///
    /// Not `len`, which clippy rightly pairs with `is_empty`: an empty
    /// `IndexSnapshot` is not a meaningful concept here — a catalog with no
    /// rows produces a perfectly valid snapshot of zero entries, and offering
    /// `is_empty` would invite reading that as "there is no snapshot".
    pub fn entries(&self) -> usize {
        self.index.len()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }
}

impl Daemon {
    pub fn new(actor: CatalogActor, events: EventHub, paths: Paths) -> Arc<Self> {
        let writer = actor.handle();
        let paths_for_secrets = paths.secrets();
        Arc::new(Self {
            writer,
            events,
            paths,
            started_at: Instant::now(),
            secrets: SecretStore::with_keyfile(paths_for_secrets),
            index: RwLock::new(Indexed::default()),
            snapshot_ticket: Mutex::new(0),
            // Advertised because the event buffer and its resume cursor exist
            // (`shepherd_proto::event`). Placeholders and hosted inference are
            // NOT advertised: Linux is delete-mode only and Phase 7 has not
            // happened, and advertising a capability this build does not have
            // is worse than omitting one it does.
            capabilities: vec![Capability::new(capability::EVENT_RESUME)],
            _actor: actor,
        })
    }

    /// The metadata index, or the reason there is not one.
    ///
    /// Never synthesises an empty index on failure — see the field docs.
    pub fn index(&self) -> Result<Arc<MetaIndex>, RpcError> {
        let guard = self
            .index
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        // `Arc::clone`, not a copy of the index: one refcount bump per
        // metadata search, so the arena is never duplicated to answer one.
        guard.index.as_ref().map(Arc::clone).ok_or_else(|| {
            RpcError::new(
                ErrorCode::Precondition,
                "the metadata index has not been built; the daemon could not read the \
                 catalog at start-up. Run `shepctl doctor`, then restart the daemon.",
            )
        })
    }

    /// Rebuild the index from the catalog and swap it in.
    ///
    /// **This is the cold-start cost §4.6 accepted for this candidate.** The
    /// arena has no persisted form, so it is paid at every daemon start, and the
    /// daemon starts at every logon. Phase 0b measured it at ~3.5 s for 10M rows.
    ///
    /// A dedicated read-only connection rather than the writer actor: at 10M
    /// rows this read runs for seconds, and routing it through the actor would
    /// block every write — including the scan whose completion triggered it —
    /// for the duration. SQLite's WAL mode is many-readers/one-writer precisely
    /// so this does not have to be serialised (ADR-001).
    ///
    /// Returns the size of the index that is installed **when this call
    /// returns**, which is not always the size of what it built: a rebuild that
    /// finished behind a newer one does not install, and reporting the count it
    /// built would let `scan_exec`'s `indexed=` log describe an index nobody is
    /// searching.
    pub fn rebuild_index(&self) -> Result<usize, String> {
        let snapshot = self.build_snapshot()?;
        Ok(self.install_snapshot(snapshot))
    }

    /// Read the catalog into a new index, tagged with a generation that orders
    /// it against every other concurrent rebuild.
    ///
    /// # Why a ticket, and why the lock is exactly this wide
    ///
    /// The generation has to order *snapshots*, not completions — that is the
    /// whole race. So the ticket is taken while the read snapshot is being
    /// pinned, and released the moment it is: two rebuilds then carry tickets in
    /// the same order as the catalog states they are about to read, and
    /// [`Self::install_snapshot`] can compare them.
    ///
    /// SQLite's `BEGIN` is DEFERRED, so the snapshot is not pinned by the
    /// `BEGIN` — it is pinned by the **first read inside it**. The `COUNT(*)`
    /// is therefore inside the ticket lock rather than after it; moving it out
    /// would issue tickets in an order unrelated to the snapshots they name,
    /// which is the bug wearing a fix's clothes.
    ///
    /// The build itself is outside the lock. At 10M rows it is seconds, and
    /// serialising *that* is the cost this design exists to avoid paying.
    pub fn build_snapshot(&self) -> Result<IndexSnapshot, String> {
        let db = self.paths.catalog();
        let conn = rusqlite::Connection::open_with_flags(
            &db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| format!("opening {} read-only: {e}", db.display()))?;

        // One read transaction across BOTH statements, so the count and the rows
        // come from the same WAL snapshot.
        //
        // Without it these are two auto-commit reads with two snapshots, and any
        // write landing between them — the worker pool runs several scans, and
        // each one's completion rebuilds while another may still be upserting —
        // makes the count disagree with the rows for no reason. The consistency
        // check below would then fail the scan job with a confident message
        // about a partial index that was never partial. Pinning the snapshot is
        // what turns that check from a race detector into a real guard.
        let tx = conn
            .unchecked_transaction()
            .map_err(|e| format!("opening a read snapshot of the catalog: {e}"))?;

        // Reserving up front avoids doubling a several-hundred-megabyte arena,
        // which costs both rebuild time and — because the old and new
        // allocations coexist during a copy — transient RSS charged to AC-46.
        let (generation, expected): (u64, i64) = {
            let mut ticket = self
                .snapshot_ticket
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            // This read is what pins the snapshot, and it happens under the
            // ticket lock. See the doc comment.
            let expected: i64 = tx
                .query_row("SELECT COUNT(*) FROM file", [], |r| r.get(0))
                .map_err(|e| format!("counting catalog rows: {e}"))?;
            *ticket += 1;
            (*ticket, expected)
        };
        let mut builder = MetaIndexBuilder::with_capacity(expected.max(0) as usize);

        // `ORDER BY id` is load-bearing, not tidiness: `MetaIndex` returns hits
        // in push order, so pushing in id order is what makes a paged search
        // return a stable, non-overlapping sequence of pages.
        {
            let mut stmt = tx
                .prepare("SELECT id, rel_path FROM file ORDER BY id")
                .map_err(|e| format!("preparing the index rebuild query: {e}"))?;
            let mut rows = stmt
                .query([])
                .map_err(|e| format!("reading catalog rows: {e}"))?;
            while let Some(row) = rows.next().map_err(|e| format!("reading a row: {e}"))? {
                let id: i64 = row.get(0).map_err(|e| format!("file.id: {e}"))?;
                let rel_path: String = row.get(1).map_err(|e| format!("file.rel_path: {e}"))?;
                builder
                    .push(id, &rel_path)
                    .map_err(|e| format!("building the metadata index: {e}"))?;
            }
        }
        // Read-only and read-only throughout, so there is nothing to commit;
        // dropping the transaction rolls back an empty one.
        drop(tx);

        let built = builder
            .build()
            .map_err(|e| format!("sealing the metadata index: {e}"))?;
        let entries = built.len();
        // Counted, then compared: a rebuild that silently indexed fewer rows
        // than the catalog holds is a search that silently cannot find them.
        if entries as i64 != expected {
            return Err(format!(
                "the metadata index holds {entries} entries but the catalog reported \
                 {expected} rows; refusing to serve searches from a partial index"
            ));
        }
        tracing::info!(
            entries,
            generation,
            resident_bytes = built.resident_bytes(),
            segments = built.segment_count(),
            "metadata index built"
        );
        Ok(IndexSnapshot {
            generation,
            index: built,
        })
    }

    /// Swap `snapshot` in, unless a newer one already landed.
    ///
    /// Returns the number of entries in the index that is installed afterwards.
    ///
    /// # The comparison is the fix
    ///
    /// The worker pool runs four scans, and each one rebuilds when it finishes.
    /// Nothing makes those rebuilds finish in the order they started: a rebuild
    /// that pinned an *earlier* catalog snapshot can be the last one to reach
    /// this function, and an unconditional assignment would then replace a
    /// newer index with an older one. The rows a concurrent scan committed stay
    /// in SQLite and vanish from `search` until something rebuilds again —
    /// which, since a rebuild only happens when a scan completes, can be until
    /// the daemon restarts.
    ///
    /// Rejecting on `<=` rather than `<` costs nothing and keeps the ordering
    /// total: no two builds share a generation, so equality can only mean the
    /// same snapshot being installed twice.
    pub fn install_snapshot(&self, snapshot: IndexSnapshot) -> usize {
        let mut guard = self
            .index
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if snapshot.generation <= guard.generation {
            tracing::info!(
                stale = snapshot.generation,
                installed = guard.generation,
                "discarding a metadata index built from an older catalog snapshot"
            );
            return guard.index.as_ref().map_or(0, |i| i.len());
        }
        let entries = snapshot.index.len();
        guard.index = Some(Arc::new(snapshot.index));
        guard.generation = snapshot.generation;
        tracing::info!(
            entries,
            generation = snapshot.generation,
            "metadata index installed"
        );
        entries
    }

    /// Drop the installed index, so `search` refuses instead of answering from
    /// one that is known to be wrong.
    ///
    /// For the case where the catalog has moved and the rebuild that was
    /// supposed to follow it FAILED. `Daemon::index` has no staleness check —
    /// it hands out whatever is installed — so leaving the pre-change arena in
    /// place means serving it indefinitely, until a scan or a restart happens
    /// to rebuild. Rows the catalog no longer has go on consuming the capped,
    /// file-id-ordered candidate prefix that `hydrate` then drops, and searches
    /// come back short or empty with no indication why.
    ///
    /// "No index" is a state this daemon already models honestly: `search`
    /// answers `Precondition` and `doctor` reports it, precisely so an index
    /// that is absent is never mistaken for one that found nothing.
    ///
    /// The generation is left alone deliberately. It orders SNAPSHOTS, and a
    /// concurrent rebuild reading the newer catalog must still be able to
    /// install — clearing it would let an older in-flight snapshot win.
    pub fn invalidate_index(&self) {
        let mut guard = self
            .index
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if guard.index.take().is_some() {
            tracing::warn!(
                generation = guard.generation,
                "metadata index dropped: the catalog changed and the rebuild that should \
                 have followed it failed. `search` is refused until one succeeds"
            );
        }
    }

    /// The self-checks behind the `doctor` method.
    ///
    /// The lingering check comes from `shepherd_obs::lingering`, shared with
    /// startup and with `shepctl doctor`'s offline path, so the OQ-F wording
    /// exists once.
    pub fn run_checks(&self) -> Result<Vec<DoctorCheck>, RpcError> {
        let mut checks = Vec::new();

        let user = shepherd_obs::lingering::current_user();
        let state = shepherd_obs::lingering::probe(&user);
        checks.push(convert(shepherd_obs::lingering::check(
            &state,
            shepherd_obs::lingering::looks_seated(),
            &user,
        )));

        // Catalog reachability: the writer actor answering at all is the check.
        let reachable = self.writer.try_with(|cat| {
            cat.conn()
                .query_row("SELECT COUNT(*) FROM scan_root", [], |r| r.get::<_, i64>(0))
                .map_err(shepherd_catalog::CatalogError::from)
        });
        checks.push(DoctorCheck {
            name: "catalog".into(),
            status: match &reachable {
                Ok(_) => CheckStatus::Ok,
                Err(_) => CheckStatus::Fail,
            },
            detail: match &reachable {
                Ok(n) => Some(format!(
                    "{} at schema version {}, {n} root(s)",
                    self.paths.catalog().display(),
                    shepherd_catalog::SCHEMA_VERSION
                )),
                Err(e) => Some(e.to_string()),
            },
            remediation: None,
        });

        checks.push(DoctorCheck {
            name: "ipc socket".into(),
            status: CheckStatus::Ok,
            detail: Some(self.paths.socket.display().to_string()),
            remediation: None,
        });

        // Reported because an absent index is the one failure that would
        // otherwise be invisible: `search` would answer, and it would answer
        // nothing, and nothing is a valid-looking result.
        checks.push(match self.index() {
            Ok(index) => DoctorCheck {
                name: "metadata index".into(),
                status: CheckStatus::Ok,
                detail: Some(format!(
                    "{} entries, {:.1} MiB resident, {} scan segment(s)",
                    index.len(),
                    index.resident_bytes() as f64 / (1024.0 * 1024.0),
                    index.segment_count()
                )),
                remediation: None,
            },
            Err(e) => DoctorCheck {
                name: "metadata index".into(),
                status: CheckStatus::Fail,
                detail: Some(e.message),
                remediation: Some("restart the daemon".into()),
            },
        });

        Ok(checks)
    }
}

/// `shepherd_obs::doctor::Check` -> the wire type.
///
/// A conversion rather than a shared type because `shepherd-proto` may not
/// depend on `shepherd-obs` any more than on anything else internal (§4.1
/// rule 1), and because the wire shape should be free to differ from the
/// in-process one.
pub fn convert(c: shepherd_obs::doctor::Check) -> DoctorCheck {
    use shepherd_obs::doctor::CheckStatus as S;
    let (status, detail, remediation) = match c.status {
        S::Ok => (CheckStatus::Ok, None, None),
        S::Warn {
            detail,
            remediation,
        } => (CheckStatus::Warn, Some(detail), remediation),
        S::Fail { detail } => (CheckStatus::Fail, Some(detail), None),
        S::NotApplicable { reason } => (CheckStatus::NotApplicable, Some(reason), None),
    };
    DoctorCheck {
        name: c.name,
        status,
        detail,
        remediation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A daemon over a real catalog file, in its own directory.
    ///
    /// A file, not `:memory:`, because `build_snapshot` opens its own read-only
    /// connection to `paths.catalog()` — a second connection to `:memory:` is a
    /// different, empty database, so an in-memory catalog would make every
    /// snapshot here empty for a reason unrelated to what is under test.
    fn daemon_on_disk(tag: &str) -> (Arc<Daemon>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "shepherd-state-{}-{tag}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let paths = shepherd_obs::paths::Paths {
            state_dir: dir.clone(),
            socket: dir.join("daemon.sock"),
        };
        let catalog = shepherd_catalog::Catalog::open(&paths.catalog()).unwrap();
        let actor = CatalogActor::start(catalog, Some(paths.catalog()));
        let daemon = Daemon::new(actor, crate::events::EventHub::new(8, "test"), paths);
        (daemon, dir)
    }

    /// Add one root and return its id.
    fn add_root(daemon: &Daemon, path: &str) -> shepherd_core::RootId {
        daemon
            .writer
            .try_with({
                let path = path.to_string();
                move |cat| {
                    shepherd_catalog::file_repo::FileRepo::new(cat).insert_root(
                        &path,
                        shepherd_core::StubMode::Delete,
                        shepherd_catalog::PathCasePolicy::Sensitive,
                        shepherd_catalog::PathNormPolicy::Nfc,
                        shepherd_catalog::AtimeMode::Relatime,
                        None,
                        false,
                        &[],
                        shepherd_core::Timestamp::from_nanos(1),
                    )
                }
            })
            .unwrap()
    }

    /// Commit one file row through the writer actor.
    fn add_file(daemon: &Daemon, root: shepherd_core::RootId, rel_path: &str) {
        daemon
            .writer
            .try_with({
                let rel_path = rel_path.to_string();
                move |cat| {
                    let r = shepherd_catalog::file_repo::FileRepo::new(cat)
                        .get_root(root)?
                        .unwrap();
                    shepherd_catalog::file_repo::FileRepo::new(cat).upsert_file(
                        &r,
                        &shepherd_core::FileStat {
                            root,
                            rel_path,
                            size: 1,
                            mtime: shepherd_core::Timestamp::from_nanos(1),
                            ctime: shepherd_core::Timestamp::from_nanos(1),
                            atime: None,
                            blake3: None,
                            ino: shepherd_core::InodeSighting::Unknown,
                        },
                        1,
                        shepherd_core::Timestamp::from_nanos(2),
                    )
                }
            })
            .unwrap();
    }

    fn finds(daemon: &Daemon, needle: &str) -> bool {
        !daemon.index().unwrap().search(needle, 16).ids.is_empty()
    }

    /// A rebuild that pinned an older catalog snapshot must not replace a newer
    /// index, whichever order the two finish in.
    ///
    /// # Why this is written as two explicit halves
    ///
    /// The race needs rebuild A to read an *earlier* snapshot than rebuild B and
    /// yet swap *later*. Calling `rebuild_index` twice cannot produce that — it
    /// reads and swaps in one breath, so the second call always both reads and
    /// swaps last, and the test would pass against the broken code. Spawning two
    /// threads and hoping for the interleaving would be worse: it would pass
    /// most of the time for reasons no one controls.
    ///
    /// So the snapshot and the swap are separate operations and this test
    /// performs them in the order the race requires: build A (one file), commit
    /// a second file, build B (two files), then install **B first and A second**.
    /// That is exactly the four-worker interleaving the finding describes, made
    /// deterministic.
    ///
    /// What is asserted is that `beta.txt` is still findable — the fact a user
    /// would notice — not merely that some counter went the right way. A daemon
    /// that installed A's stale snapshot would still have `beta.txt` in SQLite
    /// and would not find it, which is the bug.
    #[test]
    fn a_rebuild_from_an_older_snapshot_does_not_replace_a_newer_index() {
        let (daemon, dir) = daemon_on_disk("stale-swap");
        let root = add_root(&daemon, "/data");

        add_file(&daemon, root, "alpha.txt");
        let older = daemon.build_snapshot().unwrap();
        assert_eq!(older.entries(), 1, "snapshot A saw one file");

        add_file(&daemon, root, "beta.txt");
        let newer = daemon.build_snapshot().unwrap();
        assert_eq!(newer.entries(), 2, "snapshot B saw both files");
        assert!(
            newer.generation() > older.generation(),
            "the later snapshot must carry the later generation: {} !> {}",
            newer.generation(),
            older.generation()
        );

        // The interleaving: B swaps first, A finishes afterwards.
        assert_eq!(daemon.install_snapshot(newer), 2);
        let installed = daemon.install_snapshot(older);

        assert_eq!(
            installed, 2,
            "the stale swap must leave the newer index in place, and must report the index \
             that is actually installed"
        );
        assert!(
            finds(&daemon, "beta.txt"),
            "`beta.txt` is committed in SQLite; a stale index swap is what makes it \
             unsearchable until the daemon restarts"
        );
        assert!(finds(&daemon, "alpha.txt"));

        let _ = std::fs::remove_dir_all(dir);
    }

    /// The accepting direction, and it is not a formality.
    ///
    /// "Reject an older generation" and "reject everything" are the same code
    /// path seen from one side. Without this, `install_snapshot` could return
    /// early unconditionally and the test above would still pass — the index
    /// would just never update at all, which is a strictly worse version of the
    /// bug being fixed.
    #[test]
    fn a_rebuild_from_a_newer_snapshot_does_replace_the_index() {
        let (daemon, dir) = daemon_on_disk("fresh-swap");
        let root = add_root(&daemon, "/data");

        add_file(&daemon, root, "alpha.txt");
        let first = daemon.build_snapshot().unwrap();
        assert_eq!(daemon.install_snapshot(first), 1);
        assert!(!finds(&daemon, "beta.txt"), "beta.txt does not exist yet");

        add_file(&daemon, root, "beta.txt");
        let second = daemon.build_snapshot().unwrap();
        assert_eq!(
            daemon.install_snapshot(second),
            2,
            "a snapshot newer than the installed one must be installed"
        );
        assert!(
            finds(&daemon, "beta.txt"),
            "a file committed after the last rebuild must be findable once a newer \
             rebuild lands"
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    /// Generations must order *snapshots*, not completions.
    ///
    /// If the ticket were taken after the read snapshot was pinned — outside the
    /// lock, or after the build — two concurrent rebuilds could carry
    /// generations in the opposite order to the catalog states they read, and
    /// the comparison in `install_snapshot` would then confidently enforce the
    /// wrong order. Sequential builds cannot prove that on their own, but they
    /// can pin the property the ordering rests on: a snapshot taken later sees
    /// at least as much as one taken earlier, and carries a strictly greater
    /// generation.
    #[test]
    fn a_later_snapshot_carries_a_later_generation_and_sees_at_least_as_much() {
        let (daemon, dir) = daemon_on_disk("monotonic");
        let root = add_root(&daemon, "/data");

        let mut last_gen = 0;
        let mut last_len = 0;
        for i in 0..4 {
            add_file(&daemon, root, &format!("f{i}.txt"));
            let s = daemon.build_snapshot().unwrap();
            assert!(
                s.generation() > last_gen,
                "generation {} did not advance past {last_gen}",
                s.generation()
            );
            assert!(
                s.entries() >= last_len,
                "snapshot {} saw {} rows, fewer than the earlier {last_len}",
                s.generation(),
                s.entries()
            );
            last_gen = s.generation();
            last_len = s.entries();
        }
        assert_eq!(last_len, 4);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn a_warning_converts_with_its_remediation_intact() {
        let c = shepherd_obs::doctor::Check::new(
            "systemd lingering",
            shepherd_obs::doctor::CheckStatus::warn("off", "loginctl enable-linger sam"),
        );
        let w = convert(c);
        assert_eq!(w.status, CheckStatus::Warn);
        assert_eq!(w.remediation.as_deref(), Some("loginctl enable-linger sam"));
        assert_eq!(w.detail.as_deref(), Some("off"));
    }

    #[test]
    fn every_obs_status_has_a_wire_counterpart() {
        use shepherd_obs::doctor::CheckStatus as S;
        for (s, want) in [
            (S::Ok, CheckStatus::Ok),
            (S::fail("x"), CheckStatus::Fail),
            (
                S::NotApplicable { reason: "x".into() },
                CheckStatus::NotApplicable,
            ),
        ] {
            assert_eq!(
                convert(shepherd_obs::doctor::Check::new("n", s)).status,
                want
            );
        }
    }
}
