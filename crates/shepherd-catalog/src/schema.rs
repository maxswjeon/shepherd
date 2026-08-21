//! Migration 0001 — the whole of §4.4's schema sketch.
//!
//! # Why every table lands at once, including ones no code touches yet
//!
//! Tables for Phase 2 (`discard_episode`, `discard_candidate`, `discard_rate_window`,
//! `deferral`) and Phase 5 (`model`, `audit_hosted`, `embedding`, `label_prototype`)
//! are created here even though nothing reads or writes them this phase. Every one
//! of them would otherwise land in *this* file, weeks apart, edited by three
//! different task owners — the same collision Phase 0a avoided by creating all 21
//! crate skeletons up front. Each such table carries a comment naming the phase and
//! task that implements its use, so their presence is never misread as
//! implementation.
//!
//! # `synchronous = FULL` is an invariant, not a tuning choice
//!
//! See [`crate::PRAGMAS`]. The short version, repeated at `target.replica_hwm`
//! because that is where someone profiling SQLite will be standing: a soft fsync
//! lets a crash replay a sequence allocation, after which a *restarted* writer
//! allocates an already-used name and silently overwrites a valid pointer.

/// Schema version applied by [`crate::migrate::migrate`].
pub const SCHEMA_VERSION: i64 = 1;

/// The full DDL for [`SCHEMA_VERSION`].
///
/// Executed as one batch inside a transaction, so a partially-applied schema is
/// not a reachable state.
pub const MIGRATION_0001: &str = r#"
-- ---------------------------------------------------------------------------
-- Roots
-- ---------------------------------------------------------------------------
CREATE TABLE scan_root (
    id                     INTEGER PRIMARY KEY,
    path                   TEXT    NOT NULL UNIQUE,
    enabled                INTEGER NOT NULL DEFAULT 1,
    stub_mode              TEXT    NOT NULL,          -- dehydrate | delete
    hosted_optin           INTEGER NOT NULL DEFAULT 0,
    ignore_patterns_json   TEXT    NOT NULL DEFAULT '[]',

    -- PM-3: gates ALL tiering, destruction and discard for this root. Set on
    -- journal overflow; cleared only by a completed resync.
    resync_required        INTEGER NOT NULL DEFAULT 0,

    -- PM-3 #2: an unavailable root processes ZERO absences. Absence of a file
    -- under an unmounted root is not evidence the file is gone.
    availability           TEXT    NOT NULL DEFAULT 'available',  -- available | unavailable | unmounted

    -- §4.4/§4.9: filesystem UUID or NTFS volume serial. NEVER st_dev, which is
    -- not stable across remounts for removable media, so a remount would
    -- re-key every row under this root and manufacture false absence.
    volume_id              TEXT,

    -- §4.4: the ENROLLED DIRECTORY's own identity, as `volume::fs_id` builds
    -- one for a file.
    --
    -- `volume_id` says which filesystem the root is on and nothing about WHICH
    -- DIRECTORY on it. A registered root reached through a symlinked ancestor,
    -- or one that is itself a symlink, can be retargeted at another directory
    -- on the same filesystem — and every volume check still passes, so the scan
    -- commits the replacement tree under this root and sweeps the enrolled
    -- tree's rows as absent, stub custody included.
    --
    -- NULL where the identity could not be established at enrollment, which is
    -- the same "unknown, not wrong" the file rows use.
    root_fs_id             TEXT,

    -- §4.12: reliable | relatime | disabled | unknown. On a volume where
    -- last-access updates are off, atime never advances, so "not accessed in
    -- 1 year" eventually matches EVERYTHING, including files in daily use.
    atime_mode             TEXT    NOT NULL DEFAULT 'unknown',

    -- §4.9: probed at enrollment, never assumed. ext4 holds Report.txt and
    -- report.txt as two files; SMB and OneDrive fold them to one.
    path_case_policy       TEXT    NOT NULL DEFAULT 'sensitive',   -- sensitive | insensitive
    path_norm_policy       TEXT    NOT NULL DEFAULT 'preserve',    -- nfc | nfd | preserve

    -- OQ-A: claimed | symlink | delete, chosen per root at runtime. Both macOS
    -- mechanisms ship; this records which one this root uses.
    macos_placeholder_mode TEXT,

    -- D-12 (§4.10.1): this root's filesystem supports neither identity-bound
    -- staging (RENAME_NOREPLACE returns EINVAL on some FUSE/exFAT mounts) nor
    -- enforceable writer exclusion. Such a root is scanned, indexed, searched
    -- and may be COPIED to a target — its originals are simply never destroyed.
    --
    -- Set by a feasibility probe at ENROLLMENT, never discovered at destroy
    -- time. §4.10.1 permits no detect-only fallback: iteration 2 fell back to
    -- pathname deletion and logged the residual, "which directly contradicted
    -- its own fail-closed gate — a plan cannot promise fail-closed and then
    -- ship the failure mode behind a log line".
    destruction_ineligible INTEGER NOT NULL DEFAULT 0,
    destruction_ineligible_reason TEXT,

    journal_cursor         BLOB,                       -- watcher cursor (T6/Phase 4)
    created_at             INTEGER NOT NULL,

    CHECK (stub_mode IN ('dehydrate','delete')),
    CHECK (availability IN ('available','unavailable','unmounted')),
    CHECK (atime_mode IN ('reliable','relatime','disabled','unknown')),
    CHECK (path_case_policy IN ('sensitive','insensitive')),
    CHECK (path_norm_policy IN ('nfc','nfd','preserve')),
    CHECK (macos_placeholder_mode IS NULL
           OR macos_placeholder_mode IN ('claimed','symlink','delete'))
);

-- ---------------------------------------------------------------------------
-- Files
-- ---------------------------------------------------------------------------
CREATE TABLE file (
    id                 INTEGER PRIMARY KEY,
    root_id            INTEGER NOT NULL REFERENCES scan_root(id) ON DELETE CASCADE,
    rel_path           TEXT    NOT NULL,
    name               TEXT    NOT NULL,
    ext                TEXT,
    size               INTEGER NOT NULL,
    mtime              INTEGER NOT NULL,
    ctime              INTEGER NOT NULL,
    atime              INTEGER,

    -- §4.4: (volume_id, inode) on unix, (volume serial, FILE_ID_INFO) on
    -- Windows. Proves "same file" across a rename, and catches
    -- unlink-and-recreate at destroy-time revalidation (PM-1).
    fs_id              BLOB,

    -- §4.9: rel_path normalised and case-folded per THIS root's policy. Watcher
    -- events match against this column, never against rel_path: macOS emits NFD
    -- where Linux preserves bytes, and a lookup in the wrong normalisation
    -- returns false absence, which PM-3 shows is discard-trigger territory.
    norm_key           TEXT    NOT NULL,

    -- §4.12: the min-age floor reads this where mtime is untrusted or in the
    -- future, so a bogus timestamp cannot buy a file past the age floor.
    first_seen_at      INTEGER NOT NULL,

    -- §4.12: Shepherd-owned access signal, uniform across platforms and
    -- strictly better than OS atime. Fed by hydrations, restores and served
    -- opens; OS atime deltas fold in ONLY where fidelity is 'reliable'.
    last_observed_access INTEGER,
    access_signal_src  TEXT,                    -- observed | atime | mtime

    -- NULL until hashed. Hashing is its own job class and never gates
    -- cataloguing (§6 Phase 1).
    blake3             BLOB,

    state              TEXT    NOT NULL DEFAULT 'local',  -- local | stub | remote | missing

    -- What `state` was when the reconciliation sweep marked this row `missing`.
    --
    -- A `stat` cannot tell a dehydrate-mode placeholder from a file with bytes
    -- in it, which is why `upsert_file` preserves `state` at all — so a stub
    -- that vanished for one scan and reappeared would come back as `local`,
    -- claiming the bytes are here while its `object_location` still says they
    -- are remote. Recording what the row was is what lets revival put it back
    -- instead of guessing.
    --
    -- NULL for every row that is not currently `missing`.
    state_before_missing TEXT,
    flags              INTEGER NOT NULL DEFAULT 0,        -- hardlink|sparse|symlink|open (AC-8)
    dirty              INTEGER NOT NULL DEFAULT 0,
    model_version      TEXT,
    last_seen_gen      INTEGER NOT NULL DEFAULT 0,
    updated_at         INTEGER NOT NULL,

    CHECK (state IN ('local','stub','remote','missing')),
    CHECK (access_signal_src IS NULL
           OR access_signal_src IN ('observed','atime','mtime'))
);
CREATE UNIQUE INDEX file_root_relpath ON file(root_id, rel_path);
-- Not UNIQUE: on a case-sensitive root, Report.txt and report.txt legitimately
-- fold to one norm_key and remain two rows. Uniqueness here would corrupt that.
CREATE INDEX file_root_normkey ON file(root_id, norm_key);
CREATE INDEX file_blake3       ON file(blake3);
CREATE INDEX file_state        ON file(state);
CREATE INDEX file_ext_mtime    ON file(ext, mtime);
CREATE INDEX file_size         ON file(size DESC);

-- ---------------------------------------------------------------------------
-- Tags and vectors.  Phase 5 (T-infer/T-extract) implements their use.
-- `embedding` holds only pointers into on-disk ANN shards; vectors are NOT in
-- SQLite (§4.4).
-- ---------------------------------------------------------------------------
CREATE TABLE tag (
    id     INTEGER PRIMARY KEY,
    name   TEXT NOT NULL UNIQUE,
    source TEXT NOT NULL,                       -- builtin | user | deterministic
    CHECK (source IN ('builtin','user','deterministic'))
);
CREATE TABLE file_tag (
    file_id    INTEGER NOT NULL REFERENCES file(id) ON DELETE CASCADE,
    tag_id     INTEGER NOT NULL REFERENCES tag(id)  ON DELETE CASCADE,
    confidence REAL,
    PRIMARY KEY (file_id, tag_id)
);
CREATE TABLE embedding (
    file_id       INTEGER PRIMARY KEY REFERENCES file(id) ON DELETE CASCADE,
    model_id      TEXT    NOT NULL,
    model_version TEXT    NOT NULL,
    dim           INTEGER NOT NULL,
    shard_id      INTEGER NOT NULL,
    vec_ord       INTEGER NOT NULL
);
CREATE TABLE label_prototype (
    id                    INTEGER PRIMARY KEY,
    label                 TEXT NOT NULL,
    description           TEXT,
    example_file_ids_json TEXT NOT NULL DEFAULT '[]',
    proto_vec             BLOB
);

-- ---------------------------------------------------------------------------
-- Targets
-- ---------------------------------------------------------------------------
CREATE TABLE target (
    id                     INTEGER PRIMARY KEY,
    name                   TEXT    NOT NULL UNIQUE,
    adapter                TEXT    NOT NULL,
    config_json            TEXT    NOT NULL DEFAULT '{}',
    credentials_ref        TEXT,
    enabled                INTEGER NOT NULL DEFAULT 1,

    replica_backend        TEXT,

    -- OQ-1. Incremented and fsync'd ONCE per daemon start.
    replica_writer_epoch   INTEGER NOT NULL DEFAULT 0,

    -- OQ-1, and the reason `synchronous = FULL` is not negotiable.
    --
    -- Durable local sequence high-water mark. Allocation bumps this and fsyncs
    -- BEFORE returning, and NEVER reads LIST to decide the next name.
    --
    -- If that fsync is soft, a crash replays the allocation: a RESTARTED writer
    -- — not a concurrent one — hands out an already-used name, silently
    -- overwrites a valid pointer, and orphans a delta segment with no way to
    -- detect it afterwards. That failure is why the replica design is on its
    -- third revision. Persisting the high-water mark before the PUT is what
    -- closes it, and it only closes it if the write is actually durable.
    -- Do not relax `synchronous` to make a profile look better.
    replica_hwm            INTEGER NOT NULL DEFAULT 0,

    replica_head_ptr_blake3 BLOB,               -- tip of the validated hash chain
    replica_head_at        INTEGER,
    replica_state          TEXT,                -- ok | incomplete | forked

    is_third_party         INTEGER NOT NULL DEFAULT 0,   -- WASM-plugin-backed
    custody_eligible       INTEGER NOT NULL DEFAULT 0,

    -- §4.10.2, probed at target registration. A literal conjunct of the destroy
    -- predicate — `L.attestation_mode != none` — so T8/T10 cannot express the
    -- predicate without it.
    --
    -- DEFAULT 'none' is the fail-closed direction: a target that was never
    -- probed cannot authorize a destruction. §4.10.2's S3 rider is why this is
    -- a column rather than an assumption — bucket versioning is OFF by default,
    -- so an ordinary S3/MinIO bucket is mechanism B, and "silently landing on B
    -- while believing A is exactly how a safety claim decays into a slogan".
    attestation_mode       TEXT    NOT NULL DEFAULT 'none',

    -- §4.4 INVARIANT: is_third_party = 1  =>  custody_eligible = 0.
    --
    -- There is no API, setting, acknowledgement or migration path that may set
    -- custody_eligible on a third-party target. "Defaults false" was the
    -- iteration-4 wording and is explicitly NOT the rule: a default can be
    -- overridden, an invariant cannot. AC-38's gate attacks this through the
    -- API, an import, a hand-edited row plus restart, and a migration — so the
    -- CHECK below is necessary and not sufficient, and
    -- `migrate::assert_invariants` re-asserts it on every open.
    CHECK (is_third_party = 0 OR custody_eligible = 0),
    CHECK (attestation_mode IN ('version','content','none')),
    CHECK (replica_state IS NULL OR replica_state IN ('ok','incomplete','forked'))
);

CREATE TABLE remote_object (
    id             INTEGER PRIMARY KEY,
    target_id      INTEGER NOT NULL REFERENCES target(id) ON DELETE CASCADE,
    key            TEXT    NOT NULL,
    size           INTEGER NOT NULL,
    blake3         BLOB,
    etag           TEXT,

    -- IMMUTABLE provider version/generation id (S3/R2/B2 versionId, Azure
    -- ETag+version, Drive/Graph revision id). Pinned at verify, REVALIDATED
    -- after the final local hash (§4.10). An opaque token: compared, never
    -- parsed, never assumed to be a content hash.
    object_version TEXT,
    checksum_kind  TEXT,                        -- provider-content-hash | etag-opaque | none

    -- The checksum ITSELF, which the kind alone is not.
    --
    -- `verify_upload` captures a provider whole-object checksum specifically so
    -- later scrub passes can compare without egress — it says so, and it is the
    -- entire reason the upload asks for one. Storing only the kind threw the
    -- value away the moment the verification result left memory, so after a
    -- restart the advertised checksum-based scrub had nothing to compare and
    -- had to re-read every object or, worse, treat the KIND as evidence of
    -- integrity.
    --
    -- `checksum_algorithm` is separate from `checksum_kind` and not a
    -- duplicate: the kind says where the value came from and what it is worth
    -- (a real content hash, or an opaque ETag), the algorithm says how to
    -- reproduce it (crc32c, sha256, …). A scrub needs both — one to decide
    -- whether comparing is meaningful, the other to compute the comparand.
    -- Base64 as the provider returned it; compared, never parsed.
    checksum_algorithm TEXT,
    checksum_value     TEXT,

    -- PM-2 keeps these apart on purpose. A HEAD proves EXISTENCE only; a full
    -- read proves INTEGRITY. Conflating them is how verification decays to
    -- nothing while still reporting green.
    last_presence_check_at     INTEGER,
    last_full_hash_verified_at INTEGER,

    last_scrub_at  INTEGER,
    scrub_result   TEXT,                        -- ok | missing | mismatch | unreachable

    CHECK (checksum_kind IS NULL
           OR checksum_kind IN ('provider-content-hash','etag-opaque','none')),
    CHECK (scrub_result IS NULL
           OR scrub_result IN ('ok','missing','mismatch','unreachable'))
);
CREATE UNIQUE INDEX remote_object_target_key ON remote_object(target_id, key);

CREATE TABLE object_location (
    file_id          INTEGER NOT NULL REFERENCES file(id) ON DELETE CASCADE,
    target_id        INTEGER NOT NULL REFERENCES target(id) ON DELETE CASCADE,
    remote_object_id INTEGER NOT NULL REFERENCES remote_object(id),
    state            TEXT    NOT NULL DEFAULT 'pending',   -- pending | verified | lost
    verified_at      INTEGER,
    PRIMARY KEY (file_id, target_id),
    -- PM-2: 'lost' with no sibling location is alert-grade — it means the only
    -- copy of a destroyed original is gone.
    CHECK (state IN ('pending','verified','lost'))
);
-- Drives the oldest-first scrub sweep (PM-2).
CREATE INDEX object_location_verified_at ON object_location(verified_at ASC);

-- ---------------------------------------------------------------------------
-- Rules.  Phase 1 implements only the matcher (`shepherd-rules::match`);
-- the engine, preview and delete-policy machinery are Phase 2 (T10).
-- ---------------------------------------------------------------------------
CREATE TABLE rule (
    id                INTEGER PRIMARY KEY,
    name              TEXT    NOT NULL,
    match_json        TEXT    NOT NULL,
    action            TEXT    NOT NULL,
    destinations_json TEXT    NOT NULL DEFAULT '[]',
    enabled           INTEGER NOT NULL DEFAULT 0,
    -- AC-14: enabling is REJECTED while these are NULL, and editing the rule
    -- body clears them, which re-blocks enablement. last_preview_hash binds a
    -- dry-run to the exact body that was previewed.
    last_preview_at   INTEGER,
    last_preview_hash BLOB,
    CHECK (enabled = 0 OR (last_preview_at IS NOT NULL AND last_preview_hash IS NOT NULL))
);

CREATE TABLE delete_policy (
    id                    INTEGER PRIMARY KEY,
    priority              INTEGER NOT NULL DEFAULT 0,
    match_json            TEXT    NOT NULL,
    -- archive = copy to destination, verify, THEN delete from the origin target
    --           (that origin deletion is itself a remote destroy → full apparatus)
    -- discard = delete from ALL targets. Sole-copy destruction. The irreversible one
    -- orphan  = destroy NOTHING; drop the file→location binding, still listable
    --           and restorable via `shepctl orphan list|restore`
    action                TEXT    NOT NULL,
    destination_target_id INTEGER REFERENCES target(id),
    -- OQ-H (settled 2026-08-16): NULL inherits the 14-day default.
    deferral_window_days  INTEGER,
    last_preview_at       INTEGER,
    last_preview_hash     BLOB,
    enabled               INTEGER NOT NULL DEFAULT 0,
    CHECK (action IN ('archive','discard','orphan')),
    -- OQ-G (settled 2026-08-16): a DeletePolicy is a Rule variant and INHERITS
    -- AC-14, so the mandatory preview is a requirement, not a default awaiting
    -- confirmation. Same constraint as `rule`, deliberately duplicated rather
    -- than assumed.
    CHECK (enabled = 0 OR (last_preview_at IS NOT NULL AND last_preview_hash IS NOT NULL))
);

-- ---------------------------------------------------------------------------
-- Jobs.  Phase 1 (T6) implements queue/worker; cron/catchup are Phase 4.
-- ---------------------------------------------------------------------------
CREATE TABLE job (
    id              INTEGER PRIMARY KEY,
    class           TEXT    NOT NULL,
    state           TEXT    NOT NULL,
    priority        INTEGER NOT NULL DEFAULT 0,
    payload_json    TEXT    NOT NULL DEFAULT '{}',
    checkpoint_json TEXT,
    attempts        INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,

    -- Retry backoff (T6). The job is not claimable until this instant.
    --
    -- A stored deadline rather than one derived from `updated_at + backoff
    -- (attempts)` in the claim query: deriving it would weld backoff POLICY
    -- into the claim statement, where it cannot be tested or changed without
    -- touching the one query whose single-statement atomicity stops a `destroy`
    -- job being handed out twice.
    run_after       INTEGER NOT NULL DEFAULT 0,

    created_at      INTEGER NOT NULL,
    updated_at      INTEGER NOT NULL,
    -- `scrub` (PM-2) is a first-class class so it inherits per-class power and
    -- network gating (OQ-2) and never runs on battery or metered by default.
    CHECK (class IN ('scan','hash','extract','tag','embed','upload','verify',
                     'destroy','restore','replicate','scrub'))
);
CREATE INDEX job_state_priority ON job(state, run_after ASC, priority DESC, id ASC);

-- Transfer sessions (§4.5).  Consumer is Phase 2 (T9, worker-4); the columns
-- were agreed with that owner rather than invented here.
--
-- §4.4 sketched only `transfer_part`, which review rejected as unable to
-- support cross-process resume: a bare (job_id, upload_id, part_no, etag) row
-- carries no target or object identity, no source fingerprint, no part layout,
-- no provider-session expiry, no completion state and nothing to reconcile an
-- ambiguous crash against.
CREATE TABLE transfer_session (
    id                   INTEGER PRIMARY KEY,
    -- UNIQUE because the consumer's `load(job_id)` expects one row and resume
    -- is per job. Without it the database permits a state the code cannot
    -- represent: two sessions for one job would make SQLite return whichever it
    -- liked, and a resumed transfer would reconcile against the wrong part set
    -- — silently, and only on a resume, which is the worst pair of properties.
    --
    -- Same reasoning as `src_blake3` being NOT NULL. A column permitting a
    -- state the consumer cannot express is a column that will eventually hold
    -- one.
    --
    -- It is a BACKSTOP, not the mechanism. The store writes with an explicit
    -- UPDATE-then-INSERT inside a transaction, correct under single-writer and
    -- not dependent on this constraint, so if it ever fires it means something
    -- upstream is wrong rather than that the happy path needed it.
    job_id               INTEGER NOT NULL UNIQUE REFERENCES job(id) ON DELETE CASCADE,
    target_id            INTEGER NOT NULL REFERENCES target(id) ON DELETE CASCADE,
    file_id              INTEGER REFERENCES file(id) ON DELETE SET NULL,  -- NULL: control object
    remote_key           TEXT    NOT NULL,

    state                TEXT    NOT NULL DEFAULT 'planned',

    -- Source identity as believed at planning time, so a resumed run can prove
    -- the local file did not change underneath it.
    src_size             INTEGER NOT NULL,
    -- NOT NULL: AC-1 makes the hash the precondition for destruction, so a
    -- transfer cannot be planned without one. The consumer's `SourceIdentity`
    -- cannot represent its absence either, and a column permitting a state the
    -- consumer cannot express is a column that will eventually hold one.
    src_blake3           BLOB    NOT NULL,
    src_fs_id            BLOB,
    src_mtime            INTEGER,

    upload_id            TEXT,                  -- opaque provider token
    -- NULL means "this provider does not tell us", NOT "unknown yet".
    upload_id_expires_at INTEGER,

    -- Fixed at `planned`. A resume recomputes identical part boundaries from
    -- these; they are never renegotiated mid-session.
    part_size            INTEGER NOT NULL,
    -- NOT NULL: always >= 1. A zero-byte object is still one empty part.
    part_count           INTEGER NOT NULL,

    attempt_epoch        INTEGER NOT NULL DEFAULT 0,   -- bumped per resume
    last_reconciled_at   INTEGER,

    manifest_blake3      BLOB,                  -- over the ordered part list
    object_version       TEXT,                  -- pinned at completion (§4.10)
    committed_at         INTEGER,
    created_at           INTEGER NOT NULL,
    updated_at           INTEGER NOT NULL,

    -- §4.5's state machine, plus the two abort outcomes. `aborted_ambiguous` is
    -- the lost-CompleteMultipartUpload-response case, resolved by version-scoped
    -- HEAD plus the mandatory full remote re-read AC-1 already requires, so it
    -- cannot leak into the destroy predicate.
    CHECK (state IN ('planned','initiating','uploading','completing','verifying',
                     'committed','abort_pending','aborted_clean','aborted_ambiguous'))
);
CREATE INDEX transfer_session_state ON transfer_session(state);

CREATE TABLE transfer_part (
    session_id    INTEGER NOT NULL REFERENCES transfer_session(id) ON DELETE CASCADE,
    job_id        INTEGER NOT NULL,
    upload_id     TEXT,
    part_no       INTEGER NOT NULL,
    etag          TEXT,
    bytes         INTEGER NOT NULL,

    -- Per-part source hash. WRITE-ONLY TODAY, pending PM-1 hardening — the
    -- transfer driver persists it and does not yet read it, and that is
    -- recorded here rather than left for someone to discover.
    --
    -- Its purpose: an editor that preserves mtime defeats the cheap
    -- `(size, mtime, fs_id)` resume fingerprint, and per-part source hashes are
    -- the only record that could catch a changed part without re-reading the
    -- whole file. Today the full remote BLAKE3 re-read at `verifying` is the
    -- backstop that catches it.
    --
    -- `offset` is deliberately absent: it is derivable as
    -- `(part_no - 1) * part_size`, and `part_size` is immutable for a session's
    -- life (see the CHECK note on `transfer_session`).
    local_blake3  BLOB,

    -- The PROVIDER's per-part checksum, echoed back at completion.
    --
    -- `CompleteMultipartUpload` must repeat each part's checksum alongside its
    -- ETag on a checksum-enabled target, or S3-compatible providers reject the
    -- completion with `InvalidPart` (verified against MinIO). It lived only in
    -- memory, so a crash after the session was durably advanced to `completing`
    -- lost every one of them: the reloaded driver starts IN `completing`, never
    -- runs `upload_pending` or its `list_parts` healing loop, and completes with
    -- `checksum: None` — a resume that cannot succeed on the targets that need
    -- it most.
    --
    -- Opaque, like the ETag beside it: stored, echoed, never interpreted.
    -- Cleared with the rest of the receipts by `restart_attempt`, because a
    -- checksum from a session the provider has forgotten proves nothing about
    -- the next one.
    checksum      TEXT,

    attempt_epoch INTEGER NOT NULL DEFAULT 0,
    verified_at   INTEGER,
    PRIMARY KEY (session_id, part_no)
);

CREATE TABLE schedule (
    id           INTEGER PRIMARY KEY,
    cron_expr    TEXT    NOT NULL,
    job_class    TEXT    NOT NULL,
    last_run_at  INTEGER,
    catch_up     INTEGER NOT NULL DEFAULT 1
);

-- ---------------------------------------------------------------------------
-- The destroy apparatus (§4.10).  SCHEMA ONLY at Phase 1.
-- Phase 2 (T8) implements the protocol over these tables; nothing in this
-- repository writes to them yet.
--
-- The destroy AUDIT log is deliberately NOT here: §4.4 puts it in a separate
-- append-only FILE, because a row can be lost with the database and the
-- forensic record must not be able to be.
-- ---------------------------------------------------------------------------
CREATE TABLE destroy_intent (
    id                     INTEGER PRIMARY KEY,
    kind                   TEXT    NOT NULL,     -- local | remote
    file_id                INTEGER REFERENCES file(id) ON DELETE SET NULL,
    path                   TEXT    NOT NULL,
    size                   INTEGER NOT NULL,
    blake3                 BLOB,
    target_ids_json        TEXT    NOT NULL DEFAULT '[]',
    remote_keys_json       TEXT    NOT NULL DEFAULT '[]',
    -- §4.10.2: version id, OR a content self-attestation for version-less
    -- substrates (OQ-I, mechanism B).
    attested_identity_json TEXT,
    verified_at            INTEGER,
    state                  TEXT    NOT NULL DEFAULT 'prepared',
    batch_id               TEXT,
    episode_id             INTEGER,
    created_at             INTEGER NOT NULL,
    CHECK (kind IN ('local','remote')),
    -- §4.4's eight states, transcribed rather than summarised. The row is
    -- fsync'd BEFORE the syscall; a failed fsync or ENOSPC at that point
    -- refuses the destruction (fail closed).
    CHECK (state IN ('prepared','syscall-issued','outcome-known','outcome-ambiguous',
                     'audited','catalog-committed','aborted','reconstructed-after-crash'))
);
CREATE INDEX destroy_intent_state ON destroy_intent(state);

CREATE TABLE discard_episode (
    id                   INTEGER PRIMARY KEY,
    root_id              INTEGER REFERENCES scan_root(id) ON DELETE SET NULL,
    target_id            INTEGER REFERENCES target(id)    ON DELETE SET NULL,
    policy_id            INTEGER REFERENCES delete_policy(id) ON DELETE SET NULL,
    opened_at            INTEGER NOT NULL,
    state                TEXT    NOT NULL DEFAULT 'enumerating',
    candidate_count      INTEGER NOT NULL DEFAULT 0,
    -- Confirmation binds to THIS hash. Iteration 2 described a durably held
    -- candidate set and a confirmation hash in prose while persisting only a
    -- batch_id, which is not a property the system could actually hold.
    candidate_set_blake3 BLOB,
    confirmed_at         INTEGER,
    confirmed_by         TEXT,
    expires_at           INTEGER,
    CHECK (state IN ('enumerating','held','confirmed','executing','completed',
                     'expired','cancelled'))
);
CREATE TABLE discard_candidate (
    episode_id INTEGER NOT NULL REFERENCES discard_episode(id) ON DELETE CASCADE,
    file_id    INTEGER NOT NULL,
    path       TEXT    NOT NULL,
    blake3     BLOB,
    PRIMARY KEY (episode_id, file_id)
);
-- Persisted rolling window; survives restart, so repeated sub-threshold passes
-- cannot evade the breaker by waiting.
CREATE TABLE discard_rate_window (
    target_id    INTEGER NOT NULL,
    root_id      INTEGER NOT NULL,
    bucket_start INTEGER NOT NULL,
    count        INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (target_id, root_id, bucket_start)
);

-- Keyed by the whole deferral identity, NOT by `file_id` alone.
--
-- A deferral is validated as belonging to a specific `(file, target, kind)`,
-- and `file_id PRIMARY KEY` allowed exactly one row per file — so a file
-- replicated to two targets could not hold independent remote-discard windows,
-- and a local deferral could not coexist with a remote one. The second insert
-- either failed or replaced the first, and a pending window disappearing is a
-- deferral silently expiring early or an operation refused forever.
CREATE TABLE deferral (
    file_id               INTEGER NOT NULL REFERENCES file(id) ON DELETE CASCADE,
    -- CASCADE, not SET NULL. A remote deferral is a window before discarding an
    -- object ON A TARGET, so it is meaningless once that target is gone — and
    -- nulling the column instead would collide two deregistered targets' rows
    -- into one identity, aborting the cascade on the unique index below. A
    -- LOCAL deferral is NULL here from the start and is untouched by any of it.
    target_id             INTEGER REFERENCES target(id) ON DELETE CASCADE,
    trigger_kind          TEXT    NOT NULL,      -- local | remote
    deferred_at           INTEGER NOT NULL,
    -- OQ-H (2026-08-16): 14-day default, overridden per delete policy.
    window_days           INTEGER NOT NULL DEFAULT 14,
    confirmed_permanent_at INTEGER,
    -- §4.10.3's four-field clock record. A monotonic instant alone does not
    -- survive a reboot, so wall clock governs when boot_id differs. If the wall
    -- clock has moved BACKWARD relative to clock_provenance, the deferral HOLDS
    -- and alerts — it never shortens.
    wall_clock_deadline   INTEGER NOT NULL,
    monotonic_deadline    INTEGER,
    boot_id               TEXT,
    clock_provenance      TEXT,                  -- ntp-synced | local | unknown
    cancelled_at          INTEGER,               -- undelete before expiry ⇒ destroy NOTHING
    CHECK (trigger_kind IN ('local','remote')),
    CHECK (clock_provenance IS NULL
           OR clock_provenance IN ('ntp-synced','local','unknown'))
);
-- The identity, as a UNIQUE INDEX rather than a PRIMARY KEY, because
-- `target_id` is legitimately NULL for a local deferral and SQLite treats NULLs
-- in a multi-column PK as distinct — which would make "one local deferral per
-- file" unenforceable. `IFNULL` collapses that to a value the index can compare.
CREATE UNIQUE INDEX deferral_identity
    ON deferral(file_id, trigger_kind, IFNULL(target_id, -1));

-- ---------------------------------------------------------------------------
-- Phase 5 (T-infer) and settings.  Schema only at Phase 1.
-- ---------------------------------------------------------------------------
CREATE TABLE model (
    id            INTEGER PRIMARY KEY,
    role          TEXT NOT NULL,
    kind          TEXT NOT NULL,
    manifest_json TEXT NOT NULL DEFAULT '{}',
    checksum      BLOB,
    version       TEXT,
    dim           INTEGER,
    installed_at  INTEGER,
    consented_at  INTEGER
);
CREATE TABLE audit_hosted (
    id            INTEGER PRIMARY KEY,
    ts            INTEGER NOT NULL,
    file_id       INTEGER,
    provider      TEXT NOT NULL,
    root_id       INTEGER,
    bytes_sent    INTEGER NOT NULL DEFAULT 0,
    cost_micros   INTEGER NOT NULL DEFAULT 0,
    gate_decision TEXT
);
CREATE TABLE setting (
    key        TEXT PRIMARY KEY,
    value_json TEXT NOT NULL
);
"#;
