//! POSIX-only: this file asserts POSIX file identity and permissions on the resumed artifact, via `std::os::unix`'s `MetadataExt`
//! and `PermissionsExt`. Gated at file level rather than per-item so
//! Windows COMPILES the crate and runs everything else, instead of the
//! whole workspace failing to build on one leg — §9 wants a platform
//! break found on the commit that caused it, which needs the other
//! platforms to still build.
//!
//! This is a real coverage gap on Windows and is meant to read as one.
#![cfg(unix)]

//! **AC-2 at its stated size**: kill the daemon mid-upload of a 50 GB object,
//! restart, resume without re-sending verified parts.
//!
//! ```text
//! docker compose -f tests/docker-compose.yml -f tests/docker-compose.nas.yml up -d --wait
//! SHEPHERD_MINIO_ENDPOINT=http://127.0.0.1:9000 \
//!   cargo test -p shepherd-tier --test ac2_resume_50gb -- --ignored --nocapture
//! ```
//!
//! # Why this file exists when the mechanism was already proven
//!
//! `session_store_tests.rs` proves cross-process resume — but on a **51-byte
//! body with 16-byte parts**. §9's Phase 2 row requires "a fresh 50 GB resume
//! artifact in *this* gate, not merely nightly", and §8.2's 5 GB per-push
//! substitution was resolved **in §9's favour** precisely because a critic
//! rejected letting Phase 2 close on a smaller stand-in. So the gap this file
//! closes is **size only**: not a new mechanism, an artifact at the size the
//! criterion names.
//!
//! Producing it was blocked on hardware (§2196: "not producible here at ~19 GiB
//! free"). That block is gone — the object and MinIO's erasure parity now live
//! on external storage via `tests/docker-compose.nas.yml`.
//!
//! # What "kill" means here, and why it is a real process
//!
//! The unit test's "process" is a scope that drops its store. That is enough to
//! prove the row survives a closed connection, and it is **not** enough at this
//! size, because the interesting failure modes at 50 GB — a partially flushed
//! WAL, an in-flight PUT, a provider session outliving the client — need a
//! process that dies without running any destructor.
//!
//! So this spawns the test binary again as a **child process**, lets it upload
//! against real MinIO, and sends it **SIGKILL** mid-transfer. Nothing unwinds;
//! no `Drop` runs; no buffer is flushed on the way out. The assertion that the
//! kill was real is not a comment — [`assert_killed_not_exited`] requires the
//! child's wait status to carry signal 9 and **no** exit code, so a child that
//! finished early or panicked cleanly fails the run instead of quietly turning
//! it into an in-process test wearing a process's clothes.
//!
//! The resume then runs in a **third** process, which opens its own database
//! and its own provider client. `Backend::Owned` exists for exactly this: "a
//! restart genuinely opens its own database, and a test sharing the daemon's
//! actor would be exercising something weaker than a restart."
//!
//! # The defect this file is shaped against
//!
//! `upload_item` once hardcoded `DEFAULT_PART_SIZE`, so the plan collapsed to a
//! single part and **the resume test had nothing to skip and passed while
//! proving nothing**. Every quantity below is therefore asserted as a *number*
//! against a *literal*, and the numbers are chosen so that the vacuous version
//! of this test cannot produce them:
//!
//! * [`PART_SIZE`] is deliberately **not** `DEFAULT_PART_SIZE`, and the
//!   persisted `plan.part_size` is asserted to equal it. A part size that never
//!   reached `PartPlan::new` would show up as 16 MiB and 2 981 parts, not
//!   64 MiB and [`EXPECTED_PARTS`].
//! * `bytes_skipped` is asserted **equal to a computed quantity**, not merely
//!   `> 0`. `> 0` is satisfied by one 16-byte part.
//! * The parts sent after resume plus the parts already acknowledged must equal
//!   the whole object exactly. That identity is what pins the from-scratch
//!   count without paying for a second 50 GB upload — see
//!   [`the_from_scratch_comparison`] below.
//! * Three [negative controls](`negative_controls`) perturb the real
//!   reconciliation inputs and show the skip count collapsing. A skip that
//!   survived them would not be caused by what this test claims causes it.
//!
//! # `the_from_scratch_comparison`
//!
//! AC-2 asks for the resumed part count to be lower than a from-scratch run by
//! the number already acknowledged. A literal second 50 GB upload would measure
//! that directly and cost another ~10 minutes of gate time. It is not run, and
//! the substitute is stated rather than hidden:
//!
//! * A from-scratch run sends `plan.part_count` parts — asserted directly, at
//!   this size, by the **first** child: it starts from an empty session and its
//!   `bytes_skipped` is zero for every part it sends.
//! * `plan.part_count` is read off the persisted session and asserted equal to
//!   the literal [`EXPECTED_PARTS`].
//! * The resumed run's `parts_sent` plus `acked_before` is asserted equal to
//!   that same number.
//!
//! So both counts in "746 from scratch, 746 − *n* on resume" are observed at
//! 50 GB; only the *second full traversal* is elided. What is **not** covered:
//! a defect that made a from-scratch run send more parts than the plan (a
//! retry loop) would be invisible here. `m2_e2e` covers that shape at 12 MiB.

#![cfg(unix)]

use std::io::{Read, Write};
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use shepherd_catalog::Catalog;
use shepherd_core::{Blake3Hash, FileId, FsId, JobId, TargetId};
use shepherd_storage::adapter::{
    AttestationMode, PartReceipt, StorageAdapter, verify_full_content,
};
use shepherd_storage::multipart::{DEFAULT_PART_SIZE, PartAction, reconcile_parts};
use shepherd_storage::s3::{S3Adapter, S3Config, StaticCredentials};
use shepherd_storage::transfer_session::{TransferSession, TransferSessionStore, TransferState};
use shepherd_tier::{
    CatalogSessionStore, FileLocks, TierItem, derive_object_key, hash_file, upload_item,
};

// ---------------------------------------------------------------------------
// The size, and the arithmetic that must follow from it
// ---------------------------------------------------------------------------

/// **50 GB, decimal**, which is the unit §9 and §8.3 state it in.
///
/// Hardcoded with no environment override, deliberately. A shrinkable size is
/// the same defect class this whole file is written against: the knob would be
/// turned down for a quick local run, the gate would keep citing the test, and
/// the citation would go on saying "50 GB" while the artifact was 500 MB. Pilot
/// at a smaller size by editing this constant locally and **not committing it**.
const TOTAL_BYTES: u64 = 50_000_000_000;

/// 64 MiB parts.
///
/// **Deliberately not [`DEFAULT_PART_SIZE`]** (16 MiB), which is the discriminator
/// that catches a part size never reaching `PartPlan::new`: at the default this
/// object plans 2 981 parts, not [`EXPECTED_PARTS`].
const PART_SIZE: u64 = 64 * 1024 * 1024;

/// 50 000 000 000 B in 64 MiB parts: 745 full parts and a short 746th.
///
/// A literal rather than a `div_ceil` recomputation of `PartPlan::new`'s own
/// arithmetic, so a change in the planner cannot quietly agree with itself here.
const EXPECTED_PARTS: u32 = 746;

/// The short final part — 3 896 320 B.
///
/// Decimal 50 GB is used partly *for* this: 50 GiB in 64 MiB parts divides
/// evenly, every part is full, and `reconcile_parts`' length-agreement check
/// would never see a part whose length differs from the plan's part size. The
/// remainder keeps that branch load-bearing at this scale.
const LAST_PART_LEN: u64 = TOTAL_BYTES - (EXPECTED_PARTS as u64 - 1) * PART_SIZE;

/// Kill once this many parts are **durably** acknowledged — a quarter of the
/// object, so `bytes_skipped` is a substantial and specific quantity rather
/// than a token one.
const KILL_AFTER_ACKED: u32 = 186;

// Every property the constants above exist to hold, checked at compile time so
// an edit cannot silently turn this back into a test with nothing to skip.
const _: () = assert!(PART_SIZE != DEFAULT_PART_SIZE);
// Consistency between *these two literals* — NOT a re-derivation of the
// planner's arithmetic, which is asserted at run time against the persisted
// `plan.part_count`.
const _: () = assert!((EXPECTED_PARTS as u64) * PART_SIZE >= TOTAL_BYTES);
const _: () = assert!((EXPECTED_PARTS as u64 - 1) * PART_SIZE < TOTAL_BYTES);
// The last part really is short; see `LAST_PART_LEN`.
const _: () = assert!(LAST_PART_LEN > 0 && LAST_PART_LEN < PART_SIZE);
// The kill lands strictly inside the transfer: something acknowledged to skip,
// and something left to send.
const _: () = assert!(KILL_AFTER_ACKED > 0 && KILL_AFTER_ACKED < EXPECTED_PARTS);

/// Versioning on: mechanism A. Chosen over the plain bucket because it is the
/// configuration that depends on MinIO's **erasure-coded** backend, so running
/// the artifact here also demonstrates that moving the drives to external
/// storage did not silently collapse the deployment to the un-versioned
/// mechanism `tests/docker-compose.yml` exists to prevent.
const BUCKET: &str = "shepherd-versioned";

const FS_ID: &str = "uuid:ac2-50gb";

/// The test's own name, used to re-invoke this binary. A `const` rather than a
/// literal at the call site so a rename cannot leave the child running a filter
/// that matches nothing — which `cargo test` reports by exiting **0**.
const TEST_NAME: &str =
    "a_fifty_gb_upload_killed_mid_flight_resumes_without_resending_verified_parts";

// ---------------------------------------------------------------------------
// Roles
// ---------------------------------------------------------------------------

const ROLE: &str = "SHEPHERD_AC2_ROLE";
const ROLE_UPLOAD: &str = "upload";
const ROLE_RESUME: &str = "resume";

const ENV_DB: &str = "SHEPHERD_AC2_DB";
const ENV_SRC: &str = "SHEPHERD_AC2_SRC";
const ENV_PREFIX: &str = "SHEPHERD_AC2_PREFIX";
const ENV_HASH: &str = "SHEPHERD_AC2_HASH";

/// Where the 50 GB fixture and the MinIO drives live.
///
/// Defaults to the path `tests/docker-compose.nas.yml` is documented against.
/// The local disk on the development box cannot hold either (§2196), so this
/// is a real prerequisite rather than a preference — [`assert_room_for`] turns
/// a too-small filesystem into an immediate named failure instead of an ENOSPC
/// ten minutes into a transfer.
const ENV_SCRATCH: &str = "SHEPHERD_AC2_SCRATCH";
const SCRATCH_DEFAULT: &str = "/mnt/dataset/shepherd/ac2";

/// The prefix of the resume child's machine-readable result line.
const RESULT_MARKER: &str = "AC2-RESUME ";

fn endpoint() -> String {
    std::env::var("SHEPHERD_MINIO_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:9000".to_string())
}

fn scratch_dir() -> PathBuf {
    PathBuf::from(std::env::var(ENV_SCRATCH).unwrap_or_else(|_| SCRATCH_DEFAULT.to_string()))
}

async fn adapter() -> S3Adapter {
    let mut cfg = S3Config::minio(BUCKET, endpoint());
    cfg.credentials = Some(StaticCredentials {
        access_key_id: "shepherdtest".into(),
        secret_access_key: "shepherdtest".into(),
    });
    S3Adapter::new(cfg).await.expect("build S3 adapter")
}

/// Everything a child process needs, all of it read from the environment so the
/// child re-derives the work rather than being handed a serialized session.
struct ChildCfg {
    db: PathBuf,
    src: PathBuf,
    item: TierItem,
    job: JobId,
}

impl ChildCfg {
    fn from_env() -> Self {
        let db = PathBuf::from(std::env::var(ENV_DB).expect(ENV_DB));
        let src = PathBuf::from(std::env::var(ENV_SRC).expect(ENV_SRC));
        let prefix = std::env::var(ENV_PREFIX).expect(ENV_PREFIX);
        // Passed as hex rather than re-hashed: the parent computed it with the
        // real streamed `hash_file`, and re-reading 50 GB per child to reach the
        // same number would cost minutes to learn nothing.
        let blake3 = Blake3Hash::from_hex(&std::env::var(ENV_HASH).expect(ENV_HASH))
            .expect("the parent passes a well-formed BLAKE3 hex");
        Self {
            db,
            src: src.clone(),
            item: TierItem {
                file: FileId::new(1),
                path: src.display().to_string(),
                size: TOTAL_BYTES,
                blake3,
                target: TargetId::new(1),
                // The production key derivation, not one the test built for
                // itself: a hand-made key would pass happily while the real one
                // differed.
                remote_key: derive_object_key(&prefix, blake3),
            },
            job: JobId::new(7),
        }
    }
}

// ---------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------

/// Bytes available on the filesystem holding `dir`, via `df`.
///
/// `df` rather than a `statvfs` binding because this crate has no libc
/// dependency and adding one to read a precondition would be a worse trade than
/// shelling out to a tool that is present on every Unix this runs on. Returns
/// `None` if `df` is absent or unparseable — an unavailable precondition check
/// must not fail a run it cannot speak to.
fn avail_bytes(dir: &Path) -> Option<u64> {
    let out = Command::new("df")
        .args(["-B1", "--output=avail"])
        .arg(dir)
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .nth(1)?
        .trim()
        .parse()
        .ok()
}

fn assert_room_for(dir: &Path, need: u64) {
    let Some(avail) = avail_bytes(dir) else {
        eprintln!(
            "[ac2] could not read free space for {}; continuing",
            dir.display()
        );
        return;
    };
    assert!(
        avail >= need,
        "{} has {avail} B free but this artifact needs at least {need} B. Point ${ENV_SCRATCH} \
         at a filesystem with room — §2196 records this as a hardware prerequisite, and \
         discovering it as an ENOSPC ten minutes into a 50 GB transfer is the expensive way \
         to learn it",
        dir.display()
    );
}

/// The 50 GB source, created once and reused by size.
///
/// Filled from `/dev/urandom`. High-entropy on purpose — an object that
/// compressed or deduplicated would let a size comparison stand in for the
/// hash comparison, and MinIO's erasure backend would not be moving the bytes
/// this measures. Non-deterministic is fine and slightly better: the object key
/// is content-addressed, so a regenerated fixture lands at a fresh key.
///
/// Returns whether it had to be created, so the report can separate fixture
/// time from transfer time.
fn ensure_fixture(path: &Path) -> bool {
    if let Ok(md) = std::fs::metadata(path)
        && md.len() == TOTAL_BYTES
    {
        eprintln!("[ac2] reusing fixture {} ({TOTAL_BYTES} B)", path.display());
        return false;
    }
    eprintln!(
        "[ac2] creating {TOTAL_BYTES} B fixture at {} …",
        path.display()
    );
    let t = Instant::now();
    let mut urandom = std::fs::File::open("/dev/urandom").expect("open /dev/urandom");
    let mut f = std::fs::File::create(path).expect("create fixture");
    let mut buf = vec![0u8; 8 * 1024 * 1024];
    let mut written = 0u64;
    while written < TOTAL_BYTES {
        let n = usize::try_from((TOTAL_BYTES - written).min(buf.len() as u64)).expect("fits");
        urandom.read_exact(&mut buf[..n]).expect("read urandom");
        f.write_all(&buf[..n]).expect("write fixture");
        written += n as u64;
    }
    // Durable before anything reads it: the uploader opens the file fresh in
    // another process.
    f.sync_all().expect("fsync fixture");
    drop(f);
    let s = t.elapsed().as_secs_f64();
    eprintln!(
        "[ac2] fixture written: {TOTAL_BYTES} B in {s:.0}s = {:.0} MB/s",
        TOTAL_BYTES as f64 / s / 1e6
    );
    assert_eq!(
        std::fs::metadata(path).expect("stat fixture").len(),
        TOTAL_BYTES,
        "the fixture must be exactly the size this test claims to upload"
    );
    true
}

/// The rows `transfer_session`'s foreign keys point at.
///
/// Real FKs — a session in production always hangs off a real job, target and
/// file, and inventing ids fails with `FOREIGN KEY constraint failed` on the
/// first save.
fn seed(db: &Path, job: JobId, target: TargetId, file: FileId) {
    let cat = Catalog::open(db).expect("open for seeding");
    let c = cat.conn();
    c.execute(
        "INSERT INTO scan_root (id, path, stub_mode, created_at) VALUES (1, ?1, 'delete', 0)",
        [db.to_string_lossy().to_string()],
    )
    .expect("scan_root");
    c.execute(
        "INSERT INTO file (id, root_id, rel_path, name, size, mtime, ctime,
                           norm_key, first_seen_at, updated_at)
         VALUES (?1, 1, 'ac2.bin', 'ac2.bin', 0, 0, 0, 'ac2.bin', 0, 0)",
        [file.get()],
    )
    .expect("file");
    c.execute(
        "INSERT INTO target (id, name, adapter) VALUES (?1, 'ac2-target', 's3')",
        [target.get()],
    )
    .expect("target");
    c.execute(
        "INSERT INTO job (id, class, state, created_at, updated_at)
         VALUES (?1, 'upload', 'running', 0, 0)",
        [job.get()],
    )
    .expect("job");
}

/// Durably acknowledged parts, read with a plain connection that only ever
/// SELECTs.
///
/// **Not** `Catalog::open`: that runs migrations, which write, and a second
/// writer against the child's live WAL is `SQLITE_BUSY` rather than a reading.
/// The database is already migrated by [`seed`] before any child starts.
fn acked_parts(db: &Path, job: JobId) -> u32 {
    let conn = match rusqlite::Connection::open(db) {
        Ok(c) => c,
        Err(_) => return 0,
    };
    conn.query_row(
        "SELECT COUNT(*) FROM transfer_part WHERE job_id = ?1 AND etag IS NOT NULL",
        [job.get()],
        |r| r.get::<_, i64>(0),
    )
    .map(|n| u32::try_from(n).unwrap_or(0))
    .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// The children
// ---------------------------------------------------------------------------

/// A private copy of this test binary, taken **once** before the long phases.
///
/// # Why not just `current_exe()`
///
/// Because it does not survive a rebuild, and this tree is built by several
/// workers at once. `cargo` relinks a test binary to the **same path with a new
/// inode**; the running process keeps the old, now-unlinked image, and Linux
/// then reports `/proc/self/exe` as `…/ac2_resume_50gb-866c… (deleted)`.
/// `current_exe()` returns that literal string, and spawning it fails with
/// `NotFound`.
///
/// Observed, not hypothetical: a 50 GB run died three minutes in at `spawn the
/// child process: Os { code: 2, kind: NotFound }` because another worker's
/// `cargo test` relinked this binary while the source was being hashed. The
/// timestamps matched to the minute.
///
/// The copy is taken **from `/proc/self/exe`**, which still resolves to the
/// running image's inode even after the directory entry is gone, so it works in
/// both the healthy and the already-clobbered case. A plain `current_exe()`
/// fallback is kept for non-Linux Unix, where the race does not arise the same
/// way.
fn stable_self_copy(dir: &Path) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let dest = dir.join("ac2-child");
    let proc_self = Path::new("/proc/self/exe");
    let copied = std::fs::copy(proc_self, &dest).or_else(|_| {
        let exe = std::env::current_exe().expect("the test binary can name itself");
        std::fs::copy(&exe, &dest)
    });
    copied.unwrap_or_else(|e| panic!("cannot copy this test binary to {}: {e}", dest.display()));
    std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))
        .expect("make the child copy executable");
    dest
}

fn spawn_child(
    exe: &Path,
    role: &str,
    cfg: &ChildCfg,
    prefix: &str,
    capture_stdout: bool,
) -> std::process::Child {
    let mut cmd = Command::new(exe);
    cmd.args([
        TEST_NAME,
        "--exact",
        "--ignored",
        "--nocapture",
        "--test-threads",
        "1",
    ])
    .env(ROLE, role)
    .env(ENV_DB, &cfg.db)
    .env(ENV_SRC, &cfg.src)
    .env(ENV_PREFIX, prefix)
    .env(ENV_HASH, cfg.item.blake3.to_hex())
    .env("SHEPHERD_MINIO_ENDPOINT", endpoint())
    .stdin(Stdio::null())
    // Inherited so the child's own progress reporting reaches the same terminal
    // the parent's does, rather than sitting in a pipe nobody drains.
    .stderr(Stdio::inherit())
    .stdout(if capture_stdout {
        Stdio::piped()
    } else {
        Stdio::null()
    });
    cmd.spawn().expect("spawn the child process")
}

/// The child that will be killed. Never returns normally in a healthy run.
async fn child_upload(cfg: &ChildCfg) {
    // ITS OWN store, against its own connection — `Backend::Owned`.
    let store = CatalogSessionStore::open(&cfg.db).expect("child opens its own database");
    let a = adapter().await;
    let locks = FileLocks::new();
    let out = upload_item(
        cfg.job,
        &cfg.item,
        &a,
        &store,
        &locks,
        FsId::new(FS_ID),
        PART_SIZE,
    )
    .await;
    // Reaching here means the parent never managed to kill it. Say so loudly on
    // stdout; the parent independently detects the early exit and fails.
    println!("AC2-CHILD-FINISHED-EARLY role=upload outcome={out:?}");
}

/// The restart. A third process, its own database handle, its own client.
async fn child_resume(cfg: &ChildCfg) {
    let store = CatalogSessionStore::open(&cfg.db).expect("the restart opens its own database");
    let a = adapter().await;
    let locks = FileLocks::new();
    let t = Instant::now();
    let out = upload_item(
        cfg.job,
        &cfg.item,
        &a,
        &store,
        &locks,
        FsId::new(FS_ID),
        PART_SIZE,
    )
    .await
    .expect("the resumed transfer must reach a terminal state");
    println!(
        "{RESULT_MARKER}parts_sent={} bytes_uploaded={} bytes_skipped={} committed={} ambiguous={} secs={:.1}",
        out.parts_sent,
        out.bytes_uploaded,
        out.bytes_skipped,
        out.state == TransferState::Committed,
        out.resolved_ambiguous_completion,
        t.elapsed().as_secs_f64(),
    );
}

/// One `key=value` field out of the child's RESULT line.
fn field<'a>(line: &'a str, key: &str) -> &'a str {
    line.split_whitespace()
        .find_map(|tok| tok.strip_prefix(key))
        .unwrap_or_else(|| panic!("the child's RESULT line has no `{key}` field: {line}"))
}

/// A wait status that proves the process was **killed**, not that it finished.
///
/// The whole point of spawning a child is that the boundary is real. A child
/// that exited on its own — because it finished, or panicked, or could not
/// reach MinIO — leaves a session this test would then "resume" from a state no
/// crash produced. `signal() == 9` with no exit code is the only status that
/// says SIGKILL landed on a running process.
fn assert_killed_not_exited(status: std::process::ExitStatus) {
    assert_eq!(
        status.signal(),
        Some(9),
        "the upload child must have died by SIGKILL; got {status:?}. A child that exited on \
         its own was not killed mid-upload, and resuming from whatever it left behind would \
         measure something other than a crash"
    );
    assert!(
        status.code().is_none(),
        "a signalled process has no exit code; got {status:?}"
    );
}

// ---------------------------------------------------------------------------
// The three negative controls
// ---------------------------------------------------------------------------

/// Perturb the **real** reconciliation inputs — the durable checkpoints this
/// run wrote and the part list this MinIO deployment reports — and show the
/// skip collapsing.
///
/// Without these, "186 parts were skipped" is a number with no demonstrated
/// cause. Each control removes exactly one of the things `reconcile_parts`
/// requires, and asserts the skip count moves by exactly the amount that thing
/// was responsible for.
fn negative_controls(session: &TransferSession, remote: &[PartReceipt], acked: u32, baseline: u64) {
    // 1. The provider forgot the session. If the skip were driven by local
    //    state alone — the tempting implementation, and the one §4.5's
    //    opaque-token rule forbids — this would still skip 186 parts.
    let recon = reconcile_parts(&session.plan, &session.parts, &[]);
    assert_eq!(
        recon.bytes_skipped, 0,
        "with an empty provider listing NOTHING may be skipped: a durable ETag is not \
         evidence the provider still holds the part"
    );
    assert_eq!(
        recon
            .actions
            .iter()
            .filter(|a| **a == PartAction::Skip)
            .count(),
        0
    );

    // 2. One acknowledged part's ETag no longer matches. Exactly one part's
    //    worth of bytes must stop being skipped — not zero (the check is inert)
    //    and not all of them (the reconciliation is all-or-nothing).
    let mut tampered: Vec<PartReceipt> = remote.to_vec();
    let victim = tampered
        .iter_mut()
        .find(|r| r.part_no == 1)
        .expect("part 1 was acknowledged before the kill");
    let victim_len = victim.size;
    victim.etag = shepherd_storage::adapter::OpaqueToken::new("not-the-etag-the-provider-issued");
    let recon = reconcile_parts(&session.plan, &session.parts, &tampered);
    assert_eq!(
        recon.bytes_skipped,
        baseline - victim_len,
        "changing ONE ETag must cost exactly that one part's bytes"
    );
    assert_eq!(
        recon
            .actions
            .iter()
            .filter(|a| **a == PartAction::Skip)
            .count(),
        acked as usize - 1
    );

    // 3. The ETag matches but the length does not — the case an ETag-only
    //    comparison would wave through, and the one that turns a completed
    //    object into a chimera.
    let mut tampered: Vec<PartReceipt> = remote.to_vec();
    tampered
        .iter_mut()
        .find(|r| r.part_no == 1)
        .expect("part 1")
        .size += 1;
    let recon = reconcile_parts(&session.plan, &session.parts, &tampered);
    assert_eq!(
        recon.bytes_skipped,
        baseline - victim_len,
        "agreement is on part number, ETag AND length; a length disagreement must re-send"
    );

    eprintln!(
        "[ac2] negative controls: empty listing -> 0 B skipped; one wrong ETag -> \
         {} B skipped; one wrong length -> {} B skipped (baseline {baseline} B)",
        baseline - victim_len,
        baseline - victim_len
    );
}

// ---------------------------------------------------------------------------
// The artifact
// ---------------------------------------------------------------------------

#[tokio::test]
#[ignore = "produces a real 50 GB object: requires MinIO and ~110 GB of storage — see the module docs"]
async fn a_fifty_gb_upload_killed_mid_flight_resumes_without_resending_verified_parts() {
    // The three roles share one entry point so the child can re-invoke this
    // binary by name. Branch first: everything below the match is the parent.
    match std::env::var(ROLE).as_deref() {
        Ok(ROLE_UPLOAD) => return child_upload(&ChildCfg::from_env()).await,
        Ok(ROLE_RESUME) => return child_resume(&ChildCfg::from_env()).await,
        Ok(other) => panic!("unknown ${ROLE}: {other}"),
        Err(_) => {}
    }

    // The catalog goes on LOCAL disk, not the NAS: SQLite's locking is
    // documented as unreliable over NFS, and the session row is a few KB next
    // to a 50 GB object. Created FIRST because the child-binary copy lives here
    // too, and that copy wants taking before the minutes-long phases below —
    // see `stable_self_copy`.
    let dbdir = std::env::temp_dir().join(format!("shepherd-ac2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dbdir);
    std::fs::create_dir_all(&dbdir).expect("catalog dir");
    let db = dbdir.join("catalog.db");
    let child_exe = stable_self_copy(&dbdir);

    let scratch = scratch_dir();
    std::fs::create_dir_all(&scratch).unwrap_or_else(|e| {
        panic!(
            "cannot create {} — set ${ENV_SCRATCH}: {e}",
            scratch.display()
        )
    });
    // Three times the object: the fixture, plus the erasure-coded copy MinIO
    // writes (EC:2 over four drives doubles it). Conservative when the drives
    // are on a different filesystem than the fixture — which is the direction
    // to be wrong in, since the alternative is an ENOSPC deep inside a transfer
    // that has already run for minutes.
    assert_room_for(&scratch, TOTAL_BYTES * 3);

    let src = scratch.join("ac2-source-50gb.bin");
    let fixture_created = ensure_fixture(&src);

    // The real streamed planning hasher over the real 50 GB file.
    let t = Instant::now();
    let blake3 = hash_file(&src).expect("hash the 50 GB source");
    let hash_secs = t.elapsed().as_secs_f64();
    eprintln!(
        "[ac2] hashed {TOTAL_BYTES} B in {hash_secs:.0}s = {:.0} MB/s -> {}",
        TOTAL_BYTES as f64 / hash_secs / 1e6,
        blake3.to_hex()
    );

    // A fresh prefix per run, so the content-addressed key is one no previous
    // run can have populated. Without it a leftover object would make the
    // driver's window-3 HEAD short-circuit `CompleteMultipartUpload` entirely —
    // `resolved_ambiguous_completion` would be true and the run would prove
    // nothing about multipart completion. That flag is asserted false below,
    // which is only meaningful because of this.
    let prefix = format!(
        "ac2-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos()
    );

    let job = JobId::new(7);
    let target = TargetId::new(1);
    let file = FileId::new(1);
    seed(&db, job, target, file);

    let cfg = ChildCfg {
        db: db.clone(),
        src: src.clone(),
        item: TierItem {
            file,
            path: src.display().to_string(),
            size: TOTAL_BYTES,
            blake3,
            target,
            remote_key: derive_object_key(&prefix, blake3),
        },
        job,
    };
    let key = cfg.item.remote_key.clone();

    // --- process 1: upload for real, then die mid-flight ---------------------
    eprintln!("[ac2] process 1: uploading to {}/{}", BUCKET, key.as_str());
    let upload_started = Instant::now();
    let mut child = spawn_child(&child_exe, ROLE_UPLOAD, &cfg, &prefix, false);

    let deadline = Duration::from_secs(45 * 60);
    let mut last_report = Instant::now();
    let mut foreign_deaths = 0u32;
    let acked_at_kill = loop {
        if let Some(status) = child.try_wait().expect("poll the upload child") {
            let acked = acked_parts(&db, job);

            // A NORMAL exit means the upload either finished or failed. Either
            // way there is nothing left to kill, and resuming from it would
            // measure something other than a crash.
            assert!(
                status.signal().is_some(),
                "the upload child exited on its own ({status:?}) at {acked}/{EXPECTED_PARTS} \
                 acked parts, before this test could kill it. Nothing to resume from. Check \
                 MinIO and the endpoint."
            );
            assert!(
                acked < EXPECTED_PARTS,
                "the upload child got all {EXPECTED_PARTS} parts acknowledged before the kill \
                 landed; there is nothing left for a resume to skip"
            );

            // A death by a signal this test did not send. It happens: this is a
            // shared machine, and an external SIGTERM landed on a real 50 GB
            // run at 134/746 parts. It is not a defect in the code under test
            // and it is not a reason to discard 10 minutes of transfer — the
            // session is durable, so a fresh process simply picks up where this
            // one stopped.
            //
            // Reported loudly rather than absorbed, and bounded, so a machine
            // that is killing everything fails the run instead of looping. The
            // SIGKILL this test asserts is still the one THIS test sends, at
            // the threshold, below.
            foreign_deaths += 1;
            assert!(
                foreign_deaths <= 5,
                "the upload child has been killed by a foreign signal {foreign_deaths} times \
                 (last: {status:?}). Something on this machine is terminating these processes; \
                 that is the thing to fix, not this test"
            );
            eprintln!(
                "[ac2] WARNING: the upload child was terminated by a signal this test did not \
                 send ({status:?}) at {acked}/{EXPECTED_PARTS} acked parts. Respawning to \
                 continue toward the kill threshold — the durable session makes this a resume. \
                 Foreign interruptions so far: {foreign_deaths}."
            );
            child = spawn_child(&child_exe, ROLE_UPLOAD, &cfg, &prefix, false);
            continue;
        }
        let acked = acked_parts(&db, job);
        if acked >= KILL_AFTER_ACKED {
            break acked;
        }
        assert!(
            upload_started.elapsed() < deadline,
            "no progress to {KILL_AFTER_ACKED} acknowledged parts within {deadline:?} \
             (got {acked}). Slow is fine and is reported as a rate; stalled is not"
        );
        if last_report.elapsed() >= Duration::from_secs(10) {
            let secs = upload_started.elapsed().as_secs_f64();
            eprintln!(
                "[ac2]   {acked}/{EXPECTED_PARTS} parts acked, {:.1} GB, {:.0} MB/s",
                acked as f64 * PART_SIZE as f64 / 1e9,
                acked as f64 * PART_SIZE as f64 / secs / 1e6,
            );
            last_report = Instant::now();
        }
        std::thread::sleep(Duration::from_millis(200));
    };

    let upload_secs = upload_started.elapsed().as_secs_f64();
    let upload_rate = acked_at_kill as f64 * PART_SIZE as f64 / upload_secs / 1e6;

    // SIGKILL. `Child::kill` is exactly that on Unix — no destructor runs, no
    // buffer is flushed, no `Drop` closes the database.
    child.kill().expect("SIGKILL the upload child");
    let status = child.wait().expect("reap the upload child");
    assert_killed_not_exited(status);
    eprintln!(
        "[ac2] process 1 killed by SIGKILL after {acked_at_kill} acked parts \
         ({upload_secs:.0}s, {upload_rate:.0} MB/s)"
    );

    // --- what survived the kill ---------------------------------------------
    let session = {
        let store = CatalogSessionStore::open(&db).expect("reopen the catalog after the kill");
        store
            .load(job)
            .await
            .expect("load")
            .expect("something was durable before the kill")
    };

    assert_eq!(
        session.plan.part_size,
        PART_SIZE,
        "the part size must come from the transfer config, not a constant. This is the \
         instance-#6 defect: a hardcoded DEFAULT_PART_SIZE would plan {} parts and leave \
         this test measuring a different object than it claims",
        TOTAL_BYTES.div_ceil(DEFAULT_PART_SIZE)
    );
    assert_eq!(
        session.plan.part_count, EXPECTED_PARTS,
        "the planner's own part count, against this file's literal"
    );
    assert_eq!(session.plan.total_size, TOTAL_BYTES);
    assert_eq!(session.state, TransferState::Uploading);
    assert_eq!(session.source.size, TOTAL_BYTES);

    let acked_before = session.parts.iter().filter(|p| p.is_acknowledged()).count();
    assert!(
        acked_before >= KILL_AFTER_ACKED as usize,
        "the acknowledged parts must survive the kill: expected at least {KILL_AFTER_ACKED}, \
         found {acked_before}"
    );
    assert!(
        acked_before < EXPECTED_PARTS as usize,
        "precondition: the upload must NOT have finished, or there is nothing to resume"
    );

    // The acknowledged parts are an ascending, contiguous, full-size prefix.
    // Asserted rather than assumed because the `bytes_skipped` identity below
    // is derived from it — `acked_before * PART_SIZE` is only the right number
    // if none of the acknowledged parts is the short final one.
    let mut acknowledged: Vec<u32> = session
        .parts
        .iter()
        .filter(|p| p.is_acknowledged())
        .map(|p| p.part_no)
        .collect();
    acknowledged.sort_unstable();
    assert_eq!(
        acknowledged,
        (1..=acked_before as u32).collect::<Vec<_>>(),
        "parts are sent in ascending order, so the acknowledged set must be the prefix"
    );
    for p in session.parts.iter().filter(|p| p.is_acknowledged()) {
        assert_eq!(
            p.len, PART_SIZE,
            "part {} is not full-size; the bytes_skipped identity assumes the acknowledged \
             prefix excludes the short final part",
            p.part_no
        );
    }
    let expect_skipped = acked_before as u64 * PART_SIZE;

    // --- the provider's side, and the negative controls ----------------------
    let a = adapter().await;
    let upload_id = session
        .upload_id
        .clone()
        .expect("a session in Uploading has a provider upload id");
    let remote = a
        .list_parts(&key, &upload_id)
        .await
        .expect("the provider still knows the multipart session");
    assert!(
        remote.len() >= acked_before,
        "the provider reports {} parts but {acked_before} were durably acknowledged — the \
         durable record must never claim more than the provider confirmed",
        remote.len()
    );

    let recon = reconcile_parts(&session.plan, &session.parts, &remote);
    let skips = recon
        .actions
        .iter()
        .filter(|x| **x == PartAction::Skip)
        .count();
    assert_eq!(
        skips, acked_before,
        "every durably acknowledged part must reconcile as Skip against the real listing"
    );
    assert_eq!(
        recon.bytes_skipped, expect_skipped,
        "bytes_skipped is a QUANTITY: {acked_before} parts of {PART_SIZE} B"
    );

    negative_controls(&session, &remote, acked_before as u32, recon.bytes_skipped);

    // --- process 2: the restart ---------------------------------------------
    eprintln!("[ac2] process 2: restarting and resuming");
    let resume_started = Instant::now();
    let out = spawn_child(&child_exe, ROLE_RESUME, &cfg, &prefix, true)
        .wait_with_output()
        .expect("run the resume child");
    let resume_secs = resume_started.elapsed().as_secs_f64();
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    // Named explicitly, because the two causes want opposite responses: a
    // non-zero exit is a defect in the resume path, while a signal this test
    // did not send is the shared machine interfering and means "run it again",
    // not "the resume is broken". A bare `success()` cannot tell them apart,
    // and the first time this happened to process 1 it cost a full run to
    // diagnose.
    if let Some(sig) = out.status.signal() {
        panic!(
            "the resume child was killed by signal {sig}, which this test does not send — \
             something on this machine terminated it {resume_secs:.0}s into the resume. That \
             is an environment fault, not a verdict on AC-2: re-run it.\n{stdout}"
        );
    }
    assert!(
        out.status.success(),
        "the resume child failed ({:?}):\n{stdout}",
        out.status
    );
    // Searched for anywhere in a line, not at its start: under `--nocapture`
    // libtest interleaves the child's own `println!` with its progress line, so
    // the marker arrives as `test some_name ... AC2-RESUME parts_sent=… ok`.
    // Anchoring at the line start found nothing and failed a run whose numbers
    // were all correct.
    let line = stdout
        .lines()
        .find_map(|l| l.find(RESULT_MARKER).map(|i| &l[i..]))
        .unwrap_or_else(|| panic!("the resume child printed no RESULT line:\n{stdout}"));

    let parts_sent: u32 = field(line, "parts_sent=").parse().expect("parts_sent");
    let bytes_uploaded: u64 = field(line, "bytes_uploaded=")
        .parse()
        .expect("bytes_uploaded");
    let bytes_skipped: u64 = field(line, "bytes_skipped=")
        .parse()
        .expect("bytes_skipped");
    assert_eq!(field(line, "committed="), "true", "{line}");
    assert_eq!(
        field(line, "ambiguous="),
        "false",
        "the driver found an object already at the key and skipped \
         CompleteMultipartUpload — this run proves nothing about multipart completion: {line}"
    );

    // --- the identities AC-2 is stated in ------------------------------------
    assert_eq!(
        bytes_skipped, expect_skipped,
        "the resumed run must skip exactly the bytes the durable checkpoints vouch for"
    );
    assert_eq!(
        parts_sent,
        EXPECTED_PARTS - acked_before as u32,
        "the resumed run must send the whole object MINUS the acknowledged parts"
    );
    assert_eq!(
        acked_before as u32 + parts_sent,
        EXPECTED_PARTS,
        "from scratch this object is {EXPECTED_PARTS} parts; the resume sent {parts_sent}, \
         lower by exactly the {acked_before} already acknowledged"
    );
    assert_eq!(
        bytes_uploaded + bytes_skipped,
        TOTAL_BYTES,
        "every byte is accounted for exactly once: sent or skipped"
    );

    // --- the object is actually correct --------------------------------------
    //
    // The driver verified itself during `Verifying`. That is the code under
    // test deciding it passed, and AC-2 would be worthless if "skipped" could
    // mean "omitted": re-read the whole object here, independently.
    let meta = a
        .head(&key)
        .await
        .expect("head")
        .expect("the resumed transfer committed an object");
    assert_eq!(meta.size, TOTAL_BYTES, "the committed object is 50 GB");
    let t = Instant::now();
    verify_full_content(&a, &key, blake3, TOTAL_BYTES, DEFAULT_PART_SIZE)
        .await
        .expect(
            "the object assembled from skipped-plus-resent parts must hash to the source. A \
             failure here means resume produced a chimera, which is the outcome AC-2 exists \
             to rule out",
        );
    let verify_secs = t.elapsed().as_secs_f64();

    // Moving the drives to external storage must not have collapsed the
    // deployment to the un-versioned mechanism `tests/docker-compose.yml`
    // exists to prevent.
    assert_eq!(
        a.probe_attestation_mode().await.expect("probe"),
        AttestationMode::Version,
        "bucket `{BUCKET}` must still report mechanism A after the storage move"
    );

    // The durable session, after the restart finished it.
    let session = {
        let store = CatalogSessionStore::open(&db).expect("reopen");
        store.load(job).await.expect("load").expect("row survived")
    };
    assert_eq!(session.state, TransferState::Committed);
    assert_eq!(session.parts.len(), EXPECTED_PARTS as usize);
    assert_eq!(
        session.parts.iter().filter(|p| p.is_acknowledged()).count(),
        EXPECTED_PARTS as usize
    );
    assert_eq!(
        session
            .parts
            .iter()
            .find(|p| p.part_no == EXPECTED_PARTS)
            .expect("the final part")
            .len,
        LAST_PART_LEN,
        "the short final part"
    );

    eprintln!(
        "\n\
         ================ AC-2 ARTIFACT ================\n\
         object              {} B ({:.1} GB) at {}/{}\n\
         part size           {PART_SIZE} B (DEFAULT is {DEFAULT_PART_SIZE} B)\n\
         parts, from scratch {EXPECTED_PARTS}  (last part {LAST_PART_LEN} B)\n\
         killed              SIGKILL after {acked_before} durably acked parts ({upload_rate:.0} MB/s)\n\
         parts sent, resume  {parts_sent}   = {EXPECTED_PARTS} - {acked_before}\n\
         BYTES SKIPPED       {bytes_skipped} B ({:.1} GB, {:.1}% of the object)\n\
         bytes re-sent       {bytes_uploaded} B\n\
         resume wall clock   {resume_secs:.0}s\n\
         independent verify  {TOTAL_BYTES} B re-read in {verify_secs:.0}s = {:.0} MB/s, \
         BLAKE3 {} MATCHES\n\
         fixture             {}\n\
         ===============================================\n\
         Leftover: this object is NOT deleted by the test (§4.1 rule 4 fences\n\
         `delete_object` to shepherd-tier::destroy). Clean up with:\n\
           mc rm --versions --force <alias>/{BUCKET}/{}\n",
        TOTAL_BYTES,
        TOTAL_BYTES as f64 / 1e9,
        BUCKET,
        key.as_str(),
        bytes_skipped as f64 / 1e9,
        100.0 * bytes_skipped as f64 / TOTAL_BYTES as f64,
        TOTAL_BYTES as f64 / verify_secs / 1e6,
        blake3.to_hex(),
        if fixture_created {
            "created this run"
        } else {
            "reused"
        },
        key.as_str(),
    );

    let _ = std::fs::remove_dir_all(&dbdir);
}
