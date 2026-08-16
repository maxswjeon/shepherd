//! Fixture generator and benchmark harness — Phase 0b, the index bake-off.
//!
//! # What survives and what does not
//!
//! **The harness survives.** That is: the deterministic corpus generator
//! (`generate.rs`), the contract loader, the machine probe, the latency
//! statistics, the RSS accounting, the cold-cache protocol, and the
//! `bench-baseline.json` writer in this file. Phase 5's gate re-runs the same
//! bench against the real `fixtures/corpus-10m`, so a number produced now and a
//! number produced then have to be comparable, which they only are if the
//! measuring apparatus is the same code.
//!
//! **The candidates do not survive.** The three metadata candidate
//! implementations in `meta_bench.rs` are spike code written to be measured, not
//! to be shipped. Exactly one of them is re-implemented properly in
//! `shepherd-index/src/meta.rs` at Phase 1 (task T7), and at that point the
//! other two, plus their entries in this crate's manifest, are deleted.
//!
//! # Why the contract is a file and not flags
//!
//! §9's Phase 0a/0b gate requires the numeric workload contract to be *fixed
//! before 0b runs*. A contract that lives in command-line flags is fixed by
//! whoever types the command, which is the same person reading the result. So
//! it lives in `bench-contract.toml`, committed in its own commit ahead of any
//! measurement, and this harness refuses to run a workload the contract does
//! not describe.

mod ann_bench;
mod generate;
mod meta_bench;

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// The precommitted contract (bench-contract.toml)
// ---------------------------------------------------------------------------

/// The numeric workload contract. Every field here is a number the gate says
/// must be fixed before the run, so every field is `#[serde(deny_unknown_fields)]`
/// -adjacent in spirit: a contract that silently ignores a key someone added is
/// a contract that can be edited without effect, which is worse than no file.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Contract {
    pub contract_version: u32,
    pub reference_machine: ReferenceMachine,
    pub fixture: Fixture,
    pub query_trace: QueryTrace,
    pub execution: Execution,
    pub statistics: Statistics,
    pub bars: Bars,
    pub tiebreak: Tiebreak,
    pub disk_guard: DiskGuard,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceMachine {
    pub declared_cores: usize,
    pub declared_ram_gib: u32,
    pub declared_storage_class: String,
    pub pin_to_cores: String,
    pub substitution_is_a_rebaseline: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Fixture {
    pub seed: u64,
    pub rows: u64,
    pub vectors: u64,
    pub dimensions: usize,
    pub vectors_per_shard: u64,
    pub centroids: u64,
    pub cluster_noise: f32,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryTrace {
    pub file: String,
    pub total_queries: usize,
    pub pct_prefix: u32,
    pub pct_infix: u32,
    pub pct_path_fragment: u32,
    pub pct_semantic: u32,
    pub lexical_classes: Vec<String>,
    pub semantic_classes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Execution {
    pub query_clients: usize,
    pub background_ingest: bool,
    pub background_ingest_rows_per_sec: u64,
    pub cache_states: Vec<String>,
    pub top_k: usize,
    pub result_limit: usize,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Statistics {
    pub queries_per_run: usize,
    pub runs: usize,
    pub accept_on: String,
    pub drift_flag_pct: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bars {
    pub metadata_p95_ms: f64,
    pub vector_p95_ms: f64,
    pub ac46_ceiling_min_gib: f64,
    pub ac46_ceiling_max_gib: f64,
    pub ann_recall_at_10_floor: f64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Tiebreak {
    pub rule_text: String,
    pub latency_tie_pct: f64,
    pub scored_axes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DiskGuard {
    pub abort_below_free_gib: f64,
}

impl Contract {
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read contract {}: {e}", path.display()))?;
        let c: Contract = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        c.validate()?;
        Ok(c)
    }

    /// Internal consistency. A contract that does not add to 100% would let the
    /// query mix drift without anyone noticing which is exactly the failure the
    /// precommitment is meant to prevent.
    fn validate(&self) -> Result<(), String> {
        let pct = self.query_trace.pct_prefix
            + self.query_trace.pct_infix
            + self.query_trace.pct_path_fragment
            + self.query_trace.pct_semantic;
        if pct != 100 {
            return Err(format!(
                "query_trace percentages sum to {pct}, expected 100"
            ));
        }
        if !self
            .fixture
            .vectors
            .is_multiple_of(self.fixture.vectors_per_shard)
        {
            return Err("fixture.vectors must be a whole multiple of vectors_per_shard".into());
        }
        if self.statistics.accept_on != "median_of_runs_p95" {
            return Err(format!(
                "statistics.accept_on = {:?}; this harness only implements \
                 \"median_of_runs_p95\" and will not silently accept on another rule",
                self.statistics.accept_on
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Machine probe — what we ACTUALLY ran on
// ---------------------------------------------------------------------------

/// The contract declares a reference machine; this records the one in front of
/// us. They are separate fields in `bench-baseline.json` on purpose: the gate
/// says "any substitution re-baselines rather than compares", and a single
/// merged "machine" field would make the substitution invisible.
#[derive(Debug, Serialize)]
pub struct MachineActual {
    pub cpu_model: String,
    pub cpu_logical_cores: usize,
    pub cores_pinned_to: String,
    pub ram_total_gib: f64,
    pub storage_device: String,
    pub storage_rotational: bool,
    pub storage_note: String,
    pub kernel: String,
    pub virtualization: String,
    pub rustc: String,
    pub sqlite: String,
    pub usearch: String,
    pub usearch_simd_compiled: String,
    pub usearch_simd_available: String,
}

fn first_line(cmd: &str, args: &[&str]) -> String {
    Command::new(cmd)
        .args(args)
        .output()
        .ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.lines().next().unwrap_or("").trim().to_string())
        .unwrap_or_else(|| "unknown".into())
}

fn read_trim(path: &str) -> String {
    std::fs::read_to_string(path)
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into())
}

pub fn probe_machine(pinned: &str) -> MachineActual {
    let cpuinfo = std::fs::read_to_string("/proc/cpuinfo").unwrap_or_default();
    let cpu_model = cpuinfo
        .lines()
        .find(|l| l.starts_with("model name"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|| "unknown".into());
    let meminfo = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let ram_kb: f64 = meminfo
        .lines()
        .find(|l| l.starts_with("MemTotal:"))
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(0.0);

    MachineActual {
        cpu_model,
        cpu_logical_cores: std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(0),
        cores_pinned_to: pinned.to_string(),
        ram_total_gib: ram_kb / 1024.0 / 1024.0,
        storage_device: first_line("lsblk", &["-dno", "NAME,MODEL", "/dev/sda"]),
        storage_rotational: read_trim("/sys/block/sda/queue/rotational") == "1",
        storage_note: "QEMU/KVM virtual block device, non-rotational, `none` I/O \
                       scheduler. NOT a bare-metal NVMe: the contract's declared \
                       storage class is not met and this is recorded as a \
                       substitution, not as an equivalent."
            .into(),
        kernel: first_line("uname", &["-sr"]),
        virtualization: first_line("systemd-detect-virt", &[]),
        rustc: first_line("rustc", &["--version"]),
        sqlite: rusqlite::version().to_string(),
        usearch: usearch::version().to_string(),
        usearch_simd_compiled: usearch::hardware_acceleration_compiled(),
        usearch_simd_available: usearch::hardware_acceleration_available(),
    }
}

// ---------------------------------------------------------------------------
// Latency statistics — §9's rule, implemented literally
// ---------------------------------------------------------------------------

/// Percentiles of one run of `n` queries.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct Percentiles {
    pub n: usize,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
}

impl Percentiles {
    /// Nearest-rank percentile on the sorted sample. Nearest-rank rather than
    /// interpolated because with n = 1000 the two differ in the third decimal
    /// and nearest-rank is the one a reader can recompute by hand from the raw
    /// latencies, which matters more here than the smoother estimator.
    pub fn of(mut samples: Vec<Duration>) -> Self {
        assert!(!samples.is_empty(), "no latency samples");
        samples.sort_unstable();
        let ms = |d: Duration| d.as_secs_f64() * 1000.0;
        let at = |q: f64| {
            let rank = ((q * samples.len() as f64).ceil() as usize).max(1);
            ms(samples[rank - 1])
        };
        let sum: f64 = samples.iter().map(|d| ms(*d)).sum();
        Self {
            n: samples.len(),
            p50_ms: at(0.50),
            p95_ms: at(0.95),
            p99_ms: at(0.99),
            max_ms: ms(*samples.last().unwrap()),
            mean_ms: sum / samples.len() as f64,
        }
    }
}

/// The `runs`-many repetitions of one (candidate, cache-state) cell, reduced by
/// the contract's acceptance rule.
#[derive(Debug, Clone, Serialize)]
pub struct RunSet {
    pub runs: Vec<Percentiles>,
    /// The number the gate is decided on: **median across runs of each run's
    /// p95**. Not the p95 of the pooled samples — pooling would let one slow run
    /// be absorbed by two fast ones, and §9 says median-of-runs.
    pub accepted_p95_ms: f64,
    pub median_p50_ms: f64,
    pub median_p99_ms: f64,
    /// Spread across runs as a percentage of the accepted p95. The contract
    /// flags >10%: a cell that drifts that much between identical runs is not a
    /// measurement anyone should decide an architecture on.
    pub run_to_run_drift_pct: f64,
    pub drift_flagged: bool,
}

impl RunSet {
    pub fn reduce(runs: Vec<Percentiles>, drift_flag_pct: f64) -> Self {
        assert!(!runs.is_empty(), "no runs");
        let median = |mut v: Vec<f64>| -> f64 {
            v.sort_by(|a, b| a.partial_cmp(b).unwrap());
            v[v.len() / 2]
        };
        let p95s: Vec<f64> = runs.iter().map(|r| r.p95_ms).collect();
        let accepted = median(p95s.clone());
        let lo = p95s.iter().cloned().fold(f64::INFINITY, f64::min);
        let hi = p95s.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
        let drift = if accepted > 0.0 {
            (hi - lo) / accepted * 100.0
        } else {
            0.0
        };
        Self {
            median_p50_ms: median(runs.iter().map(|r| r.p50_ms).collect()),
            median_p99_ms: median(runs.iter().map(|r| r.p99_ms).collect()),
            accepted_p95_ms: accepted,
            run_to_run_drift_pct: drift,
            drift_flagged: drift > drift_flag_pct,
            runs,
        }
    }
}

// ---------------------------------------------------------------------------
// RSS accounting
// ---------------------------------------------------------------------------

/// Peak resident set size of this process, from `/proc/self/status: VmHWM`.
///
/// **Read the method before reading the number.** `VmHWM` is a high-water mark
/// for the whole process and it never falls, so it is only meaningful when a
/// candidate is measured in a freshly spawned process — which is why the
/// per-candidate runs are separate `shepherd-bench` invocations rather than
/// stages of one long-lived one.
///
/// For `view()`-mmap'd usearch shards, resident pages are page-cache-backed and
/// their accounting is the kernel's decision, not the allocator's, so `VmHWM`
/// alone would understate the true memory demand. Every mmap-mode measurement
/// therefore reports `VmHWM` **and** on-disk index bytes **and** `VmRSS` at the
/// end of the query phase, and the decision text says which of the three it is
/// using. A single unqualified "RAM" number for an mmap'd index is not a
/// falsifiable claim.
pub fn vm_hwm_bytes() -> u64 {
    proc_status_kb("VmHWM:") * 1024
}

pub fn vm_rss_bytes() -> u64 {
    proc_status_kb("VmRSS:") * 1024
}

fn proc_status_kb(key: &str) -> u64 {
    std::fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|s| {
            s.lines()
                .find(|l| l.starts_with(key))
                .and_then(|l| l.split_whitespace().nth(1))
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(0)
}

/// Total bytes of a file or of every file under a directory.
pub fn path_bytes(path: &Path) -> u64 {
    let Ok(md) = std::fs::metadata(path) else {
        return 0;
    };
    if md.is_file() {
        return md.len();
    }
    let mut total = 0;
    if let Ok(rd) = std::fs::read_dir(path) {
        for e in rd.flatten() {
            total += path_bytes(&e.path());
        }
    }
    total
}

pub fn free_bytes(path: &Path) -> u64 {
    // `df --output=avail -B1` is parsed rather than statvfs-via-libc because the
    // harness has no libc dependency and this runs once per leg, not per query.
    let out = Command::new("df")
        .args(["--output=avail", "-B1"])
        .arg(path)
        .output();
    out.ok()
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .and_then(|s| s.lines().nth(1).and_then(|l| l.trim().parse().ok()))
        .unwrap_or(0)
}

/// Abort rather than fill a shared box. §9 has no opinion on this; operating a
/// dev machine at 87% full does.
pub fn disk_guard(path: &Path, min_free_gib: f64) -> Result<(), String> {
    let free = free_bytes(path) as f64 / (1024.0 * 1024.0 * 1024.0);
    if free < min_free_gib {
        return Err(format!(
            "disk guard: {free:.1} GiB free at {} is below the contract's \
             {min_free_gib:.1} GiB floor. Refusing to start this leg. \
             This is an escalation, not a retry-with-less.",
            path.display()
        ));
    }
    eprintln!("[disk] {free:.1} GiB free (floor {min_free_gib:.1} GiB) — ok");
    Ok(())
}

// ---------------------------------------------------------------------------
// Cold-cache protocol
// ---------------------------------------------------------------------------

/// Drop the kernel page cache, dentries and inodes.
///
/// The cold run is not decoration. The 300 ms vector budget assumes a warm page
/// cache over mmap'd shards, and the first query after a boot is where a user
/// forms their impression of whether the product is fast. A cold p95 over budget
/// while the warm p95 passes is an escalation, not a pass.
pub fn drop_page_cache() -> Result<(), String> {
    let sync = Command::new("sync").status();
    if !matches!(sync, Ok(s) if s.success()) {
        return Err("sync failed".into());
    }
    let out = Command::new("sudo")
        .args(["-n", "sh", "-c", "echo 3 > /proc/sys/vm/drop_caches"])
        .output()
        .map_err(|e| format!("drop_caches: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "drop_caches failed: {}. A cold run cannot be faked by \
             re-opening files; without this the cold number must be reported as \
             NOT MEASURED rather than estimated.",
            String::from_utf8_lossy(&out.stderr).trim()
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Deterministic RNG
// ---------------------------------------------------------------------------

/// SplitMix64. Chosen over the `rand` crate for one reason: it is *indexable*.
/// `mix(seed, i)` yields row `i`'s bits without generating rows `0..i`, which is
/// what lets the corpus be generated in parallel across 8 threads, lets the
/// query trace be derived from row indices without materializing the corpus,
/// and lets any single row be re-derived later to check a result by hand.
#[inline]
pub fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Stream keyed by `(seed, index)`, so every row is independent of every other.
#[inline]
pub fn stream(seed: u64, index: u64) -> u64 {
    let mut s = seed ^ index.wrapping_mul(0xD6E8_FEB8_6659_FD93);
    splitmix64(&mut s);
    s
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

const USAGE: &str = "\
shepherd-bench — Phase 0b index bake-off harness

USAGE:
  shepherd-bench <command> [options]

COMMANDS:
  smoke                    Prove the dependency stack works end to end at toy
                           scale before generating anything large.
  machine                  Print the probed machine record as JSON.
  gen-trace                Write the committed query trace from the contract seed.
  gen-catalog              Generate the SQLite catalog fixture (contract rows).
  build-meta   <candidate> Build one metadata index: arena | tantivy | fts5
  bench-meta   <candidate> Benchmark one metadata candidate.
  build-ann    <precision> Build usearch shards: f32 | f16 | i8
  bench-ann    <precision> Benchmark one usearch precision.
  recall-ann   <precision> Recall@10 vs an exact brute-force oracle.

GLOBAL OPTIONS:
  --contract <path>        Default: bench-contract.toml
  --fixtures <path>        Default: fixtures/
  --out      <path>        Default: bench-baseline.json
  --cache    warm|cold     Default: warm
  --rows     <n>           Scale override. REQUIRES --scaled-run-reason.
  --scaled-run-reason <s>  Why this run is not the contract scale. Recorded in
                           the output so a scaled number can never be read as a
                           contract-scale number.
";

pub struct Args {
    pub command: String,
    pub target: Option<String>,
    pub contract: PathBuf,
    pub fixtures: PathBuf,
    pub out: PathBuf,
    pub cache: String,
    pub rows_override: Option<u64>,
    pub scaled_run_reason: Option<String>,
}

fn parse_args() -> Result<Args, String> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        return Err(USAGE.into());
    }
    let mut a = Args {
        command: argv[0].clone(),
        target: None,
        contract: PathBuf::from("bench-contract.toml"),
        fixtures: PathBuf::from("fixtures"),
        out: PathBuf::from("bench-baseline.json"),
        cache: "warm".into(),
        rows_override: None,
        scaled_run_reason: None,
    };
    let mut i = 1;
    while i < argv.len() {
        let arg = &argv[i];
        let mut take = |name: &str| -> Result<String, String> {
            i += 1;
            argv.get(i)
                .cloned()
                .ok_or_else(|| format!("{name} needs a value"))
        };
        match arg.as_str() {
            "--contract" => a.contract = PathBuf::from(take("--contract")?),
            "--fixtures" => a.fixtures = PathBuf::from(take("--fixtures")?),
            "--out" => a.out = PathBuf::from(take("--out")?),
            "--cache" => a.cache = take("--cache")?,
            "--rows" => {
                a.rows_override = Some(
                    take("--rows")?
                        .parse()
                        .map_err(|e| format!("--rows: {e}"))?,
                )
            }
            "--scaled-run-reason" => a.scaled_run_reason = Some(take("--scaled-run-reason")?),
            other if other.starts_with("--") => return Err(format!("unknown flag {other}")),
            other => a.target = Some(other.to_string()),
        }
        i += 1;
    }
    // A scaled run that does not say why it is scaled is the exact failure the
    // assignment forbids: "silently benchmarking something smaller and reporting
    // it as the real thing".
    if a.rows_override.is_some() && a.scaled_run_reason.is_none() {
        return Err(
            "--rows without --scaled-run-reason is refused: a scaled run must \
                    carry its own reason into bench-baseline.json"
                .into(),
        );
    }
    if !matches!(a.cache.as_str(), "warm" | "cold") {
        return Err(format!("--cache must be warm|cold, got {}", a.cache));
    }
    Ok(a)
}

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("shepherd-bench: {e}");
            std::process::ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    match args.command.as_str() {
        "smoke" => smoke(),
        "machine" => {
            let c = Contract::load(&args.contract)?;
            let m = probe_machine(&c.reference_machine.pin_to_cores);
            println!(
                "{}",
                serde_json::to_string_pretty(&m).map_err(|e| e.to_string())?
            );
            Ok(())
        }
        "gen-trace" => generate::gen_trace(&args),
        "gen-catalog" => generate::gen_catalog(&args),
        "build-meta" => meta_bench::build(&args),
        "bench-meta" => meta_bench::bench(&args),
        "build-ann" => ann_bench::build(&args),
        "bench-ann" => ann_bench::bench(&args),
        "recall-ann" => ann_bench::recall(&args),
        other => Err(format!("unknown command {other}\n\n{USAGE}")),
    }
}

// ---------------------------------------------------------------------------
// Result emission
// ---------------------------------------------------------------------------

/// Append one measured cell to `bench-baseline.json`.
///
/// Append rather than overwrite: the legs run as separate processes (so `VmHWM`
/// means something), sequentially over hours, and a crash in leg 4 must not
/// erase legs 1-3.
pub fn emit(out: &Path, key: &str, value: serde_json::Value) -> Result<(), String> {
    let mut doc: serde_json::Value = match std::fs::read_to_string(out) {
        Ok(s) => serde_json::from_str(&s).map_err(|e| format!("{}: {e}", out.display()))?,
        Err(_) => serde_json::json!({}),
    };
    doc.as_object_mut()
        .ok_or("bench-baseline.json is not an object")?
        .insert(key.to_string(), value);
    let text = serde_json::to_string_pretty(&doc).map_err(|e| e.to_string())?;
    std::fs::write(out, text).map_err(|e| format!("{}: {e}", out.display()))?;
    eprintln!("[emit] {} <- {key}", out.display());
    Ok(())
}

// ---------------------------------------------------------------------------
// Smoke test
// ---------------------------------------------------------------------------

/// Toy-scale end-to-end exercise of every dependency the bake-off relies on.
///
/// Runs in seconds. Its whole purpose is to fail *before* an hour of fixture
/// generation if an API moved, a feature flag is missing (FTS5 in particular is
/// a compile-time SQLite option and its absence shows up only at query time), or
/// `view()` does not do what §4.6 assumes it does.
fn smoke() -> Result<(), String> {
    let dir = std::env::temp_dir().join("shepherd-bench-smoke");
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
    let mut report = String::new();

    // -- memchr ------------------------------------------------------------
    let arena = b"alpha.txt\0quarterly-report.pdf\0notes.md\0";
    let finder = memchr::memmem::Finder::new(b"report");
    let hits = finder.find_iter(arena).count();
    writeln!(report, "memchr        : {hits} hit(s) — ok").unwrap();
    if hits != 1 {
        return Err("memchr smoke: expected exactly 1 hit".into());
    }

    // -- SQLite FTS5 trigram ----------------------------------------------
    // FTS5 and the trigram tokenizer are both compile-time SQLite options. If
    // `bundled` ever stops enabling them this line is where we find out.
    let conn = rusqlite::Connection::open_in_memory().map_err(|e| e.to_string())?;
    conn.execute_batch(
        "CREATE VIRTUAL TABLE t USING fts5(name, tokenize='trigram');
         INSERT INTO t(name) VALUES ('quarterly-report.pdf'), ('notes.md');",
    )
    .map_err(|e| format!("FTS5 trigram unavailable in this SQLite build: {e}"))?;
    let n: i64 = conn
        .query_row(
            "SELECT count(*) FROM t WHERE name LIKE '%report%'",
            [],
            |r| r.get(0),
        )
        .map_err(|e| e.to_string())?;
    writeln!(
        report,
        "sqlite {:<7}: FTS5 trigram ok, {n} row(s)",
        rusqlite::version()
    )
    .unwrap();
    if n != 1 {
        return Err("FTS5 smoke: expected exactly 1 row".into());
    }

    // -- tantivy with an n-gram tokenizer ---------------------------------
    {
        use tantivy::schema::{STORED, Schema, TEXT, TextFieldIndexing, TextOptions};
        use tantivy::tokenizer::NgramTokenizer;
        let mut sb = Schema::builder();
        let opts = TextOptions::default().set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer("ng")
                .set_index_option(tantivy::schema::IndexRecordOption::WithFreqs),
        );
        let name = sb.add_text_field("name", opts);
        let _id = sb.add_u64_field("id", STORED);
        let _p = sb.add_text_field("path", TEXT);
        let schema = sb.build();
        let idx = tantivy::Index::create_in_ram(schema);
        idx.tokenizers().register(
            "ng",
            NgramTokenizer::all_ngrams(3, 3).map_err(|e| e.to_string())?,
        );
        let mut w: tantivy::IndexWriter = idx.writer(50_000_000).map_err(|e| e.to_string())?;
        w.add_document(tantivy::doc!(name => "quarterly-report.pdf"))
            .map_err(|e| e.to_string())?;
        w.add_document(tantivy::doc!(name => "notes.md"))
            .map_err(|e| e.to_string())?;
        w.commit().map_err(|e| e.to_string())?;
        let reader = idx.reader().map_err(|e| e.to_string())?;
        let searcher = reader.searcher();
        let qp = tantivy::query::QueryParser::for_index(&idx, vec![name]);
        let q = qp.parse_query("\"rep\"").map_err(|e| e.to_string())?;
        let top = searcher
            .search(
                &q,
                &tantivy::collector::TopDocs::with_limit(10).order_by_score(),
            )
            .map_err(|e| e.to_string())?;
        writeln!(
            report,
            "tantivy       : ngram(3,3) ok, {} hit(s)",
            top.len()
        )
        .unwrap();
        if top.is_empty() {
            return Err("tantivy smoke: ngram query returned nothing".into());
        }
    }

    // -- usearch: build, save, view(), search ------------------------------
    {
        use usearch::{Index, IndexOptions, MetricKind, ScalarKind};
        let dims = 384usize;
        for (label, q) in [
            ("f32", ScalarKind::F32),
            ("f16", ScalarKind::F16),
            ("i8", ScalarKind::I8),
        ] {
            let opts = IndexOptions {
                dimensions: dims,
                metric: MetricKind::Cos,
                quantization: q,
                connectivity: 16,
                expansion_add: 128,
                expansion_search: 64,
                multi: false,
            };
            let idx = Index::new(&opts).map_err(|e| e.to_string())?;
            idx.reserve(2_000).map_err(|e| e.to_string())?;
            let mut v = vec![0f32; dims];
            for k in 0..2_000u64 {
                let mut s = stream(1, k);
                for x in v.iter_mut() {
                    *x = (splitmix64(&mut s) as f64 / u64::MAX as f64) as f32 - 0.5;
                }
                idx.add(k, &v).map_err(|e| e.to_string())?;
            }
            let p = dir.join(format!("smoke-{label}.usearch"));
            idx.save(p.to_str().unwrap()).map_err(|e| e.to_string())?;
            drop(idx);

            // The §4.6 assumption under test: an index can be re-opened as a
            // read-only memory map rather than loaded into the heap.
            let viewed = Index::new(&opts).map_err(|e| e.to_string())?;
            viewed
                .view(p.to_str().unwrap())
                .map_err(|e| format!("view() failed for {label}: {e}"))?;
            let m = viewed.search(&v, 10).map_err(|e| e.to_string())?;
            writeln!(
                report,
                "usearch {label:<4}  : save+view()+search ok, {} neighbour(s), \
                 on-disk {:.1} MiB, size {}",
                m.keys.len(),
                path_bytes(&p) as f64 / 1048576.0,
                viewed.size()
            )
            .unwrap();
            if m.keys.len() != 10 {
                return Err(format!("usearch {label} smoke: expected 10 neighbours"));
            }
        }
    }

    // -- cold-cache privilege ---------------------------------------------
    match drop_page_cache() {
        Ok(()) => writeln!(report, "drop_caches   : ok (cold runs are measurable)").unwrap(),
        Err(e) => writeln!(
            report,
            "drop_caches   : UNAVAILABLE — {e}\n                cold-cache rows \
             must be reported as NOT MEASURED"
        )
        .unwrap(),
    }

    let _ = std::fs::remove_dir_all(&dir);
    print!("{report}");
    println!("\nsmoke: all dependency checks passed.");
    Ok(())
}
