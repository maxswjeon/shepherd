//! Deterministic corpus and query-trace generation. **This is harness code and
//! it survives** — Phase 5's gate re-runs the bench against the real
//! `fixtures/corpus-10m`, and a Phase 0b number is only comparable to a Phase 5
//! number if the fixture is built by the same generator from the same seed.
//!
//! # Why the generator is counter-based
//!
//! Row `i` is a pure function of `(seed, i)`. Nothing depends on rows before it.
//! Three things fall out of that, and all three are needed:
//!
//! * generation parallelises across threads with no coordination;
//! * the **query trace can be derived without materialising the corpus**, which
//!   is what lets the trace be committed before the 10M-row fixture exists;
//! * any single row can be re-derived later, by hand, to check a result.
//!
//! # Why the names are realistic rather than random
//!
//! Random strings would make every candidate look equally good and would be a
//! measurement of nothing. Substring search cost depends on how often a query
//! matches, how the matches cluster, and how long the strings are. Real
//! filesystems have a small vocabulary reused constantly, heavily skewed
//! extensions, and long shared directory prefixes — all three change the answer.

use std::fmt::Write as _;
use std::io::{BufWriter, Write as _};
use std::path::Path;

use rayon::prelude::*;

use crate::{Args, Contract, splitmix64, stream};

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// Words that actually appear in file and directory names. Deliberately small:
/// a real filesystem reuses a modest vocabulary constantly, which is what makes
/// a substring query match many rows rather than one. A large vocabulary would
/// make every query near-unique and would flatter every candidate equally.
const WORDS: &[&str] = &[
    "annual",
    "archive",
    "assets",
    "audit",
    "backup",
    "budget",
    "build",
    "cache",
    "campaign",
    "client",
    "config",
    "contract",
    "customer",
    "dashboard",
    "data",
    "delivery",
    "design",
    "device",
    "diagram",
    "draft",
    "engine",
    "estimate",
    "export",
    "final",
    "finance",
    "forecast",
    "handoff",
    "handover",
    "header",
    "hotfix",
    "image",
    "import",
    "index",
    "internal",
    "invoice",
    "kickoff",
    "layout",
    "ledger",
    "legacy",
    "license",
    "logistics",
    "manifest",
    "meeting",
    "metrics",
    "migration",
    "minutes",
    "mockup",
    "monthly",
    "network",
    "notes",
    "onboarding",
    "output",
    "overview",
    "package",
    "patch",
    "payroll",
    "pipeline",
    "planning",
    "policy",
    "portrait",
    "presentation",
    "pricing",
    "product",
    "profile",
    "project",
    "proposal",
    "prototype",
    "quarterly",
    "receipt",
    "recording",
    "refactor",
    "release",
    "render",
    "report",
    "request",
    "research",
    "resource",
    "response",
    "restore",
    "review",
    "roadmap",
    "rollout",
    "sample",
    "sandbox",
    "schedule",
    "schema",
    "scratch",
    "screenshot",
    "script",
    "security",
    "server",
    "service",
    "session",
    "settings",
    "sheet",
    "sketch",
    "snapshot",
    "source",
    "specification",
    "sprint",
    "staging",
    "statement",
    "storage",
    "strategy",
    "summary",
    "support",
    "survey",
    "sync",
    "system",
    "template",
    "testing",
    "timeline",
    "tracking",
    "transcript",
    "transfer",
    "update",
    "upload",
    "usage",
    "vendor",
    "version",
    "video",
    "wireframe",
    "workflow",
    "workshop",
];

/// Extensions with realistic frequency skew. The first entries dominate because
/// on a real disk they do; a uniform extension distribution would make the
/// `.ext`-routed query class unrepresentative.
const EXTS: &[(&str, u32)] = &[
    ("jpg", 140),
    ("png", 90),
    ("pdf", 80),
    ("txt", 60),
    ("md", 55),
    ("docx", 50),
    ("xlsx", 45),
    ("json", 42),
    ("log", 40),
    ("rs", 35),
    ("ts", 33),
    ("py", 30),
    ("csv", 28),
    ("html", 25),
    ("css", 22),
    ("mp4", 20),
    ("zip", 18),
    ("pptx", 16),
    ("yaml", 15),
    ("toml", 12),
    ("svg", 12),
    ("heic", 10),
    ("mov", 9),
    ("sql", 8),
    ("java", 8),
    ("go", 7),
    ("tar.gz", 6),
    ("nef", 5),
    ("psd", 4),
    ("iso", 2),
];

/// Top-level roots, weighted the way a home directory actually is.
const ROOTS: &[&str] = &[
    "/home/user/Documents",
    "/home/user/Documents",
    "/home/user/Downloads",
    "/home/user/Pictures",
    "/home/user/Pictures",
    "/home/user/Projects",
    "/home/user/Projects",
    "/home/user/Music",
    "/home/user/Videos",
    "/home/user/Desktop",
    "/mnt/nas/shared",
    "/mnt/nas/team",
];

/// Directory-name components, distinct from file words so path-fragment queries
/// are recognisably path-shaped.
const DIRWORDS: &[&str] = &[
    "2019",
    "2020",
    "2021",
    "2022",
    "2023",
    "2024",
    "2025",
    "2026",
    "accounting",
    "admin",
    "android",
    "api",
    "archive",
    "backend",
    "benchmarks",
    "clients",
    "common",
    "components",
    "core",
    "customers",
    "デザイン",
    "docs",
    "engineering",
    "examples",
    "exports",
    "fixtures",
    "frontend",
    "hr",
    "images",
    "imports",
    "infra",
    "inbox",
    "legal",
    "lib",
    "marketing",
    "media",
    "migrations",
    "misc",
    "mobile",
    "models",
    "modules",
    "operations",
    "outbox",
    "packages",
    "personal",
    "photos",
    "platform",
    "products",
    "public",
    "quarterly",
    "reports",
    "research",
    "resources",
    "sales",
    "scripts",
    "服务",
    "shared",
    "src",
    "staging",
    "static",
    "styles",
    "support",
    "targets",
    "tests",
    "tools",
    "utils",
    "vendors",
    "웹",
    "workspace",
];

// ---------------------------------------------------------------------------
// Row model
// ---------------------------------------------------------------------------

/// One catalog row. Only the fields the metadata index actually touches: the
/// bake-off is about name/path search, and carrying the rest of the real schema
/// would inflate the fixture without changing any measured number.
pub struct Row {
    pub id: u64,
    pub parent: String,
    pub name: String,
    pub ext: &'static str,
    pub size: u64,
    pub mtime: i64,
}

impl Row {
    pub fn path(&self) -> String {
        format!("{}/{}", self.parent, self.name)
    }
}

#[inline]
fn pick<'a, T>(s: &mut u64, xs: &'a [T]) -> &'a T {
    &xs[(splitmix64(s) % xs.len() as u64) as usize]
}

/// Weighted pick over `EXTS`. Linear scan over 30 entries beats building a
/// lookup table: it runs once per row and the table would need to be threaded
/// through every call site.
#[inline]
fn pick_ext(s: &mut u64) -> &'static str {
    let total: u32 = EXTS.iter().map(|(_, w)| w).sum();
    let mut r = (splitmix64(s) % total as u64) as u32;
    for (e, w) in EXTS {
        if r < *w {
            return e;
        }
        r -= w;
    }
    EXTS[0].0
}

/// Keys the directory stream away from the row stream, so the directory tree is
/// stable even if the row generator changes shape.
const DIR_STREAM_KEY: u64 = 0xD15E_A5ED_0000_0004;

/// The directory a row lives in. Directories are drawn from a bounded space —
/// `dir_space` distinct directories — so that many files share a parent, which
/// is what real trees look like and what makes path-fragment queries return
/// many rows rather than one.
pub fn dir_for(seed: u64, dir_id: u64) -> String {
    let mut s = stream(seed ^ DIR_STREAM_KEY, dir_id);
    let root = pick(&mut s, ROOTS);
    let depth = 1 + (splitmix64(&mut s) % 4); // 1..=4 components below the root
    let mut p = String::with_capacity(64);
    p.push_str(root);
    for _ in 0..depth {
        p.push('/');
        p.push_str(pick(&mut s, DIRWORDS));
    }
    p
}

/// Row `i`, derived from `(seed, i)` alone.
pub fn row(seed: u64, i: u64, dir_space: u64) -> Row {
    let mut s = stream(seed, i);
    let dir_id = splitmix64(&mut s) % dir_space;
    let parent = dir_for(seed, dir_id);
    let ext = pick_ext(&mut s);

    // Name shapes, chosen because these are the shapes that actually occur and
    // because they stress substring search differently: camel/snake identifiers
    // have no separators to anchor on, dated names share long common prefixes,
    // and camera names are near-uniform noise.
    let shape = splitmix64(&mut s) % 100;
    let mut stem = String::with_capacity(32);
    match shape {
        // Hyphenated multi-word — the common document case.
        0..=39 => {
            let n = 2 + (splitmix64(&mut s) % 3);
            for k in 0..n {
                if k > 0 {
                    stem.push('-');
                }
                stem.push_str(pick(&mut s, WORDS));
            }
        }
        // Word plus a date. Long shared prefixes; the hard case for prefix
        // search to discriminate on.
        40..=59 => {
            let _ = write!(
                stem,
                "{}-{}-{:02}-{:02}",
                pick(&mut s, WORDS),
                2019 + splitmix64(&mut s) % 8,
                1 + splitmix64(&mut s) % 12,
                1 + splitmix64(&mut s) % 28
            );
        }
        // snake_case identifier — code.
        60..=71 => {
            let n = 2 + (splitmix64(&mut s) % 2);
            for k in 0..n {
                if k > 0 {
                    stem.push('_');
                }
                stem.push_str(pick(&mut s, WORDS));
            }
        }
        // CamelCase identifier. No separators at all: a substring scan cannot
        // anchor on punctuation here.
        72..=79 => {
            let n = 2 + (splitmix64(&mut s) % 2);
            for _ in 0..n {
                let w = pick(&mut s, WORDS);
                let mut c = w.chars();
                if let Some(f) = c.next() {
                    stem.extend(f.to_uppercase());
                    stem.push_str(c.as_str());
                }
            }
        }
        // Camera / device names — near-uniform, deliberately low-signal.
        80..=89 => {
            let _ = write!(
                stem,
                "IMG_{}{:02}{:02}_{:06}",
                2019 + splitmix64(&mut s) % 8,
                1 + splitmix64(&mut s) % 12,
                1 + splitmix64(&mut s) % 28,
                splitmix64(&mut s) % 1_000_000
            );
        }
        // Word plus version, and a versioned copy suffix. The "final-v2 (copy)"
        // family that makes users search in the first place.
        _ => {
            let _ = write!(
                stem,
                "{}-v{}",
                pick(&mut s, WORDS),
                1 + splitmix64(&mut s) % 9
            );
            if splitmix64(&mut s).is_multiple_of(4) {
                let _ = write!(stem, " (copy {})", 1 + splitmix64(&mut s) % 3);
            }
        }
    }

    Row {
        id: i,
        parent,
        name: format!("{stem}.{ext}"),
        ext,
        // Log-ish size distribution: mostly small, a long tail of large files.
        size: 1 << (10 + splitmix64(&mut s) % 20),
        mtime: 1_500_000_000 + (splitmix64(&mut s) % 250_000_000) as i64,
    }
}

/// One directory per ~50 files. Chosen to land near 200k directories at 10M
/// rows, which is the order of magnitude a large real home directory reaches.
pub fn dir_space(rows: u64) -> u64 {
    (rows / 50).max(1)
}

// ---------------------------------------------------------------------------
// Catalog fixture
// ---------------------------------------------------------------------------

pub fn catalog_path(fixtures: &Path) -> std::path::PathBuf {
    fixtures.join("catalog.sqlite")
}

/// Build the SQLite catalog fixture.
///
/// This is the shared source of truth for all three metadata candidates: FTS5
/// indexes it in place, tantivy indexes from it, and the arena is **rebuilt from
/// it** — which is the cold-start measurement the tiebreak rule's third
/// durability axis needs.
pub fn gen_catalog(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let rows = a.rows_override.unwrap_or(c.fixture.rows);
    let seed = c.fixture.seed;
    let space = dir_space(rows);

    std::fs::create_dir_all(&a.fixtures).map_err(|e| e.to_string())?;
    // ~0.10 GiB per million rows, measured on the 200k pilot.
    crate::disk_guard_start(
        &a.fixtures,
        c.disk_guard.abort_below_free_gib,
        0.10 * rows as f64 / 1e6,
    )?;

    let db = catalog_path(&a.fixtures);
    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(db.with_extension("sqlite-wal"));
    let _ = std::fs::remove_file(db.with_extension("sqlite-shm"));

    let conn = rusqlite::Connection::open(&db).map_err(|e| e.to_string())?;
    // WAL because §4.8 pins the catalog to `rusqlite` + WAL, and the write
    // discipline is part of what the background-ingest load is measuring.
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA synchronous=NORMAL;
         PRAGMA cache_size=-262144;
         CREATE TABLE file (
             id     INTEGER PRIMARY KEY,
             parent TEXT NOT NULL,
             name   TEXT NOT NULL,
             ext    TEXT NOT NULL,
             size   INTEGER NOT NULL,
             mtime  INTEGER NOT NULL
         );",
    )
    .map_err(|e| e.to_string())?;

    let t0 = std::time::Instant::now();
    const BATCH: u64 = 100_000;
    let mut done = 0u64;
    while done < rows {
        let n = BATCH.min(rows - done);
        // Generate off the write thread. String formatting dominates row cost,
        // and it is the part that parallelises.
        let batch: Vec<Row> = (done..done + n)
            .into_par_iter()
            .map(|i| row(seed, i, space))
            .collect();
        let tx = conn.unchecked_transaction().map_err(|e| e.to_string())?;
        {
            let mut st = tx
                .prepare_cached(
                    "INSERT INTO file (id,parent,name,ext,size,mtime) VALUES (?,?,?,?,?,?)",
                )
                .map_err(|e| e.to_string())?;
            for r in &batch {
                // `u64` has no `ToSql`: SQLite integers are signed 64-bit, so
                // the cast is the storage reality rather than a convenience.
                st.execute(rusqlite::params![
                    r.id as i64,
                    &r.parent,
                    &r.name,
                    r.ext,
                    r.size as i64,
                    r.mtime
                ])
                .map_err(|e| e.to_string())?;
            }
        }
        tx.commit().map_err(|e| e.to_string())?;
        done += n;
        if done.is_multiple_of(1_000_000) {
            eprintln!(
                "[gen-catalog] {done}/{rows} rows, {:.1}s",
                t0.elapsed().as_secs_f64()
            );
        }
    }
    conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
        .map_err(|e| e.to_string())?;
    let elapsed = t0.elapsed();
    let bytes = crate::path_bytes(&db);
    eprintln!(
        "[gen-catalog] {rows} rows in {:.1}s, {:.2} GiB on disk",
        elapsed.as_secs_f64(),
        bytes as f64 / 1073741824.0
    );

    crate::emit(
        &a.out,
        "fixture_catalog",
        serde_json::json!({
            "rows": rows,
            "seed": seed,
            "dir_space": space,
            "generate_seconds": elapsed.as_secs_f64(),
            "on_disk_bytes": bytes,
            "scaled_run_reason": a.scaled_run_reason,
        }),
    )
}

// ---------------------------------------------------------------------------
// Query trace
// ---------------------------------------------------------------------------

/// Keys the trace RNG into a stream separate from the corpus RNG, so adding or
/// reordering a query class can never shift which rows the corpus contains.
const TRACE_STREAM_KEY: u64 = 0x51D3_7AAC_E000_0001;

// ---------------------------------------------------------------------------
// Vector fixture
// ---------------------------------------------------------------------------

/// Distinct keyed streams. Separate constants rather than one shared stream so
/// that the corpus vectors, the cluster centres and the query perturbations are
/// mutually independent — sharing a stream would correlate a query with the
/// vector sitting at the same index and quietly inflate recall.
const VECTOR_STREAM_KEY: u64 = 0x0EC7_0217_0000_0001;
const CENTROID_STREAM_KEY: u64 = 0x0CE4_7401_0000_0002;
const QUERY_STREAM_KEY: u64 = 0x00E7_1234_0000_0003;

/// Vector for row `i`: a unit-normalised point drawn near one of
/// `centroids` cluster centres.
///
/// **Why not uniform noise.** In a uniformly random 384-dimensional cube every
/// point is nearly equidistant from every other. HNSW then has no neighbourhood
/// structure to exploit, so latency degenerates toward brute force and recall
/// becomes meaningless — the benchmark would measure an index doing a job no
/// real embedding ever asks of it. Real sentence embeddings sit on the unit
/// sphere in tight topical clusters, so the fixture is
/// `normalize(centroid + noise)` and the metric is cosine, matching §4.6.
pub fn vector_for(seed: u64, i: u64, dims: usize, centroids: u64, noise: f32, out: &mut [f32]) {
    debug_assert_eq!(out.len(), dims);
    let mut s = stream(seed ^ VECTOR_STREAM_KEY, i);
    let cid = splitmix64(&mut s) % centroids;
    centroid_into(seed, cid, out);
    for x in out.iter_mut() {
        *x += noise * gauss(&mut s);
    }
    normalize(out);
}

/// Cluster centre `cid`. Derived rather than stored: 4096 x 384 f32 would be a
/// 6 MiB table to thread through every call site, and deriving it costs the same
/// arithmetic the noise term already pays.
pub fn centroid_into(seed: u64, cid: u64, out: &mut [f32]) {
    let mut s = stream(seed ^ CENTROID_STREAM_KEY, cid);
    for x in out.iter_mut() {
        *x = gauss(&mut s);
    }
    normalize(out);
}

/// A query vector for the semantic trace class: the same construction as a
/// corpus vector, so a query lands inside the cluster structure the index was
/// built from rather than in empty space.
pub fn query_vector(seed: u64, centroid_id: u64, k: u64, noise: f32, out: &mut [f32]) {
    centroid_into(seed, centroid_id, out);
    let mut s = stream(seed ^ QUERY_STREAM_KEY, k);
    for x in out.iter_mut() {
        *x += noise * gauss(&mut s);
    }
    normalize(out);
}

/// Box-Muller, one of the two normals kept. Cheap enough at 384 dims and avoids
/// a `rand` dependency whose default RNG is not guaranteed stable across
/// versions — which would silently change the fixture on a routine bump.
#[inline]
fn gauss(s: &mut u64) -> f32 {
    let u1 = ((splitmix64(s) >> 11) as f64 / (1u64 << 53) as f64).max(1e-12);
    let u2 = (splitmix64(s) >> 11) as f64 / (1u64 << 53) as f64;
    ((-2.0 * u1.ln()).sqrt() * (std::f64::consts::TAU * u2).cos()) as f32
}

#[inline]
fn normalize(v: &mut [f32]) {
    let n: f32 = v.iter().map(|x| x * x).sum::<f32>().sqrt();
    if n > 0.0 {
        let inv = 1.0 / n;
        for x in v.iter_mut() {
            *x *= inv;
        }
    }
}

/// A trace line. `source` is the row id (lexical) or centroid id (semantic) the
/// query was derived from, and it is committed with the query so a reviewer can
/// re-derive the row and confirm the query genuinely matches something. A trace
/// of strings that return zero rows would benchmark the empty case and look
/// excellent.
pub struct TraceLine {
    pub idx: usize,
    pub class: &'static str,
    pub text: String,
    pub source: u64,
}

/// Build the committed trace deterministically from the contract.
///
/// Note it never touches the corpus: rows are re-derived on demand from
/// `(seed, id)`. That is what allows the trace to be committed before the
/// fixture is generated, which is what the gate's "fixed before 0b runs"
/// requires.
pub fn build_trace(c: &Contract) -> Vec<TraceLine> {
    let seed = c.fixture.seed;
    let rows = c.fixture.rows;
    let space = dir_space(rows);
    let total = c.query_trace.total_queries;
    let n_prefix = total * c.query_trace.pct_prefix as usize / 100;
    let n_infix = total * c.query_trace.pct_infix as usize / 100;
    let n_path = total * c.query_trace.pct_path_fragment as usize / 100;
    let n_sem = total - n_prefix - n_infix - n_path;

    let mut out = Vec::with_capacity(total);
    let mut idx = 0usize;

    // The trace RNG is a separate keyed stream from the corpus RNG, so adding a
    // query class later cannot shift which rows the corpus contains.
    let mut push = |class: &'static str, count: usize, out: &mut Vec<TraceLine>, tag: u64| {
        for k in 0..count {
            let mut s = stream(seed ^ TRACE_STREAM_KEY, tag * 1_000_000 + k as u64);
            let rid = splitmix64(&mut s) % rows;
            let r = row(seed, rid, space);
            let text = match class {
                // Prefix: the leading 3-8 chars of a real name. Short prefixes
                // match enormously; that is the point — as-you-type issues its
                // first query at 3 characters.
                "prefix" => {
                    let want = 3 + (splitmix64(&mut s) % 6) as usize;
                    take_chars(&r.name, 0, want)
                }
                // Infix: 4-8 chars from the middle of a real name. This is the
                // class FTS5-trigram is expected to struggle on and the class
                // the arena exists for.
                "infix" => {
                    let chars = r.name.chars().count();
                    let want = 4 + (splitmix64(&mut s) % 5) as usize;
                    let start = if chars > want + 1 {
                        1 + (splitmix64(&mut s) % (chars - want - 1) as u64) as usize
                    } else {
                        0
                    };
                    take_chars(&r.name, start, want)
                }
                // Path fragment: contains a '/', which per the §4.6 routing
                // table forces the L-only path. Two trailing directory
                // components, sometimes with a name prefix appended.
                "path_fragment" => {
                    let comps: Vec<&str> = r.parent.split('/').filter(|s| !s.is_empty()).collect();
                    let tail = comps.len().min(2);
                    let mut t = comps[comps.len() - tail..].join("/");
                    if splitmix64(&mut s).is_multiple_of(2) {
                        t.push('/');
                        t.push_str(&take_chars(&r.name, 0, 3));
                    }
                    t
                }
                // Semantic: a natural-language-ish phrase. Its text is not used
                // to search the metadata index at all — the vector leg uses
                // `source` as the centroid id to synthesise the query vector,
                // because Phase 0b has no embedding model wired up (that is
                // `shepherd-infer`, Phase 5). The text is committed anyway so
                // the trace is readable and so Phase 5 can embed these exact
                // strings rather than inventing new ones.
                _ => format!(
                    "{} {} about {}",
                    pick_word(&mut s),
                    pick_word(&mut s),
                    pick_word(&mut s)
                ),
            };
            let source = if class == "semantic" {
                splitmix64(&mut s) % c.fixture.centroids
            } else {
                rid
            };
            out.push(TraceLine {
                idx,
                class,
                text,
                source,
            });
            idx += 1;
        }
    };

    push("prefix", n_prefix, &mut out, 1);
    push("infix", n_infix, &mut out, 2);
    push("path_fragment", n_path, &mut out, 3);
    push("semantic", n_sem, &mut out, 4);

    // INTERLEAVE, and this is load-bearing rather than cosmetic.
    //
    // Generated class-by-class, the trace is 4000 prefix queries followed by
    // 3000 infix, then 2000 path-fragment, then 1000 semantic. Each run draws a
    // contiguous 1000-query slice — so run 0, run 1 and run 2 would every one of
    // them be *pure prefix*, and the infix class, which is the whole reason this
    // bake-off is hard, would never be measured at all. The pilot run caught
    // exactly that.
    //
    // Fixed by emitting in blocks of ten holding exactly the mandated mix
    // (4 prefix : 3 infix : 2 path : 1 semantic), with the order inside each
    // block permuted deterministically from the seed. Every 1000-query window
    // then carries the contract's composition, and no window is a single class.
    let mut buckets: std::collections::BTreeMap<&str, std::collections::VecDeque<TraceLine>> =
        std::collections::BTreeMap::new();
    for l in out {
        buckets.entry(l.class).or_default().push_back(l);
    }
    let mut mixed = Vec::with_capacity(total);
    let mut block: Vec<&str> = Vec::new();
    let mut s = stream(seed ^ TRACE_STREAM_KEY, 0xFFFF_FFFF);
    let mut i = 0usize;
    while mixed.len() < total {
        if block.is_empty() {
            for (class, n) in [
                ("prefix", c.query_trace.pct_prefix / 10),
                ("infix", c.query_trace.pct_infix / 10),
                ("path_fragment", c.query_trace.pct_path_fragment / 10),
                ("semantic", c.query_trace.pct_semantic / 10),
            ] {
                for _ in 0..n {
                    block.push(class);
                }
            }
            // Fisher-Yates over the ten slots.
            for k in (1..block.len()).rev() {
                block.swap(k, (splitmix64(&mut s) % (k as u64 + 1)) as usize);
            }
        }
        let class = block.pop().unwrap();
        // A bucket can run dry only if the percentages do not divide evenly into
        // tens; fall through to any non-empty bucket rather than emitting fewer
        // queries than the contract fixes.
        let take = if buckets.get(class).is_some_and(|b| !b.is_empty()) {
            class
        } else {
            match buckets.iter().find(|(_, b)| !b.is_empty()) {
                Some((k, _)) => k,
                None => break,
            }
        };
        if let Some(mut l) = buckets.get_mut(take).and_then(|b| b.pop_front()) {
            l.idx = i;
            i += 1;
            mixed.push(l);
        }
    }
    mixed
}

fn pick_word(s: &mut u64) -> &'static str {
    WORDS[(splitmix64(s) % WORDS.len() as u64) as usize]
}

/// Character-wise slice. `DIRWORDS` deliberately contains non-ASCII entries, so
/// byte slicing here would panic on a multi-byte boundary — and a corpus with no
/// non-ASCII names would not represent the filesystems this product targets.
fn take_chars(s: &str, start: usize, n: usize) -> String {
    s.chars().skip(start).take(n).collect()
}

pub fn gen_trace(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let path = Path::new(&c.query_trace.file);
    if let Some(p) = path.parent() {
        std::fs::create_dir_all(p).map_err(|e| e.to_string())?;
    }
    let lines = build_trace(&c);

    let f = std::fs::File::create(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let mut w = BufWriter::new(f);
    writeln!(
        w,
        "# shepherd-bench query trace v1 — GENERATED, COMMITTED, AND FIXED BEFORE THE RUN.\n\
         # Regenerate with: shepherd-bench gen-trace\n\
         # Derived purely from bench-contract.toml [fixture].seed = {}; no corpus needed.\n\
         # columns: idx <TAB> class <TAB> query <TAB> source\n\
         #   source = corpus row id (lexical classes) or centroid id (semantic class),\n\
         #   so any line can be checked by re-deriving the row it came from.",
        c.fixture.seed
    )
    .map_err(|e| e.to_string())?;
    for l in &lines {
        writeln!(w, "{}\t{}\t{}\t{}", l.idx, l.class, l.text, l.source)
            .map_err(|e| e.to_string())?;
    }
    w.flush().map_err(|e| e.to_string())?;

    let mut counts = std::collections::BTreeMap::new();
    for l in &lines {
        *counts.entry(l.class).or_insert(0usize) += 1;
    }
    eprintln!("[gen-trace] {} -> {} queries", path.display(), lines.len());
    for (k, v) in &counts {
        eprintln!("[gen-trace]   {k:<14} {v}");
    }
    Ok(())
}

/// Load the committed trace. Used by both benchmark legs.
pub fn load_trace(c: &Contract) -> Result<Vec<(String, String, u64)>, String> {
    let path = Path::new(&c.query_trace.file);
    let text = std::fs::read_to_string(path).map_err(|e| {
        format!(
            "{}: {e} — run `shepherd-bench gen-trace` first; the trace is a \
             committed input, not something a benchmark run may invent",
            path.display()
        )
    })?;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let mut f = line.split('\t');
        let _idx = f.next();
        let class = f.next().ok_or("trace: missing class")?;
        let q = f.next().ok_or("trace: missing query")?;
        let src: u64 = f
            .next()
            .ok_or("trace: missing source")?
            .parse()
            .map_err(|e| format!("trace: bad source: {e}"))?;
        out.push((class.to_string(), q.to_string(), src));
    }
    if out.len() != c.query_trace.total_queries {
        return Err(format!(
            "trace has {} lines but the contract fixes {}. The trace is \
             precommitted; regenerate it deliberately or fix the contract, but \
             do not run against a mismatched pair.",
            out.len(),
            c.query_trace.total_queries
        ));
    }
    Ok(out)
}
