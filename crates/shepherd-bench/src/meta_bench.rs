//! The metadata bake-off — §4.6's three candidates against the 50 ms bar.
//!
//! # Status of this file
//!
//! **SPIKE CODE. Only the measurement scaffolding at the bottom survives.** The
//! three candidate implementations exist to be measured, not to be shipped.
//! Exactly one is re-implemented properly in `shepherd-index/src/meta.rs` at
//! Phase 1 (task T7), and the other two leave this crate along with their
//! manifest entries. Nothing here has production error handling, deletion
//! support or crash recovery, and it should not acquire any.
//!
//! # What all three candidates must do
//!
//! §4.6's routing table sends three query classes down the L-only as-you-type
//! path, and a candidate has to serve all three or it has not answered AC-40:
//!
//! * **prefix** — the leading characters of a filename. Cheap for anything with
//!   an ordered term dictionary.
//! * **infix substring** — characters from the middle of a filename, with no
//!   token boundary to anchor on. This is the class that makes the problem hard
//!   and it is why the plan already expects the obvious answer to fail.
//! * **path fragment** — a query containing `/`, matched against the full path.
//!
//! Matching is **case-insensitive** — as-you-type search that is case-sensitive
//! is not the feature AC-40 describes — and folding is ASCII-only. The corpus
//! contains non-ASCII directory names on purpose; full Unicode case folding is a
//! different and much slower operation, and applying it to one candidate and not
//! another would silently decide the bake-off.
//!
//! # Fairness rules this file is built around
//!
//! These exist because the easiest way to get a wrong answer here is to measure
//! three subtly different jobs and compare the numbers.
//!
//! 1. **One definition of a match.** `qualifies()` decides what each class means
//!    for every candidate. Three separately-drifting definitions of "prefix"
//!    would make the comparison meaningless.
//! 2. **Every candidate carries the background ingest load.** An earlier draft
//!    of this file wired the writer only to FTS5, which would have charged the
//!    one candidate with a real durability story for work the other two were
//!    silently excused. All three now take concurrent writes.
//! 3. **Early exit at `result_limit` for all three.** An as-you-type UI shows one
//!    screenful; an exact total for a 3-character prefix matching a million rows
//!    is work no user sees. The honest consequence, recorded rather than buried:
//!    **the worst case for every candidate is a query matching nothing**, since
//!    that is the one that cannot exit early.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use crate::generate::{self, Row};
use crate::{Args, Contract, Percentiles, RunSet};

// ---------------------------------------------------------------------------
// Shared query semantics — one definition, used by all three candidates
// ---------------------------------------------------------------------------

/// ASCII-lowercase. Deliberately not `str::to_lowercase`, which is
/// Unicode-aware, allocates, and can change a string's byte length — the last of
/// which would corrupt the arena's offset table.
fn fold(s: &str) -> String {
    s.to_ascii_lowercase()
}

/// Is the hit at `hit_at` inside the *name* component of `path`?
#[inline]
fn hit_in_name(path: &[u8], hit_at: usize) -> bool {
    !path[hit_at..].contains(&b'/')
}

/// Does a hit at byte offset `hit_at` in `path` satisfy `class`?
#[inline]
fn qualifies(class: &str, path: &[u8], hit_at: usize) -> bool {
    match class {
        // Prefix: the hit starts the filename — it is in the name component and
        // is immediately preceded by the separator (or by nothing at all).
        "prefix" => hit_in_name(path, hit_at) && (hit_at == 0 || path[hit_at - 1] == b'/'),
        // Infix: anywhere inside the name component, but not in a directory.
        "infix" => hit_in_name(path, hit_at),
        // Path fragment: anywhere in the full path.
        _ => true,
    }
}

// ---------------------------------------------------------------------------
// Candidate (a) — in-RAM name arena + SIMD substring scan
// ---------------------------------------------------------------------------

/// The user's own "Everything" reference from interview Round 4.
///
/// Layout: one contiguous `Vec<u8>` of NUL-terminated, ASCII-folded full paths
/// plus a `Vec<u32>` of start offsets. Row id is the index into the offset
/// table, so the id column costs nothing.
///
/// **Why the scan is segmented across the rayon pool.** §4.6 projects "a SIMD
/// substring scan at several GB/s crosses 350 MB in tens of ms". At 10M rows the
/// arena is nearer 700 MB — full paths, not bare names — and a single `memmem`
/// stream runs at a few GB/s, which puts a *single-threaded* full scan at or
/// over the 50 ms bar on its own. Any real implementation of this design would
/// parallelise, so this one does. Measuring it single-threaded would be
/// measuring a strawman and would hand the bake-off to another candidate on a
/// technicality.
///
/// The growable state is behind an `RwLock` because fairness rule 2 requires
/// this candidate to take concurrent writes like the other two.
pub struct Arena {
    inner: RwLock<ArenaInner>,
}

struct ArenaInner {
    bytes: Vec<u8>,
    /// `starts[i] .. starts[i+1] - 1` is entry `i`; the byte at `starts[i+1]-1`
    /// is the NUL terminator.
    starts: Vec<u32>,
    /// Segment boundaries as indices into `starts`, one per parallel scan task.
    segments: Vec<(usize, usize)>,
}

impl ArenaInner {
    fn resegment(&mut self) {
        let n = self.starts.len() - 1;
        let tasks = std::thread::available_parallelism()
            .map(|p| p.get())
            .unwrap_or(8)
            * 2;
        let per = n.div_ceil(tasks.max(1));
        self.segments = (0..tasks)
            .map(|s| (s * per, ((s + 1) * per).min(n)))
            .filter(|(a, b)| a < b)
            .collect();
    }
}

impl Arena {
    /// Rebuild from the catalog.
    ///
    /// **This is the cold-start rebuild the tiebreak rule's third durability
    /// axis measures.** The arena has no persisted form, so there is no cheaper
    /// path: this cost is paid at every daemon start, and the daemon starts at
    /// every logon.
    pub fn rebuild_from_catalog(db: &Path, expect_rows: u64) -> Result<(Self, Duration), String> {
        let t0 = Instant::now();
        let conn = rusqlite::Connection::open_with_flags(
            db,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA cache_size=-131072;")
            .map_err(|e| e.to_string())?;

        // Reserve up front. Growing a ~700 MB Vec by doubling would add several
        // full memcpys to a number the decision depends on.
        let mut bytes: Vec<u8> = Vec::with_capacity(expect_rows as usize * 76);
        let mut starts: Vec<u32> = Vec::with_capacity(expect_rows as usize + 1);

        let mut st = conn
            .prepare("SELECT parent, name FROM file ORDER BY id")
            .map_err(|e| e.to_string())?;
        let mut rows = st.query([]).map_err(|e| e.to_string())?;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let parent: String = r.get(0).map_err(|e| e.to_string())?;
            let name: String = r.get(1).map_err(|e| e.to_string())?;
            let at = bytes.len();
            starts.push(
                u32::try_from(at).map_err(|_| "arena exceeded 4 GiB; offsets would need u64")?,
            );
            bytes.extend_from_slice(parent.as_bytes());
            bytes.push(b'/');
            bytes.extend_from_slice(name.as_bytes());
            bytes[at..].make_ascii_lowercase();
            bytes.push(0);
        }
        starts.push(bytes.len() as u32);

        let mut inner = ArenaInner {
            bytes,
            starts,
            segments: Vec::new(),
        };
        inner.resegment();
        Ok((
            Self {
                inner: RwLock::new(inner),
            },
            t0.elapsed(),
        ))
    }

    pub fn resident_bytes(&self) -> u64 {
        let g = self.inner.read().unwrap();
        (g.bytes.capacity() + g.starts.capacity() * 4) as u64
    }

    pub fn len(&self) -> usize {
        self.inner.read().unwrap().starts.len() - 1
    }

    /// Concurrent write path (fairness rule 2). An in-RAM append under a write
    /// lock is what this design's ingest actually is — there is nothing to fsync
    /// and nothing to commit, which is precisely the property the durability
    /// axes score it down for.
    fn append(&self, path: &str) {
        let mut g = self.inner.write().unwrap();
        let at = g.bytes.len();
        let Ok(off) = u32::try_from(at) else { return };
        let last = g.starts.len() - 1;
        g.starts[last] = off;
        g.bytes.extend_from_slice(path.as_bytes());
        g.bytes[at..].make_ascii_lowercase();
        g.bytes.push(0);
        let end = g.bytes.len() as u32;
        g.starts.push(end);
        if g.starts.len().is_multiple_of(4096) {
            g.resegment();
        }
    }

    fn search(&self, class: &str, needle: &str, limit: usize) -> usize {
        use rayon::prelude::*;
        if needle.is_empty() {
            return 0;
        }
        let g = self.inner.read().unwrap();
        let finder = memchr::memmem::Finder::new(needle.as_bytes());
        let found = AtomicUsize::new(0);

        g.segments.par_iter().for_each(|&(lo, hi)| {
            // A segment starting after the limit is already met does no work.
            if found.load(Ordering::Relaxed) >= limit {
                return;
            }
            let from = g.starts[lo] as usize;
            let to = g.starts[hi] as usize;
            let mut since_check = 0u32;
            for m in finder.find_iter(&g.bytes[from..to]) {
                let abs = from + m;
                // Locate the containing entry. This binary search runs once per
                // HIT, never once per byte, so it stays out of the scan's inner
                // loop — which is the whole reason the offset table is separate
                // from the bytes.
                let idx = g.starts[lo..=hi].partition_point(|&s| (s as usize) <= abs) - 1 + lo;
                let e_start = g.starts[idx] as usize;
                let e_end = g.starts[idx + 1] as usize - 1;
                if abs + needle.len() <= e_end
                    && qualifies(class, &g.bytes[e_start..e_end], abs - e_start)
                    && found.fetch_add(1, Ordering::Relaxed) + 1 >= limit
                {
                    return;
                }
                since_check += 1;
                if since_check.is_multiple_of(64) && found.load(Ordering::Relaxed) >= limit {
                    return;
                }
            }
        });
        found.load(Ordering::Relaxed).min(limit)
    }
}

// ---------------------------------------------------------------------------
// Candidate (b) — tantivy with an n-gram tokenizer
// ---------------------------------------------------------------------------

/// §4.6: "excellent for token/prefix/fuzzy; **infix substring needs an n-gram
/// tokenizer**, which inflates the index. No 10M-doc latency benchmark found."
///
/// Trigrams **with positions** are the configuration that actually answers infix
/// substring, because a substring query becomes a phrase query over its
/// consecutive trigrams. Trigrams without positions would match a document
/// containing the right trigrams in any order — `report` would match `reptor` —
/// which is a different and wrong answer. The positional cost is therefore not
/// optional, and it is a large part of why this index inflates.
struct Tantivy;

/// Start-of-name sentinel. Indexed as the first character of the `name` field so
/// that a **prefix** query can be expressed as an anchored phrase: without it a
/// trigram phrase matches a substring anywhere, and tantivy would answer the
/// prefix class with infix semantics — more hits than the other two candidates,
/// scored against a different question. `\x02` (STX) cannot occur in a path.
const NAME_ANCHOR: char = '\u{2}';

/// A trigram tokenizer that assigns **increasing positions**.
///
/// # Why this exists — a real defect in the stock tokenizer
///
/// tantivy 0.26.1's own `NgramTokenizer` hardcodes `self.token.position = 0` in
/// `advance()` (`src/tokenizer/ngram_tokenizer.rs`), so every n-gram of a
/// document is indexed at position zero. A `PhraseQuery` needs strictly
/// increasing positions, so phrase-over-n-grams — the only construction that
/// expresses *ordered* substring matching — silently matches nothing.
///
/// The pilot run caught this the only way it is catchable: tantivy came back
/// with 100% zero-hit on infix and path-fragment queries while posting the
/// second-fastest p95 on the aggregate. §4.6 assumes "infix substring needs an
/// n-gram tokenizer" and stops there; with the stock tokenizer an n-gram field
/// is **not sufficient**, and benchmarking it as shipped would have measured an
/// index that answers nothing and called it fast.
///
/// The alternative — a boolean AND over the query's trigrams — is not
/// equivalent: it matches a document holding the right trigrams in any order, so
/// `report` would match a name containing `rep`, `epo`, `por`, `ort` scattered
/// anywhere, and every hit would then need re-verification against the stored
/// name. Correct positions give exact substring matching with no post-filter:
/// `abc` at position i and `bcd` at i+1 implies the four bytes `abcd`.
#[derive(Clone, Default)]
struct PositionalTrigram {
    token: tantivy::tokenizer::Token,
}

struct TrigramStream<'a> {
    text: &'a str,
    /// Byte offsets of every character boundary, plus the end. Trigrams are
    /// counted in characters, not bytes — the corpus has non-ASCII directory
    /// names and byte windows would slice them apart.
    bounds: Vec<usize>,
    next: usize,
    token: &'a mut tantivy::tokenizer::Token,
}

impl tantivy::tokenizer::Tokenizer for PositionalTrigram {
    type TokenStream<'a> = TrigramStream<'a>;
    fn token_stream<'a>(&'a mut self, text: &'a str) -> TrigramStream<'a> {
        self.token.reset();
        let mut bounds: Vec<usize> = text.char_indices().map(|(i, _)| i).collect();
        bounds.push(text.len());
        TrigramStream {
            text,
            bounds,
            next: 0,
            token: &mut self.token,
        }
    }
}

impl tantivy::tokenizer::TokenStream for TrigramStream<'_> {
    fn advance(&mut self) -> bool {
        // `bounds.len() - 1` is the character count; a trigram needs three.
        if self.next + 3 >= self.bounds.len() {
            return false;
        }
        let from = self.bounds[self.next];
        let to = self.bounds[self.next + 3];
        self.token.position = self.next;
        self.token.offset_from = from;
        self.token.offset_to = to;
        self.token.text.clear();
        self.token.text.push_str(&self.text[from..to]);
        self.next += 1;
        true
    }
    fn token(&self) -> &tantivy::tokenizer::Token {
        self.token
    }
    fn token_mut(&mut self) -> &mut tantivy::tokenizer::Token {
        self.token
    }
}

struct TantivyIndex {
    reader: tantivy::IndexReader,
    name: tantivy::schema::Field,
    path: tantivy::schema::Field,
}

impl Tantivy {
    fn index_path(fixtures: &Path) -> PathBuf {
        fixtures.join("tantivy")
    }

    fn schema() -> (
        tantivy::schema::Schema,
        tantivy::schema::Field,
        tantivy::schema::Field,
    ) {
        use tantivy::schema::{IndexRecordOption, Schema, TextFieldIndexing, TextOptions};
        let opts = TextOptions::default().set_indexing_options(
            TextFieldIndexing::default()
                .set_tokenizer("trigram")
                .set_index_option(IndexRecordOption::WithFreqsAndPositions),
        );
        let mut sb = Schema::builder();
        let name = sb.add_text_field("name", opts.clone());
        let path = sb.add_text_field("path", opts);
        let schema = sb.build();
        (schema, name, path)
    }

    fn register(index: &tantivy::Index) -> Result<(), String> {
        // NOT `NgramTokenizer::all_ngrams(3, 3)` — see `PositionalTrigram`.
        index
            .tokenizers()
            .register("trigram", PositionalTrigram::default());
        Ok(())
    }

    fn build(fixtures: &Path, catalog: &Path, heap_mb: usize) -> Result<Duration, String> {
        let dir = Self::index_path(fixtures);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;
        let t0 = Instant::now();
        let (schema, f_name, f_path) = Self::schema();
        let index = tantivy::Index::create_in_dir(&dir, schema).map_err(|e| e.to_string())?;
        Self::register(&index)?;
        let mut w: tantivy::IndexWriter = index
            .writer(heap_mb * 1024 * 1024)
            .map_err(|e| e.to_string())?;

        let conn = rusqlite::Connection::open_with_flags(
            catalog,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| e.to_string())?;
        let mut st = conn
            .prepare("SELECT parent, name FROM file ORDER BY id")
            .map_err(|e| e.to_string())?;
        let mut rows = st.query([]).map_err(|e| e.to_string())?;
        let mut n = 0u64;
        while let Some(r) = rows.next().map_err(|e| e.to_string())? {
            let parent: String = r.get(0).map_err(|e| e.to_string())?;
            let name: String = r.get(1).map_err(|e| e.to_string())?;
            let full = format!("{parent}/{name}");
            w.add_document(tantivy::doc!(
                f_name => format!("{NAME_ANCHOR}{}", fold(&name)),
                f_path => fold(&full)
            ))
            .map_err(|e| e.to_string())?;
            n += 1;
            if n.is_multiple_of(1_000_000) {
                eprintln!(
                    "[tantivy] {n} docs, {:.0}s, index {:.2} GiB",
                    t0.elapsed().as_secs_f64(),
                    crate::path_bytes(&dir) as f64 / 1073741824.0
                );
            }
        }
        w.commit().map_err(|e| e.to_string())?;
        Ok(t0.elapsed())
    }

    /// Open and make queryable. **This is tantivy's cold-start cost** — far
    /// smaller than the arena's because the index is persisted and mmap'd rather
    /// than reconstructed, which is exactly what the durability axes are about.
    fn open(fixtures: &Path) -> Result<(TantivyIndex, Duration), String> {
        let t0 = Instant::now();
        let index =
            tantivy::Index::open_in_dir(Self::index_path(fixtures)).map_err(|e| e.to_string())?;
        Self::register(&index)?;
        let reader = index
            .reader_builder()
            .reload_policy(tantivy::ReloadPolicy::Manual)
            .try_into()
            .map_err(|e: tantivy::TantivyError| e.to_string())?;
        let schema = index.schema();
        let name = schema.get_field("name").map_err(|e| e.to_string())?;
        let path = schema.get_field("path").map_err(|e| e.to_string())?;
        Ok((TantivyIndex { reader, name, path }, t0.elapsed()))
    }

    /// A writer for the background ingest load.
    fn writer(fixtures: &Path) -> Result<(tantivy::IndexWriter, tantivy::schema::Field), String> {
        let index =
            tantivy::Index::open_in_dir(Self::index_path(fixtures)).map_err(|e| e.to_string())?;
        Self::register(&index)?;
        let f = index
            .schema()
            .get_field("name")
            .map_err(|e| e.to_string())?;
        let w = index.writer(256 * 1024 * 1024).map_err(|e| e.to_string())?;
        Ok((w, f))
    }
}

impl TantivyIndex {
    fn search(&self, class: &str, q: &str, limit: usize) -> usize {
        use tantivy::query::{PhraseQuery, Query, TermQuery};
        use tantivy::schema::IndexRecordOption;
        use tantivy::{Term, collector::TopDocs};

        let field = if class == "path_fragment" {
            self.path
        } else {
            self.name
        };
        // A prefix query is the same phrase, anchored to the start-of-name
        // sentinel. Without the anchor tantivy would answer the prefix class
        // with infix semantics and report more hits than the question asked for.
        let owned;
        let q = if class == "prefix" {
            owned = format!("{NAME_ANCHOR}{q}");
            owned.as_str()
        } else {
            q
        };
        let chars: Vec<char> = q.chars().collect();
        if chars.len() < 3 {
            return 0;
        }
        let terms: Vec<Term> = chars
            .windows(3)
            .map(|w| Term::from_field_text(field, &w.iter().collect::<String>()))
            .collect();
        let query: Box<dyn Query> = if terms.len() == 1 {
            Box::new(TermQuery::new(
                terms[0].clone(),
                IndexRecordOption::WithFreqs,
            ))
        } else {
            Box::new(PhraseQuery::new(terms))
        };
        let searcher = self.reader.searcher();
        searcher
            .search(&query, &TopDocs::with_limit(limit).order_by_score())
            .map(|d| d.len())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Candidate (c) — SQLite FTS5 trigram
// ---------------------------------------------------------------------------

/// The baseline to beat. §4.6 records it at **~1.75 s on 18.2M rows**, ~35x over
/// budget — a `[V]` figure in the sense of source-verified, not fact-established.
/// This run is what establishes it here.
///
/// `LIKE '%x%'` rather than `MATCH`, because that is the form SQLite documents
/// the trigram tokenizer as accelerating and the form that expresses true infix
/// substring search.
struct Fts5;

impl Fts5 {
    fn index_path(fixtures: &Path) -> PathBuf {
        fixtures.join("fts5.sqlite")
    }

    fn build(fixtures: &Path, catalog: &Path) -> Result<Duration, String> {
        let db = Self::index_path(fixtures);
        for suffix in ["", "-wal", "-shm"] {
            let _ = std::fs::remove_file(format!("{}{suffix}", db.display()));
        }
        let t0 = Instant::now();
        let conn = rusqlite::Connection::open(&db).map_err(|e| e.to_string())?;
        conn.execute_batch(&format!(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=OFF;
             PRAGMA cache_size=-524288;
             ATTACH DATABASE '{}' AS src;
             CREATE VIRTUAL TABLE meta USING fts5(name, path, tokenize='trigram');
             INSERT INTO meta(rowid, name, path)
                 SELECT id, lower(name), lower(parent || '/' || name) FROM src.file;",
            catalog.display()
        ))
        .map_err(|e| e.to_string())?;
        eprintln!(
            "[fts5] populated in {:.0}s, optimizing…",
            t0.elapsed().as_secs_f64()
        );
        conn.execute_batch("INSERT INTO meta(meta) VALUES('optimize');")
            .map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| e.to_string())?;
        Ok(t0.elapsed())
    }
}

/// One searcher per thread: `rusqlite::Connection` is not `Sync`, and sharing
/// one behind a mutex would measure lock contention rather than the index.
struct Fts5Searcher {
    conn: rusqlite::Connection,
}

impl Fts5Searcher {
    fn open(fixtures: &Path) -> Result<Self, String> {
        let conn = rusqlite::Connection::open_with_flags(
            Fts5::index_path(fixtures),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .map_err(|e| e.to_string())?;
        conn.execute_batch("PRAGMA cache_size=-65536;")
            .map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    fn search(&self, class: &str, q: &str, limit: usize) -> usize {
        let (col, pat) = match class {
            "prefix" => ("name", format!("{q}%")),
            "infix" => ("name", format!("%{q}%")),
            _ => ("path", format!("%{q}%")),
        };
        let sql = format!("SELECT rowid FROM meta WHERE {col} LIKE ?1 LIMIT ?2");
        let Ok(mut st) = self.conn.prepare_cached(&sql) else {
            return 0;
        };
        st.query_map(rusqlite::params![pat, limit as i64], |_| Ok(()))
            .map(|rows| rows.count())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Per-class accounting
// ---------------------------------------------------------------------------

/// Latency and hit counts split by query class.
///
/// This exists because of a real failure caught in the pilot run: tantivy
/// returned **zero hits on 2504 of 3000 queries** and was therefore the second
/// fastest candidate on the aggregate number. An aggregate p95 cannot tell
/// "answered quickly" apart from "answered nothing quickly", and the bake-off
/// would have selected on the difference. Reporting hits per class alongside
/// latency per class is what makes that visible without anyone having to think
/// to look.
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

// ---------------------------------------------------------------------------
// Dispatch
// ---------------------------------------------------------------------------

enum Shared {
    Arena(Arc<Arena>),
    Tantivy(Arc<TantivyIndex>),
    Fts5,
}

enum Searcher {
    Arena(Arc<Arena>),
    Tantivy(Arc<TantivyIndex>),
    Fts5(Box<Fts5Searcher>),
}

impl Searcher {
    fn search(&self, class: &str, q: &str, limit: usize) -> usize {
        match self {
            Searcher::Arena(a) => a.search(class, q, limit),
            Searcher::Tantivy(t) => t.search(class, q, limit),
            Searcher::Fts5(f) => f.search(class, q, limit),
        }
    }
}

pub fn build(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let which = a
        .target
        .clone()
        .ok_or("build-meta needs arena|tantivy|fts5")?;
    let catalog = generate::catalog_path(&a.fixtures);
    if !catalog.exists() {
        return Err(format!(
            "{} missing — run `shepherd-bench gen-catalog` first",
            catalog.display()
        ));
    }

    let rows = a.rows_override.unwrap_or(c.fixture.rows);
    // Projected from the 200k pilot, scaled: fts5 ~0.45 GiB per million rows,
    // tantivy ~0.25 GiB per million. The arena writes nothing to disk.
    let projected_gib = match which.as_str() {
        "fts5" => 0.45 * rows as f64 / 1e6,
        "tantivy" => 0.25 * rows as f64 / 1e6,
        _ => 0.0,
    };
    crate::disk_guard_start(
        &a.fixtures,
        c.disk_guard.abort_below_free_gib,
        projected_gib,
    )?;

    let (secs, bytes, note) = match which.as_str() {
        "fts5" => {
            let d = Fts5::build(&a.fixtures, &catalog)?;
            (
                d.as_secs_f64(),
                crate::path_bytes(&Fts5::index_path(&a.fixtures)),
                "transactional with the catalog; nothing to rebuild at start",
            )
        }
        "tantivy" => {
            let d = Tantivy::build(&a.fixtures, &catalog, 2048)?;
            (
                d.as_secs_f64(),
                crate::path_bytes(&Tantivy::index_path(&a.fixtures)),
                "independent on-disk index with its own commit semantics",
            )
        }
        "arena" => {
            let (arena, d) = Arena::rebuild_from_catalog(&catalog, rows)?;
            let r = arena.resident_bytes();
            eprintln!(
                "[arena] {} entries, {:.2} GiB resident",
                arena.len(),
                r as f64 / 1073741824.0
            );
            (
                d.as_secs_f64(),
                r,
                "NO persisted form; this build IS the cold-start rebuild, paid at every logon",
            )
        }
        other => return Err(format!("unknown candidate {other}")),
    };

    eprintln!(
        "[build-meta {which}] {secs:.1}s, {:.2} GiB",
        bytes as f64 / 1073741824.0
    );
    crate::emit(
        &a.out,
        &format!("meta_build_{which}"),
        serde_json::json!({
            "candidate": which,
            "rows": rows,
            "build_seconds": secs,
            "bytes": bytes,
            "peak_vm_hwm_bytes": crate::vm_hwm_bytes(),
            "persistence_note": note,
            "scaled_run_reason": a.scaled_run_reason,
        }),
    )
}

pub fn bench(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let which = a
        .target
        .clone()
        .ok_or("bench-meta needs arena|tantivy|fts5")?;
    let rows = a.rows_override.unwrap_or(c.fixture.rows);
    let catalog = generate::catalog_path(&a.fixtures);

    // Lexical slice only. The semantic 10% belongs to the vector leg; mixing
    // them would corrupt both numbers (see bench-contract.toml [query_trace]).
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
    let clients = c.execution.query_clients;
    let mut run_stats = Vec::new();
    let mut index_bytes = 0u64;
    let mut total_hits = 0u64;
    let mut zero_hit = 0u64;
    let mut by_class: std::collections::BTreeMap<String, ClassStat> =
        std::collections::BTreeMap::new();

    // EVERY RUN OPENS ITS OWN INDEX, and for a cold cell every run drops the page
    // cache first.
    //
    // An earlier draft dropped the cache once and then ran all three runs
    // back-to-back. Run 0 was cold; runs 1 and 2 were warmed by run 0 — so
    // median-of-runs-p95 over [cold, warm, warm] reported the WARM number under
    // a cold label. "Cold over budget while warm passes" is an explicit
    // escalation trigger, so that defect would have suppressed precisely the
    // escalation the cold cell exists to raise. Re-opening on warm runs too
    // costs a little wall clock and makes the two cells structurally identical,
    // differing only by the cache drop.
    //
    // Re-opening matters for FTS5 in particular: each connection holds SQLite's
    // own multi-MiB heap page cache, which `drop_caches` cannot touch, so a cold
    // run reusing its connection would query a warm cache behind a cold label.
    let mut open_secs: Vec<f64> = Vec::new();
    let mut ingest_total = 0usize;
    for run in 0..c.statistics.runs {
        if a.cache == "cold" {
            crate::drop_page_cache().map_err(|e| {
                format!("{e}\n(candidate {which}: refusing to report this run as cold)")
            })?;
        }
        let t_open = Instant::now();
        let shared: Shared = match which.as_str() {
            "arena" => Shared::Arena(Arc::new(Arena::rebuild_from_catalog(&catalog, rows)?.0)),
            "tantivy" => Shared::Tantivy(Arc::new(Tantivy::open(&a.fixtures)?.0)),
            "fts5" => Shared::Fts5,
            other => return Err(format!("unknown candidate {other}")),
        };
        open_secs.push(t_open.elapsed().as_secs_f64());
        index_bytes = match &shared {
            Shared::Arena(x) => x.resident_bytes(),
            Shared::Tantivy(_) => crate::path_bytes(&Tantivy::index_path(&a.fixtures)),
            Shared::Fts5 => crate::path_bytes(&Fts5::index_path(&a.fixtures)),
        };

        // Background ingest — §9's "under a background ingest load", and
        // fairness rule 2. Spawned per run so it writes to the index this run is
        // actually querying.
        let stop = Arc::new(AtomicBool::new(false));
        let ingested = Arc::new(AtomicUsize::new(0));
        let ingest = if c.execution.background_ingest {
            Some(spawn_ingest(
                &shared,
                &a.fixtures,
                c.fixture.seed,
                rows,
                c.execution.background_ingest_rows_per_sec,
                Arc::clone(&stop),
                Arc::clone(&ingested),
            )?)
        } else {
            None
        };

        let slice: Arc<Vec<(String, String)>> = Arc::new(
            lexical[run * c.statistics.queries_per_run..(run + 1) * c.statistics.queries_per_run]
                .to_vec(),
        );
        let next = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..clients {
            let slice = Arc::clone(&slice);
            let next = Arc::clone(&next);
            let s: Searcher = match &shared {
                Shared::Arena(x) => Searcher::Arena(Arc::clone(x)),
                Shared::Tantivy(x) => Searcher::Tantivy(Arc::clone(x)),
                Shared::Fts5 => Searcher::Fts5(Box::new(Fts5Searcher::open(&a.fixtures)?)),
            };
            handles.push(std::thread::spawn(move || {
                let mut lat = Vec::with_capacity(slice.len());
                // Per-class, because an aggregate hides the failure the pilot
                // run actually found: a candidate that answers prefix queries
                // well and infix queries not at all looks excellent in the
                // aggregate and is useless for AC-40.
                let mut per: std::collections::BTreeMap<String, ClassStat> =
                    std::collections::BTreeMap::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= slice.len() {
                        break;
                    }
                    let (class, q) = &slice[i];
                    let folded = fold(q);
                    let t = Instant::now();
                    let n = s.search(class, &folded, limit);
                    let d = t.elapsed();
                    lat.push(d);
                    let e = per.entry(class.clone()).or_default();
                    e.queries += 1;
                    e.hits += n as u64;
                    if n == 0 {
                        e.zero_hit += 1;
                    }
                    e.lat.push(d);
                }
                (lat, per)
            }));
        }
        let mut lat = Vec::new();
        for h in handles {
            let (l, per) = h.join().map_err(|_| "query client panicked")?;
            lat.extend(l);
            for (k, v) in per {
                let e = by_class.entry(k).or_default();
                total_hits += v.hits;
                zero_hit += v.zero_hit;
                e.merge(v);
            }
        }
        stop.store(true, Ordering::Relaxed);
        if let Some(h) = ingest {
            let _ = h.join();
        }
        ingest_total += ingested.load(Ordering::Relaxed);

        let p = Percentiles::of(lat);
        eprintln!(
            "[bench-meta {which}/{}] run {run}: p50 {:.2}  p95 {:.2}  p99 {:.2}               max {:.2} ms  (open {:.1}s)",
            a.cache, p.p50_ms, p.p95_ms, p.p99_ms, p.max_ms, open_secs[run]
        );
        run_stats.push(p);
    }

    let rs = RunSet::reduce(run_stats, c.statistics.drift_flag_pct);
    let pass = rs.accepted_p95_ms < c.bars.metadata_p95_ms;
    eprintln!(
        "[bench-meta {which}/{}] ACCEPTED p95 {:.2} ms vs bar {:.0} ms -> {}",
        a.cache,
        rs.accepted_p95_ms,
        c.bars.metadata_p95_ms,
        if pass { "PASS" } else { "FAIL" }
    );

    crate::emit(
        &a.out,
        &format!("meta_bench_{which}_{}", a.cache),
        serde_json::json!({
            "candidate": which,
            "cache": a.cache,
            "rows": rows,
            "stats": rs,
            "bar_ms": c.bars.metadata_p95_ms,
            "pass": pass,
            "open_or_rebuild_seconds_per_run": open_secs,
            "index_bytes": index_bytes,
            "peak_vm_hwm_bytes": crate::vm_hwm_bytes(),
            "vm_rss_after_queries_bytes": crate::vm_rss_bytes(),
            "query_clients": clients,
            "background_rows_ingested": ingest_total,
            "mean_hits_per_query": total_hits as f64 / need as f64,
            "zero_hit_queries": zero_hit,
            "by_class": by_class.iter().map(|(k, v)| (k.clone(), v.report())).collect::<serde_json::Map<_,_>>(),
            "machine": crate::probe_machine(&c.reference_machine.pin_to_cores),
            "scaled_run_reason": a.scaled_run_reason,
        }),
    )
}

/// The background writer, one implementation per candidate so all three carry
/// the same load (fairness rule 2). Rows are appended *beyond* the fixture's id
/// range so an ingested row can never collide with a trace query's source row.
fn spawn_ingest(
    shared: &Shared,
    fixtures: &Path,
    seed: u64,
    rows: u64,
    rate: u64,
    stop: Arc<AtomicBool>,
    counter: Arc<AtomicUsize>,
) -> Result<std::thread::JoinHandle<()>, String> {
    let space = generate::dir_space(rows);
    let batch = (rate / 20).max(1);

    enum Writer {
        Arena(Arc<Arena>),
        Tantivy(Mutex<(tantivy::IndexWriter, tantivy::schema::Field)>),
        Fts5(rusqlite::Connection),
    }
    let writer = match shared {
        Shared::Arena(a) => Writer::Arena(Arc::clone(a)),
        Shared::Tantivy(_) => Writer::Tantivy(Mutex::new(Tantivy::writer(fixtures)?)),
        Shared::Fts5 => {
            let conn = rusqlite::Connection::open(Fts5::index_path(fixtures))
                .map_err(|e| e.to_string())?;
            conn.execute_batch("PRAGMA synchronous=NORMAL;")
                .map_err(|e| e.to_string())?;
            Writer::Fts5(conn)
        }
    };

    Ok(std::thread::spawn(move || {
        let mut id = rows;
        let mut since_commit = 0u64;
        while !stop.load(Ordering::Relaxed) {
            let t = Instant::now();
            match &writer {
                Writer::Arena(a) => {
                    for _ in 0..batch {
                        let r: Row = generate::row(seed, id, space);
                        a.append(&r.path());
                        id += 1;
                    }
                    counter.fetch_add(batch as usize, Ordering::Relaxed);
                }
                Writer::Tantivy(m) => {
                    if let Ok(mut g) = m.lock() {
                        let f = g.1;
                        for _ in 0..batch {
                            let r: Row = generate::row(seed, id, space);
                            let _ = g.0.add_document(
                                tantivy::doc!(f => format!("{NAME_ANCHOR}{}", fold(&r.name))),
                            );
                            id += 1;
                        }
                        since_commit += batch;
                        // Commit periodically rather than per batch: tantivy
                        // segment commits are expensive and a real ingest would
                        // amortise them, so committing every batch would charge
                        // this candidate a cost its own design avoids.
                        if since_commit >= 20_000 {
                            let _ = g.0.commit();
                            since_commit = 0;
                        }
                        counter.fetch_add(batch as usize, Ordering::Relaxed);
                    }
                }
                Writer::Fts5(conn) => {
                    if let Ok(tx) = conn.unchecked_transaction() {
                        for _ in 0..batch {
                            let r: Row = generate::row(seed, id, space);
                            let _ = tx.execute(
                                "INSERT INTO meta(rowid,name,path) VALUES (?,?,?)",
                                rusqlite::params![id as i64, fold(&r.name), fold(&r.path())],
                            );
                            id += 1;
                        }
                        if tx.commit().is_ok() {
                            counter.fetch_add(batch as usize, Ordering::Relaxed);
                        }
                    }
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
