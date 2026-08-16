//! The metadata name index — an in-RAM path arena scanned with SIMD substring
//! search.
//!
//! # Why this design and not an inverted index
//!
//! §4.6 put three candidates in front of the 50 ms p95 bar at 10M names and the
//! Phase 0b bake-off measured them (`.omc/artifacts/phase-0ab/meta-bench.log`):
//!
//! | candidate | warm p95 | cold p95 | verdict |
//! |---|---|---|---|
//! | in-RAM arena + `memchr::memmem` | **22.20 ms** | **23.48 ms** | PASS |
//! | `tantivy` 0.26.1, positional trigrams | 68.08 ms | 87.99 ms | FAIL |
//! | SQLite FTS5-trigram | 378.59 ms | 587.53 ms | FAIL |
//!
//! **That decision is settled and this module does not re-open it.** The one
//! thing worth carrying forward for anyone who does: tantivy's stock
//! `NgramTokenizer` hardcodes every token's position to zero, so the
//! `PhraseQuery` that expresses *ordered* substring matching matches nothing.
//! Measured naively, tantivy posts a beautiful p95 while returning zero results
//! on 100% of infix queries. The bake-off had to write a positional tokenizer to
//! test it fairly, and it failed the bar anyway. This module's tests exist in
//! that shadow: **every latency claim here is paired with a hit-count claim,**
//! because an index that matches nothing is arbitrarily fast.
//!
//! # What one entry costs
//!
//! This matters because it is charged against AC-46's RAM ceiling, so it is
//! stated as an arithmetic identity and asserted by the test
//! `the_documented_per_entry_overhead_is_the_real_layout` rather than estimated
//! in prose:
//!
//! ```text
//! per entry = len(rel_path)          bytes   the folded path itself
//!           + 1                      byte    the NUL terminator
//!           + 4                      bytes   its `starts` offset (u32)
//!           + 8                      bytes   its `file_id` (i64)
//!           = len(rel_path) + 13 bytes
//! ```
//!
//! **§4.6's "10M names × ~35 B ≈ 350 MB" understates the shipped index by
//! roughly 2×, and the gap is not rounding.** Two reasons, both structural:
//!
//! 1. It counts *names*; this index stores whole `rel_path`s, because the
//!    path-fragment query class is not answerable from bare filenames.
//! 2. It counts no row identity, and a production index has to return something
//!    the catalog can hydrate — hence 8 bytes of `file_id` per entry that a
//!    benchmark counting matches never had to carry.
//!
//! **Measured on this implementation**, not projected — 10M synthetic entries
//! with 57-byte paths, `--release`, by the `#[ignore]`d
//! `the_production_index_meets_the_50ms_bar_at_10m_entries`:
//!
//! ```text
//! entries    10,000,000        build      1.83 s
//! resident   667.6 MiB         per entry  70.0 bytes  (57 + 13, exactly)
//! p50        10.63 ms          p95        14.66 ms    (bar 50 ms)
//! segments   32                p99        22.09 ms
//! ```
//!
//! So the real charge is **~670 MB**, about 2× §4.6's 350 MB, and the identity
//! above is exact rather than approximate. [`MetaIndex::resident_bytes`] reports
//! it from real capacities; prefer it over any projection, including this one.
//!
//! Two notes on how that number was reached, because both were bugs first:
//!
//! * The same measurement first reported **839.2 MiB / 88.0 bytes per entry**.
//!   The whole 18-byte gap was [`MetaIndexBuilder::with_capacity`]'s
//!   [`ESTIMATED_PATH_BYTES`] guessing high — ~170 MB of reserved-and-unusable
//!   arena that an immutable index can never spend. `build()` now shrinks to
//!   fit, which is where the two figures diverge.
//! * The p95 is **not** the spike's 22.20 ms and must not be quoted as it. This
//!   index carries a `file_id` the benchmark never had, drives the scan with
//!   `std::thread::scope` rather than rayon, and does strictly more work per
//!   query because its cap is per-segment. It is faster here for an unrelated
//!   reason — 32 cores against the reference machine's — which is exactly why
//!   the shipped code has its own measurement instead of inheriting one.
//!
//! # Query semantics
//!
//! Matching is **case-insensitive by ASCII folding** — as-you-type search that
//! is case-sensitive is not the feature AC-40 describes. Folding is deliberately
//! not `str::to_lowercase`: full Unicode folding can change a string's byte
//! length, and the offset table is byte-indexed, so a Unicode fold would corrupt
//! the arena rather than merely slow it down.
//!
//! §4.6 routes three query classes down this path — prefix, infix substring and
//! path fragment. `shepherd_proto::request::SearchRequest` carries no class
//! discriminator, and it does not need one, because the query decides:
//!
//! * a query containing a path separator is a **path fragment** and may match
//!   anywhere in the `rel_path`;
//! * any other query matches only within the **final path component**, so
//!   typing `doc` does not return every file that happens to live under `docs/`.
//!
//! Prefix is not a third case here. It is infix with the hit at offset zero, and
//! it differs from infix only in *ranking* — which a metadata query does not do
//! (`SearchHit::score` is documented absent for exactly this reason).
//!
//! # Determinism, and why the scan does not exit early globally
//!
//! The scan is segmented across threads because a single `memmem` stream runs at
//! a few GB/s and a ~730 MB arena is at or over the bar on one core. The
//! tempting optimisation — a shared "stop, we have enough" flag — makes the
//! *result set* depend on thread scheduling: a paged query would return
//! different rows on identical input, and page 2 could repeat page 1.
//!
//! So the cap is **per segment, not global**. Each segment collects at most
//! `cap` matches from its own slice and stops; results are concatenated in
//! segment order, which is entry order, which is `file_id` order for an index
//! built by `SELECT ... ORDER BY id`. The first `cap` of that concatenation is a
//! deterministic prefix of the true ordered match set. Work stays bounded, and
//! the answer does not depend on which core won.
//!
//! The honest cost, recorded rather than buried: **a query matching nothing
//! cannot exit early anywhere and pays a full scan.** That is the worst case for
//! this design, it is the case the 22.20 ms p95 already includes, and it is why
//! [`Matches::truncated`] exists — a truncated result reports a *floor* on the
//! total, never a total.

use memchr::memmem;

/// A hard ceiling: entry offsets are `u32`, so the arena addresses 4 GiB.
///
/// At the documented ~73 bytes/entry that is ~58M entries, comfortably past the
/// 10M the plan sizes for. Widening to `u64` would add 4 bytes to every entry —
/// ~40 MB at 10M — to buy headroom nothing needs, so the limit is enforced
/// instead of paid for.
pub const MAX_ARENA_BYTES: u64 = u32::MAX as u64;

/// Fixed bytes each entry costs on top of its own path text.
///
/// 1 (NUL terminator) + 4 (`starts` offset) + 8 (`file_id`). See the module
/// docs; asserted against the real layout by a test.
pub const OVERHEAD_BYTES_PER_ENTRY: usize = 1 + 4 + 8;

/// Mean path length assumed by [`MetaIndexBuilder::with_capacity`].
///
/// A reservation hint only — never a limit, and wrong in either direction costs
/// only reallocation. Sized from the Phase 0b fixture corpus.
pub const ESTIMATED_PATH_BYTES: usize = 76;

/// Below this the arena is scanned on the calling thread.
///
/// Spawning a dozen threads to scan a few megabytes costs more than the scan.
/// The threshold is well under any corpus where the bar is in question.
const PARALLEL_SCAN_THRESHOLD_BYTES: usize = 8 * 1024 * 1024;

/// The index could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuildError {
    /// The arena outgrew the `u32` offset table.
    ///
    /// Carries what it took to get there so the operator sees a size, not a
    /// mystery.
    ArenaTooLarge { entries: usize, bytes: u64 },
}

impl std::fmt::Display for BuildError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BuildError::ArenaTooLarge { entries, bytes } => write!(
                f,
                "the metadata index exceeded its {MAX_ARENA_BYTES}-byte addressable arena \
                 at {entries} entries ({bytes} bytes); offsets are u32"
            ),
        }
    }
}

impl std::error::Error for BuildError {}

/// Where in a path a hit is allowed to land.
///
/// Chosen from the query by [`Scope::for_query`]; never passed in by a caller,
/// because two callers choosing differently is how one search surface starts
/// answering a different question from another.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
    /// The hit must lie inside the final path component.
    Name,
    /// The hit may lie anywhere in the path.
    Path,
}

impl Scope {
    /// A query naming a directory boundary is asking about paths; anything else
    /// is asking about filenames.
    pub fn for_query(needle: &str) -> Scope {
        if needle.bytes().any(is_separator) {
            Scope::Path
        } else {
            Scope::Name
        }
    }
}

/// Both separators, always.
///
/// `rel_path` is stored "with separators left exactly as the OS gave them"
/// (`shepherd_scan::walk`), so a catalog written on Windows holds `\` and one
/// written on Linux holds `/`. Accepting only the host's separator would make a
/// catalog restored across platforms silently unsearchable by path — the
/// catalog's own `split_name` already takes both, and this agrees with it.
#[inline]
fn is_separator(b: u8) -> bool {
    b == b'/' || b == b'\\'
}

/// The result of a search.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Matches {
    /// Matching `file_id`s, in index order. One entry per matching file, even
    /// when the needle occurs in it several times.
    pub ids: Vec<i64>,
    /// Some segment stopped at its cap, so `ids` is a prefix of the matches and
    /// its length is a **floor** on the true total, not the total.
    pub truncated: bool,
}

/// Accumulates entries into an arena.
///
/// Push order is preserved and becomes the result order, so a caller that reads
/// the catalog `ORDER BY id` gets `file_id`-ordered results for free.
pub struct MetaIndexBuilder {
    bytes: Vec<u8>,
    starts: Vec<u32>,
    ids: Vec<i64>,
}

impl Default for MetaIndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl MetaIndexBuilder {
    pub fn new() -> Self {
        Self {
            bytes: Vec::new(),
            starts: Vec::new(),
            ids: Vec::new(),
        }
    }

    /// Reserve for `entries` up front.
    ///
    /// Worth doing rather than growing by doubling: at 10M entries the arena is
    /// ~700 MB, and doubling into it both adds full memcpys to the rebuild the
    /// daemon pays at every start *and* transiently doubles peak RSS — which is
    /// charged against the same AC-46 ceiling the steady-state figure is.
    pub fn with_capacity(entries: usize) -> Self {
        Self {
            bytes: Vec::with_capacity(entries.saturating_mul(ESTIMATED_PATH_BYTES)),
            starts: Vec::with_capacity(entries.saturating_add(1)),
            ids: Vec::with_capacity(entries),
        }
    }

    /// Append one catalog row.
    ///
    /// `path` is the `rel_path`; it is ASCII-folded on the way in, so a query is
    /// folded once at search time rather than every row being folded per query.
    pub fn push(&mut self, file_id: i64, path: &str) -> Result<(), BuildError> {
        let at = self.bytes.len();
        let start = u32::try_from(at).map_err(|_| BuildError::ArenaTooLarge {
            entries: self.ids.len(),
            bytes: at as u64,
        })?;
        self.starts.push(start);
        self.bytes.extend_from_slice(path.as_bytes());
        self.bytes[at..].make_ascii_lowercase();
        // The terminator is what stops a needle from matching across the seam
        // between two adjacent entries. A needle containing NUL is rejected at
        // search time, so this byte is unmatchable by construction.
        self.bytes.push(0);
        self.ids.push(file_id);
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Seal the arena.
    pub fn build(mut self) -> Result<MetaIndex, BuildError> {
        let end = u32::try_from(self.bytes.len()).map_err(|_| BuildError::ArenaTooLarge {
            entries: self.ids.len(),
            bytes: self.bytes.len() as u64,
        })?;
        // The sentinel: `starts[i]..starts[i + 1] - 1` is entry `i`'s text for
        // every `i`, including the last, with no special case at the end.
        self.starts.push(end);

        // Hand back what `with_capacity`'s estimate over-reserved.
        //
        // Measured, not assumed: at 10M entries with 57-byte paths the arena
        // reported 88.0 bytes/entry against the 70 the layout identity predicts,
        // and the whole 18-byte gap was `ESTIMATED_PATH_BYTES` guessing high —
        // ~190 MB of nothing, charged to AC-46's ceiling for the daemon's entire
        // lifetime. The index is immutable once built, so the spare capacity can
        // never be used and there is nothing to trade away by returning it.
        //
        // Cheap in practice: an allocation this size comes from `mmap`, so
        // shrinking it is an `mremap` rather than a copy.
        self.bytes.shrink_to_fit();
        self.starts.shrink_to_fit();
        self.ids.shrink_to_fit();

        let segments = segment(self.ids.len(), self.bytes.len());
        Ok(MetaIndex {
            bytes: self.bytes,
            starts: self.starts,
            ids: self.ids,
            segments,
        })
    }
}

/// Split `entries` into contiguous ranges, one per scan thread.
fn segment(entries: usize, bytes: usize) -> Vec<(usize, usize)> {
    if entries == 0 {
        return Vec::new();
    }
    if bytes < PARALLEL_SCAN_THRESHOLD_BYTES {
        return vec![(0, entries)];
    }
    let tasks = std::thread::available_parallelism()
        .map(|p| p.get())
        .unwrap_or(4)
        .max(1);
    let per = entries.div_ceil(tasks);
    (0..tasks)
        .map(|s| (s * per, ((s + 1) * per).min(entries)))
        .filter(|(a, b)| a < b)
        .collect()
}

/// An immutable arena of ASCII-folded paths plus its offset table.
///
/// **Immutable on purpose.** The Phase 0b spike kept its arena behind an
/// `RwLock` and grew it in place, because the bake-off's fairness rules made
/// every candidate take concurrent writes. Production has no such requirement
/// and the in-place variant carries real hazards — a partly-appended entry
/// visible to a concurrent scan, a sentinel that has to be patched rather than
/// pushed, and a silent drop when an offset overflows `u32`. Phase 1's only
/// mutator is the scan, which rebuilds; a caller wanting freshness swaps a whole
/// new `Arc<MetaIndex>` in and lets readers finish on the old one.
pub struct MetaIndex {
    /// Folded paths, each NUL-terminated, back to back.
    bytes: Vec<u8>,
    /// `starts[i]..starts[i + 1] - 1` is entry `i`; `bytes[starts[i + 1] - 1]`
    /// is its NUL. Length is `ids.len() + 1`.
    starts: Vec<u32>,
    /// `file_id` per entry, index-aligned with `starts`.
    ids: Vec<i64>,
    /// Entry-index ranges, one per scan thread.
    segments: Vec<(usize, usize)>,
}

impl MetaIndex {
    /// An index over nothing. Searches it correctly — returning nothing.
    pub fn empty() -> MetaIndex {
        MetaIndexBuilder::new()
            .build()
            .expect("an empty arena cannot overflow a u32 offset")
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// Bytes actually held, from real allocation capacities.
    ///
    /// This is the number to report against AC-46's ceiling. It is measured, not
    /// projected, and it will exceed `len() * (mean_path + 13)` whenever a `Vec`
    /// holds spare capacity.
    pub fn resident_bytes(&self) -> u64 {
        (self.bytes.capacity()
            + self.starts.capacity() * size_of::<u32>()
            + self.ids.capacity() * size_of::<i64>()
            + self.segments.capacity() * size_of::<(usize, usize)>()) as u64
    }

    /// How many parallel segments a scan uses. Diagnostic.
    pub fn segment_count(&self) -> usize {
        self.segments.len()
    }

    /// Find up to `cap` files whose path matches `query`.
    ///
    /// Returns an empty result — never an error — for a query that cannot match
    /// anything: empty, or containing a NUL (which is the arena's own separator
    /// and appears in no path any filesystem can produce). Callers that want to
    /// *refuse* an empty query should do so before calling; the distinction
    /// between "asked nothing" and "matched nothing" is a protocol decision, not
    /// an index one.
    pub fn search(&self, query: &str, cap: usize) -> Matches {
        let needle = query.to_ascii_lowercase();
        if needle.is_empty() || cap == 0 || self.is_empty() || needle.as_bytes().contains(&0) {
            return Matches::default();
        }
        let scope = Scope::for_query(&needle);
        let finder = memmem::Finder::new(needle.as_bytes());

        let parts: Vec<(Vec<i64>, bool)> = if self.segments.len() < 2 {
            self.segments
                .iter()
                .map(|&(lo, hi)| self.scan_segment(lo, hi, &finder, needle.len(), scope, cap))
                .collect()
        } else {
            // Scoped threads rather than a pool: the pool would be a dependency
            // and a lifetime, and the spawn cost is tens of microseconds against
            // a scan measured in milliseconds. Guarded by
            // `PARALLEL_SCAN_THRESHOLD_BYTES` so a small index never pays it.
            std::thread::scope(|s| {
                let handles: Vec<_> = self
                    .segments
                    .iter()
                    .map(|&(lo, hi)| {
                        let finder = &finder;
                        let len = needle.len();
                        s.spawn(move || self.scan_segment(lo, hi, finder, len, scope, cap))
                    })
                    .collect();
                handles
                    .into_iter()
                    .map(|h| {
                        h.join()
                            .expect("a scan segment panicked; the arena is immutable during a scan")
                    })
                    .collect()
            })
        };

        let mut ids = Vec::new();
        let mut truncated = false;
        for (part, hit_cap) in parts {
            truncated |= hit_cap;
            ids.extend(part);
        }
        if ids.len() > cap {
            ids.truncate(cap);
            truncated = true;
        }
        Matches { ids, truncated }
    }

    /// Scan entries `lo..hi`, collecting at most `cap` matching ids.
    ///
    /// Returns `(ids, hit_cap)`. `hit_cap` says this segment stopped early, so
    /// its slice may hold matches that are not in `ids`.
    fn scan_segment(
        &self,
        lo: usize,
        hi: usize,
        finder: &memmem::Finder<'_>,
        needle_len: usize,
        scope: Scope,
        cap: usize,
    ) -> (Vec<i64>, bool) {
        let mut out: Vec<i64> = Vec::new();
        let from = self.starts[lo] as usize;
        let to = self.starts[hi] as usize;
        // The entry most recently pushed, so a path containing the needle twice
        // yields one result rather than two. `usize::MAX` is not a valid entry
        // index, so the first hit is never suppressed.
        let mut last_pushed = usize::MAX;

        for m in finder.find_iter(&self.bytes[from..to]) {
            let abs = from + m;
            // Locating the containing entry is a binary search, and it runs once
            // per HIT rather than once per byte. That is the whole reason the
            // offset table is a separate array from the bytes: keeping it out of
            // the scan's inner loop is what leaves the loop as a bare `memmem`
            // stream at SIMD speed.
            let idx = self.starts[lo..=hi].partition_point(|&s| (s as usize) <= abs) - 1 + lo;
            if idx == last_pushed {
                continue;
            }
            let entry_end = self.starts[idx + 1] as usize - 1; // the NUL's index
            // Defence in depth. A needle carrying no NUL cannot span the
            // terminator, and NUL needles are rejected above — but the invariant
            // that a match lies wholly inside one entry is what keeps two
            // adjacent unrelated paths from fusing into a phantom match, so it
            // is checked rather than reasoned about.
            if abs + needle_len > entry_end {
                continue;
            }
            let qualifies = match scope {
                Scope::Path => true,
                // In `Name` scope the hit must be in the last component: no
                // separator may follow it inside this entry.
                Scope::Name => memchr::memchr2(b'/', b'\\', &self.bytes[abs..entry_end]).is_none(),
            };
            if !qualifies {
                continue;
            }
            last_pushed = idx;
            out.push(self.ids[idx]);
            if out.len() >= cap {
                return (out, true);
            }
        }
        (out, false)
    }
}

impl std::fmt::Debug for MetaIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MetaIndex")
            .field("entries", &self.ids.len())
            .field("resident_bytes", &self.resident_bytes())
            .field("segments", &self.segments.len())
            .finish()
    }
}

#[cfg(test)]
#[path = "meta_tests.rs"]
mod tests;
