//! # What these tests are defending against
//!
//! Not "does it compile" and not "is it fast". The recurring defect on this
//! project — eight instances so far, and instance #3 was *this exact component*
//! in its bake-off form — is a check that measures nothing: an index posting an
//! excellent p95 while matching zero documents. tantivy's positionless n-gram
//! tokenizer produced precisely that, and it looked healthy from the outside.
//!
//! So the rule here is that **no test asserts only an absence**. Every needle
//! that should match asserts the *exact set of ids* it matches, chosen so the
//! expected count is neither zero nor the whole corpus; and each of those is
//! paired with a needle that must match nothing, in the same corpus, so a
//! degenerate "match everything" implementation fails just as loudly as a
//! degenerate "match nothing" one.
//!
//! That claim was checked by mutation rather than asserted, because "my tests
//! are good" is itself a check that can measure nothing. Against the 21 tests
//! below:
//!
//! | mutation | failures |
//! |---|---|
//! | `search` returns `Matches::default()` unconditionally | **12** |
//! | scope forced to `Scope::Path` (name/path distinction gone) | **6** |
//! | the NUL terminator is not written (adjacent entries fuse) | **3** |
//!
//! Re-run those three by hand before trusting a change to this module; a
//! refactor that drops the first number to zero has deleted the point of the
//! file while leaving it green.

use super::*;

/// A corpus with deliberate traps in it.
///
/// * `report` appears in a filename (2, 4), in a *directory* name (5), and as a
///   substring of a longer word (`reporting`, 4) — so name-scope and path-scope
///   must disagree about row 5, and any implementation that anchors on token
///   boundaries loses row 4.
/// * casing varies, so a case-sensitive scan loses rows 4 and 6.
/// * rows 7 and 8 are adjacent and chosen so a needle spanning the seam between
///   them (`bar.txtzeta`) would match if the NUL terminator were absent.
/// * row 9 carries a Windows separator, which a `/`-only implementation would
///   treat as one long filename.
fn corpus() -> MetaIndex {
    let mut b = MetaIndexBuilder::with_capacity(16);
    for (id, path) in rows() {
        b.push(id, path).unwrap();
    }
    b.build().unwrap()
}

fn rows() -> Vec<(i64, &'static str)> {
    vec![
        (1, "notes/alpha.md"),
        (2, "notes/quarterly-report.pdf"),
        (3, "notes/beta.txt"),
        (4, "docs/Annual_REPORTING_2025.docx"),
        (5, "reports/summary.csv"),
        (6, "docs/Gamma.TXT"),
        (7, "seam/bar.txt"),
        (8, "seam/zeta.log"),
        (9, "win\\subdir\\delta.txt"),
        (10, "notes/epsilon.md"),
    ]
}

/// Search with a cap high enough that truncation cannot occur, and assert it did
/// not — otherwise a "count" is really "cap".
fn find(ix: &MetaIndex, q: &str) -> Vec<i64> {
    let m = ix.search(q, 1_000);
    assert!(
        !m.truncated,
        "`{q}` truncated at a cap of 1000; the count below would be meaningless"
    );
    m.ids
}

// ---------------------------------------------------------------------------
// The M1 demo needle, and its negative control
// ---------------------------------------------------------------------------

/// `shepctl search "report"` — the literal M1 demo query, against a corpus
/// where the right answer is a specific, non-trivial subset.
#[test]
fn the_m1_demo_needle_matches_exactly_the_files_whose_names_contain_it() {
    let ix = corpus();
    // Name scope: rows 2 and 4. NOT row 5 — `reports/` is a directory, and a
    // filename search returning every file under `reports/` is the bug that
    // makes as-you-type search useless on a organised tree.
    assert_eq!(find(&ix, "report"), vec![2, 4]);
}

/// The control. Same corpus, same code path, a needle that is present in no
/// path: if this returned hits the matcher would be matching something other
/// than what it was asked for.
#[test]
fn a_needle_present_in_no_path_matches_nothing() {
    let ix = corpus();
    for absent in [
        "zzzz",
        "report.pdf.bak",
        "quarterly-reports", // a superstring of a real name
        "\u{1F600}",
        "notes/gamma",
    ] {
        assert_eq!(
            find(&ix, absent),
            Vec::<i64>::new(),
            "`{absent}` is in no path in the corpus"
        );
    }
}

/// The two halves together, on one index instance: an implementation cannot
/// satisfy both by being degenerate in either direction.
#[test]
fn the_same_index_answers_a_present_and_an_absent_needle_differently() {
    let ix = corpus();
    let present = find(&ix, "report");
    let absent = find(&ix, "zzzz");
    assert_eq!(present.len(), 2);
    assert_eq!(absent.len(), 0);
    assert_ne!(present, absent);
}

// ---------------------------------------------------------------------------
// Query semantics
// ---------------------------------------------------------------------------

#[test]
fn matching_is_case_insensitive_in_both_directions() {
    let ix = corpus();
    // The corpus rows are mixed case; the queries here are too. Every one of
    // these must find the same two files.
    for q in ["report", "REPORT", "RePoRt"] {
        assert_eq!(find(&ix, q), vec![2, 4], "query `{q}`");
    }
    // And a row stored upper-case is reachable by a lower-case query.
    assert_eq!(find(&ix, "gamma.txt"), vec![6]);
    assert_eq!(find(&ix, "GAMMA.TXT"), vec![6]);
}

#[test]
fn a_query_naming_a_separator_searches_the_whole_path() {
    let ix = corpus();
    assert_eq!(Scope::for_query("notes/"), Scope::Path);
    assert_eq!(Scope::for_query("report"), Scope::Name);

    // Path scope reaches directory components...
    assert_eq!(find(&ix, "notes/"), vec![1, 2, 3, 10]);
    assert_eq!(find(&ix, "reports/"), vec![5]);
    // ...and spans the separator itself.
    assert_eq!(find(&ix, "notes/beta"), vec![3]);
    // The same text without the separator is a name query and finds nothing,
    // because no *filename* contains `notes`.
    assert_eq!(find(&ix, "notes"), Vec::<i64>::new());
}

#[test]
fn a_hit_in_a_directory_component_does_not_satisfy_a_name_query() {
    let ix = corpus();
    // `reports/summary.csv` contains "report" — in its directory. A name query
    // must not return it, or every file in a well-named folder becomes a hit
    // for that folder's name.
    assert!(!find(&ix, "report").contains(&5));
    // But `summary` is in its filename, so the row is reachable.
    assert_eq!(find(&ix, "summary"), vec![5]);
}

#[test]
fn a_windows_separator_delimits_a_name_exactly_as_a_unix_one_does() {
    let ix = corpus();
    // `rel_path` keeps the separators the OS gave it, so a catalog written on
    // Windows holds `\`. Row 9 is `win\subdir\delta.txt`.
    assert_eq!(find(&ix, "delta"), vec![9]);
    // `subdir` is a directory component of row 9 — a name query must miss it.
    // A `/`-only implementation sees one long filename and wrongly returns it.
    assert_eq!(find(&ix, "subdir"), Vec::<i64>::new());
    // Under path scope it is reachable.
    assert_eq!(find(&ix, "subdir\\"), vec![9]);
}

#[test]
fn a_prefix_query_is_just_an_infix_query_that_matched_at_zero() {
    let ix = corpus();
    // Leading characters of a filename.
    assert_eq!(find(&ix, "quarter"), vec![2]);
    // Middle of a filename, no token boundary to anchor on — the class §4.6
    // says makes the problem hard, and the one FTS5 and tantivy failed.
    assert_eq!(find(&ix, "arterly-rep"), vec![2]);
    // Trailing characters.
    assert_eq!(find(&ix, ".docx"), vec![4]);
}

#[test]
fn a_file_containing_the_needle_twice_is_returned_once() {
    let mut b = MetaIndexBuilder::new();
    b.push(1, "aa/aaa.txt").unwrap(); // "aa" occurs at 0, 3 and 4
    b.push(2, "b/c.txt").unwrap();
    let ix = b.build().unwrap();
    // Three raw `memmem` hits, one of which is in the directory; the file must
    // appear exactly once, or `total` double-counts and paging skips rows.
    assert_eq!(find(&ix, "aa"), vec![1]);
}

// ---------------------------------------------------------------------------
// Arena integrity
// ---------------------------------------------------------------------------

#[test]
fn a_needle_spanning_two_adjacent_entries_matches_nothing() {
    let ix = corpus();
    // Rows 7 and 8 are `seam/bar.txt` and `seam/zeta.log`, stored back to back.
    // Without the NUL terminator the arena reads `...bar.txtseam/zeta.log...`
    // and this needle matches a file that does not exist.
    assert_eq!(find(&ix, "bar.txtseam"), Vec::<i64>::new());
    assert_eq!(find(&ix, "txtseam"), Vec::<i64>::new());
    // Both halves are individually present, so the corpus really does place
    // them adjacently and the assertion above is not vacuous.
    assert_eq!(find(&ix, "bar.txt"), vec![7]);
    assert_eq!(find(&ix, "zeta"), vec![8]);
}

#[test]
fn a_needle_containing_the_arenas_own_separator_matches_nothing() {
    let ix = corpus();
    // NUL is the terminator. If it were searchable, this needle would match
    // every entry boundary in the arena.
    assert_eq!(ix.search("\0", 1_000), Matches::default());
    assert_eq!(ix.search("txt\0seam", 1_000), Matches::default());
}

#[test]
fn an_empty_query_matches_nothing_rather_than_everything() {
    let ix = corpus();
    // `memmem` with an empty needle finds a hit at every byte offset. Returning
    // the whole corpus for an empty as-you-type box is the failure this guards.
    assert_eq!(ix.search("", 1_000), Matches::default());
    assert_eq!(ix.search("report", 0).ids, Vec::<i64>::new());
}

#[test]
fn an_empty_index_is_searchable_and_answers_nothing() {
    let ix = MetaIndex::empty();
    assert_eq!(ix.len(), 0);
    assert!(ix.is_empty());
    assert_eq!(ix.search("report", 10), Matches::default());
    // A daemon that has scanned nothing must answer "no hits", not panic — the
    // e2e's empty-catalog control depends on this.
    assert_eq!(ix.segment_count(), 0);
}

#[test]
fn results_are_returned_in_push_order_which_the_daemon_makes_id_order() {
    let mut b = MetaIndexBuilder::new();
    // Pushed ascending, as `SELECT ... ORDER BY id` yields them.
    for id in [3i64, 9, 14, 27, 100] {
        b.push(id, &format!("dir/report-{id}.txt")).unwrap();
    }
    let ix = b.build().unwrap();
    assert_eq!(find(&ix, "report"), vec![3, 9, 14, 27, 100]);
}

// ---------------------------------------------------------------------------
// Capping and truncation
// ---------------------------------------------------------------------------

#[test]
fn a_cap_bounds_the_result_and_says_so() {
    let mut b = MetaIndexBuilder::new();
    for id in 1..=50i64 {
        b.push(id, &format!("d/report-{id:03}.txt")).unwrap();
    }
    let ix = b.build().unwrap();

    let all = ix.search("report", 1_000);
    assert_eq!(all.ids.len(), 50, "every row contains the needle");
    assert!(!all.truncated);

    let capped = ix.search("report", 10);
    assert_eq!(capped.ids.len(), 10);
    assert!(
        capped.truncated,
        "a capped result must announce that its length is a floor, not a total"
    );
    // Deterministic prefix: the capped answer is the first 10 of the full one,
    // so page 2 cannot repeat page 1.
    assert_eq!(capped.ids, all.ids[..10]);
}

/// A page that is FULL is not a page that was cut short.
///
/// The scan used to set the flag the moment `out.len()` reached the cap,
/// without ever looking for a match beyond it. So a query with exactly `cap`
/// matches — an unfiltered search with the default limit of 50 and fifty files
/// — was reported truncated, and `search` told the caller its `total` was a
/// lower bound when it was the exact count. "Fifty results, and there may be
/// more" and "fifty results, that is all of them" are different answers and a
/// user acts on them differently.
#[test]
fn exactly_a_full_page_is_not_reported_as_truncated() {
    let mut b = MetaIndexBuilder::new();
    for id in 1..=50i64 {
        b.push(id, &format!("d/report-{id:03}.txt")).unwrap();
    }
    let ix = b.build().unwrap();

    let exact = ix.search("report", 50);
    assert_eq!(exact.ids.len(), 50);
    assert!(
        !exact.truncated,
        "fifty matches under a cap of fifty is the complete answer, not a floor"
    );

    // The discriminating pair: one more match than the cap, and the flag is
    // right again. Without this the fix could be "never truncate".
    let one_short = ix.search("report", 49);
    assert_eq!(one_short.ids.len(), 49);
    assert!(
        one_short.truncated,
        "forty-nine of fifty really is a truncated page"
    );
}

#[test]
fn the_capped_result_is_the_same_on_every_run() {
    let mut b = MetaIndexBuilder::new();
    for id in 1..=200i64 {
        b.push(id, &format!("d/report-{id:03}.txt")).unwrap();
    }
    let ix = b.build().unwrap();
    let first = ix.search("report", 7);
    for _ in 0..20 {
        assert_eq!(
            ix.search("report", 7),
            first,
            "a repeated identical query returned a different set"
        );
    }
}

// ---------------------------------------------------------------------------
// The parallel scan
// ---------------------------------------------------------------------------

/// The segmented scan must produce exactly what a single-segment scan produces.
///
/// This is the test that would catch a boundary bug in the segment arithmetic —
/// an entry dropped at a seam, or one counted by two segments. The arena is
/// pushed past `PARALLEL_SCAN_THRESHOLD_BYTES` so the parallel path is really
/// taken, which the assertion on `segment_count` proves rather than assumes.
#[test]
fn the_parallel_scan_agrees_with_the_single_threaded_one() {
    let mut big = MetaIndexBuilder::new();
    let mut small = MetaIndexBuilder::new();
    let mut expected = Vec::new();
    // ~9 MB of paths: over the parallel threshold, quick to build.
    let filler = "x".repeat(80);
    for id in 1..=110_000i64 {
        // Every 1000th row is a hit, so the expected set is spread across every
        // segment rather than living in the first one.
        let path = if id % 1_000 == 0 {
            expected.push(id);
            format!("dir{id}/{filler}-report-{id}.txt")
        } else {
            format!("dir{id}/{filler}-{id}.txt")
        };
        big.push(id, &path).unwrap();
        small.push(id, &path).unwrap();
    }
    let big = big.build().unwrap();
    assert_eq!(expected.len(), 110);

    if std::thread::available_parallelism().map_or(1, |p| p.get()) > 1 {
        assert!(
            big.segment_count() > 1,
            "this test is pointless unless the parallel path is taken; \
             arena is {} bytes across {} segments",
            big.resident_bytes(),
            big.segment_count()
        );
    }

    let got = big.search("report", 10_000);
    assert!(!got.truncated);
    assert_eq!(
        got.ids, expected,
        "the segmented scan lost or duplicated rows"
    );

    // And the absent-needle control at the same scale, where a full scan of
    // every segment is forced and no early exit can hide a broken segment.
    assert_eq!(big.search("no-such-needle-anywhere", 10_000).ids.len(), 0);
}

// ---------------------------------------------------------------------------
// The RAM figure AC-46 is charged
// ---------------------------------------------------------------------------

/// The per-entry cost is a documented constant, so it is asserted against the
/// real allocation rather than restated.
#[test]
fn the_documented_per_entry_overhead_is_the_real_layout() {
    assert_eq!(OVERHEAD_BYTES_PER_ENTRY, 13);

    const N: usize = 4_096;
    const PATH: &str = "some/directory/somewhere/file-000000.dat"; // 40 bytes
    let mut b = MetaIndexBuilder::with_capacity(N);
    for id in 0..N as i64 {
        b.push(id, PATH).unwrap();
    }
    let ix = b.build().unwrap();

    // What the documented identity predicts, ignoring spare Vec capacity.
    let predicted = N * (PATH.len() + OVERHEAD_BYTES_PER_ENTRY);
    let actual = ix.resident_bytes() as usize;

    assert!(
        actual >= predicted,
        "resident {actual} < predicted {predicted}; the identity over-counts, \
         which would understate the AC-46 charge"
    );
    // `with_capacity` assumes 76-byte paths against these 40-byte ones, so
    // without the `shrink_to_fit` in `build()` this index would be carrying
    // ~36 bytes/entry of reserved-and-unusable arena. At 10M that is ~360 MB
    // charged to AC-46 for nothing, which is why the shrink is not optional.
    assert!(
        actual < predicted + N * 4,
        "resident {actual} is far above the predicted {predicted}: the builder is \
         holding spare capacity an immutable index can never use"
    );

    // The §4.6 correction, pinned as a test so it cannot drift back into prose:
    // 350 MB at 10M entries is not reachable by this design.
    let per_entry_at_10m = 60 + OVERHEAD_BYTES_PER_ENTRY; // 60-byte mean path
    let projected_10m = 10_000_000u64 * per_entry_at_10m as u64;
    assert!(
        projected_10m > 700_000_000,
        "§4.6 budgets 350 MB at 10M names; full paths plus a file_id are {projected_10m} bytes"
    );
}

#[test]
fn resident_bytes_grows_with_the_corpus_and_is_never_zero_for_a_nonempty_index() {
    let empty = MetaIndex::empty().resident_bytes();
    let ix = corpus();
    assert!(
        ix.resident_bytes() > empty,
        "an index over {} entries reported {} bytes",
        ix.len(),
        ix.resident_bytes()
    );
    assert_eq!(ix.len(), rows().len());
}

// ---------------------------------------------------------------------------
// Build-time limits
// ---------------------------------------------------------------------------

#[test]
fn the_builder_reports_what_it_holds() {
    let mut b = MetaIndexBuilder::new();
    assert!(b.is_empty());
    b.push(7, "a/b.txt").unwrap();
    b.push(8, "a/c.txt").unwrap();
    assert_eq!(b.len(), 2);
    assert!(!b.is_empty());
    assert_eq!(b.build().unwrap().len(), 2);
}

// ---------------------------------------------------------------------------
// The 50 ms bar, against the shipped code
// ---------------------------------------------------------------------------

/// §4.6's bar, re-measured against **this** implementation rather than the
/// spike's.
///
/// This test exists because the spike's 22.20 ms p95 does not transfer for free.
/// The shipped index differs from the measured one in three ways that all touch
/// the hot path: it carries a `file_id` per entry (a bigger arena), it uses
/// `std::thread::scope` where the spike used rayon, and it dropped the spike's
/// *global* early exit for a per-segment one, which does strictly more work.
/// Quoting 22.20 ms for code that was never run would be exactly the move §4.6
/// warns about.
///
/// `#[ignore]` because it allocates ~700 MB and takes a minute or so; it is a
/// gate you run deliberately:
///
/// ```text
/// cargo test -p shepherd-index --release -- --ignored --nocapture
/// ```
///
/// Debug builds are meaningless here — `memmem` without optimisation is not the
/// thing being measured — so the test refuses to report a verdict unless it was
/// compiled in release.
#[test]
#[ignore = "allocates ~700 MB and takes ~1 min; run explicitly with --release"]
fn the_production_index_meets_the_50ms_bar_at_10m_entries() {
    // Fails loudly rather than reporting a debug-build number. A `memmem` scan
    // compiled without optimisation is not the thing under measurement, and a
    // p95 from one would be a figure about nothing.
    if cfg!(debug_assertions) {
        panic!(
            "this measurement is only meaningful in --release; \
             run `cargo test -p shepherd-index --release -- --ignored --nocapture`"
        );
    }

    const N: usize = 10_000_000;
    const BAR_MS: f64 = 50.0;

    let t0 = std::time::Instant::now();
    let mut b = MetaIndexBuilder::with_capacity(N);
    // Deterministic synthetic paths with a ~60-byte mean, the figure the RAM
    // projection uses. No RNG: a fixed corpus makes the number comparable
    // between runs, and `Math.random`-style variation would only add noise to a
    // latency measurement.
    for id in 0..N as i64 {
        let d1 = id % 977;
        let d2 = (id / 977) % 653;
        let path = format!("home/user/archive-{d1:04}/project-{d2:04}/document-{id:08}.dat");
        b.push(id, &path).unwrap();
    }
    let ix = b.build().unwrap();
    let build = t0.elapsed();
    assert_eq!(ix.len(), N);

    // The as-you-type profile: a query is typed one character at a time, so the
    // interesting latencies are the short prefixes that match a great deal and
    // the ones that match nothing. Both are included on purpose — §4.6 records
    // that **the worst case for this design is a query matching nothing**,
    // because that is the one that cannot exit early anywhere.
    let queries: Vec<(&str, bool)> = vec![
        ("doc", true),
        ("docu", true),
        ("docum", true),
        ("document-0000", true),
        ("document-00000042", true),
        ("archive-0500/", true),
        ("zzz", false),
        ("qqqqqqqq", false),
        ("document-99999999", false),
        ("no-such-document-anywhere", false),
    ];

    let mut samples: Vec<f64> = Vec::new();
    let mut total_hits = 0usize;
    for round in 0..20 {
        for (q, should_hit) in &queries {
            let t = std::time::Instant::now();
            let m = ix.search(q, 100);
            samples.push(t.elapsed().as_secs_f64() * 1000.0);
            total_hits += m.ids.len();
            // The pairing that makes the latency mean something. A p95 measured
            // over queries that all returned nothing is the tantivy trap.
            if *should_hit {
                assert!(
                    !m.ids.is_empty(),
                    "round {round}: `{q}` matched nothing at 10M entries — \
                     the latency below would be measuring an index that does not work"
                );
            } else {
                assert!(
                    m.ids.is_empty(),
                    "round {round}: `{q}` should match nothing"
                );
            }
        }
    }
    assert!(
        total_hits > 0,
        "every query returned nothing; this measured an empty scan"
    );

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let pct = |p: f64| samples[((samples.len() as f64 * p) as usize).min(samples.len() - 1)];
    let (p50, p95, p99) = (pct(0.50), pct(0.95), pct(0.99));
    let resident_mb = ix.resident_bytes() as f64 / (1024.0 * 1024.0);

    println!(
        "\n  entries      {N}\n  \
           build        {:.2} s\n  \
           resident     {resident_mb:.1} MiB ({:.1} bytes/entry)\n  \
           segments     {}\n  \
           hits total   {total_hits}\n  \
           p50          {p50:.2} ms\n  \
           p95          {p95:.2} ms   (bar {BAR_MS} ms)\n  \
           p99          {p99:.2} ms\n",
        build.as_secs_f64(),
        ix.resident_bytes() as f64 / N as f64,
        ix.segment_count(),
    );

    assert!(
        p95 < BAR_MS,
        "§4.6's metadata bar is {BAR_MS} ms p95 at 10M; measured {p95:.2} ms"
    );
}

#[test]
fn the_arena_ceiling_is_an_error_and_names_its_size() {
    let e = BuildError::ArenaTooLarge {
        entries: 58_000_000,
        bytes: MAX_ARENA_BYTES + 1,
    };
    let text = e.to_string();
    assert!(text.contains("58000000"), "{text}");
    assert!(text.contains("u32"), "{text}");
    // The spike's in-place `append` silently dropped an entry on this
    // condition — an index quietly missing rows. Production must be an error.
    assert!(matches!(e, BuildError::ArenaTooLarge { .. }));
}
