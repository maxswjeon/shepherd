//! The vector leg — `usearch` at f32/f16/i8, `view()` mmap, 1M-vector shards,
//! against the 300 ms bar and the AC-46 RAM ceiling.
//!
//! # Status of this file
//!
//! Mixed, and the split matters. **The measurement scaffolding survives** —
//! shard sizing, the mmap open path, the RSS accounting and the recall oracle
//! are what Phase 5's gate re-runs. **The query loop is spike code**: there is no
//! embedding model here (that is `shepherd-infer`, Phase 5), so query vectors are
//! synthesised from the fixture's own cluster structure rather than produced by
//! MiniLM. That is stated rather than hidden, because it means this leg measures
//! *index* latency and excludes the 15-25 ms §4.6 budgets for query embedding.
//!
//! # What is actually under test
//!
//! §4.6 picks `usearch` as the primary on evidence, so the bake-off here is not
//! between crates — it is between **precisions**, and the thing being checked is
//! the plan's own RAM extrapolation:
//!
//! | Precision | Vectors | HNSW links (M=16) | Total |
//! |---|---|---|---|
//! | f32 | 14.6 GB | 2.5 GB | ~17 GB |
//! | f16 | 7.7 GB | 2.5 GB | ~10 GB |
//! | i8 | 3.8 GB | 2.5 GB | ~6.3 GB |
//!
//! That table is flagged `[U — third-party, single source; Phase 0b
//! re-measures]`, and R-4 hangs a High risk on it. This is the re-measurement.
//!
//! # Why recall is measured at all
//!
//! The plan pre-decides i8 as the default on RAM grounds. RAM and latency alone
//! cannot distinguish a good i8 index from a small fast one that returns
//! garbage, and quantisation is exactly the knob that produces the latter. So
//! every precision is checked against an exact brute-force oracle. The floor is
//! recorded in the contract as a **sanity** floor, not an acceptance criterion
//! the plan authorised.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;

use rayon::prelude::*;
use usearch::{Index, IndexOptions, MetricKind, ScalarKind};

use crate::generate;
use crate::{Args, Contract, Percentiles, RunSet};

/// §4.6 pins `connectivity = 16` (M=16) as the basis of its link-overhead
/// estimate, so changing it would make the measurement answer a different
/// question than the table it is checking.
const CONNECTIVITY: usize = 16;
const EXPANSION_ADD: usize = 128;
const EXPANSION_SEARCH: usize = 64;

fn scalar(prec: &str) -> Result<ScalarKind, String> {
    match prec {
        "f32" => Ok(ScalarKind::F32),
        "f16" => Ok(ScalarKind::F16),
        "i8" => Ok(ScalarKind::I8),
        other => Err(format!(
            "unknown precision {other} (expected f32|f16|i8 — the three §4.6 tabulates)"
        )),
    }
}

fn options(dims: usize, prec: &str) -> Result<IndexOptions, String> {
    Ok(IndexOptions {
        dimensions: dims,
        // Cosine, because the fixture is unit-normalised on the hypersphere the
        // way sentence embeddings are, and §4.6's retrieval stage scores on
        // cosine similarity.
        metric: MetricKind::Cos,
        quantization: scalar(prec)?,
        connectivity: CONNECTIVITY,
        expansion_add: EXPANSION_ADD,
        expansion_search: EXPANSION_SEARCH,
        multi: false,
    })
}

fn shard_dir(fixtures: &Path, prec: &str) -> PathBuf {
    fixtures.join(format!("usearch-{prec}"))
}

fn shard_path(fixtures: &Path, prec: &str, i: u64) -> PathBuf {
    shard_dir(fixtures, prec).join(format!("shard-{i:03}.usearch"))
}

// ---------------------------------------------------------------------------
// Build
// ---------------------------------------------------------------------------

/// Build the shard set, one shard at a time.
///
/// **One at a time is the point, not an implementation detail.** §4.6's write
/// path is LSM-style precisely because `usearch`'s own issue tracker leaves it
/// open whether `view()` supports safe incremental writes against the mapped
/// file (#97). Sealing one shard before starting the next also bounds build-time
/// RAM to a single shard, which is what makes a 10M-vector build possible on a
/// machine that could not hold the whole f32 index in the heap at once.
pub fn build(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let prec = a.target.clone().ok_or("build-ann needs f32|f16|i8")?;
    let opts = options(c.fixture.dimensions, &prec)?;
    let total = a.rows_override.unwrap_or(c.fixture.vectors);
    let per_shard = c.fixture.vectors_per_shard.min(total);
    let shards = total.div_ceil(per_shard);

    crate::disk_guard(&a.fixtures, c.disk_guard.abort_below_free_gib)?;
    let dir = shard_dir(&a.fixtures, &prec);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let dims = c.fixture.dimensions;
    let t0 = Instant::now();
    for s in 0..shards {
        // Re-check between shards: this loop is the largest disk consumer in the
        // whole spike and the box is shared.
        crate::disk_guard(&a.fixtures, c.disk_guard.abort_below_free_gib)?;
        let lo = s * per_shard;
        let hi = (lo + per_shard).min(total);
        let index = Index::new(&opts).map_err(|e| e.to_string())?;
        index
            .reserve(( hi - lo) as usize)
            .map_err(|e| e.to_string())?;

        // usearch takes concurrent adds; generation is the expensive half and it
        // parallelises perfectly since vector i depends only on (seed, i).
        (lo..hi)
            .into_par_iter()
            .try_for_each(|i| -> Result<(), String> {
                let mut v = vec![0f32; dims];
                generate::vector_for(
                    c.fixture.seed,
                    i,
                    dims,
                    c.fixture.centroids,
                    c.fixture.cluster_noise,
                    &mut v,
                );
                index.add(i, &v).map_err(|e| e.to_string())
            })?;

        let p = shard_path(&a.fixtures, &prec, s);
        index.save(p.to_str().ok_or("non-UTF8 path")?).map_err(|e| e.to_string())?;
        eprintln!(
            "[build-ann {prec}] shard {s}/{shards} sealed, {:.0}s elapsed, \
             {:.2} GiB on disk, peak RSS {:.2} GiB",
            t0.elapsed().as_secs_f64(),
            crate::path_bytes(&dir) as f64 / 1073741824.0,
            crate::vm_hwm_bytes() as f64 / 1073741824.0
        );
    }

    let elapsed = t0.elapsed();
    let bytes = crate::path_bytes(&dir);
    let per_vec = bytes as f64 / total as f64;
    eprintln!(
        "[build-ann {prec}] {total} vectors in {shards} shards, {:.0}s, \
         {:.2} GiB total ({per_vec:.0} B/vector)",
        elapsed.as_secs_f64(),
        bytes as f64 / 1073741824.0
    );

    crate::emit(
        &a.out,
        &format!("ann_build_{prec}"),
        serde_json::json!({
            "precision": prec,
            "vectors": total,
            "dimensions": dims,
            "shards": shards,
            "vectors_per_shard": per_shard,
            "connectivity": CONNECTIVITY,
            "build_seconds": elapsed.as_secs_f64(),
            "on_disk_bytes": bytes,
            "bytes_per_vector": per_vec,
            "on_disk_gib": bytes as f64 / 1073741824.0,
            "peak_vm_hwm_bytes": crate::vm_hwm_bytes(),
            "scaled_run_reason": a.scaled_run_reason,
        }),
    )
}

// ---------------------------------------------------------------------------
// Query
// ---------------------------------------------------------------------------

/// Every shard, opened read-only through `view()`.
///
/// This is §4.6's central claim under test: "Resident RAM is then only
/// navigation structures plus a bounded hot-page budget; the OS page cache does
/// the rest." If that holds, `VmRSS` after a query run is far below the on-disk
/// size. If it does not, the AC-46 ceiling arithmetic in the plan is wrong.
struct Shards {
    indexes: Vec<Index>,
}

impl Shards {
    fn open(fixtures: &Path, prec: &str, opts: &IndexOptions) -> Result<(Self, f64), String> {
        let dir = shard_dir(fixtures, prec);
        let mut paths: Vec<PathBuf> = std::fs::read_dir(&dir)
            .map_err(|e| format!("{}: {e} — run `build-ann {prec}` first", dir.display()))?
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "usearch"))
            .collect();
        paths.sort();
        if paths.is_empty() {
            return Err(format!("no shards in {}", dir.display()));
        }
        let t0 = Instant::now();
        let mut indexes = Vec::with_capacity(paths.len());
        for p in &paths {
            let idx = Index::new(opts).map_err(|e| e.to_string())?;
            idx.view(p.to_str().ok_or("non-UTF8 path")?)
                .map_err(|e| format!("view() failed on {}: {e}", p.display()))?;
            indexes.push(idx);
        }
        Ok((Self { indexes }, t0.elapsed().as_secs_f64()))
    }

    fn count(&self) -> usize {
        self.indexes.iter().map(|i| i.size()).sum()
    }

    /// Query every shard in parallel and merge, which is §4.6's "ANN top-K
    /// across shards, parallel, per-shard deadline" minus the deadline — a
    /// per-shard timeout would cap the tail by *dropping results*, and measuring
    /// a latency bound that is enforced by discarding answers would make the p95
    /// meaningless.
    fn search(&self, q: &[f32], k: usize) -> Vec<(u64, f32)> {
        let mut merged: Vec<(u64, f32)> = self
            .indexes
            .par_iter()
            .map(|idx| {
                idx.search(q, k)
                    .map(|m| {
                        m.keys
                            .into_iter()
                            .zip(m.distances)
                            .collect::<Vec<(u64, f32)>>()
                    })
                    .unwrap_or_default()
            })
            .reduce(Vec::new, |mut a, b| {
                a.extend(b);
                a
            });
        merged.sort_by(|x, y| x.1.partial_cmp(&y.1).unwrap_or(std::cmp::Ordering::Equal));
        merged.truncate(k);
        merged
    }
}

/// The semantic slice of the committed trace, as query vectors.
///
/// **Recorded substitution:** there is no embedding model at Phase 0b, so the
/// query *text* in the trace is not embedded. Each semantic line carries the
/// centroid id it was generated against, and the query vector is synthesised
/// from that centroid — so a query lands inside the fixture's cluster structure
/// exactly as a real embedding would land inside a topic. What this does NOT
/// include is the 15-25 ms §4.6 budgets for embedding the query; the numbers
/// here are index latency alone, and the report says so.
fn query_vectors(c: &Contract) -> Result<Vec<Vec<f32>>, String> {
    let trace = generate::load_trace(c)?;
    let dims = c.fixture.dimensions;
    Ok(trace
        .iter()
        .filter(|(class, _, _)| c.query_trace.semantic_classes.contains(class))
        .enumerate()
        .map(|(k, (_, _, centroid))| {
            let mut v = vec![0f32; dims];
            generate::query_vector(
                c.fixture.seed,
                *centroid,
                k as u64,
                c.fixture.cluster_noise,
                &mut v,
            );
            v
        })
        .collect())
}

pub fn bench(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let prec = a.target.clone().ok_or("bench-ann needs f32|f16|i8")?;
    let opts = options(c.fixture.dimensions, &prec)?;
    let queries = query_vectors(&c)?;
    if queries.len() < c.statistics.queries_per_run {
        return Err(format!(
            "trace holds {} semantic queries; the contract fixes n = {} per run",
            queries.len(),
            c.statistics.queries_per_run
        ));
    }

    // Cold BEFORE open, so the mmap open and its first page faults are inside
    // the cold measurement rather than warmed up ahead of it.
    if a.cache == "cold" {
        crate::drop_page_cache()
            .map_err(|e| format!("{e}\n(precision {prec}: refusing to report this run as cold)"))?;
        eprintln!("[cache] page cache dropped — this run is genuinely cold");
    }

    let (shards, open_seconds) = Shards::open(&a.fixtures, &prec, &opts)?;
    let shards = Arc::new(shards);
    let on_disk = crate::path_bytes(&shard_dir(&a.fixtures, &prec));
    let rss_after_open = crate::vm_rss_bytes();
    eprintln!(
        "[bench-ann {prec}] {} vectors across {} shards viewed in {open_seconds:.2}s, \
         RSS after open {:.2} GiB vs {:.2} GiB on disk",
        shards.count(),
        shards.indexes.len(),
        rss_after_open as f64 / 1073741824.0,
        on_disk as f64 / 1073741824.0
    );

    let k = c.execution.top_k;
    let queries = Arc::new(queries);
    let mut run_stats = Vec::new();

    for run in 0..c.statistics.runs {
        let next = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..c.execution.query_clients {
            let shards = Arc::clone(&shards);
            let queries = Arc::clone(&queries);
            let next = Arc::clone(&next);
            let n = c.statistics.queries_per_run;
            handles.push(std::thread::spawn(move || {
                let mut lat = Vec::new();
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    if i >= n {
                        break;
                    }
                    let t = Instant::now();
                    let _ = shards.search(&queries[i], k);
                    lat.push(t.elapsed());
                }
                lat
            }));
        }
        let mut lat = Vec::new();
        for h in handles {
            lat.extend(h.join().map_err(|_| "query client panicked")?);
        }
        let p = Percentiles::of(lat);
        eprintln!(
            "[bench-ann {prec}/{}] run {run}: p50 {:.2}  p95 {:.2}  p99 {:.2}  max {:.2} ms",
            a.cache, p.p50_ms, p.p95_ms, p.p99_ms, p.max_ms
        );
        run_stats.push(p);
    }

    let rs = RunSet::reduce(run_stats, c.statistics.drift_flag_pct);
    let pass = rs.accepted_p95_ms < c.bars.vector_p95_ms;
    let gib = on_disk as f64 / 1073741824.0;
    eprintln!(
        "[bench-ann {prec}/{}] ACCEPTED p95 {:.2} ms vs bar {:.0} ms -> {}   \
         index {gib:.2} GiB (AC-46 range {:.0}-{:.0} GiB)",
        a.cache,
        rs.accepted_p95_ms,
        c.bars.vector_p95_ms,
        if pass { "PASS" } else { "FAIL" },
        c.bars.ac46_ceiling_min_gib,
        c.bars.ac46_ceiling_max_gib
    );

    crate::emit(
        &a.out,
        &format!("ann_bench_{prec}_{}", a.cache),
        serde_json::json!({
            "precision": prec,
            "cache": a.cache,
            "vectors": shards.count(),
            "shards": shards.indexes.len(),
            "top_k": k,
            "stats": rs,
            "bar_ms": c.bars.vector_p95_ms,
            "pass": pass,
            "view_open_seconds": open_seconds,
            // The three numbers the RSS method note in main.rs insists on
            // reporting together, because for a view()-mmap'd index no single
            // one of them is a falsifiable claim about memory.
            "on_disk_bytes": on_disk,
            "on_disk_gib": gib,
            "vm_rss_after_open_bytes": rss_after_open,
            "vm_rss_after_queries_bytes": crate::vm_rss_bytes(),
            "peak_vm_hwm_bytes": crate::vm_hwm_bytes(),
            "ac46_min_gib": c.bars.ac46_ceiling_min_gib,
            "ac46_max_gib": c.bars.ac46_ceiling_max_gib,
            "ac46_fits_ceiling_range": gib <= c.bars.ac46_ceiling_max_gib,
            "embedding_cost_excluded_note":
                "Index latency only. No embedding model exists at Phase 0b, so \
                 §4.6's 15-25 ms query-embedding budget is NOT included in these \
                 numbers and must be added before comparing against the 300 ms \
                 end-to-end bar.",
            "machine": crate::probe_machine(&c.reference_machine.pin_to_cores),
            "scaled_run_reason": a.scaled_run_reason,
        }),
    )
}

// ---------------------------------------------------------------------------
// Recall
// ---------------------------------------------------------------------------

/// Recall@10 of one shard against an exact brute-force oracle.
///
/// **Measured on a single shard, deliberately.** Production queries each shard
/// and merges, so per-shard recall is the unit that actually composes; and a
/// whole-corpus oracle would mean streaming 15 GiB of f32 per query, which buys
/// no additional information about quantisation loss. The oracle recomputes the
/// original f32 vectors from the seed rather than reading them back out of the
/// index — reading them back would compare a quantised index against its own
/// quantised contents and report near-perfect recall for every precision, which
/// is precisely the check that would not catch a bad i8 index.
pub fn recall(a: &Args) -> Result<(), String> {
    let c = Contract::load(&a.contract)?;
    let prec = a.target.clone().ok_or("recall-ann needs f32|f16|i8")?;
    let opts = options(c.fixture.dimensions, &prec)?;
    let dims = c.fixture.dimensions;
    let per_shard = c.fixture.vectors_per_shard;

    let path = shard_path(&a.fixtures, &prec, 0);
    let index = Index::new(&opts).map_err(|e| e.to_string())?;
    index
        .view(path.to_str().ok_or("non-UTF8 path")?)
        .map_err(|e| format!("view() failed on {}: {e}", path.display()))?;
    let n = index.size() as u64;

    // Regenerate shard 0's vectors as f32 ground truth.
    let t0 = Instant::now();
    let mut flat = vec![0f32; (n as usize) * dims];
    flat.par_chunks_mut(dims).enumerate().for_each(|(i, out)| {
        generate::vector_for(
            c.fixture.seed,
            i as u64,
            dims,
            c.fixture.centroids,
            c.fixture.cluster_noise,
            out,
        );
    });
    eprintln!(
        "[recall {prec}] oracle corpus rebuilt ({n} x {dims} f32, {:.1} GiB) in {:.1}s",
        flat.len() as f64 * 4.0 / 1073741824.0,
        t0.elapsed().as_secs_f64()
    );

    const PROBES: usize = 100;
    const K: usize = 10;
    let queries = query_vectors(&c)?;
    let probes: Vec<&Vec<f32>> = queries.iter().take(PROBES).collect();

    let hits: usize = probes
        .par_iter()
        .enumerate()
        .map(|(qi, q)| {
            // Exact top-K by cosine distance. Vectors are unit-normalised, so
            // 1 - dot is the cosine distance and no norms are needed.
            let mut all: Vec<(f32, u64)> = (0..n as usize)
                .map(|i| {
                    let base = i * dims;
                    let dot: f32 = (0..dims).map(|d| flat[base + d] * q[d]).sum();
                    (1.0 - dot, i as u64)
                })
                .collect();
            all.sort_by(|x, y| x.0.partial_cmp(&y.0).unwrap_or(std::cmp::Ordering::Equal));
            let truth: std::collections::HashSet<u64> =
                all.iter().take(K).map(|(_, id)| *id).collect();
            let got = index
                .search(probes[qi], K)
                .map(|m| m.keys)
                .unwrap_or_default();
            got.iter().filter(|k| truth.contains(k)).count()
        })
        .sum();

    let recall = hits as f64 / (PROBES * K) as f64;
    let floor = c.bars.ann_recall_at_10_floor;
    eprintln!(
        "[recall {prec}] recall@{K} = {recall:.4} over {PROBES} probes on shard 0 \
         ({n} vectors); sanity floor {floor:.2} -> {}",
        if recall >= floor { "ok" } else { "BELOW FLOOR" }
    );

    crate::emit(
        &a.out,
        &format!("ann_recall_{prec}"),
        serde_json::json!({
            "precision": prec,
            "shard": 0,
            "shard_vectors": n,
            "vectors_per_shard_contract": per_shard,
            "probes": PROBES,
            "k": K,
            "recall_at_10": recall,
            "sanity_floor": floor,
            "above_floor": recall >= floor,
            "oracle": "exact cosine brute force over f32 vectors regenerated from the \
                       seed — NOT read back from the quantised index, which would \
                       compare the index against itself",
            "scaled_run_reason": a.scaled_run_reason,
        }),
    )
}
