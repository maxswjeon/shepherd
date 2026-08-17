# Phase 0b — the index decision

**Status:** metadata index **decided** (§3). Vector precision **measured and
recorded** (§7), with one escalation.
**Date:** 2026-08-16
**Gate:** §9 Phase 0a/0b. Evidence: `bench-baseline.json`, `bench-contract.toml`,
`crates/shepherd-bench/traces/query-trace-v1.tsv`.
**Decides:** what `shepherd-index/src/meta.rs` is (Phase 1, task T7), and the
default ANN precision.

> Every number below is measured on this machine, on the fixture the committed
> contract specifies. Nothing here is projected. Where something could not be
> measured it says so instead of estimating.

---

## 1. The rule this decision was made under

§4.6, quoted verbatim, and committed to `bench-contract.toml` **before** the
first measurement (commit `ebe4fa4`, ahead of every result commit):

> Decision rule, written now so the spike cannot rationalize: pick the lowest-RAM
> candidate whose measured p95 is < 50 ms for the as-you-type profile at 10M rows
> on the reference machine. If two are within 20% of each other on latency, pick
> the lower RSS. If **none** passes, the plan escalates to the user (already
> recorded as OQ-E) with the option of redefining AC-40's as-you-type semantics
> as prefix/token matching and moving infix substring to the explicit-search
> path.

§9's gate adds three further scored axes: **persistence, crash-consistency with
the catalog, and cold-start rebuild cost**. Those are scored below and, per the
contract, they do not silently re-rank the §4.6 selection — if they had pointed
elsewhere, both results would be reported and the tension escalated rather than
the rule quietly amended.

They did not point elsewhere. See §5.

---

## 2. The machine, and why this is a new baseline

§9 specifies an 8-core x86-64, 32 GB, NVMe reference machine and says any
substitution "re-baselines rather than compares". This is a substitution.

| | declared (§9) | actual |
|---|---|---|
| cores | 8 | 32 vCPU, **pinned to 8 with `taskset -c 0-7`** |
| RAM | 32 GB | 68.6 GiB (cannot be constrained down) |
| storage | NVMe SSD | QEMU/KVM virtual block device, non-rotational, `none` scheduler |
| CPU | — | AMD EPYC 7302P |
| kernel | — | Linux 6.8.0-136-generic, KVM guest |
| rustc | — | 1.96.0 |
| SQLite | — | 3.53.2 (bundled) |
| usearch | — | 2.26.0, SIMD available: `serial, haswell` |

**Core pinning is a decision-integrity control, not housekeeping.** The arena
candidate is an embarrassingly parallel scan; unpinned on 32 cores it would run
several times faster than on the machine the plan specifies, which is enough to
pass the 50 ms bar here and fail it there — flipping the winner T7 builds on.

RAM and storage could not be constrained downward. Excess RAM flatters warm
mmap runs; the cold-cache cells (real `drop_caches`, per run) are what covers
that. **This run is therefore a new baseline. It is not comparable to a future
run on different hardware — that run re-baselines too.**

---

## 3. Metadata index — the decision

### 3.1 Step 1: filter on measured p95 < 50 ms

Accepted p95 = **median across 3 runs of each run's p95**, n = 1000 queries per
run, 4 concurrent query clients, under background ingest. Query mix per run is
exactly the contract's 40% prefix / 30% infix / 20% path-fragment (the semantic
10% belongs to the vector leg and is excluded — the as-you-type path never
invokes the ANN index).

| candidate | warm p95 | cold p95 | bar | verdict |
|---|---|---|---|---|
| **(a) in-RAM SIMD name arena** | **22.20 ms** | **23.48 ms** | 50 ms | **PASS** |
| (b) tantivy 0.26.1, positional trigram | 68.08 ms | 87.99 ms | 50 ms | FAIL (1.36×) |
| (c) SQLite FTS5-trigram | 378.59 ms | 587.53 ms | 50 ms | FAIL (7.6×) |

**Exactly one candidate passes.**

### 3.2 Steps 2 and 3 are not reached

- Step 2 ("if two are within 20% of each other on latency, pick the lower RSS")
  requires two survivors. There is one.
- Step 3 ("if none passes, escalate to the user") requires zero survivors.

### 3.3 Decision

> **The metadata index is the in-RAM name arena with a SIMD substring scan
> (candidate (a)).** Selected by the §4.6 rule as written, at step 1, with no
> tie to break and no judgement exercised.

It is also the user's own reference from interview Round 4 ("Everything").

### 3.4 Validation — all three candidates answered the same question

The pilot run caught tantivy returning **zero results for 2504 of 3000 queries**
while posting the second-best aggregate p95. An aggregate latency number cannot
distinguish "answered quickly" from "answered nothing quickly", so hit counts are
reported per class alongside latency. At 10M rows, after the fix:

| class | arena | fts5 | tantivy |
|---|---|---|---|
| prefix | 50.00 | 50.00 | 50.00 |
| infix | 48.68 | 48.72 | 48.68 |
| path_fragment | 38.30 | 38.32 | 38.30 |

Zero-hit rate is **0.0% for every candidate in every class**. The three agree on
what they find; the latency differences are real. (The ~0.04 hit delta on FTS5 is
background-ingest visibility — its writer landed more rows during the run, §3.6.)

### 3.5 R-3 confirmed, with a sharper diagnosis than the plan had

§4.6 carries FTS5 at "~1.75 s at 18.2M rows, ~35× over budget", marked `[V]` in
the sense of source-verified rather than fact-established. **Established here:
378.59 ms warm at 10M rows, 7.6× over the bar.** The plan's direction was right
and FTS5 is out.

The per-class split shows what the aggregate was hiding:

| class | fts5 warm p95 | fts5 cold p95 |
|---|---|---|
| prefix | **7.31 ms** | 6.84 ms |
| infix | 37.91 ms | 54.05 ms |
| **path_fragment** | **870.33 ms** | 1410.70 ms |

FTS5-trigram is comfortably inside the bar on **prefix**, marginal on infix, and
catastrophic on **path-fragment** — two orders of magnitude worse than its own
prefix number.

**This changes what an OQ-E renegotiation would cost.** §4.6's stated fallback is
"redefining AC-40's as-you-type semantics as prefix/token matching and moving
infix substring to the explicit-search path". On these numbers that fallback
would rescue FTS5 outright: its prefix class is 7 ms. That option is materially
more viable than the plan assumed. **Recorded, not taken** — the bar was met, so
no renegotiation is owed, and the choice would be the user's regardless.

Tantivy fails in the opposite shape: its **prefix** class is its worst
(126.86 ms warm), because a tantivy phrase query ranks all matches and cannot
exit early at 50 the way the other two do.

### 3.6 Caveats that are not buried

1. **The arena's writer starved under read load.** Background ingest landed
   **1,400 rows for the arena against 92,600 for FTS5** in comparable wall-clock.
   The `RwLock` write path is starved by continuous readers, so the arena's p95
   was measured under materially *less* concurrent write pressure than the other
   two carried. It does not change the outcome — the margin over tantivy is 3×
   and the ingest rate is only 2,000 rows/s — but **T7 must not implement the
   arena with a naive `RwLock`.** It needs epoch-based or double-buffered
   updates, or the writer will not land under sustained querying.
2. **Tantivy has no early exit.** It ranks all matches; arena and FTS5 stop at
   `result_limit = 50`. This is inherent to the engine, not an artefact of the
   harness, and it explains its prefix-class tail.
3. **Run-to-run drift exceeded the contract's 10% flag on two cells** — FTS5 warm
   51.3%, arena warm 13.3%. Flagged as the contract requires. The arena's margin
   is wide enough that 13% does not threaten the verdict; FTS5's does not matter
   at 7.6× over.
4. **No daemon exists at Phase 0b**, so "4 concurrent clients against a daemon"
   is 4 threads against a shared in-process index. IPC and serialisation cost are
   excluded and are added by Phase 5's re-run.

### 3.7 A correction §4.6 needs

§4.6 says infix substring "needs an n-gram tokenizer" and stops there. **That is
materially incomplete.** tantivy 0.26.1's `NgramTokenizer::advance()` hardcodes
`self.token.position = 0` (`src/tokenizer/ngram_tokenizer.rs`), so every n-gram
of a document is indexed at position zero. `PhraseQuery` requires strictly
increasing positions, so phrase-over-trigrams — the only construction expressing
*ordered* substring matching — silently matches nothing.

An implementer following §4.6 as written gets an index that returns zero results
on 100% of infix queries while posting an excellent p95. Tantivy was given a fair
test here only by writing a positional trigram tokenizer plus a start-of-name
sentinel for prefix anchoring. **If this choice is ever revisited, §4.6 must carry
that sentence or the next reader repeats the mistake.**

---

## 4. Cost of the winner, stated plainly

| | arena | tantivy | fts5 |
|---|---|---|---|
| build / populate | **3.7 s** | 116.1 s | 372.3 s |
| cold-start to queryable | **3.53 s** | 0.03 s | 0.00 s |
| index size | 0.75 GiB resident | 2.00 GiB on disk | 4.04 GiB on disk |
| peak VmHWM (contract's `index_rss`) | 0.76 GiB | 1.25 GiB | 0.46 GiB |
| post-query VmRSS | 0.02 GiB | 0.02 GiB | 0.16 GiB |

`index_rss` is defined in the contract as **peak VmHWM of a freshly-spawned bench
process**, fixed before the results existed. On-disk bytes and post-query VmRSS
are reported alongside so the choice can be checked rather than trusted — for an
mmap'd index no single one of the three is a falsifiable claim about memory.

---

## 5. The three durability axes

Scored as the contract pre-committed: cold-start rebuild **measured**, the other
two reported as **design scores** and explicitly not dressed up as benchmarks.

| axis | arena | tantivy | fts5 |
|---|---|---|---|
| cold-start rebuild (measured) | **3.53 s** at 10M | 0.03 s | 0.00 s |
| persistence model | **none** — derived from the catalog at every daemon start | independent on-disk index, own commit semantics | transactional with the catalog |
| crash-consistency with catalog | **cannot desynchronise** | **two stores; a crash between the SQLite commit and the tantivy commit leaves them disagreeing** | free |

Two results here are worth stating explicitly because they run against the
expectation that framed the axes:

**The rebuild is 3.5 seconds, not a minute.** The concern was that the arena "has
*no* persistence and must be rebuilt at every daemon start (and the daemon starts
at every logon)". True — and the measured price at full 10M scale is 3.53 s. That
is a real cost at every logon and a much smaller objection than it looked before
measurement.

**The arena has no crash-consistency problem precisely *because* it has no
persistence.** It is derived from the catalog every time, so there is no second
store that can disagree with the catalog. The candidate carrying the genuine
two-store desynchronisation risk is **tantivy** — and tantivy is already
eliminated on latency.

**So the durability axes and the §4.6 rule agree.** There is no tension to
escalate. FTS5's transactional-with-the-catalog property is a genuine advantage,
correctly identified as the thing the original scoring was missing, and it is not
enough: FTS5 misses the bar it had to clear by 7.6×.

---

## 5a. A confound that applies to every number in this document

**This machine was shared with four other agents building the same workspace
throughout the measurement window.** Load average during the metadata cells was
8–10 against 8 pinned cores, and `taskset -c 0-7` restricts *this* process to
cores 0–7 without excluding anyone else from them.

What that does and does not threaten:

- **The comparison is sound.** All three candidates were measured inside the same
  three-minute window under the same ambient conditions, so the ranking is not an
  artefact of one candidate getting a quieter box.
- **The absolute numbers carry ambient noise**, and the contract's run-to-run
  drift metric is what exposes it — FTS5 warm drifted 51.3% run to run, which is
  larger than any index effect and is mostly this.
- **One verdict sits close enough to the bar to deserve a re-check**: tantivy
  fails at 68.08 ms against a 50 ms bar, only 36% over, which is not obviously
  outside ambient noise. §5b records the confirmation run.

Reported rather than left implicit: a benchmark run on a contended box is a
weaker measurement than one run on a quiet box, and saying so is cheaper than
having a reader discover it.

## 5b. Confirmation re-run — tantivy's FAIL holds

§5a flagged one verdict as close enough to the bar to deserve re-checking:
tantivy fails at 68.08 ms against 50 ms, only 36% over, which is not obviously
outside the ambient noise of a shared machine. The arena's PASS (22.20 ms) and
FTS5's FAIL (378.59 ms) are far enough away that no plausible load reorders them.

Re-run end to end — catalog regenerated from the seed, tantivy index rebuilt,
both candidates re-benched — and emitted under separate keys so it could not
overwrite the contract run:

| candidate | contract run | confirmation | verdict |
|---|---|---|---|
| arena | 22.20 ms | **24.00 ms** | PASS both times |
| tantivy | 68.08 ms | **62.09 ms** | **FAIL both times** |

**It was not a quieter box — it was a busier one.** Load average was 15.0 during
the confirmation against roughly 10 during the contract run, recorded from
`/proc/loadavg` at both ends of the run. That makes the result stronger, not
weaker: under *heavier* contention tantivy came in **6 ms faster** and still
missed the bar by 24%. Whatever ambient noise is present is not what put tantivy
over.

Two incidental reproducibility checks fell out of it, and both are worth more
than they cost:

- the tantivy index rebuilt from the same seed in **113.9 s** against 116.1 s,
  and the arena rebuilt in 3.6 s against 3.53 s;
- separately, the 10M i8 vector index was built twice from the same seed and
  produced **4.96 GiB / 532 B per vector both times**, in 822 s against 825 s.

Two independent builds agreeing to within 0.4% on time and exactly on size is
the evidence that the counter-based generator delivers what §0 claims: the
fixture is reproducible, so a future re-run is comparing indexes rather than
comparing corpora.

## 6. What survives into Phase 1

**Survives (harness):** `generate.rs` in full, the contract loader, the machine
probe, `Percentiles`/`RunSet`, the RSS accounting, the cold-cache protocol, the
disk guards, and the `bench-baseline.json` writer. Phase 5's gate re-runs this
bench against the real `fixtures/corpus-10m`, and the numbers are only comparable
if the measuring apparatus is the same code.

**Does not survive (spike):** all three candidate implementations in
`meta_bench.rs`, and the `tantivy`, `rusqlite` and `memchr` entries in
`shepherd-bench/Cargo.toml` that exist only to serve them. T7 re-implements the
arena properly in `shepherd-index/src/meta.rs`; at that point the two losing
candidates and their dependencies leave this crate.

`memchr` is the exception worth naming: it is deleted from *this* crate, but the
real implementation needs it, so it moves to `shepherd-index` rather than
disappearing.

**Carried to T7 as a requirement, not a suggestion:** the writer-starvation
finding in §3.6.1. The bake-off measured a design whose write path does not work
under sustained read load.

---

## 7. Vector index — `usearch` precision

§4.6 selects `usearch` on evidence, so this leg is not a bake-off between
crates. It measures **precision** against the 300 ms bar and the AC-46 RAM
ceiling, and re-measures the plan's own RAM extrapolation, which R-4 flags
`[U — third-party, single source; Phase 0b re-measures]`.

### 7.0 The first vector run was void, and why

**Every ANN number from the first run was discarded before it was reported.**
The fixture generator added `noise * gauss()` per component; a 384-dimensional
vector of `N(0, 0.45)` components has length `0.45 * sqrt(384) ≈ 8.8`, so the
perturbation was **8.8× longer than the unit centroid it perturbed**. The
centroid contributed ~11% of direction and the corpus was, in effect, uniform
random on the sphere — the exact degenerate case `bench-contract.toml` says
clustering exists to avoid.

It surfaced as `recall@10 = 0.0070` for i8. What identified it as a fixture
fault rather than quantisation loss was **running the same check on f32**, which
stores vectors exactly and therefore cannot lose accuracy to quantisation. f32
scored 0.0500. When the control fails too, the fault is not in the thing under
test.

The contract stated the intent correctly and the code did not implement it, so
this was a bug fix; `cluster_noise = 0.45` kept its committed value and no
contract edit was made. Corroboration from an independent direction: the
corrected fixture builds **2.8× faster** (83 s/shard against 230 s) and queries
**3.6× faster**, because HNSW converges and traverses faster when the data has
neighbourhood structure to exploit.

### 7.1 Latency against the 300 ms bar

Accepted p95 = median-of-runs, 3 runs × 1000 semantic queries, 4 concurrent
clients, `expansion_search = top_k = 200`, per-run drop-and-reopen for cold.

| precision | scale | warm p95 | cold p95 | bar | verdict |
|---|---|---|---|---|---|
| **i8** | 10M `[M]` | **10.25 ms** | **14.21 ms** | 300 ms | **PASS** (21×) |
| **f16** | 10M `[M]` | **10.69 ms** | **42.48 ms** | 300 ms | **PASS** (7×) |
| f32 | 2M `[M, scaled]` | 2.75 ms | 23.70 ms | 300 ms | PASS — *not comparable*, see 7.3 |

Cold p95 exceeds warm for every precision and by the largest factor for f16
(4.0×), which is what a larger mmap'd index paying more first-touch page faults
should look like. **No cold cell is over budget**, so there is no cold-vs-warm
escalation.

**These exclude query embedding.** No model exists at Phase 0b, so §4.6's
15–25 ms embed budget is not in these figures; that note travels in the JSON,
not only here.

### 7.2 RAM — AC-46, and R-4 re-measured

| precision | measured | B/vector | 10M projection | plan's `[U]` estimate | AC-46 4–16 GB |
|---|---|---|---|---|---|
| **i8** | 4.96 GiB @ 10M `[M]` | 532 | **5.33 GB** | ~6.3 GB | **inside** |
| **f16** | 8.54 GiB @ 10M `[M]` | 916 | **9.17 GB** | ~10 GB | **inside** |
| f32 | 3.14 GiB @ 2M `[M]` | 1684 | **16.84 GB** `[X]` | ~17 GB | **at/over the ceiling** |

**R-4's extrapolation is confirmed and was conservative** — high by ~1% (f32),
~9% (f16), ~18% (i8). The table §4.6 flagged as single-source is now measured,
and it erred in the safe direction.

**§4.6's `view()` mmap claim is confirmed with a number.** "Resident RAM is then
only navigation structures plus a bounded hot-page budget; the OS page cache
does the rest" was an architectural assertion. Measured:

| precision | on disk | RSS after open | resident fraction |
|---|---|---|---|
| i8 | 4.96 GiB | **1.97 GiB** | 40% |
| f16 | 8.54 GiB | **1.95 GiB** | 23% |

Resident set stays flat at ~1.95 GiB while the index nearly doubles — which is
what "navigation structures plus a bounded hot-page budget" predicts, and it is
the property the whole AC-46 ceiling argument depends on.

### 7.3 f32 was measured at 2M, deliberately

The start guard refused f32 at 10M with the real output:

```
disk guard: 25.0 GiB free at fixtures, but this leg needs 15.6 GiB and the
reserve floor is 12.0 GiB (27.6 GiB required). Refusing to start.
```

**The reserve was not lowered to make it fit.** Adjusting a threshold until the
thing passes is the instinct this spike exists to resist, and the machine is
shared with three other agents.

Scaling f32 costs nothing the decision needs, because **f32's job here is to
confirm exclusion, not to be chosen**: R-4 put it above the AC-46 ceiling before
measurement, and the measurement agrees at 16.84 GB. What 2M gives exactly is
bytes-per-vector — verified dead linear across shards in both full runs — and
shard-0 recall, which every precision measures on the identical seed-derived 1M
shard. What it does **not** give is 10M-corpus latency for f32, which is neither
measured nor claimed.

### 7.4 Recall — and the number that needed a diagnosis

**The floor here is self-imposed.** §4.6's tiebreak rule governs latency and RSS
and does not mention recall; `ann_recall_at_10_floor = 0.90` is a sanity check
this spike added to catch a fast, small index that returns garbage. A breach is
a finding, never a failure of a candidate the plan did not authorise failing.

Measured on the identical 1M shard 0, 100 probes, against an exact brute-force
oracle over f32 vectors **regenerated from the seed** — never read back out of
the index under test, which would compare a quantised index against its own
quantised contents and report near-perfect recall for everything:

| ef | i8 recall | i8 ratio | f16 recall | f16 ratio | f32 recall | f32 ratio |
|---|---|---|---|---|---|---|
| 64 | 0.7160 | **1.4059** | 0.9080 | **1.4063** | 0.9300 | **1.3192** |
| **200** (bench's ef) | **0.7780** | **1.0445** | **0.9880** | **1.0444** | **1.0000** | **1.0000** |
| 512 | 0.7850 | 1.0036 | 0.9980 | 1.0000 | 1.0000 | 1.0000 |

**Two findings, and the first one corrects a methodological error of mine.**

**(a) Recall had been measured at a different `ef` than latency.** `recall-ann`
used `ef = 64` while `bench-ann` uses `ef = top_k = 200`, so an earlier
"i8 recall 0.729, ratio 1.3255" and "i8 p95 10.25 ms" described two different
search configurations and were about to be reported as one system. The ef=64 row
above shows why it mattered: **at ef=64 even f16 — near-lossless for unit
vectors — posts ratio 1.4063, worse than i8's.** The distance degradation was
beam width, not precision. Sweeping ef fixes it by construction: the headline row
is the one measured at the bench's own ef.

**(b) i8 substitutes ids among neighbours of equal quality.** At ef=200, i8 and
f16 return neighbours at mean cosine distance **0.155621 and 0.155609** — a
difference of 0.008% — yet their id-recall differs by 21 points (0.778 vs 0.988).
Their distance ratios are identical to four decimals. i8's quantisation
reshuffles *which* near-neighbours come back without meaningfully changing *how
close* they are. Raising ef does not fix i8's id-recall (0.778 → 0.785 from 200
to 512, saturated) but does drive its ratio to 1.0036, so the residual is a
quantisation ceiling on identity, not on quality.

**Read the ratio as a mean, and outlier-sensitive.** f32 reaches exactly 1.0000
at ef=200 while f16 and i8 sit at 1.0445 on 0.988 and 0.778 recall respectively —
consistent with roughly one probe in a hundred landing in a poor graph region
rather than a broad quality gap.

### 7.5 Decision, and the escalation

> **SUPERSEDED 2026-08-17 by the user's decision on the escalation below.**
> **f16 is the default. All three precisions are user-configurable.** The
> measurements in this document are unchanged and were what the decision was made
> on — only the default moves. See §7.5a.

*Original spike recommendation, kept because the escalation it raised is what
changed it:*

> **i8 is confirmed as the default**, on the plan's own criteria. It passes the
> 300 ms bar by 21× warm and 14× cold, and at **5.33 GB** it is the only
> precision comfortably inside AC-46's 4–16 GB band. **f16 is a viable fallback**
> at 9.17 GB, also inside the band. **f32 is excluded**, at 16.84 GB against a
> 16 GB ceiling — as R-4 predicted, now measured.

### 7.5a The decision as taken — f16 default, precision configurable

The escalation asked whether *identity* or *quality* is the criterion. The answer
taken is that **it does not have to be settled once for everyone**: f16 ships as
the default, and i8 and f32 are both selectable.

| precision | index @10M | + name arena (0.70 GB) | **total RSS** | AC-46 4–16 GB | warm p95 | cold p95 | recall @ ef=200 |
|---|---|---|---|---|---|---|---|
| i8 | 5.33 GB | 6.03 | **6.03 GB** | inside | 10.25 ms | 14.21 ms | 0.778 |
| **f16 — DEFAULT** | 9.17 GB | 9.87 | **9.87 GB** | inside | 10.69 ms | 42.48 ms | 0.988 |
| f32 | 16.84 GB | 17.54 | **17.54 GB** | **BREACHES** | *(2M only)* | *(2M only)* | 1.000 |

Two consequences the spike did not have to carry and Phase 5 does:

**1. f32 is offerable and does not fit at 10M — so the guard is mandatory.**
17.54 GB against a 16 GB ceiling. Offering the option is right (the ceiling is
*configured*, and a smaller corpus or a larger machine changes the sum), but
Phase 5 **must project RSS from the real corpus size and the selected precision
and refuse an over-budget combination, naming both numbers.** Accepting a setting
that cannot fit is how AC-46 becomes a value nothing enforces. The precedent is
this spike's own disk guard, which refused f32 at 10M with `25.0 GiB free, needs
15.6 + 12.0 reserve` — and was obeyed rather than lowered.

**2. The cold-p95 margin shrinks by 3× and is now the number to watch.** f16's
cold p95 is **42.48 ms against i8's 14.21 ms**. Both clear the 300 ms bar, but
§4.6's 15–25 ms query-embedding budget is excluded from both figures (see the
`embedding_cost_excluded_note` in `bench-baseline.json`), so f16 cold lands near
**67 ms all-in**. The margin drops from ~21× to ~4.5×. That is still comfortable
and it is no longer the kind of margin that absorbs a surprise, which matters
because embedding cost is the one component Phase 5 adds and Phase 0b could not
measure.

**Not affected:** every measurement above, the tiebreak that selected the arena,
and f32's exclusion *as a default*. f32 remains outside the ceiling at 10M; what
changed is that a user may choose it anyway, under a guard.

**Escalated, not decided here:** i8's id-recall at the benched configuration is
**0.778**, below the 0.90 sanity floor, while its retrieval *quality* is
indistinguishable from f16's. Whether that matters is a product judgement about
what "correct results" means, and it is not this spike's to settle:

- if relevance is the criterion — a user searching their own files wants good
  results, not identity with a brute-force oracle's id list — **i8 is fine**, and
  §4.6's RRF fusion consumes ranks rather than exact ids, which points this way;
- if exact-id agreement matters anywhere downstream, **f16 buys 21 points of
  recall for +3.84 GB**, still inside the ceiling, at +4.0× cold p95.

The lever exists and is cheap either way, which is what the sweep is for.

### 7.6 Disclosures

1. **No background ingest on this leg.** The contract's `[execution]` block reads
   as global and the writer was implemented for the metadata leg only. Defensible
   — §4.6's sealed shards are immutable by design and the hot-shard write path is
   Phase 5 — but it is a deviation from the contract as written, and stated here
   rather than left for a reviewer to notice.
2. **Query embedding is excluded** (§7.1).
3. **`ann_build_i8` was briefly overwritten** by the 1M shard-0 re-measurement,
   because both emitted under one key. The 10M figures survived in
   `ann_bench_i8_*` and the run log, and `emit` now suffixes any scaled record so
   a scaled run can never displace a contract-scale one again.
4. **Shared machine** — see §5a. Applies here too.
