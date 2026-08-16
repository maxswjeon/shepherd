# Phase 0b — the index decision

**Status:** metadata index **decided**. Vector leg (§7) **measurement in
progress** — this document is incomplete until that section carries numbers.
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
