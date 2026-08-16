# T2b — the 50 TB capacity model

**Status:** complete for the five components §9's Phase 0a/0b gate names.
**Date:** 2026-08-16
**Gate:** §9 Phase 0a/0b — "DB growth, checkpoint size, scrub request/egress
cost, restart time, and transfer duration each have a fail bound rather than
being *measured-or-extrapolated*."

> **Every figure is marked `[M] measured` or `[X] extrapolated`, and every `[X]`
> names what it was extrapolated from.** Two reviewers rejected an earlier plan
> revision for saying "measured-or-extrapolated" without distinguishing them, and
> for recording values where it needed fail bounds. A gate that records a number
> instead of failing on it is not a gate, so every component below carries a
> **numeric reject threshold** and a verdict against it.

---

## 0. The declared 50 TB object-size distribution

The model is worthless without this, because the two cost drivers pull in
opposite directions: **request counts scale with object *count*, egress scales
with object *bytes*,** and a distribution that gets the split wrong gets both
answers wrong. §5's headline result is entirely a consequence of this table.

Declared, and used unchanged throughout:

| bucket | share of count | files | mean size | bytes | share of bytes |
|---|---|---|---|---|---|
| tiny — documents, thumbnails, config | 70% | 7,000,000 | 120 KB | 0.84 TB | 1.7% |
| small — photos, PDFs | 20% | 2,000,000 | 1.5 MB | 3.00 TB | 6.0% |
| medium — raw photos, audio, archives | 8% | 800,000 | 20 MB | 16.00 TB | 32.0% |
| **large — video, disk images** | **2%** | **200,000** | **150.8 MB** | **30.16 TB** | **60.3%** |
| **total** | 100% | **10,000,000** | 5.0 MB mean | **50.00 TB** | 100% |

Heavy-tailed on purpose: 2% of the files hold 60% of the bytes. That is what a
real 50 TB personal corpus looks like, and §5 shows it is also the single fact
that determines whether scrub is affordable.

`[X]` — this distribution is **declared, not measured**. It is not derived from
the user's actual corpus. §6 records what changes if it is wrong.

---

## 1. DB growth

**Measured primitives**, `shepherd-bench capacity`, 10M rows, SQLite 3.53.2,
4096-byte pages:

| quantity | value | |
|---|---|---|
| catalog size at 10M rows | 854,011,904 B (0.80 GiB) | `[M]` |
| bytes per row, whole-file average | **85.4 B** | `[M]` |
| bytes per row, marginal over 200k further inserts | **85.6 B** | `[M]` |

The base and marginal figures agreeing to 0.2% is the useful part: **growth is
linear in row count**, so extrapolating by multiplication is legitimate here
rather than hopeful.

**Extrapolation to the production schema.** The measured number is for the bench
schema (`id, parent, name, ext, size, mtime`). §4.4's real schema stores more per
file, so the model builds it up per table rather than applying one hand-waved
multiplier:

| table | per-file bytes | basis |
|---|---|---|
| `file` (adds `norm_key`, `fs_id`, `blake3`, `atime_mode`, policy columns) | ~171 B | `[X]` 2× the measured 85.4 B |
| `remote_object` (key ~80 B, `blake3` 32 B, `etag`, `object_version`, 3 timestamps, `checksum_kind`, `scrub_result`) | ~230 B | `[X]` from §4.4 column list |
| `object_location` | ~50 B | `[X]` from §4.4 column list |
| index overhead | ×1.4 | `[X]` SQLite B-tree on the indices §4.4 names |
| **total** | **~630 B/file** | `[X]` |

**Projection: ~6.3 GB at 10M files / 50 TB.** `[X]`

| | |
|---|---|
| **Reject threshold** | **catalog > 20 GB at 10M files** |
| Projection | 6.3 GB |
| **Verdict** | **PASS**, 3.2× margin |

Threshold rationale: 20 GB is ~0.04% of the 50 TB it describes, and it must
coexist on the user's local disk with the index (0.75 GiB measured) inside a
laptop SSD. Set at ~3× the projection so it fails on a genuine model error rather
than on estimation noise.

---

## 2. Checkpoint size

**Measured**, same run:

| quantity | value | |
|---|---|---|
| WAL growth | **86.2 B per row** | `[M]` |
| WAL peak after 200,000 rows in one transaction | 16.4 MiB | `[M]` |
| WAL after `PRAGMA wal_checkpoint(TRUNCATE)` | 0 B | `[M]` |
| checkpoint wall time | **< 0.01 s** | `[M]` |

WAL bytes per row (86.2 B) tracking DB bytes per row (85.4 B) says the WAL is
carrying roughly one row's worth of page delta per row — i.e. inserts are landing
densely rather than dirtying a fresh page each, which is what makes the projection
below linear.

**Projection.** At the production row size the WAL accumulates ~630 B per file
`[X]`. An initial 10M-file scan with **no** intervening checkpoint would drive the
WAL to **~6.3 GB** `[X]`.

| | |
|---|---|
| **Reject threshold** | **WAL exceeds 1 GB at any point during the 10M-file initial scan** |
| Consequence | forces a checkpoint at least every ~1.6M files |
| **Verdict** | **PASS conditional on §4.4's dedicated PASSIVE-checkpoint connection actually running during the initial scan.** Unchecked, the projection breaches by 6.3×. |

Threshold rationale: a WAL beyond 1 GB means a crash replays more than a gigabyte
before the daemon is usable, and the eventual checkpoint stalls writers for its
duration. The measured TRUNCATE cost is negligible, so **there is no reason to let
the WAL grow — this is a scheduling requirement on Phase 1, not a cost.**

**This is the one component whose PASS depends on unwritten code**, and it is
flagged rather than assumed: Phase 1's gate must show WAL size bounded across the
10M-row scan, not merely that a checkpoint connection exists.

---

## 3. Scrub request and egress cost

The SLO is precommitted in PM-2: `max_full_verification_age` = **90 days for
sole-copy** locations, 365 for replicated. Sole-copy fraction *f* = **0.5**, the
plan's own worked example — so 5,000,000 objects holding 25 TB.

**The fact that decides this section.** A `HEAD` proves presence, never
integrity, so a full-hash verification needs a real read *unless* the provider
publishes a trusted content hash. §4.6/PM-2 lists those as Azure `Content-MD5`,
B2 `SHA1`, and **single-part S3/R2 `ETag` only**. Against the declared
distribution, the 2% large bucket is multipart at any sane threshold — and that
bucket is **60.3% of all bytes**. So:

> **The 2% of objects whose ETag cannot be trusted are exactly the 2% that hold
> most of the data.** Cheap HEAD verification covers 98% of objects and 40% of
> bytes; the expensive full-read path covers 2% of objects and 60% of bytes.

Per 90-day cycle, sole-copy half of the corpus: **5,000,000 HEADs** and
**100,000 full GETs totalling 15.08 TB** `[X]`.

Prices are `[X]` — external, current as of 2026-08 and sourced below.

| target | requests / 90d | egress / 90d | cost / 90d | **cost / month** |
|---|---|---|---|---|
| **AWS S3 Standard** | 5.1M × $0.0004/1k = $2.04 | 15.08 TB @ tiered $0.09→$0.085 = **$1,322** | $1,324 | **≈ $441** |
| **Cloudflare R2** | 5.1M Class B @ $0.36/M = $1.84 | **$0.00** (no egress charge, any volume) | $1.84 | **≈ $0.61** |
| **Backblaze B2** | Class B free | within free allowance (3× stored = 75 TB/mo vs 5 TB/mo needed) | $0.00 | **$0.00** |
| **SMB / NFS NAS** | n/a | no checksum at all ⇒ **100% full read**, 25 TB/90d = 278 GB/day ≈ **3.2 MB/s sustained** | no provider cost | **$0.00**, but constant LAN + disk load |

The NAS row reproduces the plan's own 3.2 MB/s figure, which is a useful check
that this model and §PM-2 are computing the same thing.

| | |
|---|---|
| **Reject threshold** | **projected scrub cost > $25/month** — the default ceiling `shepctl target cost --explain` enforces before scrub may be enabled |
| **Verdict** | **AWS S3 Standard FAILS by ~18×.** R2, B2 and NAS pass with enormous margin. |

**This is the capacity model's headline result and it is a design finding, not a
number.** PM-2 already says "the gate fails where the projection exceeds the
user's cost ceiling rather than silently widening the interval". Measured against
a real distribution, that gate **fires on the most common S3 configuration**. The
consequences, none of which are mine to choose:

1. sole-copy custody on S3 Standard at this scale cannot have a 90-day
   full-verification SLO at a hobbyist cost ceiling;
2. the cost is *not* spread across the corpus — it is concentrated in 2% of
   objects, so a policy that verifies large multipart objects on a longer cycle
   than small ones would cut it by orders of magnitude at a stated loss of
   assurance;
3. **enabling S3 multipart checksums (`ChecksumAlgorithm`, whole-object) at
   upload time would move the large bucket onto the cheap HEAD path entirely**,
   and is the change most worth investigating before accepting (1) or (2). It is
   a Phase 2 upload-path decision, not a scrub-path one.

---

## 4. Restart time

The daemon starts at every logon, so this is a cost the user pays constantly
rather than once.

| component | value | |
|---|---|---|
| index cold-start rebuild (arena, 10M rows, warm cache) | **3.53 s** | `[M]` `bench-meta arena --cache warm`, median of 3 |
| index cold-start rebuild (arena, 10M rows, **cold page cache**) | **4.04 s** | `[M]` `bench-meta arena --cache cold`, median of 3 |
| catalog open + WAL recovery, clean shutdown | < 0.01 s | `[M]` |
| job-queue recovery, checkpoint replay | not measured | `[X]` Phase 1 code does not exist; budgeted at ≤ 2 s |
| **projected start-to-queryable at 10M files** | **≈ 6 s** | `[X]` sum of the above |

| | |
|---|---|
| **Reject threshold** | **> 30 s start-to-queryable at 10M files** |
| Projection | ~6 s (of which 4.04 s is measured) |
| **Verdict** | **PASS**, 5× margin |

Threshold rationale: beyond ~30 s at every logon the user experiences the product
as broken at login, which is a product failure rather than a performance one.

This number is also the answer to the §4.6 durability objection against the
arena — "no persistence, rebuilt at every daemon start". True, and it costs
4.04 s cold.

---

## 5. Transfer duration

Initial upload of the full 50 TB. Uplink is the dominant term and is a property
of the user's connection, so the model is stated across a range rather than at
one assumed speed.

| sustained uplink | 50 TB transfer time | |
|---|---|---|
| 25 Mbit/s (typical ADSL/entry fibre upload) | **185 days** | `[X]` |
| 100 Mbit/s (typical symmetric residential fibre) | **46.3 days** | `[X]` |
| 300 Mbit/s | 15.4 days | `[X]` |
| 1 Gbit/s | 4.6 days | `[X]` |

Per-object overhead is second-order but not zero: 10,000,000 objects at even
50 ms of round-trip setup each is 5.8 days **serialised** `[X]`. At the plan's
adaptive concurrency (8 in flight) that falls to ~0.7 days and is absorbed into
the figures above.

| | |
|---|---|
| **Reject threshold** | **projected initial transfer > 60 days at the user's measured uplink** |
| **Verdict** | **PASS at ≥ 100 Mbit/s (46.3 days). FAILS at 25 Mbit/s (185 days).** |

**Second design finding, and it is the more uncomfortable one.** The product's
own headline scale target — 50 TB — is **not reachable within any reasonable
window on a common residential uplink**. At 25 Mbit/s the initial tier-out takes
half a year of continuous saturated upload, during which the machine cannot be
suspended without the plan's resume machinery carrying the whole burden (AC-2,
AC-44).

This is not a bug in the model and it is not something Phase 0b can engineer
around. It means either the 50 TB target implies a bandwidth floor that should be
stated as a supported-configuration requirement, or the first-run experience must
be designed for a multi-month initial sync as the normal case rather than the
degenerate one. **Escalating rather than choosing.**

---

## 6. What breaks this model

Stated because a capacity model whose sensitivities are unstated invites being
quoted past its evidence.

- **The object-size distribution (§0) is declared, not measured.** §3's entire
  result is driven by the 2% large bucket. If the real corpus is flatter — say
  no bucket above 8 MB — every object is single-part, every ETag is trusted,
  scrub becomes 5M HEADs, and the S3 cost collapses from $441/month to under
  $1/month. If it is *more* skewed, the cost rises proportionally with bytes.
  **This single table is worth measuring against the user's real corpus before
  anyone acts on §3.**
- **`f` = 0.5 is the plan's example, not a measurement.** Cost scales linearly
  in `f`.
- **Row-size extrapolation (§1, §2) is per-table arithmetic over §4.4's column
  list**, not a measurement of the production schema, which did not exist when
  this was written. `shepherd-catalog` now exists; re-measuring `bytes_per_row`
  against the real schema would convert §1 and §2 from `[X]` to `[M]` cheaply and
  should be done at the Phase 1 gate.
- **Provider prices are external and current as of 2026-08.** Egress pricing is
  the term most likely to move.
- **Nothing here measures a real provider.** §9 confines Phase 0 to local
  emulators; the real-provider leg is Phase 6.

---

## Sources

- [Amazon S3 pricing](https://aws.amazon.com/s3/pricing/) — GET $0.0004/1,000; egress tiers $0.09/GB then $0.085/GB
- [Cloudflare R2 pricing](https://developers.cloudflare.com/r2/pricing/) — no egress charge at any volume; Class B $0.36/million
- [Backblaze B2 pricing](https://www.backblaze.com/cloud-storage/pricing) and [transaction pricing](https://www.backblaze.com/cloud-storage/transaction-pricing) — free egress up to 3× average monthly stored data; Class B free
