# T2b — the 50 TB capacity model

**Status:** complete for the five components §9's Phase 0a/0b gate names.
**Date:** 2026-08-16, revised 2026-08-17 — §3's scrub-cost verdict is now
conditional on one upload-time setting, measured against real AWS S3 (§3a), and
the earlier `MinIO — none returned` row is **retracted** as a defect in our own
client rather than a provider limitation (§3a, §3c).
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

> **§3a now measures the premise of that sentence and finds it false on S3.**
> Real S3 *does* publish a whole-object checksum for multipart objects, so the
> 100,000 full GETs become HEADs and the egress term goes to zero. The row below
> is retained unchanged because it remains the correct price for a corpus
> uploaded **without** whole-object checksums requested — which is still the
> default (`multipart_checksum: None`) and cannot be retrofitted without
> re-uploading. Read the two S3 rows as the two configurations, not as an old
> number and a new one.

Prices are `[X]` — external, current as of 2026-08 and sourced below.

| target | requests / 90d | egress / 90d | cost / 90d | **cost / month** |
|---|---|---|---|---|
| **AWS S3 Standard**, no whole-object checksum | 5.1M × $0.0004/1k = $2.04 | 15.08 TB @ tiered $0.09→$0.085 = **$1,322** | $1,324 | **≈ $441** |
| **AWS S3 Standard**, whole-object checksum requested at upload `[M]` | 5.1M × $0.0004/1k = $2.04 | **$0.00** — every object verifies by HEAD | $2.04 | **≈ $0.68** |
| **Cloudflare R2** | 5.1M Class B @ $0.36/M = $1.84 | **$0.00** (no egress charge, any volume) | $1.84 | **≈ $0.61** |
| **Backblaze B2** | Class B free | within free allowance (3× stored = 75 TB/mo vs 5 TB/mo needed) | $0.00 | **$0.00** |
| **SMB / NFS NAS** | n/a | no checksum at all ⇒ **100% full read**, 25 TB/90d = 278 GB/day ≈ **3.2 MB/s sustained** | no provider cost | **$0.00**, but constant LAN + disk load |

The NAS row reproduces the plan's own 3.2 MB/s figure, which is a useful check
that this model and §PM-2 are computing the same thing.

| | |
|---|---|
| **Reject threshold** | **projected scrub cost > $25/month** — the default ceiling `shepctl target cost --explain` enforces before scrub may be enabled |
| **Verdict** | **Determined by one upload-time setting, now measured rather than assumed.** S3 Standard **FAILS by ~18× ($441/mo)** for a corpus uploaded without whole-object checksums, and **PASSES with 37× margin ($0.68/mo)** for one uploaded with them `[M]`. R2, B2 and NAS pass with enormous margin either way. |

**This is the capacity model's headline result and it is a design finding, not a
number.** PM-2 already says "the gate fails where the projection exceeds the
user's cost ceiling rather than silently widening the interval". Measured against
a real distribution, that gate **fires on the most common S3 configuration** —
because the *default* configuration is still the expensive one. What §3a changes
is that the cheap configuration is now known to exist on S3 rather than hoped
for, which moves this from an unavoidable cost to **a registration-time decision
that is irreversible per object**. The consequences, none of which are mine to
choose — (1) and (2) now apply only to the **default** configuration, and (3) is
what changes that:

1. sole-copy custody on S3 Standard at this scale cannot have a 90-day
   full-verification SLO at a hobbyist cost ceiling;
2. the cost is *not* spread across the corpus — it is concentrated in 2% of
   objects, so a policy that verifies large multipart objects on a longer cycle
   than small ones would cut it by orders of magnitude at a stated loss of
   assurance;
3. **enabling S3 multipart checksums (whole-object) at upload time moves the
   large bucket onto the cheap HEAD path entirely.** This was written as the
   change "most worth investigating before accepting (1) or (2)"; §3a has now
   investigated it against real S3 and it works `[M]`, which retires (1) and (2)
   for any corpus uploaded with it. It remains a Phase 2 upload-path decision,
   not a scrub-path one, and that is now the whole difficulty: it must be taken
   **before the first object is uploaded**.

### 3a. Response 3 is built, and now measured against real S3

**Settled on 2026-08-17 against a real AWS account** (`025383730468`,
`ap-northeast-2`, a throwaway bucket created and destroyed for the run). The
previous revision of this subsection recorded the question as a Phase 6
prerequisite and predicted that pointing the probe at a real endpoint would
settle it in one run. It did — and it also overturned the emulator result that
motivated the caution.

`ChecksumType::FULL_OBJECT` on `CreateMultipartUpload` is **implemented**
(`8766be2`, worker-4). Only CRC32 / CRC32C / CRC64NVME support `FULL_OBJECT`;
the SHA algorithms are composite-only for multipart, which is the same
digest-of-digests problem that makes the ETag untrustworthy to begin with — so
the choice of algorithm is not free.

**What the server actually returned.** A 10,485,837-byte object uploaded as a
genuine 3-part multipart with `x-amz-checksum-type: FULL_OBJECT` and CRC64NVME,
then HEADed twice:

```text
HEAD, x-amz-checksum-mode unset:
    etag: "7ef4e974a603f6db7b86925a6bafbb2e-3"

HEAD, x-amz-checksum-mode: ENABLED:
    etag: "7ef4e974a603f6db7b86925a6bafbb2e-3"
    x-amz-checksum-crc64nvme: CnmyweQWB7U=
    x-amz-checksum-type: FULL_OBJECT

GetObjectAttributes:
    Checksum: {ChecksumCRC64NVME: CnmyweQWB7U=, ChecksumType: FULL_OBJECT}
    ObjectParts: {TotalPartsCount: 3}
```

| provider | whole-object checksum on HEAD | |
|---|---|---|
| **AWS S3** | **CRC64NVME, `ChecksumType: FULL_OBJECT` — multipart objects verify by HEAD** | `[M]` |
| **MinIO** | **CRC64NVME, `FULL_OBJECT`; byte-identical value to S3's for the same content** | `[M]` |
| Cloudflare R2 | unknown — **no credentials; not guessed** | — |
| Backblaze B2 | unknown — **no credentials; not guessed** | — |

**The earlier `MinIO — none returned` row was an instrument defect, not a
provider difference.** S3 omits every `x-amz-checksum-*` response field unless
the request carries `x-amz-checksum-mode: ENABLED`, and `S3Adapter::head` never
sent it. Both servers had been storing the checksum correctly all along; the
read path could not see it. Re-measured after the one-line fix, MinIO and S3
agree exactly — **there was never any emulator-versus-real-service divergence to
be cautious about.** The caution was still correct: it prevented the model from
being revised in the *wrong* direction on bad evidence.

**Side by side, raw wire headers, same test binary, same 10,485,837-byte
content** — MinIO on the four-drive erasure set with NAS-backed storage, so the
emulator is a realistic deployment rather than a straw man:

| | AWS S3 `ap-northeast-2` | MinIO `RELEASE.2025-04-22` |
|---|---|---|
| `etag` | `"7ef4e974…bafbb2e-3"` | `"7ef4e974…bafbb2e-3"` |
| HEAD, mode unset | etag only | etag only |
| HEAD, `mode: ENABLED` | `x-amz-checksum-crc64nvme: CnmyweQWB7U=`<br>`x-amz-checksum-type: FULL_OBJECT` | `x-amz-checksum-crc64nvme: CnmyweQWB7U=`<br>`x-amz-checksum-type: FULL_OBJECT` |

**Identical, down to the checksum value and the ETag.** The claim this document
made — *"MinIO's behaviour does not predict S3's"* — is **not supported on the
path Shepherd uses**, and the evidence for it was our own missing header.

**There is one real divergence, and it is not on that path.** On
`GetObjectAttributes` — which Shepherd does *not* call — the two disagree:

```text
AWS S3 : Checksum: {ChecksumCRC64NVME: CnmyweQWB7U=, ChecksumType: FULL_OBJECT}
MinIO  : Checksum: {ChecksumCRC64NVME: CnmyweQWB7U=}          <- no ChecksumType
```

Harmless today, and worth writing down precisely because it is a **loaded trap
for the obvious future optimisation**: `GetObjectAttributes` also returns the
per-part checksum list, so a scrub implementation would be tempted to prefer it
over HEAD. Against MinIO it reports no `ChecksumType`, `whole_object` would
derive as `false`, the checksum would be dropped, and multipart objects would go
back to full reads — **reproducing this exact section's retracted finding
through a different API.** If scrub ever moves off `HeadObject`, that derivation
has to be re-measured, not carried over.

That defect is worth naming precisely, because it is the third instance of this
spike's recurring shape and the only one that fails toward *expense* rather than
toward false assurance: a missing request header made a working provider feature
look absent, and the conclusion it invited — "this provider does not support
whole-object checksums" — would have been recorded as a measured fact and priced
at $441/month forever. **A false negative about a capability is as expensive as
a false positive about integrity, and much harder to notice, because nothing
ever fails.**

Therefore: **§3's verdict is now conditional rather than a flat FAIL.** With
whole-object checksums requested at upload, the 100,000 full GETs collapse into
HEADs, egress goes to zero, and the figure falls from **$441/month to
$0.68/month — a factor of 649**, close to the three orders of magnitude the
previous revision predicted. Two things keep this from being a free win:

1. **`multipart_checksum` still defaults to `None`** (`s3.rs`), deliberately, so
   that a provider which rejects the parameter does not fail every multipart
   upload. The cheap path is therefore **opt-in and not what a target gets by
   default.**
2. **It cannot be retrofitted.** A corpus already uploaded without it keeps the
   $441/month price until every multipart object is re-uploaded. This is a
   decision that must be taken at target registration, before the first upload —
   which is what `s3.rs`'s own doc comment already demands, and is now backed by
   a measured 649× rather than by an argument.

**This does not become a cheap path to gating destruction.** A provider-computed
CRC detects bit rot; it is worthless against a provider that is wrong about its
own bytes, and it is not BLAKE3. It addresses scrub *cost* only. §4.10's
attestation requirements are untouched by it, and the assurance framing above is
unchanged.

### 3b. The composite-ETag trap is closed, and that was checked rather than assumed

Trusting a digest-of-digests as if it were a content hash would be a
**correctness** defect in scrub, not merely a cost one, so the dangerous
direction was measured too. A deliberately COMPOSITE multipart object on the same
real bucket returns:

```text
x-amz-checksum-crc32: 72M33w==-2      <- note the "-2": a digest-of-digests
x-amz-checksum-type:  COMPOSITE
```

That value can never equal a CRC32 of the bytes. Two independent guards stop it
from being treated as though it could:

- `s3.rs` sets `ObjectChecksum::whole_object` from
  `checksum_type() == FULL_OBJECT`, so the COMPOSITE value above is carried as
  `whole_object: false`;
- `verify.rs` applies `.filter(|c| c.whole_object)` before it reaches
  `VerifiedLocation`, so only a genuinely whole-object value is ever persisted
  for scrub to compare against.

**The failure direction is safe.** A provider that returns a checksum with no
`ChecksumType` at all also lands on `whole_object: false` and is dropped, which
costs a full read that was not strictly necessary but never mistakes a composite
digest for a content hash. Single-part objects were checked separately and do
report `ChecksumType: FULL_OBJECT` `[M]`, so the common case is not
false-negatived.

No scrub code exists yet — nothing writes `remote_object.checksum_kind` — so
this records that the trap is closed **before** the consumer that could fall into
it is written, rather than after.

**Filling in R2 and B2 needs no code change.** The probe reads
`SHEPHERD_S3_BUCKET` / `SHEPHERD_S3_ENDPOINT` / `SHEPHERD_S3_REGION`, so any
S3-compatible endpoint settles its own row in one run. They are left `unknown`
above because guessing them is exactly what produced the `[M]` that had to be
retracted.

### 3c. Two defects, one shape — and the second one was predicted here

**The near-miss recorded at upload.** The checksum was being requested at upload
and then **dropped at verify** — the `VerifiedLocation` did not carry it through
to `remote_object.checksum_kind` (fixed in `9f241ef`). Had it shipped, every step
would have succeeded: the upload works, the provider computes the checksum,
`verify_upload` returns `Ok`. Nothing would have failed anywhere. The only value
scrub compares against on every later pass would simply have been discarded, and
**the entire upload-time decision priced above would have bought nothing.**

That is a defect whose symptom is a **cost** — it shows up in a bill, not in a
log line. Worse than the money, as the previous revision put it:

> scrub would have gone on reading multipart objects in full forever, and
> someone would eventually have concluded that whole-object checksums "don't
> work on this provider" and retired a working mechanism on false evidence.

**That sentence was written as a hypothetical, and it had already happened.** The
missing `x-amz-checksum-mode` header (§3a) produced exactly that outcome one
paragraph away: a working mechanism, a green upload path, and a table in this
document recording `MinIO — none returned` as a **measured** fact. The prediction
and the instance are separated by about thirty lines of the same file, which is
the strongest argument available for why this class gets checked by measurement
and not by reading.

Both defects share the shape every other one in this spike has: **every
observable signal was green and the work behind it was absent.** `9f241ef` was
caught by reading the code; the checksum-mode defect survived a code review that
caught the first one and was caught only by pointing the probe at a real server
and comparing two HEADs.

**The end-to-end chain, with each link marked by how it is actually known** —
because "confirmed end to end" is the kind of summary this section exists to
distrust:

| link | status |
|---|---|
| upload requests `FULL_OBJECT` and S3 stores it | `[M]` measured on real S3 |
| HEAD returns it and the adapter surfaces it as `whole_object: true` | `[M]` measured on real S3 |
| `verify_upload` carries it into `VerifiedLocation` | **inspected, not measured** — `verify.rs`'s two-line filter was read, not exercised against S3 |

The third link is the one `9f241ef` already broke once. Its only unit test pins
the `None` case, so **no test would fail today if it were re-broken for a
provider that does return a checksum.** Closing that needs either a fake that can
return one, or `verify_upload` in the live probe; it is cheap and it is not done
here.

**This does not become a cheap path to gating destruction.** A provider-computed
CRC detects bit rot; it is worthless against a provider that is wrong about its
own bytes, and it is not BLAKE3. It addresses scrub *cost* only. §4.10's
attestation requirements are untouched by it, and the assurance framing above is
unchanged.

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
  the term most likely to move. Note that the measured S3 configuration in §3a
  has **no egress term at all**, so it is insensitive to exactly the price most
  likely to change — the $441/month row remains fully exposed to it.
- **One real provider is now measured; the rest are not.** §9 confines Phase 0
  to local emulators, and the real-provider leg is Phase 6 — but the §3a probe
  has been run against a real AWS S3 bucket, so that one row is `[M]` on the
  service itself rather than on an emulator. **Cloudflare R2 and Backblaze B2
  remain `unknown` and must not be assumed to follow S3**, which is precisely
  the mistake the retracted MinIO row embodied, in the opposite direction.
  Either can be settled without a code change by pointing the probe at it.
- **A capability measured through our own client is only as good as the
  client.** §3a's first result was a false negative caused by a header
  `S3Adapter::head` failed to send, and it was recorded as `[M]` for a day. Any
  future `[M]` of the form "provider X does not support Y" should be read as
  "our client did not observe Y", and confirmed against a second instrument
  before it is priced. §3a's raw-header capture exists for that reason.

---

## Sources

- [Amazon S3 pricing](https://aws.amazon.com/s3/pricing/) — GET $0.0004/1,000; egress tiers $0.09/GB then $0.085/GB
- [Cloudflare R2 pricing](https://developers.cloudflare.com/r2/pricing/) — no egress charge at any volume; Class B $0.36/million
- [Backblaze B2 pricing](https://www.backblaze.com/cloud-storage/pricing) and [transaction pricing](https://www.backblaze.com/cloud-storage/transaction-pricing) — free egress up to 3× average monthly stored data; Class B free
