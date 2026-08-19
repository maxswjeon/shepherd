# Shepherd

Local-first file tiering. Scan a root, evaluate rules, upload to a storage
target, **re-read the remote copy and hash-match it**, and only then dehydrate
(Windows/macOS) or delete (all platforms). Files come back on open.

[![CI](https://github.com/maxswjeon/shepherd/actions/workflows/ci.yml/badge.svg)](https://github.com/maxswjeon/shepherd/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/rust-1.96.0-orange)
![Platforms](https://img.shields.io/badge/platforms-linux%20%7C%20macos%20%7C%20windows-blue)

---

> ### ⚠ Status: Phase 1 of 9. Not usable yet.
>
> This is a repository under construction, not a product. The daemon serves 10 of
> its 17 protocol methods; **tiering, rules, restore and the placeholder
> providers are Phase 2 and later.** Nothing here will move your files, because
> nothing here can yet.
>
> What *is* done is the part most projects leave until last: the catalog, the
> scan pipeline at 10M files, the identity layer, the storage adapter with
> verified multipart round-trips, and the machinery that refuses to call any of
> it finished without evidence.
>
> `cargo xtask gate --phase 1` passes with 13 acceptance criteria asserted by 80
> tests that actually ran. `--phase 2` does not, and says exactly which three
> criteria are unmet and why.

## Why it is built this way

Shepherd deletes your files. That is the whole product: it is not a backup tool
that leaves the original alone, it is a tiering tool that removes the local copy
once a remote one is verified. A bug in the wrong place does not cost a feature,
it costs data.

So the interesting engineering here is not the file mover. It is the set of
constraints that make the file mover hard to get wrong, and the gates that
refuse to report progress that has not happened.

**Destruction lives behind a dependency edge.** Every destructive syscall —
`unlink`, `CfDehydratePlaceholder`, File Provider eviction — is inside a
`PlaceholderProvider` implementation, and `cargo xtask check-deps` fails the
build if any crate except `shepherd-tier` depends on that crate. Cargo cannot
forbid a syscall; it can forbid an edge, and one edge is checkable in a way that
a hundred call sites are not.

**A floor that cannot answer refuses.** Open-handle detection is implemented on
Linux. On macOS and Windows it returns `CouldNotDetermine`, and the acquisition
floor treats that as *held open* — so destruction is refused on the platforms
where it cannot be proven safe, rather than proceeding on a check that did not
run.

**Gates assert counts, never exit codes.** `cargo test --exact
a_test_that_does_not_exist` exits `0` having run nothing. Every gate here parses
`N passed` and requires `N >= 1`, because a CI step that runs zero tests and
reports green is the failure mode this project has actually hit.

**Absent evidence fails; it never skips.** A MinIO leg that cannot run because
an endpoint is unset is not a pass. Skipping is how "not run" becomes "passed".

**Stated gaps stay red.** A criterion can have passing evidence and still be
held red by a written gap, so the gate can say *here is what is proven, and here
is what is still missing* rather than choosing between a bare failure and a
green it has not earned.

## Try it

Nothing to try yet. You can run what exists:

```sh
git clone https://github.com/maxswjeon/shepherd
cd shepherd

cargo build --workspace
cargo test  --workspace                                  # 767 tests
cargo clippy --workspace --all-targets -- -D warnings
```

The gates are the interesting part:

```sh
cargo xtask check-deps       # §4.1 dependency rules — fails the build on violation
cargo xtask gate --audit     # §9 rule 6 — AC ownership vs. the phase that builds the machinery
cargo xtask gate --phase 1   # runs every AC the phase owns and reconciles §9's row for it
cargo xtask gate --phase 2   # fails, and names the three criteria that are unmet
cargo xtask codegen --check  # §4.3 — IPC artifacts in step with the method table
```

`gate --phase 1` runs a 1M-file scan and is a **scheduled command**, not a quick
check. It needs `SHEPHERD_M1_CORPUS` pointing at a generated corpus:

```sh
cargo run --release -p shepherd-bench -- gen-files \
  --dest /var/tmp/shepherd-m1/corpus-1m --files 1000000
SHEPHERD_M1_CORPUS=/var/tmp/shepherd-m1/corpus-1m cargo xtask gate --phase 1
```

## The dependency rules

`cargo xtask check-deps` is the load-bearing gate in this repository:

| # | Rule |
|---|---|
| 0 | Every crate under `crates/` is a workspace member (otherwise it is invisible to the rest) |
| 1 | `shepherd-core` and `shepherd-proto` depend on nothing internal |
| 2 | **No crate except `shepherd-tier` may depend on `shepherd-placeholder`** |
| 3 | `shepherd-plugin` depends only on an explicit allowlist — never on `shepherd-tier`, `shepherd-placeholder`, or a filesystem-mutating crate |
| 4 | `shepherd-tier/src/destroy.rs` is the sole caller of any destructive `PlaceholderProvider` method and of `StorageAdapter::delete_object` |
| 5 | Only `shepherd-storage` may depend on `opendal`, and only for `_shepherd/` control objects |

Rule 2 is the one that matters, for the reason above. `delete_system_object` is
deliberately outside rule 4: it is scoped by construction to the `_shepherd/`
prefix, is callable by replica maintenance, and is never counted by the discard
breaker.

The policy is data, in [`xtask/deps-policy.toml`](xtask/deps-policy.toml), so
every widening of it is a one-line diff in a file whose only reason to exist is
safety enforcement.

Rule 4 matches *calls*, not mentions — it blanks string literals and comments
before scanning, because a message explaining that a test does **not** call
`delete_object` is not a call, and a check that fires on prose describing the
thing is matching the name rather than the use.

## Platforms

| | build | tests | placeholders | notes |
|---|---|---|---|---|
| **Linux** | ✅ | ✅ | delete-mode only | primary development and CI target |
| **macOS** | ✅ | ✅ | File Provider (Phase 3) | registration verified ad-hoc; hydration not yet |
| **Windows** | ✅ | ✅ | Cloud Files (Phase 3) | IPC transport is Phase 3 — `run` refuses and says so |

The whole workspace builds and tests on all three from Phase 0a, so a
platform-specific break is found on the commit that caused it. Where a capability
genuinely does not exist on a platform, the code **refuses with a reason** rather
than being absent — a binary that compiles and silently does nothing is the same
shape as a check that passes without its subject.

Two limits are worth knowing because they are contract-level rather than
temporary. `mtime` is preserved to the resolution the target filesystem can
represent — 1 ns on POSIX, 100 ns on NTFS — and POSIX `mode` is not preserved on
Windows at all, which has ACLs and a read-only flag and no mode bits. Both are
stated in `shepherd-tier::fidelity` rather than discovered at restore time.

## Layout

```
crates/               21 crates
  shepherd-core         shared types, no internal deps
  shepherd-proto        the wire protocol and method registry
  shepherd-catalog      SQLite (WAL) catalog: schema, identity, atime, writer actor
  shepherd-scan         the walker and the acquisition floors
  shepherd-index        metadata and ANN indexes
  shepherd-storage      S3 and the multipart/checksum path
  shepherd-tier         the only crate that may destroy anything
  shepherd-placeholder  every destructive syscall lives here
  shepherd-daemon       the served surface
  shepherd-cli          shepctl
  ...
xtask/                the gates: check-deps, gate --audit, gate --phase, codegen
spikes/               platform spikes with their findings (Windows CfAPI, macOS File Provider)
docs/adr/             architecture decisions, including the 50 TB capacity model
```

## Contributing

The repository is early and the plan is dense; the most useful contribution
right now is reading a gate row and disagreeing with it. Rows carry their own
reasoning, including what they deliberately do **not** claim.

Two conventions matter more than style here:

- **Evidence over assertion.** A change that closes a gap should cite a test
  that fails when the change is reverted. Several tests in this repository carry
  the mutation that was used to prove they were load-bearing.
- **A stated gap is a valid outcome.** `evidence_missing` in
  [`xtask/ac-map.toml`](xtask/ac-map.toml) keeps a criterion red with a written
  reason. Recording what is missing is better than a green that has not been
  earned, and it is not a failure to report one.

## License

Not yet chosen. Until a `LICENSE` file lands, no permission to use, modify or
distribute this code is granted — this is stated explicitly rather than left
ambiguous.
