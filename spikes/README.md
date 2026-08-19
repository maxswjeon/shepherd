# spikes/

Platform spikes for **Phase 0c**. §9's `G-0C-SPIKES` row asks for this directory to exist with the
spike work in it; until now the code lived only on the two probe machines and the findings only in
gitignored `.omc/artifacts/`, so the row read **"no evidence at all"** while the work had in fact
been done. That is the gap this directory closes.

| leg | question | verdict |
|---|---|---|
| [`windows-cfapi/`](windows-cfapi/FINDINGS.md) | can registration and hydration live in different processes? | **YES**, and no package identity is needed |
| [`macos-fileprovider/`](macos-fileprovider/FINDINGS.md) | what does a File Provider extension cost to register and hydrate? | registration needs **no Apple certificate**; hydration is blocked on `G-0D-PROCUREMENT` |

## ⚠ These do not run in CI, and that is not an oversight

The gate executes `cargo test -p <pkg> --exact <name>` **on Linux**. A Windows Cloud Files provider
needs the `cldflt.sys` kernel mini-filter; a macOS File Provider extension needs `pkd` and
`fileproviderd`. **Neither can execute on the machine that runs the gate**, and no amount of
arranging changes that.

So the evidence here is **platform-bound and deliberately not gate-executable**. The obvious
workaround — a Linux test asserting these files exist and parse — is refused on purpose: it would
pass honestly while saying nothing about whether either spike works, which is the defect class this
repository spends most of its effort removing. §9's own row text accepts a documented conditional
for this phase (*"a documented sparse failure plus full-MSIX success"*), and that is what this is.

**Re-running them means going to the hardware.** Each leg's `FINDINGS.md` says how.

## What each leg leaves open

**Windows** — reboot persistence untested; shell/Explorer integration untested and the likeliest
remaining home of a real package-identity requirement; Server 2022 rather than a Win11 client.

**macOS** — two things, and the second is uncomfortable:

1. **Hydration was never reached**, not attempted-and-failed. The domain is created `user-disabled`
   and no extension method was ever entered. Enabling it needs a console operator or a provisioned
   identity, and the notarized extension the row names needs Apple Developer Program membership.
   Both are `G-0D-PROCUREMENT`, which the user excluded from this pass.
2. **The registration result does not currently reproduce.** It was demonstrated in a `tart` VM
   that was then destroyed without preserving its bundle. The sources here are a reconstruction —
   original Swift, corrected build recipe, rebuilt `Info.plist` files — and on the host it is not
   discovered at all (`pkd` never mentions it; `-2014 ApplicationExtensionNotFound`). Build and
   signing ARE verified. Discovery is not. See that leg's findings for the full evidence and the
   control that rules out a broken `pluginkit`.

That second point is why this directory exists in the form it does. A result reproducible only from
a destroyed VM is a report, not a spike, and recording the gap is worth more than a directory that
looks complete.

## Provenance

Both legs were run 2026-08-17/18 against real hardware. The macOS reconstruction and its host
verification are 2026-08-19.

**The two `FINDINGS.md` files here are the evidence of record.** Longer working notes exist at
`.omc/artifacts/phase-0c/` on the machine this was done on, but **that directory is gitignored and
is not part of this repository** — a fresh clone will not have it, so nothing here depends on it.
Anything from those notes that matters has been restated in full above rather than cited across
that boundary. Pointing at an untracked file as though it were evidence is the same class of
mistake as a row citing a test that does not run.

For anyone who does have those notes: two of them are stamped `⚠ RETRACTED` and their central
finding — that ad-hoc signing silently discards entitlements — is false. Read
`macos-VERDICT-CORRECTED.md` and disregard `macos-signing-answer.md` and `macos-vm-verdict.md`.

**No Apple Developer Program membership, no provisioning profile, no notarization, and no
organisational signing identity was used anywhere in this work.** Ad-hoc throughout, deliberately.
