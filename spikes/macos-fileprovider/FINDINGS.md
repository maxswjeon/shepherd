# macOS File Provider spike — Phase 0c / OQ-D

**Question §9 asks:** can Shepherd run a File Provider extension on macOS, and what does it cost
to get one registered and hydrating?

**Answer, in one line:** registration needs no Apple certificate of any kind; hydration needs a
domain to be *enabled*, which needs either a console operator or a provisioned identity, and is
therefore blocked on `G-0D-PROCUREMENT`.

---

## What is verified here, and by what

| claim | status | how |
|---|---|---|
| appex must be Mach-O `MH_EXECUTE` with `_NSExtensionMain` entry | **verified** | `build.sh` asserts it and aborts on `MH_BUNDLE`; run on macOS 26.5.2 → `Mach-O 64-bit executable arm64` |
| ad-hoc signing embeds entitlements | **verified** | `codesign -d --entitlements` → `app-sandbox entries: 1`, `Signature=adhoc`, no Apple cert present |
| extension must carry `com.apple.security.app-sandbox` | recorded, not re-verified | `pkd`: *"Ignoring mis-configured plugin: plug-ins must be sandboxed"* (2026-08-18, VM) |
| a domain registers under ad-hoc | **recorded in a VM, NOT reproduced on the host** | see the reproducibility gap below |
| hydration | **never reached** | domain is created `user-disabled`; no extension method was ever entered |

## ⚠ The reproducibility gap — read this before trusting the registration claim

The 2026-08-18 probe registered a domain ad-hoc in a **fresh `tart` VM** (guest macOS 26.6.1).
That VM was destroyed and **its bundle was not preserved**. The sources here are a reconstruction:
the Swift is the original, recovered from the probe script; the build line and the entitlement are
the corrected recipe from the artifacts; **the `Info.plist` files are rebuilt from the recipe's
description, not from the originals.**

Run against the **host** (macOS 26.5.2) on 2026-08-19, this reconstruction:

```
bundle installed at /Applications/ShepherdSpike.app     Mach-O 64-bit executable arm64
codesign -d --entitlements                              app-sandbox entries: 1, Signature=adhoc
pluginkit -mAvvv | grep shepherd.spike                  (nothing)
pluginkit -a <appex>                                    (no output)
lsregister -f + 6s, pluginkit -m -p com.apple...        still absent
log show --predicate 'process == "pkd"' | grep shepherd (never mentions it)
NSFileProviderManager.add                               REFUSED -2001, underlying -2014
```

`-2014` is `NSFileProviderErrorApplicationExtensionNotFound`: the extension was never discovered.
**pkd does not reject it — pkd never sees it.**

A control ran in the same session and passed: `pluginkit -m -p com.apple.fileprovider-nonui` lists
`PhotosFileProvider`, `iCloudDriveFileProvider` and `iCloudDriveFileProviderManaged`, so
`pluginkit` and the extension point are working on that host.

**So the honest state is: build and signing are verified; discovery is not.** Whether the
difference is host-versus-VM, or a detail of the original `Info.plist` that the artifact's prose
did not capture, is **undetermined** — and it cannot be settled by re-reading the artifact,
because the artifact is the thing that turned out to be insufficient. Settling it needs a fresh
VM from `ghcr.io/cirruslabs/macos-tahoe-base` and a bisect against this bundle.

This gap is recorded rather than smoothed over because the whole point of `spikes/` is that
someone can re-run the thing. A spike whose result is reproducible only from a destroyed VM is a
report, not a spike.

## Entitlements

`Provider.entitlements` carries exactly one, and two are deliberately absent.

**Present — `com.apple.security.app-sandbox`.** Unrestricted, so an ad-hoc signature can
self-grant it. Without it `pkd` refuses the plug-in outright.

**Absent — `com.apple.security.application-groups`.** It embeds cleanly and verifies under
`codesign -d --entitlements`, and it is refused at runtime:

```
containermanagerd: [kr.swjeon.shepherd.vm.provider] requesting [group.kr.swjeon.shepherd.vm]:
REJECTED. Requestor's signature does not allow it to access a TCC-protected group container.
Group containers identifiers should be prefixed by requestor's team ID to allow access on this
platform.
```

Ad-hoc has `TeamIdentifier=not set`, so a team-prefixed group is impossible. **Consequence for
Shepherd's design: any component that puts state in an App Group container cannot be validated
without a real team identity.** Including the entitlement would put something in the bundle that
passes every static check and does nothing — this project's own defect class, inside Apple's stack.

**Absent — `com.apple.developer.fileprovider.testing-mode`**, the documented way to enable a domain
headlessly via `NSFileProviderDomain.testingModes`. It is *restricted*: signing it ad-hoc gets the
process AMFI-SIGKILLed (exit 137, *"adhoc signed but contains restricted entitlements"*). Reverting
it made the identical binary run again, so the kill was the entitlement and not the code. Without
it, `testingModes` is silently ignored.

## Why hydration is blocked, and on what

The domain is created **`user-disabled`**:

```
fileproviderctl dump:  + (⏹ user-disabled)   enabled: no
                       last-drop-reason: Domain disabled
                       error:'FP -2011' domain:domainDisabled
```

`-2011` = `NSFileProviderErrorDomainDisabled`, decoded from the SDK header rather than guessed.
Enabling it needs a GUI operator or the restricted testing-mode entitlement above — and the
notarized extension §9's row names needs Apple Developer Program membership. **Both are
`G-0D-PROCUREMENT`, which the user excluded from this pass.**

**Hydration was never reached, not attempted-and-failed.** No `NSFileProviderReplicatedExtension`
method was ever entered — the `NSLog` lines in `Provider.swift` exist so that a future run can tell
those two apart. Whether the provider would hydrate correctly once enabled is **untested, not
falsified.**

## The expensive mistake, recorded so it is not repeated

Nine probes concluded that ad-hoc signing "silently discards entitlements", and that finding was
written down and reported before a control disproved it. The real cause:

```
swiftc -emit-library -Xlinker -bundle   → Mach-O 64-bit bundle    ← wrong
swiftc -emit-executable -Xlinker -e -Xlinker _NSExtensionMain
                                        → Mach-O 64-bit executable ← right
```

**`codesign` silently ignores `--entitlements` on a bundle-type Mach-O.** Exit 0, no warning,
nothing embedded. Every downstream symptom followed from that one flag.

The control that settled it took four seconds and should have been probe 1, not probe 9: sign
`/bin/echo` with the same entitlements and dump them. It separates *the instrument* from *the
subject* immediately.

**Do not cite `macos-signing-answer.md` or `macos-vm-verdict.md`** — both are stamped
`⚠ RETRACTED` and their central finding is false. `macos-VERDICT-CORRECTED.md` supersedes them.
