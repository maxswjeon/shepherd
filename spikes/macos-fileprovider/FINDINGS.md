# macOS File Provider spike — Phase 0c / OQ-D

**Question §9 asks:** can Shepherd run a File Provider extension on macOS, and what does it cost
to get one registered and hydrating?

**Answer, in one line:** registration needs no Apple certificate of any kind — reproduced
2026-08-19 on the mac host *and* in a fresh VM, ad-hoc, zero signing identities; hydration needs a
domain to be *enabled*, which needs either a console operator or a provisioned identity, and is
therefore blocked on `G-0D-PROCUREMENT`.

---

## What is verified here, and by what

| claim | status | how |
|---|---|---|
| appex must be Mach-O `MH_EXECUTE` with `_NSExtensionMain` entry | **verified** | `build.sh` asserts it and aborts on `MH_BUNDLE`; run on macOS 26.5.2 → `Mach-O 64-bit executable arm64` |
| ad-hoc signing embeds entitlements | **verified** | `codesign -d --entitlements` → `app-sandbox entries: 1`, `Signature=adhoc`, no Apple cert present |
| extension must carry `com.apple.security.app-sandbox` | recorded, not re-verified | `pkd`: *"Ignoring mis-configured plugin: plug-ins must be sandboxed"* (2026-08-18, VM) |
| extension must carry `com.apple.security.application-groups` matching its `NSExtensionFileProviderDocumentGroup` | **verified** | `fileproviderd` ERROR names the key; drop it and `add` returns -2014. See below |
| `lsregister -f` alone does not make the appex discoverable | **verified** | host and VM: app registers, appex absent from `pluginkit` after a 45 s wait; `pluginkit -a` fixes it |
| a domain registers under ad-hoc | **verified on host AND in a fresh VM, 2026-08-19** | `ACCEPTED — domain registered`, `Signature=adhoc`, `TeamIdentifier=not set`, `0 valid identities found` |
| the extension process actually launches | **verified** | `fileproviderd`: *"Created new process ExtensionProcess: bundleID: …hostb.provider … pid: 78086"* |
| hydration | **never reached** | domain is created `user-disabled`; no extension method was ever entered |

## The reproducibility gap — CLOSED 2026-08-19

The earlier version of this file recorded that registration was *"recorded in a VM, NOT reproduced
on the host"*, and named the `Info.plist` files as the prime suspect because they were the only
part rebuilt from prose. **Both halves of that guess were wrong, and the real cause is worse:** the
reconstruction dropped an entitlement *on purpose*, for a reason that was true about container
access and false about registration.

### What settled it

Two primary sources, neither of them the artifact that had already proved insufficient:

1. **The original probe scripts were still on the mac host** in `/private/tmp` — `vmfp.sh`,
   `vf.sh`, `vfin.sh`, `vad.sh`, the actual probes 1–12. They are archived at
   `.omc/artifacts/phase-0c/salvage-original-probes/`. `vmfp.sh`'s `write_plist()` generates the
   appex `Info.plist` **key-for-key identically** to the committed `Info-appex.plist`, modulo the
   `.vm` → `.spike` namespace. **The plists were never the problem** — they are a faithful
   reconstruction, and that suspect is retired on evidence rather than on argument.

2. **A fresh VM** cloned from `ghcr.io/cirruslabs/macos-tahoe-base` (guest 26.6.1, `0 valid
   identities found`), plus the host (26.5.2, SIP **enabled**). Three variants, one cold boot:

   | variant | entitlements | `pluginkit` | `NSFileProviderManager.add` |
   |---|---|---|---|
   | A — the committed spike as it stood | `app-sandbox` only | listed | **REFUSED, underlying -2014** |
   | B — A plus `application-groups` | `app-sandbox` + group | listed | **ACCEPTED — domain registered** |
   | C — the literal original `.vm` namespace, root-owned | `app-sandbox` + group | listed | **ACCEPTED — domain registered** |

   Then on the **host**, same recipe, fresh bundle identifier, twice:
   `ACCEPTED — domain registered`, `removed cleanly`.

### The two defects in the reconstruction

**1. The missing entitlement.** `Info-appex.plist` declares
`NSExtensionFileProviderDocumentGroup`, and `fileproviderd` requires the extension to actually hold
`com.apple.security.application-groups` for that exact string. The reconstruction removed the
entitlement and kept the declaration. Nothing complains at build time — `codesign` succeeds,
`codesign -d --entitlements` looks clean, `pluginkit` lists the extension — and the one diagnostic
in the entire system is a single `fileproviderd` line:

```
[ERROR] Extension <private> doesn't have a group container for document group
group.kr.swjeon.shepherd.hostc specified via NSExtensionFileProviderDocumentGroup.
Ignoring the extension.
```

The caller sees `-2014 NSFileProviderErrorApplicationExtensionNotFound`, which reads as *"your
extension was never discovered"*. It was discovered, and then discarded.

**This is the project's own defect class again, and this time we wrote it ourselves:** the previous
pass proved the App Group *container* is unusable ad-hoc (`containermanagerd` rejects it, no team
ID) and concluded the entitlement should therefore be dropped as decorative. The entitlement is not
decorative. Container access and extension admission are two different checks, and only the first
one fails ad-hoc. Removing it produced a bundle that passes every static check and does nothing —
the exact failure the old text congratulated itself on avoiding.

**2. `lsregister -f` is not sufficient, and `pluginkit -a` must follow it immediately.** On both
machines `lsregister -f` registered the containing *app* with Launch Services while leaving the
`.appex` absent from `pluginkit` entirely — confirmed unchanged at 45 s, so this is not indexing
lag. `pluginkit -a "$APPEX"` makes it appear.

**And the gap between those two commands decides the outcome.** The first patched `build.sh` still
slept 5 s between them, and failed three times in a row while the identical bundle registered by
hand. That looked like flakiness. It is not:

| gap between `lsregister -f` and `pluginkit -a` | result |
|---|---|
| 0 s | ACCEPTED, ACCEPTED, ACCEPTED |
| 5 s | REFUSED -2014, REFUSED -2014, REFUSED -2014 |

Six trials, alternated `0,5,0,5,0,5` so drift and daemon state cannot explain it, identical
bundles, and each trial asserted its `NSExtensionFileProviderDocumentGroup` matched its embedded
entitlement before being counted. **Perfect separation, 6/6.** With the gap present,
`fileproviderd` never logs the request at all, so the failure is upstream of it and completely
silent — which is why it read as randomness for six earlier probes.

The mechanism is not established: presumably `lsregister -f` kicks off an asynchronous Launch
Services / pkd discovery pass, and `pluginkit -a` only takes effect if it lands before that pass
settles. **The rule is measured; the explanation is a guess and is labelled as one.**

### The end-to-end check, which is the point of a spike

`build.sh` as committed here was run unmodified on the host (macOS 26.5.2, SIP enabled, ad-hoc,
`TeamIdentifier=not set`) against two bundle identifiers never used on that machine before:

```
app-sandbox entries: 1      Signature=adhoc
kr.swjeon.shepherd.spikeu.provider(1.0)     ACCEPTED — domain registered
kr.swjeon.shepherd.spikev.provider(1.0)     ACCEPTED — domain registered
```

Both torn down clean: no bundle, no container, no group container, no `CloudStorage` mount, zero
`shepherd` entries left in `pluginkit`. **The script in this directory is the script that was
verified** — not a description of one.

### What is still not clean, stated rather than hidden

The *mechanism* behind rule (b) is unexplained; only its effect is measured.

Rule (b) is also **host-specific, and known not to bind in the VM.** The VM matrix registered
variant B after a 10 s gap, so the sensitivity is real on the host (26.5.2, SIP enabled) and
demonstrably absent on the guest (26.6.1, SIP disabled). Which of those two differences accounts
for it was not tested. **Consequence: a green run in a VM does not clear this recipe on a host.**
If a future run returns `-2014` with everything else correct, suspect that gap first.

Registration also still is not storage. With the domain registered, the kernel refuses the
provider's own directory:

```
System Policy: fileproviderd(607) deny(1) file-write-create
/Users/swjeon/Library/Group Containers/group.kr.swjeon.shepherd.hostz/File Provider Storage
```

So the App Group entitlement is **necessary to be admitted and insufficient to be useful** — it
buys registration and not a writable container. Nothing here changes the hydration verdict below.

## Entitlements

`Provider.entitlements` carries exactly two, and one is deliberately absent.

**Present — `com.apple.security.app-sandbox`.** Unrestricted, so an ad-hoc signature can
self-grant it. Without it `pkd` refuses the plug-in outright.

**Present — `com.apple.security.application-groups`, and it is REQUIRED.** It must list exactly
the string `Info-appex.plist` gives for `NSExtensionFileProviderDocumentGroup`; without it
`fileproviderd` discards the extension and `add` answers `-2014`. See "The reproducibility gap —
CLOSED" above; this file previously omitted it and that omission is what stopped the spike
reproducing.

The entitlement is nonetheless **not sufficient for storage**. It embeds cleanly, verifies under
`codesign -d --entitlements`, admits the extension — and the container it names is refused at
runtime:

```
containermanagerd: [kr.swjeon.shepherd.vm.provider] requesting [group.kr.swjeon.shepherd.vm]:
REJECTED. Requestor's signature does not allow it to access a TCC-protected group container.
Group containers identifiers should be prefixed by requestor's team ID to allow access on this
platform.
```

Ad-hoc has `TeamIdentifier=not set`, so a team-prefixed group is impossible. **Consequence for
Shepherd's design: any component that puts state in an App Group container cannot be validated
without a real team identity.** The entitlement is still required in the bundle — it gates
admission, not access — so the two facts have to be held at once: *declared and admitted, but not
writable.*

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
