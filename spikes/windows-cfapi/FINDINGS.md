# Windows Cloud Files spike — Phase 0c / §6

**Question §6 asks:** can the process that *registers* a sync root be different from the process
that *serves* hydration? Shepherd's design has the installer register and the daemon serve, so if
those cannot be decoupled the architecture changes.

**Answer: yes, and no package identity is required.** Demonstrated with three distinct processes.

---

## The decoupling result

| step | pid | image | outcome |
|---|---|---|---|
| register | 1684 | `cfreg.exe` | `CfRegisterSyncRoot(CF_REGISTER_FLAG_NONE)` OK, **then exits** |
| connect + placeholder | 3008 | `cfserve.exe` | `CfConnectSyncRoot` OK; 12,000-byte placeholder created |
| read | 5896 | `powershell.exe` | 12,000 bytes returned in 40 ms |

The registrant was **gone before the server started**. `CF_CALLBACK_TYPE_FETCH_DATA` fired in the
server process and was served across the process boundary.

The reader's identity is **the kernel's word, not our bookkeeping** — `cfserve` connects with
`CF_CONNECT_FLAG_REQUIRE_PROCESS_INFO`, so the callback reports who asked:

```
[serve] FETCH_DATA fired in pid 3008 | requester pid=5896 session=0
  image="\Device\HarddiskVolume5\...\powershell.exe" cmdline="... reader.ps1 ...\hello.bin"
[serve] CfExecute(TRANSFER_DATA) OK — 12000 bytes at offset 0
```

**Bytes verified, not assumed.** The provider serves `b'A' + i%26`, so hydrating to zeroes would be
distinguishable from hydrating correctly. The reader reported `sha256=c784c9fd…777a1`; the same
digest was computed independently off-host. `dir` shows `(12,000)` both before and after the read —
the placeholder declares its size before any content exists.

## No package identity needed

`CfRegisterSyncRoot` succeeds from an **unpackaged executable** with `CF_REGISTER_FLAG_NONE`. This
contradicts the premise in §6 and OQ-C that an MSIX/sparse package identity would be required
before any of this could be attempted.

## Persistence — what was and was not shown

**Past process exit: yes.** A registration from 2026-08-17 still resolved a day later from a new
process, and a same-boot control reproduced it (register in pid 6220 → exit → query from pid 6492 →
OK).

**Across reboot: UNTESTED, and not claimed.** `LastBootUpTime = 2026-08-08` predates both
registrations, so the machine never rebooted between them.

## Correction of record: the registry key that looks right and is not

An earlier check reported "`SyncRootManager` lists no registered sync roots" as a qualification on
this result. **That check could not have failed for the right reason.**
`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\SyncRootManager` belongs to the
shell-level WinRT `StorageProviderSyncRootManager` API. **`cfapi` never writes it.** It had zero
children immediately after a registration that then read back 1028 bytes of provider info.

The load-bearing check is **`CfGetSyncRootInfoByPath`**, and unregistration is what makes it
load-bearing rather than merely present: it returns `0x80070186` afterwards.

That key is genuinely where sync roots appear *for packaged providers*, which is why the check read
as correct right up until someone asked what writes it.

## The mistake that nearly became a wrong architectural claim

The first provider registered **only** `FETCH_DATA`. Every outside process was then locked out:
`dir` returned empty, writes failed `0x801F0005`, and the write-up was one paragraph from
*"unpackaged sync roots are non-functional, so package identity is required after all"* — a large,
plan-shaping, wrong conclusion.

The tell was the **second** error: `0x800701AA ERROR_CLOUD_FILE_REQUEST_TIMEOUT`. A timeout means
something is *waiting on you*. Adding `FETCH_PLACEHOLDERS` and `CANCEL_FETCH_DATA` turned every one
of those failures green on the next run, fresh root, nothing else changed. **The platform was fine;
the provider was incomplete.**

That reasoning is recorded in `src/cfserve.rs` beside the callback table, where the next person to
trim the registration will hit it.

## Operational note for Phase 3

**A registered sync root with no connected provider is inaccessible to every other process**
(`0x801F0005`). Expected Cloud Files behaviour, but it means that while the Shepherd daemon is
down, its sync roots are unreadable — not merely un-hydratable.

## Named limits

- **Reboot persistence untested** (above).
- **Shell/Explorer integration untested**, and it remains the likeliest place a real package
  identity requirement would appear.
- **Windows Server 2022, not a Windows 11 client.** The Cloud Files driver is the same, the shell
  is not.

## Building and running

`build-in-container.ps1` builds in a process-isolated container. Two traps that cost hours and are
not obvious:

- **`CARGO_TARGET_DIR` must live off the bind mount** — `os error 3` otherwise.
- **Anything built in the container needs `-C target-feature=+crt-static`** to run on the host, or
  it dies with `0xC0000135` (`STATUS_DLL_NOT_FOUND`): the container image carries the MSVC runtime
  and the host does not.

Cloud Files is a kernel mini-filter (`cldflt.sys`) and **cannot run inside a container** — build in
the container, run on the host.
