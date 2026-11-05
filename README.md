# Xbox-One-Research
My research into my 2018 era xbox one.

## 0. Executive summary

The campaign has two phases, and they stand in very different places.

**Phase 1 — get code execution on the console: DONE.** CVE-2019-0567 (Chakra `DataView` type
confusion, the legacy-Edge scripting engine) was ported to the console and turned into a full
exploitation stack: arbitrary read/write, ASLR-proof module-base derivation, import resolution by
name, the engine pointer-chain walk, stack leak, ROP arm + chain + thread spawn, a reflective PE
loader, and finally **payload execution as a real process on the console** — the current payloads
(`run.exe` lineage and the tokprobe lane's `tok.exe`) run with a real user token, real `kernelbase`,
and working sockets, and report line-by-line to the PC on TCP :7070. The bootstrapping runs entirely
through rendered HTML pages served from the PC: *the console is driven by pressing buttons on a
web page and reading logs.*

**Phase 2 — escape the app container (privilege escalation): OPEN.** The seat we hold is a LOW-
integrity AppContainer (`microsoft.ntscaptiveportal_8wekyb3d8bbwe`, `WWAHost.exe`, session 0,
`DefaultAccount`). Every user-mode escalation row of a standard Windows privesc checklist was
*measured* on the console and closed (no handle to any process, four token privileges of which one
is enabled and worthless, no writable system paths, no UAC, no LSASS-shaped targets — §3). The only
live route is the kernel. Two kernel lanes exist:

- **dxgkrnl CVE-2018-8405 — the live candidate.** Screened against the console's exact driver
  (`dxgkrnl.sys` 10.0.15063.138) and verified **instruction-level live on the console**: the
  vulnerable function is byte-identical to the pre-fix desktop code, and the bug is a controlled
  6-field pool-corruption primitive, fully anatomised in an instrumented twin VM (§5.1). It is not
  yet an exploit: the frontier is *aiming* the corruption at a useful victim.
- **afd.sys IOCTL `0x120DB` — surface excavation, parked.** The device's input model was mapped
  from inside a real payload process over 34 build/run cycles; no memory-safety break found yet (§5.2).

**The CVE ledger in one line:** one working foothold (CVE-2019-0567), one live kernel candidate
(CVE-2018-8405), and **everything else screened is not workable**, each with a measured reason —
CVE-2019-0555 (no MSXML on this image), CVE-2024-30088 (kernel-build gate excludes 15063), the
nine classic win32k one-days (the console's `win32kbase` is a custom branch; `win32kfull` absent;
per-CVE functions absent or structurally divergent), and the closed non-CVE routes (§6).

---

## 1. The target

**Console** (`192.168.1.178`), retail Xbox One, SystemOS. The console's own registry reports
(measured from inside the container):

```
ProductName = 'SystemOS'
BuildLabEx  = '15063.3054.amd64fre.rs2_release_xbox_1705.170512-1759'
```

i.e. the **May 2017 Xbox 1705 servicing of the RS2 (15063) branch**. The image is a *mixed-branch
composition* — per-component versions differ from (and are more interesting than) the OS level:

| Component | Version found on console | Note |
|---|---|---|
| win32u.dll | 15254.158 | Mobile fork (15254 line!) |
| win32kbase.sys | **custom** — TimeDateStamp `0xcd5d2467`, SizeOfImage `0x206000` | not on MSDL, not a desktop build |
| dxgkrnl.sys | **10.0.15063.138** | Sept-2017 servicing; the live kernel candidate's module |
| afd.sys, mskssrv, ndis, WDF01000 | 15063.413 | |
| tcpip.sys | 15063.296 | |
| ks.sys, portcls.sys | RTM | |
| kernelbase.dll | custom | MSDL builds don't match |

**Modules absent from the image** (each was searched for and is genuinely not present):
`ntoskrnl`, `hal`, `ci`, `netio`, `ksecdd`, `ntfs`, `clfs`, `cng`, `ws2ifsl`, `csc`, `appid`,
`win32kfull` — plus (user-mode) `whoami.exe`, `ole32.dll`, `wshom.ocx`, `advapi32.dll`
(`advapi32legacy.dll` stands in for it). `cmd.exe` **is present** but unreachable from our seats.

**The seat.** The browser is `WWAHost.exe` hosting legacy Edge/Chakra under the package
`microsoft.ntscaptiveportal_8wekyb3d8bbwe` — a LOW-integrity AppContainer, session 0, running as
`DefaultAccount` (`S-1-5-21-…-503`), with four privileges of which exactly one is enabled
(`SeChangeNotifyPrivilege`; the rest disabled: Shutdown, IncreaseWorkingSet, TimeZone). No
`SeDebug`/`SeTcb`/`SeImpersonate`/`SeAssignPrimaryToken` class privileges exist on the token at all.

**Image rules discovered (each cost a session to learn, none may be re-discovered cheaply):**

- **No module load from `LocalState`** — DLLs cannot be "loaded" from the writable package dir;
  code must be **reflective** (mapped manually) or executed as a staged payload process.
- **File system:** `<pkg>\LocalState` and `<pkg>\AC\Temp` are the only writable places; `LocalState`
  is the durable one (Temp-path writes are not durable — read-back `lastErr=2`). System-side writes
  refused `err 5` (including `System32`, `Windows\Temp`, `drivers\etc\hosts`); reads of `System32`
  DLLs succeed; `System32\config\SAM` read refused 5.
- **Registry is readable freely** from the container (via `advapi32legacy.dll`).
- **No UAC on this OS**; the analogous boundary is AppContainer → full trust — the objective itself.
- **No ACG / no dynamic-code block on this build** (EB FE probe): dynamically generated code pages
  are executable — which is what makes the ROP→RWX-page design viable.
- **Services are kernel drivers**; there is no SCM CLI, no scheduled-task machinery we can write.
- **The console cannot be connected *to*** from the PC (inbound listener `M:CONNME` → :1337 timed
  out) — all channels are initiated by the console.

---

## 2. Phase 1 — the Chakra foothold (CVE-2019-0567)

### 2.1 The bug and the port

CVE-2019-0567 is a **`DataView` type confusion in Chakra's JIT**: a prototype-chain walk in the
optimizer leaves a variable typed as an object while it actually holds a `DataView`. The public PoC
shape works on the console essentially as published, with these console-specific adjustments:

- The **little-endian flag `true` is mandatory** on all `setUint32`/`getUint32` calls in the primitive.
- The primitive itself: `o2.c = dv1; obj.h = dv2` aliasing after a ~2000-iteration warm-up; aim
  `dv1.setUint32(0x38, lo, true)` / `(0x3C, hi, true)` (the write target address lives in the
  `DataView`'s buffer-pointer fields); read/write through `dv2.getUint32(0/4, true)`.

**The twin-DLL method** (the porting workhorse): a desktop Windows 10 1607 `Chakra.dll` is the
static-analysis proxy for the console's engine. Verified matches: **DataView vtable RVA `0x5D0C00`
(identical, live-verified), `.rdata`/`.data` VAs identical, no CFG in either, no engine RTTI in
either**; `.text` differs by a `0x1b0` delta. Rule that came out of it: **gadget RVAs transfer only
as search seeds — every console address must be byte-verified at runtime.** Derive, never fit.

### 2.2 The exploitation stack (all proven on-console)

- **Arbitrary R/W** via the DataView primitive (write-then-read-back verified).
- **ASLR-proof module base** — MZ/PE-walk down from the DataView vtable (`RVA 0x5D0C00`), validated
  inside the module mapping (JS shift-wraparound traps: compare section-name bytes individually,
  `SizeOfOptionalHeader` = COFF dword at `pe+0x14`).
- **Import resolution by name** — walks export tables (in some modules, resolve against
  `kernelbase.dll` — `KERNEL32.dll` is not in the loader list on this image; `Rtl*` lives in `ntdll`).
- **Engine pointer-chain walk / stack leak** — `dv1[0x08]` → `+0x8` javascriptLibrary → `+0x440`
  scriptContext → `+0x370` threadContext → `+0x7b8` StackBase / `+0x7c0` SP. A good load shows a
  ~`0x5868` stack window and ~90 `.text` pointers; a bad load shows ~`0x9f8` and none — the
  `[2] FAIL: implausible stack fields` gate reloads the page (part of the reliability discipline).
- **Arm + chain + spawn** — the return-address arm prefers deterministic `E8 6F`/`E8 89` bytes at
  `ptr-5`, else a rank-2 JIT candidate; ranks 3/4 are never used. Exec page layout at `0x40000`:
  stub at `+0x0`, payload/data at `+0x1000`, launcher at `+0x29000..0x2F000`, chain block home at
  `+0x30000`. Stub convention: entry `rcx` = parameter table (`[+0x00/08/10]` = APIs, `[+0x18/20/28]`
  = args, `+0x30` upward = result slots; `sub rsp,0x28` shadow).
  **RIP control was achieved (v147); the full ROP chain fired (v148).**
- **File stubs** — read (191 B) and write (315 B) through the package path; status `0x600D` = written
  *and read back by a fresh handle*; `0xBAD` = open failed. A write experiment always starts with a
  no-op write (same value back) before anything real is written.
- **WinRT chain (end to end)** — `RoInitialize` → `WindowsCreateStringReference` →
  `RoGetActivationFactory` (statics IID) → `GetTemplateContent(1,&doc)` → a real `IXmlDocument`.
- **Reflective loader** — `WpadEscape.dll` mapped into the browser process: headers and `.text`
  byte-perfect, 851 relocations applied, 78 imports resolved, none missing. Verified offline
  (synthetic-memory test) then live.

The era's health harness reported **13 PASS / 0 FAIL** across the core primitives; from that point
the harness page (`00-latest.html`, currently `rw-tools-87`, md5 `16adfd1a`) is a stable instrument.
Harness discipline that is now law: **never overwrite a build — every change is a new `vN+1` file
plus a numbered alias**; per-press verdict flags reset every press; a value staged before the shared
table build is destroyed by it (slots `VLO+0x1C8..0x208` are zeroed — look it up, don't re-learn it);
one result slot per result; GUID `data4` is two little-endian dwords (copy packed GUID dwords from a
PoC, never reconstruct).

### 2.3 From page to process — the delivery machinery

The chain that turns "JS running in a page" into "a payload process on the console":

1. **Page delivery** — the console fetches pages from the PC (`http://192.168.1.146/redirect/…`),
   reached through the console's captive-portal flow (LAN DNS + HTTP server, `lan_dns_web`). The page
   auto-reloads when the served version string changes. Hard-reload before every run — the page
   caches payload binaries at load, and staleness is silent.
2. **Binary writes** — the exploit's file stubs write the payload and a loader to
   `<pkg>\LocalState\` (`run.exe` / `tok.exe`, `stage2.bin` / `stage2_tok.bin`). `publish.py`-style
   gates (undefined-call scan + `node --check` on the extracted script) refuse to publish a broken page.
3. **The launcher (S2)** — a loader staged on the console reads the payload from disk and enters it.
   Because the image refuses module loading from `LocalState`, this route (a staged process/loader
   pair) is the way code becomes a *process* — with a real thread stack, a real token, `kernelbase`
   already loaded by name, and the payload's own I/O table.
4. **The payload era.** The current payload lineage is **Collateral Damage repurposed as a vehicle**
   (`run_v2.exe` = 0x29000 bytes): it is not used as an exploit — it is a known-good EXE whose
   startup a small **cave shellcode blob** (`mymark_*.asm`, ≤ 0x800 bytes, spliced at VA `0x37000`
   with an entry hook) hijacks to run trials *inside the real process* and report home. The cave gets
   everything the browser never had: real sockets (one-shot `WSASocketW→connect→send→close` per
   message — a persistent socket stalls after its first send on this platform), `DeviceIoControl`,
   `VirtualAlloc`, and a real kernel entry surface.
5. **Reporting** — the payload/cave sends `M:…` reports to the PC on **TCP :7070**
   (`beacon_listener.py`; inbound :7070/:8081 must never be reused by anything else). The page's own
   relay log is :8080; the exploit lane's logserver also uses :8080 plus a blob sink on :8082.
   **The rule: the `:7070` log is the payload's witness; an empty log is only meaningful once the
   HTTP log proves the run happened** (the "void run" trap — a screenshot of an idle console and a
   stale log once masqueraded as a 6-minute survival).

### 2.4 The second payload lane (tokprobe)

A separate lane (`00-tokprobe.html` = `tokprobe-2.html`, payload `tok.exe` + `stage2_tok.bin`,
build ledger v1–v4) runs the **Windows privesc checklist as measurements** — see §3. Lane isolation
is a hard rule: the rw-tools lane owns `run.exe`/`run_probe.bin`/`00-latest.html`; tokprobe owns
`tok.exe`/`tokprobe.bin`/`00-tokprobe.html`; tools in one lane deliberately restore the other lane's
served payload from backup on every run.

---

## 3. Phase 2 — the container escape problem, measured

The tokprobe lane answered a generic Windows-privesc checklist *on this console*, by calling APIs
directly (no enumeration CLIs exist — no `whoami`, `systeminfo`, `net`, `sc`, `reg`, `tasklist`):

| Checklist row | Verdict on this console |
|---|---|
| Enumeration CLIs | **N/A — no binaries.** Everything must be measured via API calls |
| Token privileges | **MEASURED → CLOSED** (below) |
| Weak file/object permissions | **Files/processes CLOSED; device namespace = open probe** (v5 lane) |
| Kernel exploits | **LIVE — the only route left** |
| Explorer-suggester class tools | replaced by TimeDateStamp+SizeOfImage → MSDL → patch diff (§4) |
| Stored credentials / autoruns / AlwaysInstallElevated | mostly absent / no consumer (`msiexec` missing) |
| UAC bypass | **N/A — no UAC.** The analogous boundary is AppContainer → full trust = the objective |
| Unquoted service paths / SCM / schtasks | **N/A** — no CLI, services are kernel drivers |
| Credential dumping (mimikatz/LSASS/SAM) | dead on arrival even post-exploit — no such process shapes |
| Automated tools (winPEAS etc.) | cannot run — no PE execution out of the container, no .NET |

**The measured token (runs v2/v3/v4, consistent):** user = owner = the `DefaultAccount` SID above;
12 groups; LOW integrity (`S-1-16-4096`); AppContainer with its own SID; session 0; PRIMARY token;
elevation 0; **4 privileges, exactly one enabled** (`SeChangeNotifyPrivilege`, enabled-by-default) —
`SeShutdownPrivilege`, `SeIncreaseWorkingSetPrivilege`, `SeTimeZonePrivilege` all disabled. No
debug/impersonation/loader privileges exist to enable. The Potato/impersonation classes are
structurally dead here.

**Process space:** `NtQuerySystemInformation(SystemProcessInformation)` returns **only two entries**
(idle + ourselves) — the kernel filters the process list for this seat. `NtOpenProcess` is therefore
the only *existence oracle*: the PID sweep found pids 4, 500, 1200 exist with every open refused
(`0x1000` and `0x1F0FFF`); everything else = `STATUS_INVALID_CID`. No handle to any process at all.

**Files:** exactly two writable locations (`<pkg>\LocalState`, `<pkg>\AC\Temp`); system-side writes
refused 5. Registry readable. Module bases stable per boot (`ntdll 0x7FFFE4370000`,
`kernelbase 0x7FFFE40A0000`, `advapi32legacy 0x7FFFE2E90000` on the recorded runs) — still derive,
never hardcode, across rebuilds.

**Walls already measured closed (do not re-derive):** `HttpInitialize(SERVER)` → `5
ERROR_ACCESS_DENIED`; COM activation of the UPnP container manager → `0x80070005 E_ACCESSDENIED`;
device-handle opens from the Edge content process (LPAC) denied — `\\.\NUL` = 5, MSKSSRV interface
= 5 (note: `\Device\DxgKrnl` open being denied is irrelevant to the D3DKMT syscall path, which works).

**Conclusion:** the user-mode escalation surface from this seat is empty — measured, not argued.
What remains live: (a) the **device/object namespace probe** (`\Device` / `\GLOBAL??` enumeration +
per-device open, to map which drivers accept a handle from this seat — planned as tokprobe v5), and
(b) the **kernel lanes** (§5).

---

## 4. Method — how unknown builds get triaged (the diff gate)

Everything about "is bug X live on this console" reduces to a build-identification pipeline:

1. **Identify the module**: TimeDateStamp + SizeOfImage (+ section hashes) → map to a Microsoft
   public build via MSDL (`fetch_15063.py` etc.). The console's copies are matched to exact desktop
   servicing builds; where TDS/SOI don't match winbindex's SHA (14 dxgkrnl builds had a conflicting
   sha), the TDS-anchored build wins.
2. **Build the spine**: for dxgkrnl, **36 builds (.0 → .2679), 32 distinct binaries**;
   timestamps anchor each; per-function first-change datelines across the spine
   (`dateline_v2.txt` style). The console's `.138` is the base; **869 dxgkrnl functions have
   servicings after `.138`** — the candidate minefield.
3. **Screen the candidate**: take the CVE's fix (from the known patch diff), locate the changed
   bytes in the post-fix build, and **byte-compare against the console's module**:
   - vulnerable code present → **live candidate**;
   - guard/fix present, or function absent, or structurally divergent → **not workable** (record why).
4. **Adjudicate on the target only when cheap**: the console itself must answer "does it fire". The
   corruption canary: **a patched Chakra bug reads as all-zero corruption** (nonzero = live).
5. **The twin lab** (Phase-2 accelerator): a VirtualBox twin VM (Win10 15063 + the console's exact
   `dxgkrnl.sys` 10.0.15063.138) with Driver Verifier and **live kernel debugging over a named pipe**
   (`\\.\pipe\twinlab_kd`), snapshots and dump harvesting automated in `twinlab.sh`. This replaces
   "1 bit per console boot" with minutes-per-datapoint and full live-state inspection at the exact
   faulting instruction.

The win32k lane used the same method against the console's `win32kbase` (custom, TDS `0xcd5d2467`)
with a 20-build desktop spine (250 … 2679), per-CVE function pair-scans, and a per-function
"console matches which build" dateline (`dateline_v2.txt`, `b2_missing_servicing.txt`,
`adjudication_report.txt`, `pairscan_report.txt`).

---

## 5. The kernel lanes

### 5.1 dxgkrnl CVE-2018-8405 — the live candidate (fully characterised)

**Attribution & timeline:** ZDI-18-946 (ZDI-CAN-6118), ChenNan & RanchoIce (Tencent ZhanluLab);
CVSS 6.9 (ZDI) / 7.8 (NVD); **patched 2018-08-14** (first fixed 15063 build: **.1266**);
**CISA KEV 2022** (exploited in the wild). Published in a ZDI five-PoC dxgkrnl pack (ZDI-18-946/947/950
on disk; 946 is the one this project decoded).

**The bug:** in `OpenResourceObject`, the pre-fix code validates the wrong thing
(`test [alloc+0x38], 0x800`); the fix is `mov eax,[rcx+0xC]; test al,0x20` on the shared object,
else `0xC000000D`. On the console's `.138` driver the vulnerable form is present —
**431-instruction check, 0 rejects**. The downstream primitive lets a `CreateResource=1` style
`D3DKMTCreateAllocation` resource end up writing into memory beyond its own object.

**The fault site (console and twin are byte-identical):**
`mov dword ptr [rdi+0B0h], eax` @ console RVA **`0x13FFF5`** (bytes `89 87 B0 00 00 00`);
guard at `13FFC8/13FFCB`.

**The primitive — write map** (`this` = block+0x10; block size 0xD0; object type
DXGSHAREDRESOURCE; ctor `0x8DFF4`, dtor `0x8E0F0`, vtable `@0x471A8`; **real members end at `+0xB0`;
`+0xB0..+0xBF` is the uninitialised tail slack; `this+0xC0` is the *next* block's pool header**):

| Field | Content | Control |
|---|---|---|
| `+0xB0`, `+0xB4`, `+0xB8` | 3 dwords from the "describe" path | **caller-controlled — but must be valid allocation geometry** (markers like `0x11111111` are rejected `0xC000000D`; `0x100/0x200/0x15`, `0x80/0x100/0x15`, `0x1000/0x4000/0x15` accepted) |
| `+0xC0` | qword kernel pointer | from a section-lookup call (`0x2514C`) — not caller-free |
| `+0xC8` | qword kernel pointer | second lookup |
| `+0xD0` | dword `0xFFFFFFFF` | fixed |

The first three land inside the object's own slack; **everything from `this+0xC0` onward lands in the
adjacent pool block's header/body (~0x14 bytes)** — `!poolval` reports *"Bad previous allocation
size"*. Console kill mechanics: the teardown free-cascade **coalesces on the corrupted header**
(instant kill; "trigger alone" can survive, a B-form destroy then kills, and unpatched free paths
bugcheck immediately). Observed verdicts (twin, under verifier): `0xC4/0x13A` (verifier's pool-
tracking token sits in the slack at `data+0xB8` — a lucky detector), `0x19 BAD_POOL_HEADER`,
`0xC2/7` ("already freed" — when a free consumes our injected `+0xC0` pointer as a pool address),
`0xD6` (special pool).

**Victim classes seen next to the corrupted block:** `Free` (benign), `CMnb` (benign), **`AlMs`**
(ALPC message buffer — kills), `NtFs`/`Ntfo` (object-manager name blocks — delayed kill when the
owner touches it), `IoNm` (I/O name cache). **Practical neighbours are NT metadata — user-mode
sprays (before, between, after allocations) do not steer adjacency**; the blocks land on
NT-metadata-dense pages.

**The consume amplifier (park-and-consume, `poc_alpc.exe`):** park N ALPC messages (full
connect→receive→**accept** handshake — the accept step is required, else `0xC0000707`) next to the
resource, trigger, then drain the messages: rep 1 produced a **deterministic kill** (`0xC2/7` with
`P3` = our injected pointer) — rep 2 survived the drain but died **~21 min later** (`0x19/0x20` at
the corrupted header). Corrected picture: **every corruption is eventually consumed; only the clock
varies (5–21 min observed). The amplifier raises the odds (~1/2 overall), it is not a guarantee.**

**The twin lab (proven instrument):** VBox `twin15063`; console-exact `dxgkrnl.sys` (10.0.15063.138); Driver Verifier
(Special Pool for fault-site fidelity; Pool Tracking flag `0x8` for alloc/free stacks; Special Pool
OFF for console-fidelity runs); kd over `\\.\pipe\twinlab_kd` (note: `cdbX64` has no `-k`; use
`kdX64.exe`); four money breakpoints (`0x13ff47` pre-fill, `0x13ff4c` post-fill, `0x13fff5` pre-write,
`0x140082` post-write) capture the entire write live; crash cycles harvested as memory dumps with
`!analyze`/`!verifier` post-mortems. The write was captured **live on the console too** (breakpoint
at `dxgkrnl+0x13fff5`; `rdi` = the 0xD0 'DxgK' block; `eax=0x100`; then `0xC4/0x13A` on resume —
same mechanism as the console's instant kill, minus the verifier).

**What remains before an EoP (the two forks):**
1. **Aim** the corrupted block at a victim whose *consumption* yields a memory effect, not a bugcheck
   (fake-pool-header aiming at the injected pointer is unproven; adjacency from user mode is not
   steerable — the fork is a kernel-side allocation strategy inside the driver's own paths, or a
   different primitive use of the same writer).
2. **Convert** a consumption bugcheck into a win — e.g. arrange the corrupted header so the
   coalescing free produces a controlled overlap *before* anything checks.
The concrete next console step is planned as **v15**: park ALPC (the LPAC ALPC-port-creation
assumption is the one unproven item), trigger, drain — through the existing payload/cave channel,
with the twin lab adjudicating each move.

### 5.2 afd.sys IOCTL `0x120DB` — the excavated surface (parked)

The second lane drives `DeviceIoControl(sock, 0x120DB, record, 0x20, …)` against the AFD device from
**inside a real payload process** (the cave vehicle; real token, `kernelbase`, ws2_32 IAT). Over
**34 build/run cycles** the input model was mapped byte-level:

- record (0x20 B): `{type; param; subtype; flag=1; pad; ptr32; len32}` with validator rules
  (type 1–3; type-3 requires param 0; `ptr32` is a zero-extended 32-bit pointer — structures must be
  below 4 GB, mapped via `VirtualAlloc(0x10000000, …)`).
- Observed error taxonomy: `6` = afd's SEH caught a bad pointer/alignment; `87/0xC000000D` = the TLI
  provider rejected a well-formed call; `998` = fault caught at entry; `0xC0000184` = an endpoint
  state gate.
- The lane reached the TLI provider's own validation and state machine; **no memory-safety break was
  found**. Status: parked as an excavation, not falsified.

---

## 6. The CVE ledger — everything screened, and why it is or isn't workable

### 6.1 Working

| CVE | Where it sits | Status |
|---|---|---|
| **CVE-2019-0567** | Chakra (legacy Edge) — the foothold | **WORKS**: full R/W, ROP, spawn, loaders, payload processes, on-console verified (§2) |

### 6.2 Live candidate (kernel)

| CVE | Module | Status |
|---|---|---|
| **CVE-2018-8405** (ZDI-18-946) | dxgkrnl.sys 15063.138 | **LIVE**: vulnerable code byte-identical on console; primitive fully characterised; exploit forks open (§5.1) |

### 6.3 Screened — NOT workable, and why

| CVE / route | Target | Verdict & reason (measured) |
|---|---|---|
| **CVE-2019-0555** ("TriBell" MSXML cross-boundary `XmlDocument`) | Edge→MSXML escape | **Not workable.** The escape needs `IXMLDOMDocument2`; this image does not expose it: `QueryInterface` returns `E_NOINTERFACE` even with corrected GUID bytes, and `GetIids` lists six interfaces, *none* MSXML's `2933BF90-…`. The payload path (`AllowXsltScript` + `transformNode`) is MSXML-only; WinRT's `XsltProcessor` has no script equivalent. |
| **CVE-2024-30088** ("Collateral Damage") | NT kernel (25398.x line) | **Not workable.** Built for GameScript-app contexts and kernel builds 22621.2864 / 25398.4478 / 4908 / 4909 — its build gate **refuses 15063** and the payload aborts on console. The repo was repurposed: its EXE became the **cave vehicle** for the kernel lanes, not an exploit. |
| **CVE-2018-8120** | win32k | **Not workable.** Console `win32kbase` is a custom branch (TDS `0xcd5d2467`, not on MSDL); the CVE's patched functions map to the console copy as ABSENT or structurally divergent (pairscan). |
| **CVE-2018-8589** | win32k | **Not workable** — same reason (candidate functions absent/divergent; console copy not a desktop build). |
| **CVE-2018-8611 / CVE-2018-8639** | win32k | **Not workable** — same reason. |
| **CVE-2019-0797** | win32k | **Not workable** — same reason. |
| **CVE-2019-0808** | win32k | **Not workable** — same reason. |
| **CVE-2019-1458** | win32k | **Not workable as a portable one-day.** Its named functions exist on the console in early/pre-servicing form, but exploitation requires the desktop window-manager object surface; no reachable trigger from this seat was demonstrated. *Honest residual: this family is parked as "unproven", not formally dead — see §9.* |
| **CVE-2020-1054** | win32k | **Not workable** — palettes/GDI functions absent or divergent on the console branch. |
| **CVE-2021-1732** | win32k | **Not workable** — same reason (console branch predates/diverges from the desktop code the exploit targets). |
| **CVE-2021-40449** | win32k | **Not workable** — same reason. |
| **ZDI-18-947 / ZDI-18-950** (dxgkrnl siblings of 946) | dxgkrnl | **Unpursued.** Their PoCs are on disk; the project converged on 946 because its vulnerable function exists byte-identical on the console. Status: not falsified — simply not pursued once 8405 was fully decoded. |

**Why the whole win32k family fails as a class:** the console's `win32kbase.sys` is a *custom,
non-MSDL* build on a different (Xbox/Mobile-forked) branch; `win32kfull.sys` **does not exist** on
the image at all; and where a candidate function does exist, it matches neither the desktop's
vulnerable nor fixed form cleanly (dateline/pairscan adjudication). The classic win32k exploit
techniques additionally assume desktop window-station/desktop-object machinery that this seat does
not demonstrably reach.

### 6.4 Non-CVE routes screened and closed

| Route | Verdict |
|---|---|
| **WPAD / `WinHttpAutoProxySvc` RPC over `ncalrpc`** (`3473dd4d-…` v5.1 interface — real) | **Closed.** The RPC runtime cannot be driven from our spawned thread: through the *identical stub*, `kernelbase!GetCurrentProcessId` survives while `rpcrt4!RpcStringBindingComposeW` crashes. (Control-validated — the first two "RPC is unusable" verdicts were withdrawn and re-tested properly.) |
| **AppResolver private WinRT class** (2026-era blog route) | **Closed as an entry.** `RoGetActivationFactory("Windows.Internal.AppResolver.…")` **faults the process** instead of returning `REGDB_E_CLASSNOTREG` — probing private class names kills the thread. The class's existence on 15063 remains UNKNOWN; the probe method itself is hostile. |
| **Drive-by device opens from the content process (LPAC)** | Closed: NUL=5, MSKSSRV interface=5; mutate to the D3DKMT syscall path instead (works). |
| **`HttpInitialize(SERVER)`**, **UPnP container-manager COM** | Closed (5 / `E_ACCESSDENIED`) — measured, not argued. |

### 6.5 Out of scope

The workspace also contains non-console side artifacts (`curveball-mitm`, Xbox-LIVE certificate
emulation work). They are not part of this campaign and carry no console verdicts.

---

## 7. Everything discovered — the catalogue

**OS / image:** mixed-branch SystemOS (stamps §1); absent-module list (§1); no module load from
`LocalState`; no ACG on this build; services are kernel drivers; no UAC; registry readable from the
container; only `<pkg>\LocalState` + `<pkg>\AC\Temp` writable (LocalState durable; `AC\Temp` writes
not durable); `advapi32.dll` absent → `advapi32legacy.dll`; `whoami`/`ole32`/`wshom` absent;
`cmd.exe` present; `SAM`/`hosts` writes refused 5; LPAC device-handle denials.

**The seat (measured):** WWAHost AppContainer, `microsoft.ntscaptiveportal_8wekyb3d8bbwe`,
`DefaultAccount`, LOW IL, session 0, 4-privilege token (1 enabled); process list filtered to 2
entries; NtOpenProcess as the PID oracle; no handle to any process.

**Chakra/engine:** DataView vtable RVA `0x5D0C00` (exact twin match); `pop rsp 0x737b`,
`pop rcx 0x2979f`, `pop rax 0x5efd1`, `mov [rcx],rax 0x31321d` (verify at runtime);
`KERNELBASE VirtualProtect 0x61700`; bridge chain `+0x8 database → +0x440 scriptContext →
+0x370 threadContext → +0x7b8/+0x7c0 stack`; good-load/bad-load gates; the `E8` arm lottery and its
discipline; exec-page map; the file-stub status vocabulary (`0x600D`/`0xBAD`).

**Delivery/infra:** captive portal + LAN DNS/HTTP (`lan_dns_web`: DNS 53, HTTP 80, HTTPS 443,
relay 8080); pages with auto-reload + publish gates; S2 loader machinery; reflective loading
(WpadEscape.dll proof); the cave splice pipeline (entry hook, IAT rewrite discipline, reloc
restore, R_X `.reloc`); one-shot-socket rule; :7070 reports as the witness channel; "the HTTP log
is where a run is confirmed"; pc→console inbound is impossible.

**Kernel (dxgkrnl):** the whole §5.1 anatomy — plus: pool-tracker history showed every historical
owner of the target 0xD0 cell was nt! security/token code (cross-owner corruption shape);
verifier observatories `C4/13A`, `19/20`, `C2/7`, `D6`; the four breakpoints; the twin-lab recipe.

**Method:** the diff gate (§4); twin-DLL proxy rule; "derive, never fit"; the corruption canary
(all-zero = patched); fire-lottery discipline; per-press re-derivation; last-line logging.

---

## 8. Where it stands / next moves

1. **v15 console harness** (dxgkrnl lane): park → trigger → drain via the payload channel; reads
   first: `make_d3dkmt_v14.py`, the v10 asm, `00-d3dkmt.html`; unproven assumption = LPAC ALPC port
   creation on the console's seat.
2. **Twin-lab forks**: fake-block aiming; adjacency via driver-side allocation shaping; and the
   coalescing-free overlap experiment. Each move is minutes in the twin, not console boots.
3. **tokprobe v5**: the `\Device` / `\GLOBAL??` namespace probe (which drivers accept handles from
   this seat, with what access) — fits in the payload's remaining ~2.5 KB headroom.
4. **afd lane**: parked; resume only if the dxgkrnl lane stalls or the namespace probe surfaces a
   better device.
5. Environment that remains ready: relay + portal + logserver/beacon; twin VM + kd scripts +
   watchdogs; pages `00-latest.html` (rw-tools-87), `00-tokprobe.html`, `00-d3dkmt.html` (v14);
   era handovers; this document.

**Honest status of the endgame:** not yet a sandbox escape. What exists is a real, controlled,
content-controlling pool-corruption primitive in a kernel driver whose code is confirmed live on the
console, plus the instrumentation to iterate on it at high speed. The remaining problem is the
exploit-shaping problem — aiming and consumption — not discovery.

---

## 9. Corrections & method rules paid for

Conclusions that were falsified during the campaign (kept here so they are not re-derived):

- **"The RPC runtime is unusable"** — reported twice, withdrawn twice. The control shared the
  mechanism (our own stub), so a stub fault was indistinguishable from an rpcrt4 fault. Fixed test:
  hold the mechanism fixed, change only the target to something that cannot fault.
- **`E_NOINTERFACE` misread** on the WinRT path — `IID_IActivationFactory` returns it for *every*
  class; the answer must come from `GetIids`, not from a familiar HRESULT.
- **"The box survived the trigger"** — three times a "survivor" later died of the same corruption
  (5–21 min). The corrected rule: every corruption is eventually consumed; only the clock varies.
- **"6 minutes alive"** on the console — a void run (the PoC never launched due to a `timeout`-vs-
  function bug; the log was stale). Rule: confirm the run in the HTTP log before believing an empty
  report log; make the harness prove it launched.
- **win32k-in-early-form ≠ exploitable** — presence of a pre-fix instruction stream is necessary,
  not sufficient; without a reachable trigger it is parked as *unproven*, not claimed dead (and not
  claimed live).
- Operational traps that each cost a console run at least once: page staleness (hard-reload);
  a rename is an audit of every emitted line; the stale-arm crash class ("look for the MISSING
  heartbeat"); `write_file` stale-write guards on docs (`rm` first); VBox session wedge = kill the
  whole VBox process family; `timeout` cannot wrap shell functions; guest `guestcontrol` calls need
  `timeout` wrappers or they hang forever when the guest dies mid-call.

**Standing rules:** never overwrite a harness (new `vN+1` + numbered alias); publish `00-latest`/
`00-reader` after every build; derive every constant; verify by bytes (`od`/hex), never by displayed
text; one result slot per result; the console file system answers only under `<pkg>\LocalState`.
