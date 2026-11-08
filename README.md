# Xbox One SystemOS Security Campaign — Findings Write-up

**Date:** 2026-11-08 · **Target:** Xbox One SystemOS (Windows 10 15063-class RS2, EOL Oct 2018) · **Seat:** the Edge-browser AppContainer process (Low-IL), reached via the chakra exploit chain · **Method:** static binary analysis on console file dumps + live console probes (P1–P60) + twin-VM (clean 1703) validation.

---

## 1. What we HAVE

These are capabilities proven with live console runs (each re-verified per session, the "re-prove" discipline):

| Capability | Evidence |
|---|---|
| **Code execution in the browser seat** | The chakra exploit chain lands; payload (`ipcx.bin`) runs, beacons to the LAN server (:7070), survives process exit |
| **Raw kernel-object opens from the seat** | `NtOpenFile(\Device\Afd\Endpoint, 0x0012019B, …)` → **SUCCESS** (P-runs; re-proved every run) |
| **Socket creation + connection** | `WSASocketW` → connect → the full afd ioctl set reachable (A2 probe) |
| **Kernel ioctl conversation** | The afd dispatch table (73 ioctls, 0x12003–0x12123) walked live; per-ioctl statuses measured |
| **Kernel pool interaction** | 2,000 IoCc objects sprayed, CloseHandle holes, survives; the pool-reclaim geometry proven (P36/P45) |
| **Race primitives** | The 60719 twin PoC bugchecked the twin twice (BUGCHECK 0x3B) — the race/UAF engine works on this kernel generation |
| **Registry read (SYSTEM context reachable via legacy dll)** | The winsock catalog read live (advapi32legacy.dll) — the full standard MSAFD catalog |
| **Filesystem read/write** | The payload writes itself to LocalState; the beacon log writes to the LAN server; guest-equivalent file R/W on the twin |
| **A full static picture of the console's kernel/userland** | 1,498 System32 binaries + 142 drivers parsed (imports/exports/versions/strings); every afd ioctl mapped; the cert-consumer map |

**In short:** we have a stable, re-provable AppContainer seat with deep afd/WSK interaction, kernel-pool manipulation, and a complete static map of the OS. We do **not** yet have kernel read/write or SYSTEM.

---

## 2. What we DON'T have

| Missing | Why (the measured walls) |
|---|---|
| **Kernel arbitrary read/write** | Every UAF/race lane closed at a structural wall (below). No primitive survived the endpoint-class or transport checks |
| **SYSTEM / EoP** | Depends on kernel R/W; the only ITW-confirmed-live UAF (60719) bugs the twin but is class-gated on the console (0xafd0 vs 0xaafd) |
| **The raw `\\Device\Tcp` open** | AppContainer-blocked — the transport wall (P60/T1). This killed the RIO/38193 lane at the delivery step |
| **DRM-descrambler KS filter** | `drmk.sys` absent → the filter never instantiates → 35250's trigger device does not exist on the box |
| **win32k console path** | `ConsoleWindow` compiled out of the console's win32kbase → 21882 unreachable |
| **WOW64** | x64-only → 38054's thunk path dead code |
| **IoRing surface** | 1709+ addition → 21768 structurally absent |
| **Persisted kernel exec** | No primitive = no post-exploitation (kCFG absent would have made it easy — confirmed via KernelSight) |
| **Runtime config hives** | The dump has no `config\` — per-service SYSTEM attributions are class-defaults, not confirmed |

---

## 3. Same-era Windows 10 CVEs — tested and why they don't apply

All of these were triaged against the **console's own binaries** (not patched builds, not documentation): dispatch tables walked, import tables swept, strings searched, and — where the surface existed — live ioctl probes from the seat.

### CVE-2023-21768 — afd `AfdNotifyRemoveIoCompletion` missing ProbeForWrite (kernel RCE, ITW)
**Tested:** static opcode scan of the console afd + the notify-socket ioctl (0x1201B) probe.
**Why not:** the notify/IoRing socket family was added in **1709**; the 15063 dispatch table ends at 0x12123 with zero notify-family entries. **STRUCTURAL** — the code doesn't exist on this build.

### CVE-2023-28218 — afd `AfdComputeCMSGLength`/`AfdCopyCMSGBuffer` integer overflow (EoP, ITW)
**Tested:** the most thorough campaign lane — 38 builds, 12+ console runs (P17–P37): the input model measured against a live host's patched afd, the 12-byte cmsg-header semantics derived, the TDI transport-address paint decoded, the overflow length walked to the faulting gate.
**Why not:** the copy path requires the **FastIoDispatch** table (the RS2 afd has none — the fast path was added later), and the small-path variant is bounded/self-healing (the inline `ControlLength` root cause). The overflow writes land in a lookaside-reuse slot that self-corrects. **STRUCTURAL-UNREACHABLE** — real bug, real write site, but the console's afd shape makes the corruption unusable.

### CVE-2024-38054 — ksthunk `KSSTREAM_HEADER` WOW64 thunk integer overflow (EoP)
**Tested:** the mskssrv/ksthunk lane from the P30–P37 S-probes + the dump.
**Why not:** the vulnerable code is the **WOW64 thunk** (32-bit process → 64-bit kernel). The console is x64-only; **WOW64 is absent**, the thunk is dead code. Also the device never instantiated from the seat. **UNREACHABLE.**

### CVE-2025-32709 — afd use-after-free after socket closure (EoP, ITW)
**Tested:** the dispatch-table audit + the zeropath writeup (flagged AI-generated, discounted; verdict rests on the binary).
**Why not:** the closure-UAF needs the notify/io-completion ioctls (0x12127+) — same 1709+ family as 21768. Absent. **STRUCTURAL-UNREACHABLE.**

### CVE-2025-60719 — afd use-after-free, unbind-vs-get-info race (EoP, ITW, public PoC)
**Tested:** the deepest lane. Static: the unbarriered body 0x53f7c–0x54034 decoded, the fix (AfdPreventUnbind/AfdReallowUnbind) confirmed absent on 15063. Live: the twin PoC **bugchecked the twin twice (BUGCHECK 0x3B)** — the UAF is genuinely live on this kernel generation. Then the console: P42 crashed the console in the same place, P45–P46 mapped the real unbind (0x12117 → handler 0x46800), and the run matrix showed:
**Why not:** the unbind handler accepts **only the 0xaafd endpoint class**; afd assigns the console-visible sockets the **0xafd0 class**. The class flips only when the open packet's deciding field is zero — and every reachable open path (ws2_32-created, EA-painted) yields 0xafd0. **STRUCTURAL-UNREACHABLE** — the bug is real (twin-verified), the console's socket-class wall blocks the trigger. This is the closest we came: a live UAF, one class-check away.

### CVE-2024-38193 — afd RIO buffer dereg-vs-in-flight UAF (EoP, Lazarus ITW)
**Tested:** the full RIO surface walk (P47–P60). The pre-fix deregistration shape (`lock xadd [rcx+0x18],-1; cmp eax,1; je free` with **no in-flight reference**) is present in-binary at 0x8050; the RIO provider (mswsock) ships with both EA names and the WSAID_MULTIPLE_RIO GUID; the winsock catalog is complete.
**Why not:** every path to instantiate a RIO socket dies at the transport. `WSASocketW(…, WSA_FLAG_REGISTERED_IO)` succeeds but the extension fetch returns **WSAEOPNOTSUPP (10045)**; the raw `NtCreateFile` EA-open with the exact mswsock paint gets past the EA validator only to hit **ACCESS_DENIED** — decoded to the afd's transport-open failing (`\\Device\Tcp` open fails). **The direct probe (P60/T1) confirmed: `\\Device\Tcp` = ACCESS_DENIED from the AppContainer seat.** The transport wall kills the RIO lane at delivery. **STRUCTURAL-UNREACHABLE** (the pre-fix bug is in-binary and twin-reachable in principle; the console's seat cannot open the transport).

### CVE-2022-21882 — win32k ConsoleWindow/WndExtra type confusion (EoP, ITW)
**Tested:** string + code-path audit of the console's win32kbase.sys (15063.3054, the pre-patch build).
**Why not:** the console-subsystem code path is **compiled out** — zero `ConsoleWindow` strings; the only "Console" strings are remote-shadow registration keys. `NtUserConsoleControl`'s vulnerable path doesn't exist in this build's binary. **STRUCTURAL-UNREACHABLE** (compiled-out, not patched-out).

### CVE-2024-35250 — ks.sys untrusted pointer, IOCTL_KS_PROPERTY UnserializePropertySet (EoP, Pwn2Own/ITW)
**Tested:** full static decode of the console's ks.sys (`541d6a16`) — KspPropertyHandler at 0x23040, the UNSERIALIZESET (0x1000) branch present, the probe-guard decodes to *skip-the-probe-for-user-mode-requests* (the bug, verbatim), KsSynchronousIoControlDevice at 0x29ed0 with 22 callers, the DRM-propset GUID present, the KB5039212 fix absent. The public PoC exists and was ported.
**Why not:** the trigger device — the **DRM-descrambler KS filter** — never instantiates on the console because **`drmk.sys` is absent** from the image. The twin (clean 1703 VBox, zero media devices) reproduced the wall: `KsOpenDefaultDevice(KSCATEGORY_DRM_DESCRAMBLE)` → `0x80070103` (ERROR_NO_MORE_ITEMS). The vulnerable code is real and in-binary; the device it rides on does not exist. **STRUCTURAL-UNREACHABLE.** (Note for the future: the bug is in the *generic* property handler — any instantiated KS filter would do; a live-filter enumeration from a reachable seat would reopen this.)

### CVE-2024-29050 — cryptsvc numeric truncation in cert import (RCE) — **OPEN**
Static: the vulnerable decode path (`CryptDecodeObject`, type `X509_CRL_DIST_POINTS`) is present in the console's crypt32 (byte-identical to ISO 1703). A public PoC exists (~10 lines). The delivery sweep found 20 importers including edgehtml/mshtml/wininet (delay-imported — the seat itself can trigger the chain-build → cryptnet fetch → decode) and cryptsvc (SYSTEM, the best pivot). The console auto-fetches trust-list cabs (`disallowedcertstl.cab`, `pinrulesstl.cab`) from `ctldl.windowsupdate.com` in SYSTEM context — a natural shaped-input channel. **Not yet tested live** — this is the active lead.

### CVE-2020-0601 — crypt32 ECC "Curveball" chain-engine trust flaw — **OPEN**
Static: the console's crypt32 = pre-Feb-2020 = the vulnerable chain logic present and unpatchable; byte-identical to ISO 1703 so desktop knowledge transfers. The model (corrected): Curveball = **signing**, not interception — the rogue-CA (real issuer's AKI key-id + own generator point) makes the console's **local** validators accept chains we sign (package/update/device-assoc chains). The MITM+TLS-leak = the delivery channel (already in hand). **Not yet tested live.**

---

## 4. The pattern (why the console closed so many lanes)

The 15063 console binaries are **code-identical to the desktop's** (afdd/crypt32/ks verified byte-identical .text). The bugs are present. What closes the lanes is **system shape**, not patch level:

1. **The 1709+ surface doesn't exist** (21768, 32709) — the ioctls were added after this build.
2. **The RS2-era shapes differ** (28218's FastIoDispatch, the inline ControlLength).
3. **The optional components aren't there** (WOW64, drmk.sys, the console subsystem in win32k, `\\Device\Tcp` from AppContainer).
4. **The class/object checks bite** (60719's 0xaafd vs 0xafd0 endpoint classes).

The KernelSight cross-check confirms the flip side: with no kCFG/kCET/HLAT/VBS, **if** a kernel primitive lands, nothing stands in the way of the exploit — the walls are all at the *trigger* layer, not the *post-exploitation* layer.

## 5. What would change the verdict

- **Any instantiated KS filter reachable from a seat** → 35250 reopens (generic property handler bug).
- **A seat-visible 0xaafd-class endpoint** (the deciding-field-zero open path) → 60719 reopens with the proven twin recipe.
- **A transport-bypassing RIO socket instantiation** → 38193 reopens (the pre-fix dereg is in-binary).
- **The 29050/0601 lanes** → the active leads; the twin PoC work is in progress (the other agent).

---
