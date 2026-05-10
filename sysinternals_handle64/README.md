# Auditing the Process Explorer Kernel Driver (PROCEXP152.sys)

A security audit of the Microsoft-signed PROCEXP152.sys kernel driver, extracted from Sysinternals handle64.exe. This writeup documents the full reverse engineering of both handle64.exe and its embedded kernel driver, a per-IOCTL security assessment, confirmed exploitation primitives, and a standalone client tool that exercises all 16 IOCTLs — including dumping the live ntoskrnl.exe image from kernel memory.

All analysis was performed using [GhidraSQL](https://github.com/0xeb/ghidrasql), a SQL interface for Ghidra that enables query-driven reverse engineering.

> **Disclaimer**: This research is for defensive security analysis and education only. All testing was performed on the author's own system. The PROCEXP152.sys driver is publicly available and Microsoft-signed — it ships with every copy of Process Explorer and Sysinternals Handle.

---

## Why This Driver Matters

PROCEXP152.sys is a **Microsoft-signed kernel driver** present on millions of machines. It loads without test signing, without kernel debugging, without any boot configuration changes. Any administrator with `SeDebugPrivilege` can open a handle to `\\.\PROCEXP152` and issue IOCTLs that:

- Read 16+ MB of live kernel memory (the entire ntoskrnl image)
- Enumerate handles in Protected Process Light (PPL) processes like lsass.exe
- Bypass DACL-based process access restrictions
- Defeat KASLR with exact ntoskrnl base address and all internal offsets
- Force-close handles in any process on the system

The driver was designed for Process Explorer's legitimate introspection needs. This audit examines what else those primitives can do.

The single biggest finding: **you can dump the entire live ntoskrnl.exe image** (~16 MB of kernel code, data, and globals) through a single IOCTL on a stock Windows system with no special setup. That dump contains the SSDT, `PsActiveProcessHead`, `PsLoadedModuleList`, `KiProcessorBlock`, and every other kernel global — live, with runtime values. We confirmed this by diffing the dump against the on-disk binary and discovering Windows boot-time retpoline patches (KRIO) that aren't visible from the static file alone.

**Signature chain**: Microsoft Windows Hardware Compatibility Publisher &rarr; Microsoft Windows Third Party Component CA 2014 &rarr; Microsoft Root Certificate Authority 2010.

---

## Methodology

The entire analysis was done through **GhidraSQL** — two concurrent headless Ghidra instances exposing SQL virtual tables over HTTP:

- **Port 8081**: handle64.exe (1,969 functions, 38 renamed, 18 signatures set, 8 plate comments)
- **Port 8082**: PROCEXP152.sys (68 functions, 25 renamed, fully annotated)

The workflow: import binary &rarr; auto-analyze &rarr; query via SQL &rarr; decompile functions &rarr; annotate with `UPDATE`/`INSERT` statements &rarr; save. No GUI, no clicking — everything driven by HTTP `POST /query` with SQL statements.

Key GhidraSQL queries used:
```sql
-- Decompile a function
SELECT text FROM pseudocode WHERE func_addr = 0x180001AE0;

-- Rename a function
UPDATE funcs SET name = 'IoctlDispatch' WHERE address = 0x180001AE0;

-- Find string references
SELECT func_name, string_value FROM string_refs WHERE func_name = 'MainHandleProcessor';

-- Set a function signature
UPDATE funcs SET signature = 'int IoctlDispatch(void *FileObject, int CallerMode, ...)' WHERE address = 0x180001AE0;

-- Save the database
SELECT save_database();
```

The driver was extracted from handle64.exe's PE resources using a Python script (see `scripts/extract_driver.py`), then loaded into a second GhidraSQL instance for independent analysis.

---

## handle64.exe — The Carrier

### What It Does

Sysinternals Handle is a command-line tool that enumerates all open OS handles (files, registry keys, sections, threads, etc.) across every process. It finds which process has a file locked, searches handles by name, and can force-close handles.

```
usage: handle [[-a [-l]] [-u] | [-c <handle> [-y]] | [-s]] [-p <process>|<pid>] [name] [-nobanner]
```

### Architecture

```
wmain (0x140005E90)
 +-- PrintBanner("Handle")
 +-- CheckAcceptEula()           <- registry: EulaAccepted, or -accepteula flag
 +-- ResolveNtApis()             <- LoadLibrary ntdll/kernel32 + GetProcAddress
 +-- ParseCommandLine()          <- -a, -c, -l, -p, -s, -u, -y, name/file args
 +-- MainHandleProcessor()
      +-- EnablePrivilege("SeDebugPrivilege")
      +-- LoadDriver("PROCEXP152")      <- extract from resources, install via SCM
      +-- NtQuerySystemInformation(SystemHandleInformation)  <- get ALL handles
      +-- for each handle:
      |    +-- ResolveTypeName()         <- type index -> "File", "Key", etc.
      |    +-- NtQueryObject()           <- get NT object path via driver
      |    +-- TranslateRegistryPath()   <- \REGISTRY\MACHINE\ -> HKLM\
      |    +-- TranslateDevicePath()     <- \Device\HarddiskVolumeN\ -> C:\
      |    +-- ApplyFilters() + Print
      +-- (if -c) CloseHandle via driver IOCTL
```

### NT API Dynamic Resolution (0x140004720)

handle64.exe statically links the CRT (no import table). It dynamically resolves these undocumented APIs from ntdll.dll:

| API | Purpose |
|-----|---------|
| `NtQuerySystemInformation` | Enumerate all system handles |
| `NtQueryObject` | Get handle name and type |
| `NtQueryInformationProcess/Thread` | Process and thread details |
| `NtQuerySection` | Section (mapped file) info |
| `NtOpen/QueryDirectoryObject` | Object namespace traversal |
| `NtOpen/QuerySymbolicLinkObject` | Resolve symlinks |
| `FindFirstFileNameW/FindNextFileNameW` | NTFS hardlink enumeration |

### Command-Line Parsing (0x140005540)

| Flag | Global | Meaning |
|------|--------|---------|
| `-a` | `DAT_140080be0` | Show all handle types |
| `-c` | `DAT_140080be4` | Close handle (hex value) |
| `-l` | `DAT_140080be1` | Show section names |
| `-p` | `DAT_140080cf8` / `DAT_140082760` | Filter by PID or name |
| `-s` | `DAT_140080be3` | Summary mode |
| `-u` | `DAT_140080be8` | Show owning user |
| `-y` | `DAT_140080be9` | Auto-confirm close |

Non-flag arguments trigger NTFS hardlink resolution via `FindFirstFileNameW` — all hardlinks are collected into a linked list and any match counts.

---

## Driver Extraction

The driver is embedded as a PE resource:

| Property | Value |
|----------|-------|
| Resource type | `BINRES` (custom type name) |
| Resource ID | 0x67 (103 decimal) |
| Size | 36,424 bytes |
| Format | PE32+ x64 kernel driver |
| PDB path | `C:\agent\_work\105\s\modules\procexp\sys\x64\Release\ProcExpDriver.pdb` |
| Version | 16.27 |

Extraction is straightforward — parse the `.rsrc` section, find `BINRES/103/1033`, copy the data:

```python
python scripts/extract_driver.py handle64.exe PROCEXP152.sys
# Output: Extracted 36424 bytes to PROCEXP152.sys
#         Valid PE (MZ header confirmed)
```

handle64.exe extracts it to `%SystemRoot%\System32\Drivers\PROCEXP152.sys`, then loads it via the Service Control Manager:
```c
CreateServiceW(hSCM, L"PROCEXP152", ..., SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START, ..., sysPath);
StartServiceW(hSvc, 0, NULL);
```

---

## User-Mode to Kernel Communication

handle64.exe communicates with the driver via `DeviceIoControl` on `\\.\PROCEXP152`. All IOCTLs use `METHOD_BUFFERED` — the I/O manager allocates a system buffer, copies user input into it, the driver reads/writes the same buffer, and the I/O manager copies the result back.

The IOCTL codes use device type `0x8335` with `FILE_ANY_ACCESS`:
```c
#define IOCTL_CODE  CTL_CODE(0x8335, function, METHOD_BUFFERED, FILE_ANY_ACCESS)
// Produces codes: 0x83350000, 0x83350004, 0x83350008, ...
```

The primary flow for handle enumeration:
1. User mode: `NtQuerySystemInformation(SystemHandleInformation)` &rarr; gets PID, handle value, object pointer, type index for every handle
2. For each handle: `DeviceIoControl(IOCTL_PROCEXP_QUERY_OBJECT_NAME_UNICODE, &request)` &rarr; driver attaches to target process, resolves the handle, returns the NT object path
3. User mode: translates `\Device\HarddiskVolume3\...` to `C:\...` and `\REGISTRY\MACHINE\...` to `HKLM\...`

---

## PROCEXP152.sys — Driver Architecture

### DriverEntry (0x1800015D0)

1. Checks OS build number via `PsGetVersion` — rejects builds before Windows XP SP2 (< 0xA28)
2. Dynamically resolves optional kernel APIs via `MmGetSystemRoutineAddress`:
   - Vista+ (build 6000+): `PsAcquireProcessExitSynchronization`, `PsReleaseProcessExitSynchronization`, `MmGetMaximumNonPagedPoolInBytes`
   - Win7+ (build 7600+): `ObGetObjectType`
3. Resolves the `Mutant` kernel object type via `\ObjectTypes\Mutant`
4. Creates `\Device\PROCEXP152` with SDDL security descriptor via `WdmlibIoCreateDeviceSecure`
5. Creates symlink `\DosDevices\PROCEXP152`
6. Sets IRP dispatch:
   - `IRP_MJ_CREATE` / `IRP_MJ_CLOSE` / `IRP_MJ_DEVICE_CONTROL` &rarr; `IrpDispatch` (0x180002220)
   - `DriverUnload` &rarr; `DriverUnload` (0x180003280)

### Security Gate

`IrpDispatch` checks `SeDebugPrivilege` on every `IRP_MJ_CREATE`. Only callers with debug privilege can open the device. Once the device handle is obtained, **all IOCTLs are available with no further access checks**.

```c
// From decompiled IrpDispatch:
case IRP_MJ_CREATE:
    privSet.Privilege[0].Luid.LowPart = 0x14;  // SE_DEBUG_PRIVILEGE
    SeCaptureSubjectContext(&subjCtx);
    result = SePrivilegeCheck(&privSet, &subjCtx, ExGetPreviousMode());
    if (!result) status = STATUS_PRIVILEGE_NOT_HELD;
```

### Build-Dependent ETHREAD Offsets

The driver reads undocumented ETHREAD fields that change between Windows versions:

| Build | Windows Version | Offset |
|-------|----------------|--------|
| 0xECE (3790) | Server 2003 | +0x38 |
| < 6000 | XP/2003 variants | +0x48 |
| < 0x23F0 (9200) | Vista/7 | +0x38 |
| >= 0x23F0 | Win8+ | +0x58 |

---

## IOCTL Attack Surface — All 16 IOCTLs

### Handle Operations

| Code | Name | Input | Output | PPL Bypass | Security |
|------|------|-------|--------|-----------|----------|
| `0x83350000` | QueryObjectName (ANSI) | 0x20: PID+handle+objptr | flags+ANSI name | Yes | `PsLookupProcessByProcessId` bypasses PPL; object pointer verified against kernel's own `ObReferenceObjectByHandle` |
| `0x83350048` | QueryObjectName (Unicode) | 0x20 | flags+Unicode name | Yes | Same as above |
| `0x83350040` | QueryFileName (ANSI) | 0x20 | ANSI name | Yes | Uses `ZwQueryObject` while attached to target context |
| `0x8335004C` | QueryFileName (Unicode) | 0x20 | Unicode name | Yes | Same |
| `0x83350004` | CloseHandle | 0x20 | none | Partial | `ZwDuplicateObject(DUPLICATE_CLOSE_SOURCE)` — atomically closes handle in target |

### Process/Thread Introspection

| Code | Name | Input | Output | Security |
|------|------|-------|--------|----------|
| `0x8335000C` | OpenProcessToken | 8: handle | 8: token handle | Handle validated by `ObReferenceObjectByHandle` |
| `0x83350014` | OpenObjectByPointer | 0x20: PID | 8: handle | `PsLookupProcessByProcessId` (bypasses PPL) but returns `OBJ_KERNEL_HANDLE` |
| `0x83350028` | QueryThreadInfo | 8: thread handle | 0x18: start+TEB+addr | Handle validated with `PsThreadType` |
| `0x8335002C` | QueryMutantOwner | 8: mutant handle | 8: thread handle | Handle validated with Mutant type |
| `0x83350034` | QueryProcessPriority | 8: process handle | 4: I/O priority | Handle validated with `PsProcessType` |
| `0x8335003C` | OpenProcessByPID | 8: PID | 8: process handle | `ZwOpenProcess` with UserMode PreviousMode — PPL still blocks |

### System Queries

| Code | Name | Input | Output | Security |
|------|------|-------|--------|----------|
| `0x83350008` | VersionCheck | 4: version | 4: 0x98 | Constant exchange |
| `0x83350024` | QuerySystemMemory | 0x10 | variable | Proxies `ZwQuerySystemInformation` |
| `0x83350050` | GetMaxNonPagedPool | none | 8: pool size | Calls `MmGetMaximumNonPagedPoolInBytes` |

### Exploitable Primitives

| Code | Name | Input | Output | Vulnerability |
|------|------|-------|--------|--------------|
| **`0x83350020`** | **ReadObjectField** | **8: raw kernel ptr** | **8: value at ptr+0x20** | **Raw pointer dereference — 4-byte magic gate only** |
| **`0x83350044`** | **ReadKernelMemory** | **8: kernel addr** | **variable: memory** | **Full read within ntoskrnl's mapped image** |

---

## Exploitable Primitive 1: Raw Pointer Dereference (0x83350020)

### Decompiled Logic

```c
case 0x83350020:
    ptr = *(void **)SystemBuffer;                    // user controls this pointer
    if (*(USHORT*)ptr == 5 && *(USHORT*)(ptr+2) == 0xD8) {  // FILE_OBJECT tag check
        *(ULONGLONG*)SystemBuffer = *(ULONGLONG*)(ptr + 0x20);  // return 8 bytes
    }
```

The driver takes an 8-byte pointer from user input and **directly dereferences it in kernel space**. The only validation is that the first 4 bytes at that address must be `05 00 D8 00` (the FILE_OBJECT type/size tag). No `ObReferenceObjectByHandle`, no pool validation.

### What You Can Do

- **Read FILE_OBJECT.SectionObjectPointer** for any file handle in the system. FILE_OBJECT addresses are known from `NtQuerySystemInformation(SystemHandleInformation)`.
- **Scan ntoskrnl for natural occurrences** of the byte pattern `05 00 D8 00` and read 8 bytes at each hit + 0x20.

### What You Can't Do

We scanned the entire 16.3 MB live ntoskrnl image. Only 4 occurrences of `05 00 D8 00` exist — all in code sections (instruction encodings), returning garbage at +0x20. No usable stepping stones for chained reads. EPROCESS has type tag 3 (not 5), so kernel process structures can't be read through this primitive.

---

## Exploitable Primitive 2: ntoskrnl Image Read (0x83350044)

### Decompiled Logic

```c
case 0x83350044:
    // Query SystemModuleInformation — stack layout trick:
    // local_120 overlaps Modules[0].ImageBase at buffer+0x18
    // local_118 overlaps Modules[0].ImageSize at buffer+0x20
    ZwQuerySystemInformation(SystemModuleInformation, stackBuf, 0x130);

    srcAddr = *(PVOID *)SystemBuffer;
    readLen = OutputBufferLength;

    // Three-check range validation (verified from disassembly)
    if (srcAddr >= ntoskrnl_base &&
        srcAddr <= ntoskrnl_base + ntoskrnl_size &&      // ← check 2: kills overflow
        srcAddr + readLen <= ntoskrnl_base + ntoskrnl_size) {
        memcpy(SystemBuffer, srcAddr, readLen);
    }
```

### What You Can Read

ntoskrnl.exe is typically 10-20 MB. The mapped image includes:

| Section | Contents | Security Value |
|---------|----------|---------------|
| `.text` | All syscall implementations | Full kernel code |
| `.rdata` | SSDT pointers, type info | SSDT dump |
| `.data` | **Writable globals** | `PsActiveProcessHead`, `PsInitialSystemProcess`, `PsLoadedModuleList`, `KiProcessorBlock`, `ObTypeIndexTable`, `KeServiceDescriptorTable`, `KdDebuggerEnabled`, `NtGlobalFlag` |
| `PAGE*` | Pageable kernel code | Additional code sections |

### Confirmed: Full ntoskrnl Dump

```
> procexp_client ntinfo
ntoskrnl:
  Module:    ntoskrnl.exe
  Base:      0xFFFFF8077F400000
  Size:      0x1045000 (16660 KB)

> procexp_client ntread FFFFF8077F400000 64
  FFFFF8077F400000  4D 5A 90 00 03 00 00 00 ...  MZ......

> procexp_client ntdump ntoskrnl_live.bin
Done: 16660 KB dumped, 0 page errors
```

### Integer Overflow Analysis (Verified from Disassembly)

The range check compiles to three separate `CMP`/`Jcc` gates:

```asm
; Setup: rcx = ntoskrnl_base + ntoskrnl_size (upper bound)
mov  ecx, [rbp-0x20]          ; ecx = ntoskrnl_size (32-bit, zero-extended)
add  rcx, [rbp-0x28]          ; rcx = upper_bound

mov  rdx, [r14]               ; rdx = srcAddr (attacker-controlled)

cmp  rdx, [rbp-0x28]          ; CHECK 1: srcAddr < ntoskrnl_base?
jb   REJECT

cmp  rdx, rcx                 ; CHECK 2: srcAddr > upper_bound?
ja   REJECT                   ;   ← THIS KILLS OVERFLOW ATTEMPTS

mov  r14d, [rbp+0x128]        ; r14d = readLen (32-bit, zero-extended)
lea  rax, [r14 + rdx]         ; rax = srcAddr + readLen (64-bit, CAN wrap)

cmp  rax, rcx                 ; CHECK 3: srcAddr + readLen > upper_bound?
ja   REJECT
```

The `LEA` at `0x180001E6B` performs a 64-bit add that CAN mathematically wrap. But check 2 constrains `srcAddr <= upper_bound` BEFORE the addition. Any `srcAddr` high enough to cause a wrap (e.g., `0xFFFFFFFFFFFFFFF0`) exceeds ntoskrnl's end address (~`0xFFFFF807'80445000`) and is rejected by check 2. **The three-check pattern is watertight.**

---

## Confirmed Capabilities

| Capability | IOCTL | Verified |
|-----------|-------|----------|
| Full ntoskrnl image dump (16.3 MB) | 0x83350044 | Yes — dumped, diffed |
| Read ntoskrnl .data globals | 0x83350044 | Yes |
| KASLR full defeat | 0x83350044 + NtQSI | Yes |
| SSDT dump | 0x83350044 | Feasible |
| Enumerate handles in PPL processes | 0x83350000 | Yes — lsass 1,969 handles |
| Resolve handle names in any process | 0x83350000/48 | Yes |
| Close handles in any process | 0x83350004 | Available |
| Read FILE_OBJECT fields for any file | 0x83350020 | Feasible |
| Process token/priority for any PID | 0x8335000C/34 | Yes |
| Thread start address + TEB | 0x83350028 | Available |
| Detect kernel code patching | 0x83350044 + diff | Yes — found retpoline |
| Live kernel integrity check | 0x83350044 + diff | Yes |

---

## Live Kernel Diff: Retpoline Discovery

We dumped the live ntoskrnl and compared it section-by-section against `C:\Windows\System32\ntoskrnl.exe`, accounting for ASLR relocations.

### Results

| Section | Bytes | Genuine Diffs | Cause |
|---------|-------|--------------|-------|
| `.text` | 3,980,169 | 7,645 (0.19%) | Retpoline patches |
| `PAGE` | 3,944,342 | 1,581 (0.04%) | Retpoline patches |
| `PAGELK` | 150,596 | 111 (0.07%) | Retpoline patches |
| `PAGEKD` | 23,442 | 208 (0.89%) | Retpoline patches |
| `.data` | 77,824 | 4,484 (14.9%) | Live globals (expected) |
| `INIT` | 567,064 | 532,317 (97%) | Discarded after boot (expected) |
| `.pdata` | 424,260 | 0 | Identical |

The code section diffs are exclusively **Kernel Retpoline Import Optimization (KRIO)** — the Windows boot loader replaces indirect calls through the IAT:

```
Disk:  48 FF 15 xx xx xx xx       call [rip+disp]        ; indirect call
Live:  4C 8B 15 xx xx xx xx E8    mov r10,[rip+disp]     ; load target
       xx xx xx xx                call rel32              ; direct call
```

This is a Spectre v2 mitigation applied at boot. The core logic is identical — just the call mechanism changes.

The diff script (`scripts/diff_ntoskrnl.py`) handles relocation awareness, per-section comparison, and classifies diffs as relocation-induced vs genuine.

---

## Process Access Model

### Normal Processes

Standard `OpenProcess` + `ReadProcessMemory` works with admin + SeDebugPrivilege. No driver needed.

### DACL-Protected Processes

Some non-PPL processes restrict access via custom security descriptors:
- Processes calling `SetSecurityInfo` on themselves
- Services with restrictive DACLs
- EDR/AV-hooked `NtOpenProcess`

**Driver provides**: Full handle/name/thread introspection via `PsLookupProcessByProcessId` which bypasses DACLs entirely (direct kernel PID→EPROCESS lookup, no security descriptor check). But NO user-mode handle with `PROCESS_VM_READ` — can't `ReadProcessMemory`.

### PPL-Protected Processes (lsass.exe, csrss.exe, etc.)

`OpenProcess` returns `ACCESS_DENIED` regardless of privilege level.

**Driver provides**: Same as DACL — full introspection, no VM access. `PsLookupProcessByProcessId` + `KeStackAttachProcess` bypass PPL because they're kernel-internal operations with no protection-level check.

| Scenario | OpenProcess | Driver Introspection | ReadProcessMemory |
|----------|------------|---------------------|-------------------|
| Normal | Full access | Full | Yes (standard API) |
| DACL-restricted | Blocked | Full (bypasses DACL) | No |
| PPL-protected | ACCESS_DENIED | Full (bypasses PPL) | No |

---

## Write Primitive Analysis

**There is no arbitrary memory write IOCTL.** The driver is fundamentally read-only.

The only state-mutating operation is `CloseHandle` (0x83350004), which can be weaponized:
- Close a mutex → release lock → trigger race condition
- Close a file handle → force file unlock → modify protected file
- Close a section handle → invalidate mapping → crash target
- Close a registry key handle → disrupt configuration reads

The `memcpy` in IOCTL 0x83350044 copies FROM kernel TO user buffer, never the reverse.

---

## Limitations

| Capability | Why Not |
|-----------|---------|
| Arbitrary kernel pool read | 0x83350044 range-locked to ntoskrnl; 0x83350020 magic-gated |
| Read EPROCESS fields | EPROCESS type tag (3) ≠ required (5) |
| Walk page tables | Can't read CR3 from EPROCESS, can't read PTEs from pool |
| Process virtual memory | No VM read primitive in any IOCTL |
| Write kernel memory | No write IOCTL exists |
| Inject code | No code execution primitive |
| Bypass PPL for VM access | 0x8335003C uses UserMode PreviousMode |

---

## Function Reference

### handle64.exe (38 functions renamed)

| Address | Name | Role |
|---------|------|------|
| `0x140005E90` | wmain | Entry point |
| `0x140001050` | PrintBanner | Sysinternals banner |
| `0x1400020D0` | CheckAcceptEula | EULA argv scan |
| `0x1400022A0` | VerifyEulaAccepted | Registry check + prompt |
| `0x140004720` | ResolveNtApis | Dynamic ntdll/kernel32 resolution |
| `0x140005540` | ParseCommandLine | Argument parser |
| `0x1400031B0` | MainHandleProcessor | Core handle enumeration |
| `0x140002A30` | EnablePrivilege | SeDebugPrivilege |
| `0x140002F00` | LoadDriver | SCM driver install |
| `0x140004530` | QuerySystemHandles | NtQuerySystemInformation wrapper |
| `0x140003D30` | ResolveTypeName | Handle type index → name |
| `0x140005000` | TranslateRegistryPath | NT → HKLM/HKCU |
| `0x140004ED0` | TranslateDevicePath | \Device\ → drive letter |
| `0x140004B30` | GetProcessName | PID → name |
| `0x140004D00` | GetProcessUser | PID → username |
| `0x1400028C0` | PrintFormatted | Output |
| `0x140003160` | CloseRemoteHandle | NtDuplicateObject(CLOSE_SOURCE) |
| `0x140002B10` | ExtractDriverResource | PE resource extraction |

### PROCEXP152.sys (25 functions renamed)

| Address | Name | Role |
|---------|------|------|
| `0x1800015D0` | DriverEntry | Device creation, API resolution |
| `0x180003280` | DriverUnload | Delete symlink + device |
| `0x180002220` | IrpDispatch | CREATE/CLOSE/DEVICE_CONTROL handler |
| `0x180001AE0` | IoctlDispatch | Main IOCTL switch (16 cases) |
| `0x180002680` | QueryObjectName | Handle name resolution (core operation) |
| `0x180002B40` | QueryObjectNameFromFile | File name via ZwQueryObject |
| `0x180002320` | QueryFileNameFromObject | FILE_OBJECT field extraction |
| `0x180001A20` | CloseHandleInProcess | Remote handle close |
| `0x180001950` | OpenProcessHandle | Open process by pointer |
| `0x180002500` | QueryThreadInfo | Thread TEB + start address |
| `0x1800025E0` | QueryMutantOwner | Mutant owner thread |
| `0x180002E40` | LookupObjectType | \ObjectTypes\<name> resolution |
| `0x180002FF0` | QueryProcessPriority | Process I/O priority |
| `0x1800032F0` | ReopenHandleAsKernelHandle | User → kernel handle |
| `0x180003370` | QuerySystemModuleInfo | ZwQuerySystemInformation wrapper |
| `0x180003560` | DetachAndDereference | Cleanup helper |

---

## The Client: procexp_client

A standalone C program that exercises all 16 driver IOCTLs. Builds with CMake + MSVC (no WDK needed for the client — only for recompiling the driver source).

### Build

```bash
cd src
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
# Output: build/client/Release/procexp_client.exe
```

### Commands

**Driver lifecycle:**
```
procexp_client install <path-to-PROCEXP152.sys>
procexp_client uninstall
```

**Handle operations:**
```
procexp_client version                    # Protocol handshake (returns 0x98)
procexp_client pool                       # Max non-paged pool size
procexp_client process <pid>              # Open process, show priority + token
procexp_client query <pid> <handle-hex>   # Resolve single handle name
procexp_client close <pid> <handle-hex>   # Force-close a remote handle
procexp_client enum [-p pid] [-s] [-a] [-n name]   # System-wide handle enumeration
```

**Research primitives:**
```
procexp_client ntinfo                     # ntoskrnl base address and size
procexp_client ntread <addr-hex> [len]    # Read kernel memory (hex dump)
procexp_client ntdump <outfile>           # Dump entire ntoskrnl to file
procexp_client objread <ptr-hex>          # Read object field via raw deref
```

### Example Session

```
> procexp_client version
Driver protocol version: 0x98

> procexp_client ntinfo
ntoskrnl:
  Module:    ntoskrnl.exe
  Base:      0xFFFFF8077F400000
  Size:      0x1045000 (16660 KB)

> procexp_client ntread FFFFF8077F400000 64
  FFFFF8077F400000  4D 5A 90 00 03 00 00 00 ...  MZ......
  FFFFF8077F400010  B8 00 00 00 00 00 00 00 ...  ........

> procexp_client enum -p 872 -s
Total handles in snapshot: 108582
Handle type summary:
  Type  16: 231
  Type  19: 791
  Type  37:  30
  Type  44: 152
  Type  46: 141
  ...
Total: 1969 handles
```

The `enum -p 872` command enumerates all 1,969 handles in lsass.exe (PID 872) — a PPL-protected process that returns `ACCESS_DENIED` from user-mode `OpenProcess`.

---

## Source Layout

```
sysinternals_handle64/
├── README.md              This article
├── .gitignore             Excludes binaries, builds, Ghidra projects
├── scripts/
│   ├── extract_driver.py  Extract PROCEXP152.sys from handle64.exe resources
│   └── diff_ntoskrnl.py   PE section differ (live vs on-disk, relocation-aware)
└── src/
    ├── CMakeLists.txt      Top-level build (client + optional driver)
    ├── common/
    │   └── procexp_shared.h   Shared IOCTL codes, structures, flags
    ├── client/
    │   ├── CMakeLists.txt
    │   ├── main.c             CLI with all commands
    │   ├── drvclient.c        IOCTL wrapper library
    │   └── drvclient.h        Library API
    └── driver/
        ├── CMakeLists.txt     Requires WDK 10
        ├── procexp.c          Reconstructed driver source (all 16 IOCTLs)
        └── procexp.h          Driver-private header
```

## License

Licensed under the [BSD 3-Clause License](../LICENSE).
