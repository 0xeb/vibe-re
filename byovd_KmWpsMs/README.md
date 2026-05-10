# KmWpsMs.sys — NcHost

Client library and demo for **KmWpsMs.sys**, a vulnerable Windows kernel
driver from NComputing vSpace Multi-User Station software that exposes
arbitrary physical memory read/write primitives to usermode through IOCTLs.

| | |
|---|---|
| **Device** | `\\Device\\NcHost` (`\\.\NcHost`) |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `0c488b536a5df62166894d1e89b39c9a` |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |
| **Product** | NComputing vSpace 12.1.0.0 |

## What It Does

The driver creates `\\Device\\NcHost` (device type `FILE_DEVICE_UNKNOWN`,
0x22) and exposes approximately 70 `METHOD_NEITHER` IOCTLs for NComputing
multi-user station management.  Among these are two critically vulnerable
IOCTLs that provide unguarded physical memory access:

| IOCTL | Code | Input | Description |
|-------|------|-------|-------------|
| Read physical | `0x2221A4` | 0x18 bytes | Reads physical memory via `MmGetVirtualForPhysical` / `MmMapIoSpace` |
| Physical ops | `0x2221DC` | 0x30 bytes | Multi-subcommand: VA-to-PA translation, physical read/write, MDL alloc/map/free |

No caller validation, no access checks, no `ProbeForRead`/`ProbeForWrite`.

### Vulnerable IOCTL Details

**IOCTL 0x2221A4 (Read Physical Memory)**

Takes a 0x18-byte input buffer whose first 8 bytes are a physical address.
Uses `MmGetVirtualForPhysical` (fast path) or `MmMapIoSpace` (fallback)
to map the page, then copies `OutputBufferLength` bytes back to the caller.

**IOCTL 0x2221DC (Physical Operations)**

Multi-subcommand interface keyed by a 0x4641 ("AF") magic signature and
a 2-byte subcommand selector:

| Subcmd | Operation | Kernel API |
|--------|-----------|------------|
| 1 | Virtual to physical translation | `MmGetPhysicalAddress` |
| 2 | Write to physical memory | `MmMapIoSpace` + MDL copy |
| 3 | Allocate & lock MDL (kernel) | `IoAllocateMdl` + `MmProbeAndLockPages` |
| 4 | Copy between MDL regions | MDL-to-MDL `memcpy` |
| 5 | Allocate & lock MDL (user) | `IoAllocateMdl` + `MmProbeAndLockPages` |
| 6 | Map locked pages (kernel) | `MmMapLockedPages(KernelMode)` |
| 7 | Map locked pages (user) | `MmMapLockedPages(UserMode)` |
| 8 | Free MDL resources | `MmUnmapLockedPages` + `MmUnlockPages` + `IoFreeMdl` |

## Driver Binary

The signed driver binary can be obtained from
[KeServiceDescriptorTable/vulnerable-drivers](https://github.com/KeServiceDescriptorTable/vulnerable-drivers).

## Build

```
cmake -B build -G "Visual Studio 17 2022"
cmake --build build --config Release
```

## Client API

```c
#include "nchost.h"

NCHOST ctx;
nchost_open(&ctx);

// Read physical memory
UCHAR buf[0x100];
nchost_read_physical(&ctx, 0x1000, buf, sizeof(buf));

// Translate VA -> PA
UINT64 phys;
nchost_get_physical_addr(&ctx, (UINT64)some_ptr, &phys);

// Write to physical memory
UINT64 val = 0x41414141;
nchost_write_physical(&ctx, phys, &val, sizeof(val));

nchost_close(&ctx);
```

The read/write functions automatically loop across page boundaries.

## Demo

```
nchost_demo.exe [phys_addr_hex]
```

1. Opens `\\.\NcHost`
2. Queries the driver version (0x20041021)
3. Reads and hex-dumps physical memory at the given address
4. Translates a local variable's VA to PA and verifies round-trip
5. Self-test: writes a value to its own physical memory, reads
   it back, verifies the round-trip

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed
by NComputing, Windows loads it without complaint.  Once loaded, any
unprivileged process can:

- **Dump credentials** from `lsass.exe` without triggering PPL
- **Blind EDR agents** by patching their hooks in physical memory
- **Inject code** into arbitrary processes via physical writes
- **Read/write kernel structures** (EPROCESS, callbacks, etc.)
- **Bypass PatchGuard** by operating at the physical level

Mitigations: HVCI, Microsoft's vulnerable driver blocklist, and
driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
