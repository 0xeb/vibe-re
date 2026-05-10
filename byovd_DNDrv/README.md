# DNDrv.sys — DNDrv

Client library and demo for **DNDrv.sys**, a vulnerable Windows kernel driver
based on VirtualBox Support Driver (VBoxDrv/SUPDrv, version 4.3.12).  Exposes
the full SUPR0 kernel API surface to usermode through IOCTLs — arbitrary kernel
memory allocation, ring-0 module loading, VM execution, and physical page
mapping — with no caller validation.

| | |
|---|---|
| **Device** | `\\Device\\DNDrv` (`\\.\DNDrv`) + `\\Device\\DNDrvU` |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `d31c9e4b1aa80d922bfb10b0c780fe2c` |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |
| **Origin** | VBoxDrv/SUPDrv 4.3.12 (`C:\work\VBox_4.3.12\vboxsrc`) |

## What It Does

The driver is a renamed build of the VirtualBox kernel support driver
(SUPDrv).  It creates two device objects — `\\Device\\DNDrv` (main,
with a 0x920-byte device extension holding all SUPDrv state) and
`\\Device\\DNDrvU` (user-facing stub that redirects to main).  Both
have `\\DosDevices` symlinks.

The IOCTL interface implements the full VirtualBox SUP protocol, with
a cookie-based session handshake followed by 30+ operation codes:

| IOCTL | Code | Description |
|-------|------|-------------|
| SUP_IOCTL_COOKIE | `0x228204` | Session handshake (magic word + version) |
| SUP_IOCTL_QUERY_FUNCS | `0x228208` | Dump 256-entry kernel symbol table |
| SUP_IOCTL_LDR_OPEN | `0x22820C` | Open a ring-0 module loader slot |
| SUP_IOCTL_LDR_LOAD | `0x228210` | Load arbitrary image into ring-0 |
| SUP_IOCTL_LDR_FREE | `0x228214` | Unload a ring-0 module |
| SUP_IOCTL_LDR_GET_SYMBOL | `0x228218` | Resolve an exported ring-0 symbol |
| SUP_IOCTL_CALL_VMMR0 | `0x22821C` | Call into VMM at ring-0 |
| SUP_IOCTL_LOW_ALLOC | `0x228220` | Allocate low-physical memory |
| SUP_IOCTL_LOW_FREE | `0x228224` | Free low-physical memory |
| SUP_IOCTL_PAGE_ALLOC_EX | `0x228228` | Allocate kernel pages (mapped to user) |
| SUP_IOCTL_PAGE_MAP_KERNEL | `0x22822C` | Map pages into kernel address space |
| SUP_IOCTL_PAGE_PROTECT | `0x228230` | Change page protection |
| SUP_IOCTL_PAGE_FREE | `0x228234` | Free kernel pages |
| SUP_IOCTL_PAGE_LOCK | `0x228238` | Lock user pages into kernel |
| SUP_IOCTL_PAGE_UNLOCK | `0x22823C` | Unlock locked pages |
| SUP_IOCTL_CONT_ALLOC | `0x228240` | Allocate physically contiguous memory |
| SUP_IOCTL_CONT_FREE | `0x228244` | Free contiguous memory |
| SUP_IOCTL_GET_PAGING_MODE | `0x228248` | Query CPU paging mode |
| SUP_IOCTL_SET_VM_FOR_FAST | `0x22824C` | Set VM pointer for fast IOCTLs |
| SUP_IOCTL_GIP_MAP | `0x228250` | Map VBox Global Info Page |
| SUP_IOCTL_GIP_UNMAP | `0x228254` | Unmap GIP |
| SUP_IOCTL_CALL_SERVICE | `0x228258` | Call a named ring-0 service |
| SUP_IOCTL_SEM_OP2 / OP3 | `0x228260` / `0x228264` | Semaphore operations |
| SUP_IOCTL_VT_CAPS | `0x228268` | Query VT-x/AMD-V capabilities |
| SUP_IOCTL_CALL_VMMR0_BIG | `0x22826C` | Large VMM call |
| FAST_DO_RAW_RUN | `0x228303` | Fast-path: raw-mode execution |
| FAST_DO_HM_RUN | `0x228307` | Fast-path: hardware-assisted VM run |
| FAST_DO_NOP | `0x22830B` | Fast-path: no-op (latency test) |

### Internals

- **Session management**: Each `IRP_MJ_CREATE` allocates a session
  via `RTMemAllocZTag` with a spinlock, handle table, and process
  identity.  Sessions are reference-counted and freed on file close.
- **Cookie handshake**: Callers must send `"The Magic Word!"` and a
  matching SUP version (`0x001A0007`) before any other IOCTL succeeds.
- **Module loader**: `LDR_OPEN` + `LDR_LOAD` can map arbitrary
  PE images into ring-0 address space with full symbol resolution.
- **Function table**: 256 entries of `{ char name[28]; void *pfn; }`
  exposing every SUPR0 and IPRT symbol to usermode.

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
#include "dndrv.h"

DNDRV ctx;
dndrv_open(&ctx);
dndrv_cookie(&ctx);   /* session handshake required first */

UINT32 caps, mode;
dndrv_query_vt_caps(&ctx, &caps);
dndrv_query_paging_mode(&ctx, &mode);

/* Query the full kernel function table */
UCHAR buf[0x2820];
UINT32 count;
dndrv_query_funcs(&ctx, buf, sizeof(buf), &count);

dndrv_close(&ctx);
```

## Demo

```
dndrv_demo.exe
```

1. Opens `\\.\DNDrv`
2. Performs the SUP_IOCTL_COOKIE handshake (magic word + version)
3. Queries the CPU paging mode
4. Queries VT-x/AMD-V hardware capabilities
5. Dumps the first 20 entries of the 256-symbol kernel function table

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it is a renamed build
of a legitimately signed VirtualBox support driver, Windows loads it
without complaint.  Once loaded, any process that completes the trivial
cookie handshake can:

- **Load arbitrary code into ring-0** via the LDR_OPEN + LDR_LOAD
  IOCTLs — inject any kernel module without signing
- **Allocate and map kernel pages** into user space, bypassing ASLR
  and supervisor-mode access prevention (SMAP/SMEP)
- **Resolve any SUPR0/IPRT kernel symbol** by name — leak the
  addresses of 256+ kernel helper functions
- **Execute code in a VM context** via CALL_VMMR0, potentially
  hijacking hypervisor-level operations
- **Allocate physically contiguous memory** for DMA attacks
- **Map the VBox Global Info Page** to leak precise kernel timing data

Mitigations: HVCI (Hypervisor-Protected Code Integrity), Microsoft's
vulnerable driver blocklist, and driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
