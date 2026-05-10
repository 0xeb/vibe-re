# Cormem.sys -- CORMEM

Client library and demo for **Cormem.sys**, a vulnerable Windows kernel
driver from Teledyne Digital Imaging's Sapera LT framework that exposes
physical memory mapping, I/O port access, contiguous DMA memory allocation,
and scatter-gather primitives to usermode through IOCTLs.

| | |
|---|---|
| **Device** | `\\Device\\CORMEM` (`\\.\CORMEM`) |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `78fb9882e498d964f42169ce511f07fc` |
| **Vendor** | Teledyne Digital Imaging Inc. (Sapera LT v9.00) |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |

## What It Does

The driver creates `\\Device\\CORMEM` with a `\\DosDevices` symlink,
then exposes 27 `METHOD_BUFFERED` IOCTLs on device type `0x22`
(`FILE_DEVICE_UNKNOWN`):

| IOCTL | Code | Description |
|-------|------|-------------|
| MapPool | `0x222000` | Map a contiguous memory pool block |
| FreeBuffer | `0x222004` | Free a virtual buffer allocation |
| GetFunctions | `0x222008` | Return internal function pointer table |
| MapBuffer | `0x22200C` | Map physical memory via `\\Device\\PhysicalMemory` |
| UnmapBuffer | `0x222010` | Unmap a previously mapped buffer |
| ReadIo | `0x222014` | Read an I/O port (byte/word/dword) |
| WriteIo | `0x222018` | Write an I/O port (byte/word/dword) |
| VirtualToPhys | `0x22201C` | Translate virtual to physical address |
| FreeBufferPhys | `0x222020` | Free a buffer by physical address |
| ScatterGatherLock | `0x222024` | Lock user buffer for DMA scatter-gather |
| UserBufFree | `0x222028` | Free a locked user buffer |
| FreeUnused | `0x22202C` | Free allocations from dead processes |
| AllocBufferObj | `0x222030` | Allocate from 32-bit object pool |
| AllocBufferMsg | `0x222034` | Allocate from messaging pool |
| GetMsgBoundary | `0x222038` | Get messaging pool boundary |
| AllocPhysMem | `0x22203C` | Allocate physically contiguous pages |
| FreePhysMem | `0x222040` | Free physically contiguous pages |
| MapPhysMem | `0x222044` | Map an MDL into user address space |
| UnmapPhysMem | `0x222048` | Unmap an MDL from user address space |
| GetPhysMem | `0x22204C` | Get physical page list from MDL |
| BufferObjStatus | `0x222050` | Query 32-bit object pool status |
| BufferMemStatus | `0x222054` | Query messaging pool status |
| CreateMdlAndLock | `0x222058` | Create MDL and lock user buffer |
| GetPoolBlockCount | `0x22205C` | Get total pool block count |
| GetPhysMem_64 | `0x222060` | Get 64-bit physical page list |
| AllocBufferObj64 | `0x222064` | Allocate from 64-bit object pool |
| BufferObj64Status | `0x222068` | Query 64-bit object pool status |

No caller validation, no access checks, no `ProbeForRead`/`ProbeForWrite`.

### Internals

- **Physical memory mapping**: Maps `\\Device\\PhysicalMemory` sections via
  `ZwOpenSection` + `ZwMapViewOfSection`.
- **I/O port access**: Direct `in`/`out` instruction wrappers (byte, word,
  dword) with no validation of port numbers.
- **Memory pools**: Allocates contiguous physical memory
  (`MmAllocateContiguousMemory`) in three tiers: messaging pool, 32-bit
  object pool, and 64-bit object pool.
- **MDL tracking**: Tracks locked user buffers and physically allocated
  pages via linked lists protected by kernel mutexes.

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
#include "cormem.h"

CORMEM ctx;
cormem_open(&ctx);

// Read an I/O port
UINT32 val;
cormem_read_io(&ctx, 0x3F8, 1, &val);

// Map physical memory
PVOID mapped;
cormem_map_buffer(&ctx, 0xFED00000, 0x1000, &mapped);

// Translate virtual to physical
UINT64 phys;
cormem_virt_to_phys(&ctx, (UINT64)&val, &phys);

// Read/write physical memory (convenience)
cormem_read_phys32(&ctx, 0xFEE00020, &val);
cormem_write_phys32(&ctx, 0xFEE00020, val | 0x100);

cormem_close(&ctx);
```

## Demo

```
cormem_demo.exe [phys_addr]
```

1. Opens `\\.\CORMEM`
2. Queries pool block count and messaging pool status
3. Translates a virtual address to physical
4. Tests I/O port read/write on COM1 scratch register
5. Maps a physical page and dumps its contents
6. Reads a DWORD via the convenience API

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed
by Teledyne Digital Imaging, Windows loads it without complaint.  Once
loaded, any unprivileged process can:

- **Map arbitrary physical memory** via `\\Device\\PhysicalMemory`
- **Read/write I/O ports** -- interact with hardware directly
- **Allocate contiguous DMA memory** -- useful for DMA attacks
- **Translate virtual to physical addresses** -- locate kernel objects
- **Lock and map user buffers** with kernel MDLs -- bypass memory protections

Mitigations: HVCI (Hypervisor-Protected Code Integrity), Microsoft's
vulnerable driver blocklist, and driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
