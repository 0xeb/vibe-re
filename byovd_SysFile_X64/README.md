# SysFile_X64.sys — WinHwDriver

Client library and demo for **SysFile_X64.sys**, a vulnerable Windows kernel
driver that exposes raw hardware access primitives to usermode through ten
IOCTLs covering MSRs, I/O ports, PCI configuration space, and physical memory.

| | |
|---|---|
| **Device** | `\\Device\\WinHwDriver` (`\\.\WinHwDriver`) |
| **Arch** | x86-64, Windows kernel (KMDF) |
| **MD5** | `9ddff9a4ec7e38e4e05fd16e2b1037ff` |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |

## What It Does

The driver creates `\\Device\\WinHwDriver` with a `\\DosDevices` symlink,
then exposes ten `METHOD_BUFFERED` IOCTLs on device type `0x9c40`:

| IOCTL | Code | Description |
|-------|------|-------------|
| Get driver version | `0x9c402000` | Returns 4-byte version constant (0x01000001) |
| Get refcount | `0x9c402004` | Returns open-handle reference count |
| Read MSR | `0x9c402084` | Reads a Model-Specific Register via `__readmsr` |
| Write MSR | `0x9c402088` | Writes a Model-Specific Register via `__writemsr` |
| Read I/O port | `0x9c4060CC/D0/D4` | Reads 1/2/4 bytes from an I/O port |
| Write I/O port | `0x9c40A0D8/DC/E0` | Writes 1/2/4 bytes to an I/O port |
| Read memory | `0x9c406104` | Reads physical memory via `MmMapIoSpace` |
| Write memory | `0x9c40A108` | Writes physical memory via `MmMapIoSpace` |
| Read PCI config | `0x9c406144` | Reads PCI config via `HalGetBusDataByOffset` |
| Write PCI config | `0x9c40A148` | Writes PCI config via `HalSetBusDataByOffset` |

No caller validation, no access checks.  Any usermode process that can
open the device handle gets direct hardware access.

### Internals

- **Physical memory**: Mapped via `MmMapIoSpace` with `MmNonCached`
  caching, element-wise copy in 1/2/4/8-byte units.
- **MSR access**: Direct `__readmsr`/`__writemsr` intrinsic calls.
- **I/O ports**: Direct `READ_PORT_UCHAR`/`WRITE_PORT_UCHAR` family.
- **PCI config**: `HalGetBusDataByOffset`/`HalSetBusDataByOffset` with
  PCI address encoded as bus(15:8)/device(7:3)/function(2:0).

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
#include "winhwdriver.h"

WINHWDRIVER ctx;
winhwdriver_open(&ctx);

UINT32 version;
winhwdriver_get_version(&ctx, &version);

UINT64 tsc;
winhwdriver_read_msr(&ctx, 0x10, &tsc);

UCHAR buf[256];
winhwdriver_read_memory(&ctx, 0xFEE00000, 4, 64, buf);

winhwdriver_close(&ctx);
```

## Demo

```
winhwdriver_demo.exe
```

1. Opens `\\.\WinHwDriver`
2. Queries driver version and reference count
3. Reads MSR 0x10 (Time Stamp Counter)
4. Reads I/O port 0x40 (PIT channel 0)
5. Reads PCI config for host bridge at 00:00.0
6. Reads 64 bytes of physical memory at address 0

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed,
Windows loads it without complaint.  Once loaded, any unprivileged process
can:

- **Read/write arbitrary MSRs** — disable security features, modify
  processor configuration, bypass SMEP/SMAP
- **Access arbitrary I/O ports** — interact with any hardware device
- **Read/write PCI configuration space** — reconfigure DMA engines,
  disable IOMMU protections
- **Read/write arbitrary physical memory** — dump credentials, patch
  kernel structures, inject code into any process

Mitigations: HVCI (Hypervisor-Protected Code Integrity), Microsoft's
vulnerable driver blocklist, and driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
