# gibepext.sys — GibEpExt

Client library and demo for **gibepext.sys**, a vulnerable Windows kernel
driver from Group-IB THF Huntpoint v1.2.37.0 that exposes physical memory
read/write, PCI configuration space access, MSR reads, and IO-space mapping
to admin-level usermode callers.

| | |
|---|---|
| **Device** | `\Device\GibEpExt` (`\\.\GibEpFirmware`, `\\.\GibEpForensic`) |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `98b2adeb673ec8dfd390af389c32513f` |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |
| **Vendor** | Group-IB LTD. |
| **Product** | Group-IB THF Huntpoint |

## What It Does

The driver creates `\Device\GibEpExt` with two `\DosDevices` symlinks
(one for firmware operations, one for forensic operations), then exposes
IOCTLs on device type `0x22` (`FILE_DEVICE_UNKNOWN`):

### Firmware IOCTLs (\\.\GibEpFirmware)

| IOCTL | Code | Description |
|-------|------|-------------|
| Read PCI config | `0x22e008` | Reads PCI configuration registers via port I/O |
| Read phys mem | `0x22e00c` | Reads arbitrary physical memory via MmMapIoSpace |
| Read phys mem (MDL) | `0x22e00e` | Same as above, using MDL mapping |
| Write phys mem | `0x22e010` | Writes arbitrary physical memory |
| Map IO space | `0x22e014` | Returns a kernel VA for a physical address |
| Read MSR | `0x22e020` | Reads MSR registers via rdmsr |
| Get phys addr | `0x22e024` | Translates virtual to physical address |
| Get stats | `0x226007` | Returns IOCTL invocation statistics |
| Get map stats | `0x22e01b` | Returns IO-space mapping statistics |

### Forensic IOCTLs (\\.\GibEpForensic)

| IOCTL | Code | Description |
|-------|------|-------------|
| Enum pipes | `0x222404` | Enumerates named pipe handles system-wide |
| Read file | `0x222408` | Reads file contents to user buffer |
| Hash file (SHA) | `0x22240c` | Computes SHA hash of a file |
| Enum handles | `0x222410` | Enumerates handles for pipe enumeration |
| Crash dump | `0x222418` | Creates a crash dump file |
| Copy file | `0x22241c` | Copies file contents |
| Set log level | `0x222420` | Sets driver debug log level |
| Clear log level | `0x222424` | Clears log level callback |
| Set dump flag | `0x222440` | Sets internal dump flag |
| Get file size | `0x222444` | Returns the size of a file |

The only access check is `SeTokenIsAdmin` on the firmware IOCTLs.
Each firmware IOCTL buffer includes a CRC-32 integrity check, but
this is trivially computed by any caller.

### Internals

- **Physical memory access**: `MmMapIoSpace` with `MmCached`, then
  `memcpy` into/from the mapped region.  No size or address validation.
- **PCI config space**: Direct port I/O to `0xCF8`/`0xCFC` (the standard
  PCI configuration mechanism).
- **MSR access**: Direct `rdmsr` intrinsic with CPU affinity pinning.
- **Integrity check**: CRC-32 checksum appended to each IOCTL buffer,
  verified before processing.  Easily computed client-side.
- **Mapping tracker**: Red-black tree tracking `MmMapIoSpace` mappings
  so they can be unmapped on driver unload.

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
#include "gibepext.h"

GIBEPEXT ctx;
gibepext_open(&ctx);

// Read 64 bytes of physical memory
UCHAR buf[64];
gibepext_read_physmem(&ctx, 0xF0000, buf, sizeof(buf));

// Write to physical memory (with CRC-32 integrity)
UINT32 val = 0x41414141;
gibepext_write_physmem(&ctx, 0x100000, &val, sizeof(val));

// Read an MSR
UINT32 lo, hi;
gibepext_read_msr(&ctx, 0, 0x10, &lo, &hi);

// Get physical address for a virtual address
UINT64 phys;
gibepext_get_phys_addr(&ctx, (UINT64)&val, &phys);

gibepext_close(&ctx);
```

The write function automatically computes the CRC-32 checksum required
by the driver's integrity check.

## Demo

```
gibepext_demo.exe [phys_addr]
```

1. CRC-32 self-test
2. Opens `\\.\GibEpFirmware`
3. Reads physical memory at the specified address (default: 0x1000)
4. Reads the BIOS data area at 0xF0000
5. Reads MSR 0x10 (IA32_TSC) on CPU 0

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed
by Group-IB, Windows loads it without complaint.  Once loaded, any admin
process can:

- **Read/write any physical memory** without restriction
- **Read PCI configuration space** to fingerprint or reconfigure hardware
- **Read MSR registers** for side-channel attacks or security bypass
- **Map arbitrary IO space** into the kernel address space
- **Enumerate system handles** for forensic or offensive reconnaissance
- **Create crash dumps** containing kernel memory

Mitigations: HVCI (Hypervisor-Protected Code Integrity), Microsoft's
vulnerable driver blocklist, and driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
