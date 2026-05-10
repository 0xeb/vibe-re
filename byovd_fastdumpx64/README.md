# fastdumpx64.sys — FastDump

Client library and demo for **fastdumpx64.sys**, a vulnerable Windows kernel
driver from CounterTack that exposes arbitrary physical memory read primitives
to usermode through IOCTLs and the IRP_MJ_READ path.

| | |
|---|---|
| **Device** | `\\Device\\FastDump` (`\\.\FastDump`) |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `016c1d3cc193732736eeaeb3094154f2` |
| **Vendor** | CounterTack, Inc. |
| **Version** | 2.3.0.97 |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |

## What It Does

The driver creates `\\Device\\FastDump` with a `\\??\\FastDump` symlink
protected by an SDDL string limiting access to SYSTEM and Administrators.
It then exposes 14 `METHOD_BUFFERED` IOCTLs (plus one `METHOD_NEITHER`)
on a custom device type `0x9C40`, along with a direct `IRP_MJ_READ`
handler for page-at-a-time physical memory reads.

| IOCTL | Code | Description |
|-------|------|-------------|
| Map buffer | `0x9C400007` | Map user pages via MmGetPhysicalAddress |
| Init | `0x9C400000` | Allocate dump context |
| Get context | `0x9C400008` | Get context state |
| Release | `0x9C40000C` | Release context |
| Get sysinfo | `0x9C400010` | Full system info (CPU, memory ranges) |
| Read phys | `0x9C400014` | Read physical memory into mapped buffer |
| Read phys mapped | `0x9C400018` | Read physical range to output buffer |
| CPU info full | `0x9C40001C` | CPUID + MSR + memory map |
| Open dump | `0x9C400020` | Create dump file on disk |
| Do dump | `0x9C400024` | Write physical pages to file |
| Close dump | `0x9C400028` | Close dump file handle |
| Get CPUID | `0x9C40002C` | Raw CPUID leaf enumeration |
| Read MSR | `0x9C400030` | Execute RDMSR for any index |
| CPU info light | `0x9C400034` | CPUID only (no MTRR/phys) |

### Internals

- **Physical read path**: Uses `MmCopyMemory` with
  `MM_COPY_MEMORY_PHYSICAL` (Win 8+), falling back to `MmMapIoSpace`
  on older systems.
- **IRP_MJ_READ handler**: Maps one physical page at a time via
  `MmMapIoSpace` + MDL, copies to user buffer.
- **MTRR enumeration**: Reads MTRRcap/MTRRdefType MSRs and fixed/
  variable MTRR registers to build a memory type map.
- **Context pool**: Three pre-allocated 0x1948-byte context slots
  managed via a spin-locked free list.
- **Dump format**: Supports raw binary and ELF64 core dump output,
  writing physical memory ranges to a file via `ZwCreateFile` /
  `ZwWriteFile`.

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
#include "fastdump.h"

FASTDUMP ctx;
fastdump_open(&ctx);

// Read 256 bytes of physical memory
UCHAR buf[256];
fastdump_read_phys(&ctx, 0x1000, buf, sizeof(buf));

// Read MSR
UINT64 msr_val;
fastdump_read_msr(&ctx, 0xFE, &msr_val);

// Get CPUID
FASTDUMP_CPUID_RESPONSE cpuid;
fastdump_get_cpuid(&ctx, &cpuid);

fastdump_close(&ctx);
```

## Demo

```
fastdump_demo.exe [phys_addr]
```

1. Opens `\\.\FastDump`
2. Queries CPUID via the driver
3. Reads IA32_MTRRCAP MSR
4. Reads page 0 (BIOS data area)
5. Reads 256 bytes at the specified physical address

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed
by CounterTack, Windows loads it without complaint.  Once loaded, any
Administrator process can:

- **Dump all physical memory** — the driver's primary purpose
- **Read any MSR** — exposing CPU configuration and security state
- **Extract credentials** from physical memory without triggering
  virtual-memory-based protections
- **Bypass Credential Guard** by reading LSASS data from the physical
  address space directly

Mitigations: HVCI (Hypervisor-Protected Code Integrity), Microsoft's
vulnerable driver blocklist, and driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
