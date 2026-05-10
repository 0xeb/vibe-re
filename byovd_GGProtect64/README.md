# GGProtect64.sys

Client library and demo for **GGProtect64.sys**, a game guard anti-cheat
kernel driver exposing 60+ IOCTLs for process protection, DLL injection,
keyboard/mouse hooking, physical memory scanning, registry monitoring,
callback enumeration, SSDT introspection, and more.

| | |
|---|---|
| **Device** | `\\Device\\GGProtect64` (`\\.\GGProtect64`) |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `b6a0d03122bd968b40ce97c145b491c7` |
| **PDB** | `F:\TFS\zuhao\GGame\Output\Release\GGProtect64.pdb` |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |

## What It Does

The driver creates `\\Device\\GGProtect64` with a `\\DosDevices` symlink,
then exposes 60+ `METHOD_BUFFERED` IOCTLs on device type `0x22`
(`FILE_DEVICE_UNKNOWN`).  It also registers a minifilter (altitude 321229)
with a communication port at `\\GG_CommPort`.

### Authentication

The first IOCTL (`DRIVER_LOAD`, code `0x223c14`) records the calling
process's PID and XOR's the supplied key with `0x5A84`.  All subsequent
IOCTLs are rejected unless the caller PID matches.  This is the **only**
access control -- no token check, no integrity level check, no signature
validation.

### IOCTL Categories

| Category | Code Range | Examples |
|----------|-----------|---------|
| Init / teardown | `0x223c14`-`0x223c18` | DRIVER_LOAD, DRIVER_UNLOAD |
| I/O port access | `0x223804`-`0x223808` | Raw IN/OUT byte/dword |
| Process protection | `0x223c04`-`0x223d84` | Add/delete protected PIDs, HIPS |
| Driver enumeration | `0x223c40`-`0x223c74` | By device name, driver name, all |
| SSDT / Shadow SSDT | `0x223c58`, `0x223c78` | Address lookup by index |
| Function code read | `0x223c54` | Kernel/process/SSDT/SSSDT code copy |
| OB callbacks | `0x223c5c`-`0x223c60` | Enumerate and uninstall |
| Notification callbacks | `0x223d40`-`0x223d4c` | LoadImage, CreateProcess, CreateThread, CmRegister |
| Input hooking | `0x223c64`-`0x223ce8` | Mouse, keyboard, system key |
| Thread monitoring | `0x223c7c`-`0x223cf0` | Add/update/delete/status |
| File/process filters | `0x223c1c`-`0x223c30` | Minifilter rules |
| DLL injection | `0x223cbc`, `0x223cb0` | APC-based inject into running/future processes |
| Registry monitoring | `0x223cc0`-`0x223cc4` | CmRegisterCallback |
| Memory scanning | `0x223d18`-`0x223d38` | Physical + nonpaged pool pattern scan |
| Bluescreen | `0x223c10` | Intentional bugcheck |

### Internals

- **Minifilter**: Registers with `FltRegisterFilter` (altitude `321229`),
  creates communication port `\\GG_CommPort`, intercepts IRP_MJ_CREATE,
  IRP_MJ_WRITE, IRP_MJ_READ, and IRP_MJ_SET_INFORMATION for file
  protection.
- **Keyboard/mouse hooking**: Attaches to `\\Driver\\Kbdclass`,
  `\\Driver\\Mouclass`, `\\Driver\\i8042prt`, `\\Driver\\Kbdhid`,
  `\\Driver\\Mouhid`, `\\Driver\\SynTP`, `\\Driver\\TermDD` device stacks.
- **DLL injection**: APC-based injection via `NtTestAlert` shellcode,
  resolves `ZwAllocateVirtualMemory`, `NtContinue`, `LdrLoadDll` from
  ntdll.dll in the target process.
- **SSDT resolution**: Scans `KeServiceDescriptorTable` and its shadow
  to resolve syscall addresses by index.
- **Physical memory scanning**: Enumerates `MmGetPhysicalMemoryRanges()`,
  maps pages via `MmMapIoSpaceEx`, scans for byte patterns.

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
#include "ggprotect64.h"

GGPROTECT ctx;
ggprotect_open(&ctx);

// Initialize driver session with auth key
ggprotect_driver_load(&ctx, 0x1234);

// Query SSDT entry
UINT64 addr;
ggprotect_get_ssdt_addr(&ctx, 0, &addr);

// Enable process creation monitoring
ggprotect_enable_create_proc(&ctx, 1);

// Tear down session
ggprotect_driver_unload(&ctx, ctx.auth_key);
ggprotect_close(&ctx);
```

## Demo

```
ggprotect64_demo.exe
```

1. Opens `\\.\GGProtect64`
2. Initializes the session with `DRIVER_LOAD` + XOR'd auth key
3. Enables debug log output
4. Queries SSDT and Shadow SSDT addresses
5. Queries kernel procedure addresses
6. Enables/disables process creation monitoring
7. Enumerates OB callbacks
8. Tears down the session with `DRIVER_UNLOAD`

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed,
Windows loads it without complaint.  Once loaded, any process that knows
the PID-registration trick can:

- **Read/write arbitrary I/O ports** -- full hardware access (ports
  `0x60`-`0x64` for keyboard, any PCI config space, etc.)
- **Read arbitrary kernel memory** via `IOCTL_GET_FUN_CODE` and
  `IOCTL_GET_MDL_DATA` -- dump any kernel structure
- **Inject DLLs** into arbitrary processes via APC shellcode
- **Uninstall security callbacks** -- strip OB callbacks from EDR/AV
- **Trigger bluescreen** on demand (`IOCTL_BLUESCREEN`)
- **Hook keyboard/mouse** at the device stack level
- **Scan physical memory** for cheat signatures (or credentials)
- **Enumerate and remove** process/thread/image-load notification
  callbacks

The "authentication" is a single PID check with an XOR'd key -- trivially
bypassable by any process running as the same user.

Mitigations: HVCI, Microsoft's vulnerable driver blocklist, driver
signing enforcement with revocation checking.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
