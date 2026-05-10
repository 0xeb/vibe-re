# bin_intigua_driver64.sys — Intigua Service Hook Driver

Client library and demo for **bin_intigua_driver64.sys**, a vulnerable
Windows kernel driver that hooks the Import Address Table (IAT) of
`services.exe` to intercept process creation calls.

| | |
|---|---|
| **Device** | `\\Device\\{4cdec755-627a-4141-99e5-76ff636b1282}` (`\\.\\{4cdec755-627a-4141-99e5-76ff636b1282}`) |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `0146c74cb125b188dbac4f9fa8ab867e` |
| **Vendor** | Intigua (version 0.0.243.0) |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |

## What It Does

The driver creates `\\Device\\{4cdec755-627a-4141-99e5-76ff636b1282}` with a
`\\DosDevices` symlink, then exposes three `METHOD_BUFFERED` IOCTLs on device
type `0x9C40`:

| IOCTL | Code | Input | Description |
|-------|------|-------|-------------|
| Patch | `0x9C40240C` | 4-byte PID | Hook IAT entries in services.exe (current DLL) |
| Unpatch | `0x9C402410` | 4-byte PID | Restore original IAT entries and free shellcode |
| Patch 2019 | `0x9C402414` | 4-byte PID | Hook IAT entries using older DLL name |

The driver performs a basic admin token check (`SeTokenIsAdmin`) but has no
further caller validation, no integrity checks on the shellcode payload, and
no verification that the target PID is actually services.exe.

### Internals

- **IAT hooking**: Walks the PE import directory of a target module loaded in
  `services.exe` to locate the IAT slots for `CreateProcessAsUserW` and
  `CreateProcessW`.
- **Module enumeration**: Resolves `PsGetProcessPeb` at runtime via
  `MmGetSystemRoutineAddress`, then walks the PEB loader `InMemoryOrderModuleList`
  to find the base address of the target DLL.
- **Shellcode injection**: Allocates `PAGE_EXECUTE_READWRITE` memory in the
  target process via `ZwAllocateVirtualMemory` and copies a ~21 KB payload.
- **MDL-based write**: Uses `IoAllocateMdl` / `MmProbeAndLockPages` /
  `MmMapLockedPagesSpecifyCache` to write new function pointers into the
  (potentially read-only) IAT.
- **Dynamic code policy**: Calls `ZwSetInformationProcess` with
  `ProcessMitigationPolicy` (0x34) to enable/disable `ProcessDynamicCodePolicy`
  on the target process, allowing the injected shellcode to execute.

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
#include "intigua_driver.h"

INTIGUA_DRIVER ctx;
intigua_driver_open(&ctx);

// Hook services.exe IAT
intigua_driver_patch(&ctx, services_pid);

// ... hooks are active ...

// Restore original IAT entries
intigua_driver_unpatch(&ctx, services_pid);

intigua_driver_close(&ctx);
```

## Demo

```
intigua_driver_demo.exe <services_pid>
intigua_driver_demo.exe auto
```

1. Opens `\\.\{4cdec755-627a-4141-99e5-76ff636b1282}`
2. Patches services.exe IAT (tries current DLL, falls back to 2019 variant)
3. Waits for user input
4. Unpatches (restores original IAT entries, frees injected shellcode)

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed by
Intigua, Windows loads it without complaint.  Once loaded, any admin-level
process can:

- **Inject arbitrary code** into `services.exe` (a critical system process)
  by replacing the shellcode payload
- **Intercept all process creation** on the system by hooking
  `CreateProcessAsUserW` / `CreateProcessW` in the service control manager
- **Bypass PPL** (Protected Process Light) since the driver operates from
  kernel mode and uses MDL-based writes to patch read-only memory
- **Disable security mitigations** by toggling `ProcessDynamicCodePolicy`
  on protected processes

Mitigations: HVCI (Hypervisor-Protected Code Integrity), Microsoft's
vulnerable driver blocklist, and driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
