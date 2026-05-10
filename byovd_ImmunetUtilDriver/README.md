# ImmunetUtilDriver.sys — ImmunetUtilDriver

Client library and demo for **ImmunetUtilDriver.sys**, a vulnerable Windows
kernel driver from Cisco Secure Endpoint (Immunet) that exposes dangerous
kernel introspection and handle manipulation primitives to usermode through
eleven METHOD_BUFFERED IOCTLs.

| | |
|---|---|
| **Device** | `\\Device\\ImmunetUtilDriver0` (`\\.\ImmunetUtilDriver0`) |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `413184d2547bba85b13b943df8200a81` |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |

## What It Does

The driver creates `\\Device\\ImmunetUtilDriver0` with a `\\DosDevices`
symlink using `WdmlibIoCreateDeviceSecure`, then exposes eleven
`METHOD_BUFFERED` IOCTLs on custom device type `0x8FEA`:

| IOCTL | Code | Description |
|-------|------|-------------|
| Get version | `0x8FEAA000` | Returns driver version string |
| File open handle | `0x8FEAA004` | Opens a kernel file handle by path |
| Open process | `0x8FEAA008` | Opens a process handle by PID |
| Open directory object | `0x8FEAA00C` | Opens an object namespace directory |
| Query directory object | `0x8FEAA010` | Enumerates directory entries |
| Get driver data | `0x8FEAA014` | Serializes a DRIVER_OBJECT by name |
| Get device data | `0x8FEAA018` | Serializes a DEVICE_OBJECT by name |
| Get handle data (cross) | `0x8FEAA01C` | Inspects handles in another process |
| Duplicate handle | `0x8FEAA020` | Duplicates handles from a remote process |
| Get handle data | `0x8FEAA024` | Inspects handles in the current process |
| Close directory object | `0x8FEAA028` | Closes a previously opened directory |

The driver enforces a single-connection model (one process at a time) and
thread-safety via spinlocks, but once connected the calling process gets
unrestricted access to all IOCTLs.

### Internals

- **Single connection**: The driver tracks a single connected PID in
  `g_ConnectedPid` and rejects concurrent connections.
- **Object introspection**: `ObReferenceObjectByName` enumerates driver
  objects; `IoGetDeviceObjectPointer` resolves device objects.  Results
  are serialized into flat buffers with relative pointers.
- **Handle operations**: `ObReferenceObjectByHandle` +
  `KeStackAttachProcess` enables cross-process handle inspection.
  `ZwDuplicateObject` clones handles from remote processes.
- **Directory objects**: `ZwOpenDirectoryObject` / `ZwQueryDirectoryObject`
  enumerate the kernel object namespace.  Up to 250 directory handles are
  tracked per session.

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
#include "immunetutildriver.h"

IMMUNET ctx;
immunet_open(&ctx);

// Get driver version
WCHAR version[512];
immunet_get_version(&ctx, version, sizeof(version));

// Open a process handle by PID
HANDLE proc;
immunet_open_process(&ctx, target_pid, &proc);

// Get handle data
UCHAR buf[4096];
DWORD bytes;
immunet_get_handle_data(&ctx, proc, buf, sizeof(buf), &bytes);

// Enumerate directory objects
UINT64 dir_idx;
immunet_open_directory(&ctx, L"\\Driver", &dir_idx);
immunet_query_directory(&ctx, (UINT32)dir_idx, buf, sizeof(buf), &bytes);
immunet_close_directory(&ctx, (UINT32)dir_idx);

immunet_close(&ctx);
```

## Demo

```
immunetutildriver_demo.exe <pid>
```

1. Opens `\\.\ImmunetUtilDriver0`
2. Queries the driver version string
3. Opens a process handle for the target PID
4. Gets handle data for the opened handle
5. Queries driver object data for the ImmunetUtilDriver itself
6. Enumerates the `\Driver` object namespace directory
7. Cleans up and closes the device

Requires Administrator (driver device access).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed
by Cisco, Windows loads it without complaint.  Once loaded, any process
that can open the device handle (SYSTEM / Administrators) can:

- **Enumerate all kernel driver objects** including their internal
  structure, device lists, and major function tables
- **Open handles to any process** with `PROCESS_ALL_ACCESS` rights
  bypassing usermode access checks
- **Duplicate handles** from any process, stealing file handles,
  registry keys, tokens, and other securable objects
- **Inspect handle tables** of remote processes by attaching to
  their address space
- **Enumerate the kernel object namespace** to discover hidden
  devices, drivers, and other kernel objects
- **Open arbitrary files** through the kernel bypassing NTFS
  security checks (IO_NO_PARAMETER_CHECKING)

Mitigations: HVCI (Hypervisor-Protected Code Integrity), Microsoft's
vulnerable driver blocklist, and driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
