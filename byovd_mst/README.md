# mst.sys — Mellanox MST Driver

Client library and demo for **mst.sys**, a vulnerable Windows kernel driver
from the Mellanox Software Tools (MST) package that exposes arbitrary PCI
configuration space read/write, physical memory mapping, and HCA device
management to usermode through IOCTLs.

| | |
|---|---|
| **Device** | `\\Device\\mst64_4.20.0` (`\\.\mst64_4.20.0`) |
| **Arch** | x86-64, Windows kernel |
| **MD5** | `84c230b35f5c8e2a075362277c513a94` |
| **Class** | BYOVD (Bring Your Own Vulnerable Driver) |
| **Version** | 4.20.0 (Mellanox/NVIDIA) |

## What It Does

The driver creates `\\Device\\mst64_4.20.0` with a `\\DosDevices`
symlink, protected by a basic SDDL ACL (`SY` + `BA` only), then
exposes seven `METHOD_BUFFERED` IOCTLs on device type `0x22`
(`FILE_DEVICE_UNKNOWN`):

| IOCTL | Code | Description |
|-------|------|-------------|
| MST_IOCTL_ENUM | `0x222008` | Enumerate known Mellanox HCA devices |
| MST_IOCTL_MAP_MEM | `0x22200C` | Firmware access sub-commands (20+ sub-ops) |
| MST_IOCTL_VPD_OP | `0x222014` | VPD (Vital Product Data) read/write |
| MST_IOCTL_ALLOC_PAGE | `0x222018` | Allocate + map a physical page to usermode |
| MST_IOCTL_PCI_READ_DWORD | `0x22201C` | Read any PCI config DWORD |
| MST_IOCTL_PCI_WRITE_DWORD | `0x222020` | Write any PCI config DWORD |
| MST_IOCTL_PCI_GET_DEVICES | `0x222024` | Enumerate all PCI devices system-wide |

### Internals

- **PCI config access**: Directly calls `HalGetBusDataByOffset` /
  `HalSetBusDataByOffset` — reads and writes arbitrary PCI config space
  registers for any bus/slot/offset without device ownership checks.
- **Physical memory mapping**: `MmGetVirtualForPhysical` +
  `MmMapLockedPagesSpecifyCache` maps arbitrary physical pages to
  usermode with `MmNonCached` access.
- **CR-space access**: Maps device BAR0 via `MmMapIoSpace` and exposes
  it to usermode for direct MMIO reads/writes.
- **HCA reset**: Full PCI link disable/enable cycle with configuration
  space save/restore — can be used to reset any PCI Express device.
- **VSEC operations**: Vendor-specific extended capability register
  read/write with semaphore locking.
- **Device enumeration**: Scans all PCI buses for ~46 known Mellanox
  device IDs (ConnectX-4/5/6/7, BlueField 1/2/3, Spectrum, etc.).

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
#include "mst.h"

MST ctx;
mst_open(&ctx);

// Read PCI Vendor/Device ID from bus 0, slot 0
UINT32 value;
mst_pci_read(&ctx, 0, 0, 0, &value);
printf("VendorID:DeviceID = %04X:%04X\n", value & 0xFFFF, value >> 16);

// Write a PCI config register
mst_pci_write(&ctx, bus, slot, offset, new_value);

// Enumerate Mellanox HCA devices
MST_DEVICE_ENTRY entries[16];
UINT32 count;
mst_enum_devices(&ctx, entries, 16, &count);

// Allocate a physical page mapped to usermode
UINT64 user_va, phys_addr;
mst_alloc_page(&ctx, &user_va, &phys_addr);

mst_close(&ctx);
```

## Demo

```
mst_demo.exe [bus:slot]
```

1. Opens `\\.\mst64_4.20.0`
2. Enumerates Mellanox HCA devices
3. Reads PCI config header for the specified bus:slot
4. Non-destructive write + readback verification
5. Allocates a physical page via the driver
6. Enumerates all PCI devices on the system

Requires Administrator (driver device ACL requires elevation).

## Why This Driver Is Dangerous

This is a classic **BYOVD** target.  Because it was legitimately signed
by Mellanox/NVIDIA, Windows loads it without complaint.  Once loaded,
any elevated process can:

- **Read/write arbitrary PCI config space** — modify DMA addresses,
  BAR mappings, bus-master enable bits on any device
- **Map arbitrary physical memory** to usermode — bypass all OS
  memory protections
- **Reset any PCIe device** — denial of service against any hardware
- **Access device MMIO registers** directly — bypass driver isolation
- **Modify IOMMU/VT-d configuration** via PCI config space writes

Mitigations: HVCI (Hypervisor-Protected Code Integrity), Microsoft's
vulnerable driver blocklist, and driver signing enforcement.

## License

This reconstruction is provided for **educational and defensive security
research purposes only**. Licensed under the [BSD 3-Clause License](../LICENSE).
