/*
 * mst.h — Client library for the MST kernel driver (mst.sys)
 *
 * Provides typed wrappers around the IOCTLs exposed by
 * \\.\mst64_4.20.0:
 *
 *   0x222008  MST_IOCTL_ENUM           — Enumerate Mellanox HCA devices
 *   0x22200C  MST_IOCTL_MAP_MEM        — Firmware access sub-commands
 *   0x222014  MST_IOCTL_VPD_OP         — VPD read/write operations
 *   0x222018  MST_IOCTL_ALLOC_PAGE     — Allocate and map a physical page
 *   0x22201C  MST_IOCTL_PCI_READ_DWORD — Read PCI config DWORD
 *   0x222020  MST_IOCTL_PCI_WRITE_DWORD— Write PCI config DWORD
 *   0x222024  MST_IOCTL_PCI_GET_DEVICES— Enumerate all PCI devices
 *
 * Usage:
 *   MST ctx;
 *   if (mst_open(&ctx)) {
 *       UINT32 value;
 *       mst_pci_read(&ctx, bus, slot, offset, &value);
 *       ...
 *       mst_close(&ctx);
 *   }
 */

#ifndef MST_H
#define MST_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — METHOD_BUFFERED, FILE_DEVICE_UNKNOWN (0x22)         */
/* ------------------------------------------------------------------ */

#define IOCTL_MST_ENUM              0x222008
#define IOCTL_MST_MAP_MEM           0x22200C
#define IOCTL_MST_VPD_OP            0x222014
#define IOCTL_MST_ALLOC_PAGE        0x222018
#define IOCTL_MST_PCI_READ_DWORD    0x22201C
#define IOCTL_MST_PCI_WRITE_DWORD   0x222020
#define IOCTL_MST_PCI_GET_DEVICES   0x222024

/* ------------------------------------------------------------------ */
/*  IOCTL request structures (must match driver layout exactly)       */
/* ------------------------------------------------------------------ */

#pragma pack(push, 8)

typedef struct MST_PCI_READ_REQUEST {
    UINT32  bus;
    UINT32  slot;
    UINT32  offset;
} MST_PCI_READ_REQUEST;

typedef struct MST_PCI_WRITE_REQUEST {
    UINT32  bus;
    UINT32  slot;
    UINT32  offset;
    UINT32  value;
} MST_PCI_WRITE_REQUEST;

typedef struct MST_ALLOC_PAGE_OUT {
    UINT64  user_va;
    UINT64  phys_addr;
} MST_ALLOC_PAGE_OUT;

typedef struct MST_FW_REQUEST {
    UINT32  dev_id;
    UINT32  padding;
    UINT32  sub_cmd;
    UINT32  bus_slot;
    UINT32  data[12];       /* variable-length payload (0x30 total) */
} MST_FW_REQUEST;

typedef struct MST_DEVICE_ENTRY {
    UINT64  bar0_pa;
    UINT64  bar0_size;
    UINT32  reserved[4];
    UINT32  dev_id;
    UINT32  name_idx;
    UINT32  bus;
    UINT32  slot;
    UINT32  reserved2[4];
} MST_DEVICE_ENTRY;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct MST {
    HANDLE      device;
    DWORD       last_error;
} MST;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\mst64_4.20.0.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL mst_open(MST *ctx);

/*
 * Close the device handle.
 */
void mst_close(MST *ctx);

/*
 * IOCTL 0x22201C — Read a DWORD from PCI configuration space.
 */
BOOL mst_pci_read(MST *ctx, UINT32 bus, UINT32 slot,
                   UINT32 offset, UINT32 *value_out);

/*
 * IOCTL 0x222020 — Write a DWORD to PCI configuration space.
 */
BOOL mst_pci_write(MST *ctx, UINT32 bus, UINT32 slot,
                    UINT32 offset, UINT32 value);

/*
 * IOCTL 0x222008 — Enumerate Mellanox HCA devices known to the driver.
 * Returns device count and fills entries[] (up to max_entries).
 */
BOOL mst_enum_devices(MST *ctx, MST_DEVICE_ENTRY *entries,
                       UINT32 max_entries, UINT32 *count_out);

/*
 * IOCTL 0x222018 — Allocate a NonPaged physical page mapped to user.
 */
BOOL mst_alloc_page(MST *ctx, UINT64 *user_va_out, UINT64 *phys_addr_out);

/*
 * IOCTL 0x222024 — Enumerate all PCI devices on the system.
 * Returns bus/slot pairs.
 */
BOOL mst_enum_all_pci(MST *ctx, void *buffer, UINT32 buf_size,
                       UINT32 *count_out);

#ifdef __cplusplus
}
#endif

#endif /* MST_H */
