/*
 * winhwdriver.h — Client library for the WinHwDriver kernel driver
 *                 (SysFile_X64.sys)
 *
 * Provides typed wrappers around the IOCTLs exposed by
 * \\.\WinHwDriver:
 *
 *   0x9c402000  Get driver version
 *   0x9c402004  Get reference count
 *   0x9c402084  Read MSR
 *   0x9c402088  Write MSR
 *   0x9c4060CC  Read I/O port (byte)
 *   0x9c4060D0  Read I/O port (word)
 *   0x9c4060D4  Read I/O port (dword)
 *   0x9c40A0D8  Write I/O port (byte)
 *   0x9c40A0DC  Write I/O port (word)
 *   0x9c40A0E0  Write I/O port (dword)
 *   0x9c406104  Read physical memory
 *   0x9c40A108  Write physical memory
 *   0x9c406144  Read PCI configuration
 *   0x9c40A148  Write PCI configuration
 *
 * Usage:
 *   WINHWDRIVER ctx;
 *   if (winhwdriver_open(&ctx)) {
 *       UINT32 version;
 *       winhwdriver_get_version(&ctx, &version);
 *       ...
 *       winhwdriver_close(&ctx);
 *   }
 */

#ifndef WINHWDRIVER_H
#define WINHWDRIVER_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes                                                       */
/* ------------------------------------------------------------------ */

#define IOCTL_WHD_GET_DRIVER_VERSION  0x9c402000
#define IOCTL_WHD_GET_REFCOUNT        0x9c402004

#define IOCTL_WHD_READ_MSR            0x9c402084
#define IOCTL_WHD_WRITE_MSR           0x9c402088

#define IOCTL_WHD_READ_IO_PORT_BYTE   0x9c4060CC
#define IOCTL_WHD_READ_IO_PORT_WORD   0x9c4060D0
#define IOCTL_WHD_READ_IO_PORT_DWORD  0x9c4060D4

#define IOCTL_WHD_WRITE_IO_PORT_BYTE  0x9c40A0D8
#define IOCTL_WHD_WRITE_IO_PORT_WORD  0x9c40A0DC
#define IOCTL_WHD_WRITE_IO_PORT_DWORD 0x9c40A0E0

#define IOCTL_WHD_READ_MEMORY         0x9c406104
#define IOCTL_WHD_WRITE_MEMORY        0x9c40A108

#define IOCTL_WHD_READ_PCI_CONFIG     0x9c406144
#define IOCTL_WHD_WRITE_PCI_CONFIG    0x9c40A148

/* ------------------------------------------------------------------ */
/*  IOCTL request structures (must match driver layout exactly)       */
/* ------------------------------------------------------------------ */

#pragma pack(push, 8)

typedef struct WHD_MSR_REQUEST_TAG {
    UINT32      Address;        /* MSR register index                  */
    UINT64      Data;           /* MSR value (read result / write src) */
} WHD_MSR_REQUEST;

typedef struct WHD_IO_PORT_REQUEST_TAG {
    UINT32      Port;           /* I/O port number                     */
    UINT32      Value;          /* port value (read result / write src)*/
} WHD_IO_PORT_REQUEST;

typedef struct WHD_PCI_CONFIG_REQUEST_TAG {
    UINT32      PciAddress;     /* bus/device/function packed address  */
    UINT32      PciOffset;      /* register offset into config space   */
} WHD_PCI_CONFIG_REQUEST;

typedef struct WHD_MEMORY_REQUEST_TAG {
    UINT64      PhysicalAddress;/* target physical address             */
    UINT32      UnitSize;       /* element width: 1, 2, 4, or 8       */
    UINT32      Count;          /* number of elements                  */
} WHD_MEMORY_REQUEST;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct WINHWDRIVER_TAG {
    HANDLE      device;
    DWORD       last_error;
} WINHWDRIVER;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\WinHwDriver.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL winhwdriver_open(WINHWDRIVER *ctx);

/*
 * Close the device handle.
 */
void winhwdriver_close(WINHWDRIVER *ctx);

/*
 * IOCTL 0x9c402000 — Get driver version (4-byte UINT32).
 */
BOOL winhwdriver_get_version(WINHWDRIVER *ctx, UINT32 *version_out);

/*
 * IOCTL 0x9c402004 — Get open-handle reference count.
 */
BOOL winhwdriver_get_refcount(WINHWDRIVER *ctx, INT32 *count_out);

/*
 * IOCTL 0x9c402084 — Read a Model-Specific Register.
 */
BOOL winhwdriver_read_msr(WINHWDRIVER *ctx, UINT32 msr_addr,
                          UINT64 *value_out);

/*
 * IOCTL 0x9c402088 — Write a Model-Specific Register.
 */
BOOL winhwdriver_write_msr(WINHWDRIVER *ctx, UINT32 msr_addr,
                           UINT64 value);

/*
 * IOCTL 0x9c4060CC/D0/D4 — Read from an I/O port.
 * `size` must be 1, 2, or 4.
 */
BOOL winhwdriver_read_io_port(WINHWDRIVER *ctx, UINT32 port,
                              UINT32 size, UINT32 *value_out);

/*
 * IOCTL 0x9c40A0D8/DC/E0 — Write to an I/O port.
 * `size` must be 1, 2, or 4.
 */
BOOL winhwdriver_write_io_port(WINHWDRIVER *ctx, UINT32 port,
                               UINT32 size, UINT32 value);

/*
 * IOCTL 0x9c406104 — Read physical memory.
 * Maps `count * unit_size` bytes at `phys_addr` and copies to `buffer`.
 */
BOOL winhwdriver_read_memory(WINHWDRIVER *ctx, UINT64 phys_addr,
                             UINT32 unit_size, UINT32 count,
                             void *buffer);

/*
 * IOCTL 0x9c40A108 — Write physical memory.
 * Maps `count * unit_size` bytes at `phys_addr` and copies from `buffer`.
 */
BOOL winhwdriver_write_memory(WINHWDRIVER *ctx, UINT64 phys_addr,
                              UINT32 unit_size, UINT32 count,
                              const void *buffer);

/*
 * IOCTL 0x9c406144 — Read PCI configuration space.
 * Reads `length` bytes at `offset` from the PCI device at `pci_addr`.
 */
BOOL winhwdriver_read_pci_config(WINHWDRIVER *ctx, UINT32 pci_addr,
                                 UINT32 offset, void *buffer,
                                 UINT32 length);

/*
 * IOCTL 0x9c40A148 — Write PCI configuration space.
 * Writes `length` bytes at `offset` to the PCI device at `pci_addr`.
 */
BOOL winhwdriver_write_pci_config(WINHWDRIVER *ctx, UINT32 pci_addr,
                                  UINT32 offset, const void *buffer,
                                  UINT32 length);

#ifdef __cplusplus
}
#endif

#endif /* WINHWDRIVER_H */
