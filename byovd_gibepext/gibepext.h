/*
 * gibepext.h — Client library for the gibepext kernel driver (gibepext.sys)
 *
 * Provides typed wrappers around the firmware IOCTLs exposed by
 * \\.\GibEpFirmware:
 *
 *   0x22e008  Read PCI configuration register
 *   0x22e00c  Read physical memory
 *   0x22e010  Write physical memory
 *   0x22e014  Map IO space (MmMapIoSpace)
 *   0x22e020  Read MSR
 *   0x22e024  Get physical address (MmGetPhysicalAddress)
 *
 * Usage:
 *   GIBEPEXT ctx;
 *   if (gibepext_open(&ctx)) {
 *       UINT8 buf[256];
 *       gibepext_read_physmem(&ctx, 0x1000, buf, sizeof(buf));
 *       ...
 *       gibepext_close(&ctx);
 *   }
 */

#ifndef GIBEPEXT_H
#define GIBEPEXT_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — firmware module                                     */
/* ------------------------------------------------------------------ */

#define IOCTL_GIBEPEXT_READ_PCI_CFG     0x22e008
#define IOCTL_GIBEPEXT_READ_PHYSMEM     0x22e00c
#define IOCTL_GIBEPEXT_READ_PHYSMEM_MDL 0x22e00e
#define IOCTL_GIBEPEXT_WRITE_PHYSMEM    0x22e010
#define IOCTL_GIBEPEXT_MAP_IOSPACE      0x22e014
#define IOCTL_GIBEPEXT_READ_MSR         0x22e020
#define IOCTL_GIBEPEXT_GET_PHYS_ADDR    0x22e024
#define IOCTL_GIBEPEXT_GET_STATS        0x226007

/* ------------------------------------------------------------------ */
/*  IOCTL request structures (must match driver layout exactly)       */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

typedef struct GIBEPEXT_PHYSMEM_REQUEST {
    UINT32      addr_lo;        /* physical address low DWORD           */
    UINT32      addr_hi;        /* physical address high DWORD          */
    UINT32      size;           /* byte count (0 treated as 4)          */
    UINT32      checksum;       /* CRC-32 of first 12 bytes            */
} GIBEPEXT_PHYSMEM_REQUEST;

typedef struct GIBEPEXT_WRITE_PHYSMEM_REQUEST {
    UINT32      addr_lo;        /* physical address low DWORD           */
    UINT32      addr_hi;        /* physical address high DWORD          */
    UINT32      size;           /* byte count of data following         */
    /* UINT8    data[size]; */  /* payload bytes                        */
    /* UINT32   checksum;  */   /* CRC-32 of (header + data)            */
} GIBEPEXT_WRITE_PHYSMEM_REQUEST;

typedef struct GIBEPEXT_MSR_REQUEST {
    UINT32      cpu_index;      /* which CPU to read from               */
    UINT32      msr_reg;        /* MSR register number                  */
    UINT32      checksum;       /* CRC-32 of first 8 bytes              */
} GIBEPEXT_MSR_REQUEST;

typedef struct GIBEPEXT_MSR_RESULT {
    UINT32      lo;             /* low 32 bits of MSR value             */
    UINT32      hi;             /* high 32 bits of MSR value            */
} GIBEPEXT_MSR_RESULT;

typedef struct GIBEPEXT_VIRT2PHYS_REQUEST {
    UINT64      virtual_addr;
    UINT32      checksum;       /* CRC-32 of first 8 bytes              */
} GIBEPEXT_VIRT2PHYS_REQUEST;

typedef struct GIBEPEXT_MAP_REQUEST {
    UINT64      phys_addr;      /* physical address to map              */
    UINT32      size;           /* mapping size                         */
    UINT32      pad;
    UINT32      cache_type;     /* MEMORY_CACHING_TYPE                  */
    UINT32      reserved;
    UINT32      checksum;       /* CRC-32 of first 24 bytes             */
} GIBEPEXT_MAP_REQUEST;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct GIBEPEXT {
    HANDLE      device;
    DWORD       last_error;
} GIBEPEXT;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\GibEpFirmware.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL gibepext_open(GIBEPEXT *ctx);

/*
 * Close the device handle.
 */
void gibepext_close(GIBEPEXT *ctx);

/*
 * Read `size` bytes from physical address `phys_addr` into `buffer`.
 */
BOOL gibepext_read_physmem(GIBEPEXT *ctx, UINT64 phys_addr,
                           void *buffer, UINT32 size);

/*
 * Write `size` bytes from `buffer` to physical address `phys_addr`.
 */
BOOL gibepext_write_physmem(GIBEPEXT *ctx, UINT64 phys_addr,
                            const void *buffer, UINT32 size);

/*
 * Read an MSR register on a specific CPU.
 */
BOOL gibepext_read_msr(GIBEPEXT *ctx, UINT32 cpu_index, UINT32 msr_reg,
                       UINT32 *lo, UINT32 *hi);

/*
 * Translate a virtual address to a physical address via the driver.
 */
BOOL gibepext_get_phys_addr(GIBEPEXT *ctx, UINT64 virtual_addr,
                            UINT64 *phys_out);

/*
 * Map an IO-space region via MmMapIoSpace (returns kernel VA).
 * WARNING: The returned pointer is a kernel-mode address.
 */
BOOL gibepext_map_iospace(GIBEPEXT *ctx, UINT64 phys_addr, UINT32 size,
                          UINT32 cache_type, UINT64 *mapped_out);

/*
 * CRC-32 checksum (matches the driver's integrity check).
 */
UINT32 gibepext_crc32(const void *data, UINT32 len);

#ifdef __cplusplus
}
#endif

#endif /* GIBEPEXT_H */
