/*
 * fastdump.h — Client library for the FastDump kernel driver (fastdumpx64.sys)
 *
 * Provides typed wrappers around the IOCTLs exposed by
 * \\.\FastDump:
 *
 *   0x9C400007  Map user pages for DMA-style reads
 *   0x9C400014  Read arbitrary physical memory range
 *   0x9C400018  Read physical memory into mapped buffer
 *   0x9C40001C  Get CPU info (CPUID + MSR + memory ranges)
 *   0x9C40002C  Get raw CPUID leaves
 *   0x9C400030  Read model-specific register (MSR)
 *
 * Usage:
 *   FASTDUMP ctx;
 *   if (fastdump_open(&ctx)) {
 *       UCHAR page[0x1000];
 *       fastdump_read_phys(&ctx, 0x1000, page, sizeof(page));
 *       ...
 *       fastdump_close(&ctx);
 *   }
 */

#ifndef FASTDUMP_H
#define FASTDUMP_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — custom device type 0x9C40                           */
/* ------------------------------------------------------------------ */

#define IOCTL_FASTDUMP_MAP_BUFFER        0x9C400007
#define IOCTL_FASTDUMP_READ_PHYS         0x9C400014
#define IOCTL_FASTDUMP_READ_PHYS_MAPPED  0x9C400018
#define IOCTL_FASTDUMP_GET_CPUINFO_FULL  0x9C40001C
#define IOCTL_FASTDUMP_GET_CPUID         0x9C40002C
#define IOCTL_FASTDUMP_READ_MSR          0x9C400030

/* ------------------------------------------------------------------ */
/*  Status codes from driver response                                 */
/* ------------------------------------------------------------------ */

#define FD_STATUS_SUCCESS       0x00010000
#define FD_STATUS_ERROR_MASK    0x00030000

/* ------------------------------------------------------------------ */
/*  IOCTL request / response structures                               */
/* ------------------------------------------------------------------ */

#pragma pack(push, 8)

/*
 * IOCTL_FASTDUMP_READ_PHYS_MAPPED (0x9C400018)
 * Input:  20 bytes — status, phys_addr, size, ...
 * Output: 0x34 + read_size bytes
 */
typedef struct FASTDUMP_READ_PHYS_REQUEST_TAG {
    UINT32      status;         /* driver sets to FD_STATUS_SUCCESS */
    UINT64      phys_addr;      /* physical address (page-aligned)  */
    UINT32      size;           /* bytes to read                    */
    UINT32      valid_mask_lo;  /* bitmask of valid pages (low)     */
    UCHAR       valid_bitmap[0x20]; /* per-page validity            */
    /* followed by read data at offset 0x34 */
} FASTDUMP_READ_PHYS_REQUEST, *PFASTDUMP_READ_PHYS_REQUEST;

/*
 * IOCTL_FASTDUMP_READ_MSR (0x9C400030)
 * Input:  12 bytes — status, msr_index
 * Output: 16 bytes — status, msr_value
 */
typedef struct FASTDUMP_MSR_REQUEST_TAG {
    UINT32      status;
    UINT32      pad;
    UINT64      msr_value;      /* in: MSR index; out: MSR value    */
} FASTDUMP_MSR_REQUEST, *PFASTDUMP_MSR_REQUEST;

/*
 * IOCTL_FASTDUMP_GET_CPUID (0x9C40002C)
 * Output: 0x410 bytes of CPUID leaf data
 */
typedef struct FASTDUMP_CPUID_LEAF_TAG {
    UINT32      eax;
    UINT32      ebx;
    UINT32      edx;
    UINT32      ecx;
} FASTDUMP_CPUID_LEAF, *PFASTDUMP_CPUID_LEAF;

typedef struct FASTDUMP_CPUID_RESPONSE_TAG {
    UINT32      status;
    UINT32      pad;
    UINT32      max_leaf;       /* number of standard leaves        */
    UINT32      max_ext_leaf;   /* number of extended leaves        */
    FASTDUMP_CPUID_LEAF standard[0x21]; /* leaves 0..0x20          */
    FASTDUMP_CPUID_LEAF extended[0x21]; /* leaves 0x80000000+      */
} FASTDUMP_CPUID_RESPONSE, *PFASTDUMP_CPUID_RESPONSE;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct FASTDUMP_TAG {
    HANDLE      device;
    DWORD       last_error;
} FASTDUMP, *PFASTDUMP;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\FastDump.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL fastdump_open(FASTDUMP *ctx);

/*
 * Close the device handle.
 */
void fastdump_close(FASTDUMP *ctx);

/*
 * Read `size` bytes from physical address `phys_addr` into `buffer`.
 * Uses IOCTL_FASTDUMP_READ_PHYS_MAPPED.  The driver maps via
 * MmMapIoSpace and copies back; no access checks apply.
 *
 * This wrapper loops to satisfy reads larger than one page.
 */
BOOL fastdump_read_phys(FASTDUMP *ctx, UINT64 phys_addr,
                        void *buffer, SIZE_T size);

/*
 * Read a single MSR by index.  Executes RDMSR in ring 0.
 */
BOOL fastdump_read_msr(FASTDUMP *ctx, UINT32 msr_index, UINT64 *value);

/*
 * Retrieve all CPUID leaves (standard + extended).
 * Output buffer must be at least sizeof(FASTDUMP_CPUID_RESPONSE).
 */
BOOL fastdump_get_cpuid(FASTDUMP *ctx, FASTDUMP_CPUID_RESPONSE *out);

/*
 * Read a single physical page (0x1000 bytes) via IRP_MJ_READ.
 * `phys_addr` must be page-aligned.
 */
BOOL fastdump_read_page(FASTDUMP *ctx, UINT64 phys_addr, void *buffer);

#ifdef __cplusplus
}
#endif

#endif /* FASTDUMP_H */
