/*
 * cormem.h -- Client library for the CORMEM kernel driver (Cormem.sys)
 *
 * Provides typed wrappers around the IOCTLs exposed by
 * \\.\CORMEM (Sapera LT Memory Manager):
 *
 *   0x222000  MapPool          — map a contiguous memory pool block
 *   0x222004  FreeBuffer       — free a virtual buffer allocation
 *   0x22200C  MapBuffer        — map physical memory via ZwMapViewOfSection
 *   0x222010  UnmapBuffer      — unmap a previously mapped buffer
 *   0x222014  ReadIo           — read an I/O port (byte/word/dword)
 *   0x222018  WriteIo          — write an I/O port (byte/word/dword)
 *   0x22201C  VirtualToPhys    — translate virtual to physical address
 *   0x222030  AllocBufferObj   — allocate from 32-bit object pool
 *   0x222034  AllocBufferMsg   — allocate from messaging pool
 *   0x22203C  AllocPhysMem     — allocate physically contiguous pages
 *   0x222044  MapPhysMem       — map an MDL into user address space
 *   0x222058  CreateMdlAndLock — lock a user buffer and create MDL
 *
 * Usage:
 *   CORMEM ctx;
 *   if (cormem_open(&ctx)) {
 *       UINT32 val;
 *       cormem_read_io(&ctx, 0x3F8, 1, &val);
 *       ...
 *       cormem_close(&ctx);
 *   }
 */

#ifndef CORMEM_H
#define CORMEM_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — METHOD_BUFFERED, FILE_DEVICE_UNKNOWN (0x22)         */
/* ------------------------------------------------------------------ */

#define IOCTL_CORMEM_MAPPOOL              0x222000
#define IOCTL_CORMEM_FREE_BUFFER          0x222004
#define IOCTL_CORMEM_GET_FUNCTIONS        0x222008
#define IOCTL_CORMEM_MAP_BUFFER           0x22200C
#define IOCTL_CORMEM_UNMAP_BUFFER         0x222010
#define IOCTL_CORMEM_READ_IO              0x222014
#define IOCTL_CORMEM_WRITE_IO             0x222018
#define IOCTL_CORMEM_VIRTUAL_TO_PHYS      0x22201C
#define IOCTL_CORMEM_FREE_BUFFER_PHYS     0x222020
#define IOCTL_CORMEM_SG_LOCK              0x222024
#define IOCTL_CORMEM_USERBUF_FREE         0x222028
#define IOCTL_CORMEM_FREE_UNUSED          0x22202C
#define IOCTL_CORMEM_ALLOC_BUF_OBJ        0x222030
#define IOCTL_CORMEM_ALLOC_BUF_MSG        0x222034
#define IOCTL_CORMEM_GET_MSG_BOUNDARY     0x222038
#define IOCTL_CORMEM_ALLOC_PHYS           0x22203C
#define IOCTL_CORMEM_FREE_PHYS            0x222040
#define IOCTL_CORMEM_MAP_PHYS             0x222044
#define IOCTL_CORMEM_UNMAP_PHYS           0x222048
#define IOCTL_CORMEM_GET_PHYS             0x22204C
#define IOCTL_CORMEM_BUF_OBJ_STATUS       0x222050
#define IOCTL_CORMEM_BUF_MEM_STATUS       0x222054
#define IOCTL_CORMEM_CREATE_MDL_LOCK      0x222058
#define IOCTL_CORMEM_GET_POOL_BLOCK_COUNT 0x22205C
#define IOCTL_CORMEM_GET_PHYS_64          0x222060
#define IOCTL_CORMEM_ALLOC_BUF_OBJ64      0x222064
#define IOCTL_CORMEM_BUF_OBJ64_STATUS     0x222068

/* ------------------------------------------------------------------ */
/*  IOCTL request structures (must match driver layout exactly)       */
/* ------------------------------------------------------------------ */

#pragma pack(push, 8)

typedef struct CORMEM_IO_REQUEST {
    UINT64      port_and_size;      /* low 32 = data size, high 16 = port */
    UINT64      value;              /* data value (for write)             */
} CORMEM_IO_REQUEST;

typedef struct CORMEM_MAP_REQUEST {
    UINT64      phys_addr;          /* physical address to map            */
    UINT64      length;             /* length in bytes                    */
    INT32       interface_type;     /* bus interface (-1 for direct)      */
    UINT32      bus_number;
} CORMEM_MAP_REQUEST;

typedef struct CORMEM_POOL_STATUS {
    UINT32      struct_size;
    UINT32      free_size;
    UINT32      free_frags;
    UINT32      max_free_block;
    UINT32      used_size;
    UINT32      used_frags;
    UINT32      max_used_block;
} CORMEM_POOL_STATUS;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct CORMEM {
    HANDLE      device;
    DWORD       last_error;
} CORMEM;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\CORMEM.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL cormem_open(CORMEM *ctx);

/*
 * Close the device handle.
 */
void cormem_close(CORMEM *ctx);

/*
 * IOCTL 0x222014 -- Read an I/O port.
 * data_size: 1 (byte), 2 (word), or 4 (dword).
 */
BOOL cormem_read_io(CORMEM *ctx, UINT16 port, UINT32 data_size,
                    UINT32 *value_out);

/*
 * IOCTL 0x222018 -- Write an I/O port.
 * data_size: 1, 2, or 4.
 */
BOOL cormem_write_io(CORMEM *ctx, UINT16 port, UINT32 data_size,
                     UINT32 value);

/*
 * IOCTL 0x22201C -- Translate a virtual address to a physical address.
 */
BOOL cormem_virt_to_phys(CORMEM *ctx, UINT64 virt_addr, UINT64 *phys_out);

/*
 * IOCTL 0x22200C -- Map a region of physical memory into the caller's
 * address space via \\Device\\PhysicalMemory.
 */
BOOL cormem_map_buffer(CORMEM *ctx, UINT64 phys_addr, UINT64 length,
                       PVOID *mapped_out);

/*
 * IOCTL 0x222010 -- Unmap a previously mapped buffer.
 */
BOOL cormem_unmap_buffer(CORMEM *ctx, PVOID mapped_addr);

/*
 * IOCTL 0x222054 -- Query messaging pool status.
 */
BOOL cormem_get_pool_status(CORMEM *ctx, CORMEM_POOL_STATUS *status_out);

/*
 * IOCTL 0x22205C -- Get total pool block count.
 */
BOOL cormem_get_pool_block_count(CORMEM *ctx, UINT32 *count_out);

/*
 * Convenience: read a DWORD from a physical address (map, read, unmap).
 */
BOOL cormem_read_phys32(CORMEM *ctx, UINT64 phys_addr, UINT32 *value_out);

/*
 * Convenience: write a DWORD to a physical address (map, write, unmap).
 */
BOOL cormem_write_phys32(CORMEM *ctx, UINT64 phys_addr, UINT32 value);

#ifdef __cplusplus
}
#endif

#endif /* CORMEM_H */
