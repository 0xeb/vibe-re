/*
 * cormem.c -- Client library implementation
 */

#include "cormem.h"
#include <stdio.h>

#define DEVICE_PATH L"\\\\.\\CORMEM"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL cormem_open(CORMEM *ctx)
{
    ctx->last_error = 0;
    ctx->device = CreateFileW(DEVICE_PATH,
                              GENERIC_READ | GENERIC_WRITE,
                              FILE_SHARE_READ | FILE_SHARE_WRITE,
                              NULL, OPEN_EXISTING, 0, NULL);
    if (ctx->device == INVALID_HANDLE_VALUE) {
        ctx->last_error = GetLastError();
        return FALSE;
    }
    return TRUE;
}

void cormem_close(CORMEM *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

static BOOL ioctl(CORMEM *ctx, DWORD code,
                  void *in_buf, DWORD in_size,
                  void *out_buf, DWORD out_size,
                  DWORD *bytes_ret)
{
    DWORD bytes = 0;
    BOOL  ok = DeviceIoControl(ctx->device, code,
                               in_buf, in_size,
                               out_buf, out_size,
                               &bytes, NULL);
    if (bytes_ret)
        *bytes_ret = bytes;
    if (!ok)
        ctx->last_error = GetLastError();
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Read I/O port                                                     */
/* ------------------------------------------------------------------ */

BOOL cormem_read_io(CORMEM *ctx, UINT16 port, UINT32 data_size,
                    UINT32 *value_out)
{
    UINT64 req[2];
    UINT32 result = 0;

    *value_out = 0;

    /* Pack: low 32 bits = data size, bits 32-47 = port number */
    req[0] = (UINT64)data_size | ((UINT64)port << 32);
    req[1] = 0;

    if (!ioctl(ctx, IOCTL_CORMEM_READ_IO,
               req, sizeof(req),
               &result, sizeof(result), NULL))
        return FALSE;

    *value_out = result;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Write I/O port                                                    */
/* ------------------------------------------------------------------ */

BOOL cormem_write_io(CORMEM *ctx, UINT16 port, UINT32 data_size,
                     UINT32 value)
{
    UINT64 req[2];

    req[0] = (UINT64)data_size | ((UINT64)port << 32);
    req[1] = (UINT64)value << 32;  /* value in high dword of second qword */

    return ioctl(ctx, IOCTL_CORMEM_WRITE_IO,
                 req, sizeof(req),
                 NULL, 0, NULL);
}

/* ------------------------------------------------------------------ */
/*  Virtual to physical                                               */
/* ------------------------------------------------------------------ */

BOOL cormem_virt_to_phys(CORMEM *ctx, UINT64 virt_addr, UINT64 *phys_out)
{
    UINT64 buf = virt_addr;
    *phys_out = 0;

    if (!ioctl(ctx, IOCTL_CORMEM_VIRTUAL_TO_PHYS,
               &buf, sizeof(buf),
               &buf, sizeof(buf), NULL))
        return FALSE;

    *phys_out = buf;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Map physical buffer                                               */
/* ------------------------------------------------------------------ */

BOOL cormem_map_buffer(CORMEM *ctx, UINT64 phys_addr, UINT64 length,
                       PVOID *mapped_out)
{
    /*
     * The driver's MAPBUFFER IOCTL takes a structure:
     *   [0]: physical address (8 bytes)
     *   [1]: length (8 bytes)
     *   [2]: interface type (-1 for direct physical)
     *   [3]: bus number
     * Output: mapped virtual address (8 bytes)
     */
    UINT64 req[3];
    UINT64 result = 0;

    *mapped_out = NULL;

    req[0] = phys_addr;
    req[1] = length;
    req[2] = (UINT64)-1;  /* interface type = -1 (direct physical) */

    if (!ioctl(ctx, IOCTL_CORMEM_MAP_BUFFER,
               req, sizeof(req),
               &result, sizeof(result), NULL))
        return FALSE;

    *mapped_out = (PVOID)result;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Unmap buffer                                                      */
/* ------------------------------------------------------------------ */

BOOL cormem_unmap_buffer(CORMEM *ctx, PVOID mapped_addr)
{
    UINT64 buf = (UINT64)mapped_addr;
    return ioctl(ctx, IOCTL_CORMEM_UNMAP_BUFFER,
                 &buf, sizeof(buf),
                 NULL, 0, NULL);
}

/* ------------------------------------------------------------------ */
/*  Pool status                                                       */
/* ------------------------------------------------------------------ */

BOOL cormem_get_pool_status(CORMEM *ctx, CORMEM_POOL_STATUS *status_out)
{
    memset(status_out, 0, sizeof(*status_out));
    return ioctl(ctx, IOCTL_CORMEM_BUF_MEM_STATUS,
                 NULL, 0,
                 status_out, sizeof(*status_out), NULL);
}

/* ------------------------------------------------------------------ */
/*  Pool block count                                                  */
/* ------------------------------------------------------------------ */

BOOL cormem_get_pool_block_count(CORMEM *ctx, UINT32 *count_out)
{
    *count_out = 0;
    return ioctl(ctx, IOCTL_CORMEM_GET_POOL_BLOCK_COUNT,
                 NULL, 0,
                 count_out, sizeof(*count_out), NULL);
}

/* ------------------------------------------------------------------ */
/*  Convenience: read DWORD at physical address                       */
/* ------------------------------------------------------------------ */

BOOL cormem_read_phys32(CORMEM *ctx, UINT64 phys_addr, UINT32 *value_out)
{
    PVOID mapped;
    *value_out = 0;

    /* Map one page containing the target address */
    UINT64 page_base = phys_addr & ~0xFFFULL;
    UINT64 page_off  = phys_addr & 0xFFF;

    if (!cormem_map_buffer(ctx, page_base, 0x1000, &mapped))
        return FALSE;

    *value_out = *(volatile UINT32 *)((PUCHAR)mapped + page_off);

    cormem_unmap_buffer(ctx, mapped);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Convenience: write DWORD at physical address                      */
/* ------------------------------------------------------------------ */

BOOL cormem_write_phys32(CORMEM *ctx, UINT64 phys_addr, UINT32 value)
{
    PVOID mapped;

    UINT64 page_base = phys_addr & ~0xFFFULL;
    UINT64 page_off  = phys_addr & 0xFFF;

    if (!cormem_map_buffer(ctx, page_base, 0x1000, &mapped))
        return FALSE;

    *(volatile UINT32 *)((PUCHAR)mapped + page_off) = value;

    cormem_unmap_buffer(ctx, mapped);
    return TRUE;
}
