/*
 * nchost.c — Client library implementation
 */

#include "nchost.h"
#include <stdio.h>

#define DEVICE_PATH L"\\\\.\\NcHost"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL nchost_open(NCHOST *ctx)
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

void nchost_close(NCHOST *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

static BOOL ioctl(NCHOST *ctx, DWORD code, void *buf, DWORD size)
{
    DWORD bytes = 0;
    BOOL  ok = DeviceIoControl(ctx->device, code,
                               buf, size,   /* input  */
                               buf, size,   /* output */
                               &bytes, NULL);
    if (!ok)
        ctx->last_error = GetLastError();
    return ok;
}

/* ------------------------------------------------------------------ */
/*  IOCTL 0x222004: Get driver version                                */
/* ------------------------------------------------------------------ */

BOOL nchost_get_version(NCHOST *ctx, UINT32 *version_out)
{
    DWORD bytes = 0;
    UINT32 ver  = 0;
    BOOL ok = DeviceIoControl(ctx->device, IOCTL_NCHOST_GET_VERSION,
                              NULL, 0,
                              &ver, sizeof(ver),
                              &bytes, NULL);
    if (!ok) {
        ctx->last_error = GetLastError();
        return FALSE;
    }
    *version_out = ver;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  IOCTL 0x2221A4: Read physical memory                              */
/*                                                                    */
/*  Loops across page boundaries — the driver processes one page per  */
/*  call (0x1000 minus the intra-page offset).                        */
/* ------------------------------------------------------------------ */

BOOL nchost_read_physical(NCHOST *ctx, UINT64 phys_addr,
                          void *buffer, SIZE_T size)
{
    PUCHAR dst = (PUCHAR)buffer;
    SIZE_T remaining = size;

    while (remaining > 0) {
        SIZE_T page_remaining = 0x1000 - (phys_addr & 0xFFF);
        SIZE_T chunk = (remaining < page_remaining) ? remaining : page_remaining;

        NCHOST_PHYSMEM_REQUEST req = {0};
        req.phys_addr = phys_addr;

        /* The driver reads OutputBufferLength bytes, so we set output
         * size to 'chunk'.  Since METHOD_NEITHER uses Type3InputBuffer,
         * we pass the request struct as input and receive data in it. */
        DWORD bytes = 0;
        BOOL ok = DeviceIoControl(ctx->device, IOCTL_NCHOST_READ_PHYSICAL,
                                  &req, sizeof(req),
                                  dst, (DWORD)chunk,
                                  &bytes, NULL);
        if (!ok) {
            ctx->last_error = GetLastError();
            return FALSE;
        }

        dst       += chunk;
        phys_addr += chunk;
        remaining -= chunk;
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  IOCTL 0x2221DC subcmd 1: translate virtual -> physical            */
/* ------------------------------------------------------------------ */

BOOL nchost_get_physical_addr(NCHOST *ctx, UINT64 virt_addr,
                              UINT64 *phys_out)
{
    NCHOST_PHYSOP_REQUEST req = {0};
    req.magic      = 0x4641;   /* 'AF' */
    req.subcommand = NCHOST_PHYSOP_GET_PA;
    req.virt_addr  = virt_addr;

    if (!ioctl(ctx, IOCTL_NCHOST_PHYSICAL_OP, &req, sizeof(req)))
        return FALSE;

    *phys_out = *(UINT64 *)&req;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  IOCTL 0x2221DC subcmd 2: write physical memory                    */
/*                                                                    */
/*  Loops across page boundaries.                                     */
/* ------------------------------------------------------------------ */

BOOL nchost_write_physical(NCHOST *ctx, UINT64 phys_addr,
                           const void *buffer, SIZE_T size)
{
    const PUCHAR src = (const PUCHAR)buffer;
    SIZE_T remaining = size;
    SIZE_T offset = 0;

    while (remaining > 0) {
        SIZE_T page_remaining = 0x1000 - (phys_addr & 0xFFF);
        SIZE_T chunk = (remaining < page_remaining) ? remaining : page_remaining;

        NCHOST_PHYSOP_REQUEST req = {0};
        req.magic      = 0x4641;
        req.subcommand = NCHOST_PHYSOP_WRITE_PHYS;
        req.map_size   = 0x1000;
        req.copy_size  = chunk;
        req.virt_addr  = (UINT64)(src + offset);
        req.mdl_or_dst = phys_addr & 0xFFF;  /* offset within mapped page */
        req.phys_addr  = phys_addr & ~0xFFFULL;

        if (!ioctl(ctx, IOCTL_NCHOST_PHYSICAL_OP, &req, sizeof(req)))
            return FALSE;

        offset    += chunk;
        phys_addr += chunk;
        remaining -= chunk;
    }
    return TRUE;
}
