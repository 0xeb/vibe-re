/*
 * mst.c — Client library implementation
 */

#include "mst.h"
#include <stdio.h>

#define DEVICE_PATH L"\\\\.\\mst64_4.20.0"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL mst_open(MST *ctx)
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

void mst_close(MST *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

static BOOL ioctl(MST *ctx, DWORD code,
                  void *inBuf, DWORD inSize,
                  void *outBuf, DWORD outSize,
                  DWORD *bytesOut)
{
    DWORD bytes = 0;
    BOOL  ok = DeviceIoControl(ctx->device, code,
                               inBuf, inSize,
                               outBuf, outSize,
                               &bytes, NULL);
    if (bytesOut)
        *bytesOut = bytes;
    if (!ok)
        ctx->last_error = GetLastError();
    return ok;
}

/* ------------------------------------------------------------------ */
/*  PCI configuration read                                            */
/* ------------------------------------------------------------------ */

BOOL mst_pci_read(MST *ctx, UINT32 bus, UINT32 slot,
                   UINT32 offset, UINT32 *value_out)
{
    MST_PCI_READ_REQUEST req;
    UINT32 result = 0;

    req.bus    = bus;
    req.slot   = slot;
    req.offset = offset;

    if (!ioctl(ctx, IOCTL_MST_PCI_READ_DWORD,
               &req, sizeof(req),
               &result, sizeof(result), NULL))
        return FALSE;

    *value_out = result;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  PCI configuration write                                           */
/* ------------------------------------------------------------------ */

BOOL mst_pci_write(MST *ctx, UINT32 bus, UINT32 slot,
                    UINT32 offset, UINT32 value)
{
    MST_PCI_WRITE_REQUEST req;

    req.bus    = bus;
    req.slot   = slot;
    req.offset = offset;
    req.value  = value;

    return ioctl(ctx, IOCTL_MST_PCI_WRITE_DWORD,
                 &req, sizeof(req),
                 NULL, 0, NULL);
}

/* ------------------------------------------------------------------ */
/*  Enumerate Mellanox HCA devices                                    */
/* ------------------------------------------------------------------ */

BOOL mst_enum_devices(MST *ctx, MST_DEVICE_ENTRY *entries,
                       UINT32 max_entries, UINT32 *count_out)
{
    UINT8  buf[0x4008];
    UINT32 count;
    UINT32 i, copy;

    *count_out = 0;

    if (!ioctl(ctx, IOCTL_MST_ENUM,
               NULL, 0,
               buf, sizeof(buf), NULL))
        return FALSE;

    /* Device count is at offset 0x4000 (after the device table) */
    count = *(UINT32 *)(buf + 0x4000);
    copy  = (count < max_entries) ? count : max_entries;

    for (i = 0; i < copy; i++) {
        memcpy(&entries[i], buf + i * sizeof(MST_DEVICE_ENTRY),
               sizeof(MST_DEVICE_ENTRY));
    }
    *count_out = count;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Allocate a physical page                                          */
/* ------------------------------------------------------------------ */

BOOL mst_alloc_page(MST *ctx, UINT64 *user_va_out, UINT64 *phys_addr_out)
{
    MST_ALLOC_PAGE_OUT out = {0};

    if (!ioctl(ctx, IOCTL_MST_ALLOC_PAGE,
               NULL, 0,
               &out, sizeof(out), NULL))
        return FALSE;

    *user_va_out    = out.user_va;
    *phys_addr_out  = out.phys_addr;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Enumerate all PCI devices                                         */
/* ------------------------------------------------------------------ */

BOOL mst_enum_all_pci(MST *ctx, void *buffer, UINT32 buf_size,
                       UINT32 *count_out)
{
    DWORD bytes = 0;

    *count_out = 0;

    if (!ioctl(ctx, IOCTL_MST_PCI_GET_DEVICES,
               NULL, 0,
               buffer, buf_size, &bytes))
        return FALSE;

    if (bytes >= 8)
        *count_out = ((UINT32 *)buffer)[1];

    return TRUE;
}
