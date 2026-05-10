/*
 * winhwdriver.c — Client library implementation
 */

#include "winhwdriver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEVICE_PATH L"\\\\.\\WinHwDriver"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_open(WINHWDRIVER *ctx)
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

void winhwdriver_close(WINHWDRIVER *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

static BOOL ioctl_rw(WINHWDRIVER *ctx, DWORD code,
                     void *in_buf, DWORD in_size,
                     void *out_buf, DWORD out_size,
                     DWORD *bytes_out)
{
    DWORD bytes = 0;
    BOOL  ok = DeviceIoControl(ctx->device, code,
                               in_buf, in_size,
                               out_buf, out_size,
                               &bytes, NULL);
    if (bytes_out)
        *bytes_out = bytes;
    if (!ok)
        ctx->last_error = GetLastError();
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Get driver version                                                */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_get_version(WINHWDRIVER *ctx, UINT32 *version_out)
{
    *version_out = 0;
    return ioctl_rw(ctx, IOCTL_WHD_GET_DRIVER_VERSION,
                    NULL, 0, version_out, sizeof(*version_out), NULL);
}

/* ------------------------------------------------------------------ */
/*  Get reference count                                               */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_get_refcount(WINHWDRIVER *ctx, INT32 *count_out)
{
    *count_out = 0;
    return ioctl_rw(ctx, IOCTL_WHD_GET_REFCOUNT,
                    NULL, 0, count_out, sizeof(*count_out), NULL);
}

/* ------------------------------------------------------------------ */
/*  Read MSR                                                          */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_read_msr(WINHWDRIVER *ctx, UINT32 msr_addr,
                          UINT64 *value_out)
{
    WHD_MSR_REQUEST req = {0};
    BOOL ok;

    req.Address = msr_addr;
    *value_out = 0;

    ok = ioctl_rw(ctx, IOCTL_WHD_READ_MSR,
                  &req, sizeof(req), &req, sizeof(req), NULL);
    if (ok)
        *value_out = req.Data;
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Write MSR                                                         */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_write_msr(WINHWDRIVER *ctx, UINT32 msr_addr,
                           UINT64 value)
{
    WHD_MSR_REQUEST req = {0};

    req.Address = msr_addr;
    req.Data    = value;

    return ioctl_rw(ctx, IOCTL_WHD_WRITE_MSR,
                    &req, sizeof(req), &req, sizeof(req), NULL);
}

/* ------------------------------------------------------------------ */
/*  Read I/O port                                                     */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_read_io_port(WINHWDRIVER *ctx, UINT32 port,
                              UINT32 size, UINT32 *value_out)
{
    WHD_IO_PORT_REQUEST req = {0};
    DWORD ioctl;
    BOOL  ok;

    req.Port = port;
    *value_out = 0;

    switch (size) {
    case 1: ioctl = IOCTL_WHD_READ_IO_PORT_BYTE;  break;
    case 2: ioctl = IOCTL_WHD_READ_IO_PORT_WORD;  break;
    case 4: ioctl = IOCTL_WHD_READ_IO_PORT_DWORD; break;
    default:
        ctx->last_error = ERROR_INVALID_PARAMETER;
        return FALSE;
    }

    ok = ioctl_rw(ctx, ioctl, &req, sizeof(req),
                  &req, sizeof(req), NULL);
    if (ok)
        *value_out = req.Value;
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Write I/O port                                                    */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_write_io_port(WINHWDRIVER *ctx, UINT32 port,
                               UINT32 size, UINT32 value)
{
    WHD_IO_PORT_REQUEST req = {0};
    DWORD ioctl;

    req.Port  = port;
    req.Value = value;

    switch (size) {
    case 1: ioctl = IOCTL_WHD_WRITE_IO_PORT_BYTE;  break;
    case 2: ioctl = IOCTL_WHD_WRITE_IO_PORT_WORD;  break;
    case 4: ioctl = IOCTL_WHD_WRITE_IO_PORT_DWORD; break;
    default:
        ctx->last_error = ERROR_INVALID_PARAMETER;
        return FALSE;
    }

    return ioctl_rw(ctx, ioctl, &req, sizeof(req), NULL, 0, NULL);
}

/* ------------------------------------------------------------------ */
/*  Read physical memory                                              */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_read_memory(WINHWDRIVER *ctx, UINT64 phys_addr,
                             UINT32 unit_size, UINT32 count,
                             void *buffer)
{
    WHD_MEMORY_REQUEST req = {0};
    DWORD total = unit_size * count;

    req.PhysicalAddress = phys_addr;
    req.UnitSize        = unit_size;
    req.Count           = count;

    return ioctl_rw(ctx, IOCTL_WHD_READ_MEMORY,
                    &req, sizeof(req), buffer, total, NULL);
}

/* ------------------------------------------------------------------ */
/*  Write physical memory                                             */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_write_memory(WINHWDRIVER *ctx, UINT64 phys_addr,
                              UINT32 unit_size, UINT32 count,
                              const void *buffer)
{
    DWORD total = unit_size * count;
    DWORD req_size = (DWORD)(sizeof(WHD_MEMORY_REQUEST) + total);
    PUCHAR req_buf;
    BOOL   ok;

    req_buf = (PUCHAR)malloc(req_size);
    if (!req_buf) {
        ctx->last_error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }

    memset(req_buf, 0, req_size);
    ((WHD_MEMORY_REQUEST *)req_buf)->PhysicalAddress = phys_addr;
    ((WHD_MEMORY_REQUEST *)req_buf)->UnitSize        = unit_size;
    ((WHD_MEMORY_REQUEST *)req_buf)->Count           = count;
    memcpy(req_buf + sizeof(WHD_MEMORY_REQUEST), buffer, total);

    ok = ioctl_rw(ctx, IOCTL_WHD_WRITE_MEMORY,
                  req_buf, req_size, NULL, 0, NULL);
    free(req_buf);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Read PCI configuration space                                      */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_read_pci_config(WINHWDRIVER *ctx, UINT32 pci_addr,
                                 UINT32 offset, void *buffer,
                                 UINT32 length)
{
    WHD_PCI_CONFIG_REQUEST req = {0};

    req.PciAddress = pci_addr;
    req.PciOffset  = offset;

    return ioctl_rw(ctx, IOCTL_WHD_READ_PCI_CONFIG,
                    &req, sizeof(req), buffer, length, NULL);
}

/* ------------------------------------------------------------------ */
/*  Write PCI configuration space                                     */
/* ------------------------------------------------------------------ */

BOOL winhwdriver_write_pci_config(WINHWDRIVER *ctx, UINT32 pci_addr,
                                  UINT32 offset, const void *buffer,
                                  UINT32 length)
{
    DWORD req_size = (DWORD)(sizeof(WHD_PCI_CONFIG_REQUEST) + length);
    PUCHAR req_buf;
    BOOL   ok;

    req_buf = (PUCHAR)malloc(req_size);
    if (!req_buf) {
        ctx->last_error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }

    memset(req_buf, 0, req_size);
    ((WHD_PCI_CONFIG_REQUEST *)req_buf)->PciAddress = pci_addr;
    ((WHD_PCI_CONFIG_REQUEST *)req_buf)->PciOffset  = offset;
    memcpy(req_buf + sizeof(WHD_PCI_CONFIG_REQUEST), buffer, length);

    ok = ioctl_rw(ctx, IOCTL_WHD_WRITE_PCI_CONFIG,
                  req_buf, req_size, NULL, 0, NULL);
    free(req_buf);
    return ok;
}
