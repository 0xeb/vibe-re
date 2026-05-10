/*
 * fastdump.c — Client library implementation
 */

#include "fastdump.h"
#include <stdio.h>

#define DEVICE_PATH L"\\\\.\\FastDump"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL fastdump_open(FASTDUMP *ctx)
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

void fastdump_close(FASTDUMP *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

static BOOL ioctl_raw(FASTDUMP *ctx, DWORD code,
                      void *in_buf, DWORD in_size,
                      void *out_buf, DWORD out_size,
                      DWORD *bytes_returned)
{
    DWORD bytes = 0;
    BOOL  ok = DeviceIoControl(ctx->device, code,
                               in_buf, in_size,
                               out_buf, out_size,
                               &bytes, NULL);
    if (bytes_returned)
        *bytes_returned = bytes;
    if (!ok)
        ctx->last_error = GetLastError();
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Read physical memory via IOCTL_FASTDUMP_READ_PHYS_MAPPED          */
/* ------------------------------------------------------------------ */

BOOL fastdump_read_phys(FASTDUMP *ctx, UINT64 phys_addr,
                        void *buffer, SIZE_T size)
{
    PUCHAR dst = (PUCHAR)buffer;
    SIZE_T remaining = size;

    while (remaining > 0) {
        /*
         * The driver reads up to 0x100000 bytes at a time, but the
         * output includes a 0x34-byte header before the data.  We
         * use a stack buffer sized for one page to keep things simple.
         */
        SIZE_T chunk = (remaining < 0x1000) ? remaining : 0x1000;
        UCHAR  resp[0x34 + 0x1000];
        DWORD  bytes = 0;

        /* Build request: status(4), phys_addr(8), size(4), padding... */
        UINT64 req[4];
        req[0] = 0;                             /* status (set by driver) */
        req[1] = phys_addr & 0xFFFFFFFFFFFFF000ULL;
        req[2] = chunk;
        req[3] = 0;

        if (!ioctl_raw(ctx, IOCTL_FASTDUMP_READ_PHYS_MAPPED,
                       req, 0x14,
                       resp, (DWORD)(0x34 + chunk), &bytes))
            return FALSE;

        /* Check driver status word */
        if (*(PUINT32)resp != FD_STATUS_SUCCESS) {
            ctx->last_error = ERROR_READ_FAULT;
            return FALSE;
        }

        /* Handle intra-page offset */
        {
            UINT32 page_off = (UINT32)(phys_addr & 0xFFF);
            SIZE_T avail = chunk;
            if (page_off + avail > 0x1000)
                avail = 0x1000 - page_off;

            memcpy(dst, resp + 0x34 + page_off, avail);
            dst        += avail;
            phys_addr  += avail;
            remaining  -= avail;
        }
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Read physical page via IRP_MJ_READ (direct read path)             */
/* ------------------------------------------------------------------ */

BOOL fastdump_read_page(FASTDUMP *ctx, UINT64 phys_addr, void *buffer)
{
    DWORD  bytes = 0;
    LARGE_INTEGER offset;
    OVERLAPPED ov = {0};

    offset.QuadPart = (LONGLONG)phys_addr;
    ov.Offset     = offset.LowPart;
    ov.OffsetHigh = offset.HighPart;

    if (!ReadFile(ctx->device, buffer, 0x1000, &bytes, &ov)) {
        ctx->last_error = GetLastError();
        return FALSE;
    }
    return (bytes == 0x1000);
}

/* ------------------------------------------------------------------ */
/*  Read MSR                                                          */
/* ------------------------------------------------------------------ */

BOOL fastdump_read_msr(FASTDUMP *ctx, UINT32 msr_index, UINT64 *value)
{
    FASTDUMP_MSR_REQUEST req = {0};
    DWORD bytes = 0;

    req.msr_value = (UINT64)msr_index;

    if (!ioctl_raw(ctx, IOCTL_FASTDUMP_READ_MSR,
                   &req, 0x0C,
                   &req, sizeof(req), &bytes))
        return FALSE;

    if ((req.status & 0xFFFF0000) != FD_STATUS_SUCCESS) {
        ctx->last_error = ERROR_GEN_FAILURE;
        return FALSE;
    }

    *value = req.msr_value;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Get CPUID                                                         */
/* ------------------------------------------------------------------ */

BOOL fastdump_get_cpuid(FASTDUMP *ctx, FASTDUMP_CPUID_RESPONSE *out)
{
    DWORD bytes = 0;

    memset(out, 0, sizeof(*out));

    if (!ioctl_raw(ctx, IOCTL_FASTDUMP_GET_CPUID,
                   out, sizeof(*out),
                   out, sizeof(*out), &bytes))
        return FALSE;

    if ((out->status & 0xFFFF0000) != FD_STATUS_SUCCESS) {
        ctx->last_error = ERROR_GEN_FAILURE;
        return FALSE;
    }

    return TRUE;
}
