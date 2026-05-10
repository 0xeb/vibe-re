/*
 * immunetutildriver.c — Client library implementation
 */

#include "immunetutildriver.h"
#include <stdio.h>
#include <string.h>

#define DEVICE_PATH L"\\\\.\\ImmunetUtilDriver0"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL immunet_open(IMMUNET *ctx)
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

void immunet_close(IMMUNET *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

static BOOL ioctl(IMMUNET *ctx, DWORD code,
                  void *in_buf, DWORD in_size,
                  void *out_buf, DWORD out_size,
                  DWORD *bytes_returned)
{
    DWORD bytes = 0;
    BOOL  ok = DeviceIoControl(ctx->device, code,
                               in_buf, in_size,
                               out_buf, out_size,
                               &bytes, NULL);
    if (!ok)
        ctx->last_error = GetLastError();
    if (bytes_returned)
        *bytes_returned = bytes;
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Get version string                                                */
/* ------------------------------------------------------------------ */

BOOL immunet_get_version(IMMUNET *ctx, WCHAR *buf, DWORD buf_size)
{
    return ioctl(ctx, IOCTL_IMMUNET_GET_VERSION,
                 NULL, 0, buf, buf_size, NULL);
}

/* ------------------------------------------------------------------ */
/*  Open process handle                                               */
/* ------------------------------------------------------------------ */

BOOL immunet_open_process(IMMUNET *ctx, DWORD pid, HANDLE *handle_out)
{
    UINT64 result = 0;
    UINT32 in_pid = pid;
    DWORD  bytes  = 0;
    BOOL   ok;

    ok = ioctl(ctx, IOCTL_IMMUNET_OPEN_PROCESS,
               &in_pid, sizeof(in_pid),
               &result, sizeof(result), &bytes);
    if (ok && bytes >= sizeof(UINT64))
        *handle_out = (HANDLE)(ULONG_PTR)result;
    else
        *handle_out = NULL;
    return ok;
}

/* ------------------------------------------------------------------ */
/*  File open handle                                                  */
/* ------------------------------------------------------------------ */

BOOL immunet_file_open(IMMUNET *ctx, const WCHAR *path,
                        HANDLE *handle_out)
{
    DWORD  path_bytes = (DWORD)(wcslen(path) * sizeof(WCHAR));
    DWORD  total      = sizeof(UINT32) + path_bytes;
    UINT8 *buf        = (UINT8 *)malloc(total + 8);
    DWORD  bytes      = 0;
    BOOL   ok;

    if (!buf) {
        ctx->last_error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }

    *(UINT32 *)buf = path_bytes;
    memcpy(buf + sizeof(UINT32), path, path_bytes);

    ok = ioctl(ctx, IOCTL_IMMUNET_FILE_OPEN_HANDLE,
               buf, total, buf, total < 8 ? 8 : total, &bytes);
    if (ok && bytes >= 8)
        *handle_out = *(HANDLE *)buf;
    else
        *handle_out = NULL;

    free(buf);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Open directory object                                             */
/* ------------------------------------------------------------------ */

BOOL immunet_open_directory(IMMUNET *ctx, const WCHAR *path,
                             UINT64 *index_out)
{
    DWORD  path_bytes = (DWORD)(wcslen(path) * sizeof(WCHAR));
    DWORD  total      = sizeof(UINT32) + path_bytes;
    UINT8 *buf        = (UINT8 *)malloc(total < 8 ? 8 : total);
    DWORD  bytes      = 0;
    BOOL   ok;

    if (!buf) {
        ctx->last_error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }

    *(UINT32 *)buf = path_bytes;
    memcpy(buf + sizeof(UINT32), path, path_bytes);

    ok = ioctl(ctx, IOCTL_IMMUNET_OPEN_DIR_OBJECT,
               buf, total, buf, total < 8 ? 8 : total, &bytes);
    if (ok && bytes >= 8)
        *index_out = *(UINT64 *)buf;
    else
        *index_out = 0;

    free(buf);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Query directory object                                            */
/* ------------------------------------------------------------------ */

BOOL immunet_query_directory(IMMUNET *ctx, UINT32 index,
                              void *buf, DWORD buf_size,
                              DWORD *bytes_out)
{
    /* Build the 14-byte input: 4-byte index + flags + context */
    UINT8  in_buf[16];
    DWORD  bytes = 0;
    BOOL   ok;

    memset(in_buf, 0, sizeof(in_buf));
    *(UINT32 *)in_buf = index;
    in_buf[8] = 1;     /* single entry */
    in_buf[9] = 1;     /* restart */
    *(UINT32 *)(in_buf + 10) = 0; /* context = 0 */

    ok = ioctl(ctx, IOCTL_IMMUNET_QUERY_DIR_OBJECT,
               in_buf, 14, buf, buf_size, &bytes);
    if (bytes_out)
        *bytes_out = bytes;
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Close directory object                                            */
/* ------------------------------------------------------------------ */

BOOL immunet_close_directory(IMMUNET *ctx, UINT32 index)
{
    UINT64 in_buf = index;
    UINT32 out    = 0;

    return ioctl(ctx, IOCTL_IMMUNET_CLOSE_DIR_OBJECT,
                 &in_buf, 8, &out, sizeof(out), NULL);
}

/* ------------------------------------------------------------------ */
/*  Get driver data                                                   */
/* ------------------------------------------------------------------ */

BOOL immunet_get_driver_data(IMMUNET *ctx, const WCHAR *driver_path,
                              void *buf, DWORD buf_size,
                              DWORD *bytes_out)
{
    DWORD  path_bytes = (DWORD)(wcslen(driver_path) * sizeof(WCHAR));
    DWORD  total      = sizeof(UINT32) + path_bytes;
    UINT8 *in_buf     = (UINT8 *)malloc(total);
    DWORD  bytes      = 0;
    BOOL   ok;

    if (!in_buf) {
        ctx->last_error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }

    *(UINT32 *)in_buf = path_bytes;
    memcpy(in_buf + sizeof(UINT32), driver_path, path_bytes);

    ok = ioctl(ctx, IOCTL_IMMUNET_GET_DRIVER_DATA,
               in_buf, total, buf, buf_size, &bytes);
    if (bytes_out)
        *bytes_out = bytes;

    free(in_buf);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Get device data                                                   */
/* ------------------------------------------------------------------ */

BOOL immunet_get_device_data(IMMUNET *ctx, const WCHAR *device_path,
                              void *buf, DWORD buf_size,
                              DWORD *bytes_out)
{
    DWORD  path_bytes = (DWORD)(wcslen(device_path) * sizeof(WCHAR));
    DWORD  total      = sizeof(UINT32) + path_bytes;
    UINT8 *in_buf     = (UINT8 *)malloc(total);
    DWORD  bytes      = 0;
    BOOL   ok;

    if (!in_buf) {
        ctx->last_error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }

    *(UINT32 *)in_buf = path_bytes;
    memcpy(in_buf + sizeof(UINT32), device_path, path_bytes);

    ok = ioctl(ctx, IOCTL_IMMUNET_GET_DEVICE_DATA,
               in_buf, total, buf, buf_size, &bytes);
    if (bytes_out)
        *bytes_out = bytes;

    free(in_buf);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Get handle data (current process)                                 */
/* ------------------------------------------------------------------ */

BOOL immunet_get_handle_data(IMMUNET *ctx, HANDLE h,
                              void *buf, DWORD buf_size,
                              DWORD *bytes_out)
{
    INT64 handle_val = (INT64)(LONG_PTR)h;
    DWORD bytes = 0;
    BOOL  ok;

    ok = ioctl(ctx, IOCTL_IMMUNET_GET_HANDLE_DATA,
               &handle_val, sizeof(handle_val),
               buf, buf_size, &bytes);
    if (bytes_out)
        *bytes_out = bytes;
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Get handle data (cross-process)                                   */
/* ------------------------------------------------------------------ */

BOOL immunet_get_handle_data_remote(IMMUNET *ctx,
                                     HANDLE process_handle,
                                     HANDLE object_handle,
                                     void *buf, DWORD buf_size,
                                     DWORD *bytes_out)
{
    IMMUNET_HANDLE_QUERY query;
    DWORD bytes = 0;
    BOOL  ok;

    query.process_handle = (INT64)(LONG_PTR)process_handle;
    query.object_handle  = (INT64)(LONG_PTR)object_handle;

    ok = ioctl(ctx, IOCTL_IMMUNET_GET_HANDLE_BY_SWITCH,
               &query, sizeof(query), buf, buf_size, &bytes);
    if (bytes_out)
        *bytes_out = bytes;
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Duplicate handles from remote process                             */
/* ------------------------------------------------------------------ */

BOOL immunet_duplicate_handles(IMMUNET *ctx, DWORD pid,
                                HANDLE *handles, DWORD count)
{
    DWORD  total = sizeof(UINT32) * 2 + count * sizeof(INT64);
    UINT8 *buf   = (UINT8 *)malloc(total);
    DWORD  bytes = 0;
    DWORD  i;
    BOOL   ok;

    if (!buf) {
        ctx->last_error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }

    *(UINT32 *)buf = pid;
    *(UINT32 *)(buf + 4) = count;
    for (i = 0; i < count; i++)
        *(INT64 *)(buf + 8 + i * sizeof(INT64)) = (INT64)(LONG_PTR)handles[i];

    ok = ioctl(ctx, IOCTL_IMMUNET_DUPLICATE_HANDLE,
               buf, total, buf, total, &bytes);
    if (ok) {
        for (i = 0; i < count; i++)
            handles[i] = (HANDLE)(ULONG_PTR)*(INT64 *)(buf + 8 + i * sizeof(INT64));
    }

    free(buf);
    return ok;
}
