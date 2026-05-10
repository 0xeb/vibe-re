/*
 * ggprotect64.c — Client library implementation
 */

#include "ggprotect64.h"
#include <stdio.h>

#define DEVICE_PATH L"\\\\.\\GGProtect64"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL ggprotect_open(GGPROTECT *ctx)
{
    ctx->last_error = 0;
    ctx->auth_key   = 0;
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

void ggprotect_close(GGPROTECT *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

BOOL ggprotect_raw_ioctl(GGPROTECT *ctx, DWORD code,
                          void *buf, DWORD size)
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
/*  Driver initialization / teardown                                  */
/* ------------------------------------------------------------------ */

BOOL ggprotect_driver_load(GGPROTECT *ctx, UINT32 key)
{
    ctx->auth_key = key ^ 0x5A84;
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_DRIVER_LOAD,
                                &key, sizeof(key));
}

BOOL ggprotect_driver_unload(GGPROTECT *ctx, UINT32 key)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_DRIVER_UNLOAD,
                                &key, sizeof(key));
}

/* ------------------------------------------------------------------ */
/*  SSDT / Shadow SSDT / procedure address                            */
/* ------------------------------------------------------------------ */

BOOL ggprotect_get_ssdt_addr(GGPROTECT *ctx, UINT32 index,
                              UINT64 *addr_out)
{
    UINT32 buf = index;
    *addr_out = 0;
    if (!ggprotect_raw_ioctl(ctx, IOCTL_GG_GET_SSDT_ADDR,
                              &buf, sizeof(buf)))
        return FALSE;
    *addr_out = *(UINT64 *)&buf;
    return TRUE;
}

BOOL ggprotect_get_sssdt_addr(GGPROTECT *ctx, UINT32 index,
                               UINT64 *addr_out)
{
    UINT32 buf = index;
    *addr_out = 0;
    if (!ggprotect_raw_ioctl(ctx, IOCTL_GG_GET_SSSDT_ADDR,
                              &buf, sizeof(buf)))
        return FALSE;
    *addr_out = *(UINT64 *)&buf;
    return TRUE;
}

BOOL ggprotect_get_procedure_addr(GGPROTECT *ctx, UINT32 index,
                                   UINT64 *addr_out)
{
    UINT32 buf = index;
    *addr_out = 0;
    if (!ggprotect_raw_ioctl(ctx, IOCTL_GG_GET_PROCEDURE_ADDR,
                              &buf, sizeof(buf)))
        return FALSE;
    *addr_out = *(UINT64 *)&buf;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Input device hooking                                              */
/* ------------------------------------------------------------------ */

BOOL ggprotect_enable_mouse(GGPROTECT *ctx, UINT8 enable)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_ENABLE_MOUSE,
                                &enable, sizeof(enable));
}

BOOL ggprotect_enable_keyboard(GGPROTECT *ctx, UINT8 enable)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_ENABLE_KEYBOARD,
                                &enable, sizeof(enable));
}

/* ------------------------------------------------------------------ */
/*  Debug log                                                         */
/* ------------------------------------------------------------------ */

BOOL ggprotect_enable_log(GGPROTECT *ctx)
{
    UINT8 dummy = 1;
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_ENABLE_SHOW_LOG,
                                &dummy, 0);
}

/* ------------------------------------------------------------------ */
/*  OB callback enumeration                                           */
/* ------------------------------------------------------------------ */

BOOL ggprotect_get_obcallbacks(GGPROTECT *ctx, UINT16 maxCount,
                                void *outBuf, SIZE_T outSize)
{
    UINT16 buf = maxCount;
    (void)outSize;

    if (!ggprotect_raw_ioctl(ctx, IOCTL_GG_GET_OBCALLBACK,
                              &buf, sizeof(buf)))
        return FALSE;

    /* Driver copies results into the system buffer */
    return TRUE;
}

BOOL ggprotect_uninstall_obcallback(GGPROTECT *ctx, UINT64 handle)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_UNINSTALL_OBCALLBACK,
                                &handle, sizeof(handle));
}

/* ------------------------------------------------------------------ */
/*  Game process management                                           */
/* ------------------------------------------------------------------ */

BOOL ggprotect_add_game_proc(GGPROTECT *ctx, UINT32 pid)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_ADD_GAME_PROCINF,
                                &pid, sizeof(pid));
}

/* ------------------------------------------------------------------ */
/*  Notification enables                                              */
/* ------------------------------------------------------------------ */

BOOL ggprotect_enable_create_proc(GGPROTECT *ctx, UINT8 enable)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_ENABLE_CREATE_PROC,
                                &enable, sizeof(enable));
}

BOOL ggprotect_enable_open_proc(GGPROTECT *ctx, UINT8 enable)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_ENABLE_OPEN_PROC,
                                &enable, sizeof(enable));
}

BOOL ggprotect_enable_protect_self(GGPROTECT *ctx, UINT8 enable)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_ENABLE_PROTECT_SELF,
                                &enable, sizeof(enable));
}

/* ------------------------------------------------------------------ */
/*  Physical memory scanning                                          */
/* ------------------------------------------------------------------ */

BOOL ggprotect_start_scan_physical(GGPROTECT *ctx)
{
    UINT8 dummy = 0;
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_START_SCAN_PHYSICAL,
                                &dummy, 0);
}

BOOL ggprotect_stop_scan_physical(GGPROTECT *ctx)
{
    UINT8 dummy = 0;
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_STOP_SCAN_PHYSICAL,
                                &dummy, 0);
}

/* ------------------------------------------------------------------ */
/*  Process control                                                   */
/* ------------------------------------------------------------------ */

BOOL ggprotect_clear_proc_ctrl(GGPROTECT *ctx, UINT32 pid)
{
    return ggprotect_raw_ioctl(ctx, IOCTL_GG_CLEAR_PROC_CTRL,
                                &pid, sizeof(pid));
}
