/*
 * intigua_driver.c — Client library implementation
 */

#include "intigua_driver.h"
#include <stdio.h>

#define DEVICE_PATH L"\\\\.\\{4cdec755-627a-4141-99e5-76ff636b1282}"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL intigua_driver_open(INTIGUA_DRIVER *ctx)
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

void intigua_driver_close(INTIGUA_DRIVER *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

static BOOL ioctl(INTIGUA_DRIVER *ctx, DWORD code, void *buf, DWORD size)
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
/*  IOCTL 0x9C40240C: Patch (hook IAT)                                */
/* ------------------------------------------------------------------ */

BOOL intigua_driver_patch(INTIGUA_DRIVER *ctx, DWORD pid)
{
    DWORD pidVal = pid;
    return ioctl(ctx, IOCTL_INTIGUA_PATCH, &pidVal, sizeof(pidVal));
}

/* ------------------------------------------------------------------ */
/*  IOCTL 0x9C402410: Unpatch (restore IAT)                           */
/* ------------------------------------------------------------------ */

BOOL intigua_driver_unpatch(INTIGUA_DRIVER *ctx, DWORD pid)
{
    DWORD pidVal = pid;
    return ioctl(ctx, IOCTL_INTIGUA_UNPATCH, &pidVal, sizeof(pidVal));
}

/* ------------------------------------------------------------------ */
/*  IOCTL 0x9C402414: Patch 2019 (hook IAT, older DLL name)           */
/* ------------------------------------------------------------------ */

BOOL intigua_driver_patch_2019(INTIGUA_DRIVER *ctx, DWORD pid)
{
    DWORD pidVal = pid;
    return ioctl(ctx, IOCTL_INTIGUA_PATCH_2019, &pidVal, sizeof(pidVal));
}
