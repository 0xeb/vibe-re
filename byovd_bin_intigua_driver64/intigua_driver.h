/*
 * intigua_driver.h — Client library for the Intigua kernel driver
 *                     (bin_intigua_driver64.sys)
 *
 * Provides typed wrappers around the three IOCTLs exposed by
 * \\.\{4cdec755-627a-4141-99e5-76ff636b1282}:
 *
 *   0x9C40240C  Patch (hook IAT entries in services.exe)
 *   0x9C402410  Unpatch (restore original IAT entries)
 *   0x9C402414  Patch 2019 (hook IAT via older DLL name)
 *
 * Usage:
 *   INTIGUA_DRIVER ctx;
 *   if (intigua_driver_open(&ctx)) {
 *       intigua_driver_patch(&ctx, services_pid);
 *       ...
 *       intigua_driver_unpatch(&ctx, services_pid);
 *       intigua_driver_close(&ctx);
 *   }
 */

#ifndef INTIGUA_DRIVER_H
#define INTIGUA_DRIVER_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — METHOD_BUFFERED, device type 0x9C40                 */
/* ------------------------------------------------------------------ */

#define IOCTL_INTIGUA_PATCH         0x9C40240C
#define IOCTL_INTIGUA_UNPATCH       0x9C402410
#define IOCTL_INTIGUA_PATCH_2019    0x9C402414

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct INTIGUA_DRIVER_TAG {
    HANDLE      device;
    DWORD       last_error;
} INTIGUA_DRIVER, *PINTIGUA_DRIVER;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\{4cdec755-627a-4141-99e5-76ff636b1282}.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL intigua_driver_open(INTIGUA_DRIVER *ctx);

/*
 * Close the device handle.
 */
void intigua_driver_close(INTIGUA_DRIVER *ctx);

/*
 * IOCTL 0x9C40240C — Hook CreateProcessAsUserW and CreateProcessW
 * in the IAT of services.exe (identified by `pid`), using the
 * current DLL name (api-ms-win-core-processthreads-l1-1-2.dll).
 */
BOOL intigua_driver_patch(INTIGUA_DRIVER *ctx, DWORD pid);

/*
 * IOCTL 0x9C402410 — Restore the original IAT entries and free
 * injected shellcode from the target process.
 */
BOOL intigua_driver_unpatch(INTIGUA_DRIVER *ctx, DWORD pid);

/*
 * IOCTL 0x9C402414 — Same as patch, but uses the Windows 2019
 * DLL name (API-MS-Win-Core-ProcessThreads-L1-1-0.dll).
 */
BOOL intigua_driver_patch_2019(INTIGUA_DRIVER *ctx, DWORD pid);

#ifdef __cplusplus
}
#endif

#endif /* INTIGUA_DRIVER_H */
