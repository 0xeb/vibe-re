/*
 * ggprotect64.h — Client library for the GGProtect64 kernel driver
 *
 * Provides typed wrappers around the 60+ IOCTLs exposed by
 * \\.\GGProtect64:
 *
 *   - Driver init/unload with XOR'd auth key
 *   - I/O port read/write
 *   - Process protection (add/delete/clear)
 *   - Driver/device enumeration
 *   - SSDT / Shadow-SSDT address lookup
 *   - OB callback enumeration and removal
 *   - Keyboard/mouse hook enable/disable
 *   - DLL injection into arbitrary processes
 *   - Physical memory pattern scanning
 *   - Registry monitoring enable/disable
 *   - Kernel function code reading
 *
 * Usage:
 *   GGPROTECT ctx;
 *   if (ggprotect_open(&ctx)) {
 *       ggprotect_driver_load(&ctx, 0x1234);
 *       UINT64 addr;
 *       ggprotect_get_ssdt_addr(&ctx, 0, &addr);
 *       ...
 *       ggprotect_driver_unload(&ctx, 0x1234 ^ 0x5A84);
 *       ggprotect_close(&ctx);
 *   }
 */

#ifndef GGPROTECT64_H
#define GGPROTECT64_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — METHOD_BUFFERED, FILE_DEVICE_UNKNOWN (0x22)         */
/* ------------------------------------------------------------------ */

#define IOCTL_GG_DRIVER_LOAD               0x223c14
#define IOCTL_GG_DRIVER_UNLOAD             0x223c18
#define IOCTL_GG_BLUESCREEN                0x223c10
#define IOCTL_GG_WRITE_PORT                0x223804
#define IOCTL_GG_READ_PORT                 0x223808
#define IOCTL_GG_SET_PROTECT_PROC          0x223c08
#define IOCTL_GG_SET_HIPS_PROTECT          0x223c04
#define IOCTL_GG_ADD_FILEFILTER            0x223c1c
#define IOCTL_GG_DEL_FILEFILTER            0x223c20
#define IOCTL_GG_ADD_PROCFILTER            0x223c28
#define IOCTL_GG_DEL_PROCFILTER            0x223c2c
#define IOCTL_GG_GET_DRIVER_BY_DEVICE      0x223c40
#define IOCTL_GG_GET_DRIVER_BY_NAME        0x223c44
#define IOCTL_GG_GET_DRIVER_POS            0x223c48
#define IOCTL_GG_GET_FUN_CODE              0x223c54
#define IOCTL_GG_GET_SSDT_ADDR             0x223c58
#define IOCTL_GG_GET_OBCALLBACK            0x223c5c
#define IOCTL_GG_UNINSTALL_OBCALLBACK      0x223c60
#define IOCTL_GG_ENABLE_MOUSE              0x223c64
#define IOCTL_GG_ENABLE_KEYBOARD           0x223c68
#define IOCTL_GG_GET_PROC_THREADINFO       0x223c70
#define IOCTL_GG_GET_ALL_DRIVER_INFO       0x223c74
#define IOCTL_GG_GET_SSSDT_ADDR            0x223c78
#define IOCTL_GG_ADD_MONITOR_THREAD        0x223c7c
#define IOCTL_GG_UPDATE_MONITOR_THREAD     0x223c80
#define IOCTL_GG_DEL_MONITOR_THREAD        0x223c84
#define IOCTL_GG_ADD_GAME_PROCINF          0x223c88
#define IOCTL_GG_GET_PROC_MODULE           0x223c90
#define IOCTL_GG_GET_PROC_MEM              0x223c94
#define IOCTL_GG_INJECT_UNRUN_PROC         0x223cb0
#define IOCTL_GG_CLEAR_INJECT_UNRUN        0x223cb4
#define IOCTL_GG_MINIFILTER_CALLBACK       0x223cb8
#define IOCTL_GG_INJECT_RUN_PROC           0x223cbc
#define IOCTL_GG_SET_REGMONITORDATA        0x223cc0
#define IOCTL_GG_ENABLE_MONITE_REG         0x223cc4
#define IOCTL_GG_ENABLE_CREATE_PROC        0x223cd0
#define IOCTL_GG_ENABLE_OPEN_PROC          0x223cd4
#define IOCTL_GG_ENABLE_ANTI_DEBUG         0x223cd8
#define IOCTL_GG_ENABLE_PROTECT_SELF       0x223cdc
#define IOCTL_GG_RESUME_THREAD             0x223ce0
#define IOCTL_GG_GET_MDL_DATA              0x223ce4
#define IOCTL_GG_ENABLE_SYSKEY             0x223ce8
#define IOCTL_GG_GET_HOOK_INF              0x223cec
#define IOCTL_GG_ENABLE_THREAD_STATUS      0x223cf0
#define IOCTL_GG_ENABLE_MONITOR_MODULE     0x223cf8
#define IOCTL_GG_ENABLE_SHOW_LOG           0x223cfc
#define IOCTL_GG_PROTECT_ADDNAME           0x223d0c
#define IOCTL_GG_PROTECT_ADDID             0x223d10
#define IOCTL_GG_PROTECT_DELETE            0x223d14
#define IOCTL_GG_ADD_SCAN_DATA             0x223d18
#define IOCTL_GG_STOP_SCAN_PHYSICAL        0x223d1c
#define IOCTL_GG_CHECK_MEM_INTEGRITY       0x223d20
#define IOCTL_GG_SET_DENY_IME              0x223d28
#define IOCTL_GG_CLEAR_DENY_IME            0x223d2c
#define IOCTL_GG_START_SCAN_PHYSICAL       0x223d30
#define IOCTL_GG_START_SCAN_NOPAGE         0x223d34
#define IOCTL_GG_STOP_SCAN_NOPAGE          0x223d38
#define IOCTL_GG_GET_LOADIMAGE_CB          0x223d40
#define IOCTL_GG_GET_CREATEPROC_CB         0x223d44
#define IOCTL_GG_GET_CREATETHREAD_CB       0x223d48
#define IOCTL_GG_GET_CMP_CB               0x223d4c
#define IOCTL_GG_GET_PROCEDURE_ADDR        0x223d50
#define IOCTL_GG_SET_COMPORT_INF           0x223d80
#define IOCTL_GG_CLEAR_PROC_CTRL           0x223d84

/* ------------------------------------------------------------------ */
/*  IOCTL request structures (must match driver layout exactly)       */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)

typedef struct GGPROTECT_PORT_IO_REQUEST {
    UINT32      port;
    UINT32      value;
    UINT8       type;             /* 0x01=byte, 0x04=dword             */
} GGPROTECT_PORT_IO_REQUEST;

typedef struct GGPROTECT_FUN_CODE_REQUEST {
    UINT8       type;             /* 0=kernel, 1=process, 2=SSDT, 3=SSSDT */
    UINT16      length;
    UINT32      index;
    UINT64      address;
} GGPROTECT_FUN_CODE_REQUEST;

typedef struct GGPROTECT_INJECT_REQUEST {
    UINT32      processId;
    WCHAR       dllPath[0x200];
} GGPROTECT_INJECT_REQUEST;

typedef struct GGPROTECT_MONITOR_THREAD {
    UINT32      type;
    UINT32      data;
} GGPROTECT_MONITOR_THREAD;

typedef struct GGPROTECT_THREADINFO_REQUEST {
    UINT32      processId;
    UINT16      maxCount;
} GGPROTECT_THREADINFO_REQUEST;

typedef struct GGPROTECT_HOOK_INF_REQUEST {
    UINT16      hookType;
    UINT16      maxCount;
    UINT32      threadId;
} GGPROTECT_HOOK_INF_REQUEST;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct GGPROTECT {
    HANDLE      device;
    DWORD       last_error;
    UINT32      auth_key;         /* XOR'd key from driver_load        */
} GGPROTECT;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\GGProtect64.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL ggprotect_open(GGPROTECT *ctx);

/*
 * Close the device handle.
 */
void ggprotect_close(GGPROTECT *ctx);

/*
 * IOCTL 0x223c14 — Initialize driver session.
 * The driver XORs `key` with 0x5A84 to create the auth token.
 * All subsequent IOCTLs are only accepted from this caller PID.
 */
BOOL ggprotect_driver_load(GGPROTECT *ctx, UINT32 key);

/*
 * IOCTL 0x223c18 — Tear down driver session.
 * `key` must match the XOR'd auth key stored by the driver.
 */
BOOL ggprotect_driver_unload(GGPROTECT *ctx, UINT32 key);

/*
 * IOCTL 0x223c58 — Get SSDT function address by index.
 */
BOOL ggprotect_get_ssdt_addr(GGPROTECT *ctx, UINT32 index, UINT64 *addr_out);

/*
 * IOCTL 0x223c78 — Get Shadow SSDT function address by index.
 */
BOOL ggprotect_get_sssdt_addr(GGPROTECT *ctx, UINT32 index, UINT64 *addr_out);

/*
 * IOCTL 0x223d50 — Get kernel procedure address by index.
 */
BOOL ggprotect_get_procedure_addr(GGPROTECT *ctx, UINT32 index, UINT64 *addr_out);

/*
 * IOCTL 0x223c64 — Enable/disable mouse hook (0=hook, nonzero=unhook).
 */
BOOL ggprotect_enable_mouse(GGPROTECT *ctx, UINT8 enable);

/*
 * IOCTL 0x223c68 — Enable/disable keyboard hook.
 */
BOOL ggprotect_enable_keyboard(GGPROTECT *ctx, UINT8 enable);

/*
 * IOCTL 0x223cfc — Enable debug log output (DbgPrint).
 */
BOOL ggprotect_enable_log(GGPROTECT *ctx);

/*
 * IOCTL 0x223c5c — Enumerate OB callbacks.
 */
BOOL ggprotect_get_obcallbacks(GGPROTECT *ctx, UINT16 maxCount,
                                void *outBuf, SIZE_T outSize);

/*
 * IOCTL 0x223c60 — Remove a specific OB callback by handle.
 */
BOOL ggprotect_uninstall_obcallback(GGPROTECT *ctx, UINT64 handle);

/*
 * IOCTL 0x223c88 — Add a game process info entry by PID.
 */
BOOL ggprotect_add_game_proc(GGPROTECT *ctx, UINT32 pid);

/*
 * IOCTL 0x223cd0 — Enable/disable create-process notification.
 */
BOOL ggprotect_enable_create_proc(GGPROTECT *ctx, UINT8 enable);

/*
 * IOCTL 0x223cd4 — Enable/disable open-process monitoring.
 */
BOOL ggprotect_enable_open_proc(GGPROTECT *ctx, UINT8 enable);

/*
 * IOCTL 0x223cdc — Enable/disable self-protection.
 */
BOOL ggprotect_enable_protect_self(GGPROTECT *ctx, UINT8 enable);

/*
 * IOCTL 0x223d30 — Start physical memory scanning.
 */
BOOL ggprotect_start_scan_physical(GGPROTECT *ctx);

/*
 * IOCTL 0x223d1c — Stop physical memory scanning.
 */
BOOL ggprotect_stop_scan_physical(GGPROTECT *ctx);

/*
 * IOCTL 0x223d84 — Clear process control entry for a PID.
 */
BOOL ggprotect_clear_proc_ctrl(GGPROTECT *ctx, UINT32 pid);

/*
 * Generic raw IOCTL — for IOCTLs not wrapped above.
 */
BOOL ggprotect_raw_ioctl(GGPROTECT *ctx, DWORD code,
                          void *buf, DWORD size);

#ifdef __cplusplus
}
#endif

#endif /* GGPROTECT64_H */
