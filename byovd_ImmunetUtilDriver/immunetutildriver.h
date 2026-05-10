/*
 * immunetutildriver.h — Client library for the ImmunetUtilDriver kernel
 *                       driver (ImmunetUtilDriver.sys)
 *
 * Provides typed wrappers around the eleven IOCTLs exposed by
 * \\.\ImmunetUtilDriver0:
 *
 *   0x8FEAA000  Get version string
 *   0x8FEAA004  Open file handle (kernel-assisted)
 *   0x8FEAA008  Open process handle by PID
 *   0x8FEAA00C  Open directory object
 *   0x8FEAA010  Query directory object entries
 *   0x8FEAA014  Get driver object data by name
 *   0x8FEAA018  Get device object data by name
 *   0x8FEAA01C  Get handle data (cross-process)
 *   0x8FEAA020  Duplicate handles from a remote process
 *   0x8FEAA024  Get handle data (current process)
 *   0x8FEAA028  Close directory object handle
 *
 * Usage:
 *   IMMUNET ctx;
 *   if (immunet_open(&ctx)) {
 *       wchar_t ver[512];
 *       immunet_get_version(&ctx, ver, sizeof(ver));
 *       ...
 *       immunet_close(&ctx);
 *   }
 */

#ifndef IMMUNETUTILDRIVER_H
#define IMMUNETUTILDRIVER_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — METHOD_BUFFERED, device type 0x8FEA                 */
/* ------------------------------------------------------------------ */

#define IOCTL_IMMUNET_GET_VERSION          0x8FEAA000
#define IOCTL_IMMUNET_FILE_OPEN_HANDLE     0x8FEAA004
#define IOCTL_IMMUNET_OPEN_PROCESS         0x8FEAA008
#define IOCTL_IMMUNET_OPEN_DIR_OBJECT      0x8FEAA00C
#define IOCTL_IMMUNET_QUERY_DIR_OBJECT     0x8FEAA010
#define IOCTL_IMMUNET_GET_DRIVER_DATA      0x8FEAA014
#define IOCTL_IMMUNET_GET_DEVICE_DATA      0x8FEAA018
#define IOCTL_IMMUNET_GET_HANDLE_BY_SWITCH 0x8FEAA01C
#define IOCTL_IMMUNET_DUPLICATE_HANDLE     0x8FEAA020
#define IOCTL_IMMUNET_GET_HANDLE_DATA      0x8FEAA024
#define IOCTL_IMMUNET_CLOSE_DIR_OBJECT     0x8FEAA028

/* ------------------------------------------------------------------ */
/*  IOCTL request structures (must match driver layout exactly)       */
/* ------------------------------------------------------------------ */

#pragma pack(push, 8)

typedef struct IMMUNET_PATH_REQUEST_TAG {
    UINT32      path_len;           /* byte count of path data         */
    WCHAR       path[1];            /* variable-length path follows    */
} IMMUNET_PATH_REQUEST, *PIMMUNET_PATH_REQUEST;

typedef struct IMMUNET_HANDLE_QUERY_TAG {
    INT64       process_handle;     /* handle to target process        */
    INT64       object_handle;      /* handle within target process    */
} IMMUNET_HANDLE_QUERY, *PIMMUNET_HANDLE_QUERY;

typedef struct IMMUNET_DUP_REQUEST_TAG {
    UINT32      pid;                /* target process ID               */
    UINT32      handle_count;       /* number of handles to duplicate  */
    INT64       handles[1];         /* variable-length handle array    */
} IMMUNET_DUP_REQUEST, *PIMMUNET_DUP_REQUEST;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct IMMUNET_TAG {
    HANDLE      device;
    DWORD       last_error;
} IMMUNET;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\ImmunetUtilDriver0.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL immunet_open(IMMUNET *ctx);

/*
 * Close the device handle.
 */
void immunet_close(IMMUNET *ctx);

/*
 * IOCTL 0x8FEAA000 — Retrieve the driver version string.
 */
BOOL immunet_get_version(IMMUNET *ctx, WCHAR *buf, DWORD buf_size);

/*
 * IOCTL 0x8FEAA008 — Open a process handle by PID.
 * Returns the kernel-opened handle in *handle_out.
 */
BOOL immunet_open_process(IMMUNET *ctx, DWORD pid, HANDLE *handle_out);

/*
 * IOCTL 0x8FEAA004 — Open a file handle via the kernel driver.
 * Returns the kernel-opened handle in *handle_out.
 */
BOOL immunet_file_open(IMMUNET *ctx, const WCHAR *path,
                        HANDLE *handle_out);

/*
 * IOCTL 0x8FEAA00C — Open a directory object for enumeration.
 * Returns the context index in *index_out.
 */
BOOL immunet_open_directory(IMMUNET *ctx, const WCHAR *path,
                             UINT64 *index_out);

/*
 * IOCTL 0x8FEAA010 — Query entries from an opened directory object.
 */
BOOL immunet_query_directory(IMMUNET *ctx, UINT32 index,
                              void *buf, DWORD buf_size,
                              DWORD *bytes_out);

/*
 * IOCTL 0x8FEAA028 — Close a directory object handle.
 */
BOOL immunet_close_directory(IMMUNET *ctx, UINT32 index);

/*
 * IOCTL 0x8FEAA014 — Get driver object data by driver name.
 */
BOOL immunet_get_driver_data(IMMUNET *ctx, const WCHAR *driver_path,
                              void *buf, DWORD buf_size,
                              DWORD *bytes_out);

/*
 * IOCTL 0x8FEAA018 — Get device object data by device name.
 */
BOOL immunet_get_device_data(IMMUNET *ctx, const WCHAR *device_path,
                              void *buf, DWORD buf_size,
                              DWORD *bytes_out);

/*
 * IOCTL 0x8FEAA024 — Get handle data for a handle in this process.
 */
BOOL immunet_get_handle_data(IMMUNET *ctx, HANDLE h,
                              void *buf, DWORD buf_size,
                              DWORD *bytes_out);

/*
 * IOCTL 0x8FEAA01C — Get handle data from another process.
 */
BOOL immunet_get_handle_data_remote(IMMUNET *ctx,
                                     HANDLE process_handle,
                                     HANDLE object_handle,
                                     void *buf, DWORD buf_size,
                                     DWORD *bytes_out);

/*
 * IOCTL 0x8FEAA020 — Duplicate handles from a remote process.
 */
BOOL immunet_duplicate_handles(IMMUNET *ctx, DWORD pid,
                                HANDLE *handles, DWORD count);

#ifdef __cplusplus
}
#endif

#endif /* IMMUNETUTILDRIVER_H */
