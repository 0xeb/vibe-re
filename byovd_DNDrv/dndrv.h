/*
 * dndrv.h — Client library for the DNDrv kernel driver (DNDrv.sys)
 *
 * Provides typed wrappers around the VirtualBox-derived SUPR0 IOCTLs
 * exposed by \\.\DNDrv:
 *
 *   0x228204  SUP_IOCTL_COOKIE         Establish session cookie
 *   0x228208  SUP_IOCTL_QUERY_FUNCS    Query kernel function table
 *   0x22820C  SUP_IOCTL_LDR_OPEN       Open a kernel module slot
 *   0x228210  SUP_IOCTL_LDR_LOAD       Load image into ring-0
 *   0x228214  SUP_IOCTL_LDR_FREE       Unload a ring-0 module
 *   0x228218  SUP_IOCTL_LDR_GET_SYMBOL Resolve a ring-0 symbol
 *   0x22821C  SUP_IOCTL_CALL_VMMR0     Call into VMM ring-0 entry
 *   0x228220  SUP_IOCTL_LOW_ALLOC      Allocate low-phys memory
 *   0x228224  SUP_IOCTL_LOW_FREE       Free low-phys memory
 *   0x228228  SUP_IOCTL_PAGE_ALLOC_EX  Allocate kernel pages
 *   0x228234  SUP_IOCTL_PAGE_FREE      Free kernel pages
 *   0x228238  SUP_IOCTL_PAGE_LOCK      Lock user pages into kernel
 *   0x22823C  SUP_IOCTL_PAGE_UNLOCK    Unlock locked pages
 *   0x228240  SUP_IOCTL_CONT_ALLOC     Allocate contiguous memory
 *   0x228244  SUP_IOCTL_CONT_FREE      Free contiguous memory
 *   0x228248  SUP_IOCTL_GET_PAGING_MODE Query CPU paging mode
 *   0x228250  SUP_IOCTL_GIP_MAP        Map Global Info Page
 *   0x228254  SUP_IOCTL_GIP_UNMAP      Unmap Global Info Page
 *   0x228268  SUP_IOCTL_VT_CAPS        Query VT-x/AMD-V capabilities
 *
 * Usage:
 *   DNDRV ctx;
 *   if (dndrv_open(&ctx)) {
 *       if (dndrv_cookie(&ctx)) {
 *           UINT32 caps;
 *           dndrv_query_vt_caps(&ctx, &caps);
 *           ...
 *       }
 *       dndrv_close(&ctx);
 *   }
 */

#ifndef DNDRV_H
#define DNDRV_H

#include <windows.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  IOCTL codes — METHOD_BUFFERED, FILE_DEVICE_UNKNOWN (0x22)         */
/* ------------------------------------------------------------------ */

#define IOCTL_DNDRV_COOKIE              0x228204
#define IOCTL_DNDRV_QUERY_FUNCS         0x228208
#define IOCTL_DNDRV_LDR_OPEN            0x22820C
#define IOCTL_DNDRV_LDR_LOAD            0x228210
#define IOCTL_DNDRV_LDR_FREE            0x228214
#define IOCTL_DNDRV_LDR_GET_SYMBOL      0x228218
#define IOCTL_DNDRV_CALL_VMMR0          0x22821C
#define IOCTL_DNDRV_LOW_ALLOC           0x228220
#define IOCTL_DNDRV_LOW_FREE            0x228224
#define IOCTL_DNDRV_PAGE_ALLOC_EX       0x228228
#define IOCTL_DNDRV_PAGE_MAP_KERNEL     0x22822C
#define IOCTL_DNDRV_PAGE_PROTECT        0x228230
#define IOCTL_DNDRV_PAGE_FREE           0x228234
#define IOCTL_DNDRV_PAGE_LOCK           0x228238
#define IOCTL_DNDRV_PAGE_UNLOCK         0x22823C
#define IOCTL_DNDRV_CONT_ALLOC          0x228240
#define IOCTL_DNDRV_CONT_FREE           0x228244
#define IOCTL_DNDRV_GET_PAGING_MODE     0x228248
#define IOCTL_DNDRV_SET_VM_FOR_FAST     0x22824C
#define IOCTL_DNDRV_GIP_MAP             0x228250
#define IOCTL_DNDRV_GIP_UNMAP           0x228254
#define IOCTL_DNDRV_CALL_SERVICE        0x228258
#define IOCTL_DNDRV_LOGGER_SETTINGS     0x22825C
#define IOCTL_DNDRV_SEM_OP2             0x228260
#define IOCTL_DNDRV_SEM_OP3             0x228264
#define IOCTL_DNDRV_VT_CAPS             0x228268
#define IOCTL_DNDRV_CALL_VMMR0_BIG      0x22826C

/* Fast-path IOCTLs (METHOD_NEITHER) */
#define IOCTL_DNDRV_FAST_DO_RAW_RUN     0x228303
#define IOCTL_DNDRV_FAST_DO_HM_RUN      0x228307
#define IOCTL_DNDRV_FAST_DO_NOP         0x22830B

/* ------------------------------------------------------------------ */
/*  Constants                                                         */
/* ------------------------------------------------------------------ */

#define DNDRV_SUP_VERSION               0x001A0007
#define DNDRV_COOKIE_MAGIC              "The Magic Word!"
#define DNDRV_IOCTL_FLAG                0x42000042

/* ------------------------------------------------------------------ */
/*  Request header (common to all IOCTLs)                             */
/* ------------------------------------------------------------------ */

#pragma pack(push, 8)

typedef struct DNDRV_REQ_HDR {
    UINT32      u32Cookie;      /* session cookie (from COOKIE IOCTL)   */
    UINT32      u32SessionCookie;
    UINT32      cbIn;           /* total input size (incl header)       */
    UINT32      cbOut;          /* total output size (incl header)      */
    UINT32      fFlags;         /* SUP_IOCTL_FLAG = 0x42000042          */
    INT32       rc;             /* VBox return code                     */
} DNDRV_REQ_HDR;

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_COOKIE request / response                               */
/* ------------------------------------------------------------------ */

typedef struct DNDRV_COOKIE_REQ {
    DNDRV_REQ_HDR   hdr;
    union {
        struct {
            char    szMagic[16];    /* "The Magic Word!" + NUL          */
            UINT32  u32ReqVersion;
            UINT32  u32MinVersion;
        } In;
        struct {
            UINT32  u32Cookie;
            UINT32  u32SessionCookie;
            UINT32  u32SessionVersion;
            UINT32  u32DriverVersion;
            UINT32  cbSession;
            void   *pSession;
        } Out;
    } u;
} DNDRV_COOKIE_REQ;

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_VT_CAPS request / response                              */
/* ------------------------------------------------------------------ */

typedef struct DNDRV_VT_CAPS_REQ {
    DNDRV_REQ_HDR   hdr;
    UINT32          u32Caps;    /* out: VT-x/AMD-V capability flags     */
} DNDRV_VT_CAPS_REQ;

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_GET_PAGING_MODE                                         */
/* ------------------------------------------------------------------ */

typedef struct DNDRV_PAGING_MODE_REQ {
    DNDRV_REQ_HDR   hdr;
    UINT32          enmMode;    /* out: paging mode enum                 */
} DNDRV_PAGING_MODE_REQ;

/* ------------------------------------------------------------------ */
/*  Function table entry (SUP_IOCTL_QUERY_FUNCS)                      */
/* ------------------------------------------------------------------ */

typedef struct DNDRV_FUNC_ENTRY {
    char        szName[28];
    UINT32      _pad;
    UINT64      pfn;
} DNDRV_FUNC_ENTRY;

typedef struct DNDRV_QUERY_FUNCS_REQ {
    DNDRV_REQ_HDR   hdr;
    UINT32          cFunctions;     /* out: entry count                 */
    UINT32          _pad;
    /* Followed by cFunctions * DNDRV_FUNC_ENTRY entries */
} DNDRV_QUERY_FUNCS_REQ;

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_LDR_OPEN                                                */
/* ------------------------------------------------------------------ */

typedef struct DNDRV_LDR_OPEN_REQ {
    DNDRV_REQ_HDR   hdr;
    UINT32          cbImageWithTabs;
    UINT32          cbImageBits;
    char            szName[32];
    char            szFilename[260];
} DNDRV_LDR_OPEN_REQ;

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_LDR_FREE                                                */
/* ------------------------------------------------------------------ */

typedef struct DNDRV_LDR_FREE_REQ {
    DNDRV_REQ_HDR   hdr;
    UINT64          pvImageBase;
} DNDRV_LDR_FREE_REQ;

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_PAGE_ALLOC_EX                                           */
/* ------------------------------------------------------------------ */

typedef struct DNDRV_PAGE_ALLOC_REQ {
    DNDRV_REQ_HDR   hdr;
    UINT32          cPages;
    UINT8           fKernelMapping;
    UINT8           fUserMapping;
    UINT8           fReserved0;
    UINT8           fReserved1;
    UINT64          pvR0;           /* out: kernel address              */
    /* Followed by cPages * UINT64 page descriptors */
} DNDRV_PAGE_ALLOC_REQ;

#pragma pack(pop)

/* ------------------------------------------------------------------ */
/*  Client context                                                    */
/* ------------------------------------------------------------------ */

typedef struct DNDRV {
    HANDLE      device;
    DWORD       last_error;
    UINT32      u32Cookie;
    UINT32      u32SessionCookie;
} DNDRV;

/* ------------------------------------------------------------------ */
/*  API                                                               */
/* ------------------------------------------------------------------ */

/*
 * Open a handle to \\.\DNDrv.
 * Returns TRUE on success; on failure sets ctx->last_error.
 */
BOOL dndrv_open(DNDRV *ctx);

/*
 * Close the device handle.
 */
void dndrv_close(DNDRV *ctx);

/*
 * Perform the SUP_IOCTL_COOKIE handshake to obtain session cookies.
 * Must be called before any other IOCTL.
 */
BOOL dndrv_cookie(DNDRV *ctx);

/*
 * SUP_IOCTL_VT_CAPS — Query VT-x/AMD-V hardware capabilities.
 */
BOOL dndrv_query_vt_caps(DNDRV *ctx, UINT32 *caps_out);

/*
 * SUP_IOCTL_GET_PAGING_MODE — Query the CPU paging mode.
 */
BOOL dndrv_query_paging_mode(DNDRV *ctx, UINT32 *mode_out);

/*
 * SUP_IOCTL_QUERY_FUNCS — Query the exported kernel function table.
 * buf must be at least 0x2820 bytes.  Returns entry count in *count_out.
 */
BOOL dndrv_query_funcs(DNDRV *ctx, void *buf, DWORD bufSize,
                       UINT32 *count_out);

/*
 * SUP_IOCTL_PAGE_ALLOC_EX — Allocate kernel pages.
 */
BOOL dndrv_page_alloc(DNDRV *ctx, UINT32 cPages, UINT64 *pvR0_out);

/*
 * SUP_IOCTL_PAGE_FREE — Free previously allocated kernel pages.
 */
BOOL dndrv_page_free(DNDRV *ctx, UINT64 pvR3);

/*
 * Raw IOCTL helper — send an arbitrary request structure.
 */
BOOL dndrv_ioctl(DNDRV *ctx, DWORD code, void *buf, DWORD size);

#ifdef __cplusplus
}
#endif

#endif /* DNDRV_H */
