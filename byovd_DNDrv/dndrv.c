/*
 * dndrv.c — Client library implementation
 */

#include "dndrv.h"
#include <stdio.h>
#include <string.h>

#define DEVICE_PATH L"\\\\.\\DNDrv"

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL dndrv_open(DNDRV *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
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

void dndrv_close(DNDRV *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

BOOL dndrv_ioctl(DNDRV *ctx, DWORD code, void *buf, DWORD size)
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
/*  SUP_IOCTL_COOKIE — establish session                              */
/* ------------------------------------------------------------------ */

BOOL dndrv_cookie(DNDRV *ctx)
{
    DNDRV_COOKIE_REQ req;

    memset(&req, 0, sizeof(req));
    req.hdr.cbIn    = 0x30;
    req.hdr.cbOut   = 0x38;
    req.hdr.fFlags  = DNDRV_IOCTL_FLAG;

    /* Cookie magic identifies us as a VBox client */
    memcpy(req.u.In.szMagic, DNDRV_COOKIE_MAGIC, 16);
    req.u.In.u32ReqVersion = DNDRV_SUP_VERSION;
    req.u.In.u32MinVersion = DNDRV_SUP_VERSION & 0xFFFF0000;

    if (!dndrv_ioctl(ctx, IOCTL_DNDRV_COOKIE, &req, sizeof(req)))
        return FALSE;

    if (req.hdr.rc != 0)
        return FALSE;

    ctx->u32Cookie        = req.u.Out.u32Cookie;
    ctx->u32SessionCookie = req.u.Out.u32SessionCookie;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Fill standard header fields for authenticated IOCTLs              */
/* ------------------------------------------------------------------ */

static void FillHeader(DNDRV *ctx, DNDRV_REQ_HDR *hdr,
                       UINT32 cbIn, UINT32 cbOut)
{
    hdr->u32Cookie        = ctx->u32Cookie;
    hdr->u32SessionCookie = ctx->u32SessionCookie;
    hdr->cbIn             = cbIn;
    hdr->cbOut            = cbOut;
    hdr->fFlags           = DNDRV_IOCTL_FLAG;
    hdr->rc               = 0;
}

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_VT_CAPS — query hardware virtualization capabilities    */
/* ------------------------------------------------------------------ */

BOOL dndrv_query_vt_caps(DNDRV *ctx, UINT32 *caps_out)
{
    DNDRV_VT_CAPS_REQ req;

    memset(&req, 0, sizeof(req));
    FillHeader(ctx, &req.hdr, 0x18, 0x1C);
    *caps_out = 0;

    if (!dndrv_ioctl(ctx, IOCTL_DNDRV_VT_CAPS, &req, sizeof(req)))
        return FALSE;

    if (req.hdr.rc < 0)
        return FALSE;

    *caps_out = req.u32Caps;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_GET_PAGING_MODE                                         */
/* ------------------------------------------------------------------ */

BOOL dndrv_query_paging_mode(DNDRV *ctx, UINT32 *mode_out)
{
    DNDRV_PAGING_MODE_REQ req;

    memset(&req, 0, sizeof(req));
    FillHeader(ctx, &req.hdr, 0x18, 0x1C);
    *mode_out = 0;

    if (!dndrv_ioctl(ctx, IOCTL_DNDRV_GET_PAGING_MODE, &req, sizeof(req)))
        return FALSE;

    *mode_out = req.enmMode;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_QUERY_FUNCS                                             */
/* ------------------------------------------------------------------ */

BOOL dndrv_query_funcs(DNDRV *ctx, void *buf, DWORD bufSize,
                       UINT32 *count_out)
{
    DNDRV_QUERY_FUNCS_REQ *pReq;

    *count_out = 0;
    if (bufSize < 0x2820)
        return FALSE;

    pReq = (DNDRV_QUERY_FUNCS_REQ *)buf;
    memset(pReq, 0, sizeof(*pReq));
    FillHeader(ctx, &pReq->hdr, 0x18, 0x2820);

    if (!dndrv_ioctl(ctx, IOCTL_DNDRV_QUERY_FUNCS, buf, 0x2820))
        return FALSE;

    *count_out = pReq->cFunctions;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_PAGE_ALLOC_EX — allocate kernel pages                   */
/* ------------------------------------------------------------------ */

BOOL dndrv_page_alloc(DNDRV *ctx, UINT32 cPages, UINT64 *pvR0_out)
{
    UCHAR buf[0x2000];     /* enough for header + page descriptors */
    DNDRV_PAGE_ALLOC_REQ *pReq = (DNDRV_PAGE_ALLOC_REQ *)buf;
    UINT32 cbOut;

    *pvR0_out = 0;
    cbOut = (UINT32)(0x28 + cPages * 8);
    if (cbOut > sizeof(buf))
        return FALSE;

    memset(buf, 0, sizeof(buf));
    FillHeader(ctx, &pReq->hdr, 0x20, cbOut);
    pReq->cPages         = cPages;
    pReq->fKernelMapping  = 1;
    pReq->fUserMapping    = 1;

    if (!dndrv_ioctl(ctx, IOCTL_DNDRV_PAGE_ALLOC_EX, buf, cbOut))
        return FALSE;

    *pvR0_out = pReq->pvR0;
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  SUP_IOCTL_PAGE_FREE — free kernel pages                           */
/* ------------------------------------------------------------------ */

BOOL dndrv_page_free(DNDRV *ctx, UINT64 pvR3)
{
    struct {
        DNDRV_REQ_HDR hdr;
        UINT64        pvR3;
    } req;

    memset(&req, 0, sizeof(req));
    FillHeader(ctx, &req.hdr, 0x20, 0x18);
    req.pvR3 = pvR3;

    return dndrv_ioctl(ctx, IOCTL_DNDRV_PAGE_FREE, &req, sizeof(req));
}
