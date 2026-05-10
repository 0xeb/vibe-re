/*
 * gibepext.c — Client library implementation
 */

#include "gibepext.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define DEVICE_PATH L"\\\\.\\GibEpFirmware"

/* ------------------------------------------------------------------ */
/*  CRC-32 (must match driver's table-based implementation)           */
/* ------------------------------------------------------------------ */

static const UINT32 g_Crc32Table[256] = {
    0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,
    0xE963A535,0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91B,0x97D2D988,
    0x09B64C2B,0x7EB17CBB,0xE7B82D09,0x90BF1D9F,0x1DB71064,0x6AB020F2,
    0xF3B97148,0x84BE41DE,0x1ADAD47D,0x6DDDE4EB,0xF4D4B551,0x83D385C7,
    0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,0x14015C4F,0x63066CD9,
    0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,
    0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
    0xDBBBB9D6,0xACBCB9C0,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,
    0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F6B5,0x56B3C423,
    0xCFBA9599,0xB8BDA50F,0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,
    0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,0x76DC4190,0x01DB7106,
    0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,
    0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0D6B,0x086D3D2D,
    0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
    0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,
    0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,
    0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,
    0xA4D1C46D,0xD3D6F4FB,0x4369E96A,0x346ED9FC,0xAD678846,0xDA60B8D0,
    0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7822,0x3B6E20C8,0x4C69105E,
    0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,
    0x35B5A8FA,0x42B2986C,0xDBBBB9D6,0xACBCB9C0,0x32D86CE3,0x45DF5C75,
    0xDCD60DCF,0xABD13D59,0x26D930AC,0x51DE003A,0xC8D75180,0xBFD06116,
    0x21B4F6B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,0x2802B89E,0x5F058808,
    0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,0xB6662D3D,
    0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
    0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,
    0x7F6A0D6B,0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,
    0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,
    0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,0x62DD1DDF,0x15DA2D49,
    0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,0xA3BC0074,0xD4BB30E2,
    0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,0x346ED9FC,
    0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7822,
    0x3B6E20C8,0x4C69105E,0xD56041E4,0xA2677172,0x3C03E4D1,0x4B04D447,
    0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,0xDBBBB9D6,0xACBCB9C0,
    0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,0x51DE003A,
    0xC8D75180,0xBFD06116,0x21B4F6B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
    0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,
    0xC1611DAB,0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,
    0x71B18589,0x06B6B51F,0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,
    0x9609A88E,0xE10E9818,0x7F6A0D6B,0x086D3D2D,0x91646C97,0xE6635C01,
    0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,0x6C0695ED,0x1B01A57B,
    0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,0xFCB9887C,
    0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65
};

UINT32 gibepext_crc32(const void *data, UINT32 len)
{
    const UINT8 *p = (const UINT8 *)data;
    UINT32 crc = 0xFFFFFFFF;
    UINT32 i;

    for (i = 0; i < len; i++)
        crc = g_Crc32Table[(crc ^ p[i]) & 0xFF] ^ (crc >> 8);

    return ~crc;
}

/* ------------------------------------------------------------------ */
/*  Open / Close                                                      */
/* ------------------------------------------------------------------ */

BOOL gibepext_open(GIBEPEXT *ctx)
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

void gibepext_close(GIBEPEXT *ctx)
{
    if (ctx->device && ctx->device != INVALID_HANDLE_VALUE) {
        CloseHandle(ctx->device);
        ctx->device = INVALID_HANDLE_VALUE;
    }
}

/* ------------------------------------------------------------------ */
/*  Raw IOCTL helper                                                  */
/* ------------------------------------------------------------------ */

static BOOL ioctl(GIBEPEXT *ctx, DWORD code,
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
/*  Read physical memory                                              */
/* ------------------------------------------------------------------ */

BOOL gibepext_read_physmem(GIBEPEXT *ctx, UINT64 phys_addr,
                           void *buffer, UINT32 size)
{
    GIBEPEXT_PHYSMEM_REQUEST req;
    DWORD returned;

    req.addr_lo  = (UINT32)(phys_addr & 0xFFFFFFFF);
    req.addr_hi  = (UINT32)(phys_addr >> 32);
    req.size     = size;
    req.checksum = gibepext_crc32(&req, 12);

    return ioctl(ctx, IOCTL_GIBEPEXT_READ_PHYSMEM,
                 &req, sizeof(req),
                 buffer, size,
                 &returned);
}

/* ------------------------------------------------------------------ */
/*  Write physical memory                                             */
/* ------------------------------------------------------------------ */

BOOL gibepext_write_physmem(GIBEPEXT *ctx, UINT64 phys_addr,
                            const void *buffer, UINT32 size)
{
    UINT8  *req_buf;
    UINT32  total;
    UINT32  checksum;
    BOOL    ok;

    /* Layout: [addr_lo(4) | addr_hi(4) | size(4) | data(N) | crc(4)] */
    total = 12 + size + 4;
    req_buf = (UINT8 *)malloc(total);
    if (!req_buf) {
        ctx->last_error = ERROR_NOT_ENOUGH_MEMORY;
        return FALSE;
    }

    *(UINT32 *)(req_buf + 0) = (UINT32)(phys_addr & 0xFFFFFFFF);
    *(UINT32 *)(req_buf + 4) = (UINT32)(phys_addr >> 32);
    *(UINT32 *)(req_buf + 8) = size;
    memcpy(req_buf + 12, buffer, size);
    checksum = gibepext_crc32(req_buf, 12 + size);
    *(UINT32 *)(req_buf + 12 + size) = checksum;

    ok = ioctl(ctx, IOCTL_GIBEPEXT_WRITE_PHYSMEM,
               req_buf, total,
               NULL, 0, NULL);

    free(req_buf);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Read MSR                                                          */
/* ------------------------------------------------------------------ */

BOOL gibepext_read_msr(GIBEPEXT *ctx, UINT32 cpu_index, UINT32 msr_reg,
                       UINT32 *lo, UINT32 *hi)
{
    GIBEPEXT_MSR_REQUEST req;
    GIBEPEXT_MSR_RESULT  result;
    DWORD returned;
    BOOL  ok;

    req.cpu_index = cpu_index;
    req.msr_reg   = msr_reg;
    req.checksum  = gibepext_crc32(&req, 8);

    ok = ioctl(ctx, IOCTL_GIBEPEXT_READ_MSR,
               &req, sizeof(req),
               &result, sizeof(result),
               &returned);
    if (ok) {
        *lo = result.lo;
        *hi = result.hi;
    }
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Get physical address                                              */
/* ------------------------------------------------------------------ */

BOOL gibepext_get_phys_addr(GIBEPEXT *ctx, UINT64 virtual_addr,
                            UINT64 *phys_out)
{
    GIBEPEXT_VIRT2PHYS_REQUEST req;
    DWORD returned;
    BOOL  ok;

    req.virtual_addr = virtual_addr;
    req.checksum     = gibepext_crc32(&req, 8);

    ok = ioctl(ctx, IOCTL_GIBEPEXT_GET_PHYS_ADDR,
               &req, sizeof(req),
               phys_out, sizeof(UINT64),
               &returned);
    return ok;
}

/* ------------------------------------------------------------------ */
/*  Map IO space                                                      */
/* ------------------------------------------------------------------ */

BOOL gibepext_map_iospace(GIBEPEXT *ctx, UINT64 phys_addr, UINT32 size,
                          UINT32 cache_type, UINT64 *mapped_out)
{
    GIBEPEXT_MAP_REQUEST req;
    DWORD returned;
    BOOL  ok;

    memset(&req, 0, sizeof(req));
    req.phys_addr  = phys_addr;
    req.size       = size;
    req.cache_type = cache_type;
    req.checksum   = gibepext_crc32(&req, 24);

    ok = ioctl(ctx, IOCTL_GIBEPEXT_MAP_IOSPACE,
               &req, sizeof(req),
               mapped_out, sizeof(UINT64),
               &returned);
    return ok;
}
