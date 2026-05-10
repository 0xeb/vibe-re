/*
 * demo.c — Demonstrates DNDrv driver capabilities
 *
 * Usage:  demo.exe
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Performing the SUP_IOCTL_COOKIE handshake
 *   3. Querying the kernel function table
 *   4. Querying CPU paging mode
 *   5. Querying VT-x/AMD-V capabilities
 *   6. Listing exported SUPR0/RT kernel symbols
 */

#include "dndrv.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Paging mode names                                                 */
/* ------------------------------------------------------------------ */

static const char *PagingModeName(UINT32 mode)
{
    switch (mode) {
    case 0:  return "INVALID";
    case 1:  return "32-bit";
    case 2:  return "32-bit + PAE";
    case 3:  return "64-bit (AMD64)";
    case 4:  return "NESTED_32BIT";
    case 5:  return "NESTED_PAE";
    case 6:  return "NESTED_AMD64";
    default: return "UNKNOWN";
    }
}

/* ------------------------------------------------------------------ */
/*  VT capability flag names                                          */
/* ------------------------------------------------------------------ */

static void PrintVtCaps(UINT32 caps)
{
    if (caps & 0x01) printf("    VT-x\n");
    if (caps & 0x02) printf("    AMD-V\n");
    if (caps & 0x04) printf("    Nested paging (EPT/NPT)\n");
    if (caps & 0x08) printf("    Unrestricted guest\n");
    if (caps == 0)   printf("    (none)\n");
}

/* ------------------------------------------------------------------ */
/*  Demo: list exported kernel symbols                                */
/* ------------------------------------------------------------------ */

static void DemoListSymbols(DNDRV *ctx)
{
    UCHAR                   buf[0x2820];
    DNDRV_QUERY_FUNCS_REQ  *pReq = (DNDRV_QUERY_FUNCS_REQ *)buf;
    DNDRV_FUNC_ENTRY       *pEntry;
    UINT32                  count = 0;
    UINT32                  i;
    UINT32                  supCount = 0, rtCount = 0;

    printf("\n[*] Querying kernel function table ...\n");

    if (!dndrv_query_funcs(ctx, buf, sizeof(buf), &count)) {
        printf("[-] Failed to query function table (error %lu)\n",
               ctx->last_error);
        return;
    }

    printf("[+] Function table contains %u entries\n", count);
    pEntry = (DNDRV_FUNC_ENTRY *)(buf + sizeof(DNDRV_QUERY_FUNCS_REQ));

    /* Count by prefix */
    for (i = 0; i < count; i++) {
        if (strncmp(pEntry[i].szName, "SUPR0", 5) == 0 ||
            strncmp(pEntry[i].szName, "SUP",   3) == 0)
            supCount++;
        else if (strncmp(pEntry[i].szName, "RT", 2) == 0)
            rtCount++;
    }

    printf("[+] SUPR0/SUP symbols: %u\n", supCount);
    printf("[+] RT (IPRT) symbols: %u\n\n", rtCount);

    /* Print first 20 symbols as sample */
    printf("    First %u symbols:\n", count < 20 ? count : 20);
    for (i = 0; i < count && i < 20; i++) {
        printf("      [%3u] %-28s  0x%016llX\n",
               i, pEntry[i].szName,
               (unsigned long long)pEntry[i].pfn);
    }

    if (count > 20)
        printf("      ... (%u more)\n", count - 20);
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    DNDRV   ctx;
    UINT32  vtCaps   = 0;
    UINT32  pagingMode = 0;

    (void)argc;
    (void)argv;

    printf("=== DNDrv driver demo ===\n\n");

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\DNDrv ...\n");
    if (!dndrv_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Cookie handshake --- */
    printf("\n[*] Performing SUP_IOCTL_COOKIE handshake ...\n");
    if (!dndrv_cookie(&ctx)) {
        printf("[-] Cookie handshake failed (error %lu)\n", ctx.last_error);
        dndrv_close(&ctx);
        return 1;
    }
    printf("[+] Session established\n");
    printf("    Cookie:         0x%08X\n", ctx.u32Cookie);
    printf("    Session cookie: 0x%08X\n", ctx.u32SessionCookie);

    /* --- Step 3: Query paging mode --- */
    printf("\n[*] Querying CPU paging mode ...\n");
    if (dndrv_query_paging_mode(&ctx, &pagingMode)) {
        printf("[+] Paging mode: %u (%s)\n",
               pagingMode, PagingModeName(pagingMode));
    } else {
        printf("[-] Paging mode query failed\n");
    }

    /* --- Step 4: Query VT-x/AMD-V capabilities --- */
    printf("\n[*] Querying VT-x/AMD-V capabilities ...\n");
    if (dndrv_query_vt_caps(&ctx, &vtCaps)) {
        printf("[+] VT capabilities: 0x%08X\n", vtCaps);
        PrintVtCaps(vtCaps);
    } else {
        printf("[-] VT caps query failed (may require VT-x/AMD-V HW)\n");
    }

    /* --- Step 5: List kernel symbols --- */
    DemoListSymbols(&ctx);

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    dndrv_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
