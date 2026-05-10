/*
 * demo.c — Demonstrates NcHost driver capabilities (KmWpsMs.sys)
 *
 * Usage:  demo.exe [phys_addr_hex]
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Querying the driver version
 *   3. Reading physical memory at a given address
 *   4. Translating a virtual address to physical
 *   5. Physical memory write + readback verification
 */

#include "nchost.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Hex dump helper                                                   */
/* ------------------------------------------------------------------ */

static void hexdump(const void *data, SIZE_T size, UINT64 base_addr)
{
    const UCHAR *p = (const UCHAR *)data;
    SIZE_T i, j;

    for (i = 0; i < size; i += 16) {
        printf("  %012llX  ", (unsigned long long)(base_addr + i));
        for (j = 0; j < 16; j++) {
            if (i + j < size)
                printf("%02X ", p[i + j]);
            else
                printf("   ");
            if (j == 7) printf(" ");
        }
        printf(" |");
        for (j = 0; j < 16 && i + j < size; j++) {
            UCHAR c = p[i + j];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("|\n");
    }
}

/* ------------------------------------------------------------------ */
/*  Demo: read physical memory                                        */
/* ------------------------------------------------------------------ */

static BOOL demo_read_physical(NCHOST *ctx, UINT64 phys_addr)
{
    UCHAR buf[0x100];

    printf("\n[*] Reading 0x%zX bytes at physical address 0x%llX ...\n",
           sizeof(buf), (unsigned long long)phys_addr);

    if (!nchost_read_physical(ctx, phys_addr, buf, sizeof(buf))) {
        printf("[-] Failed to read physical memory (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }

    printf("[+] Physical memory dump:\n");
    hexdump(buf, sizeof(buf), phys_addr);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: translate VA -> PA                                          */
/* ------------------------------------------------------------------ */

static BOOL demo_translate_va(NCHOST *ctx)
{
    static volatile UINT64 marker = 0xDEADBEEFCAFEBABEULL;
    UINT64 phys = 0;

    printf("\n[*] Translating VA 0x%llX (our marker variable) ...\n",
           (unsigned long long)(UINT64)&marker);

    if (!nchost_get_physical_addr(ctx, (UINT64)&marker, &phys)) {
        printf("[-] VA->PA translation failed (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }

    printf("[+] Physical address: 0x%llX\n", (unsigned long long)phys);

    /* Read back via physical address to verify */
    UINT64 readback = 0;
    if (nchost_read_physical(ctx, phys, &readback, sizeof(readback))) {
        printf("[+] Readback via PA: 0x%llX\n",
               (unsigned long long)readback);
        if (readback == marker) {
            printf("[+] VA->PA round-trip verified OK\n");
        } else {
            printf("[-] Mismatch: expected 0x%llX, got 0x%llX\n",
                   (unsigned long long)marker,
                   (unsigned long long)readback);
        }
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: write physical + readback                                   */
/* ------------------------------------------------------------------ */

static BOOL demo_write_verify(NCHOST *ctx)
{
    static volatile UINT64 scratch = 0xAAAAAAAAAAAAAAAAULL;
    UINT64 phys = 0;
    UINT64 new_value = 0x4141414141414141ULL;
    UINT64 read_back = 0;

    printf("\n[*] Write test: targeting scratch buffer in our own process\n");
    printf("    Address:  0x%llX\n", (unsigned long long)(UINT64)&scratch);
    printf("    Before:   0x%llX\n", (unsigned long long)scratch);

    /* First translate our scratch VA to PA */
    if (!nchost_get_physical_addr(ctx, (UINT64)&scratch, &phys)) {
        printf("[-] Could not translate scratch VA (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }
    printf("    PhysAddr: 0x%llX\n", (unsigned long long)phys);

    /* Write via physical address */
    if (!nchost_write_physical(ctx, phys, &new_value, sizeof(new_value))) {
        printf("[-] Write failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("    After:    0x%llX (direct read)\n",
           (unsigned long long)scratch);

    /* Verify via driver read-back through physical path */
    if (!nchost_read_physical(ctx, phys, &read_back, sizeof(read_back))) {
        printf("[-] Read-back failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("    Readback: 0x%llX (via driver)\n",
           (unsigned long long)read_back);

    if (read_back == new_value && scratch == new_value) {
        printf("[+] Write + readback verified OK\n");
        return TRUE;
    } else {
        printf("[-] Mismatch!\n");
        return FALSE;
    }
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    NCHOST ctx;
    UINT64 phys_addr = 0x1000;   /* default: read from page 1 */
    UINT32 version   = 0;

    printf("=== NcHost driver demo (KmWpsMs.sys) ===\n\n");

    if (argc >= 2) {
        phys_addr = (UINT64)strtoull(argv[1], NULL, 16);
    }

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\NcHost ...\n");
    if (!nchost_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Get version --- */
    printf("\n[*] Querying driver version ...\n");
    if (nchost_get_version(&ctx, &version)) {
        printf("[+] Driver version: 0x%08X\n", version);
    } else {
        printf("[-] Version query failed (error %lu)\n", ctx.last_error);
    }

    /* --- Step 3: Read physical memory --- */
    demo_read_physical(&ctx, phys_addr);

    /* --- Step 4: Translate VA -> PA --- */
    demo_translate_va(&ctx);

    /* --- Step 5: Write + verify --- */
    demo_write_verify(&ctx);

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    nchost_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
