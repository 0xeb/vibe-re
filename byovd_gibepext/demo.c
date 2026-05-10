/*
 * demo.c — Demonstrates all gibepext driver capabilities
 *
 * Usage:  demo.exe [phys_addr]
 *
 * Shows:
 *   1. Opening the firmware driver device
 *   2. Reading physical memory at a given address
 *   3. Writing + verifying physical memory (low BIOS region)
 *   4. Reading an MSR register (IA32_TSC)
 *   5. Translating a virtual address to physical
 */

#include "gibepext.h"
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

static BOOL demo_read_physmem(GIBEPEXT *ctx, UINT64 phys_addr)
{
    UCHAR buf[64];

    printf("\n[*] Reading 64 bytes at physical address 0x%llX ...\n",
           (unsigned long long)phys_addr);

    if (!gibepext_read_physmem(ctx, phys_addr, buf, sizeof(buf))) {
        printf("[-] Read failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Physical memory read OK:\n");
    hexdump(buf, sizeof(buf), phys_addr);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: write + readback test                                       */
/* ------------------------------------------------------------------ */

static BOOL demo_write_verify(GIBEPEXT *ctx, UINT64 phys_addr)
{
    UCHAR original[4];
    UCHAR write_buf[4] = { 0x41, 0x42, 0x43, 0x44 };
    UCHAR readback[4];

    printf("\n[*] Write test at physical address 0x%llX ...\n",
           (unsigned long long)phys_addr);

    /* Save original */
    if (!gibepext_read_physmem(ctx, phys_addr, original, 4)) {
        printf("[-] Read original failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("[+] Original: %02X %02X %02X %02X\n",
           original[0], original[1], original[2], original[3]);

    /* Write test pattern */
    if (!gibepext_write_physmem(ctx, phys_addr, write_buf, 4)) {
        printf("[-] Write failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("[+] Wrote:    41 42 43 44\n");

    /* Read back */
    if (!gibepext_read_physmem(ctx, phys_addr, readback, 4)) {
        printf("[-] Readback failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("[+] Readback: %02X %02X %02X %02X\n",
           readback[0], readback[1], readback[2], readback[3]);

    /* Restore original */
    gibepext_write_physmem(ctx, phys_addr, original, 4);

    if (memcmp(readback, write_buf, 4) == 0) {
        printf("[+] Write + readback verified OK\n");
        return TRUE;
    } else {
        printf("[-] Mismatch!\n");
        return FALSE;
    }
}

/* ------------------------------------------------------------------ */
/*  Demo: read MSR (IA32_TSC = 0x10)                                  */
/* ------------------------------------------------------------------ */

static BOOL demo_read_msr(GIBEPEXT *ctx)
{
    UINT32 lo = 0, hi = 0;

    printf("\n[*] Reading MSR 0x10 (IA32_TSC) on CPU 0 ...\n");

    if (!gibepext_read_msr(ctx, 0, 0x10, &lo, &hi)) {
        printf("[-] MSR read failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] IA32_TSC = 0x%08X%08X\n", hi, lo);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: CRC-32 self-test                                            */
/* ------------------------------------------------------------------ */

static void demo_crc32(void)
{
    const char *test = "123456789";
    UINT32 crc;

    printf("\n[*] CRC-32 self-test ...\n");
    crc = gibepext_crc32(test, 9);
    printf("[+] CRC32(\"123456789\") = 0x%08X", crc);
    if (crc == 0xCBF43926)
        printf(" (correct)\n");
    else
        printf(" (INCORRECT, expected 0xCBF43926)\n");
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    GIBEPEXT ctx;
    UINT64   phys_addr = 0x1000;  /* default: read at 1 page */

    printf("=== gibepext driver demo ===\n\n");

    if (argc >= 2)
        phys_addr = (UINT64)strtoull(argv[1], NULL, 0);

    /* --- CRC self-test (no driver needed) --- */
    demo_crc32();

    /* --- Step 1: Open driver --- */
    printf("\n[*] Opening \\\\.\\GibEpFirmware ...\n");
    if (!gibepext_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Read physical memory --- */
    demo_read_physmem(&ctx, phys_addr);

    /* --- Step 3: Read BIOS data area (0xF0000) --- */
    printf("\n[*] Reading BIOS data at 0xF0000 ...\n");
    demo_read_physmem(&ctx, 0xF0000);

    /* --- Step 4: Read MSR --- */
    demo_read_msr(&ctx);

    /* --- Step 5: Write test (low address, non-destructive) --- */
    /* NOTE: Writing to arbitrary physical memory is dangerous!
     * This demo writes + restores at a safe high address.
     * Uncomment only if you understand the implications. */
    /* demo_write_verify(&ctx, 0x100000); */

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    gibepext_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
