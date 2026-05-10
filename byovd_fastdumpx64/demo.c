/*
 * demo.c — Demonstrates all FastDump driver capabilities
 *
 * Usage:  demo.exe [phys_addr]
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Reading CPUID leaves via the driver
 *   3. Reading an MSR value (IA32_MTRRCAP = 0xFE)
 *   4. Reading a physical memory page
 *   5. Reading arbitrary physical memory range
 */

#include "fastdump.h"
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
/*  Demo: read CPUID via driver                                       */
/* ------------------------------------------------------------------ */

static BOOL demo_cpuid(FASTDUMP *ctx)
{
    FASTDUMP_CPUID_RESPONSE resp;
    char vendor[13];

    printf("\n[*] Querying CPUID via driver ...\n");

    if (!fastdump_get_cpuid(ctx, &resp)) {
        printf("[-] CPUID query failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    /* Leaf 0: vendor string = EBX + EDX + ECX */
    memcpy(vendor + 0, &resp.standard[0].ebx, 4);
    memcpy(vendor + 4, &resp.standard[0].edx, 4);
    memcpy(vendor + 8, &resp.standard[0].ecx, 4);
    vendor[12] = '\0';

    printf("[+] CPU Vendor:     %s\n", vendor);
    printf("[+] Max std leaf:   0x%X\n", resp.max_leaf);
    printf("[+] Max ext leaf:   0x%X\n", resp.max_ext_leaf);

    if (resp.max_leaf >= 1) {
        UINT32 eax = resp.standard[1].eax;
        printf("[+] Family/Model:   Family %u, Model %u, Stepping %u\n",
               ((eax >> 8) & 0xF) + ((eax >> 20) & 0xFF),
               ((eax >> 4) & 0xF) | (((eax >> 16) & 0xF) << 4),
               eax & 0xF);
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read MSR                                                    */
/* ------------------------------------------------------------------ */

static BOOL demo_msr(FASTDUMP *ctx)
{
    UINT64 value = 0;

    printf("\n[*] Reading MSR 0xFE (IA32_MTRRCAP) ...\n");

    if (!fastdump_read_msr(ctx, 0xFE, &value)) {
        printf("[-] MSR read failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] MSR 0xFE = 0x%llX\n", (unsigned long long)value);
    printf("    VCNT:     %llu\n", (unsigned long long)(value & 0xFF));
    printf("    FIX:      %s\n", (value & 0x100) ? "yes" : "no");
    printf("    WC:       %s\n", (value & 0x400) ? "yes" : "no");
    printf("    SMRR:     %s\n", (value & 0x800) ? "yes" : "no");

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read physical memory                                        */
/* ------------------------------------------------------------------ */

static BOOL demo_read_phys(FASTDUMP *ctx, UINT64 phys_addr)
{
    UCHAR page[256];

    printf("\n[*] Reading 256 bytes at physical address 0x%llX ...\n",
           (unsigned long long)phys_addr);

    if (!fastdump_read_phys(ctx, phys_addr, page, sizeof(page))) {
        printf("[-] Physical read failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Physical memory at 0x%llX:\n",
           (unsigned long long)phys_addr);
    hexdump(page, sizeof(page), phys_addr);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read page 0 (BIOS data area)                                */
/* ------------------------------------------------------------------ */

static BOOL demo_read_bios_data(FASTDUMP *ctx)
{
    UCHAR page[0x1000];

    printf("\n[*] Reading physical page 0 (real-mode IVT / BDA) ...\n");

    if (!fastdump_read_phys(ctx, 0, page, sizeof(page))) {
        printf("[-] Page 0 read failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] First 64 bytes of physical page 0:\n");
    hexdump(page, 64, 0);

    /* BIOS Data Area starts at 0x400 */
    printf("\n[+] BIOS Data Area (0x400-0x4FF):\n");
    hexdump(page + 0x400, 0x100, 0x400);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    FASTDUMP ctx;
    UINT64   phys_addr = 0x1000;    /* default: second physical page */

    printf("=== FastDump driver demo ===\n\n");

    if (argc >= 2) {
        phys_addr = _strtoui64(argv[1], NULL, 0);
    }

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\FastDump ...\n");
    if (!fastdump_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Read CPUID --- */
    demo_cpuid(&ctx);

    /* --- Step 3: Read MSR --- */
    demo_msr(&ctx);

    /* --- Step 4: Read BIOS data area --- */
    demo_read_bios_data(&ctx);

    /* --- Step 5: Read specified physical address --- */
    demo_read_phys(&ctx, phys_addr);

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    fastdump_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
