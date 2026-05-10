/*
 * demo.c — Demonstrates all WinHwDriver capabilities
 *
 * Usage:  demo.exe
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Querying driver version
 *   3. Querying open-handle reference count
 *   4. Reading an MSR (IA32_TSC = 0x10)
 *   5. Reading an I/O port (PIT channel 0 = 0x40)
 *   6. Reading PCI configuration (host bridge at 00:00.0)
 *   7. Reading physical memory at address 0 (BIOS IVT / real-mode entry)
 */

#include "winhwdriver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/*  Hex dump helper                                                   */
/* ------------------------------------------------------------------ */

static void hexdump(const void *data, SIZE_T size, UINT64 base_addr)
{
    const unsigned char *p = (const unsigned char *)data;
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
            unsigned char c = p[i + j];
            printf("%c", (c >= 0x20 && c < 0x7F) ? c : '.');
        }
        printf("|\n");
    }
}

/* ------------------------------------------------------------------ */
/*  Demo: query driver info                                           */
/* ------------------------------------------------------------------ */

static BOOL demo_driver_info(WINHWDRIVER *ctx)
{
    UINT32 version = 0;
    INT32  refcount = 0;

    printf("\n[*] Querying driver version ...\n");
    if (!winhwdriver_get_version(ctx, &version)) {
        printf("[-] Failed to get version (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }
    printf("[+] Driver version: 0x%08X (major=%u, minor=%u)\n",
           version, (version >> 24) & 0xFF, version & 0xFFFF);

    printf("\n[*] Querying reference count ...\n");
    if (!winhwdriver_get_refcount(ctx, &refcount)) {
        printf("[-] Failed to get refcount (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }
    printf("[+] Reference count: %d\n", refcount);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read MSR (IA32_TIME_STAMP_COUNTER = 0x10)                   */
/* ------------------------------------------------------------------ */

static BOOL demo_read_msr(WINHWDRIVER *ctx)
{
    UINT64 tsc = 0;

    printf("\n[*] Reading MSR 0x10 (IA32_TIME_STAMP_COUNTER) ...\n");
    if (!winhwdriver_read_msr(ctx, 0x10, &tsc)) {
        printf("[-] Failed to read MSR (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }
    printf("[+] TSC = 0x%016llX (%llu)\n",
           (unsigned long long)tsc, (unsigned long long)tsc);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read I/O port (PIT channel 0 counter)                      */
/* ------------------------------------------------------------------ */

static BOOL demo_read_io_port(WINHWDRIVER *ctx)
{
    UINT32 val = 0;

    printf("\n[*] Reading I/O port 0x40 (PIT channel 0, 1 byte) ...\n");
    if (!winhwdriver_read_io_port(ctx, 0x40, 1, &val)) {
        printf("[-] Failed to read I/O port (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }
    printf("[+] Port 0x40 = 0x%02X\n", val);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read PCI config (host bridge 00:00.0)                       */
/* ------------------------------------------------------------------ */

static BOOL demo_read_pci(WINHWDRIVER *ctx)
{
    UCHAR  pci_buf[64];
    UINT16 vendor_id, device_id;

    /*
     * PCI address encoding used by the driver:
     *   bits 15:8  = bus number
     *   bits  7:3  = device number
     *   bits  2:0  = function number
     * So bus=0, dev=0, func=0 -> pci_addr = 0x0000.
     */
    printf("\n[*] Reading PCI config for 00:00.0 (host bridge) ...\n");
    if (!winhwdriver_read_pci_config(ctx, 0x0000, 0, pci_buf, 64)) {
        printf("[-] Failed to read PCI config (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }

    vendor_id = *(UINT16 *)(pci_buf + 0);
    device_id = *(UINT16 *)(pci_buf + 2);
    printf("[+] Vendor: 0x%04X  Device: 0x%04X\n",
           vendor_id, device_id);
    hexdump(pci_buf, 64, 0);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read physical memory at address 0                           */
/* ------------------------------------------------------------------ */

static BOOL demo_read_phys_memory(WINHWDRIVER *ctx)
{
    UCHAR buf[64];

    printf("\n[*] Reading 64 bytes of physical memory at 0x0 ...\n");
    if (!winhwdriver_read_memory(ctx, 0, 1, 64, buf)) {
        printf("[-] Failed to read physical memory (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }
    printf("[+] Physical memory at 0x0:\n");
    hexdump(buf, 64, 0);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    WINHWDRIVER ctx;

    (void)argc;
    (void)argv;

    printf("=== WinHwDriver demo ===\n\n");

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\WinHwDriver ...\n");
    if (!winhwdriver_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Driver info --- */
    demo_driver_info(&ctx);

    /* --- Step 3: MSR --- */
    demo_read_msr(&ctx);

    /* --- Step 4: I/O port --- */
    demo_read_io_port(&ctx);

    /* --- Step 5: PCI config --- */
    demo_read_pci(&ctx);

    /* --- Step 6: Physical memory --- */
    demo_read_phys_memory(&ctx);

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    winhwdriver_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
