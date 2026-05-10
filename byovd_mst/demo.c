/*
 * demo.c — Demonstrates all MST driver capabilities
 *
 * Usage:  demo.exe [bus:slot]
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Enumerating Mellanox HCA devices
 *   3. Reading PCI configuration space (Vendor/Device ID)
 *   4. Writing + verifying a PCI config register (scratch)
 *   5. Allocating a physical page via the driver
 *   6. Enumerating all PCI devices on the system
 */

#include "mst.h"
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
/*  Demo: enumerate Mellanox HCA devices                              */
/* ------------------------------------------------------------------ */

static BOOL demo_enum_hca(MST *ctx)
{
    MST_DEVICE_ENTRY entries[16];
    UINT32 count = 0;
    UINT32 i;

    printf("\n[*] Enumerating Mellanox HCA devices ...\n");

    if (!mst_enum_devices(ctx, entries, 16, &count)) {
        printf("[-] Enum failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Found %u device(s)\n", count);
    for (i = 0; i < count && i < 16; i++) {
        printf("    [%u] DevID: 0x%08X  Bus: 0x%X  Slot: 0x%X  "
               "BAR0: 0x%llX (size 0x%llX)\n",
               i, entries[i].dev_id, entries[i].bus, entries[i].slot,
               (unsigned long long)entries[i].bar0_pa,
               (unsigned long long)entries[i].bar0_size);
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read PCI config header                                      */
/* ------------------------------------------------------------------ */

static BOOL demo_pci_read(MST *ctx, UINT32 bus, UINT32 slot)
{
    UINT32 value;
    UINT32 offset;
    UINT8  config[64];

    printf("\n[*] Reading PCI config header for bus 0x%X slot 0x%X ...\n",
           bus, slot);

    for (offset = 0; offset < 64; offset += 4) {
        if (!mst_pci_read(ctx, bus, slot, offset, &value)) {
            printf("[-] Read failed at offset 0x%X (error %lu)\n",
                   offset, ctx->last_error);
            return FALSE;
        }
        memcpy(config + offset, &value, 4);
    }

    printf("[+] PCI config header:\n");
    hexdump(config, 64, 0);

    /* Parse basic fields */
    UINT16 vendorId = *(UINT16 *)(config + 0);
    UINT16 deviceId = *(UINT16 *)(config + 2);
    UINT16 command  = *(UINT16 *)(config + 4);
    UINT16 status_  = *(UINT16 *)(config + 6);
    UINT8  revId    = config[8];
    UINT8  classCode = config[11];

    printf("\n[+] Vendor ID:   0x%04X%s\n", vendorId,
           vendorId == 0x15B3 ? " (Mellanox)" : "");
    printf("[+] Device ID:   0x%04X\n", deviceId);
    printf("[+] Command:     0x%04X\n", command);
    printf("[+] Status:      0x%04X\n", status_);
    printf("[+] Revision:    0x%02X\n", revId);
    printf("[+] Class:       0x%02X\n", classCode);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: PCI config write + readback verification                    */
/* ------------------------------------------------------------------ */

static BOOL demo_pci_write_verify(MST *ctx, UINT32 bus, UINT32 slot)
{
    UINT32 original, readback;
    /* Read the cache line size register (offset 0x0C, low byte) —
       usually safe to modify for testing */
    UINT32 offset = 0x0C;

    printf("\n[*] Write test: PCI config offset 0x%X on bus 0x%X slot 0x%X\n",
           offset, bus, slot);

    if (!mst_pci_read(ctx, bus, slot, offset, &original)) {
        printf("[-] Read failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("    Original: 0x%08X\n", original);

    /* Write back the same value (non-destructive) */
    if (!mst_pci_write(ctx, bus, slot, offset, original)) {
        printf("[-] Write failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    if (!mst_pci_read(ctx, bus, slot, offset, &readback)) {
        printf("[-] Readback failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("    Readback: 0x%08X\n", readback);

    if (readback == original) {
        printf("[+] Write + readback verified OK\n");
        return TRUE;
    } else {
        printf("[-] Mismatch!\n");
        return FALSE;
    }
}

/* ------------------------------------------------------------------ */
/*  Demo: allocate a physical page                                    */
/* ------------------------------------------------------------------ */

static BOOL demo_alloc_page(MST *ctx)
{
    UINT64 user_va = 0, phys_addr = 0;

    printf("\n[*] Allocating a physical page via the driver ...\n");

    if (!mst_alloc_page(ctx, &user_va, &phys_addr)) {
        printf("[-] Alloc failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] User VA:    0x%llX\n", (unsigned long long)user_va);
    printf("[+] Phys addr:  0x%llX\n", (unsigned long long)phys_addr);

    /* Read first 64 bytes from the mapped page */
    if (user_va != 0) {
        printf("[+] First 64 bytes of mapped page:\n");
        hexdump((void *)(ULONG_PTR)user_va, 64, user_va);
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: enumerate all PCI devices                                   */
/* ------------------------------------------------------------------ */

static BOOL demo_enum_all_pci(MST *ctx)
{
    UINT8  buf[8192];
    UINT32 count = 0;
    UINT32 i;
    UINT32 *data;

    printf("\n[*] Enumerating all PCI devices ...\n");

    if (!mst_enum_all_pci(ctx, buf, sizeof(buf), &count)) {
        printf("[-] Enum all PCI failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Found %u PCI device(s)\n", count);

    data = (UINT32 *)(buf + 8);
    for (i = 0; i < count && i < 32; i++) {
        printf("    [%2u] Bus: 0x%04X  Slot: 0x%04X\n",
               i, data[i * 2], data[i * 2 + 1]);
    }
    if (count > 32)
        printf("    ... (%u more)\n", count - 32);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    MST     ctx;
    UINT32  bus  = 0;
    UINT32  slot = 0;

    printf("=== MST driver demo ===\n\n");

    if (argc >= 2) {
        /* Parse bus:slot from argument */
        char *colon = strchr(argv[1], ':');
        if (colon) {
            bus  = (UINT32)strtoul(argv[1], NULL, 0);
            slot = (UINT32)strtoul(colon + 1, NULL, 0);
        } else {
            bus = (UINT32)strtoul(argv[1], NULL, 0);
        }
    }

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\mst64_4.20.0 ...\n");
    if (!mst_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Enumerate Mellanox HCA devices --- */
    demo_enum_hca(&ctx);

    /* --- Step 3: Read PCI config --- */
    printf("\n[*] Reading PCI config for bus 0x%X slot 0x%X ...\n", bus, slot);
    demo_pci_read(&ctx, bus, slot);

    /* --- Step 4: Write test (non-destructive) --- */
    demo_pci_write_verify(&ctx, bus, slot);

    /* --- Step 5: Allocate physical page --- */
    demo_alloc_page(&ctx);

    /* --- Step 6: Enumerate all PCI devices --- */
    demo_enum_all_pci(&ctx);

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    mst_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
