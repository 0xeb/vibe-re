/*
 * demo.c -- Demonstrates all CORMEM driver capabilities
 *
 * Usage:  demo.exe [phys_addr]
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Querying pool block count and messaging pool status
 *   3. Translating a virtual address to physical
 *   4. Mapping a page of physical memory and reading its contents
 *   5. Reading / writing I/O ports (COM1 scratch register)
 *   6. Reading a DWORD from a physical address (convenience API)
 */

#include "cormem.h"
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
/*  Demo: query pool information                                      */
/* ------------------------------------------------------------------ */

static BOOL demo_pool_info(CORMEM *ctx)
{
    UINT32              block_count = 0;
    CORMEM_POOL_STATUS  status;

    printf("\n[*] Querying pool block count ...\n");
    if (!cormem_get_pool_block_count(ctx, &block_count)) {
        printf("[-] Failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("[+] Pool block count: %u\n", block_count);

    printf("\n[*] Querying messaging pool status ...\n");
    if (!cormem_get_pool_status(ctx, &status)) {
        printf("[-] Failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("[+] Pool status:\n");
    printf("    Free:  %u bytes in %u fragment(s) (max block: %u)\n",
           status.free_size, status.free_frags, status.max_free_block);
    printf("    Used:  %u bytes in %u fragment(s) (max block: %u)\n",
           status.used_size, status.used_frags, status.max_used_block);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: virtual to physical translation                             */
/* ------------------------------------------------------------------ */

static BOOL demo_virt_to_phys(CORMEM *ctx)
{
    static volatile UINT32 target = 0xDEADBEEF;
    UINT64 phys = 0;

    printf("\n[*] Translating virtual address 0x%llX ...\n",
           (unsigned long long)(UINT64)&target);

    if (!cormem_virt_to_phys(ctx, (UINT64)&target, &phys)) {
        printf("[-] Failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Physical address: 0x%llX\n", (unsigned long long)phys);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: map physical memory and dump                                */
/* ------------------------------------------------------------------ */

static BOOL demo_map_physical(CORMEM *ctx, UINT64 phys_addr)
{
    PVOID mapped = NULL;

    printf("\n[*] Mapping physical page at 0x%llX ...\n",
           (unsigned long long)(phys_addr & ~0xFFFULL));

    if (!cormem_map_buffer(ctx, phys_addr & ~0xFFFULL, 0x1000, &mapped)) {
        printf("[-] Map failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Mapped at virtual address: 0x%llX\n",
           (unsigned long long)(UINT64)mapped);

    printf("[+] First 64 bytes:\n");
    hexdump(mapped, 64, phys_addr & ~0xFFFULL);

    printf("\n[*] Unmapping ...\n");
    if (!cormem_unmap_buffer(ctx, mapped)) {
        printf("[-] Unmap failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("[+] Unmapped OK\n");

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: I/O port read/write (COM1 scratch register)                 */
/* ------------------------------------------------------------------ */

static BOOL demo_io_ports(CORMEM *ctx)
{
    UINT32 orig = 0, readback = 0;
    UINT16 port = 0x3F8 + 7;  /* COM1 scratch register */

    printf("\n[*] I/O port test: COM1 scratch register (port 0x%X)\n", port);

    if (!cormem_read_io(ctx, port, 1, &orig)) {
        printf("[-] Read failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("[+] Current value: 0x%02X\n", orig);

    printf("[*] Writing 0xA5 ...\n");
    if (!cormem_write_io(ctx, port, 1, 0xA5)) {
        printf("[-] Write failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    if (!cormem_read_io(ctx, port, 1, &readback)) {
        printf("[-] Read-back failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }
    printf("[+] Read-back: 0x%02X\n", readback);

    /* Restore */
    cormem_write_io(ctx, port, 1, orig);

    if (readback == 0xA5) {
        printf("[+] I/O port write + read-back verified OK\n");
    } else {
        printf("[-] Mismatch (expected 0xA5, got 0x%02X)\n", readback);
    }

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: read physical DWORD convenience API                         */
/* ------------------------------------------------------------------ */

static BOOL demo_read_phys(CORMEM *ctx, UINT64 phys_addr)
{
    UINT32 val = 0;

    printf("\n[*] Reading DWORD at physical 0x%llX ...\n",
           (unsigned long long)phys_addr);

    if (!cormem_read_phys32(ctx, phys_addr, &val)) {
        printf("[-] Failed (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Value: 0x%08X\n", val);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    CORMEM  ctx;
    UINT64  phys_addr = 0;

    printf("=== CORMEM driver demo ===\n\n");

    if (argc >= 2) {
        phys_addr = (UINT64)_strtoui64(argv[1], NULL, 0);
        printf("[*] Target physical address: 0x%llX\n",
               (unsigned long long)phys_addr);
    }

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\CORMEM ...\n");
    if (!cormem_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Pool info --- */
    demo_pool_info(&ctx);

    /* --- Step 3: Virtual to physical --- */
    demo_virt_to_phys(&ctx);

    /* --- Step 4: I/O port test --- */
    demo_io_ports(&ctx);

    /* --- Step 5: Physical memory mapping --- */
    if (phys_addr != 0) {
        demo_map_physical(&ctx, phys_addr);
        demo_read_phys(&ctx, phys_addr);
    } else {
        printf("\n[*] Mapping page at physical 0x0 (first physical page) ...\n");
        demo_map_physical(&ctx, 0);
    }

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    cormem_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
