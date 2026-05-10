/*
 * demo.c — Demonstrates GGProtect64 driver capabilities
 *
 * Usage:  demo.exe
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Initializing the driver session (DRIVER_LOAD with auth key)
 *   3. Enabling debug log output
 *   4. Querying SSDT / Shadow SSDT addresses
 *   5. Querying kernel procedure addresses
 *   6. Enabling/disabling process creation monitoring
 *   7. Tearing down the session (DRIVER_UNLOAD)
 */

#include "ggprotect64.h"
#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/*  Demo: SSDT introspection                                          */
/* ------------------------------------------------------------------ */

static void demo_ssdt(GGPROTECT *ctx)
{
    UINT64 addr = 0;
    int    i;

    printf("\n[*] Querying first 8 SSDT entries ...\n");

    for (i = 0; i < 8; i++) {
        if (ggprotect_get_ssdt_addr(ctx, (UINT32)i, &addr)) {
            printf("[+] SSDT[%3d] = 0x%016llX\n",
                   i, (unsigned long long)addr);
        } else {
            printf("[-] SSDT[%3d] failed (error %lu)\n",
                   i, ctx->last_error);
        }
    }

    printf("\n[*] Querying first 4 Shadow SSDT entries ...\n");

    for (i = 0; i < 4; i++) {
        if (ggprotect_get_sssdt_addr(ctx, (UINT32)i, &addr)) {
            printf("[+] SSSDT[%3d] = 0x%016llX\n",
                   i, (unsigned long long)addr);
        } else {
            printf("[-] SSSDT[%3d] failed (error %lu)\n",
                   i, ctx->last_error);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Demo: procedure address lookup                                    */
/* ------------------------------------------------------------------ */

static void demo_procedure(GGPROTECT *ctx)
{
    UINT64 addr = 0;
    int    i;

    printf("\n[*] Querying first 4 procedure addresses ...\n");

    for (i = 0; i < 4; i++) {
        if (ggprotect_get_procedure_addr(ctx, (UINT32)i, &addr)) {
            printf("[+] Procedure[%d] = 0x%016llX\n",
                   i, (unsigned long long)addr);
        } else {
            printf("[-] Procedure[%d] failed (error %lu)\n",
                   i, ctx->last_error);
        }
    }
}

/* ------------------------------------------------------------------ */
/*  Demo: notification enables                                        */
/* ------------------------------------------------------------------ */

static void demo_notifications(GGPROTECT *ctx)
{
    printf("\n[*] Enabling process creation monitoring ...\n");
    if (ggprotect_enable_create_proc(ctx, 1))
        printf("[+] Create-process monitoring enabled\n");
    else
        printf("[-] Failed (error %lu)\n", ctx->last_error);

    printf("[*] Enabling open-process monitoring ...\n");
    if (ggprotect_enable_open_proc(ctx, 1))
        printf("[+] Open-process monitoring enabled\n");
    else
        printf("[-] Failed (error %lu)\n", ctx->last_error);

    printf("[*] Enabling self-protection ...\n");
    if (ggprotect_enable_protect_self(ctx, 1))
        printf("[+] Self-protection enabled\n");
    else
        printf("[-] Failed (error %lu)\n", ctx->last_error);

    printf("\n[*] Disabling all monitors ...\n");
    ggprotect_enable_create_proc(ctx, 0);
    ggprotect_enable_open_proc(ctx, 0);
    ggprotect_enable_protect_self(ctx, 0);
    printf("[+] All monitors disabled\n");
}

/* ------------------------------------------------------------------ */
/*  Demo: OB callback enumeration                                     */
/* ------------------------------------------------------------------ */

static void demo_obcallbacks(GGPROTECT *ctx)
{
    UINT8 buf[0x19 * 16];
    UINT16 count = 16;

    printf("\n[*] Enumerating OB callbacks (max %u) ...\n", count);
    if (ggprotect_get_obcallbacks(ctx, count, buf, sizeof(buf))) {
        printf("[+] OB callback query succeeded\n");
    } else {
        printf("[-] OB callback query failed (error %lu)\n",
               ctx->last_error);
    }
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    GGPROTECT ctx;
    UINT32    key = 0x47475052;   /* "GGPR" — arbitrary init key */

    (void)argc;
    (void)argv;

    printf("=== GGProtect64 driver demo ===\n\n");

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\GGProtect64 ...\n");
    if (!ggprotect_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Initialize session --- */
    printf("\n[*] Sending DRIVER_LOAD (key=0x%08X) ...\n", key);
    if (!ggprotect_driver_load(&ctx, key)) {
        printf("[-] DRIVER_LOAD failed (error %lu)\n", ctx.last_error);
        ggprotect_close(&ctx);
        return 1;
    }
    printf("[+] Session initialized (auth_key=0x%08X)\n", ctx.auth_key);

    /* --- Step 3: Enable debug log --- */
    printf("\n[*] Enabling debug log ...\n");
    if (ggprotect_enable_log(&ctx))
        printf("[+] Debug log enabled\n");
    else
        printf("[-] Failed (error %lu)\n", ctx.last_error);

    /* --- Step 4: SSDT introspection --- */
    demo_ssdt(&ctx);

    /* --- Step 5: Procedure addresses --- */
    demo_procedure(&ctx);

    /* --- Step 6: Notification enables --- */
    demo_notifications(&ctx);

    /* --- Step 7: OB callbacks --- */
    demo_obcallbacks(&ctx);

    /* --- Step 8: Tear down session --- */
    printf("\n[*] Sending DRIVER_UNLOAD (key=0x%08X) ...\n",
           ctx.auth_key);
    if (ggprotect_driver_unload(&ctx, ctx.auth_key))
        printf("[+] Session torn down\n");
    else
        printf("[-] DRIVER_UNLOAD failed (error %lu)\n", ctx.last_error);

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    ggprotect_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
