/*
 * demo.c — Demonstrates all ImmunetUtilDriver capabilities
 *
 * Usage:  demo.exe [target_pid]
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Querying the driver version string
 *   3. Opening a process handle via the driver
 *   4. Getting handle data for the opened handle
 *   5. Enumerating driver objects
 *   6. Enumerating directory objects
 *   7. Duplicating handles from a remote process
 */

#include "immunetutildriver.h"
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
/*  Demo: query driver version                                        */
/* ------------------------------------------------------------------ */

static BOOL demo_version(IMMUNET *ctx)
{
    WCHAR version[512];

    printf("\n[*] Querying driver version ...\n");
    memset(version, 0, sizeof(version));

    if (!immunet_get_version(ctx, version, sizeof(version))) {
        printf("[-] Failed to get version (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Driver version: %ws\n", version);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: open process handle                                         */
/* ------------------------------------------------------------------ */

static BOOL demo_open_process(IMMUNET *ctx, DWORD pid, HANDLE *hout)
{
    printf("\n[*] Opening process handle for PID %lu ...\n",
           (unsigned long)pid);

    if (!immunet_open_process(ctx, pid, hout)) {
        printf("[-] Failed to open process (error %lu)\n", ctx->last_error);
        return FALSE;
    }

    printf("[+] Process handle: 0x%llX\n",
           (unsigned long long)(ULONG_PTR)*hout);
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: get handle data                                             */
/* ------------------------------------------------------------------ */

static BOOL demo_handle_data(IMMUNET *ctx, HANDLE h)
{
    UCHAR buf[4096];
    DWORD bytes = 0;

    printf("\n[*] Querying handle data for 0x%llX ...\n",
           (unsigned long long)(ULONG_PTR)h);
    memset(buf, 0, sizeof(buf));

    if (!immunet_get_handle_data(ctx, h, buf, sizeof(buf), &bytes)) {
        printf("[-] Failed to get handle data (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }

    printf("[+] Handle data received (%lu bytes)\n",
           (unsigned long)bytes);
    if (bytes > 0) {
        hexdump(buf, bytes < 256 ? bytes : 256, 0);
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: get driver object data                                      */
/* ------------------------------------------------------------------ */

static BOOL demo_driver_data(IMMUNET *ctx, const WCHAR *driver_path)
{
    UCHAR buf[8192];
    DWORD bytes = 0;

    printf("\n[*] Querying driver data for %ws ...\n", driver_path);
    memset(buf, 0, sizeof(buf));

    if (!immunet_get_driver_data(ctx, driver_path,
                                  buf, sizeof(buf), &bytes)) {
        printf("[-] Failed to get driver data (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }

    printf("[+] Driver data received (%lu bytes)\n",
           (unsigned long)bytes);
    if (bytes > 0) {
        hexdump(buf, bytes < 512 ? bytes : 512, 0);
    }
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: enumerate directory objects                                  */
/* ------------------------------------------------------------------ */

static BOOL demo_directory(IMMUNET *ctx, const WCHAR *dir_path)
{
    UINT64 index = 0;
    UCHAR  buf[4096];
    DWORD  bytes = 0;

    printf("\n[*] Opening directory object %ws ...\n", dir_path);

    if (!immunet_open_directory(ctx, dir_path, &index)) {
        printf("[-] Failed to open directory (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }

    printf("[+] Directory opened, context index: %llu\n",
           (unsigned long long)index);

    printf("[*] Querying directory entries ...\n");
    memset(buf, 0, sizeof(buf));

    if (!immunet_query_directory(ctx, (UINT32)index,
                                  buf, sizeof(buf), &bytes)) {
        printf("[-] Failed to query directory (error %lu)\n",
               ctx->last_error);
    } else {
        printf("[+] Directory data (%lu bytes)\n", (unsigned long)bytes);
        if (bytes > 0) {
            hexdump(buf, bytes < 256 ? bytes : 256, 0);
        }
    }

    printf("[*] Closing directory handle ...\n");
    if (!immunet_close_directory(ctx, (UINT32)index)) {
        printf("[-] Failed to close directory (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }
    printf("[+] Directory closed\n");
    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Demo: duplicate handle from remote process                        */
/* ------------------------------------------------------------------ */

static BOOL demo_duplicate(IMMUNET *ctx, DWORD pid, HANDLE process_h)
{
    HANDLE handles[1];

    printf("\n[*] Duplicating process handle from PID %lu ...\n",
           (unsigned long)pid);

    handles[0] = process_h;

    if (!immunet_duplicate_handles(ctx, pid, handles, 1)) {
        printf("[-] Failed to duplicate handle (error %lu)\n",
               ctx->last_error);
        return FALSE;
    }

    printf("[+] Duplicated handle: 0x%llX -> 0x%llX\n",
           (unsigned long long)(ULONG_PTR)process_h,
           (unsigned long long)(ULONG_PTR)handles[0]);

    if (handles[0] != NULL && handles[0] != INVALID_HANDLE_VALUE)
        CloseHandle(handles[0]);

    return TRUE;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    IMMUNET ctx;
    DWORD   target_pid;
    HANDLE  proc_handle = NULL;

    printf("=== ImmunetUtilDriver demo ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <target_pid>\n\n", argv[0]);
        printf("  Demonstrates querying driver version, opening process\n");
        printf("  handles, inspecting handle data, enumerating directory\n");
        printf("  objects, and duplicating handles via the ImmunetUtilDriver\n");
        printf("  kernel driver.\n\n");
        printf("  Run as Administrator (driver access requires elevation).\n");
        return 1;
    }

    target_pid = (DWORD)strtoul(argv[1], NULL, 0);

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\ImmunetUtilDriver0 ...\n");
    if (!immunet_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Get version --- */
    demo_version(&ctx);

    /* --- Step 3: Open process handle --- */
    if (demo_open_process(&ctx, target_pid, &proc_handle)) {
        /* --- Step 4: Get handle data --- */
        demo_handle_data(&ctx, proc_handle);
    }

    /* --- Step 5: Get driver object data --- */
    demo_driver_data(&ctx, L"\\Driver\\ImmunetUtilDriver");

    /* --- Step 6: Enumerate directory objects --- */
    demo_directory(&ctx, L"\\Driver");

    /* --- Step 7: Cleanup --- */
    if (proc_handle != NULL && proc_handle != INVALID_HANDLE_VALUE)
        CloseHandle(proc_handle);

    printf("\n[*] Closing device\n");
    immunet_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
