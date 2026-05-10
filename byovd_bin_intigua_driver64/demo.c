/*
 * demo.c — Demonstrates all Intigua driver capabilities
 *
 * Usage:  demo.exe <services_pid>
 *
 * Shows:
 *   1. Opening the driver device
 *   2. Patching services.exe IAT (hooking CreateProcess* functions)
 *   3. Querying patch status
 *   4. Unpatching services.exe IAT (restoring originals)
 */

#include "intigua_driver.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

/* ------------------------------------------------------------------ */
/*  Find services.exe PID                                             */
/* ------------------------------------------------------------------ */

static DWORD FindServicesPid(void)
{
    HANDLE          snap;
    PROCESSENTRY32W pe;
    DWORD           pid = 0;

    snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, L"services.exe") == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return pid;
}

/* ------------------------------------------------------------------ */
/*  Main                                                              */
/* ------------------------------------------------------------------ */

int main(int argc, char *argv[])
{
    INTIGUA_DRIVER ctx;
    DWORD          target_pid;

    printf("=== intigua_driver demo ===\n\n");

    if (argc < 2) {
        printf("Usage: %s <services_pid | auto>\n\n", argv[0]);
        printf("  Demonstrates hooking/unhooking the IAT of services.exe\n");
        printf("  via the Intigua kernel driver.\n\n");
        printf("  Pass 'auto' to auto-detect services.exe PID.\n");
        printf("  Run as Administrator (driver access requires elevation).\n");
        return 1;
    }

    if (_stricmp(argv[1], "auto") == 0) {
        target_pid = FindServicesPid();
        if (target_pid == 0) {
            printf("[-] Could not find services.exe\n");
            return 1;
        }
        printf("[+] Auto-detected services.exe PID: %lu\n",
               (unsigned long)target_pid);
    } else {
        target_pid = (DWORD)strtoul(argv[1], NULL, 0);
    }

    /* --- Step 1: Open driver --- */
    printf("[*] Opening \\\\.\\{4cdec755-627a-4141-99e5-76ff636b1282} ...\n");
    if (!intigua_driver_open(&ctx)) {
        printf("[-] Failed to open device (error %lu)\n", ctx.last_error);
        printf("    Is the driver loaded? Run as Administrator?\n");
        return 1;
    }
    printf("[+] Device opened\n");

    /* --- Step 2: Patch services.exe --- */
    printf("\n[*] Patching services.exe (PID %lu) ...\n",
           (unsigned long)target_pid);
    if (!intigua_driver_patch(&ctx, target_pid)) {
        printf("[-] Patch failed (error %lu)\n", ctx.last_error);

        /* Try 2019 variant */
        printf("[*] Trying 2019 variant ...\n");
        if (!intigua_driver_patch_2019(&ctx, target_pid)) {
            printf("[-] Patch 2019 also failed (error %lu)\n",
                   ctx.last_error);
            intigua_driver_close(&ctx);
            return 1;
        }
        printf("[+] Patch 2019 succeeded\n");
    } else {
        printf("[+] Patch succeeded\n");
    }

    /* --- Step 3: Wait for user --- */
    printf("\n[*] Hooks are active.  Press Enter to unpatch ...\n");
    getchar();

    /* --- Step 4: Unpatch --- */
    printf("[*] Unpatching services.exe (PID %lu) ...\n",
           (unsigned long)target_pid);
    if (!intigua_driver_unpatch(&ctx, target_pid)) {
        printf("[-] Unpatch failed (error %lu)\n", ctx.last_error);
    } else {
        printf("[+] Unpatch succeeded — IAT restored\n");
    }

    /* --- Cleanup --- */
    printf("\n[*] Closing device\n");
    intigua_driver_close(&ctx);
    printf("[+] Done\n");

    return 0;
}
