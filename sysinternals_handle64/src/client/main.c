// ============================================================================
// main.c — procexp_client: CLI for exercising the PROCEXP152 driver
//
// Usage:
//   procexp_client install <path-to-PROCEXP152.sys>
//   procexp_client uninstall
//   procexp_client version
//   procexp_client handles <pid> [-a] [-n <name>]
//   procexp_client close <pid> <handle-hex>
//   procexp_client query <pid> <handle-hex> [--object <ptr-hex>] [--file]
//   procexp_client process <pid>
//   procexp_client thread <thread-handle-hex>
//   procexp_client pool
//   procexp_client enum [-p <pid|name>] [-s] [-a] [name-filter]
//
// All commands except install/uninstall require the driver to be loaded.
// Most require running as Administrator with SeDebugPrivilege.
// ============================================================================

#include <windows.h>
#include <winternl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <io.h>
#include <fcntl.h>
#include "drvclient.h"

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")

// ---------------------------------------------------------------------------
// NtQuerySystemInformation for handle enumeration (user-mode side)
// ---------------------------------------------------------------------------

#define SystemHandleInformation 16

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
    USHORT  UniqueProcessId;
    USHORT  CreatorBackTraceIndex;
    UCHAR   ObjectTypeIndex;
    UCHAR   HandleAttributes;
    USHORT  HandleValue;
    PVOID   Object;
    ULONG   GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION {
    ULONG   NumberOfHandles;
    SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
} SYSTEM_HANDLE_INFORMATION;

typedef NTSTATUS (NTAPI *PFN_NtQuerySystemInformation)(
    ULONG SystemInformationClass,
    PVOID SystemInformation,
    ULONG SystemInformationLength,
    PULONG ReturnLength
);

static PFN_NtQuerySystemInformation pNtQuerySystemInformation = NULL;

static void ResolveNtApis(void)
{
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (hNtdll) {
        pNtQuerySystemInformation = (PFN_NtQuerySystemInformation)
            GetProcAddress(hNtdll, "NtQuerySystemInformation");
    }
}

// ---------------------------------------------------------------------------
// Usage
// ---------------------------------------------------------------------------

static void PrintUsage(void)
{
    wprintf(
        L"procexp_client — PROCEXP152 driver exerciser\n"
        L"\n"
        L"Driver lifecycle:\n"
        L"  install <sys-path>           Install and start the driver\n"
        L"  uninstall                    Stop and remove the driver\n"
        L"\n"
        L"Queries:\n"
        L"  version                      Protocol version handshake\n"
        L"  pool                         Max non-paged pool size\n"
        L"  process <pid>                Process info (priority, token)\n"
        L"  query <pid> <handle-hex>     Query single handle name\n"
        L"       [--object <ptr-hex>]    Expected kernel object pointer\n"
        L"       [--file]                Treat as file object\n"
        L"  close <pid> <handle-hex>     Close a handle in another process\n"
        L"       [--yes]                 Skip confirmation\n"
        L"\n"
        L"Enumeration (uses NtQuerySystemInformation + driver):\n"
        L"  enum                         Enumerate all handles system-wide\n"
        L"       [-p <pid|name>]         Filter by process\n"
        L"       [-a]                    Show all types (default: File+Section)\n"
        L"       [-s]                    Summary mode (type counts only)\n"
        L"       [-n <name>]             Filter by object name substring\n"
        L"       [-t <type>]             Filter by type name (e.g. File, Key)\n"
        L"\n"
        L"Research (see sec-research.md):\n"
        L"  ntinfo                       Show ntoskrnl base address and size\n"
        L"  ntread <addr-hex> [len]      Read kernel memory at addr (must be in ntoskrnl)\n"
        L"  ntdump <outfile>             Dump entire ntoskrnl mapped image to file\n"
        L"  objread <ptr-hex>            Read 8 bytes at kernel object ptr+0x20\n"
        L"                               (ptr must have FILE_OBJECT signature 05 00 D8 00)\n"
        L"\n"
        L"Requires Administrator with SeDebugPrivilege.\n"
    );
}

// ---------------------------------------------------------------------------
// Command: install
// ---------------------------------------------------------------------------

static int CmdInstall(int argc, wchar_t **argv)
{
    if (argc < 1) {
        wprintf(L"Usage: procexp_client install <path-to-PROCEXP152.sys>\n");
        return 1;
    }

    wchar_t fullPath[MAX_PATH];
    if (!GetFullPathNameW(argv[0], MAX_PATH, fullPath, NULL)) {
        PrintError(L"GetFullPathName");
        return 1;
    }

    DWORD attrs = GetFileAttributesW(fullPath);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"File not found: %s\n", fullPath);
        return 1;
    }

    wprintf(L"Installing driver from: %s\n", fullPath);
    if (DrvInstall(fullPath) != 0)
        return 1;

    wprintf(L"Driver installed and started.\n");
    return 0;
}

// ---------------------------------------------------------------------------
// Command: uninstall
// ---------------------------------------------------------------------------

static int CmdUninstall(void)
{
    if (DrvUninstall() != 0) {
        PrintError(L"Uninstall");
        return 1;
    }
    wprintf(L"Driver stopped and removed.\n");
    return 0;
}

// ---------------------------------------------------------------------------
// Command: version
// ---------------------------------------------------------------------------

static int CmdVersion(void)
{
    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        return 1;
    }

    ULONG ver = 0;
    int rc = DrvVersionCheck(hDev, 1, &ver);
    DrvClose(hDev);

    if (rc == 0)
        wprintf(L"Driver protocol version: 0x%X\n", ver);
    else
        PrintError(L"VersionCheck");

    return rc;
}

// ---------------------------------------------------------------------------
// Command: pool
// ---------------------------------------------------------------------------

static int CmdPool(void)
{
    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        return 1;
    }

    SIZE_T pool = 0;
    int rc = DrvGetMaxNonPagedPool(hDev, &pool);
    DrvClose(hDev);

    if (rc == 0)
        wprintf(L"Max non-paged pool: %llu bytes (%.1f MB)\n",
                (unsigned long long)pool, (double)pool / (1024.0 * 1024.0));
    else
        PrintError(L"GetMaxNonPagedPool");

    return rc;
}

// ---------------------------------------------------------------------------
// Command: process <pid>
// ---------------------------------------------------------------------------

static int CmdProcess(int argc, wchar_t **argv)
{
    if (argc < 1) {
        wprintf(L"Usage: procexp_client process <pid>\n");
        return 1;
    }

    ULONG pid = wcstoul(argv[0], NULL, 0);
    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        return 1;
    }

    wprintf(L"Process %u:\n", pid);

    // Open via driver
    HANDLE hProc = NULL;
    if (DrvOpenProcessByPid(hDev, pid, &hProc) == 0 && hProc) {
        wprintf(L"  Kernel handle: 0x%p\n", hProc);

        // I/O priority
        ULONG prio = 0;
        if (DrvQueryProcessPriority(hDev, hProc, &prio) == 0)
            wprintf(L"  I/O priority:  %u\n", prio);
        else
            wprintf(L"  I/O priority:  (failed)\n");

        // Token
        HANDLE hToken = NULL;
        if (DrvOpenProcessToken(hDev, hProc, &hToken) == 0 && hToken)
            wprintf(L"  Token handle:  0x%p\n", hToken);
        else
            wprintf(L"  Token:         (failed)\n");
    } else {
        wprintf(L"  (could not open process)\n");
    }

    DrvClose(hDev);
    return 0;
}

// ---------------------------------------------------------------------------
// Command: query <pid> <handle-hex> [--object <ptr>] [--file]
// ---------------------------------------------------------------------------

static int CmdQuery(int argc, wchar_t **argv)
{
    if (argc < 2) {
        wprintf(L"Usage: procexp_client query <pid> <handle-hex> [--object <ptr-hex>] [--file]\n");
        return 1;
    }

    ULONG pid = wcstoul(argv[0], NULL, 0);
    ULONG_PTR handleVal = wcstoull(argv[1], NULL, 16);
    void *objPtr = NULL;
    BOOL isFile = FALSE;

    for (int i = 2; i < argc; i++) {
        if (wcscmp(argv[i], L"--object") == 0 && i + 1 < argc) {
            objPtr = (void *)wcstoull(argv[++i], NULL, 16);
        } else if (wcscmp(argv[i], L"--file") == 0) {
            isFile = TRUE;
        }
    }

    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        return 1;
    }

    wchar_t nameBuf[2048] = { 0 };
    ULONG flags = 0;
    int rc = DrvQueryHandleName(hDev, pid, (void *)handleVal, objPtr, isFile,
                                nameBuf, 2048, &flags);
    DrvClose(hDev);

    if (rc == 0) {
        wprintf(L"PID %u, Handle 0x%llX:\n", pid, (unsigned long long)handleVal);
        wprintf(L"  Name:  %s\n", nameBuf[0] ? nameBuf : L"(unnamed)");
        wprintf(L"  Flags: 0x%X", flags);
        if (flags & PROCEXP_FLAG_READ_ACCESS)   wprintf(L" [READ]");
        if (flags & PROCEXP_FLAG_WRITE_ACCESS)  wprintf(L" [WRITE]");
        if (flags & PROCEXP_FLAG_DELETE_ACCESS)  wprintf(L" [DELETE]");
        wprintf(L"\n");
    } else {
        PrintError(L"QueryHandleName");
    }

    return rc;
}

// ---------------------------------------------------------------------------
// Command: close <pid> <handle-hex> [--yes]
// ---------------------------------------------------------------------------

static int CmdClose(int argc, wchar_t **argv)
{
    if (argc < 2) {
        wprintf(L"Usage: procexp_client close <pid> <handle-hex> [--yes]\n");
        return 1;
    }

    ULONG pid = wcstoul(argv[0], NULL, 0);
    ULONG_PTR handleVal = wcstoull(argv[1], NULL, 16);
    BOOL autoConfirm = FALSE;

    for (int i = 2; i < argc; i++) {
        if (wcscmp(argv[i], L"--yes") == 0)
            autoConfirm = TRUE;
    }

    if (!autoConfirm) {
        wprintf(L"Close handle 0x%llX in PID %u? (y/n) ",
                (unsigned long long)handleVal, pid);
        int c = getwchar();
        if (c != L'y' && c != L'Y') {
            wprintf(L"Aborted.\n");
            return 0;
        }
    }

    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        return 1;
    }

    int rc = DrvCloseRemoteHandle(hDev, pid, (void *)handleVal, NULL);
    DrvClose(hDev);

    if (rc == 0)
        wprintf(L"Handle closed.\n");
    else
        PrintError(L"CloseRemoteHandle");

    return rc;
}

// ---------------------------------------------------------------------------
// Command: enum [-p <pid|name>] [-a] [-s] [-n <name>] [-t <type>]
//
// Uses NtQuerySystemInformation(SystemHandleInformation) to get all handles,
// then calls the driver for each to resolve names.
// ---------------------------------------------------------------------------

static int CmdEnum(int argc, wchar_t **argv)
{
    ULONG   filterPid     = 0;
    BOOL    filterPidSet  = FALSE;
    BOOL    showAll       = FALSE;
    BOOL    summaryMode   = FALSE;
    const wchar_t *nameFilter = NULL;
    const wchar_t *typeFilter = NULL;

    for (int i = 0; i < argc; i++) {
        if (wcscmp(argv[i], L"-p") == 0 && i + 1 < argc) {
            filterPid = wcstoul(argv[++i], NULL, 0);
            filterPidSet = TRUE;
        } else if (wcscmp(argv[i], L"-a") == 0) {
            showAll = TRUE;
        } else if (wcscmp(argv[i], L"-s") == 0) {
            summaryMode = TRUE;
        } else if (wcscmp(argv[i], L"-n") == 0 && i + 1 < argc) {
            nameFilter = argv[++i];
        } else if (wcscmp(argv[i], L"-t") == 0 && i + 1 < argc) {
            typeFilter = argv[++i];
        }
    }

    if (!pNtQuerySystemInformation) {
        wprintf(L"NtQuerySystemInformation not available.\n");
        return 1;
    }

    // Snapshot all system handles
    ULONG bufSize = 0x100000;
    SYSTEM_HANDLE_INFORMATION *handleInfo = NULL;
    NTSTATUS status;

    for (;;) {
        handleInfo = (SYSTEM_HANDLE_INFORMATION *)malloc(bufSize);
        if (!handleInfo) {
            wprintf(L"Out of memory.\n");
            return 1;
        }
        status = pNtQuerySystemInformation(SystemHandleInformation,
                                           handleInfo, bufSize, NULL);
        if (status == 0xC0000004 /* STATUS_INFO_LENGTH_MISMATCH */) {
            free(handleInfo);
            bufSize *= 2;
            continue;
        }
        break;
    }

    if (status != 0) {
        wprintf(L"NtQuerySystemInformation failed: 0x%08X\n", (unsigned)status);
        free(handleInfo);
        return 1;
    }

    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        free(handleInfo);
        return 1;
    }

    wprintf(L"Total handles in snapshot: %u\n\n", handleInfo->NumberOfHandles);

    ULONG typeCounts[256] = { 0 };
    ULONG matched = 0;
    ULONG errors  = 0;
    USHORT lastPid = 0xFFFF;

    for (ULONG i = 0; i < handleInfo->NumberOfHandles; i++) {
        SYSTEM_HANDLE_TABLE_ENTRY_INFO *entry = &handleInfo->Handles[i];

        if (filterPidSet && entry->UniqueProcessId != (USHORT)filterPid)
            continue;

        if (summaryMode) {
            typeCounts[entry->ObjectTypeIndex]++;
            matched++;
            continue;
        }

        // Query handle name via driver
        wchar_t nameBuf[2048] = { 0 };
        ULONG flags = 0;
        int rc = DrvQueryHandleName(
            hDev,
            entry->UniqueProcessId,
            (void *)(ULONG_PTR)entry->HandleValue,
            entry->Object,
            FALSE,
            nameBuf, 2048, &flags);

        if (rc != 0) {
            errors++;
            continue;
        }

        // Name filter
        if (nameFilter && nameBuf[0]) {
            if (!wcsstr(nameBuf, nameFilter))
                continue;
        }

        // Print handle info
        if (entry->UniqueProcessId != lastPid) {
            wprintf(L"\n--- PID %u ---\n", entry->UniqueProcessId);
            lastPid = entry->UniqueProcessId;
        }

        wchar_t accessStr[8] = L"---";
        if (flags & PROCEXP_FLAG_READ_ACCESS)   accessStr[0] = L'R';
        if (flags & PROCEXP_FLAG_WRITE_ACCESS)  accessStr[1] = L'W';
        if (flags & PROCEXP_FLAG_DELETE_ACCESS)  accessStr[2] = L'D';

        wprintf(L"  0x%04X  type:%3u  %s  %s\n",
                entry->HandleValue,
                (unsigned)entry->ObjectTypeIndex,
                accessStr,
                nameBuf[0] ? nameBuf : L"(unnamed)");
        matched++;
    }

    if (summaryMode) {
        wprintf(L"Handle type summary:\n");
        for (int t = 0; t < 256; t++) {
            if (typeCounts[t] > 0)
                wprintf(L"  Type %3d: %u\n", t, typeCounts[t]);
        }
        wprintf(L"\nTotal: %u handles\n", matched);
    } else {
        wprintf(L"\nMatched: %u, Errors: %u\n", matched, errors);
    }

    DrvClose(hDev);
    free(handleInfo);
    return 0;
}

// ---------------------------------------------------------------------------
// Command: ntinfo — show ntoskrnl base and size
// ---------------------------------------------------------------------------

static int CmdNtInfo(void)
{
    ULONG_PTR base = 0;
    ULONG size = 0;
    char name[256] = { 0 };

    if (GetNtoskrnlInfo(&base, &size, name, sizeof(name)) != 0) {
        wprintf(L"Failed to query ntoskrnl info.\n");
        return 1;
    }

    wprintf(L"ntoskrnl:\n");
    wprintf(L"  Module:  %S\n", name);
    wprintf(L"  Base:    0x%llX\n", (unsigned long long)base);
    wprintf(L"  Size:    0x%X (%u KB)\n", size, size / 1024);
    wprintf(L"  End:     0x%llX\n", (unsigned long long)(base + size));
    return 0;
}

// ---------------------------------------------------------------------------
// Command: ntread <addr-hex> [len] — read kernel memory within ntoskrnl
// ---------------------------------------------------------------------------

static int CmdNtRead(int argc, wchar_t **argv)
{
    if (argc < 1) {
        wprintf(L"Usage: procexp_client ntread <addr-hex> [len]\n");
        return 1;
    }

    ULONG_PTR addr = (ULONG_PTR)wcstoull(argv[0], NULL, 16);
    ULONG len = 0x40;  // default: 64 bytes
    if (argc >= 2)
        len = wcstoul(argv[1], NULL, 0);
    if (len > 0x10000) len = 0x10000;  // cap at 64KB per read

    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        return 1;
    }

    BYTE *buf = (BYTE *)calloc(1, len);
    if (!buf) { DrvClose(hDev); return 1; }

    int rc = DrvReadKernelMemory(hDev, addr, buf, len);
    DrvClose(hDev);

    if (rc != 0) {
        wprintf(L"ReadKernelMemory failed at 0x%llX (len=%u).\n",
                (unsigned long long)addr, len);
        wprintf(L"Address must be within ntoskrnl's mapped image.\n");
        PrintError(L"DeviceIoControl");
        free(buf);
        return 1;
    }

    // Hex dump
    for (ULONG off = 0; off < len; off += 16) {
        wprintf(L"  %llX  ", (unsigned long long)(addr + off));
        for (ULONG j = 0; j < 16 && off + j < len; j++)
            wprintf(L"%02X ", buf[off + j]);
        // Padding
        for (ULONG j = (len - off < 16 ? len - off : 16); j < 16; j++)
            wprintf(L"   ");
        wprintf(L" ");
        for (ULONG j = 0; j < 16 && off + j < len; j++) {
            BYTE c = buf[off + j];
            wprintf(L"%c", (c >= 0x20 && c < 0x7F) ? (wchar_t)c : L'.');
        }
        wprintf(L"\n");
    }

    free(buf);
    return 0;
}

// ---------------------------------------------------------------------------
// Command: ntdump <outfile> — dump entire ntoskrnl mapped image to a file
// ---------------------------------------------------------------------------

static int CmdNtDump(int argc, wchar_t **argv)
{
    if (argc < 1) {
        wprintf(L"Usage: procexp_client ntdump <output-file>\n");
        return 1;
    }

    ULONG_PTR base = 0;
    ULONG size = 0;
    char name[256] = { 0 };

    if (GetNtoskrnlInfo(&base, &size, name, sizeof(name)) != 0) {
        wprintf(L"Failed to query ntoskrnl info.\n");
        return 1;
    }

    wprintf(L"Dumping %S: base=0x%llX, size=0x%X (%u KB)\n",
            name, (unsigned long long)base, size, size / 1024);

    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        return 1;
    }

    FILE *fp = NULL;
    errno_t err = _wfopen_s(&fp, argv[0], L"wb");
    if (err != 0 || !fp) {
        wprintf(L"Cannot open output file: %s\n", argv[0]);
        DrvClose(hDev);
        return 1;
    }

    // Read in 4KB chunks
    ULONG chunkSize = 0x1000;
    BYTE *chunk = (BYTE *)malloc(chunkSize);
    ULONG totalRead = 0;
    ULONG errors = 0;

    for (ULONG offset = 0; offset < size; offset += chunkSize) {
        ULONG thisChunk = chunkSize;
        if (offset + thisChunk > size)
            thisChunk = size - offset;

        int rc = DrvReadKernelMemory(hDev, base + offset, chunk, thisChunk);
        if (rc == 0) {
            fwrite(chunk, 1, thisChunk, fp);
            totalRead += thisChunk;
        } else {
            // Write zeros for unreadable pages
            memset(chunk, 0, thisChunk);
            fwrite(chunk, 1, thisChunk, fp);
            errors++;
        }

        // Progress every 256KB
        if ((offset & 0x3FFFF) == 0) {
            wprintf(L"\r  Progress: %u / %u KB (%u errors)",
                    offset / 1024, size / 1024, errors);
        }
    }

    wprintf(L"\r  Done: %u KB dumped, %u page errors        \n",
            totalRead / 1024, errors);

    free(chunk);
    fclose(fp);
    DrvClose(hDev);

    wprintf(L"Saved to: %s\n", argv[0]);
    return 0;
}

// ---------------------------------------------------------------------------
// Command: objread <ptr-hex> — read 8 bytes via raw object pointer deref
// ---------------------------------------------------------------------------

static int CmdObjRead(int argc, wchar_t **argv)
{
    if (argc < 1) {
        wprintf(L"Usage: procexp_client objread <kernel-ptr-hex>\n"
                L"\n"
                L"Sends the pointer to IOCTL 0x83350020. The driver dereferences it,\n"
                L"checks *(USHORT*)ptr == 5 && *(USHORT*)(ptr+2) == 0xD8 (FILE_OBJECT tag),\n"
                L"then returns 8 bytes from ptr+0x20.\n"
                L"\n"
                L"Use 'enum -p <pid>' to find FILE_OBJECT pointers (the Object column).\n");
        return 1;
    }

    ULONG_PTR ptr = (ULONG_PTR)wcstoull(argv[0], NULL, 16);

    HANDLE hDev = DrvOpen();
    if (hDev == INVALID_HANDLE_VALUE) {
        PrintError(L"Open device");
        return 1;
    }

    ULONG_PTR value = 0;
    int rc = DrvReadObjectField(hDev, ptr, &value);
    DrvClose(hDev);

    if (rc == 0) {
        wprintf(L"Object at 0x%llX:\n", (unsigned long long)ptr);
        wprintf(L"  [ptr+0x20] = 0x%llX\n", (unsigned long long)value);
    } else {
        wprintf(L"Failed. Either the address is invalid or the 4-byte tag\n"
                L"at that address is not [05 00 D8 00] (FILE_OBJECT signature).\n");
    }

    return rc;
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

int wmain(int argc, wchar_t **argv)
{
    _setmode(_fileno(stdout), _O_U16TEXT);
    _setmode(_fileno(stderr), _O_U16TEXT);

    if (argc < 2) {
        PrintUsage();
        return 1;
    }

    ResolveNtApis();
    EnableDebugPrivilege();

    const wchar_t *cmd = argv[1];

    if (_wcsicmp(cmd, L"install") == 0)
        return CmdInstall(argc - 2, argv + 2);

    if (_wcsicmp(cmd, L"uninstall") == 0)
        return CmdUninstall();

    if (_wcsicmp(cmd, L"version") == 0)
        return CmdVersion();

    if (_wcsicmp(cmd, L"pool") == 0)
        return CmdPool();

    if (_wcsicmp(cmd, L"process") == 0)
        return CmdProcess(argc - 2, argv + 2);

    if (_wcsicmp(cmd, L"query") == 0)
        return CmdQuery(argc - 2, argv + 2);

    if (_wcsicmp(cmd, L"close") == 0)
        return CmdClose(argc - 2, argv + 2);

    if (_wcsicmp(cmd, L"enum") == 0)
        return CmdEnum(argc - 2, argv + 2);

    if (_wcsicmp(cmd, L"ntinfo") == 0)
        return CmdNtInfo();

    if (_wcsicmp(cmd, L"ntread") == 0)
        return CmdNtRead(argc - 2, argv + 2);

    if (_wcsicmp(cmd, L"ntdump") == 0)
        return CmdNtDump(argc - 2, argv + 2);

    if (_wcsicmp(cmd, L"objread") == 0)
        return CmdObjRead(argc - 2, argv + 2);

    if (_wcsicmp(cmd, L"help") == 0 || _wcsicmp(cmd, L"--help") == 0 ||
        _wcsicmp(cmd, L"-h") == 0) {
        PrintUsage();
        return 0;
    }

    wprintf(L"Unknown command: %s\n\n", cmd);
    PrintUsage();
    return 1;
}
