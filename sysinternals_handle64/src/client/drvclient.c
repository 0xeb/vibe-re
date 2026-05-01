// ============================================================================
// drvclient.c — PROCEXP152 driver client library implementation
// ============================================================================

#include <windows.h>
#include <winioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include "drvclient.h"

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

void PrintError(const wchar_t *msg)
{
    DWORD err = GetLastError();
    wchar_t *buf = NULL;
    FormatMessageW(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   NULL, err, 0, (LPWSTR)&buf, 0, NULL);
    fwprintf(stderr, L"%s: error %u", msg, err);
    if (buf) {
        fwprintf(stderr, L" — %s", buf);
        LocalFree(buf);
    } else {
        fwprintf(stderr, L"\n");
    }
}

BOOL EnableDebugPrivilege(void)
{
    HANDLE hToken;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return FALSE;

    if (!LookupPrivilegeValueW(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return FALSE;
    }

    tp.PrivilegeCount           = 1;
    tp.Privileges[0].Luid       = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    BOOL ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    DWORD err = GetLastError();
    CloseHandle(hToken);

    return ok && err == ERROR_SUCCESS;
}

// ---------------------------------------------------------------------------
// Driver lifecycle
// ---------------------------------------------------------------------------

int DrvInstall(const wchar_t *sysPath)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM) {
        PrintError(L"OpenSCManager");
        return -1;
    }

    // Try to open existing service first
    SC_HANDLE hSvc = OpenServiceW(hSCM, PROCEXP_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        hSvc = CreateServiceW(
            hSCM, PROCEXP_SERVICE_NAME, PROCEXP_SERVICE_NAME,
            SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER, SERVICE_DEMAND_START,
            SERVICE_ERROR_NORMAL, sysPath, NULL, NULL, NULL, NULL, NULL);
    }

    if (!hSvc) {
        PrintError(L"CreateService");
        CloseServiceHandle(hSCM);
        return -1;
    }

    if (!StartServiceW(hSvc, 0, NULL)) {
        DWORD err = GetLastError();
        if (err != ERROR_SERVICE_ALREADY_RUNNING) {
            PrintError(L"StartService");
            CloseServiceHandle(hSvc);
            CloseServiceHandle(hSCM);
            return -1;
        }
    }

    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return 0;
}

int DrvUninstall(void)
{
    SC_HANDLE hSCM = OpenSCManagerW(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!hSCM)
        return -1;

    SC_HANDLE hSvc = OpenServiceW(hSCM, PROCEXP_SERVICE_NAME, SERVICE_ALL_ACCESS);
    if (!hSvc) {
        CloseServiceHandle(hSCM);
        return -1;
    }

    SERVICE_STATUS ss;
    ControlService(hSvc, SERVICE_CONTROL_STOP, &ss);
    DeleteService(hSvc);
    CloseServiceHandle(hSvc);
    CloseServiceHandle(hSCM);
    return 0;
}

HANDLE DrvOpen(void)
{
    HANDLE h = CreateFileW(PROCEXP_WIN32_DEVICE, GENERIC_READ | GENERIC_WRITE,
                           0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    return h;
}

void DrvClose(HANDLE hDevice)
{
    if (hDevice && hDevice != INVALID_HANDLE_VALUE)
        CloseHandle(hDevice);
}

// ---------------------------------------------------------------------------
// Raw ioctl helper — METHOD_NEITHER requires careful handling
// ---------------------------------------------------------------------------

static int
RawIoctl(HANDLE hDevice, ULONG code,
         void *inBuf, ULONG inSize,
         void *outBuf, ULONG outSize,
         ULONG *bytesReturned)
{
    DWORD ret = 0;
    BOOL ok = DeviceIoControl(hDevice, code,
                              inBuf, inSize, outBuf, outSize,
                              &ret, NULL);
    if (bytesReturned) *bytesReturned = ret;
    return ok ? 0 : -1;
}

// ---------------------------------------------------------------------------
// Driver operations
// ---------------------------------------------------------------------------

int DrvVersionCheck(HANDLE hDevice, ULONG inVersion, ULONG *outVersion)
{
    ULONG out = 0;
    int rc = RawIoctl(hDevice, IOCTL_PROCEXP_VERSION_CHECK,
                      &inVersion, sizeof(inVersion),
                      &out, sizeof(out), NULL);
    if (outVersion) *outVersion = out;
    return rc;
}

int DrvQueryHandleName(HANDLE hDevice, ULONG pid, void *handleValue,
                       void *objectPointer, BOOL isFileObject,
                       wchar_t *nameBuf, ULONG nameBufChars, ULONG *flags)
{
    PROCEXP_HANDLE_REQUEST req = { 0 };
    req.ProcessId       = pid;
    req.HandleValue     = handleValue;
    req.ObjectPointer   = objectPointer;
    req.FileObjectFlags = isFileObject ? 1 : 0;

    ULONG outSize = (ULONG)(sizeof(ULONG) + nameBufChars * sizeof(wchar_t));
    BYTE *outBuf = (BYTE *)calloc(1, (size_t)outSize);
    if (!outBuf) return -1;

    ULONG returned = 0;
    int rc = RawIoctl(hDevice, IOCTL_PROCEXP_QUERY_OBJECT_NAME_UNICODE,
                      &req, sizeof(req), outBuf, outSize, &returned);

    if (rc == 0 && returned >= sizeof(ULONG)) {
        PPROCEXP_NAME_RESULT result = (PPROCEXP_NAME_RESULT)outBuf;
        if (flags) *flags = result->Flags;
        wcsncpy_s(nameBuf, nameBufChars, result->UnicodeName, _TRUNCATE);
    } else {
        nameBuf[0] = L'\0';
        if (flags) *flags = 0;
    }

    free(outBuf);
    return rc;
}

int DrvCloseRemoteHandle(HANDLE hDevice, ULONG pid, void *handleValue,
                         void *objectPointer)
{
    PROCEXP_HANDLE_REQUEST req = { 0 };
    req.ProcessId     = pid;
    req.HandleValue   = handleValue;
    req.ObjectPointer = objectPointer;

    return RawIoctl(hDevice, IOCTL_PROCEXP_CLOSE_HANDLE,
                    &req, sizeof(req), NULL, 0, NULL);
}

int DrvOpenProcessByPid(HANDLE hDevice, ULONG pid, HANDLE *hProcess)
{
    ULONGLONG pidVal = pid;
    HANDLE out = NULL;
    int rc = RawIoctl(hDevice, IOCTL_PROCEXP_OPEN_PROCESS_BY_PID,
                      &pidVal, sizeof(pidVal), &out, sizeof(out), NULL);
    if (hProcess) *hProcess = out;
    return rc;
}

int DrvQueryProcessPriority(HANDLE hDevice, HANDLE hProcess, ULONG *priority)
{
    ULONG out = 0;
    int rc = RawIoctl(hDevice, IOCTL_PROCEXP_QUERY_PROCESS_PRIORITY,
                      &hProcess, sizeof(hProcess), &out, sizeof(out), NULL);
    if (priority) *priority = out;
    return rc;
}

int DrvOpenProcessToken(HANDLE hDevice, HANDLE hProcess, HANDLE *hToken)
{
    HANDLE out = NULL;
    int rc = RawIoctl(hDevice, IOCTL_PROCEXP_OPEN_PROCESS_TOKEN,
                      &hProcess, sizeof(hProcess), &out, sizeof(out), NULL);
    if (hToken) *hToken = out;
    return rc;
}

int DrvQueryThreadInfo(HANDLE hDevice, HANDLE hThread,
                       PROCEXP_THREAD_INFO *info)
{
    return RawIoctl(hDevice, IOCTL_PROCEXP_QUERY_THREAD_INFO,
                    &hThread, sizeof(hThread),
                    info, sizeof(PROCEXP_THREAD_INFO), NULL);
}

int DrvGetMaxNonPagedPool(HANDLE hDevice, SIZE_T *poolSize)
{
    SIZE_T out = 0;
    int rc = RawIoctl(hDevice, IOCTL_PROCEXP_GET_MAX_NONPAGED_POOL,
                      NULL, 0, &out, sizeof(out), NULL);
    if (poolSize) *poolSize = out;
    return rc;
}

// ---------------------------------------------------------------------------
// Research primitives
// ---------------------------------------------------------------------------

int DrvReadKernelMemory(HANDLE hDevice, ULONG_PTR srcAddr, void *buf, ULONG len)
{
    return RawIoctl(hDevice, IOCTL_PROCEXP_READ_KERNEL_MEMORY,
                    &srcAddr, sizeof(srcAddr), buf, len, NULL);
}

int DrvReadObjectField(HANDLE hDevice, ULONG_PTR objPtr, ULONG_PTR *valueOut)
{
    ULONG_PTR out = 0;
    int rc = RawIoctl(hDevice, IOCTL_PROCEXP_READ_EPROCESS_FIELD,
                      &objPtr, sizeof(objPtr), &out, sizeof(out), NULL);
    if (valueOut) *valueOut = out;
    return rc;
}

// SystemModuleInformation structures (not in standard user-mode headers)
typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    UCHAR   FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES;

typedef LONG (NTAPI *PFN_NtQSI)(ULONG, PVOID, ULONG, PULONG);

int GetNtoskrnlInfo(ULONG_PTR *baseOut, ULONG *sizeOut, char *nameOut, ULONG nameMax)
{
    PFN_NtQSI pNtQSI;
    ULONG bufSize = 0x10000;
    RTL_PROCESS_MODULES *mods = NULL;
    LONG status;
    ULONG off;

    pNtQSI = (PFN_NtQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),
                                         "NtQuerySystemInformation");
    if (!pNtQSI) return -1;

    for (;;) {
        mods = (RTL_PROCESS_MODULES *)malloc(bufSize);
        if (!mods) return -1;
        status = pNtQSI(11 /* SystemModuleInformation */, mods, bufSize, &bufSize);
        if (status == (LONG)0xC0000004) {
            free(mods);
            bufSize *= 2;
            continue;
        }
        break;
    }

    if (status != 0 || mods->NumberOfModules == 0) {
        free(mods);
        return -1;
    }

    /* First module is always ntoskrnl */
    if (baseOut) *baseOut = (ULONG_PTR)mods->Modules[0].ImageBase;
    if (sizeOut) *sizeOut = mods->Modules[0].ImageSize;
    if (nameOut && nameMax > 0) {
        off = mods->Modules[0].OffsetToFileName;
        strncpy_s(nameOut, nameMax,
                  (char *)mods->Modules[0].FullPathName + off,
                  _TRUNCATE);
    }

    free(mods);
    return 0;
}
