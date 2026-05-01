#pragma once

// ============================================================================
// drvclient.h — PROCEXP152 driver client library
// Wraps all DeviceIoControl calls into clean C functions.
// ============================================================================

#include "../common/procexp_shared.h"
#include <stdio.h>

// ---------------------------------------------------------------------------
// Driver lifecycle
// ---------------------------------------------------------------------------

// Install and start the driver from a .sys path. Returns 0 on success.
int  DrvInstall(const wchar_t *sysPath);

// Stop and remove the driver service. Returns 0 on success.
int  DrvUninstall(void);

// Open a handle to the device. Returns INVALID_HANDLE_VALUE on failure.
HANDLE DrvOpen(void);

// Close device handle.
void DrvClose(HANDLE hDevice);

// ---------------------------------------------------------------------------
// Driver operations (all return 0 on success, -1 on failure)
// ---------------------------------------------------------------------------

// Version handshake — returns protocol version in *outVersion.
int DrvVersionCheck(HANDLE hDevice, ULONG inVersion, ULONG *outVersion);

// Query the name of a handle in another process (Unicode).
// nameBuf must be at least nameBufChars wchar_t's.
// flags receives PROCEXP_FLAG_* bits (nullable).
int DrvQueryHandleName(HANDLE hDevice, ULONG pid, void *handleValue,
                       void *objectPointer, BOOL isFileObject,
                       wchar_t *nameBuf, ULONG nameBufChars, ULONG *flags);

// Close a handle in another process.
int DrvCloseRemoteHandle(HANDLE hDevice, ULONG pid, void *handleValue,
                         void *objectPointer);

// Open a process by PID — returns kernel handle in *hProcess.
int DrvOpenProcessByPid(HANDLE hDevice, ULONG pid, HANDLE *hProcess);

// Query process I/O priority.
int DrvQueryProcessPriority(HANDLE hDevice, HANDLE hProcess, ULONG *priority);

// Query process token — returns token handle.
int DrvOpenProcessToken(HANDLE hDevice, HANDLE hProcess, HANDLE *hToken);

// Query thread info (start address, TEB).
int DrvQueryThreadInfo(HANDLE hDevice, HANDLE hThread,
                       PROCEXP_THREAD_INFO *info);

// Get maximum non-paged pool size.
int DrvGetMaxNonPagedPool(HANDLE hDevice, SIZE_T *poolSize);

// ---------------------------------------------------------------------------
// Research primitives (see sec-research.md)
// ---------------------------------------------------------------------------

// Read kernel memory within ntoskrnl's mapped image range.
// srcAddr must fall within [ntoskrnl_base, ntoskrnl_base + ntoskrnl_size].
// Returns 0 on success, -1 on failure. buf must be at least len bytes.
int DrvReadKernelMemory(HANDLE hDevice, ULONG_PTR srcAddr, void *buf, ULONG len);

// Read a kernel object field via raw pointer dereference (IOCTL 0x83350020).
// The driver validates *(USHORT*)objPtr == 5 && *(USHORT*)(objPtr+2) == 0xD8,
// then returns 8 bytes from objPtr + 0x20.
// Returns 0 on success, -1 on failure.
int DrvReadObjectField(HANDLE hDevice, ULONG_PTR objPtr, ULONG_PTR *valueOut);

// Get ntoskrnl base address and size via NtQuerySystemInformation(SystemModuleInformation).
// Returns 0 on success.
int GetNtoskrnlInfo(ULONG_PTR *baseOut, ULONG *sizeOut, char *nameOut, ULONG nameMax);

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// Enable SeDebugPrivilege for the current process.
BOOL EnableDebugPrivilege(void);

// Print last error with a prefix message.
void PrintError(const wchar_t *msg);
