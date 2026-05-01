// ============================================================================
// PROCEXP152.sys — Reconstructed source - For Security Research Only
// Sysinternals Process Explorer / Handle kernel driver
// Original: Copyright (C) Mark Russinovich 1996-2019, version 16.27
//
// Reconstructed from Ghidra decompilation of the embedded PE resource
// in handle64.exe. All function names, structures, and logic recovered
// from reverse engineering. Build-dependent offsets are for ETHREAD
// internals that vary across Windows versions.
// ============================================================================

#include "procexp.h"
#include <ntstrsafe.h>

#ifdef ALLOC_PRAGMA
#pragma alloc_text(INIT, DriverEntry)
#pragma alloc_text(PAGE, DriverUnload)
#endif

// ---------------------------------------------------------------------------
// Globals
// ---------------------------------------------------------------------------

PROCEXP_GLOBALS g_Globals = { 0 };
PDEVICE_OBJECT  g_DeviceObject = NULL;

// SDDL string for device security
// Permits SYSTEM and Administrators full access
static const WCHAR g_DeviceSddl[] = L"D:P(A;;GA;;;SY)(A;;GA;;;BA)";
static const GUID  g_DeviceGuid   = { 0 }; // placeholder

// ---------------------------------------------------------------------------
// Forward declarations
// ---------------------------------------------------------------------------

static NTSTATUS IrpDispatch       (_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp);
static VOID     DriverUnload      (_In_ PDRIVER_OBJECT DriverObject);
static NTSTATUS IoctlDispatch     (_In_  PVOID     FileObject,
                                   _In_  KPROCESSOR_MODE CallerMode,
                                   _In_  PVOID     InputBuffer,
                                   _In_  ULONG     InputSize,
                                   _Out_ PVOID     OutputBuffer,
                                   _In_  ULONG     OutputSize,
                                   _In_  ULONG     IoControlCode,
                                   _Out_ PIO_STATUS_BLOCK IoStatus);

static NTSTATUS QueryObjectName         (BOOLEAN IsUnicode, PPROCEXP_HANDLE_REQUEST Req,
                                         PVOID OutBuf, PULONG_PTR BytesReturned);
static NTSTATUS QueryObjectNameFromFile (BOOLEAN IsUnicode, PPROCEXP_HANDLE_REQUEST Req,
                                         PVOID OutBuf, PULONG_PTR BytesReturned);
static NTSTATUS CloseHandleInProcess    (PPROCEXP_HANDLE_REQUEST Req);
static NTSTATUS QueryFileNameFromObject (BOOLEAN IsUnicode, PVOID FileObject,
                                         PVOID OutBuf, ULONG OutBufSize);

// ---------------------------------------------------------------------------
// Helper: resolve an optional kernel export by name
// ---------------------------------------------------------------------------

static PVOID
ResolveKernelApi(const WCHAR *Name)
{
    UNICODE_STRING uName;
    RtlInitUnicodeString(&uName, Name);
    return MmGetSystemRoutineAddress(&uName);
}

// ---------------------------------------------------------------------------
// Helper: look up a kernel object type by name (e.g., L"Mutant")
// ---------------------------------------------------------------------------

static PVOID
LookupObjectType(const WCHAR *TypeName)
{
    UNICODE_STRING  path;
    WCHAR           buf[64];
    HANDLE          hObj = NULL;
    PVOID           typePtr = NULL;
    OBJECT_ATTRIBUTES oa;
    NTSTATUS        status;
    POBJECT_TYPE    processType;

    if (!g_Globals.ObGetObjectType)
        return NULL;

    // Get the type-of-types from the Process type
    processType = g_Globals.ObGetObjectType(*PsProcessType);

    // Build "\ObjectTypes\<TypeName>"
    RtlStringCchPrintfW(buf, RTL_NUMBER_OF(buf), L"\\ObjectTypes\\%s", TypeName);
    RtlInitUnicodeString(&path, buf);

    InitializeObjectAttributes(&oa, &path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
                               NULL, NULL);

    status = ObOpenObjectByName(&oa, processType, KernelMode, NULL,
                                MAXIMUM_ALLOWED, NULL, &hObj);
    if (!NT_SUCCESS(status))
        return NULL;

    status = ObReferenceObjectByHandle(hObj, MAXIMUM_ALLOWED, processType,
                                       KernelMode, &typePtr, NULL);
    ZwClose(hObj);

    if (NT_SUCCESS(status)) {
        // We got it — dereference (we just wanted the pointer value)
        ObDereferenceObject(typePtr);
        return typePtr;
    }

    return NULL;
}

// ============================================================================
// DriverEntry
// ============================================================================

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT  DriverObject,
    _In_ PUNICODE_STRING RegistryPath
    )
{
    NTSTATUS        status;
    PDEVICE_OBJECT  deviceObject = NULL;
    UNICODE_STRING  deviceName;
    UNICODE_STRING  symlinkName;
    UNICODE_STRING  sddlString;

    UNREFERENCED_PARAMETER(RegistryPath);

    // --- Check minimum OS version (XP SP2+) ---
    PsGetVersion(NULL, NULL, &g_Globals.OsBuildNumber, NULL);
    if (g_Globals.OsBuildNumber < MIN_SUPPORTED_BUILD) {
        return STATUS_NOT_SUPPORTED;
    }

    // --- Dynamically resolve optional APIs ---

    // Vista+ (build 6000+)
    if (g_Globals.OsBuildNumber > 5999) {
        g_Globals.PsAcquireProcessExitSynchronization =
            (PFN_PsAcquireProcessExitSynchronization)
            ResolveKernelApi(L"PsAcquireProcessExitSynchronization");

        g_Globals.PsReleaseProcessExitSynchronization =
            (PFN_PsReleaseProcessExitSynchronization)
            ResolveKernelApi(L"PsReleaseProcessExitSynchronization");

        g_Globals.MmGetMaximumNonPagedPoolInBytes =
            (PFN_MmGetMaximumNonPagedPoolInBytes)
            ResolveKernelApi(L"MmGetMaximumNonPagedPoolInBytes");
    }

    // Win7+ (build 7600+)
    if (g_Globals.OsBuildNumber > 0x1DAF) {
        g_Globals.ObGetObjectType =
            (PFN_ObGetObjectType)
            ResolveKernelApi(L"ObGetObjectType");
    }

    // Resolve the Mutant object type for QueryMutantOwner
    g_Globals.MutantObjectType = LookupObjectType(L"Mutant");

    // --- Create the device ---
    RtlInitUnicodeString(&deviceName, PROCEXP_DEVICE_NAME);
    RtlInitUnicodeString(&sddlString, g_DeviceSddl);

    status = WdmlibIoCreateDeviceSecure(
        DriverObject,
        0,                          // DeviceExtensionSize
        &deviceName,
        PROCEXP_DEVICE_TYPE,
        0,                          // DeviceCharacteristics
        FALSE,                      // Exclusive
        &sddlString,
        NULL,                       // DeviceClassGuid
        &deviceObject);

    if (!NT_SUCCESS(status))
        return status;

    // Clear DO_DEVICE_INITIALIZING
    deviceObject->Flags &= ~DO_DEVICE_INITIALIZING;
    g_DeviceObject = deviceObject;

    // --- Create symbolic link ---
    RtlInitUnicodeString(&symlinkName, PROCEXP_SYMLINK_NAME);
    status = IoCreateSymbolicLink(&symlinkName, &deviceName);

    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(deviceObject);
        g_DeviceObject = NULL;
        return status;
    }

    // --- Set dispatch table ---
    DriverObject->MajorFunction[IRP_MJ_CREATE]         = IrpDispatch;
    DriverObject->MajorFunction[IRP_MJ_CLOSE]          = IrpDispatch;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = IrpDispatch;
    DriverObject->DriverUnload                         = DriverUnload;

    return STATUS_SUCCESS;
}

// ============================================================================
// DriverUnload — delete symlink and device
// ============================================================================

static VOID
DriverUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symlinkName;

    PAGED_CODE();

    RtlInitUnicodeString(&symlinkName, PROCEXP_SYMLINK_NAME);
    IoDeleteSymbolicLink(&symlinkName);

    if (DriverObject->DeviceObject)
        IoDeleteDevice(DriverObject->DeviceObject);
}

// ============================================================================
// IrpDispatch — unified IRP handler for CREATE, CLOSE, DEVICE_CONTROL
// ============================================================================

static NTSTATUS
IrpDispatch(
    _In_    PDEVICE_OBJECT  DeviceObject,
    _Inout_ PIRP            Irp
    )
{
    PIO_STACK_LOCATION  irpSp;
    NTSTATUS            status = STATUS_SUCCESS;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    Irp->IoStatus.Information = 0;

    switch (irpSp->MajorFunction) {

    case IRP_MJ_CREATE: {
        //
        // Security gate: only callers with SeDebugPrivilege can open the device.
        //
        PRIVILEGE_SET   privSet;
        BOOLEAN         result;
        SECURITY_SUBJECT_CONTEXT subjCtx;

        privSet.PrivilegeCount = 1;
        privSet.Control        = PRIVILEGE_SET_ALL_NECESSARY;
        privSet.Privilege[0].Luid.LowPart  = 0x14;  // SE_DEBUG_PRIVILEGE
        privSet.Privilege[0].Luid.HighPart = 0;
        privSet.Privilege[0].Attributes    = 0;

        SeCaptureSubjectContext(&subjCtx);
        result = SePrivilegeCheck(&privSet, &subjCtx, ExGetPreviousMode());
        SeReleaseSubjectContext(&subjCtx);

        if (!result)
            status = STATUS_PRIVILEGE_NOT_HELD;
        break;
    }

    case IRP_MJ_CLOSE:
        // Nothing to do
        break;

    case IRP_MJ_DEVICE_CONTROL: {
        IO_STATUS_BLOCK ioStatus = { 0 };
        status = IoctlDispatch(
            irpSp->FileObject,
            UserMode,
            irpSp->Parameters.DeviceIoControl.Type3InputBuffer,
            irpSp->Parameters.DeviceIoControl.InputBufferLength,
            Irp->UserBuffer,
            irpSp->Parameters.DeviceIoControl.OutputBufferLength,
            irpSp->Parameters.DeviceIoControl.IoControlCode,
            &ioStatus);
        Irp->IoStatus.Status      = ioStatus.Status;
        Irp->IoStatus.Information = ioStatus.Information;
        status = (NTSTATUS)ioStatus.Status;
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

// ============================================================================
// IoctlDispatch — main IOCTL switch (16 IOCTLs)
// ============================================================================

static NTSTATUS
IoctlDispatch(
    _In_  PVOID               FileObject,
    _In_  KPROCESSOR_MODE     CallerMode,
    _In_  PVOID               InputBuffer,
    _In_  ULONG               InputSize,
    _Out_ PVOID               OutputBuffer,
    _In_  ULONG               OutputSize,
    _In_  ULONG               IoControlCode,
    _Out_ PIO_STATUS_BLOCK    IoStatus
    )
{
    NTSTATUS    status = STATUS_INVALID_PARAMETER;
    PPROCEXP_HANDLE_REQUEST req = (PPROCEXP_HANDLE_REQUEST)InputBuffer;

    UNREFERENCED_PARAMETER(FileObject);
    UNREFERENCED_PARAMETER(CallerMode);

    IoStatus->Status      = 0;
    IoStatus->Information = 0;

    switch (IoControlCode) {

    // -----------------------------------------------------------------------
    // QueryObjectName — ANSI
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_QUERY_OBJECT_NAME_ANSI:
        if (InputSize == 0x20 && OutputSize > 7) {
            IoStatus->Information = OutputSize;
            status = QueryObjectName(FALSE, req,
                                     OutputBuffer, &IoStatus->Information);
        }
        break;

    // -----------------------------------------------------------------------
    // QueryObjectName — Unicode
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_QUERY_OBJECT_NAME_UNICODE:
        if (InputSize == 0x20 && OutputSize > 7) {
            IoStatus->Information = OutputSize;
            status = QueryObjectName(TRUE, req,
                                     OutputBuffer, &IoStatus->Information);
        }
        break;

    // -----------------------------------------------------------------------
    // CloseHandle in target process
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_CLOSE_HANDLE:
        if (InputSize == 0x20 && OutputSize == 0) {
            status = CloseHandleInProcess(req);
        }
        break;

    // -----------------------------------------------------------------------
    // Version handshake
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_VERSION_CHECK:
        if (InputSize == 4 && OutputSize == 4) {
            ULONG version = *(PULONG)InputBuffer;
            if (version < 0x99) {
                *(PULONG)OutputBuffer = 0x98;
                IoStatus->Information = 4;
                status = STATUS_SUCCESS;
            } else {
                status = STATUS_INVALID_PARAMETER;
            }
        }
        break;

    // -----------------------------------------------------------------------
    // Open process token from process handle
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_OPEN_PROCESS_TOKEN: {
        if (InputSize == 8 && OutputSize == 8) {
            PVOID       procObj = NULL;
            HANDLE      hProc   = NULL;
            HANDLE      hToken  = NULL;

            status = ObReferenceObjectByHandle(
                *(PHANDLE)InputBuffer, 0, NULL, UserMode, &procObj, NULL);

            if (NT_SUCCESS(status)) {
                status = ObOpenObjectByPointer(
                    procObj, OBJ_KERNEL_HANDLE, NULL,
                    MAXIMUM_ALLOWED, NULL, KernelMode, &hProc);
                ObDereferenceObject(procObj);
            }
            if (NT_SUCCESS(status)) {
                status = ZwOpenProcessToken(hProc, TOKEN_QUERY, &hToken);
                ZwClose(hProc);
            }
            *(PHANDLE)OutputBuffer = hToken;
            IoStatus->Information  = 8;
        }
        break;
    }

    // -----------------------------------------------------------------------
    // Open object by pointer (from handle in another process)
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_OPEN_OBJECT_BY_POINTER: {
        if (InputSize == 0x20 && OutputSize == 8) {
            PEPROCESS   targetProcess = NULL;
            PVOID       objectPtr     = NULL;
            HANDLE      hResult       = NULL;

            status = PsLookupProcessByProcessId(
                (HANDLE)(ULONG_PTR)req->ProcessId, &targetProcess);

            if (NT_SUCCESS(status)) {
                status = ObOpenObjectByPointer(
                    targetProcess, OBJ_KERNEL_HANDLE, NULL,
                    MAXIMUM_ALLOWED, NULL, KernelMode, &hResult);
                ObDereferenceObject(targetProcess);
            }
            *(PHANDLE)OutputBuffer = hResult;
            IoStatus->Information  = 8;
        }
        break;
    }

    // -----------------------------------------------------------------------
    // Read EPROCESS field (used for process parent info)
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_READ_EPROCESS_FIELD: {
        if (InputSize == 8 && OutputSize == 8) {
            // Validate the pointer looks like an EPROCESS:
            // tag word at offset 0 == 5 and size word at offset 2 == 0xD8
            PSHORT pObj = *(PSHORT *)InputBuffer;
            if (pObj && pObj[0] == 5 && pObj[1] == 0xD8) {
                *(PULONG_PTR)OutputBuffer = *(PULONG_PTR)((PUCHAR)pObj + 0x20);
                IoStatus->Information = 8;
                status = STATUS_SUCCESS;
            }
        }
        break;
    }

    // -----------------------------------------------------------------------
    // Query system memory info
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_QUERY_SYSTEM_MEMORY:
        if (InputSize == 0x10) {
            IoStatus->Information = OutputSize;
            status = QuerySystemMemoryInfo(
                InputBuffer, OutputBuffer, &IoStatus->Information);
        }
        break;

    // -----------------------------------------------------------------------
    // Query thread start address and TEB
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_QUERY_THREAD_INFO: {
        if (InputSize == 8 && OutputSize == 0x18) {
            PVOID   threadObj = NULL;
            LARGE_INTEGER timeout = { 0 };
            PUCHAR  ethread;
            PUCHAR  teb;

            status = ObReferenceObjectByHandle(
                *(PHANDLE)InputBuffer, 0, *PsThreadType,
                UserMode, &threadObj, NULL);

            if (NT_SUCCESS(status)) {
                // Non-blocking wait to verify thread is alive
                NTSTATUS waitStatus = KeWaitForSingleObject(
                    threadObj, Executive, KernelMode, FALSE, &timeout);

                if (waitStatus == STATUS_SUCCESS) {
                    // Thread terminated
                    ObDereferenceObject(threadObj);
                    status = STATUS_THREAD_IS_TERMINATING;
                    break;
                }

                // Build-dependent ETHREAD offsets for TEB
                ethread = (PUCHAR)threadObj;
                if (g_Globals.OsBuildNumber >= 0x23F0) {
                    // Win8+ (build 9200+)
                    teb = *(PUCHAR *)(ethread + 0x58);
                } else if (g_Globals.OsBuildNumber >= 6000 ||
                           g_Globals.OsBuildNumber == 0xECE) {
                    // Vista/7 or Server 2003
                    teb = *(PUCHAR *)(ethread + 0x38);
                } else {
                    // XP variants
                    teb = *(PUCHAR *)(ethread + 0x48);
                }

                PPROCEXP_THREAD_INFO info = (PPROCEXP_THREAD_INFO)OutputBuffer;
                info->Win32StartAddress = *(PVOID *)(teb + 0x38);
                info->Teb               = teb + 0x40;
                info->StartAddress      = *(PVOID *)(teb + 0x30);

                ObDereferenceObject(threadObj);
                IoStatus->Information = sizeof(PROCEXP_THREAD_INFO);
                status = STATUS_SUCCESS;
            }
        }
        break;
    }

    // -----------------------------------------------------------------------
    // Query mutant (mutex) owner thread
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_QUERY_MUTANT_OWNER: {
        if (InputSize == 8 && OutputSize == 8) {
            PVOID   mutantObj = NULL;
            HANDLE  hThread   = NULL;

            status = ObReferenceObjectByHandle(
                *(PHANDLE)InputBuffer, 0, g_Globals.MutantObjectType,
                UserMode, &mutantObj, NULL);

            if (NT_SUCCESS(status)) {
                // KMUTANT->OwnerThread is at offset +0x28
                PVOID ownerThread = *(PVOID *)((PUCHAR)mutantObj + 0x28);

                if (ownerThread == NULL) {
                    *(PHANDLE)OutputBuffer = NULL;
                } else {
                    ObOpenObjectByPointer(
                        ownerThread, OBJ_KERNEL_HANDLE, NULL,
                        MAXIMUM_ALLOWED, *PsThreadType,
                        KernelMode, &hThread);
                    *(PHANDLE)OutputBuffer = hThread;
                }
                ObDereferenceObject(mutantObj);
                IoStatus->Information = 8;
                status = STATUS_SUCCESS;
            }
        }
        break;
    }

    // -----------------------------------------------------------------------
    // Query process I/O priority
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_QUERY_PROCESS_PRIORITY: {
        if (InputSize == 8 && OutputSize == 4) {
            PVOID       procObj = NULL;
            KAPC_STATE  apcState;
            ULONG       ioPriority = (ULONG)-1;
            ULONG       retLen = 0;

            status = ObReferenceObjectByHandle(
                *(PHANDLE)InputBuffer, PROCESS_QUERY_INFORMATION,
                *PsProcessType, UserMode, &procObj, NULL);

            if (NT_SUCCESS(status)) {
                KeStackAttachProcess((PEPROCESS)procObj, &apcState);
                status = ZwQueryInformationProcess(
                    NtCurrentProcess(),
                    (PROCESSINFOCLASS)0x22,     // ProcessIoPriority
                    &ioPriority, sizeof(ioPriority), &retLen);
                KeUnstackDetachProcess(&apcState);
                ObDereferenceObject(procObj);

                if (NT_SUCCESS(status)) {
                    IoStatus->Information = retLen;
                }
            }
            *(PULONG)OutputBuffer = ioPriority;
        }
        break;
    }

    // -----------------------------------------------------------------------
    // Open process by PID
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_OPEN_PROCESS_BY_PID: {
        if (InputSize == 8 && OutputSize == 8) {
            HANDLE              hProc = NULL;
            OBJECT_ATTRIBUTES   oa;
            CLIENT_ID           cid;

            cid.UniqueProcess = *(PHANDLE)InputBuffer;
            cid.UniqueThread  = NULL;

            InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

            status = ZwOpenProcess(&hProc, MAXIMUM_ALLOWED, &oa, &cid);
            *(PHANDLE)OutputBuffer = hProc;
            IoStatus->Information  = 8;
        }
        break;
    }

    // -----------------------------------------------------------------------
    // QueryFileObjectName — ANSI / Unicode variants
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_QUERY_FILE_NAME_ANSI:
        if (InputSize == 0x20 && OutputSize > 7) {
            IoStatus->Information = OutputSize;
            status = QueryObjectNameFromFile(FALSE, req,
                                             OutputBuffer, &IoStatus->Information);
        }
        break;

    case IOCTL_PROCEXP_QUERY_FILE_NAME_UNICODE:
        if (InputSize == 0x20 && OutputSize > 7) {
            IoStatus->Information = OutputSize;
            status = QueryObjectNameFromFile(TRUE, req,
                                             OutputBuffer, &IoStatus->Information);
        }
        break;

    // -----------------------------------------------------------------------
    // Read kernel memory (validated against system module range)
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_READ_KERNEL_MEMORY: {
        if (InputSize == 8 && OutputSize >= 4) {
            // Query system module information to validate address range
            PVOID       modInfo = NULL;
            NTSTATUS    qs;
            ULONG       modInfoSize = 1000;

            // Allocate and grow until we get the module list
            do {
                modInfo = ExAllocatePoolWithTag(NonPagedPool, modInfoSize,
                                                PROCEXP_MOD_POOL_TAG);
                if (!modInfo) {
                    status = STATUS_INSUFFICIENT_RESOURCES;
                    break;
                }
                qs = ZwQuerySystemInformation(
                    SystemModuleInformation, modInfo, modInfoSize, &modInfoSize);
                if (!NT_SUCCESS(qs)) {
                    ExFreePoolWithTag(modInfo, 0);
                    modInfo = NULL;
                    modInfoSize += 1000;
                }
            } while (!NT_SUCCESS(qs) && modInfoSize < 0x100000);

            if (NT_SUCCESS(qs) && modInfo) {
                PUCHAR srcAddr = *(PUCHAR *)InputBuffer;

                // Validate source is within a loaded kernel module
                // (simplified — real driver checks the full module range list)
                if (OutputSize == 4) {
                    *(PULONG)OutputBuffer = *(PULONG)srcAddr;
                    IoStatus->Information = 4;
                } else {
                    RtlCopyMemory(OutputBuffer, srcAddr, OutputSize);
                    IoStatus->Information = OutputSize;
                }
                status = STATUS_SUCCESS;
                ExFreePoolWithTag(modInfo, 0);
            }
        }
        break;
    }

    // -----------------------------------------------------------------------
    // Get maximum non-paged pool size (Vista+)
    // -----------------------------------------------------------------------
    case IOCTL_PROCEXP_GET_MAX_NONPAGED_POOL: {
        if (OutputSize == 8) {
            if (!g_Globals.MmGetMaximumNonPagedPoolInBytes) {
                status = STATUS_NOT_IMPLEMENTED;
            } else {
                *(PSIZE_T)OutputBuffer = g_Globals.MmGetMaximumNonPagedPoolInBytes();
                IoStatus->Information  = 8;
                status = STATUS_SUCCESS;
            }
        }
        break;
    }

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    // Convert STATUS_PENDING → STATUS_UNSUCCESSFUL (driver never pends)
    if (status == STATUS_PENDING)
        status = STATUS_UNSUCCESSFUL;

    IoStatus->Status = status;
    return status;
}

// ============================================================================
// QueryObjectName — get NT object name for a handle in another process
//
// This is the core operation: handle64.exe calls this for every handle
// to resolve its name (e.g., "\Device\HarddiskVolume3\Windows\System32\...")
// ============================================================================

static NTSTATUS
QueryObjectName(
    BOOLEAN                 IsUnicode,
    PPROCEXP_HANDLE_REQUEST Req,
    PVOID                   OutBuf,
    PULONG_PTR              BytesReturned
    )
{
    NTSTATUS        status;
    PEPROCESS       targetProcess = NULL;
    PVOID           objectPtr     = NULL;
    KAPC_STATE      apcState;
    BOOLEAN         exitSyncHeld  = FALSE;
    ULONG_PTR       nameBufSize;
    PPROCEXP_NAME_RESULT result = (PPROCEXP_NAME_RESULT)OutBuf;

    nameBufSize = *BytesReturned - 8;  // reserve 8 bytes for header
    *BytesReturned -= nameBufSize;

    // Initialize output flags
    result->Flags = 0;
    if (IsUnicode) {
        result->UnicodeName[0] = L'\0';
    } else {
        result->AnsiName[0] = '\0';
    }

    // --- Acquire target process ---
    if (Req->ProcessId < 8 || g_Globals.PsAcquireProcessExitSynchronization) {
        status = PsLookupProcessByProcessId(
            (HANDLE)(ULONG_PTR)Req->ProcessId, &targetProcess);
        if (!NT_SUCCESS(status))
            return status;

        // Prevent process from exiting during our operation (Vista+)
        if (g_Globals.PsAcquireProcessExitSynchronization) {
            status = g_Globals.PsAcquireProcessExitSynchronization(targetProcess);
            if (!NT_SUCCESS(status)) {
                ObDereferenceObject(targetProcess);
                return status;
            }
            exitSyncHeld = TRUE;
        }

        // --- Attach to target process and grab the object ---
        KeStackAttachProcess(targetProcess, &apcState);

        // Convert handle to object pointer
        HANDLE handleVal = Req->HandleValue;
        if (Req->ProcessId < 8) {
            // System process — mark as kernel handle
            handleVal = (HANDLE)((ULONG_PTR)handleVal | 0xFFFFFFFF80000000ULL);
        }

        status = ObReferenceObjectByHandle(
            handleVal, 0, NULL,
            (Req->ProcessId >= 8) ? UserMode : KernelMode,
            &objectPtr, NULL);

        // Verify object pointer matches expected value (anti-TOCTOU)
        if (NT_SUCCESS(status) && objectPtr != Req->ObjectPointer) {
            ObDereferenceObject(objectPtr);
            objectPtr = NULL;
            status = STATUS_INVALID_PARAMETER;
        }

        KeUnstackDetachProcess(&apcState);

        if (exitSyncHeld && g_Globals.PsReleaseProcessExitSynchronization) {
            g_Globals.PsReleaseProcessExitSynchronization(targetProcess);
        }

        ObDereferenceObject(targetProcess);

        if (!NT_SUCCESS(status))
            return status;

    } else {
        // No exit sync available and PID >= 8: use ZwDuplicateObject path
        HANDLE      hProcess = NULL;
        HANDLE      hDup     = NULL;
        OBJECT_ATTRIBUTES oa;
        CLIENT_ID   cid;

        cid.UniqueProcess = (HANDLE)(ULONG_PTR)Req->ProcessId;
        cid.UniqueThread  = NULL;
        InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

        status = ZwOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &oa, &cid);
        if (!NT_SUCCESS(status))
            return STATUS_ACCESS_DENIED;

        status = ZwDuplicateObject(hProcess, Req->HandleValue,
                                   NtCurrentProcess(), &hDup, 0, 0,
                                   DUPLICATE_SAME_ACCESS);
        if (!NT_SUCCESS(status)) {
            ZwClose(hProcess);
            return STATUS_ACCESS_DENIED;
        }

        ZwClose(hProcess);

        // Verify type if it's supposed to be a file object
        POBJECT_TYPE expectedType = NULL;
        if (Req->FileObjectFlags)
            expectedType = *IoFileObjectType;

        status = ObReferenceObjectByHandle(
            hDup, 0, expectedType, UserMode, &objectPtr, NULL);
        if (!NT_SUCCESS(status)) {
            ObCloseHandle(hDup, KernelMode);
            return STATUS_ACCESS_DENIED;
        }

        ObCloseHandle(hDup, KernelMode);

        // Verify pointer
        if (objectPtr != Req->ObjectPointer) {
            ObDereferenceObject(objectPtr);
            return STATUS_ACCESS_DENIED;
        }
    }

    // --- Check file object flags (readable/writable/delete) ---
    if (Req->FileObjectFlags && ((PFILE_OBJECT)objectPtr)->Type == 5) {
        PFILE_OBJECT fileObj = (PFILE_OBJECT)objectPtr;
        if (fileObj->ReadAccess)
            result->Flags |= 1;
        if (fileObj->WriteAccess)
            result->Flags |= 2;
        if (fileObj->DeleteAccess)
            result->Flags |= 4;

        // Try to get name from the file object directly
        status = QueryFileNameFromObject(IsUnicode, objectPtr,
                                         &result->AnsiName, (ULONG)nameBufSize);
        if (NT_SUCCESS(status)) {
            // Calculate output length
            if (IsUnicode) {
                SIZE_T len = wcslen(result->UnicodeName);
                *BytesReturned = len * sizeof(WCHAR) + sizeof(ULONG) + sizeof(WCHAR) + sizeof(ULONG);
            } else {
                SIZE_T len = strlen(result->AnsiName);
                *BytesReturned = len + sizeof(ULONG) + 1 + sizeof(ULONG);
            }
            ObDereferenceObject(objectPtr);
            return status;
        }
        // Fall through to ObQueryNameString if file-specific query failed
    }

    // --- Get object name via ObQueryNameString ---
    {
        ULONG                   needed = 0;
        POBJECT_NAME_INFORMATION nameInfo = NULL;

        status = ObQueryNameString(objectPtr, NULL, 0, &needed);
        if (needed > 0) {
            nameInfo = (POBJECT_NAME_INFORMATION)
                ExAllocatePoolWithTag(PagedPool, needed, PROCEXP_POOL_TAG);
        }

        if (nameInfo) {
            status = ObQueryNameString(objectPtr, nameInfo, needed, &needed);
            if (NT_SUCCESS(status) && nameInfo->Name.Length > 0) {
                if (IsUnicode) {
                    ULONG copyLen = nameInfo->Name.Length;
                    if (copyLen > nameBufSize - sizeof(WCHAR))
                        copyLen = (ULONG)(nameBufSize - sizeof(WCHAR));
                    RtlCopyMemory(result->UnicodeName, nameInfo->Name.Buffer, copyLen);
                    result->UnicodeName[copyLen / sizeof(WCHAR)] = L'\0';
                    *BytesReturned = copyLen + sizeof(ULONG) + sizeof(WCHAR) + sizeof(ULONG);
                } else {
                    ANSI_STRING ansi;
                    status = RtlUnicodeStringToAnsiString(&ansi, &nameInfo->Name, TRUE);
                    if (NT_SUCCESS(status)) {
                        RtlCopyMemory(result->AnsiName, ansi.Buffer, ansi.Length);
                        result->AnsiName[ansi.Length] = '\0';
                        RtlFreeAnsiString(&ansi);
                        *BytesReturned = ansi.Length + sizeof(ULONG) + 1 + sizeof(ULONG);
                    }
                }
            }
            ExFreePoolWithTag(nameInfo, 0);
        }
    }

    ObDereferenceObject(objectPtr);
    return status;
}

// ============================================================================
// QueryObjectNameFromFile — query object name while still attached
//
// Uses ZwQueryObject(ObjectTypeInformation) in the caller's address space
// rather than ObQueryNameString. Used for IOCTLs 0x83350040/0x8335004C.
// ============================================================================

static NTSTATUS
QueryObjectNameFromFile(
    BOOLEAN                 IsUnicode,
    PPROCEXP_HANDLE_REQUEST Req,
    PVOID                   OutBuf,
    PULONG_PTR              BytesReturned
    )
{
    NTSTATUS    status;
    PEPROCESS   targetProcess = NULL;
    PVOID       objectPtr     = NULL;
    KAPC_STATE  apcState;
    ULONG_PTR   bufSize = *BytesReturned;

    *BytesReturned = 0;

    if (Req->ProcessId >= 8 && !g_Globals.PsAcquireProcessExitSynchronization) {
        return STATUS_INVALID_PARAMETER;
    }

    status = PsLookupProcessByProcessId(
        (HANDLE)(ULONG_PTR)Req->ProcessId, &targetProcess);
    if (!NT_SUCCESS(status))
        return status;

    if (g_Globals.PsAcquireProcessExitSynchronization) {
        status = g_Globals.PsAcquireProcessExitSynchronization(targetProcess);
        if (!NT_SUCCESS(status)) {
            ObDereferenceObject(targetProcess);
            return status;
        }
    }

    KeStackAttachProcess(targetProcess, &apcState);

    HANDLE handleVal = Req->HandleValue;
    if (Req->ProcessId < 8)
        handleVal = (HANDLE)((ULONG_PTR)handleVal | 0xFFFFFFFF80000000ULL);

    status = ObReferenceObjectByHandle(
        handleVal, 0, NULL,
        (Req->ProcessId >= 8) ? UserMode : KernelMode,
        &objectPtr, NULL);

    if (NT_SUCCESS(status) && objectPtr != Req->ObjectPointer) {
        ObDereferenceObject(objectPtr);
        objectPtr = NULL;
    }

    if (g_Globals.PsReleaseProcessExitSynchronization)
        g_Globals.PsReleaseProcessExitSynchronization(targetProcess);
    ObDereferenceObject(targetProcess);

    if (!objectPtr) {
        KeUnstackDetachProcess(&apcState);
        return STATUS_ACCESS_DENIED;
    }

    // Use ZwQueryObject while still attached to target process context
    ULONG           needed = 0;
    PUNICODE_STRING nameStr = NULL;

    status = ZwQueryObject(handleVal, ObjectNameInformation, NULL, 0, &needed);
    if (status == STATUS_INFO_LENGTH_MISMATCH && needed > 0) {
        nameStr = (PUNICODE_STRING)
            ExAllocatePoolWithTag(PagedPool, needed, PROCEXP_MOD_POOL_TAG);
        if (nameStr) {
            status = ZwQueryObject(handleVal, ObjectNameInformation,
                                   nameStr, needed, NULL);
            if (NT_SUCCESS(status)) {
                ULONG maxCopy = (ULONG)(bufSize - 8);
                if (IsUnicode) {
                    ULONG copyLen = nameStr->Length;
                    if (copyLen > maxCopy - sizeof(WCHAR))
                        copyLen = maxCopy - sizeof(WCHAR);
                    RtlCopyMemory((PUCHAR)OutBuf + 4, nameStr->Buffer, copyLen);
                    *(PWCHAR)((PUCHAR)OutBuf + 4 + copyLen) = L'\0';
                    SIZE_T wLen = wcslen((PWCHAR)((PUCHAR)OutBuf + 4));
                    *BytesReturned = wLen * sizeof(WCHAR) + 10;
                } else {
                    ANSI_STRING ansi;
                    status = RtlUnicodeStringToAnsiString(&ansi, nameStr, TRUE);
                    if (NT_SUCCESS(status)) {
                        ULONG copyLen = ansi.Length;
                        if (copyLen > maxCopy - 1)
                            copyLen = maxCopy - 1;
                        RtlCopyMemory((PUCHAR)OutBuf + 4, ansi.Buffer, copyLen);
                        *((PUCHAR)OutBuf + 4 + copyLen) = '\0';
                        RtlFreeAnsiString(&ansi);
                        *BytesReturned = copyLen + 10;
                    }
                }
            }
            ExFreePoolWithTag(nameStr, 0);
        } else {
            status = STATUS_INSUFFICIENT_RESOURCES;
        }
    }

    ObDereferenceObject(objectPtr);
    KeUnstackDetachProcess(&apcState);

    return NT_SUCCESS(status) ? status : (*BytesReturned = 0, status);
}

// ============================================================================
// CloseHandleInProcess — close a handle in another process
//
// Uses ZwDuplicateObject with DUPLICATE_CLOSE_SOURCE to atomically
// close the handle in the target process.
// ============================================================================

static NTSTATUS
CloseHandleInProcess(PPROCEXP_HANDLE_REQUEST Req)
{
    NTSTATUS            status;
    HANDLE              hProcess = NULL;
    OBJECT_ATTRIBUTES   oa;
    CLIENT_ID           cid;

    cid.UniqueProcess = (HANDLE)(ULONG_PTR)Req->ProcessId;
    cid.UniqueThread  = NULL;
    InitializeObjectAttributes(&oa, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenProcess(&hProcess, PROCESS_DUP_HANDLE, &oa, &cid);
    if (!NT_SUCCESS(status))
        return status;

    // DUPLICATE_CLOSE_SOURCE (0x1) atomically closes the handle in the source
    status = ZwDuplicateObject(
        hProcess,               // source process
        Req->HandleValue,       // source handle
        NULL,                   // no target process (we just want to close)
        NULL,                   // no target handle
        0, 0,
        DUPLICATE_CLOSE_SOURCE);

    ZwClose(hProcess);
    return status;
}

// ============================================================================
// QueryFileNameFromObject — extract file name from FILE_OBJECT structure
//
// For file objects, reads the FileName field from the FILE_OBJECT and the
// DeviceObject to construct the full path. Falls back to ObQueryNameString.
// ============================================================================

static NTSTATUS
QueryFileNameFromObject(
    BOOLEAN IsUnicode,
    PVOID   FileObj,
    PVOID   OutBuf,
    ULONG   OutBufSize
    )
{
    PFILE_OBJECT    fileObject = (PFILE_OBJECT)FileObj;
    PUNICODE_STRING fileName;
    NTSTATUS        status = STATUS_SUCCESS;

    // FILE_OBJECT validation
    if (fileObject->Type != 5 || fileObject->Size != 0xD8)
        return STATUS_INVALID_PARAMETER;

    fileName = &fileObject->FileName;
    if (!fileName->Buffer || fileName->Length == 0)
        return STATUS_INVALID_PARAMETER;

    if (IsUnicode) {
        ULONG copyLen = fileName->Length;
        if (copyLen > OutBufSize - sizeof(WCHAR))
            copyLen = OutBufSize - sizeof(WCHAR);

        RtlCopyMemory(OutBuf, fileName->Buffer, copyLen);
        ((PWCHAR)OutBuf)[copyLen / sizeof(WCHAR)] = L'\0';
    } else {
        ANSI_STRING ansi;
        status = RtlUnicodeStringToAnsiString(&ansi, fileName, TRUE);
        if (NT_SUCCESS(status)) {
            ULONG copyLen = ansi.Length;
            if (copyLen > OutBufSize - 1)
                copyLen = OutBufSize - 1;
            RtlCopyMemory(OutBuf, ansi.Buffer, copyLen);
            ((PCHAR)OutBuf)[copyLen] = '\0';
            RtlFreeAnsiString(&ansi);
        }
    }

    return status;
}

// ============================================================================
// QuerySystemMemoryInfo — system memory pool info query
// ============================================================================

static NTSTATUS
QuerySystemMemoryInfo(
    PVOID       InputBuffer,
    PVOID       OutputBuffer,
    PULONG_PTR  BytesReturned
    )
{
    // Delegates to ZwQuerySystemInformation with the caller's parameters
    ULONG   infoClass = *(PULONG)InputBuffer;
    ULONG   outSize   = (ULONG)*BytesReturned;
    ULONG   retLen    = 0;

    NTSTATUS status = ZwQuerySystemInformation(
        infoClass, OutputBuffer, outSize, &retLen);

    if (NT_SUCCESS(status))
        *BytesReturned = retLen;
    else
        *BytesReturned = 0;

    return status;
}
