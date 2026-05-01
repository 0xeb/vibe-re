#pragma once

// ============================================================================
// procexp.h — Driver-private header
// PROCEXP152.sys kernel driver internals
// ============================================================================

#define _KERNEL_MODE
#include <ntddk.h>
#include <wdmsec.h>

#include "../common/procexp_shared.h"

// ---------------------------------------------------------------------------
// Driver-only constants
// ---------------------------------------------------------------------------

#define PROCEXP_POOL_TAG        'TOEP'  // 0x544f4550
#define PROCEXP_MOD_POOL_TAG    'PrcX'  // 0x58637250
#define MIN_SUPPORTED_BUILD     0x0A28  // Windows XP SP2

// ---------------------------------------------------------------------------
// Dynamically resolved kernel APIs (not in standard headers)
// ---------------------------------------------------------------------------

typedef NTSTATUS (NTAPI *PFN_PsAcquireProcessExitSynchronization)(PEPROCESS Process);
typedef VOID     (NTAPI *PFN_PsReleaseProcessExitSynchronization)(PEPROCESS Process);
typedef SIZE_T   (NTAPI *PFN_MmGetMaximumNonPagedPoolInBytes)(VOID);
typedef POBJECT_TYPE (NTAPI *PFN_ObGetObjectType)(PVOID Object);

// ---------------------------------------------------------------------------
// Driver globals
// ---------------------------------------------------------------------------

typedef struct _PROCEXP_GLOBALS {
    ULONG                                   OsBuildNumber;
    PVOID                                   MutantObjectType;
    PFN_PsAcquireProcessExitSynchronization PsAcquireProcessExitSynchronization;
    PFN_PsReleaseProcessExitSynchronization PsReleaseProcessExitSynchronization;
    PFN_MmGetMaximumNonPagedPoolInBytes     MmGetMaximumNonPagedPoolInBytes;
    PFN_ObGetObjectType                     ObGetObjectType;
} PROCEXP_GLOBALS;

extern PROCEXP_GLOBALS g_Globals;

// ---------------------------------------------------------------------------
// Kernel type imports
// ---------------------------------------------------------------------------

extern POBJECT_TYPE *IoFileObjectType;
extern POBJECT_TYPE *PsProcessType;
extern POBJECT_TYPE *PsThreadType;
