#pragma once

// ============================================================================
// procexp_shared.h — Shared definitions between driver and client
// PROCEXP152 kernel driver interface
//
// This header is usable from both kernel (ntddk.h) and user mode (windows.h).
// ============================================================================

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#include <winioctl.h>
#endif

// ---------------------------------------------------------------------------
// Device constants
// ---------------------------------------------------------------------------

#define PROCEXP_DEVICE_NAME     L"\\Device\\PROCEXP152"
#define PROCEXP_SYMLINK_NAME    L"\\DosDevices\\PROCEXP152"
#define PROCEXP_WIN32_DEVICE    L"\\\\.\\PROCEXP152"
#define PROCEXP_DRIVER_NAME     L"PROCEXP152"
#define PROCEXP_DRIVER_FILENAME L"PROCEXP152.sys"
#define PROCEXP_SERVICE_NAME    L"PROCEXP152"
#define PROCEXP_DEVICE_TYPE     ((ULONG)0x8335)

// Protocol version (returned by VERSION_CHECK ioctl)
#define PROCEXP_PROTOCOL_VERSION 0x98

// ---------------------------------------------------------------------------
// IOCTL codes — METHOD_BUFFERED, FILE_ANY_ACCESS
//
// Device type 0x8335, all use METHOD_BUFFERED (type 3).
// ---------------------------------------------------------------------------

#define IOCTL_PROCEXP_QUERY_OBJECT_NAME_ANSI \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0000, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350000

#define IOCTL_PROCEXP_CLOSE_HANDLE \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0001, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350004

#define IOCTL_PROCEXP_VERSION_CHECK \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0002, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350008

#define IOCTL_PROCEXP_OPEN_PROCESS_TOKEN \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0003, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x8335000C

#define IOCTL_PROCEXP_OPEN_OBJECT_BY_POINTER \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0005, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350014

#define IOCTL_PROCEXP_READ_EPROCESS_FIELD \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0008, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350020

#define IOCTL_PROCEXP_QUERY_SYSTEM_MEMORY \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0009, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350024

#define IOCTL_PROCEXP_QUERY_THREAD_INFO \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x000A, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350028

#define IOCTL_PROCEXP_QUERY_MUTANT_OWNER \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x000B, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x8335002C

#define IOCTL_PROCEXP_QUERY_PROCESS_PRIORITY \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x000D, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350034

#define IOCTL_PROCEXP_OPEN_PROCESS_BY_PID \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x000F, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x8335003C

#define IOCTL_PROCEXP_QUERY_FILE_NAME_ANSI \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0010, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350040

#define IOCTL_PROCEXP_READ_KERNEL_MEMORY \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0011, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350044

#define IOCTL_PROCEXP_QUERY_OBJECT_NAME_UNICODE \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0012, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350048

#define IOCTL_PROCEXP_QUERY_FILE_NAME_UNICODE \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0013, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x8335004C

#define IOCTL_PROCEXP_GET_MAX_NONPAGED_POOL \
    CTL_CODE(PROCEXP_DEVICE_TYPE, 0x0014, METHOD_BUFFERED, FILE_ANY_ACCESS)
// = 0x83350050

// ---------------------------------------------------------------------------
// IOCTL structures (shared between driver and client)
// ---------------------------------------------------------------------------

#pragma pack(push, 8)

// Input buffer for handle operations (0x20 = 32 bytes)
typedef struct _PROCEXP_HANDLE_REQUEST {
    ULONG       ProcessId;          // +0x00  target PID
    ULONG       _Pad0;              // +0x04
    void       *ObjectPointer;      // +0x08  expected kernel object pointer
    ULONG       FileObjectFlags;    // +0x10  nonzero = treat as file object
    ULONG       _Pad1;              // +0x14
    void       *HandleValue;        // +0x18  the handle in the target process
} PROCEXP_HANDLE_REQUEST, *PPROCEXP_HANDLE_REQUEST;

// Output for object name queries: flags + name string
typedef struct _PROCEXP_NAME_RESULT {
    ULONG       Flags;              // +0x00  bit 0=read, bit 1=write, bit 2=delete
    union {
        char    AnsiName[1];        // +0x04  for ANSI ioctls
        wchar_t UnicodeName[1];     // +0x04  for Unicode ioctls
    };
} PROCEXP_NAME_RESULT, *PPROCEXP_NAME_RESULT;

// Output for thread info query (0x18 = 24 bytes)
typedef struct _PROCEXP_THREAD_INFO {
    void       *Win32StartAddress;  // +0x00
    void       *Teb;                // +0x08
    void       *StartAddress;       // +0x10
} PROCEXP_THREAD_INFO, *PPROCEXP_THREAD_INFO;

#pragma pack(pop)

// Name result flag bits
#define PROCEXP_FLAG_READ_ACCESS    0x01
#define PROCEXP_FLAG_WRITE_ACCESS   0x02
#define PROCEXP_FLAG_DELETE_ACCESS  0x04
