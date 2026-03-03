# Blob 0 — Process Launcher / Token Theft Plugin ("Install")

## Summary

| Property | Value |
|----------|-------|
| File | Private archive artifact (available on vetted request) |
| Image Size | 0x6000 (24576 bytes) |
| Entry Point RVA | 0x2714 |
| Functions | 50 (all renamed) |
| Sections | .text, .rdata, .data2, .data3, .idata |
| Timestamp | 0x58AEBA91 (2017-02-23) |
| idasql Port | 8200 |
| Version (CMD 101) | 103 |
| Plugin ID (CMD 102) | `"Install"` (encrypted at `0x180003178`) |
| Sub-command Base | 0x670080 |

## Role

**Token-stealing process launcher with comprehensive anti-analysis suite.** Targets `winlogon.exe` to steal SYSTEM-level tokens, escalates privileges, and creates processes under stolen tokens. After launching a suspended process, calls back to the parent orchestrator's process injection vtable slot. Devotes 9 of 50 functions (18%) to anti-debug/anti-tool detection.

## Imports (34 functions, 5 DLLs)

### KERNEL32.dll (22 functions)
- GetProcAddress, GetModuleHandleA, lstrcmpiA, GetTickCount
- **OpenMutexW**, lstrcmpiW, **OpenProcess**, **CreateThread**
- lstrlenW, **ExpandEnvironmentStringsW**, **CreateProcessW**
- **CreateToolhelp32Snapshot**, **Process32FirstW**, **Process32NextW**
- lstrcpyW, CloseHandle, **CreateMutexA**, GetLastError
- **TerminateProcess**, **Sleep**, **GetCurrentProcess**, **ExitProcess**

### USER32.dll (4 functions)
- EnableWindow, GetClassNameA, GetForegroundWindow, **EnumChildWindows**

### ADVAPI32.dll (4 functions)
- **LookupPrivilegeValueA**, **AdjustTokenPrivileges**, **DuplicateTokenEx**, **OpenProcessToken**

### WS2_32.dll (2 ordinals)
- ord#14 (sendto), ord#8 (inet_addr)

### USERENV.dll (2 functions)
- **DestroyEnvironmentBlock**, **CreateEnvironmentBlock**

## Dynamically Resolved APIs

| Address | API | DLL | Resolution |
|---------|-----|-----|------------|
| qword_180004058 | `memset` | msvcrt.dll | Encrypted string + LoadLibrary |
| qword_180004060 | `ImpersonateLoggedOnUser` | advapi32.dll | Plaintext + GetProcAddress |
| qword_180004068 | `RevertToSelf` | advapi32.dll | Plaintext + GetProcAddress |
| qword_180004070 | `CreateProcessAsUserW` | advapi32.dll | Plaintext + GetProcAddress |

## Entry Point: DllMain_dispatcher (0x180002714)

Standard ScatterBrain dispatcher with fdwReason as command ID:
- **CMD 0**: Returns 0 (no-op)
- **CMD 1**: Writes two vtable function pointers via `cmd1_write_vtable`
- **CMD 100**: Stores `lpvReserved` to `qword_180004018` (parent context)
- **CMD 101**: Returns plugin ID 103
- **CMD 102**: Decrypts "Install" string, copies to output
- **CMD 104**: Returns `&qword_180004000` (vtable base)

## Vtable (2 entries at `qword_180004000`)

| Slot | Address | Function | Purpose |
|------|---------|----------|---------|
| 0 | 0x18000298C | `vtfn_subcmd_dispatcher` | Reads sub-command from arg, dispatches via ntohl |
| 1 | 0x1800025C4 | `vtfn_worker_init` | Enables privileges, finds target, creates process with stolen token |

### Sub-command Dispatch

Reads `*(DWORD*)(arg+4)`, converts via ntohl, subtracts base 0x670080:
- **0x670080** (`subcmd_query_status`): Responds with htonl(6750208) + two zero fields (heartbeat)
- **0x670081** (`subcmd_launch_process`): Sends ack, sleeps 3s, triggers process launch; self-destructs on error state 4

## Key Function: process_launcher (0x180001280, 1067 bytes)

Complete token theft and process creation flow:

1. Expand environment strings in command line path
2. Lazy-resolve `memset` from encrypted string
3. Zero STARTUPINFO and PROCESS_INFORMATION
4. Decrypt `winlogon.exe` target name -> find PID via process enumeration
5. `OpenProcess(MAXIMUM_ALLOWED, FALSE, winlogon_pid)`
6. `OpenProcessToken` -> `DuplicateTokenEx` (get impersonation token)
7. `CreateEnvironmentBlock` for the duplicated token
8. `ImpersonateLoggedOnUser` -> impersonate SYSTEM
9. `CreateProcessAsUserW` (CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT = 0x434)
10. `RevertToSelf` -> stop impersonating
11. If successful: call parent context vtable at offset +136 (0x88) -> **process injection callback**
12. If injection fails: `TerminateProcess` on the new process
13. Close all handles

Fallback path: `create_process_direct` (0x1800016C0) uses plain `CreateProcessW` without token manipulation.

## Anti-Analysis Suite (9 functions)

### Code Integrity
| Function | Address | Technique |
|----------|---------|-----------|
| `checksum_memory` | 0x180001C80 | Rolling checksum: `(result << 8) + byte + BYTE3(result)` |
| `antitamper_code_check` | 0x180001CD0 | Infinite loop checking .text section checksum; crashes if changed |
| `antitamper_export_check` | 0x180001BD0 | Checks if CreateFileW first byte is 0xCC (breakpoint); crashes if so |

### Debugger Detection
| Function | Address | Technique |
|----------|---------|-----------|
| `antidebug_timing_check` | 0x180001DC0 | Dual IsDebuggerPresent (kernelbase + kernel32) + GetTickCount timing (1000ms threshold) |
| `antidebug_detect_tools` | 0x180001F20 | EnumWindows callback: FindWindowA for OllyDbg (4 classes) + WinDbg |
| `antidebug_enum_windows` | 0x1800021C0 | Infinite loop calling EnumWindows with above callback, sleeps 5s |

### Tool Detection
| Function | Address | Technique |
|----------|---------|-----------|
| `antitool_open_devices_loop` | 0x1800021F0 | Opens `\\.\Regmon`, `\\.\FileMon`, `\\.\ProcmonDebugLogger`, `\\.\NTICE`; sleeps 1s between cycles |
| `antitool_open_device` | 0x1800020E0 | Single device open via dynamically resolved CreateFileW |
| `antitool_kill_wireshark` | 0x180001D30 | Detects Wireshark via named mutex `{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}`; terminates process |

All detections terminate via `ExitProcess(0)` or `__debugbreak()` -- burn-the-evidence approach.

## Encrypted Strings (30 total)

### Core Operation
| Address | Key Seed | Decrypted | Used For |
|---------|----------|-----------|----------|
| 0x180003138 | 0x6941 | `Global\` | Mutex name prefix (singleton) |
| 0x180003148 | 0xAD6C | `SeTcbPrivilege` | Token privilege escalation |
| 0x180003160 | 0x30C7 | `SeDebugPrivilege` | Debug privilege for OpenProcess |
| 0x180003178 | 0x32DE | `Install` | Plugin ID |
| 0x180003188 | 0x719F | `CreateFileW` | Dynamic API resolution |
| 0x180003198 | 0xECF3 | `kernel32` | DLL for CreateFileW |
| 0x180003360 | 0x4147 | `msvcrt.dll` | CRT library |
| 0x180003370 | 0x40E4 | `kernel32.dll` | Win32 library |
| 0x180003380 | 0xC921 | `winlogon.exe` | Target process |
| 0x180003390 | 0x0979 | `advapi32.dll` | Security library |
| 0x1800033A0 | 0xF76E | `memset` | Memory initialization |
| 0x1800033F8 | 0xEDA5 | `lstrcpyW` | String operations |
| 0x180003408 | 0x7FBD | `lstrcatW` | String concatenation |
| 0x180003418 | 0xDF6C | `lstrlenW` | String length |

### Anti-Analysis
| Address | Key Seed | Decrypted | Used For |
|---------|----------|-----------|----------|
| 0x1800031A8 | 0x3E27 | `\\.\Regmon` | Sysinternals Regmon |
| 0x1800031B8 | 0x17B8 | `\\.\FileMon` | Sysinternals FileMon |
| 0x1800031C8 | 0x68AA | `\\.\ProcmonDebugLogger` | Sysinternals Procmon |
| 0x1800031E8 | 0xA70D | `\\.\NTICE` | SoftICE debugger |
| 0x1800031F8 | 0x3511 | `ACPUASM` | OllyDbg CPU window |
| 0x180003208 | 0x425C | `AOPOASM` | OllyDbg window |
| 0x180003218 | 0xD846 | `AOPUASM` | OllyDbg window |
| 0x180003228 | 0x080D | `ACPOASM` | OllyDbg window |
| 0x180003238 | 0xC9CB | `WinDbgFrameClass` | WinDbg window |
| 0x180003250 | 0x0673 | `IsDebuggerPresent` | Anti-debug (kernelbase) |
| 0x180003268 | 0x747C | `kernelbase` | DLL for IsDebuggerPresent |
| 0x180003278 | 0x8339 | `IsDebuggerPresent` | Anti-debug (kernel32) |
| 0x180003290 | 0xA857 | `kernel32` | DLL for IsDebuggerPresent |
| 0x1800032A0 | 0xB493 | `Wireshark-is-running-{9CA78EEA-...}` | Wireshark mutex |
| 0x1800032E0 | 0x6513 | (same GUID) | Redundant copy |
| 0x180003320 | 0xBF5D | (same GUID) | Redundant copy |

## All 50 Functions

| # | Address | Name | Size | Category |
|---|---------|------|------|----------|
| 1 | 0x180001000 | `resolve_import_msvcrt` | 159 | Import resolution |
| 2 | 0x1800010A0 | `resolve_import_kernel32` | 159 | Import resolution |
| 3 | 0x180001140 | `resolve_import_advapi32` | 159 | Import resolution |
| 4 | 0x1800011E0 | `find_process_by_name` | 146 | Process ops |
| 5 | 0x180001280 | `process_launcher` | 1067 | Process ops |
| 6 | 0x1800016C0 | `create_process_direct` | 527 | Process ops |
| 7 | 0x1800018E0 | `try_launch_commands` | 261 | Process ops |
| 8 | 0x1800019E8 | `peb_resolve_api_hash` | 241 | API resolution |
| 9 | 0x180001AE8 | `heap_free` | 53 | Memory |
| 10 | 0x180001B28 | `heap_alloc` | 54 | Memory |
| 11 | 0x180001B68 | `heap_free_thunk` | 5 | Memory |
| 12 | 0x180001B78 | `heap_free_thunk2` | 5 | Memory |
| 13 | 0x180001B88 | `heap_alloc_thunk` | 5 | Memory |
| 14 | 0x180001B90 | `open_and_terminate` | 49 | Process ops |
| 15 | 0x180001BD0 | `antitamper_export_check` | 167 | Anti-analysis |
| 16 | 0x180001C80 | `checksum_memory` | 60 | Anti-analysis |
| 17 | 0x180001CD0 | `antitamper_code_check` | 86 | Anti-analysis |
| 18 | 0x180001D30 | `antitool_kill_wireshark` | 125 | Anti-analysis |
| 19 | 0x180001DC0 | `antidebug_timing_check` | 343 | Anti-analysis |
| 20 | 0x180001F20 | `antidebug_detect_tools` | 438 | Anti-analysis |
| 21 | 0x1800020E0 | `antitool_open_device` | 215 | Anti-analysis |
| 22 | 0x1800021C0 | `antidebug_enum_windows` | 42 | Anti-analysis |
| 23 | 0x1800021F0 | `antitool_open_devices_loop` | 161 | Anti-analysis |
| 24 | 0x180002294 | `get_vtable_ptr` | 13 | Plugin export |
| 25 | 0x1800022B4 | `get_plugin_id` | 9 | Plugin export |
| 26 | 0x1800022C4 | `stub_return_0_a` | 3 | Stub |
| 27 | 0x1800022D4 | `stub_return_0_b` | 3 | Stub |
| 28 | 0x1800022E4 | `stub_return_0_c` | 3 | Stub |
| 29 | 0x1800022F4 | `enable_privilege` | 156 | Privilege |
| 30 | 0x1800023A4 | `set_context_ptr` | 10 | Framework |
| 31 | 0x1800023B4 | `framework_wait_cmd` | 94 | Framework |
| 32 | 0x180002424 | `decrypt_and_set_name` | 57 | Framework |
| 33 | 0x180002464 | `install_service_entry` | 345 | Framework |
| 34 | 0x1800025C4 | `vtfn_worker_init` | 277 | Vtable |
| 35 | 0x1800026E4 | `cmd1_write_vtable` | 31 | Vtable |
| 36 | 0x180002714 | `DllMain_dispatcher` | 122 | Entry |
| 37 | 0x180002790 | `framework_read_config` | 85 | Framework |
| 38 | 0x1800027F0 | `framework_decode_commands` | 84 | Framework |
| 39 | 0x180002850 | `framework_send_response` | 90 | Framework |
| 40 | 0x1800028AC | `subcmd_launch_process` | 131 | Sub-command |
| 41 | 0x18000293C | `subcmd_query_status` | 73 | Sub-command |
| 42 | 0x18000298C | `vtfn_subcmd_dispatcher` | 76 | Vtable |
| 43 | 0x1800029D8 | `utf8_to_wide` | 233 | String |
| 44 | 0x180002AC8 | `wide_to_ansi` | 188 | String |
| 45 | 0x180002B98 | `sbstr_free` | 59 | String |
| 46 | 0x180002BE8 | `decrypt_string` | 185 | Crypto |
| 47 | 0x180002CA8 | `sbstr_from_utf8` | 38 | String |
| 48 | 0x180002CD8 | `wstr_concat` | 397 | String |
| 49 | 0x180002E78 | `wstr_copy` | 299 | String |
| 50 | 0x180002FB8 | `wstr_init_empty` | 45 | String |

## Operational Flow

```
Parent orchestrator (inner PE)
  -> CMD 100: store parent context
  -> CMD 1: populate vtable
  -> CMD 104: get vtable pointer
  -> vtable[1](): vtfn_worker_init
    -> Enable SeTcbPrivilege + SeDebugPrivilege
    -> Read mode from parent context
    -> Based on mode:
      -> install_service_entry: create named mutex (Global\{config})
      -> try_launch_commands (up to 4 iterations):
        1. process_launcher: steal winlogon.exe SYSTEM token
           -> CreateProcessAsUserW (suspended)
           -> Call parent injection callback (offset 0x88)
        2. Fallback: create_process_direct (standard CreateProcessW)
```

## Detailed Function Reference

All 50 functions in the Install plugin, organized by category. Each entry includes the full detailed comment from the IDA database.

---

### API Resolution / Import Helpers

#### resolve_import_msvcrt (0x180001000, 159 bytes)

Resolves a function export from msvcrt.dll given its ASCII name passed in api_name_enc. On first invocation the msvcrt.dll module handle has not yet been cached in g_hMsvcrt, so the function decrypts the DLL name string from the encrypted blob enc_msvcrt_dll using decrypt_string, converts the resulting wide string to ANSI via wide_to_ansi, then loads the library through the PEB-walking loader resolved via peb_resolve_api_hash(HASH_LoadLibraryA). The resolved LoadLibraryA pointer is cached in g_pfnPebGetModuleHandleA and the resulting module handle is stored in g_hMsvcrt for all subsequent calls. Similarly, GetProcAddress is lazily resolved via peb_resolve_api_hash(HASH_GetProcAddress) and cached in g_pfnPebGetProcAddress. The function returns GetProcAddress(g_hMsvcrt, api_name_enc), where api_name_enc is the plain-text API name string. This lazy-resolution pattern is structurally identical across resolve_import_kernel32 and resolve_import_advapi32, differing only in the encrypted DLL name blob and the module-handle global variable.

#### resolve_import_kernel32 (0x1800010A0, 159 bytes)

Resolves a function export from kernel32.dll given its ASCII name passed in api_name_enc. On first call the kernel32.dll module handle is not yet cached in g_hKernel32, so the function decrypts the DLL name from enc_kernel32_dll via decrypt_string, converts the wide result to ANSI with wide_to_ansi, then loads the library through peb_resolve_api_hash(HASH_LoadLibraryA) whose result is cached in g_pfnPebGetModuleHandleA. The obtained module handle is stored in g_hKernel32 for all future calls. GetProcAddress is likewise lazily resolved via peb_resolve_api_hash(HASH_GetProcAddress) and cached in g_pfnPebGetProcAddress. Returns GetProcAddress(g_hKernel32, api_name_enc). This function is structurally identical to resolve_import_msvcrt and resolve_import_advapi32 -- the ScatterBrain framework uses one resolver per DLL, each differing only in the encrypted DLL name blob and the corresponding module-handle global variable. The temporary decrypted string buffer is freed via sbstr_free.

#### resolve_import_advapi32 (0x180001140, 159 bytes)

Resolves a function export from advapi32.dll given its ASCII name passed in api_name_enc. On first invocation the advapi32.dll module handle has not been cached in g_hAdvapi32, so the function decrypts the DLL name from enc_advapi32_dll using decrypt_string, converts the wide string to ANSI via wide_to_ansi, and loads the library through peb_resolve_api_hash(HASH_LoadLibraryA) whose pointer is cached in g_pfnPebGetModuleHandleA. The resulting module handle is stored in g_hAdvapi32 for subsequent calls. GetProcAddress is lazily resolved via peb_resolve_api_hash(HASH_GetProcAddress) and cached in g_pfnPebGetProcAddress. Returns GetProcAddress(g_hAdvapi32, api_name_enc). This resolver is critical for the Install plugin since advapi32.dll provides the privilege and token manipulation APIs (OpenProcessToken, DuplicateTokenEx, ImpersonateLoggedOnUser, CreateProcessAsUserA, AdjustTokenPrivileges) used by the token-theft process launcher. Structurally identical to resolve_import_msvcrt and resolve_import_kernel32.

#### peb_resolve_api_hash (0x1800019E8, 241 bytes)

Resolves a Windows API function pointer by its hash value using the PEB (Process Environment Block) InLoadOrderModuleList walk. First traverses the doubly-linked LDR_DATA_TABLE_ENTRY list starting from NtCurrentPeb()->Ldr->InLoadOrderModuleList.Flink to locate kernel32.dll. Module identification uses a custom hash algorithm: each wide character of the DLL name is OR-ed with 0x20 (case-folded to lowercase), added to a ROR-8 rotation of the running hash, then XOR-ed with the magic constant 0x7C35D9A3. The target kernel32.dll hash is 0xFD5792A1 (decimal -44363167). Once the module base is found, the function parses the PE export directory (IMAGE_EXPORT_DIRECTORY at the RVA from the PE headers DataDirectory[0]) and iterates over all exported function names, applying the same ROR8/XOR hash (without case folding) to each name. When a hash match is found, the ordinal table is used to index into the AddressOfFunctions array to compute the final function pointer. Returns the resolved function pointer or NULL if either the module or export is not found.

---

### Anti-Analysis / Evasion

#### open_and_terminate (0x180001B90, 49 bytes)

Anti-analysis kill-switch that attempts to open a named mutex via OpenMutexW with SYNCHRONIZE access (0x100000) and, if the mutex exists (handle is non-NULL), immediately terminates the current process by calling TerminateProcess(GetCurrentProcess(), 0). The single parameter is a wide-string mutex name. Returns 0 if the mutex was not found (i.e., the target tool is not running). This function is called in a loop by antitool_kill_wireshark, which passes three different Wireshark-specific named mutex strings (with GUIDs like 9CA78EEA-EA4D-4490...) that Wireshark creates on startup. The check exploits the fact that Wireshark registers well-known named mutexes that can be detected from any process in the same session. If any mutex is open, the malware terminates itself rather than risk packet capture analysis.

#### antitamper_export_check (0x180001BD0, 167 bytes)

Anti-tamper integrity monitor that runs as an infinite loop on a dedicated thread, scanning all PE export entry points for INT3 (0xCC) software breakpoint patches. The param1 argument is the base address of the PE image to monitor. The function parses the PE headers to locate the export directory (e_lfanew + 136 = DataDirectory[0] offset for the export table), then reads the AddressOfFunctions array (offset 28 in IMAGE_EXPORT_DIRECTORY) containing NumberOfFunctions (offset 20) RVAs. On each iteration it counts how many export RVAs resolve to a first byte of 0xCC (INT3). On the very first pass (status_6==0) the count is saved as a baseline in status_3. On every subsequent pass, if the current INT3 count differs from the baseline, a debugger or analysis tool has patched an export entry point, and the function spawns a new thread via CreateThread targeting ExitProcess (stored in g_pfnExitProcess) to terminate the process asynchronously. The function sleeps 5 seconds between checks via g_pfnSleep(5000).

#### checksum_memory (0x180001C80, 60 bytes)

Computes a rolling checksum over a memory region for code integrity verification. Takes a pointer to the data buffer and its length. The algorithm iterates byte-by-byte, updating the accumulator as: status = (status << 8) + current_byte + BYTE3(status), which is a shift-and-fold checksum that mixes the high byte back in. Before checksumming, it checks whether the input buffer appears to be a PE image by testing if data[0] XOR data[1] equals 0x7C39504D (a magic derived from MZ and PE signatures); if so, it recalculates the length as data[14] + data[16] which corresponds to the combined size of the code section and relocation section in the ScatterBrain packed PE header layout. Returns the final 32-bit checksum value. This function is called by antitamper_code_check in a polling loop to detect runtime code modifications (debugger patches, hooks, or analyst breakpoints).

#### antitamper_code_check (0x180001CD0, 86 bytes)

Anti-tamper code integrity monitor that runs as an infinite loop on a dedicated thread, periodically checksumming a code memory region and terminating the process if tampering is detected. The param1 argument points to a structure where QWORD at offset 0 is the code base pointer and DWORD at offset 8 is the code length. On each iteration, checksum_memory is called to compute a rolling checksum over the region. On the first iteration (status_2==0) or if the checksum matches the baseline, the baseline is updated. If the checksum diverges from the saved baseline on any subsequent iteration, it indicates that a debugger, hook, or analyst has modified the code in memory, and the function spawns a thread targeting ExitProcess via CreateThread(0, 0, g_pfnExitProcess, 0, 0, ...) to terminate the process asynchronously. The function sleeps 1 second between checks via g_pfnSleep(1000), which is more aggressive than the 5-second interval used by antitamper_export_check. This function is marked __noreturn as it never exits.

#### antitool_kill_wireshark (0x180001D30, 125 bytes)

Anti-analysis watchdog thread that continuously monitors for the presence of Wireshark packet capture software by probing three distinct named mutex strings. Runs as an infinite __noreturn loop: on each iteration, it decrypts three Wireshark-specific mutex names from encrypted blobs (enc_Wireshark_is_running_9CA78EEA_EA4D_4490, enc_Wireshark_is_running_2, and enc_Wireshark_is_running_9CA78EEA_EA4D_4490_3320) using decrypt_string, passes each decrypted wide string to open_and_terminate which attempts OpenMutexW. Wireshark creates well-known named mutexes containing the GUID 9CA78EEA-EA4D-4490 when running, so a successful OpenMutexW indicates an active Wireshark instance and triggers immediate process self-termination via TerminateProcess. Each temporary decrypted string is freed via sbstr_free after the check. The function sleeps 5 seconds (g_pfnSleep(5000)) between monitoring passes. This is one of the 9 anti-analysis functions in the Install plugin and specifically targets network traffic analysis tools.

#### antidebug_timing_check (0x180001DC0, 343 bytes)

Multi-layered anti-debug check that combines API hook detection, debugger presence detection, and timing analysis. First resolves IsDebuggerPresent by decrypting the function name from enc_IsDebuggerPresent and the DLL name kernelbase.dll from enc_kernelbase, using GetModuleHandleA and GetProcAddress to obtain the function pointer. If kernelbase.dll resolution fails, falls back to kernel32.dll (decrypted from enc_kernel32_2). Before calling IsDebuggerPresent, checks the first byte of the function for a value other than 0x65 (the expected first byte of the GS-segment prefix in the legitimate IsDebuggerPresent prologue); if different, it indicates the function has been hooked or patched, and the process is terminated via TerminateProcess(GetCurrentProcess(), 0). If the function prologue is clean, calls IsDebuggerPresent() and terminates if it returns non-zero. Finally performs a timing check: captures GetTickCount before and after the IsDebuggerPresent call, and if more than 1000 milliseconds (0x3E8) have elapsed, the function terminates the process (indicating a breakpoint or single-step delay).

#### antidebug_detect_tools (0x180001F20, 438 bytes)

EnumChildWindows callback function used by antidebug_enum_windows to detect and disable debugger and analysis tool windows. Receives a child window handle (param1) and the foreground parent window handle (param2). Calls GetClassNameA to retrieve the window class name (up to 128 bytes) and then compares it case-insensitively via lstrcmpiA against five known debugger class names decrypted from encrypted blobs: ACPUASM, AOPOASM, AOPUASM, and ACPOASM (four OllyDbg disassembly panel class names), and WinDbgFrameClass (the WinDbg main frame class). A bitmask variable ch_3 tracks which encrypted strings have been allocated (bits 0-4 for the 5 comparisons) to ensure proper cleanup via sbstr_free only for strings that were actually decrypted. If any class name matches (ch_14==1), the function calls EnableWindow(param2, 0) which disables the parent foreground window, effectively freezing the debugger UI. The function uses short-circuit evaluation to bail out on the first match. Always returns 1 to continue enumeration of remaining child windows.

#### antitool_open_device (0x1800020E0, 215 bytes)

Anti-analysis device probe that detects monitoring tool kernel drivers by attempting to open their device objects. First resolves CreateFileW from kernel32.dll by decrypting the API name from enc_CreateFileW and the DLL name from enc_kernel32, using GetModuleHandleA/GetProcAddress. Before calling CreateFileW, checks the first byte of the function for 0xCC (INT3 breakpoint) which would indicate API hooking -- if detected, immediately terminates via TerminateProcess(GetCurrentProcess(), 0). Then calls CreateFileW(device_path, GENERIC_READ=0x80000000, FILE_SHARE_READ|FILE_SHARE_WRITE=3, NULL, OPEN_EXISTING=3, 0, NULL). If the returned handle is not INVALID_HANDLE_VALUE (-1), the device exists and a monitoring driver is active, so the process self-terminates. The param1 is a wide-string device path like `\\.\Regmon` or `\\.\NTICE` paths passed by antitool_open_devices_loop. Returns 1 if the device was not found (safe to continue).

#### antidebug_enum_windows (0x1800021C0, 42 bytes)

Anti-debug watchdog thread that continuously scans for debugger and analysis tool windows. Runs as an infinite __noreturn loop: on each iteration calls GetForegroundWindow to get the currently active window, then invokes EnumChildWindows with antidebug_detect_tools as the callback function and the foreground window handle as the lParam. The callback checks each child window class name against known OllyDbg panel classes (ACPUASM, AOPOASM, AOPUASM, ACPOASM) and the WinDbg frame class (WinDbgFrameClass), disabling the parent window if a match is found. The function sleeps 5 seconds (g_pfnSleep(5000)) between enumeration passes. This approach targets the foreground window specifically, meaning it will detect debuggers only when they are in the foreground, but the continuous polling ensures eventual detection. This is one of the Install plugin's 9 anti-analysis threads and complements the timing checks and device probes.

#### antitool_open_devices_loop (0x1800021F0, 161 bytes)

Anti-analysis watchdog thread that continuously probes for the presence of four well-known Windows monitoring and debugging kernel-mode drivers by their device object paths. Runs as an infinite __noreturn loop: on each iteration, decrypts four device path strings from encrypted blobs -- Regmon (Sysinternals Registry Monitor), FileMon (Sysinternals File Monitor), ProcmonDebugLogger (Process Monitor debug logging driver), and NTICE (SoftICE kernel debugger) -- and passes each to antitool_open_device, which attempts CreateFileW on the device path. If any device is successfully opened, antitool_open_device terminates the process. Each decrypted string is freed via sbstr_free after the probe. The function sleeps 1 second (g_pfnSleep(1000)) between monitoring passes, making it the most frequently polling anti-analysis thread in the plugin. The detection of NTICE (SoftICE) is a legacy check as SoftICE has been discontinued, but its presence in the check list suggests the code lineage dates back to an earlier era of Windows reverse engineering.

---

### Process Management / Token Theft

#### find_process_by_name (0x1800011E0, 146 bytes)

Enumerates all running processes to find one matching a given wide-string name and returns its PID. Takes a snapshot of all processes via CreateToolhelp32Snapshot with TH32CS_SNAPPROCESS (flag 0x2), then iterates using Process32FirstW/Process32NextW. Each PROCESSENTRY32W structure is 568 bytes (cb=568 set before each iteration). The process executable name at offset 0x2C in the structure is compared case-insensitively against target_name using lstrcmpiW. If a match is found the function closes the snapshot handle via CloseHandle and returns the process ID from offset 0x8 (th32ProcessID). If no match is found after exhausting all entries the function returns 0. This function is called by process_launcher to locate winlogon.exe for SYSTEM token theft, and by antitool_kill_wireshark to locate analysis tool processes.

#### process_launcher (0x180001280, 1067 bytes)

Launches a process under a stolen SYSTEM token obtained from winlogon.exe, implementing a full token-theft privilege escalation chain. The input cmd_buf is an ANSI command string whose length is measured via lstrlenW (widened), padded by 256, and expanded through ExpandEnvironmentStringsW into a heap-allocated wide buffer which is then copied into a wstr object. The function resolves memset from msvcrt.dll (lazy-loaded) to zero-initialize STARTUPINFOW (104 bytes, cb=104, dwFlags=1, wShowWindow=0 for hidden window) and PROCESS_INFORMATION (24 bytes). It then decrypts the string winlogon.exe from enc_winlogon_exe and calls find_process_by_name to locate its PID. If not found returns ERROR_NOT_FOUND (1168). Otherwise opens the winlogon process with MAXIMUM_ALLOWED (0x2000000) via OpenProcess, obtains its token via OpenProcessToken, duplicates it with DuplicateTokenEx (SecurityImpersonation=1, TokenPrimary=1), creates an environment block with CreateEnvironmentBlock, impersonates via ImpersonateLoggedOnUser, and calls CreateProcessAsUserW with CREATE_SUSPENDED | CREATE_NEW_CONSOLE | CREATE_UNICODE_ENVIRONMENT (0x434). On success, calls the parent framework's process injection callback at g_pParentCtx+136 (offset 0x88). If the callback returns failure, terminates the new process via TerminateProcess. Closes all handles before returning.

#### create_process_direct (0x1800016C0, 527 bytes)

Launches a process directly via CreateProcessW without token theft, serving as the fallback path when process_launcher (SYSTEM token escalation) fails. The input cmd_buf is an ANSI command string that is measured with lstrlenW, padded by 256 characters, expanded through ExpandEnvironmentStringsW into a heap-allocated buffer, then copied into a wstr object. memset is lazily resolved from msvcrt.dll to zero-initialize STARTUPINFOW (cb=104, dwFlags=STARTF_USESHOWWINDOW=1, wShowWindow=SW_HIDE=0) and PROCESS_INFORMATION (24 bytes). CreateProcessW is called with dwCreationFlags=0x14 (CREATE_SUSPENDED|CREATE_DEFAULT_ERROR_MODE). On success the process and thread handles are reported to the C2 framework via the callback at g_pParentCtx+136 with a response tag of 4; if the framework callback returns a non-zero error code the newly created process is immediately terminated via TerminateProcess. On CreateProcessW failure, GetLastError is captured. Both process and thread handles are closed via CloseHandle before returning.

#### try_launch_commands (0x1800018E0, 261 bytes)

Orchestrates process execution by iterating over up to 4 command slots extracted from the plugin's encrypted configuration blob. Allocates a 2136-byte buffer and calls framework_decode_commands to decrypt and parse the config. Command string offsets are stored as 16-bit values at buffer+16, each pointing relative to buffer+88 into the command string table. For each of the 4 slots, decrypt_string is called to recover the plaintext command; if the decrypted string is non-empty, process_launcher is tried first (SYSTEM token theft via winlogon.exe). If all 4 slots fail with process_launcher (non-zero return), the function makes a second pass over the same 4 slots using create_process_direct (no privilege escalation) as a fallback. Returns 0 on the first successful launch from either pass, or the last error code (initialized to 87 = ERROR_INVALID_PARAMETER) if all 8 attempts fail. The config buffer is freed via heap_free and any temporary decrypt_string output is freed via sbstr_free.

#### enable_privilege (0x1800022F4, 156 bytes)

Enables a named Windows privilege on the current process token, used to escalate capabilities before performing privileged operations like token theft. The privilege_name parameter is an ANSI string such as SeDebugPrivilege. The function opens the current process token via OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY=0x28, ...), then resolves the privilege LUID via LookupPrivilegeValueA(NULL, privilege_name, ...). It constructs a TOKEN_PRIVILEGES structure with Count=1 and Attributes=SE_PRIVILEGE_ENABLED (2), then calls AdjustTokenPrivileges(token, FALSE, &tp, 16, NULL, NULL) to enable the privilege. If any step in the chain fails (OpenProcessToken, LookupPrivilegeValue, or AdjustTokenPrivileges returns FALSE), the function captures GetLastError and returns it. The token handle is closed via CloseHandle before returning. Returns 0 on success. This function is called by vtfn_worker_init during plugin initialization to ensure SeDebugPrivilege is available for the subsequent OpenProcess call on winlogon.exe.

---

### Plugin Protocol / Dispatch

#### get_vtable_ptr (0x180002294, 13 bytes)

Returns a pointer to the Install plugin's 2-entry vtable array (g_vtable_slot0_dispatch) by writing its address into the output parameter. This is part of the ScatterBrain plugin registration protocol: when the inner PE framework queries a plugin for its dispatch table, it calls this function which stores the vtable pointer at *param1. The vtable contains 2 function pointers -- slot 0 is vtfn_worker_init (the main worker initialization routine) and slot 1 is vtfn_subcmd_dispatcher (the command processor). The function always returns 0 to indicate success. This function is registered in the plugin's sb_plugin_entry_t structure as the vtable accessor callback.

#### get_plugin_id (0x1800022B4, 9 bytes)

Returns the Install plugin's unique numeric identifier (103) by writing it to the DWORD pointed to by param1. In the ScatterBrain plugin framework, each plugin has a unique ID: Install=103, Plugins=101, Config=102, Online=104, TCP=200, HTTP=201, UDP=202, DNS=203. This ID is used by the inner PE dispatcher to route C2 commands to the correct plugin and by the plugin registration mechanism during DllMain initialization. The function always returns 0 to indicate success. This function is registered in the sb_plugin_entry_t structure as the ID query callback.

#### stub_return_0_a (0x1800022C4, 3 bytes)

No-op stub function that unconditionally returns 0. Serves as a placeholder in the ScatterBrain plugin registration structure (sb_plugin_entry_t) for callback slots that the Install plugin does not implement. In other plugins these slots may handle shutdown, configuration updates, or status queries, but the Install plugin leaves them as identity stubs returning success (0). This is stub_return_0_a, the first of three identical stubs (a, b, c at consecutive addresses 0x1800022C4, 0x1800022D4, 0x1800022E4), each occupying a distinct slot in the registration table so the framework can call them independently without needing null-checks.

#### stub_return_0_b (0x1800022D4, 3 bytes)

No-op stub function that unconditionally returns 0. Identical in behavior to stub_return_0_a and stub_return_0_c, this function occupies a separate slot in the sb_plugin_entry_t registration structure. The ScatterBrain framework requires all plugin callback slots to be populated with valid function pointers, and stubs like this one fill slots for capabilities that the Install plugin does not support. Returns 0 indicating success without performing any operation.

#### stub_return_0_c (0x1800022E4, 3 bytes)

No-op stub function that unconditionally returns 0. Third and final stub in the sequence (stub_return_0_a at 0x1800022C4, stub_return_0_b at 0x1800022D4, stub_return_0_c at 0x1800022E4). Like its siblings, this fills an unimplemented callback slot in the plugin's sb_plugin_entry_t registration table. The existence of three separate stubs rather than reusing a single stub address suggests the framework may check for pointer equality or the original source code used distinct empty function definitions for clarity.

#### set_context_ptr (0x1800023A4, 10 bytes)

Stores the parent framework context pointer into the global variable g_pParentCtx and returns 0. The context pointer is provided by the inner PE framework when it loads and initializes the Install plugin via DllMain_dispatcher with fdwReason=100. The g_pParentCtx structure is the plugin's primary interface to the framework, containing function pointers for command signaling (offset +24 for command allocation, +32 for command submission), response callbacks (offset +136), and a pointer to the shared state block (offset +216) which holds the plugin's operating state and config data. Nearly every non-trivial function in the Install plugin reads g_pParentCtx to interact with the framework.

#### framework_wait_cmd (0x1800023B4, 94 bytes)

Signals the framework that the Install plugin is ready and then polls for an execution command. First allocates a framework command object via the callback at g_pParentCtx+24 with command ID 101 (READY status), writes 0 to signal clean status via the data accessor at cmd+56+8, and submits it via the callback at g_pParentCtx+32. Then enters a polling loop: every 1 second (g_pfnSleep(1000)) it calls the g_pParentCtx+24 callback with command ID 106 (EXECUTE request). If the returned command object is non-NULL, a command has arrived and the function returns the command data pointer obtained via the accessor at cmd+56+8. This polling mechanism is used in states 5-6 (the framework_wait_cmd path in vtfn_worker_init) where the plugin transitions from initialization to an active command-processing role, awaiting C2 instructions relayed through the inner PE framework.

#### decrypt_and_set_name (0x180002424, 57 bytes)

Decrypts the plugin's display name string and copies it to an output buffer provided by the framework. Calls decrypt_string with the encrypted blob enc_Install to recover the wide string "Install", then copies it to the param1 buffer via lstrcpyW. The decrypted temporary buffer is freed via sbstr_free. Returns 0 on success. This function is invoked by DllMain_dispatcher when fdwReason=102, which is the framework's name query command. The framework uses this name for logging, status display, and plugin identification in the C2 protocol. The decrypt_string call returns a structure where offset +16 contains the wide-string pointer.

#### install_service_entry (0x180002464, 345 bytes)

The Install plugin's service entry point that implements single-instance enforcement and Online plugin activation. First signals READY status (101) to the framework with value 1 (indicating service mode). Reads the plugin config via framework_read_config into a local buffer. Constructs a Global named mutex name by decrypting the prefix "Global\" from enc_Global, converting the config-provided instance ID from UTF-8 to wide via utf8_to_wide, and concatenating them via wstr_concat. The combined name is converted to ANSI via wide_to_ansi and passed to CreateMutexA. If CreateMutexA succeeds and GetLastError is NOT ERROR_ALREADY_EXISTS (183), the mutex is newly created and the plugin proceeds. If the mutex already exists, it checks the framework state at g_pParentCtx+216+12: if state != 3, the plugin terminates the process via TerminateProcess/ExitProcess (with an INT3 fallback if ExitProcess fails), enforcing single-instance. If state == 3 or the mutex was newly created, the function signals the Online plugin for activation.

#### vtfn_worker_init (0x1800025C4, 277 bytes)

Main worker initialization function registered as vtable slot 0 (g_vtable_slot1_init points here). This is the primary entry point called by the inner PE framework after plugin registration. First enables two Windows privileges by decrypting SeTcbPrivilege and SeDebugPrivilege from encrypted blobs and calling enable_privilege for each -- SeTcbPrivilege allows acting as part of the OS and SeDebugPrivilege allows opening any process including SYSTEM processes like winlogon.exe. Then allocates a 2136-byte config buffer and calls framework_decode_commands to decrypt the plugin's command configuration. Routes execution based on the framework state value at g_pParentCtx+216+12: states 2/3/4 (service installation modes) call install_service_entry directly; states 5/6 (command wait modes) call framework_wait_cmd to poll for C2 commands; any other state (initial execution) calls try_launch_commands to attempt process launching. If try_launch_commands succeeds (returns 0), the framework state is set to 2 and a new thread is spawned.

#### cmd1_write_vtable (0x1800026E4, 31 bytes)

Populates the 2-entry vtable used by the Install plugin by writing the function pointers for the two primary dispatch functions. Sets g_vtable_slot0_dispatch to vtfn_subcmd_dispatcher (the command processor that handles sub-commands from the C2 framework) and g_vtable_slot1_init to vtfn_worker_init (the main initialization and routing function). Returns 0 on success. This function is called during DllMain_dispatcher processing when fdwReason=1 (DLL_PROCESS_ATTACH), establishing the vtable before the framework queries it via get_vtable_ptr. The same vtable population logic is also inlined directly in DllMain_dispatcher for the fdwReason=1 case, making this function effectively a named helper for the same operation.

#### DllMain_dispatcher (0x180002714, 122 bytes)

The DLL entry point that serves as the central command dispatcher for the Install plugin, handling framework registration commands via the fdwReason parameter. Implements a switch on fdwReason: (1) DLL_PROCESS_ATTACH -- writes the vtable by setting g_vtable_slot0_dispatch=vtfn_subcmd_dispatcher and g_vtable_slot1_init=vtfn_worker_init; (100) stores the framework context pointer from lpReserved into g_pParentCtx, equivalent to set_context_ptr; (101) writes the plugin ID constant 103 to the DWORD at lpReserved, equivalent to get_plugin_id; (102) calls decrypt_and_set_name to decrypt the plugin name "Install" and copy it to the lpReserved buffer; (103) writes the address of g_vtable_slot0_dispatch to the QWORD at lpReserved, equivalent to get_vtable_ptr. The fdwReason values 100-103 are ScatterBrain-specific plugin protocol commands overlaid on the standard DllMain reason codes. Returns TRUE (1) if the operation succeeded (status_4==0) or FALSE (0) on failure. The hinstDLL parameter is unused.

#### framework_read_config (0x180002790, 85 bytes)

Reads a portion of the plugin's configuration blob from the Config plugin (ID 102) via the framework inter-plugin communication mechanism. Acquires a reference to plugin 102 by calling the g_pParentCtx+24 allocator with command ID 102, then invokes the config plugin's read method at vtable offset 16 (the third method in the Config vtable) with parameters: output_buffer=param1, offset=16, field_id=48, total_size=20300. The offset 16 and field 48 identify the specific config region to read, and 20300 is the total config blob capacity. After the read, the reference is released via g_pParentCtx+32. Returns the status code from the config read operation. The 20300-byte config blob contains the encrypted command strings, instance IDs, and other operational parameters for the Install plugin. This function is called by install_service_entry to read config data for mutex naming.

#### framework_decode_commands (0x1800027F0, 84 bytes)

Decodes command entries from the Config plugin (ID 102) into a caller-provided output buffer. Acquires a reference to plugin 102 via the g_pParentCtx+24 callback, then calls the config plugin's decode method at vtable offset 8 (the second method) with the output buffer (param1) and a mode flag (param2). When param2=0, the decode populates the buffer with raw command data for vtfn_worker_init initial routing; when param2=1, it populates for try_launch_commands process execution. The output buffer is 2136 bytes and contains a header with command string offset table at +16 (four WORD offsets) and the actual encrypted command strings starting at +88. After decoding, the reference is released via g_pParentCtx+32. Returns the status code from the decode operation (0 on success). This function bridges the Install plugin to the Config plugin for command retrieval.

#### framework_send_response (0x180002850, 90 bytes)

Sends a response buffer back to the C2 controller via the Online plugin (ID 104). Acquires a reference to plugin 104 (Online, the C2 communication router) via g_pParentCtx+24, then calls the Online plugin's send method at vtable offset 72 (the 10th method in the Online 14-entry vtable) with the response data pointer (param1), the response buffer (param2), and a size sentinel of 0xFFFFFFFF (-1, meaning auto-detect length). After sending, the reference is released via g_pParentCtx+32. Returns the status code from the send operation (0 on success). This function is used by subcmd_query_status and subcmd_launch_process to transmit command acknowledgments and results back to the C2 server. The Online plugin handles the actual network transmission via whichever transport protocol (TCP/HTTP/UDP/DNS) is currently active.

#### subcmd_launch_process (0x1800028AC, 131 bytes)

Handles sub-command 0x670081 (Launch Process) from the C2 controller. Receives a context pointer (ctx) and a command buffer (cmd_buf). Constructs a response by writing htonl(0x670081) at cmd_buf[1], htonl(0) at cmd_buf[2] and cmd_buf[3] as zero-padded acknowledgment fields, then sends the response via framework_send_response using the context from *ctx. If the send succeeds, the function sleeps for 3 seconds (three iterations of Sleep(1000)) to allow the response to be transmitted before the process state changes. After the delay, checks the framework state at g_pParentCtx+216+12: if state==4 (error/termination state), calls ExitProcess(0) followed by an INT3 (__debugbreak) as an unreachable crash guard. Otherwise returns the magic value 20000 which signals to vtfn_subcmd_dispatcher and the framework that a process launch should be triggered. If the send fails, returns the error code directly.

#### subcmd_query_status (0x18000293C, 73 bytes)

Handles sub-command 0x670080 (Query Status) from the C2 controller. Receives a context pointer (ctx) and command buffer (cmd_buf). Constructs a response by writing htonl(0x670080) = htonl(6750208) at cmd_buf[1] as the command echo, htonl(0) at cmd_buf[2] and cmd_buf[3] as zero-padded status fields (indicating all-OK with no error). Sends the response via framework_send_response using the context from *ctx. Returns the status code from framework_send_response (0 on success). This is a simple heartbeat/status acknowledgment -- the C2 server sends 0x670080 to check if the Install plugin is responsive, and this function echoes back the command ID with zero status fields. The htonl conversion ensures network byte order for the C2 protocol which uses big-endian command IDs.

#### vtfn_subcmd_dispatcher (0x18000298C, 76 bytes)

Vtable slot 0 function (g_vtable_slot0_dispatch): the Install plugin's sub-command dispatcher that routes incoming C2 commands to the appropriate handler. Receives a context handle (hinstDLL, reused parameter name from DllMain signature) and the raw command buffer (fdwReason). Extracts the command ID from offset +4 in the command buffer via ntohl (network-to-host byte order conversion) to get the big-endian 32-bit command code. Subtracts the base command ID 0x670080 (6750208 decimal) to compute the sub-command index. Dispatches: index 0 (cmd 0x670080) routes to subcmd_query_status for heartbeat/status queries; index 1 (cmd 0x670081) routes to subcmd_launch_process for process execution with token theft. Any other command index returns -1 (0xFFFFFFFF) to indicate an unrecognized command. The Install plugin only supports these two sub-commands, making it one of the simpler plugins in the ScatterBrain framework.

---

### Utility Functions

#### heap_free (0x180001AE8, 53 bytes)

Frees a heap allocation by calling LocalFree, which is lazily resolved via peb_resolve_api_hash(HASH_LocalFree) on first invocation and cached in g_pfnHeapFree for subsequent calls. The function performs a null-check on the input pointer before attempting the free, silently returning if ptr is NULL. This is one of the two fundamental memory management primitives in the Install plugin (paired with heap_alloc). It is called extensively throughout the codebase -- directly by process_launcher, try_launch_commands, and string functions, and indirectly via the thunk wrappers heap_free_thunk and heap_free_thunk2 which exist to provide stable function pointers for the framework callback table.

#### heap_alloc (0x180001B28, 54 bytes)

Allocates zero-initialized heap memory by calling LocalAlloc(LPTR=0x40, size), where LPTR combines LMEM_FIXED and LMEM_ZEROINIT flags. LocalAlloc is lazily resolved via peb_resolve_api_hash(HASH_LocalAlloc) on the first invocation and the resulting function pointer is cached in g_pfnHeapAlloc for all subsequent calls. The single parameter is the allocation size in bytes, and the return value is a pointer to the newly allocated and zeroed buffer. This is one of the two core memory management primitives in the plugin (paired with heap_free). It is used pervasively across the Install plugin for temporary buffers, config blobs, string operations, and process launch structures. The thunk wrapper heap_alloc_thunk provides a stable indirection layer for the framework callback table.

#### heap_free_thunk (0x180001B68, 5 bytes)

Trivial thunk wrapper that forwards directly to heap_free(ptr). This indirection exists so the Install plugin can expose a stable function pointer for memory deallocation in the framework callback/vtable structure. The compiler marks this as a thunk (single-instruction tail call). It is functionally identical to heap_free_thunk2 at 0x180001B78 -- both are separate thunks presumably generated for different callback slots or calling contexts within the ScatterBrain plugin registration mechanism.

#### heap_free_thunk2 (0x180001B78, 5 bytes)

Second trivial thunk wrapper that forwards directly to heap_free(ptr). Like heap_free_thunk at 0x180001B68, this provides a separate stable function pointer for memory deallocation, likely used in a different callback slot within the ScatterBrain framework plugin interface. Having two distinct thunks for the same underlying function allows the framework to register separate free callbacks for different allocation contexts (e.g., one for framework-owned buffers and one for plugin-owned buffers) while both ultimately route to the same LocalFree-based heap_free implementation.

#### heap_alloc_thunk (0x180001B88, 5 bytes)

Trivial thunk wrapper that forwards directly to heap_alloc(size). This indirection provides a stable function pointer for memory allocation that can be registered in the ScatterBrain framework plugin callback/vtable structure. The compiler marks this as a thunk (single-instruction tail call to heap_alloc). It serves as the allocation counterpart to heap_free_thunk and heap_free_thunk2, allowing the framework to invoke the plugin's memory allocator through a uniform function-pointer interface without directly referencing the underlying LocalAlloc-based heap_alloc.

#### utf8_to_wide (0x1800029D8, 233 bytes)

Converts a UTF-8 encoded string to UTF-16LE (wide) using the Windows MultiByteToWideChar API, which is lazily resolved via peb_resolve_api_hash(HASH_MultiByteToWideChar) and cached in g_pfnMultiByteToWideChar. The conversion uses code page 65001 (CP_UTF8) with no flags. First calls MultiByteToWideChar with a NULL output buffer and length -1 (null-terminated input) to determine the required buffer size, then allocates a buffer of size*2 bytes via heap_alloc (using saturated multiplication to prevent overflow), and performs the actual conversion. The result is stored in the sbstr structure at param1: the wide string pointer goes to offset +16 and the character count to offset +24. Before writing, any pre-existing ANSI buffer (offset 0) and wide buffer (offset 16) are freed via heap_free and zeroed. Returns 0 on success or 8 (ERROR_NOT_ENOUGH_MEMORY) if the allocation fails. This function is called by decrypt_string, sbstr_from_utf8, and directly by various functions needing string encoding conversion.

#### wide_to_ansi (0x180002AC8, 188 bytes)

Converts the wide (UTF-16LE) string stored in an sbstr object at offset +16 to ANSI (system default code page) using WideCharToMultiByte, which is lazily resolved via peb_resolve_api_hash(HASH_WideCharToMultiByte) and cached in g_pfnWideCharToMultiByte. First calls WideCharToMultiByte with code page 0 (CP_ACP), no flags, the wide string pointer from offset +16, its length from offset +24, and NULL output to determine the required ANSI buffer size. Then allocates the buffer via heap_alloc and performs the actual conversion. The old ANSI buffer (if any) at offset 0 is freed and replaced with the new ANSI string pointer, and the length is stored at offset +8. Returns the ANSI string pointer on success, or 0 (NULL) if the allocation fails. This function is the counterpart to utf8_to_wide and is used extensively by the resolve_import_* functions to convert decrypted wide DLL/API names to ANSI for GetProcAddress calls.

#### sbstr_free (0x180002B98, 59 bytes)

Frees all memory associated with an sbstr (ScatterBrain string) object and resets it to a clean empty state. The sbstr structure is 28 bytes (0x1C) with layout: [QWORD ansi_ptr at +0, DWORD ansi_len at +8, QWORD wide_ptr at +16, DWORD wide_len at +24]. This function checks each pointer (ANSI at offset 0, wide at offset 16) for non-NULL, calls heap_free on the pointer if present, then zeros both the pointer and its associated length field. This is the universal cleanup function for sbstr objects throughout the Install plugin -- called after every decrypt_string usage, after wide_to_ansi conversions, and in string manipulation functions like wstr_concat and wstr_copy when replacing existing content. The function handles partially-initialized sbstr objects gracefully (e.g., an sbstr with only a wide string but no ANSI string).

#### decrypt_string (0x180002BE8, 185 bytes)

Decrypts an encrypted string blob using the ScatterBrain IMUL rolling XOR cipher and returns the result as a wide string in an sbstr structure. The encrypted blob (out_buf parameter, despite the misleading name) starts with a 2-byte little-endian seed (out_buf[0] | out_buf[1]<<8) followed by the encrypted payload starting at out_buf+2. Allocates a 4096-byte temporary buffer via heap_alloc and decrypts byte-by-byte: each plaintext byte is computed as (key_state XOR encrypted_byte), and the key state is updated via the polynomial feedback: key = -42860544 * key - 135791246 * HIWORD(key) - 1043215206 (the IMUL cipher). Decryption stops on a null terminator or after 4090 bytes (buffer overflow guard). The resulting UTF-8 plaintext is then converted to UTF-16LE via utf8_to_wide and stored in the sbstr object at enc_blob (the first parameter, which serves as the output). The temporary buffer is freed. Returns a pointer to the sbstr object. This is the core string decryption primitive used throughout the Install plugin for all 30 encrypted strings.

#### sbstr_from_utf8 (0x180002CA8, 38 bytes)

Initializes an sbstr object from a raw UTF-8 byte buffer. Zeros all four fields of the sbstr structure (ANSI ptr at +0, ANSI len at +8, wide ptr at +16, wide len at +24) to ensure a clean state, then calls utf8_to_wide to perform the UTF-8 to UTF-16LE conversion and populate the wide string fields. Returns the sbstr pointer (str_obj). This is a convenience wrapper that combines zero-initialization with UTF-8 import in a single call, used when constructing an sbstr from a known UTF-8 source buffer. Unlike decrypt_string which also produces an sbstr from encrypted data, this function takes plaintext UTF-8 input directly.

#### wstr_concat (0x180002CD8, 397 bytes)

Concatenates a wide string (src) onto the existing wide string in an sbstr object (str_obj). Lazily resolves three kernel32.dll string APIs via resolve_import_kernel32: lstrlenW (cached in g_pfnResolvedLstrlenW), lstrcpyW (cached in g_pfnResolvedLstrcpyW), and lstrcatW (cached in g_pfnResolvedLstrcatW), each decrypted from their respective encrypted name blobs. Computes the total required length as lstrlenW(src) + existing_wide_len (from str_obj+24), allocates a new buffer of total_len*2 bytes via heap_alloc (using saturated multiplication for overflow safety). Copies the existing wide string into the new buffer via lstrcpyW, then appends src via lstrcatW. Frees both the old ANSI buffer (offset 0) and old wide buffer (offset 16) via heap_free, zeroing their pointers and lengths, then stores the new concatenated buffer at offset +16 and the new length at offset +24. Returns 0 on success or 8 (ERROR_NOT_ENOUGH_MEMORY) if allocation fails. Called by install_service_entry to build the "Global\" mutex name from prefix and instance ID.

#### wstr_copy (0x180002E78, 299 bytes)

Copies a wide string (src) into an sbstr object (str_obj), replacing any existing content. Lazily resolves lstrlenW and lstrcpyW from kernel32.dll via resolve_import_kernel32, decrypting their names from encrypted blobs and caching the function pointers in g_pfnResolvedLstrlenW and g_pfnResolvedLstrcpyW respectively. Computes the required buffer size as (lstrlenW(src) + 1) * 2 bytes (the +1 accounts for the null terminator), allocates via heap_alloc with saturated multiplication for overflow protection. Copies the source string into the new buffer via lstrcpyW. Frees both the old ANSI buffer (offset 0) and old wide buffer (offset 16) of the sbstr, then stores the new buffer pointer at offset +16 and the character count (including null) at offset +24. Returns 0 on success or 8 (ERROR_NOT_ENOUGH_MEMORY) if allocation fails. This function is the fundamental wide string assignment operation for sbstr objects, used by wstr_init_empty, process_launcher, create_process_direct, and install_service_entry.

#### wstr_init_empty (0x180002FB8, 45 bytes)

Initializes an sbstr object to an empty wide string state. Zeros all four fields of the 28-byte sbstr structure (ANSI ptr at +0, ANSI len at +8, wide ptr at +16, wide len at +24), then calls wstr_copy(str_obj, g_wEmptyString) to copy the global empty wide string (a single null wide character) into the sbstr. This two-step process ensures the sbstr has a valid allocated wide string buffer (not just a NULL pointer) so that subsequent operations like wstr_concat can safely read from it without null-pointer checks. Returns the sbstr pointer. This function is the standard way to create a fresh sbstr before building up a string through concatenation, used by process_launcher, create_process_direct, and install_service_entry.
