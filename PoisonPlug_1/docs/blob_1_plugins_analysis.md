# Blob 1 — Registry Persistence Plugin ("Plugins")

## Summary

| Property | Value |
|----------|-------|
| File | Private archive artifact (available on vetted request) |
| Image Size | 0x5000 (20480 bytes) |
| Entry Point RVA | 0x10A4 |
| Functions | 34 (all renamed) |
| Sections | .text, .rdata, .data2, .data3, .idata |
| Timestamp | 0x58AEBA (2017-02-22/23) |
| idasql Port | 8201 |
| Version (CMD 101) | 101 |
| Plugin ID (CMD 102) | `"Plugins"` (encrypted) |
| Sub-command Base | 0x650000 |

## Role

**Registry-based persistence and plugin storage.** Manages encrypted plugin data blobs in the Windows Registry under `HKLM\SOFTWARE\Microsoft\{numeric_id}`. Validates packed PE format before writing, monitors registry keys for external changes via `RegNotifyChangeKeyValue`, and supports CRUD operations on stored plugins.

## Imports (12 functions, 3 DLLs)

### KERNEL32.dll (6 functions)
- GetProcAddress, GetModuleHandleA, lstrcmpiA, GetTickCount, CloseHandle, CreateThread

### USER32.dll (1 function)
- SetUnhandledExceptionFilter

### ADVAPI32.dll (5 functions)
- **RegOpenKeyExW**, **RegEnumValueW**, **RegDeleteValueW**, **RegCloseKey**, **RegQueryValueExW**

## Entry Point: DllMain_dispatcher (0x1800010A4)

| fdwReason | Command | Action |
|-----------|---------|--------|
| 0 | DLL_PROCESS_DETACH | No-op |
| 1 | CMD 1 (Attach) | Populates 5-slot vtable |
| 100 | CMD 100 | Stores parent context pointer |
| 101 | CMD 101 | Returns version 101 |
| 102 | CMD 102 | Decrypts "Plugins" string, copies to output |
| 103 | CMD 103 | Reads config, validates, triggers worker |
| 104 | CMD 104 | Returns vtable pointer |

## Vtable (5 entries)

| Slot | Address | Function | Purpose |
|------|---------|----------|---------|
| 0 | - | `vtfn_subcmd_dispatch` | Sub-command router: 0x650000-0x650004 |
| 1 | - | `vtfn_worker_entry` | Worker init: resolves APIs, spawns monitoring thread |
| 2 | - | `vtfn_enum_plugins` | Enumerate stored plugins from registry |
| 3 | - | `vtfn_query_plugin` | Query specific plugin by name |
| 4 | - | `vtfn_delete_plugin` | Delete specific plugin from registry |

## Sub-command Dispatch (base 0x650000)

| Sub-cmd | ID | Handler | Purpose |
|---------|----|---------|---------|
| 0 | 0x650000 | Store plugin | Validates packed PE magic, writes to registry |
| 1 | 0x650001 | List plugins | Enumerates registry values, returns names |
| 2 | 0x650002 | Read plugin | Reads specific plugin blob from registry |
| 3 | 0x650003 | Delete plugin | Removes specific registry value |
| 4 | 0x650004 | Update plugin | Overwrites existing plugin blob |

## Registry Operations

### Path Construction
- Base path: `HKLM\SOFTWARE\Microsoft\{numeric_id}`
- The `{numeric_id}` is derived from the parent orchestrator's config
- Each plugin stored as a named value under this key
- Values contain encrypted packed PE blobs

### PE Validation Before Write
Before storing a plugin blob, the code validates:
1. Minimum size check
2. Packed PE magic: `magic0 ^ magic1 == 0x7C35D9A3`
3. This prevents corrupt data from being persisted

### Registry Monitoring
- Worker thread calls `RegNotifyChangeKeyValue` with `REG_NOTIFY_CHANGE_LAST_SET`
- Blocks until a value is modified externally
- On change: re-reads and validates all stored plugins
- This allows the C2 to update plugins via registry writes from other tools

## Encrypted Strings (20 total)

Key strings include:
- `SOFTWARE\Microsoft\` — Registry key base path
- `Plugins` — Plugin ID string
- `RegNotifyChangeKeyValue` — API for registry monitoring
- `RegCreateKeyExW` — API for key creation
- `RegSetValueExW` — API for value writing
- `advapi32.dll` — DLL for registry APIs
- `kernel32.dll`, `msvcrt.dll` — Support DLLs
- `memset`, `memcpy` — CRT functions
- `SetUnhandledExceptionFilter` — Exception handler setup
- `TerminateThread` — Thread cleanup

## Self-Protection
- `SetUnhandledExceptionFilter` installed to catch crashes gracefully
- `TerminateThread` used for cleanup on fatal errors
- Worker thread auto-restarts on registry change notification

## Detailed Function Reference

All 34 functions in the Plugins blob, grouped by functional category.

---

### API Resolution / Import Helpers

#### resolve_kernel32_proc (0x180001000, 161 bytes)

Resolves a kernel32.dll API procedure by its ANSI name string. On first call, lazily obtains the kernel32 module handle by decrypting the string "kernel32.dll" via decrypt_string() and passing it to GetModuleHandleA (or LoadLibraryA if not yet resolved). The resolved module handle is cached in g_hKernel32 for subsequent calls. The actual procedure lookup is performed via GetProcAddress, which is itself lazily resolved through api_hash_resolve(HASH_GetProcAddress) and cached in g_pfnRegNotifyChangeKeyValue_2 (a misnamed global). Takes a single parameter: an ANSI string pointer to the desired API name. Returns the procedure address as a 64-bit integer, or implicitly returns NULL if GetProcAddress fails. This function is the primary mechanism by which the Plugins blob resolves kernel32 APIs that are not available via the PEB hash walk.

#### api_hash_resolve (0x18000124C, 241 bytes)

Resolves a Windows API function address by its pre-computed export name hash. Walks the PEB InLoadOrderModuleList to enumerate loaded modules, hashing each DLL name with a case-insensitive ROR8/XOR algorithm (constant 0x7C35D9A3) until finding kernel32.dll (expected hash result -44363167 / 0xFD578A81). Then iterates the kernel32 export directory, hashing each export name with the same ROR8/XOR algorithm and comparing against the target hash parameter. Takes a single api_hash_t parameter (the target hash). Returns a void pointer to the resolved API, or NULL if not found. The hash algorithm lowercases each character with OR 0x20 before mixing, making it case-insensitive. This is the bootstrap resolver used before any named imports are available, providing initial access to LoadLibraryA, GetProcAddress, LocalAlloc, LocalFree, and other critical APIs.

#### resolve_ws2_32_proc (0x1800015D8, 161 bytes)

Resolves a procedure from ws2_32.dll (Windows Sockets) by its ANSI name string. On first call, lazily loads ws2_32.dll by decrypting the string "ws2_32.dll" via decrypt_string() and loading it through GetModuleHandleA (or LoadLibraryA if the module handle resolver is not yet cached). The ws2_32 module handle is cached in g_hWs2_32 for subsequent calls. Performs the actual procedure lookup using GetProcAddress, lazily resolved via api_hash_resolve(HASH_GetProcAddress) and cached in g_pfnRegNotifyChangeKeyValue_2. Takes a single parameter: an ANSI string pointer to the desired ws2_32 export name. Returns the resolved procedure address. This function is structurally identical to resolve_kernel32_proc but targets ws2_32.dll. It is used to resolve ntohl for network byte order conversion in the response protocol.

#### resolve_advapi32_proc (0x1800031E0, 161 bytes)

Resolves a procedure from advapi32.dll by its ANSI name string. Structurally identical to resolve_kernel32_proc and resolve_ws2_32_proc but targets advapi32.dll. On first call, lazily loads advapi32.dll by decrypting the encrypted string for the module name and loading it via GetModuleHandleA (or LoadLibraryA if the shared module handle resolver is not yet cached). The advapi32 module handle is cached in g_hAdvapi32 for subsequent calls. Performs the actual procedure lookup using GetProcAddress, lazily resolved via api_hash_resolve(HASH_GetProcAddress) and cached in g_pfnRegNotifyChangeKeyValue_2. Takes a single parameter: an ANSI string pointer to the desired advapi32 export name. Returns the resolved function address. This is used to resolve registry APIs including RegCloseKey, RegSetValueExW, RegCreateKeyExW, and RegNotifyChangeKeyValue.

#### memcpy_wrapper (0x1800014C0, 278 bytes)

Wrapper around the C runtime memcpy function, resolved from msvcrt.dll. On first invocation, decrypts the strings "memcpy" and "msvcrt.dll", loads msvcrt.dll via GetModuleHandleA (or LoadLibraryA as fallback), then resolves the memcpy export via GetProcAddress. The resolved msvcrt module handle is cached in g_pfnmemcpy and the memcpy function pointer in g_pfnmemcpy_2. Takes three parameters: destination pointer, source pointer, and byte count, matching the standard memcpy signature. Returns the destination pointer. Uses the same lazy resolution pattern as resolve_kernel32_proc and resolve_ws2_32_proc, reusing the shared g_pfnGetModuleHandleA and g_pfnRegNotifyChangeKeyValue_2 (GetProcAddress) globals. Called by send_response_with_data and other functions that need raw memory copying.

---

### Plugin Protocol / Dispatch

#### DllMain_dispatcher (0x1800010A4, 310 bytes)

Main entry point and command dispatcher for the Plugins plugin DLL (version 101, ID string "Plugins"). Implements the ScatterBrain plugin command protocol via DllMain fdwReason overloading. CMD 1 (DLL_PROCESS_ATTACH): populates the 5-entry vtable at g_vtable with pointers to vtfn_cmd_dispatch, vtfn_spawn_worker, vtfn_reg_query_value, vtfn_reg_set_value, and vtfn_reg_delete_value, and installs the unhandled_exception_filter via SetUnhandledExceptionFilter. CMD 100: stores the host context pointer (lpReserved) in g_pParentCtx for callbacks to the inner PE. CMD 101: returns the plugin version number 101 via the lpReserved output pointer. CMD 102: writes the integer version 101 to the DWORD at lpReserved. CMD 103: decrypts the plugin ID string "Plugins" and copies it to the wide-char buffer at lpReserved using lstrcpyW. CMD 104: stores a pointer to g_vtable_cmd_dispatch in the output. Always returns TRUE (1) regardless of command. The nested if-else chain subtracts command IDs sequentially (1, then 99, then 1, 1, ...) to route to the correct handler.

#### vtfn_cmd_dispatch (0x18000167C, 206 bytes)

Vtable command dispatcher (vtable slot 1) that routes incoming C2 commands to the appropriate registry subcommand handler. Reads the subcmd DWORD from cmd_buf+4, converts from network byte order via ntohl (lazily resolved from ws2_32.dll), then subtracts the base command ID 0x650000 (6619136 decimal) and dispatches through a sequential if-chain: subcmd 0x650000 -> subcmd_enum_reg_values (enumerate all registry values), 0x650001 -> subcmd_write_reg_value, 0x650002 -> subcmd_read_reg_value, 0x650003 -> subcmd_delete_reg_value, 0x650004 -> subcmd_check_reg_value. Returns -1 (0xFFFFFFFF) for any unrecognized subcommand. Takes two parameters: ctx (the session context pointer) and cmd_buf (the raw command buffer from the C2 channel). The 0x65xxxx command range is unique to the Plugins blob (plugin ID 101).

#### unhandled_exception_filter (0x180001340, 37 bytes)

Unhandled exception filter callback installed by DllMain_dispatcher during CMD 1 (DLL_PROCESS_ATTACH). When an unhandled exception occurs, this function extracts the exception code from the EXCEPTION_POINTERS->ExceptionRecord->ExceptionCode field (first dereference of the input pointer), then calls GetCurrentThread() followed by TerminateThread() with the exception code as the exit status. This effectively silences all unhandled exceptions by terminating only the faulting thread rather than crashing the entire process, which is an anti-debugging and stealth technique. Returns the constant 1064 (though this is unreachable since TerminateThread does not return). Both GetCurrentThread and TerminateThread are pre-resolved and stored in globals g_pfnGetCurrentThread and g_pfnTerminateThread.

#### send_response (0x180001368, 90 bytes)

Sends a data-less response message back to the C2 framework through the host context callback interface. First allocates a response buffer by calling the host context vtable function at g_pParentCtx+24 with argument 104 (the Plugins plugin command ID). Then invokes the send callback at vtable offset 72 from the allocated buffer object (at buf+56), passing the caller-supplied this_ptr and param1 along with a sentinel size of 0xFFFFFFFF indicating no data payload. After sending, frees the buffer via the host context vtable at g_pParentCtx+32. Returns the result of the send callback as an unsigned 32-bit status code. This function is used for acknowledgment-only responses where no data needs to be returned to the C2 operator.

#### send_response_with_data (0x1800013C4, 250 bytes)

Sends a response message with an attached data payload back to the C2 framework. Converts the network-byte-order size field from the command buffer (dw_arg1[3]) to host order using ntohl (lazily resolved from ws2_32.dll via resolve_ws2_32_proc). Allocates a response buffer of size (data_len + 20) through the host context vtable at g_pParentCtx+160, where 20 bytes is the response header overhead. Copies three DWORD header fields from the command buffer (offsets +4, +8, +12 corresponding to dw_arg1[1..3]) into the response header, then copies the actual data payload via memcpy_wrapper into the response at offset +20. Calls send_response() to transmit the assembled message, then frees the response buffer via g_pParentCtx+192. Returns 0 on success or a non-zero error code if the buffer allocation fails (short-circuits without sending). This is the primary data-bearing response path used by all subcmd handlers.

---

### Registry CRUD Commands

#### subcmd_enum_reg_values (0x18000174C, 777 bytes)

Handles subcmd 0x650000: enumerates all registry values under the plugin persistence key and serializes them into a single response buffer. Acquires a lock via the host context vtable (g_pParentCtx+56), then iterates the synced linked list using get_first (offset +72) and get_next (offset +80) callbacks. For each list entry, reads the value name via the host context read callback (offset +48) into a 2048-byte stack buffer, converts it to ANSI via str_to_ansi with codepage 0xFDE9, then serializes the entry into the output buffer: ANSI name bytes, a 0x01 separator byte, followed by seven DWORDs from the entry structure at offsets +16, +20, +24, +28, +32, +36, +44, and finally a QWORD from offset +48. After iteration, releases the lock (g_pParentCtx+64), sets the response subcmd to htonl(0x650000), status to htonl(0), and size to htonl(serialized_length), then calls send_response_with_data to transmit. Frees the serialized buffer if non-NULL. This provides the C2 operator with a complete snapshot of all persisted plugin entries.

#### subcmd_write_reg_value (0x180001A58, 1019 bytes)

Handles subcmd 0x650001: writes a registry value to the plugin persistence key under SOFTWARE\Microsoft\{id}. First builds the registry key path via build_reg_key_path, then validates the command payload with a magic XOR check (cmd_buf[5] ^ cmd_buf[6] must equal 0x7C35D9A3) and a marker word check (cmd_buf[16] must be 523/0x020B). If validation fails, returns error 193 (ERROR_BAD_EXE_FORMAT). Decrypts the value name from the command buffer, converts it to wide string, then attempts RegSetValueExW on HKLM (0x80000002) first; if that fails (likely due to insufficient privileges), falls back to HKCU (0x80000001) with registry type 3 (REG_BINARY). After the write, sleeps for 1000ms (lazily resolving Sleep from kernel32). Constructs the response with subcmd htonl(0x650001), status code in field 2, and zero data length. If the host context lookup by plugin ID indicates the entry is already marked (field at offset +32 is non-zero), returns error 50 without writing. This is the primary mechanism for C2-directed plugin persistence writes.

#### subcmd_read_reg_value (0x180001E54, 531 bytes)

Handles subcmd 0x650002: reads a registry value and sends the result back to the C2 operator. Extracts the data length from cmd_buf[3] via ntohl, then copies the payload bytes (starting at cmd_buf+20) into a local buffer via buf_append. Parses the value name as a null-terminated ANSI string from the start of the payload, converts it to wide char via mb_to_wchar (codepage 0xFDE9), then invokes the host context registry query callback at g_pParentCtx+96 to perform the actual RegQueryValueExW. The query result status is stored and converted to network byte order. Constructs the response header with subcmd htonl(0x650002), the query status in field 2, and zero data length in field 3. Sends the response via send_response (data-less, status only). Cleans up the wide string buffer and frees any heap-allocated payload buffer. Returns the send_response result. This is the read counterpart to subcmd_write_reg_value.

#### subcmd_delete_reg_value (0x180002068, 764 bytes)

Handles subcmd 0x650003: deletes a registry value from both HKLM and HKCU persistence keys. Builds the registry key path via build_reg_key_path, extracts the data payload length via ntohl(cmd_buf[3]), copies payload into local buffer, then reads an 8-byte plugin identifier from the payload. Looks up the plugin entry via host context callback at g_pParentCtx+16. If the entry is found and its field at offset +32 is non-zero, returns error 50 (entry is locked/active). Otherwise, invokes the host context unmark callback at g_pParentCtx+40, then checks offset +40; if zero, decrypts the value name string, converts to wide char (codepage 0xFDE9), and calls vtfn_reg_delete_value twice: once with HKLM (0x80000002) and once with HKCU (0x80000001), ensuring the value is removed from both hives. Frees the plugin entry reference via g_pParentCtx+32. Constructs the response with subcmd htonl(0x650003), status in field 2, and zero data length. This is the deletion counterpart to subcmd_write_reg_value.

#### subcmd_check_reg_value (0x180002364, 425 bytes)

Handles subcmd 0x650004: checks whether a plugin entry (identified by its numeric ID) exists in the host context synced list. Converts the cmd_buf[2] field from network byte order via ntohl, then queries the host context lookup callback at g_pParentCtx+24 with the resulting ID. If the lookup returns a non-NULL entry, the function sets a 1-byte boolean payload to 1 (true/exists) and releases the entry reference via g_pParentCtx+32. If the lookup returns NULL, the payload byte defaults to 1 but the data size (ret_val) encodes 0, effectively signaling absence. Constructs the response header with subcmd htonl(0x650004), status htonl(0), and data size htonl(ret_val), then sends via send_response_with_data with the 1-byte boolean payload. This is used by the C2 operator to verify whether a specific plugin is currently registered in the persistence store before issuing write or delete commands.

---

### Registry Primitives

#### vtfn_reg_query_value (0x180002FCC, 192 bytes)

Vtable function (slot 2): queries a registry value from the persistence key. Opens the registry key using RegOpenKeyExW with the specified root key handle (ctx), subkey path (cmd_buf), and access mask KEY_QUERY_VALUE (0x1). If the key opens successfully, initializes the output size parameter (arg5) with the caller-provided buffer size (arg4), then calls RegQueryValueExW to read the value named by cmd_size into the buffer at arg3. After the query, closes the key handle via RegCloseKey (lazily resolved from advapi32.dll). Returns the RegQueryValueExW result code on success, or the RegOpenKeyExW error code if the key could not be opened. This function provides the low-level registry read primitive used by the subcmd_read_reg_value handler and the reg_enum_and_sync synchronization logic.

#### vtfn_reg_set_value (0x18000308C, 266 bytes)

Vtable function (slot 3): sets a registry value in the persistence key. Opens or creates the registry key using reg_open_key_wrapper (which calls RegCreateKeyExW) with the specified root key handle (ctx), subkey path (cmd_buf), and access mask KEY_SET_VALUE (0x2). If the key opens successfully, lazily resolves RegSetValueExW from advapi32.dll, then writes the value named by cmd_size with the specified type (arg5), data buffer (arg3), and data size (arg4). After the write, closes the key handle via RegCloseKey (lazily resolved from advapi32.dll). Returns the RegSetValueExW result code on success, or the RegCreateKeyExW error code if the key could not be created. This is the low-level write primitive used by subcmd_write_reg_value, which calls it first with HKLM then falls back to HKCU.

#### vtfn_reg_delete_value (0x180003198, 71 bytes)

Vtable function (slot 4): deletes a registry value from the persistence key. Opens the registry key using RegOpenKeyExW with the specified root key handle (ctx), subkey path (cmd_buf), and access mask 0x20006 (KEY_SET_VALUE | KEY_CREATE_SUB_KEY | DELETE combined). If the key opens successfully, calls RegDeleteValueW to remove the value named by cmd_size, then closes the key handle via g_pfnRegCloseKey_fw (a pre-resolved forwarded RegCloseKey pointer). Returns 0 on success, or the RegOpenKeyExW error code if the key could not be opened. Unlike vtfn_reg_query_value and vtfn_reg_set_value, this function uses pre-resolved function pointers (g_pfnRegDeleteValueW and g_pfnRegCloseKey_fw) rather than lazy resolution, indicating these were resolved earlier during initialization. Called by subcmd_delete_reg_value which invokes it twice: once for HKLM and once for HKCU.

#### reg_open_key_wrapper (0x180003284, 164 bytes)

Wrapper around RegCreateKeyExW that creates or opens a registry key. Lazily resolves RegCreateKeyExW from advapi32.dll by decrypting the API name string and calling resolve_advapi32_proc. The resolved function pointer is cached in g_pfnRegCreateKeyExW. Calls RegCreateKeyExW with the provided root key handle (this_ptr), subkey path (param1), and desired access (param2), while passing NULL/0 for the class, options, security attributes, and disposition parameters. The output key handle is written to the address specified by param3. Returns the RegCreateKeyExW result code (ERROR_SUCCESS on success). This function is used by vtfn_reg_set_value and worker_thread_entry to open the persistence key with write access, as opposed to vtfn_reg_query_value and vtfn_reg_delete_value which use RegOpenKeyExW directly.

#### build_reg_key_path (0x180002D94, 568 bytes)

Builds the full registry key path for plugin persistence under SOFTWARE\Microsoft\{random_id}. Retrieves the plugin identifier by calling the host context lookup callback at g_pParentCtx+24 with ID 102 (the Config blob), then invokes the config object vtable function at offset +16 from the object pointer (at obj+56) with parameters (5, 12, 0xB1071D0D) to generate a pseudorandom identifier string. Capitalizes the first and third characters of the generated string by clearing the 0x20 bit (forcing uppercase ASCII). Decrypts the encrypted string for the registry prefix path (SOFTWARE\Microsoft\) and copies it into the output wide string buffer. Converts the random ANSI identifier to wide char via mb_to_wchar, computes the total path length, allocates a new buffer, copies the prefix via lstrcpyW, then appends the random subkey name via lstrcatW. Frees the old string buffers in the output structure and stores the new concatenated path. All kernel32 string APIs (lstrcpyW, lstrcatW, lstrlenW) are lazily resolved. Returns 0 on success.

---

### Worker Thread / Registry Monitor

#### vtfn_spawn_worker (0x180002510, 201 bytes)

Vtable function (slot 0): spawns a background worker thread for registry monitoring. Lazily resolves CreateThread from kernel32.dll by decrypting the API name string, then creates a new thread with worker_thread_entry as the start routine, passing the ctx parameter as the thread argument. After thread creation, immediately closes the thread handle via CloseHandle (also lazily resolved) to avoid handle leaks, since the thread runs detached. Returns 0 unconditionally. The worker thread will build the registry key path, open the persistence key under HKLM or HKCU, and enter the reg_monitor_loop to watch for external changes to the plugin registry values. This is called by the inner PE during plugin initialization to start the background sync mechanism.

#### worker_thread_entry (0x1800025DC, 241 bytes)

Worker thread entry point spawned by vtfn_spawn_worker. Builds the full registry key path via build_reg_key_path, then attempts to open the persistence key. If the ctx parameter (this_ptr) is non-zero, uses reg_open_key_wrapper (which calls RegCreateKeyExW) with HKLM (0x80000002) and access mask 0x3FFFF (KEY_ALL_ACCESS minus reserved bits), falling back to HKCU (0x80000001) if HKLM access is denied. If this_ptr is zero, uses RegOpenKeyExW directly on HKLM with access 0x20019 (KEY_READ | KEY_NOTIFY). On successful key open, enters reg_monitor_loop which blocks indefinitely watching for registry changes. After the monitor loop exits (due to error), closes the registry key handle via RegCloseKey (lazily resolved from advapi32.dll) and cleans up the key path string. Returns 0. The HKLM-first-then-HKCU pattern allows the plugin to work under both elevated and non-elevated contexts.

#### reg_monitor_loop (0x1800026D0, 332 bytes)

Registry change monitoring loop that watches the persistence key for modifications and re-synchronizes the in-memory plugin list. Resolves RegNotifyChangeKeyValue from advapi32.dll using a two-step process: first loads advapi32 via the shared module loader, then resolves the function via GetProcAddress. Creates a manual-reset event via CreateEventW(NULL, TRUE, FALSE) for change notifications. Enters an infinite loop: calls reg_enum_and_sync to synchronize registry state with the in-memory list, then registers for change notification via RegNotifyChangeKeyValue(hKey, FALSE, REG_NOTIFY_CHANGE_LAST_SET=4, hEvent, TRUE) for asynchronous monitoring, and blocks on WaitForSingleObject(hEvent, INFINITE). The loop exits only if RegNotifyChangeKeyValue returns a non-zero error code. On exit, closes the event handle via CloseHandle if non-NULL and returns the error code. This provides real-time detection of external registry modifications (e.g., by other processes or the operator) and keeps the in-memory plugin state consistent.

#### reg_enum_and_sync (0x18000281C, 1397 bytes)

Core registry-to-memory synchronization function. Enumerates all values under the persistence registry key using RegEnumValueW in a loop, allocating dynamically-sized buffers for value names (initial 0x8000 bytes) and data (initial 1024 bytes), growing them as needed when ERROR_MORE_DATA (234) is returned. Filters entries by checking if htonl(type_field) equals 0x650001 (the plugin write marker), skipping non-matching entries. For each matching entry, allocates a 48-byte linked list node, stores the plugin ID at offset +16 and size at offset +20 (both converted via ntohl), and appends the raw data via buf_append at offset +24. After enumeration completes (ERROR_NO_MORE_ITEMS = 259), acquires the host context lock (g_pParentCtx+56), iterates the existing synced list via get_first/get_next (offsets +72/+80), and diffs against the newly-built local list. Stale entries (present in the synced list but not the local list, identified by matching fields at offsets +24/+28) are removed via the unmark callback (g_pParentCtx+40). New entries (in the local list but not the synced list) are added via the host context add callback. Releases the lock after synchronization is complete.

---

### Buffer Management / String Helpers

#### heap_alloc (0x1800011DC, 54 bytes)

Allocates zero-initialized heap memory using the Windows LocalAlloc API with flags LMEM_ZEROINIT (0x40). On first invocation, lazily resolves LocalAlloc via api_hash_resolve(HASH_LocalAlloc) and caches the function pointer in g_pfnHeapAlloc for subsequent calls. Takes a single parameter specifying the allocation size in bytes. Returns a pointer to the allocated memory block, or NULL if LocalAlloc fails. The LMEM_ZEROINIT flag ensures all allocated memory is zero-filled, which prevents information leakage from uninitialized buffers. This is the primary memory allocation primitive used throughout the Plugins blob; all dynamic buffers, string temporaries, and registry data buffers are allocated through this wrapper.

#### heap_free (0x180001214, 53 bytes)

Frees a heap memory block previously allocated by heap_alloc, using the Windows LocalFree API. Includes a NULL-pointer guard: if the input pointer is NULL, the function returns immediately without calling LocalFree, preventing potential crashes. On first invocation, lazily resolves LocalFree via api_hash_resolve(HASH_LocalFree) and caches the result in g_pfnHeapFree. Takes a single parameter: the pointer to the memory block to free. Returns void. This is the counterpart to heap_alloc and is used throughout the blob for cleanup of dynamically allocated buffers, decrypted strings, and registry data. The lazy resolution pattern matches all API wrappers in this plugin.

#### buf_append (0x180003328, 99 bytes)

Appends data to a dynamically growable buffer structure. The buffer structure has the layout: [current_size(DWORD), capacity(DWORD), offset(DWORD), padding, data_ptr(QWORD)]. Checks if the current offset plus the new data length exceeds the buffer capacity; if so, calls buf_realloc to grow the buffer by (needed + 4096) bytes for headroom. If reallocation fails, returns the error code from buf_realloc (8 = ERROR_NOT_ENOUGH_MEMORY). On success, copies the source data (param1, param2 bytes) into the buffer at the current offset via memcpy_wrapper, advances the offset by the copied length, and updates the current_size field if the new offset exceeds it. Returns 0 on success. This is the primary buffer building function used throughout the plugin for serializing registry enumeration results and command payloads.

#### buf_realloc (0x18000338C, 96 bytes)

Reallocates a growable buffer to a new, larger size. Allocates a new memory block of the requested size via heap_alloc, copies the existing data (up to the current size stored in this_ptr[0]) from the old buffer to the new one via memcpy_wrapper, then frees the old buffer via heap_free if non-NULL. Updates the buffer structure: stores the new data pointer at this_ptr+16 (QWORD) and the new capacity at this_ptr+4 (DWORD). Returns 0 on success, or 8 (ERROR_NOT_ENOUGH_MEMORY) if heap_alloc fails. The buffer structure layout is: [current_size(DWORD at +0), capacity(DWORD at +4), offset(DWORD at +8), pad, data_ptr(QWORD at +16)]. Called by buf_append when the buffer needs to grow, and by reg_enum_and_sync when the RegEnumValueW name or data buffer is too small.

#### buf_init (0x1800033EC, 45 bytes)

Initializes a buffer/string structure to an empty state. Zeros all four fields of the structure: the ANSI data pointer (QWORD at +0), the ANSI size (DWORD at +8), the wide-char data pointer (QWORD at +16), and the wide-char length (DWORD at +24). Then copies an empty wide string from the global g_Sleep address (which despite its name points to a static empty wide string L"") into the wide-char slot via wstr_copy. Returns the pointer to the initialized structure. This function is called before using any buffer/string structure to ensure clean state, particularly before build_reg_key_path, decrypt_string result handling, and mb_to_wchar conversions.

#### decrypt_string (0x18000341C, 221 bytes)

Decrypts an encrypted string blob using the ScatterBrain polynomial XOR cipher. Allocates a 4096-byte work buffer via heap_alloc, reads a 2-byte little-endian key seed from the first two bytes of the encrypted blob, then XORs each subsequent byte with the low byte of the running key. After each byte, the key is advanced via the polynomial recurrence: key = (-42860544 * key) - (135791246 * HIWORD(key)) - 1043215206. Decryption stops at the first null byte or after 4090 bytes (overflow guard). Initializes the output string structure (28 bytes: ANSI ptr, ANSI size, wchar ptr, wchar len) to zeros, then converts the decrypted ANSI bytes to a wide string via mb_to_wchar with codepage 0xFDE9 (CP_UTF8 alias). Frees the temporary work buffer via LocalFree and returns a pointer to the output structure. The encrypted string blobs are stored as globals throughout the binary with the 2-byte key prefix.

#### str_free (0x1800034FC, 59 bytes)

Frees both slots of a dual-slot string structure. The string structure contains an ANSI buffer at offset +0 (QWORD pointer) with its size at offset +8 (DWORD), and a wide-char buffer at offset +16 (QWORD pointer) with its length at offset +24 (DWORD). For each slot, checks if the pointer is non-NULL, frees it via heap_free (LocalFree), then zeroes the pointer and size fields. This function is called extensively throughout the plugin after decrypt_string, str_to_ansi, mb_to_wchar, and wstr_copy operations to release temporary string buffers. Does not return a meaningful value (the return is an artifact of register state). Safe to call on already-freed or zero-initialized structures since it checks for NULL before freeing.

#### str_to_ansi (0x180003538, 200 bytes)

Converts the wide-char string in a string structure to ANSI/multibyte encoding. Lazily resolves WideCharToMultiByte via api_hash_resolve(HASH_WideCharToMultiByte). Performs a two-pass conversion: first calls WideCharToMultiByte with a NULL output buffer and zero size to determine the required buffer length, then allocates that many bytes via heap_alloc and performs the actual conversion. The codepage parameter (param1) controls the encoding; typical values are 0 (CP_ACP) or 0xFDE9 (CP_UTF8 alias used by ScatterBrain). Reads the wide string from the structure at offset +16 (pointer) and +24 (length in characters). After conversion, frees any existing ANSI buffer at offset +0, then stores the new ANSI pointer at offset +0 and its byte length at offset +8. Returns the ANSI buffer pointer on success, or 0/NULL if heap_alloc fails. This is the reverse counterpart of mb_to_wchar.

#### mb_to_wchar (0x180003600, 227 bytes)

Converts a multibyte/ANSI string to wide-char (UTF-16LE) encoding. Lazily resolves MultiByteToWideChar via api_hash_resolve(HASH_MultiByteToWideChar). Performs a two-pass conversion: first calls MultiByteToWideChar with a NULL output buffer and zero size to determine the required length in wide characters, then allocates (length * 2) bytes via heap_alloc using saturated_mul for overflow protection, and performs the actual conversion. The codepage parameter (param2) controls the source encoding; typical values are 0 (CP_ACP) or 0xFDE9 (CP_UTF8). The source string (param1) is treated as null-terminated (length -1). After conversion, frees both existing slots (ANSI at +0 and wide at +16) if non-NULL, then stores the new wide-char pointer at offset +16 and character count at offset +24. Returns 0 on success, or 8 (ERROR_NOT_ENOUGH_MEMORY) if heap_alloc fails. This is the reverse counterpart of str_to_ansi.

#### wstr_copy (0x1800036E4, 303 bytes)

Copies a wide-char (UTF-16LE) string into a string structure, replacing any existing content. Measures the source string length via lstrlenW (lazily resolved from kernel32), adds 1 for the null terminator, allocates (length * 2) bytes via heap_alloc using saturated_mul for overflow protection, then copies the source into the new buffer via lstrcpyW (also lazily resolved). Frees both existing slots of the destination structure (ANSI at +0 and wide at +16) if non-NULL, then stores the new wide-char pointer at offset +16 and the character count (including null) at offset +24. Returns 0 on success, or 8 (ERROR_NOT_ENOUGH_MEMORY) if heap_alloc fails. This function is used by buf_init to set up the empty initial wide string, and by subcmd_enum_reg_values to copy registry value names into temporary structures for serialization.
