# Blob 3 — System Recon + C2 Router Plugin ("Online")

## Summary

| Property | Value |
|----------|-------|
| File | Private archive artifact (available on vetted request) |
| Image Size | 0xC000 (49152 bytes) |
| Entry Point RVA | 0x13E0 |
| Functions | 56 (all renamed) |
| Sections | .text, .rdata, .data2, .data3, .idata |
| Timestamp | 0x58AEBA (2017-02-22/23) |
| idasql Port | 8203 |
| Max CMD ID | 104 |
| Plugin ID (CMD 102) | `"Online"` (encrypted at `0x180006158`) |
| Sub-command Base | 0x680002 |

## Role

**System fingerprinting and C2 connection router.** The largest and most complex plugin (55 functions, 14-slot vtable). Collects comprehensive system recon data (CPU, memory, disk, display, network, OS version, user/computer name), manages C2 connections across multiple transport protocols (TCP/HTTP/HTTPS/UDP/DNS/URL/FTP), implements a Domain Generation Algorithm (DGA) for C2 beacon URLs, and supports SOCKS4/5 + HTTP proxy configurations.

## Imports (31 functions, 5 DLLs)

### KERNEL32.dll (13)
GetProcAddress, GetLastError, GetCurrentProcessId, GetModuleFileNameW, GetVersionExW, GetComputerNameW, GetNativeSystemInfo, GetSystemMetrics, GetDiskFreeSpaceExA, GetSystemDefaultLCID, GlobalMemoryStatusEx, lstrlenA, GetLastError

### USER32.dll (3)
wsprintfA, EnumDisplaySettingsW, GetSystemMetrics

### ole32.dll (2)
CoInitialize, CoUninitialize

### WININET.dll (11)
InternetOpenA, InternetConnectA, InternetSetOptionA/W, InternetQueryOptionW, HttpOpenRequestA, HttpSendRequestExA, HttpEndRequestA, HttpAddRequestHeadersW, InternetReadFile, InternetCloseHandle, FtpOpenFileA

### VERSION.dll (2)
GetFileVersionInfoW, VerQueryValueW

## Entry Point: DllMain_dispatcher (0x1800013E0)

| fdwReason | Command | Action |
|-----------|---------|--------|
| 0 | DETACH | No-op |
| 1 | ATTACH | Populates 14-slot vtable at `0x180007000` |
| 100 | Set context | Stores host context pointer to `qword_180008098` |
| 101 | Version | Writes 104 to `*lpReserved` |
| 102 | Plugin ID | Resolves "Online" via decrypt, calls lstrcpyW to output |
| 104 | Get vtable | Returns `&qword_180007000` |

## Vtable (14 slots at `0x180007000`)

| Slot | Offset | Address | Name | Purpose |
|------|--------|---------|------|---------|
| 0 | +0x00 | 0x180002830 | `cmd1_dispatch_handler` | Command router |
| 1 | +0x08 | 0x180001344 | `vtfn_main_loop` | Polling loop: calls `http_c2_main_handler` |
| 2 | +0x10 | 0x1800010A4 | `vtfn_open_channel` | Open channel by type (200-263) |
| 3 | +0x18 | 0x180001158 | `vtfn_channel_close` | Close channel |
| 4 | +0x20 | 0x180001164 | `vtfn_channel_read` | Read from channel |
| 5 | +0x28 | 0x180001184 | `j_stream_read_loop` | Stream read thunk |
| 6 | +0x30 | 0x18000118C | `vtfn_thunk_unknown` | Thunk |
| 7 | +0x38 | 0x180001194 | `vtfn_channel_write` | Write to channel |
| 8 | +0x40 | 0x1800011B4 | `vtfn_stream_write` | Stream write thunk |
| 9 | +0x48 | 0x1800011BC | `vtfn_process_command` | Deserialize + dispatch commands |
| 10 | +0x50 | 0x1800051A0 | `vtfn_bidirectional_pipe` | Two relay threads for data flow |
| 11 | +0x58 | 0x1800012E4 | `vtfn_channel_cancel` | Cancel channel |
| 12 | +0x60 | 0x1800012F0 | `vtfn_check_and_release` | Check + free channel |
| 13 | +0x68 | 0x18000133C | `vtfn_get_channel_type` | Return channel type |

## Command Dispatch (base 0x680002)

| Command ID | Handler | Purpose |
|-----------|---------|---------|
| 0x680002 (6815746) | `cmd_6815746_start_c2_thread` | Creates thread running `c2_send_receive_loop` |
| 0x680003 (6815747) | `collect_system_recon` | Collect + send system fingerprint |
| 0x680004 (6815748) | `cmd_6815748_heartbeat` | Send heartbeat with random data |
| 0x680005 (6815749) | `cmd_6815749_shutdown` | Send final response, sleep 3s, return WSAECONNABORTED |

## System Recon Data (collect_system_recon, 3027 bytes)

Collects comprehensive system fingerprint:

| # | Source | Data |
|---|--------|------|
| 1 | `collect_machine_id` | 8 random bytes persisted to registry |
| 2-7 | `GetSystemTime` | Year, month, day, hour, minute, second |
| 8 | Literal | `@` (0x40) field separator |
| 9 | `ntohl(a2[2])` | Command sequence number |
| 10 | Channel type | Communication channel type ID |
| 11 | `gethostbyname` | Local host IP address |
| 12 | `GlobalMemoryStatusEx` | Total physical memory |
| 13 | Registry | `SecureProtocols` from IE settings |
| 14-15 | `GetVersionExW` | OS build + major version |
| 16 | `GetDiskFreeSpaceExA` | Total free disk space (A:-Z:) |
| 17-18 | `EnumDisplaySettingsW` | Display width + height |
| 19 | `GetSystemDefaultLCID` | System locale ID |
| 20 | `QPC/QPF` | CPU frequency in MHz |
| 21 | `GetCurrentProcessId` | Process ID |
| 22-25 | `GetNativeSystemInfo` | Processor type, arch, level, revision |
| 26 | `GetSystemMetrics(89)` | SM_TABLETPC flag |
| 27 | `GetComputerNameW` | Computer name |
| 28 | `GetUserNameW` | Username |
| 29 | `GetModuleFileNameW` | Module file path |
| 30 | `EnumDisplaySettingsW` | Display device name |
| 31 | `GetFileVersionInfoW` | OS version string from kernel32.dll |

## C2 Connection Protocol

### Transport Type Mapping
| Protocol | Channel Type | Transport Plugin |
|----------|-------------|-----------------|
| TCP | 200 | blob_4 |
| HTTP | 201 | blob_5 |
| UDP | 202 | blob_6 |
| DNS | 203 | blob_7 |
| HTTPS | 204 | blob_5 |
| URL | Direct HTTP download | Built-in |
| FTP | Via FtpOpenFileA | Built-in |

### C2 Profile Processing (`http_c2_main_handler`, 2092 bytes)
1. Allocates 2136-byte config buffer
2. Iterates up to **16 C2 profile slots**
3. For each: decrypts URL, cracks with `InternetCrackUrlA`
4. Compares scheme to determine channel type
5. Opens channel via `vtfn_open_channel`

### Domain Generation Algorithm (`http_beacon_to_c2`, 808 bytes)
- Seed: `1999 * year + (13|17|19) * month` (factor varies by day range: 0-10=13, 11-20=17, 21+=19)
- Generates 8-15 characters: `seed % 52` mapped to a-zA-Z
- LCG: `seed = 13 * seed + 7`
- Prepended to C2 URL path
- Sets `SecureProtocols` to -1 (all TLS/SSL enabled) before connecting

### C2 Response Validation
- Must contain `$` delimiter
- Printable characters (>= 0x20)
- 8-256 bytes
- Contains valid protocol prefix: `TCP://`, `UDP://`, `HTTP://`, `HTTPS://`, `DNS://`, `URL://`

### Proxy Support (`parse_proxy_config`, 860 bytes)
Up to 8 entries (104 bytes each):
- **HTTP** proxy (type 3)
- **SOCKS4** (type 1)
- **SOCKS5** (type 2)
- Fields: host, port (via atoi), username, password

## Debug Instrumentation
Emits `OutputDebugStringA`:
```
OnlineEx( [%s] : %d : %d, [%s] : %d : %d ) PVOID(%d)\r\n
```
Reveals connection parameters — potential detection signature.

## TLS Downgrade Attack
Sets `SecureProtocols` in `Software\Microsoft\Windows\CurrentVersion\Internet Settings` to `-1`, enabling all TLS/SSL protocol versions including deprecated ones.

## Machine Persistence ID
Writes 8 random bytes to `HARDWARE\DESCRIPTION\SYSTEM\CENTRALPROCESSOR\0` under `SOFTWARE\` as a machine-unique identifier.

## Encrypted Strings (56 total)

Key strings: `Online`, `lstrcpyW`, `Sleep`, `ntohl`, `InternetCrackUrlA`, `wininet.dll`, `TCP`, `HTTP`, `HTTPS`, `UDP`, `DNS`, `URL`, `advapi32.dll`, `memset`, `gethostbyname`, `htonl`, `GetUserNameW`, `QueryPerformanceCounter/Frequency`, `GetModuleFileNameW`, `CreateThread`, `CloseHandle`, `ExpandEnvironmentStringsW`, `SecureProtocols`, `Software\Microsoft\Windows\CurrentVersion\Internet Settings`, `TCP://`, `UDP://`, `HTTP://`, `HTTPS://`, `DNS://`, `URL://`, `*/*`, `GET`, `POST`, `FTP`, `Connection: close\r\n`, `SOCKS4`, `SOCKS5`, `atoi`, `lstrcatA/W`, `lstrlenA/W`.

## All 56 Functions

All renamed. Key functions by category:
- **Entry/dispatch**: `DllMain_dispatcher`, `cmd1_dispatch_handler`
- **Recon**: `collect_system_recon`, `collect_machine_id`, `collect_file_version_info`
- **C2 protocol**: `http_c2_main_handler`, `c2_send_receive_loop`, `http_fetch_url`, `http_beacon_to_c2`, `parse_c2_response`
- **Commands**: `cmd_6815746_start_c2_thread`, `cmd_6815748_heartbeat`, `cmd_6815749_shutdown`
- **Channel ops**: `vtfn_open_channel`, `vtfn_channel_close/read/write/cancel`
- **Proxy**: `parse_proxy_config`
- **Support**: `resolve_api_by_name`, `heap_alloc/free`, `decrypt_string`, `str_to_wstr`

---

## Detailed Function Reference (56 functions)

### API Resolution / Import Helpers

#### resolve_api_by_name (0x180001000, 161 bytes)

Resolves a Windows API function by name from kernel32.dll. Takes a pointer to an ANSI function name string as the sole parameter and returns the resolved function pointer. Lazily loads kernel32.dll by first decrypting the string "kernel32.dll" using the ScatterBrain polynomial XOR cipher, then calling LoadLibraryA (resolved via PEB hash `0xBDB97F3A`). Subsequently resolves GetProcAddress (hash `0xA17B3E87`) from kernel32 to look up the requested export. Both the kernel32 module handle and the GetProcAddress pointer are cached in globals `g_pfnkernel32_dll_2` and `g_pfnGetProcAddress` respectively, so subsequent calls skip the resolution overhead. Returns the function pointer on success, or 0 if the export is not found.

#### resolve_kernel32_api_by_hash (0x180001600, 241 bytes)

Resolves a kernel32.dll API function by its hash value using PEB traversal. Takes a 32-bit hash of the target function name as the parameter. Walks the PEB->Ldr->InLoadOrderModuleList to locate kernel32.dll by computing a rolling hash (ROR8 + XOR `0x7C35D9A3`) over the module name characters (lowercased via OR 0x20), matching against the known kernel32 hash `0xFD5739E1`. Once the kernel32 base is found, parses the PE export directory to enumerate all exported function names, computing the same rolling hash over each name (without case folding). When a hash match is found, returns the resolved function pointer by indexing through the export address table via the ordinal table. Returns NULL if no match is found after exhausting all exports. This is the fundamental bootstrap API resolver used before GetProcAddress is available.

#### resolve_api_by_name_ordinal (0x1800018C0, 161 bytes)

Resolves a Windows API function by name from msvcrt.dll. Takes a pointer to an ANSI function name string (or an ordinal value) as the sole parameter and returns the resolved function pointer. Lazily loads msvcrt.dll by decrypting the string "msvcrt.dll" using the ScatterBrain polynomial XOR cipher, then calling LoadLibraryA (resolved via PEB hash `0xBDB97F3A`). Resolves GetProcAddress (hash `0xA17B3E87`) to look up the requested export. Both the msvcrt module handle (`g_pfnmsvcrt_dll`) and the GetProcAddress pointer are cached globally. Used to resolve C runtime functions like memcpy, memset, `_strnicmp`, and atoi that are needed for string operations and data manipulation throughout the plugin.

#### resolve_api_by_name_ws2 (0x1800019E0, 161 bytes)

Resolves a Windows API function by name from ws2_32.dll (Winsock). Takes a pointer to an ANSI function name string as the sole parameter and returns the resolved function pointer. Lazily loads ws2_32.dll by decrypting the library name using the ScatterBrain polynomial XOR cipher, then calling LoadLibraryA (resolved via PEB hash `0xBDB97F3A`). Resolves GetProcAddress (hash `0xA17B3E87`) to look up the requested Winsock export. Both the ws2_32 module handle (`g_pfnws2_32_dll`) and the GetProcAddress pointer are cached globally. Used to resolve network byte order conversion functions (htonl, ntohl) and DNS functions (gethostbyname) needed for C2 packet construction and system reconnaissance.

### Plugin Protocol / Dispatch

#### DllMain_dispatcher (0x1800013E0, 432 bytes)

DLL entry point and plugin initialization dispatcher for the Online plugin (blob_3, version 104). Handles multiple fdwReason codes via an arithmetic switch: (1) fdwReason=1 (DLL_PROCESS_ATTACH): populates the 14-entry `sb_online_vtable_t` with all vtable function pointers including `cmd1_dispatch_handler` (slot 0), `vtfn_main_loop` (slot 1), `vtfn_open_channel` (slot 2), `vtfn_channel_close` (slot 3), `vtfn_channel_read` (slot 4), `j_stream_read_loop` (slot 5), `vtfn_thunk_unknown` (slot 6), `vtfn_channel_write` (slot 7), `vtfn_stream_write` (slot 8), `vtfn_process_command` (slot 9), `vtfn_bidirectional_pipe` (slot 10), `vtfn_channel_cancel` (slot 11), `vtfn_check_and_release` (slot 12), and `vtfn_get_channel_type` (slot 13). (2) fdwReason=100: stores the framework context pointer (`lpReserved`) into `g_framework_ctx`. (3) fdwReason=102: writes the version number 104 to the output buffer. (4) fdwReason=103: decrypts and copies the plugin ID string "Online" to the output buffer via lstrcpyW. (5) fdwReason=104: writes the vtable pointer to the output buffer. Always returns TRUE.

#### cmd1_dispatch_handler (0x180002830, 186 bytes)

Vtable slot 0 (offset 0x00) of `sb_online_vtable_t`: top-level command dispatcher for incoming C2 packets. Takes the Online context (`this_ptr`) and the raw command packet buffer (`dw_arg1`). Resolves ntohl from ws2_32.dll and reads the 4-byte command ID from `dw_arg1+4`, converting from network byte order. Dispatches based on the command ID using an arithmetic switch: command 6815746 routes to `cmd_6815746_start_c2_thread` (start a new C2 connection thread), command 6815747 routes to `collect_system_recon` (gather and transmit 31 system reconnaissance data points), command 6815748 routes to `cmd_6815748_heartbeat` (respond with keepalive), and command 6815749 routes to `cmd_6815749_shutdown` (graceful shutdown sequence). If the command ID does not match any known handler, returns 0xFFFFFFFF (-1) to signal an unrecognized command to the caller.

#### vtfn_main_loop (0x180001344, 154 bytes)

Vtable slot 14 (offset 0x70) of `sb_online_vtable_t`: the main C2 beacon loop that runs as the Online plugin primary thread. Takes no parameters. Repeatedly calls `http_c2_main_handler` to attempt a full C2 connection cycle (URL resolution, protocol selection, connection, and command processing). If `http_c2_main_handler` returns the shutdown sentinel value 20000, the loop exits and returns 0. Otherwise, after each failed attempt, decrypts and resolves the Sleep API from kernel32.dll (cached in `g_pfnSleep`), then sleeps for 1000 milliseconds before retrying. This creates a persistent beacon that continuously attempts to reconnect to the C2 server, implementing the core keep-alive and reconnection logic of the ScatterBrain Online plugin.

#### get_plugin_id_version (0x18000175C, 75 bytes)

Retrieves the plugin configuration ID and version information from the Config plugin (blob_2, ID 102). Takes an output buffer pointer (`out_id`) where the configuration data will be written. Acquires the Config plugin instance from the framework via `g_framework_ctx+24` with plugin ID 102, then calls vtable slot 1 (offset 8) on the Config plugin vtable with the output buffer and parameter 1 to retrieve the current configuration block. Releases the Config plugin reference via `g_framework_ctx+32` after the call. Returns the result code from the Config plugin, typically 0 on success. The Config plugin stores a 2136-byte configuration blob containing C2 URLs, proxy settings, timing parameters, and other operational parameters.

### System Reconnaissance

#### collect_system_recon (0x1800028EC, 3027 bytes)

Collects and transmits a comprehensive system reconnaissance report containing approximately 31 data points. Takes the Online context pointer (`this_ptr`, used to retrieve the active channel handle) and the command buffer (`dw_arg1`) for constructing the response packet. Begins by calling `collect_machine_id` to get the 8-byte machine ID and 16-byte timestamp structure, then appends the data points sequentially to a dynamic buffer via `buffer_append_bytes` and `buffer_append_wstr`. Data points collected include: (1) 8-byte machine ID, (2-7) formatted timestamp components (year+48, month, day, hour, minute, second), (8-13) a second timestamp from `g_pfnUnk_6010`, (14) separator byte 0x40, (15) the C2 sequence number from the command packet (ntohl converted, 4 bytes), (16) connection protocol ID (2 bytes from channel offset 24), (17) local IP address resolved via `gethostbyname(NULL)` converted with ntohl (4 bytes), (18) system uptime from `g_pfnUnk_6018` (8 bytes), (19) CPU frequency from registry `HARDWARE\DESCRIPTION\System\CentralProcessor\0`, and additional hardware/OS data points through to the OS version string. The complete payload is sent via `channel_write_data`.

#### collect_machine_id (0x18000382C, 710 bytes)

Generates or retrieves the persistent machine identifier used to uniquely identify this implant installation. Takes two output parameters: `this_ptr` (8-byte buffer for the machine ID) and `param1` (16-byte buffer for the timestamp structure). On first call (when `g_machine_id_time` is zero), generates 8 random bytes via the framework PRNG at `g_framework_ctx+200` and stores them in the global `g_machine_id` array. Records the current timestamp via `g_pfnUnk_6010` into `g_machine_id_time`. If the framework context indicates this is not configuration type 3 (checked at `g_framework_ctx+216` offset 12), attempts to persist the machine ID to the Windows registry: first reads the Config plugin (ID 102) vtable slot 2 (offset 16) to get the registry path parameters, then constructs a registry subkey path under `SOFTWARE` using the decrypted string and `str_to_wstr` conversion. Tries to read the existing machine ID from HKLM first, then HKCU as fallback, using `reg_query_value_dword` with 24-byte REG_BINARY data. If neither hive has the value, writes the newly generated ID to both HKLM and HKCU via `reg_set_value_dword`.

#### collect_file_version_info (0x180003AF4, 459 bytes)

Retrieves the file version information of kernel32.dll to determine the Windows OS version. Takes two DWORD output parameters: `dw_arg0` receives the minor version and `dw_arg1` receives the major version. Decrypts the path string `%%SystemRoot%%\system32\kernel32.dll` and expands the environment variable using ExpandEnvironmentStringsW (lazily resolved from kernel32.dll). Allocates an 8KB buffer via `heap_alloc(0x2000)` and calls `g_pfnUnk_6098` (likely GetFileVersionInfoW) to read the version resource. On failure, resolves GetLastError and returns the error code. If successful, calls `g_pfnUnk_6090` (likely VerQueryValueW) with the root block path to get the VS_FIXEDFILEINFO structure. Extracts the major version from offset 16 (`dwFileVersionMS` low word) into `dw_arg1` and the minor version from offset 18 (`dwFileVersionMS` high word) into `dw_arg0`. Frees the 8KB buffer and returns 0 on success or the GetLastError code on failure.

#### reg_query_value_dword (0x1800017A8, 139 bytes)

Reads a registry value via the Plugins plugin (blob_1, ID 101). Takes six parameters: registry hive key (`this_ptr`, e.g., -2147483646 for HKLM or -2147483647 for HKCU), subkey path (`param1`), value name (`param2`), output data buffer (`param3`), data size in bytes (`param4`), and a size output pointer (`param5`). Acquires the Plugins plugin from the framework via `g_framework_ctx+24` with plugin ID 101, then calls vtable slot 2 (offset 16) on the Plugins vtable to perform the registry read. Releases the plugin reference afterward. Returns 0 on success (value was read) or a non-zero error code. Used throughout the Online plugin to read machine ID persistence data and configuration values from the Windows registry.

#### reg_set_value_dword (0x180001834, 139 bytes)

Writes a registry value via the Plugins plugin (blob_1, ID 101). Takes six parameters: registry hive key (`this_ptr`), subkey path (`param1`), value name (`param2`), data buffer to write (`param3`), data size in bytes (`param4`), and registry value type (`param5`, e.g., 3 for REG_BINARY, 4 for REG_DWORD). Acquires the Plugins plugin from the framework via `g_framework_ctx+24` with plugin ID 101, then calls vtable slot 3 (offset 24) on the Plugins vtable to perform the registry write. Releases the plugin reference afterward. Returns 0 on success or a non-zero error code. Used to persist the machine ID (24 bytes, type REG_BINARY=3) and to set the SecureProtocols registry value for TLS configuration.

### C2 Channel Management

#### vtfn_open_channel (0x1800010A4, 180 bytes)

Vtable slot 2 (offset 0x10) of `sb_online_vtable_t`: opens a communication channel to a specific transport plugin. Takes the Online context pointer, a 16-bit command/protocol identifier (`cmd_buf`), and a size parameter. Allocates a 32-byte channel descriptor via `heap_alloc` and validates the protocol ID is within the transport range 200-263 (TCP=200, HTTP=201, UDP=202, DNS=203, HTTPS=204). Retrieves the appropriate transport plugin instance from the framework via `g_framework_ctx+24` with the protocol ID, mapping HTTPS (204) to HTTP (201) for plugin lookup. Stores the plugin vtable pointer at descriptor+8 and invokes vtable slot 1 (offset 8) on the transport to initialize the channel. On success, stores the channel descriptor in `ctx->_pad_000` and returns 0. On failure (invalid protocol range or plugin not found), returns error code 126 and frees the allocated descriptor.

#### vtfn_channel_close (0x180001158, 12 bytes)

Vtable slot 3 (offset 0x18) of `sb_online_vtable_t`: closes an open communication channel. Takes the Online context pointer and delegates to the underlying transport plugin by calling vtable slot 2 (offset 0x10) on the parent context transport object (`ctx->parent_ctx`). The `parent_ctx` pointer references the transport plugin instance, and `ctx->flags` holds the channel handle. Returns the transport plugin close result, typically 0 on success or an error code on failure. This is a thin wrapper that provides the Online plugin abstraction layer over the raw transport close operation.

#### vtfn_channel_read (0x180001164, 29 bytes)

Vtable slot 4 (offset 0x20) of `sb_online_vtable_t`: reads data from an open communication channel. Takes the Online context pointer and delegates to the underlying transport plugin by calling vtable slot 3 (offset 0x18) on the parent context transport object (`ctx->parent_ctx`). Passes `ctx->flags` as the channel handle to the transport. Returns the transport plugin read result, typically 0 on success with data available, or an error code. This is a thin wrapper providing the Online abstraction over the raw transport read operation.

#### vtfn_channel_write (0x180001194, 29 bytes)

Vtable slot 7 (offset 0x38) of `sb_online_vtable_t`: writes data to an open communication channel. Takes the Online context pointer and delegates to the underlying transport plugin by calling vtable slot 4 (offset 0x20) on the parent context transport object (`ctx->parent_ctx`). Passes `ctx->flags` as the channel handle to the transport. Returns the transport plugin write result, typically 0 on success or an error code. This is a thin wrapper providing the Online abstraction over the raw transport write operation.

#### vtfn_channel_cancel (0x1800012E4, 12 bytes)

Vtable slot 11 (offset 0x58) of `sb_online_vtable_t`: cancels an active channel operation. Takes the Online context pointer and delegates to the underlying transport plugin by calling vtable slot 5 (offset 0x28) on the parent context transport object (`ctx->parent_ctx`). Passes `ctx->flags` as the channel handle to the transport. Returns the transport cancel result. This allows the Online plugin to abort in-progress reads or writes on the underlying TCP, HTTP, UDP, or DNS transport without closing the channel entirely.

#### vtfn_check_and_release (0x1800012F0, 73 bytes)

Vtable slot 12 (offset 0x60) of `sb_online_vtable_t`: checks channel status and releases resources if complete. Takes the Online context pointer. Calls vtable slot 6 (offset 0x30) on the parent transport (`ctx->parent_ctx`) with `ctx->flags` to check if the channel operation is complete. If the transport returns 0 (complete), this function releases the channel by: (1) calling the framework resource release at `g_framework_ctx+32` to free the plugin reference stored in `ctx->_pad_000`, (2) zeroing out `_pad_000`, `parent_ctx`, and `flags`, and (3) freeing the context structure via `heap_free`. Returns 0 after cleanup. If the transport returns non-zero (still busy), returns the status code without freeing anything.

#### vtfn_get_channel_type (0x18000133C, 5 bytes)

Vtable slot 13 (offset 0x68) of `sb_online_vtable_t`: returns the transport channel type identifier. Takes the Online context pointer and returns the low 16 bits of `ctx->state`, which contains the protocol type identifier (200=TCP, 201=HTTP, 202=UDP, 203=DNS, 204=HTTPS). This is used by the framework to determine which transport protocol is currently active on a given channel for routing and logging purposes.

#### channel_write_data (0x1800016F4, 102 bytes)

Writes data to a transport channel using the framework plugin lookup mechanism. Takes a channel context pointer (`this_ptr`), a data buffer pointer (`param1`), and a length/flags parameter (`param2`, passed as 0xFFFFFFFF for full-buffer writes). Retrieves the TCP transport plugin (ID 104) from the framework via `g_framework_ctx+24`, then calls vtable slot 9 (offset 72) on the transport plugin vtable to perform the actual write. After the write completes, releases the transport plugin reference via `g_framework_ctx+32`. Returns the write result code from the transport, typically 0 on success. This function is the central data transmission primitive used by the C2 command handlers to send response packets back through the active channel.

### C2 Command Router

#### http_c2_main_handler (0x180001A84, 2092 bytes)

Core C2 handler that orchestrates a complete connection cycle. This is the largest and most critical function in the Online plugin. Begins by calling `collect_machine_id` to generate/retrieve the persistent machine identifier, then allocates a 2136-byte configuration buffer and calls `get_plugin_id_version` to load the Config plugin data. Iterates through up to 16 C2 URL entries in the config (at offset 24, 2-byte offsets into the config blob). For each URL, decrypts it and uses InternetCrackUrlA (from wininet.dll) to parse the scheme, hostname, and port. Implements protocol routing by comparing the URL scheme against six supported protocols: TCP (ID 200), HTTP (ID 201), UDP (ID 202), DNS (ID 203), HTTPS (ID 204), and URL (DGA fallback). For URL-type entries, calls `http_beacon_to_c2` to perform DGA-based URL resolution. Stores the selected protocol ID in `g_c2_protocol_id` and connection parameters (config offsets 64-79) into `g_cfg_connect_param0-3`. Calls `c2_send_receive_loop` for the primary connection attempt. If the loop returns WSAECONNABORTED (10053), returns the shutdown sentinel value 20000 to `vtfn_main_loop`.

#### c2_send_receive_loop (0x1800022B0, 1407 bytes)

Main C2 send/receive loop that establishes a transport channel and processes bidirectional command traffic. Takes a parameter indicating whether this is a reconnection attempt (non-zero `this_ptr`). Initializes the framework state via `g_pfnUnk_6008(1)`, decrypts a URL template, and configures the transport connection parameters (C2 hostname, port, protocol ID, proxy settings) via `g_pfnUnk_6070` and `g_pfnUnk_6000`. Opens a channel via the framework (plugin ID 104, TCP transport) using vtable slot 2 (offset 16) to create the channel and vtable slot 3 (offset 24) to bind the port. Constructs a 20-byte C2 registration packet with: command ID 6815745 (initial hello) or 6815746 (reconnect) in network byte order at offset 4, the reconnect parameter at offset 8, and a random payload size (20-83 bytes) at offset 12. Sends this via `channel_write_data` and enters the main receive loop. For each received packet, converts the command ID from network byte order, extracts the target plugin ID (HIWORD), looks up the plugin via the framework, and dispatches the command to the appropriate plugin's vtable slot 0 handler.

#### cmd_6815746_start_c2_thread (0x1800034C0, 190 bytes)

Handles C2 command ID 6815746: starts a new C2 connection thread for parallel channel management. Takes the command buffer (`ctx`) containing the reconnect parameter at offset 8. Resolves ntohl from ws2_32.dll to convert the reconnect parameter from network byte order. Calls `create_thread_wrapper` to spawn a new thread running `c2_send_receive_loop` with the converted reconnect parameter as the thread argument. After the thread is created, resolves CloseHandle from kernel32.dll (lazily cached in `g_pfnCloseHandle`) and closes the thread handle since the thread runs detached. Returns 0 on success. This command allows the C2 server to instruct the implant to open additional parallel communication channels, enabling multiplexed command execution.

#### cmd_6815748_heartbeat (0x180003580, 309 bytes)

Handles C2 command ID 6815748: responds with a heartbeat/keepalive packet. Takes the Online context (`ctx`, containing the channel handle at `ctx->_pad_000`) and the command buffer (`cmd_buf`). Constructs a response packet by setting: `cmd_buf[1] = htonl(6815748)` as the heartbeat command echo, `cmd_buf[2] = htonl(0)` as the zero sequence number, and `cmd_buf[3] = htonl(random & 0x1F)` where random is obtained from the framework PRNG at `g_framework_ctx+200`. The random value masked to 5 bits (0-31) serves as a lightweight liveness indicator. Sends the packet via `channel_write_data` with the 0xFFFFFFFF flag. Returns 0 on success. This is the simplest command handler and enables the C2 server to verify the implant is still responsive.

#### cmd_6815749_shutdown (0x1800036B8, 371 bytes)

Handles C2 command ID 6815749: performs a graceful shutdown sequence. Takes the Online context (`ctx`) and command buffer (`cmd_buf`). Constructs a shutdown acknowledgment packet with: `cmd_buf[1] = htonl(6815749)`, `cmd_buf[2] = htonl(0)`, `cmd_buf[3] = htonl(0)`. Sends this final packet via `channel_write_data` with flag 0 (indicating final transmission). Then enters a 3-second delay loop, sleeping 1000ms per iteration (3 iterations total) via the lazily-resolved Sleep API. This delay allows the transport layer to flush the final packet before the connection is torn down. Returns the sentinel value 10053, which propagates up through `c2_send_receive_loop` to signal connection termination. The value 10053 corresponds to WSAECONNABORTED, used as the shutdown signal throughout the C2 framework.

#### vtfn_process_command (0x1800011BC, 293 bytes)

Vtable slot 9 (offset 0x48) of `sb_online_vtable_t`: processes an incoming C2 command packet on an established channel. Takes the Online context, a pointer to the raw command buffer, and the command size. Resolves ntohl from ws2_32.dll and reads the 4-byte payload length field at `cmd_buf+12`, converting from network byte order. Adds 20 bytes (the C2 packet header size) to get the total frame size. Calls the framework packet splitter at `g_framework_ctx+168` to extract the payload into a separate buffer (`out_param2`). Then writes the extracted payload to the channel via `stream_write_loop`. After writing, frees the extracted buffer via `g_framework_ctx+192`. Returns 0 on success or propagates error codes from either the splitter or the write loop.

#### vtfn_thunk_unknown (0x18000118C, 5 bytes)

Vtable slot 6 (offset 0x30) of `sb_online_vtable_t`: unknown purpose thunk function. Takes the Online context, a command buffer pointer, and a size parameter. Delegates directly to `vtfn_thunk_unknown_0` which reads a 20-byte C2 packet header from the stream, decrypts it via the framework decryption function at `g_framework_ctx+184`, parses the payload size from the header using ntohl, reads the full payload, and dispatches it through the framework command handler at `g_framework_ctx+176`. This slot handles incoming encrypted command packets on an established channel.

#### vtfn_thunk_unknown_0 (0x180004F80, 543 bytes)

Implementation behind vtable slot 6: handles incoming encrypted command packets by reading a full framed message from the transport channel. Takes the Online context (`ctx`), a command buffer reference (`cmd_buf`), and a size/timeout parameter (`cmd_size`). First reads a 20-byte C2 packet header via `stream_read_loop`, then decrypts the header using the framework decryption function at `g_framework_ctx+184` (which performs in-place decryption into the `local_27` output buffer). Parses the payload size from the decrypted header field using ntohl network byte order conversion. Allocates a new buffer via `g_framework_ctx+160` of size (payload_size + 20) to hold the complete packet. Copies the 20-byte header into the new buffer, then reads the remaining payload bytes via `stream_read_loop` into the buffer at offset 20. After the full payload is read, re-parses the payload size with ntohl and adds the 20-byte header size to compute the total frame length. Dispatches the complete packet through the framework command handler at `g_framework_ctx+176`.

### DGA (Domain Generation Algorithm)

#### http_beacon_to_c2 (0x180003DB4, 808 bytes)

Implements the DGA beacon mechanism for URL-type C2 entries. Takes a 1024-byte output buffer (`this_ptr`) for the resolved C2 URL and a pointer to the URL template suffix (`sz_arg1`, parsed from the config after skipping the first 6 bytes). Generates a pseudo-random domain name using a deterministic algorithm seeded by the current date: retrieves the system time via `g_pfnUnk_6010`, computes a seed value from year (multiplied by 1999), month (multiplied by 13, 17, or 19 depending on whether the day is in the range 0-10, 11-20, or 21+), and day. The domain length is `(seed mod 7) + 8` characters (8-14 chars). Each character is generated by: `char = seed mod 52`; if char >= 26 then char+39 (digits/symbols), else char+97 (lowercase a-z); then `seed = 13*seed+7`. The generated domain is null-terminated and converted to a wide string. After generating the DGA domain, processes the URL template suffix character by character: the at-sign (0x40) delimiter is used to concatenate the DGA domain with the template to form the complete beacon URL.

#### parse_c2_response (0x1800040DC, 737 bytes)

Parses a C2 response payload to extract the real C2 URL from DGA-downloaded content. Takes the output buffer (`this_ptr`, 1024 bytes for the resolved URL) and a pointer to the encoded data (`ptr_arg1`, positioned after a dollar-sign delimiter). First measures the encoded data length via `g_pfnUnk_6050`, allocates a decode buffer. Decodes pairs of lowercase hex characters (a-p representing nibbles 0-15) into raw bytes using the formula: `byte = (char1-97) + 16*(char2-97)`. The decoding loop terminates when a dollar-sign is encountered. Validates each nibble is in range 0-15 and returns error 13 if any character is invalid. The decoded bytes are then decrypted using `decrypt_string` (ScatterBrain polynomial XOR cipher) and converted to ANSI via `decrypt_and_resolve`. Validates the decrypted result: the string length must be between 8 and 248 characters, and every character must be >= 32 (printable). If validation passes, copies the result to the output buffer via lstrcpyA. Then performs protocol prefix validation by checking for TCP://, HTTP://, HTTPS://, UDP://, DNS://, or URL:// prefixes using `strnicmp_wrapper`.

#### http_fetch_url (0x1800043C0, 1813 bytes)

Fetches content from a URL using WinInet APIs, supporting HTTP, HTTPS, and FTP protocols. Takes the URL string (`this_ptr`) and an output wide-string struct (`param1`) to receive the response body. Begins by parsing the URL with InternetCrackUrlA (resolved from wininet.dll) to extract the scheme, hostname, port, path, and query components into a 104-byte URL_COMPONENTS structure. Configures WinInet options via `g_pfnUnk_60A8`: disables cookies (option 95), disables UI (option 39), and disables auto-redirect (option 37). Opens an internet session via `g_pfnUnk_60B0` (InternetOpenA) and connects to the server via `g_pfnUnk_60B8` (InternetConnectA) with flags 0x84000000 (INTERNET_FLAG_RELOAD | INTERNET_FLAG_NO_CACHE_WRITE). For HTTP scheme: sends a GET request via `g_pfnHTTP` (HttpOpenRequestA) with flags 0x84400000 (adds INTERNET_FLAG_KEEP_CONNECTION). For HTTPS: sends GET with flags 0x84800000 (adds INTERNET_FLAG_SECURE), then sets security option 31 to value 0xF3C0 (SECURITY_FLAG_IGNORE_ALL) via `g_pfnUnk_60C8` to bypass certificate validation. For FTP: opens the file via FtpOpenFileA. Reads the response in a loop via InternetReadFile, accumulating into a dynamic buffer until no more data is available.

### Packet Encryption / Decryption

#### decrypt_string (0x1800055EC, 215 bytes)

ScatterBrain polynomial XOR string decryptor. Takes an output `wstr_struct` pointer (`out_str`) and a pointer to the encrypted blob (`enc_blob`). Allocates a 4096-byte temporary buffer via `heap_alloc`. Reads the 2-byte XOR seed from the first two bytes of `enc_blob` (little-endian: `enc_blob[0] | enc_blob[1]<<8`). Decrypts the remaining bytes starting at `enc_blob+2` using a polynomial rolling key: each byte is XORed with the low byte of the key, then the key is updated as `key = -42860544*key - 135791246*HIWORD(key) - 1043215206` (three IMUL constants). Decryption terminates when a null byte is produced or 4090 bytes are processed. Initializes the output `wstr_struct` to zeros, converts the decrypted ANSI string to a wide string via `str_to_wstr`, then frees the temporary buffer via HeapFree. Returns the `out_str` pointer. This cipher is shared across all ScatterBrain plugins and uses the same polynomial constants.

### Transport Vtable Functions

#### j_stream_read_loop (0x180001184, 5 bytes)

Jump thunk to `stream_read_loop`. Vtable slot 5 (offset 0x28) of `sb_online_vtable_t`: provides a buffered stream read interface. Takes `this_ptr` (the channel context), a destination buffer pointer, a byte count to read, and a timeout parameter. Simply forwards all four parameters directly to `stream_read_loop` which implements the actual loop logic of repeatedly calling the transport read until the requested number of bytes has been received or an error occurs.

#### vtfn_stream_write (0x1800011B4, 5 bytes)

Vtable slot 8 (offset 0x40) of `sb_online_vtable_t`: writes data to a stream channel with full buffering. Takes the Online context, a source buffer pointer, the byte count to write, and a timeout/flags parameter (`arg3`). Delegates directly to `stream_write_loop` which implements the actual loop logic of repeatedly calling the transport write (vtable offset 0x20) until all requested bytes have been transmitted or an error occurs. Returns 0 on success when all bytes are written, or a non-zero error code from the transport if the write fails mid-stream.

#### stream_read_loop (0x180004EB0, 102 bytes)

Stream read loop that reads exactly the requested number of bytes from a transport channel. Takes four parameters: `this_ptr` (the channel context, with vtable pointer at offset 8 and channel handle at offset 16), `param1` (destination buffer pointer), `param2` (total bytes to read), and `param3` (timeout value, -1 for infinite). If `param2` is zero or negative, returns 0 immediately. Otherwise enters a loop that repeatedly calls the transport read function at vtable offset 24 (slot 3), passing the channel handle, the current buffer position (`param1 + bytes_read_so_far`), the remaining byte count, an output parameter for bytes actually read, and the timeout. Accumulates bytes read until the total reaches `param2`, then returns 0 for success. If any individual read call returns a non-zero error code, immediately returns that error. This function ensures complete reads for fixed-size protocol structures like the 20-byte C2 packet headers.

#### stream_write_loop (0x180004F18, 102 bytes)

Stream write loop that writes exactly the requested number of bytes to a transport channel. Takes four parameters: `this_ptr` (the channel context, with vtable pointer at offset 8 and channel handle at offset 16), `param1` (source buffer pointer), `param2` (total bytes to write), and `param3` (timeout value, -1 for infinite). If `param2` is zero or negative, returns 0 immediately. Otherwise enters a loop that repeatedly calls the transport write function at vtable offset 32 (slot 4), passing the channel handle, the current buffer position (`param1 + bytes_written_so_far`), the remaining byte count, an output parameter for bytes actually written, and the timeout. Accumulates bytes written until the total reaches `param2`, then returns 0 for success. If any individual write call returns a non-zero error code, immediately returns that error. This ensures complete transmission of C2 response packets.

#### vtfn_bidirectional_pipe (0x1800051A0, 686 bytes)

Vtable slot 10 (offset 0x50) of `sb_online_vtable_t`: establishes a bidirectional proxy pipe between two transport channels for data relay. Takes the Online context (`ctx`, the source channel) and a command buffer (`cmd_buf`, containing the destination channel descriptor). Sets up two relay direction descriptors: `local_24 = [ctx, cmd_buf]` (source-to-destination) and `local_25 = [cmd_buf, ctx]` (destination-to-source). Creates two threads via `create_thread_wrapper`, each running `proxy_relay_thread` with one of the direction descriptors. Waits for both threads to complete using `g_pfnUnk_6060` (likely WaitForMultipleObjects) with count=2, the thread handle array, bWaitAll=0, and timeout=0xFFFFFFFF (INFINITE). Then sleeps 3 times for 1000ms each to allow final data to flush. After the relay completes, cancels both channels: calls vtable slot 5 (offset 0x28, cancel) on the source channel and vtable slot 5 (offset 40) on the destination channel. Waits again for both threads with bWaitAll=1 and INFINITE timeout to ensure clean shutdown.

#### proxy_relay_thread (0x180005450, 110 bytes)

Thread function for bidirectional proxy relay. Takes a pointer to a 2-element array: `this_ptr[0]` is the source channel context and `this_ptr[1]` is the destination channel context. Allocates a 1024-byte transfer buffer via `heap_alloc`. Enters a loop that reads data from the source channel by calling the transport read function at vtable offset 24 (slot 3) on the source channel (`this_ptr[0]`, with channel handle at offset 16), reading up to 1024 bytes with infinite timeout (-1). If the read succeeds, writes the received data to the destination channel (`this_ptr[1]`) via `stream_write_loop` with infinite timeout. The loop continues as long as both read and write operations return 0. When either operation fails (connection closed, error, or cancel), the loop exits, the buffer is freed via `heap_free`, and the thread returns 0. Two instances of this function run concurrently (one per direction) to implement full-duplex proxy relay.

### Proxy Configuration

#### parse_proxy_config (0x180004B54, 860 bytes)

Parses proxy configuration from the Config plugin data to populate a proxy configuration table. Takes an output buffer (`this_ptr`, 872 bytes = 40 bytes header + 8 x 104-byte proxy entries). Initializes a CRITICAL_SECTION at the start of the buffer via InitializeCriticalSection (lazily resolved from kernel32.dll). Sets up 8 proxy entry slots, each containing: a 2-byte protocol type at offset 0, a 2-byte port at offset 2, and three 32-byte encrypted wide strings (hostname at offset 32, username at offset 64, password at offset 96). Loads the Config plugin data (2136 bytes) via `get_plugin_id_version`. Iterates through up to 4 proxy URL offsets (at config offset 56 onward, 2-byte offsets), decrypts each proxy URL, and parses the newline-delimited fields: line 0 = protocol type (HTTP, SOCKS4, or SOCKS5), line 1 = hostname, line 2 = port (converted via atoi from msvcrt.dll), line 3 = username, line 4 = password. Protocol types are mapped to numeric IDs: HTTP=3, SOCKS4=1, SOCKS5=2. Each parsed proxy is stored in the corresponding slot of the output table.

### Utility / String / Memory

#### heap_alloc (0x180001590, 54 bytes)

Heap memory allocator wrapper. Takes a size parameter specifying the number of bytes to allocate. Lazily resolves HeapAlloc from kernel32.dll using the PEB walk hash `0x95FA4392` and caches the function pointer in `g_pfnHeapAlloc`. Calls HeapAlloc with flags=0x40 (HEAP_ZERO_MEMORY), ensuring all allocated memory is initialized to zero. Returns the pointer to the allocated memory block.

#### heap_free (0x1800015C8, 53 bytes)

Heap memory free wrapper. Takes a pointer to a previously allocated memory block. If the pointer is null, returns immediately without action. Otherwise, lazily resolves HeapFree from kernel32.dll using the PEB walk hash `0xF334AE83` and caches the function pointer in `g_pfnHeapFree`. Calls HeapFree to release the memory block. No return value (void function). The null-pointer check provides safe freeing behavior throughout the plugin.

#### memcpy_wrapper (0x180001964, 122 bytes)

Wrapper around the C runtime memcpy function. Takes three parameters: destination buffer pointer (`this_ptr`), source buffer pointer (`param1`), and byte count (`param2`). Lazily resolves memcpy from msvcrt.dll by decrypting the string "memcpy" via the ScatterBrain cipher and calling `resolve_api_by_name_ordinal`. Caches the function pointer in `g_pfnmemcpy` for subsequent calls. Returns the destination pointer as per standard memcpy semantics. This wrapper is used extensively throughout the Online plugin for copying C2 packet headers, system recon data, machine IDs, and other binary data structures.

#### lstrcmpi_wrapper (0x180003D48, 106 bytes)

Case-insensitive ANSI string comparison wrapper. Takes two string pointers (`this_ptr` and `param1`) and compares them using the Windows lstrcmpiA API. Lazily resolves lstrcmpiA from kernel32.dll by decrypting the function name via the ScatterBrain cipher and calling `resolve_api_by_name`. Caches the function pointer in `g_pfnlstrcmpiA`. Returns 0 if the strings match (case-insensitive), a negative value if `this_ptr` is less than `param1`, or a positive value if `this_ptr` is greater than `param1`. Used extensively in the protocol routing logic to compare URL scheme strings against protocol identifiers like TCP, HTTP, HTTPS, UDP, DNS, and URL.

#### strnicmp_wrapper (0x180004AD8, 122 bytes)

Case-insensitive string comparison wrapper with length limit. Takes three parameters: the first string (`this_ptr`), the second string (`param1`), and the maximum number of characters to compare (`param2`). Lazily resolves `_strnicmp` from msvcrt.dll by decrypting the function name via the ScatterBrain cipher and calling `resolve_api_by_name_ordinal`. Caches the function pointer in `g_pfn_strnicmp`. Returns 0 if the first `param2` characters match (case-insensitive), negative if `this_ptr` is less, or positive if `this_ptr` is greater. Used in `parse_c2_response` to validate protocol prefixes (TCP://, HTTP://, HTTPS://, UDP://, DNS://, URL://) with exact length matching.

#### create_thread_wrapper (0x180003CC0, 133 bytes)

Thread creation wrapper that calls the Windows CreateThread API. Takes three parameters: the thread start routine (`this_ptr`), the thread parameter (`param1`), and a pointer to receive the thread ID (`param2`). Lazily resolves CreateThread from kernel32.dll by decrypting the string "CreateThread" via the ScatterBrain cipher and calling `resolve_api_by_name`. Caches the function pointer in `g_pfnCreateThread`. Calls CreateThread with NULL security attributes, zero stack size, the provided start routine and parameter, creation flags of 0 (immediate start), and the thread ID output pointer. Returns the thread handle on success or NULL on failure.

#### buffer_append_bytes (0x1800054C0, 99 bytes)

Appends raw bytes to a dynamically-sized buffer structure. Takes three parameters: `this_ptr` (pointer to a buffer descriptor with fields: `total_used` at offset 0, `capacity` at offset 4, `current_offset` at offset 8, and `data_ptr` at offset 16), `param1` (source data pointer), and `param2` (number of bytes to append). Checks if the current offset plus `param2` exceeds the capacity; if so, calls `get_computername` (which is actually a realloc-like function despite its name) to grow the buffer by `param2+4096` bytes. Copies `param2` bytes from the source to `data_ptr+current_offset` via `memcpy_wrapper`, increments the offset by `param2`, and updates `total_used` if offset exceeds it. Returns 0 on success or the error code from the reallocation if it fails. This is the primary buffer builder used by `collect_system_recon` to construct the variable-length reconnaissance payload.

#### buffer_append_wstr (0x180005524, 54 bytes)

Appends a wide string from an encrypted string structure to a dynamic buffer. Takes two parameters: `this_ptr` (the buffer descriptor pointer) and `param1` (pointer to a `wstr_struct` containing encrypted data). First calls `decrypt_and_resolve` with code page 0xFDE9 to ensure the string is in the correct format. Then calls `buffer_append_bytes` to append the raw wide string data (from `param1` offset 0 for the pointer and offset 8 for the length) to the buffer. Returns the result of `buffer_append_bytes`. Used by `collect_system_recon` to append the five wide string data points (computer name, username, executable path, OS description, and config identifier) to the recon payload.

#### get_computername (0x18000555C, 96 bytes)

Buffer reallocation function (misnamed as `get_computername` in the recovered source). Takes an integer pointer (`this_ptr`, the buffer descriptor) and the new desired capacity (`param1`). Allocates a new buffer of `param1` bytes via `heap_alloc`. If allocation fails, returns error code 8 (ERROR_NOT_ENOUGH_MEMORY). Copies the existing data from the old buffer (`this_ptr[2]`, which is the data pointer at offset 16) up to `this_ptr[0]` (total used bytes) into the new buffer via `memcpy_wrapper`. Frees the old buffer via `heap_free` if non-null. Updates the data pointer (`this_ptr[2] = new buffer`) and capacity (`this_ptr[1] = param1`). Returns 0 on success. Despite its name in the decompiled output, this is a standard buffer grow/realloc function used by `buffer_append_bytes` when the current capacity is exceeded.

#### init_wstr_struct (0x1800055BC, 45 bytes)

Initializes a wide string structure (`wstr_struct`) to empty state. Takes a pointer to the 32-byte structure (`this_ptr`) and zeros all fields: QWORD at offset 0 (ANSI data pointer) = 0, DWORD at offset 8 (ANSI length) = 0, QWORD at offset 16 (wide data pointer) = 0, DWORD at offset 24 (wide length) = 0. Then calls `wstr_copy_alloc` to set an initial empty wide string from the global `g_atoi` (which contains an empty or default wide string). Returns the `this_ptr` pointer. This initialization pattern is used before any string manipulation to ensure clean state, particularly in `collect_system_recon` where 10 string structures are initialized in a loop.

#### free_decrypted_string (0x1800056C4, 59 bytes)

Frees both the ANSI and wide string components of a `wstr_struct`. Takes a pointer to the 32-byte structure (`this_ptr`). If the ANSI data pointer at offset 0 is non-null, frees it via `heap_free` and zeros the pointer and length (offset 0 and 8). If the wide data pointer at offset 16 is non-null, frees it via `heap_free` and zeros the pointer and length (offset 16 and 24). This function is called after every `decrypt_string` usage to prevent memory leaks, as each decryption allocates new buffers. It is also the cleanup function for `init_wstr_struct`-initialized structures.

#### decrypt_and_resolve (0x180005700, 200 bytes)

Converts a `wstr_struct` from wide string to ANSI (multi-byte) representation. Takes the `wstr_struct` pointer (`this_ptr`) and a code page parameter (`param1`, typically 0 for system default or 0xFDE9 for UTF-8). Lazily resolves WideCharToMultiByte from kernel32.dll using the PEB hash `0x990F95AE`. First calls WideCharToMultiByte with a null output buffer to determine the required ANSI buffer size, using the wide string at `this_ptr+16` with length from `this_ptr+24`. Allocates the ANSI buffer via `heap_alloc` and calls WideCharToMultiByte again to perform the actual conversion. If the ANSI pointer at `this_ptr+0` was previously set, frees the old buffer first. Updates `this_ptr+0` with the new ANSI pointer and `this_ptr+8` with the byte count. Returns the ANSI string pointer on success or 0 on allocation failure. This function is the reverse of `str_to_wstr` and is used to produce ANSI strings for Windows API calls that require narrow character input.

#### str_to_wstr (0x1800057C8, 233 bytes)

Converts an ANSI (multi-byte) string to a wide (Unicode) string and stores it in a `wstr_struct`. Takes the `wstr_struct` pointer (`this_ptr`) and the source ANSI string pointer (`param1`). Lazily resolves MultiByteToWideChar from kernel32.dll using the PEB hash `0xB8E61F78`. First calls MultiByteToWideChar with code page 65001 (CP_UTF8), flags 0, the source string with length -1 (null-terminated), and null output to determine the required wide character count. Allocates a wide string buffer of `(count * 2)` bytes via `heap_alloc` with saturated multiplication to prevent overflow. Calls MultiByteToWideChar again to perform the actual conversion into the allocated buffer. Frees any previous ANSI data at `this_ptr+0` and wide data at `this_ptr+16` to prevent leaks. Stores the new wide string pointer at `this_ptr+16` and the character count at `this_ptr+24`. Returns 0 on success or 8 (ERROR_NOT_ENOUGH_MEMORY) if allocation fails.

#### wstr_copy_alloc (0x1800058B4, 303 bytes)

Allocates a new wide string buffer, copies the source wide string, and stores it in the destination `wstr_struct`. Takes the destination `wstr_struct` pointer (`dst`) and the source wide string pointer (`src`). Lazily resolves lstrlenW from kernel32.dll to measure the source string length, then allocates a buffer of `(lstrlenW(src) + 1) * 2` bytes via `heap_alloc` with saturated multiplication. Copies the source string into the new buffer using lstrcpyW (lazily resolved from kernel32.dll). Frees any previous ANSI data at `dst+0` and wide data at `dst+16` to prevent memory leaks. Stores the new buffer pointer at `dst+16` and the character count (including null terminator) at `dst+24`. Returns 0 on success or 8 if allocation fails. This is the primary wide string assignment function used throughout the plugin for storing decrypted strings, computer names, usernames, and other string data.

#### wstr_concat_alloc (0x1800059E4, 403 bytes)

Concatenates a source wide string to the existing content of a destination `wstr_struct`. Takes the destination `wstr_struct` pointer (`dst`) and the source wide string pointer (`src`). Lazily resolves lstrlenW from kernel32.dll to measure the source string, then computes the total required length as `lstrlenW(src) + dst[24]` (existing wide character count). Allocates a new buffer of `(total_length * 2)` bytes via `heap_alloc` with saturated multiplication. Copies the existing wide string from `dst+16` into the new buffer using lstrcpyW, then appends the source string using lstrcatW (lazily resolved from kernel32.dll). Frees any previous ANSI data at `dst+0` and wide data at `dst+16`. Stores the new concatenated buffer at `dst+16` and the new total length at `dst+24`. Returns 0 on success or 8 if allocation fails. Used in the DGA logic (`http_beacon_to_c2`) to build URLs by concatenating domain parts with the template suffix.

### Compiler-Generated

#### __alloca_probe (0x180005B90, 78 bytes)

Compiler-generated stack probe function (`__alloca_probe` / `__chkstk`). This is an automatically emitted helper that ensures sufficient stack space is committed before large stack allocations. Takes the requested allocation size in RAX (implicitly, as set by the compiler before the call). Probes each 4096-byte page of the requested stack region to trigger guard page exceptions and commit memory from the stack reserve. This function is called automatically by the compiler whenever a function uses more than one page (4096 bytes) of stack space, such as in `http_fetch_url` (which has approximately 8KB of local buffers) and `collect_system_recon` (which has approximately 2KB of local variables). No explicit parameters or return value in the calling convention.
