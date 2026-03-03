# Blob 2 — C2 Config / File Operations Plugin (Plugin ID 102, "Config")

## Summary

| Property | Value |
|----------|-------|
| File | Private archive artifact (available on vetted request) |
| Image Size | 0x6000 (24576 bytes) |
| Entry Point RVA | 0x10A4 |
| Functions | 27 (all renamed) |
| Sections | .text, .rdata, .data2, .data3, .idata |
| Timestamp | 0x58AEBA (2017-02-22/23) |
| idasql Port | 8202 |
| Plugin ID (CMD 102) | 102 (integer, not string) |
| Sub-command Base | 0x660000 |
| Static Imports | **Zero** — all APIs resolved dynamically |

## Role

**C2 configuration management module.** Manages an encrypted 2136-byte configuration blob that can be read, updated, or replaced via remote C2 commands. Persists configuration to both filesystem and Windows Registry under PRNG-derived randomized key paths. Operates with zero PE imports — bootstraps entirely from PEB walk and parent context interface.

## Zero-Import Architecture

This plugin has **no static PE imports**. All functionality comes from three sources:

1. **PEB Walk Hash Resolution** (`resolve_export_by_hash` at 0x180001224): Walks InLoadOrderModuleList, hashing with `(tolower(c) + ROR8(hash)) ^ 0x7C35D9A3`. Bootstraps 6 APIs: `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualFree`, `MultiByteToWideChar`, `WideCharToMultiByte`.

2. **Dynamic DLL Loading**: Decrypts DLL names from rolling-XOR blobs in .rdata, resolves APIs from ws2_32.dll, kernel32.dll, advapi32.dll. All cached in .data2 globals.

3. **Parent Context Vtable** (`qword_180005020`): Parent provides rich interface at known offsets for buffer allocation/freeing, encryption/decryption, inter-plugin communication, and character conversion.

## Entry Point: DllMain_dispatcher (0x1800010A4)

| fdwReason | Command | Action |
|-----------|---------|--------|
| 0 | DLL_PROCESS_DETACH | No-op, returns 1 |
| 1 | CMD 1 (Attach) | Populates 3-slot vtable at `0x180005000` |
| 100 | CMD 100 | Stores parent context pointer to `qword_180005020` |
| 101 | CMD 101 | No-op (returns 1) |
| 102 | CMD 102 | Writes `102` to `*lpReserved` |
| 103 | CMD 103 | Decrypts file path, resolves API, calls write-config handler |
| 104 | CMD 104 | Returns vtable pointer |

## Vtable (3 slots at `qword_180005000`)

| Slot | Address | Function | Purpose |
|------|---------|----------|---------|
| 0 | 0x180001318 | `vtfn_cmd_dispatch` | Sub-command router: 0x660000-0x660002 |
| 1 | 0x180001934 | `vtfn_heartbeat_handler` | Periodic config reload/update |
| 2 | 0x180002C00 | `gen_random_value_name` | PRNG-based registry key name generator |

## Sub-command Dispatch

| Sub-cmd | ID | Handler | Purpose |
|---------|----|---------|---------|
| 0 | 0x660000 | `cmd_subcmd0_list_config` | Read current config, send response via plugin 104 |
| 1 | 0x660001 | `cmd_subcmd1_update_config` | Process incoming config modification |
| 2 | 0x660002 | `cmd_subcmd2_replace_config` | Full config replacement with fresh initialization |

## Config Blob Structure (2136 bytes / 0x858)

| Offset | Size | Field |
|--------|------|-------|
| +0 | 2 | Total header size |
| +2 | 2 | Encrypted field 0 size (identifier) |
| +24-34 | 2 each | Encrypted field 1-5 offsets |
| +64 | 4 | Numeric field A |
| +68 | 4 | Numeric field B |
| +72 | 4 | Numeric field C |
| +76 | 4 | Numeric field D |
| +88+ | var | Encrypted string data region |

Serialized packet: 2156 bytes (20-byte header + 2136-byte config). Header contains `htonl(magic_marker)` at +4 and `htonl(2136)` at +12.

### String Encryption (encrypt_string_field at 0x180001DB0)
Time-seeded rolling XOR: `key_seed = 30561 * (wYear + wMonth) - 3150`. Each byte XORed with evolving key using standard polynomial PRNG.

### Config Validation
- Magic marker at offset +4: must equal `0x12345678` after ntohl
- Size at offset +12: must equal 2136 after ntohl
- If starts with "XXXX" (0x58585858): re-initialized from template

## Registry Persistence

### Path Construction (`build_registry_path` at 0x1800026D0)
1. Generates 4 random name components using `gen_random_value_name` with seeds 17201-17204
2. Decrypts base registry key path
3. Appends path segments from encrypted blobs
4. Creates via `RegSetValueExW`

### Key Path Creation (`ensure_regkey_path_exists` at 0x180002E18)
Walks path splitting on backslashes (0x5C), creates each level. Error 183 (ERROR_ALREADY_EXISTS) treated as success.

## File-Based Config Persistence
- **Read** (`read_config_from_file` at 0x180001B78): CreateFileW(GENERIC_READ) + ReadFile + CloseHandle
- **Write** (`vtfn_persist_config` at 0x1800022E8): CreateFileW(GENERIC_WRITE) + WriteFile + CloseHandle

## Parent Context Interface Offsets

| Offset | Semantics |
|--------|-----------|
| +0x18 | `get_plugin_by_id(id)` -> plugin* |
| +0x20 | `release_plugin(plugin*)` |
| +0xA0 | `alloc_comm_buffer(out, size)` |
| +0xA8 | `encrypt_serialize(buf, data, size)` |
| +0xB0 | `decrypt_deserialize(buf, data, size)` |
| +0xC0 | `free_buffer(ptr)` |
| +0xD0 | `int_to_printable_char(int)` |
| +0xE0 | Default config data pointer |

Uses **plugin 104** as communication relay: calls parent_ctx+0x18(104), then plugin 104's vtable at +0x48 to transmit data.

## All 27 Functions

| Address | Name | Purpose |
|---------|------|---------|
| 0x180001000 | `resolve_api_from_dll` | LoadLibraryA + GetProcAddress |
| 0x1800010A4 | `DllMain_dispatcher` | Entry/command dispatcher |
| 0x1800011B4 | `heap_alloc` | VirtualAlloc wrapper |
| 0x1800011EC | `heap_free` | VirtualFree wrapper |
| 0x180001224 | `resolve_export_by_hash` | PEB walk API hash resolver |
| 0x180001318 | `vtfn_cmd_dispatch` | Sub-command router |
| 0x1800013C4 | `cmd_subcmd0_list_config` | Read + return config |
| 0x180001558 | `cmd_subcmd1_update_config` | Update config fields |
| 0x1800016D0 | `cmd_subcmd2_replace_config` | Full config replacement |
| 0x180001934 | `vtfn_heartbeat_handler` | Periodic config reload |
| 0x1800019F8 | `deserialize_config_blob` | Validate + load config |
| 0x180001B78 | `read_config_from_file` | File-based config read |
| 0x180001DB0 | `encrypt_string_field` | Time-seeded XOR encrypt |
| 0x180001F0C | `init_config_template` | Fresh config initialization |
| 0x1800022E8 | `vtfn_persist_config` | Write config to file + registry |
| 0x1800026D0 | `build_registry_path` | Construct randomized reg path |
| 0x180002C00 | `gen_random_value_name` | PRNG name generator (3-8 chars) |
| 0x180002E18 | `ensure_regkey_path_exists` | Create registry key hierarchy |
| 0x180002F84 | `get_proc_from_dll_a` | DLL A API resolution |
| 0x180003028 | `memcpy_wrapper` | Memory copy |
| 0x1800030A4 | `get_proc_from_dll_b` | DLL B API resolution |
| 0x180003148 | `send_response_to_parent` | Send via plugin 104 relay |
| 0x1800031A4 | `decrypt_string` | Polynomial XOR decrypt |
| 0x1800032B8 | `widechar_convert` | Wide/multibyte conversion |
| 0x18000327C | `string_obj_free` | Free string pair |
| 0x180003380 | `multibyte_to_wide` | UTF-8 to wide |
| 0x18000346C | `wstring_copy` | Wide string duplication |

## Resolved API Cache (25+ globals)

Key cached APIs: `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `VirtualFree`, `htonl`, `ntohl`, `memcpy`, `memset`, `lstrlenW`, `CloseHandle`, `CreateFileW`, `WriteFile`, `ReadFile`, `RegSetValueExW`, `CreateDirectoryW`, `CryptAcquireContextW`, `CryptGenRandom`, `GetSystemTime`, `MultiByteToWideChar`, `WideCharToMultiByte`.

---

## Detailed Function Reference

All 27 functions in the Config plugin, grouped by category. Every function listed with its virtual address, size, and full behavioral description extracted from the annotated IDB.

---

### API Resolution

#### resolve_api_from_dll (0x180001000, 161 bytes)

Resolves a Windows API function pointer from kernel32.dll by name. Takes a single parameter (`this_ptr`) which is the ANSI function name to look up. On first invocation, lazily loads kernel32.dll by decrypting the string `kernel32.dll` from an encrypted blob, then resolving `LoadLibraryA` via PEB export hash walk (hash `0xBDBD4E16` = -1113427994). The loaded kernel32 handle is cached in `g_pfnkernel32_dll_2` for subsequent calls. `GetProcAddress` is similarly resolved by export hash (`0xA16B3307` = -1586642601) and cached in `g_pfnGetProcAddress`. Returns the resolved function pointer from kernel32.dll, or NULL if lookup fails. This is the primary API resolution mechanism for kernel32 exports used throughout the Config plugin, and is called by nearly every function that needs Win32 APIs.

#### resolve_export_by_hash (0x180001224, 241 bytes)

Resolves an exported function from ntdll.dll by walking the PEB `InLoadOrderModuleList`. Takes a single integer parameter which is the target export hash to find. First locates ntdll.dll by computing a case-insensitive hash of each loaded module name using the algorithm: `hash = (char | 0x20 + ROR(hash, 8)) XOR 0x7C35D9A3`, matching the hardcoded ntdll hash `0xFD5AA241` (-44363167). Once the ntdll base is found, walks the export directory table computing the same ROR8+XOR hash over each export name until matching the requested hash. Returns the resolved function pointer (`base + export RVA`) or NULL if the hash is not found or ntdll is not loaded. This is the lowest-level API resolution mechanism used to bootstrap `HeapAlloc`, `HeapFree`, `GetProcAddress`, and other critical ntdll exports before higher-level resolution via kernel32 or ws2_32 is available.

#### get_proc_from_dll_a (0x180002F84, 161 bytes)

Resolves an API function by name from msvcrt.dll. Takes a single parameter (`this_ptr`) which is the ANSI function name to look up. On first invocation, lazily loads msvcrt.dll by decrypting the DLL name from `enc_msvcrt_dll`, then calling `LoadLibraryA` (resolved via PEB export hash `0xBDBD4E16`). The loaded msvcrt handle is cached in `g_pfnmsvcrt_dll` for subsequent calls. `GetProcAddress` is resolved by PEB export hash `0xA16B3307` and cached in `g_pfnGetProcAddress`. Returns the resolved function pointer from msvcrt.dll. This function is the resolution mechanism for C runtime functions like `memcpy` and `memset` that the Config plugin needs but cannot import directly due to having zero PE imports. It mirrors the structure of `resolve_api_from_dll` but targets msvcrt.dll instead of kernel32.dll.

#### get_proc_from_dll_b (0x1800030A4, 161 bytes)

Resolves an API function by name from ws2_32.dll (Winsock2). Takes a single parameter (`this_ptr`) which is the ANSI function name to look up. On first invocation, lazily loads ws2_32.dll by decrypting the DLL name from `enc_ws2_32_dll`, then calling `LoadLibraryA` (resolved via PEB export hash `0xBDBD4E16`). The loaded ws2_32 handle is cached in `g_pfnws2_32_dll` for subsequent calls. `GetProcAddress` is resolved by PEB export hash `0xA16B3307` and cached in `g_pfnGetProcAddress`. Returns the resolved function pointer from ws2_32.dll. This function is the resolution mechanism for network byte order conversion functions (`htonl`, `ntohl`) and address conversion functions (`inet_addr`) that the Config plugin uses for its wire protocol and IP address handling. It mirrors the structure of `resolve_api_from_dll` and `get_proc_from_dll_a` but targets ws2_32.dll.

---

### Plugin Protocol / Dispatch

#### DllMain_dispatcher (0x1800010A4, 269 bytes)

Plugin entry point implementing the ScatterBrain `sb_plugin_entry_t` dispatch protocol. Handles `DLL_PROCESS_ATTACH` (`fdwReason=1`) by populating a 3-entry vtable: slot 0 = `vtfn_cmd_dispatch` (command handler), slot 1 = `vtfn_heartbeat_handler` (periodic config refresh), slot 2 = `gen_random_value_name` (deterministic name generation). Custom dispatch reasons (100-104) follow the standard SB plugin handshake: reason 100 stores the framework vtable pointer (`g_vtfn_lpReserved`) for accessing shared services like heap management, encryption, and plugin lookup; reason 102 returns the numeric plugin ID `102` via `lpReserved`; reason 103 copies the decrypted wide string `Config` into `lpReserved` as the plugin display name using `lstrcpyW`; reason 104 stores a pointer to the vtable function array. Always returns TRUE (1) regardless of dispatch reason. The framework vtable at `g_vtfn_lpReserved` provides offsets +24 (acquire_plugin), +32 (release_plugin), +160 (alloc), +168 (encrypt), +176 (decrypt), +192 (free), +208 (char_transform), and +224 (default config pointer).

#### vtfn_cmd_dispatch (0x180001318, 169 bytes)

Vtable command dispatcher (slot 0 in the plugin vtable). Receives a context pointer and a command buffer, extracts the 4-byte subcmd ID at `cmd_buf+4`, converts it from network byte order via `ntohl` (lazily resolved from ws2_32.dll), then subtracts the base command ID `0x660000` (6684672 decimal) to produce a zero-based index. Routes to three sub-handlers: index 0 (subcmd `0x660000`) calls `cmd_subcmd0_list_config` to dump the current 2136-byte config blob; index 1 (subcmd `0x660001`) calls `cmd_subcmd1_update_config` to persist a new config blob to disk; index 2 (subcmd `0x660002`) calls `cmd_subcmd2_replace_config` to delete the existing config file and rebuild the registry path. Returns the sub-handler result on success, or `0xFFFFFFFF` (-1) if the subcmd ID does not match any known command. The `ntohl` function is resolved from ws2_32.dll via `get_proc_from_dll_b` and cached in `g_pfnntohl`.

#### send_response_to_parent (0x180003148, 90 bytes)

Sends a response buffer back to the parent framework via the Online plugin (ID 104). Takes two parameters: `this_ptr` is the connection/session context handle, and `param1` is the pointer to the response buffer to send. Acquires a reference to the Online plugin by calling the framework vtable acquire function at offset +24 with plugin ID 104. Invokes the Online plugin send method at vtable slot 9 (offset +72 from the plugin object vtable at +56), passing the session context, response buffer, and a timeout of -1 (`0xFFFFFFFF` = infinite/blocking). Releases the Online plugin reference via the framework vtable release function at offset +32. Returns the send method result as an unsigned 32-bit value (0 on success). This function is the sole output path for all three command handlers (subcmd0, subcmd1, subcmd2), routing config query results and status codes back to the C2 controller through the Online plugin transport layer.

---

### Config Commands (0x660000-0x660002)

#### cmd_subcmd0_list_config (0x1800013C4, 401 bytes)

Handles subcmd `0x660000` (LIST_CONFIG): reads the current in-memory config blob from the inner PE framework and sends it back to the C2 server. Allocates a 2156-byte response buffer (20-byte header + 2136-byte config payload) via the framework vtable alloc function at offset +160. Acquires the Config plugin instance (ID 102) via the framework vtable at offset +24, calls its read method (vtable+56 -> slot 1) to copy the current 2136-byte config blob into the response at offset +20, then releases the plugin reference via offset +32. Constructs a network-byte-order response header: bytes 4-7 = `htonl(0x660000)` as the response command ID, bytes 8-11 = `htonl(0)` as the status code, bytes 12-15 = `htonl(2136)` as the payload size. Sends the assembled response via `send_response_to_parent` which forwards it through the Online plugin (ID 104). Frees the response buffer via framework vtable offset +192 and returns the send status.

#### cmd_subcmd1_update_config (0x180001558, 373 bytes)

Handles subcmd `0x660001` (UPDATE_CONFIG): persists the config blob embedded in the command buffer to disk. Extracts the payload size from `cmd_buf[3]` and converts via `ntohl` (though the result is unused, this validates the field). Overwrites `cmd_buf[1]` with `htonl(0x660001)` to mark the response command ID. Calls `vtfn_persist_config` with a pointer to `cmd_buf+20` (the 2136-byte config payload at offset 5 DWORDs into the buffer) which serializes and writes it to the config file on disk. Stores the persist return code (0 on success, Win32 error code on failure) in `cmd_buf[2]` via `htonl`, and sets `cmd_buf[3]` to `htonl(0)` indicating zero-length response payload. Sends the modified command buffer back as the response via `send_response_to_parent`, which routes through the Online plugin (ID 104). Returns the send status code.

#### cmd_subcmd2_replace_config (0x1800016D0, 611 bytes)

Handles subcmd `0x660002` (REPLACE_CONFIG): deletes the existing config persistence file and resets to a clean state. Allocates a 2136-byte buffer via `heap_alloc`, deserializes the current config blob into it (falling back to `init_config_template` if deserialization fails), then extracts the install ID from the config to build the deterministic filesystem path via `build_registry_path`. Attempts to delete the config file using `DeleteFileW` (lazily resolved from kernel32.dll). If `DeleteFileW` fails, checks `GetLastError` and silently suppresses `ERROR_FILE_NOT_FOUND` (2) and `ERROR_PATH_NOT_FOUND` (3) by zeroing the error code, treating a missing file as success. Constructs the response header: `cmd_buf[1]` = `htonl(0x660002)` as the response command ID, `cmd_buf[2]` = `htonl(error_code)` as the status, `cmd_buf[3]` = `htonl(0)` for zero payload. Sends the response via `send_response_to_parent` and cleans up the path string object. Returns the send status code.

---

### Config Parsing / Serialization

#### deserialize_config_blob (0x1800019F8, 384 bytes)

Deserializes an encrypted config blob into a 2136-byte config structure. Takes a destination buffer (`this_ptr`) and an optional source pointer (`ptr_arg1`); if `ptr_arg1` is NULL, reads from the framework default config at `g_vtfn_lpReserved+224`. First checks for the 4-byte sentinel `XXXX` (`0x58585858`) which indicates an uninitialized config, and if found, calls `init_config_template` to populate defaults and returns. Otherwise, decrypts the blob using the framework decrypt function at vtable offset +176, passing a 2048-byte max output size. Validates the decrypted header: bytes 4-7 must equal `htonl(0x12345678)` which is the magic value 305419896 in decimal, and bytes 12-15 must equal `htonl(2136)` confirming the expected config payload size. On successful validation, copies 2136 bytes from decrypted offset +20 into the destination buffer via `memcpy_wrapper`, frees the decrypted buffer via vtable offset +192, and returns 0. On any validation failure (bad magic, wrong size, or decrypt error), frees the buffer and returns an error code.

#### read_config_from_file (0x180001B78, 566 bytes)

Reads the config blob from a file on disk and deserializes it into a 2136-byte config structure. Takes a destination buffer (`this_ptr`) and the file path (`param1`) as a wide string. Allocates a 0x2000-byte (8192) temporary read buffer via `heap_alloc`, returning error code 8 (`ERROR_NOT_ENOUGH_MEMORY`) on allocation failure. Opens the file with `CreateFileW` using `GENERIC_READ` (`0x80000000`), `FILE_SHARE_READ` (1), and default creation/attribute settings. If the file handle is `INVALID_HANDLE_VALUE` (-1), calls `GetLastError` to capture the Win32 error. Otherwise reads up to 0x2000 bytes via `ReadFile` into the temporary buffer, checking for `ReadFile` failure via `GetLastError`. On successful read, closes the file handle via `CloseHandle` and calls `deserialize_config_blob` to parse and validate the encrypted blob contents (checking for `0x12345678` magic and 2136-byte size). All API functions (`CreateFileW`, `ReadFile`, `CloseHandle`, `GetLastError`) are lazily resolved from kernel32.dll via `resolve_api_from_dll`. Frees the temporary buffer via `heap_free` and returns 0 on success or the Win32 error code on failure.

#### encrypt_string_field (0x180001DB0, 346 bytes)

Encrypts a string field for storage in the 2136-byte config blob using an IMUL-based rolling XOR cipher. Takes a destination pointer (`this_ptr`) within the config blob where the encrypted field will be written. The plaintext string is obtained from the current string object context, first converted to multibyte then to wide via `widechar_convert` with codepage `0xFDE9` (65001 = UTF-8). Generates a 2-byte cipher key seed using `QueryPerformanceCounter` (lazily resolved from kernel32.dll): `seed = (30561 * (counter_low + counter_high) - 3150)` truncated to 16 bits. Allocates a buffer of `(string_length + 2)` bytes, writes the 2-byte key as a little-endian prefix, then XOR-encrypts each subsequent byte using the PRNG formula: `key = -42860544 * key - 135791246 * HIWORD(key) - 1043215206` (the standard ScatterBrain IMUL cipher). Copies the encrypted buffer (key prefix + ciphertext) into the config blob at `this_ptr` via `memcpy_wrapper`. Returns the total encrypted field size (`string_length + 2`) which is stored in the config header to track field boundaries.

#### init_config_template (0x180001F0C, 985 bytes)

Initializes a default 2136-byte config template with hardcoded values when no persisted config exists (`XXXX` sentinel detected). Zeros the entire buffer via msvcrt `memset` (lazily resolved via `get_proc_from_dll_a`), then sets the 2-byte variable-data offset at offset 0 to 0. Populates encrypted string fields sequentially starting at offset 88 in the blob: (1) install ID string `12345678` stored with its encrypted size recorded at `config+2`; (2) beacon string `hello` with size at `config+24`; (3) six C2 URL strings for each transport protocol: `TCP://127.0.0.1:44444`, `HTTP://127.0.0.1:44444`, `HTTPS://127.0.0.1:44444`, `UDP://127.0.0.1:44444`, `DNS://127.0.0.1:44444`, with encrypted sizes stored at config offsets +26, +28, +30, +32 respectively. Each string is encrypted via `encrypt_string_field` which prepends a 2-byte PRNG key. Additionally populates four 4-byte `inet_addr` fields at config offsets +64, +68, +72, +76 by converting IP:port strings `127.0.0.1`, `127.0.0.1:4120`, `127.0.0.1:4130`, `127.0.0.1:4140` via `inet_addr` (resolved from ws2_32.dll). These defaults serve as fallback C2 endpoints when no operator-configured config has been deployed.

#### vtfn_persist_config (0x1800022E8, 997 bytes)

Persists the current config blob to an encrypted file on disk. Takes a context parameter (`ctx`) pointing to a 2136-byte config payload to write. Allocates a working buffer and deserializes the current config via `deserialize_config_blob` to extract the install ID for path generation. Builds the deterministic filesystem path under `ALLUSERSPROFILE` via `build_registry_path` (using the decrypted install ID from config offset `*header + 88`). Allocates a 2156-byte serialization buffer (20-byte header + 2136-byte config) via the framework vtable alloc at offset +160. Constructs the header: bytes 4-7 = `htonl(0x12345678)` as the magic signature (305419896 decimal), bytes 8-11 = `htonl(0)` as reserved, bytes 12-15 = `htonl(2136)` as the payload size. Copies the 2136-byte config into the buffer at offset +20 via `memcpy_wrapper`. Encrypts the entire 2156-byte buffer using the framework encrypt function at vtable offset +168, which updates the buffer pointer and size in-place. Ensures the directory tree exists via `ensure_regkey_path_exists`, then writes the encrypted buffer to the file using `CreateFileW` with `GENERIC_WRITE`, `WriteFile`, and `CloseHandle`. Frees all intermediate buffers and returns 0 on success or a Win32 error code on failure.

#### vtfn_heartbeat_handler (0x180001934, 196 bytes)

Vtable heartbeat handler (slot 1 in the plugin vtable). Called periodically by the framework to keep the in-memory config synchronized with the on-disk persistence file. Takes two parameters: `ctx` is a pointer to the current 2136-byte config structure (cast as `unsigned __int16*` since the first word is an offset), and `cmd_buf` is a boolean flag. Always calls `deserialize_config_blob` first to validate and refresh the config from the framework default config pointer. If `cmd_buf` is nonzero (indicating a reload is requested), builds the filesystem path by extracting the install ID from `ctx` (at offset `*ctx + 88` where `*ctx` is the 2-byte variable-data offset), calling `build_registry_path` to construct the full path under `ALLUSERSPROFILE`. Then allocates a fresh 2136-byte buffer, reads the config file via `read_config_from_file`, and if successful (return 0), copies the file-based config over the in-memory config via `memcpy_wrapper`. Cleans up the temporary buffer and path string. Always returns 0.

#### build_registry_path (0x1800026D0, 1326 bytes)

Builds the full filesystem path for config file persistence. Generates four deterministic pseudo-random path segments by calling `gen_random_value_name` with seeds `0x4331`, `0x4332`, `0x4333`, `0x4334` respectively, each producing alphabetic strings of 3-8 characters derived from the install ID and volume serial number. Starts with the `ALLUSERSPROFILE` environment variable (decrypted from `enc_ALLUSERSPROFILE`), copies it into a local 256-byte ANSI buffer via `lstrcpyA`. Appends the four segments interleaved with backslash separators and two additional encrypted path components (`g_msvcrt_dll` and `g_msvcrt_dll_4178`, which despite their decompiler names are actually encrypted path fragment strings), building a path like: `ALLUSERSPROFILE\seg1\seg2\path1\seg3\path2\seg4`. Converts the assembled ANSI path to wide string via `multibyte_to_wide`, then expands environment variables using `ExpandEnvironmentStringsW` (lazily resolved from kernel32.dll) into a 2048-wchar output buffer. Stores the final expanded wide path into the output string object for use by the caller.

#### gen_random_value_name (0x180002C00, 533 bytes)

Generates a deterministic pseudo-random alphabetic string for use as directory or file name segments in the config persistence path. Takes four parameters: `this_ptr` is the output buffer, `param1` is the minimum string length, `param2` is the maximum string length, and `param3` is a 16-bit seed value (e.g. `0x4331`-`0x4334` for the four path segments). Allocates a 2136-byte buffer, deserializes the current config blob, extracts and decrypts the install ID string from config offset `*header + 88`, then frees the config buffer. Iterates over each character of the decrypted install ID, hashing it with the volume serial number using the formula: `param3 = char + HIWORD(seed) + (seed << 16)`, where `seed = (g_dwVolumeSerial - 764667742) XOR param3`. The volume serial is obtained on first call by resolving `GetSystemDirectoryW` and `GetVolumeInformationW` from kernel32.dll, reading the system drive root and caching the serial in `g_dwVolumeSerial` with `g_bVolumeInfoCached` as a one-time flag. The final hash determines string length as `param1 + (hash % (param2 - param1 + 1))` and each output character as `'a' + (hash_byte % 26)`, producing purely lowercase alphabetic names that are consistent across runs on the same machine with the same install ID.

#### ensure_regkey_path_exists (0x180002E18, 361 bytes)

Ensures all directories in a wide-string file path exist by iterating character-by-character. Starts at character index 3 (skipping the drive letter prefix like `C:\`) and scans forward. At each backslash character (`0x5C` = 92), temporarily null-terminates the string at that position, calls `CreateDirectoryW` (lazily resolved from kernel32.dll) to create the directory, then restores the backslash. If `CreateDirectoryW` fails, captures the error via `GetLastError`. Continues walking the entire path string via `lstrlenW` to determine the total length. After processing all segments, checks the final error code: if it is `ERROR_ALREADY_EXISTS` (183), treats it as success and returns 0. Otherwise returns the last Win32 error code. This function is called by `vtfn_persist_config` to create the nested directory structure under `ALLUSERSPROFILE` before writing the encrypted config file. The approach of temporarily modifying the path string in place is a common pattern for recursive directory creation without requiring a separate buffer or recursive function calls.

---

### Utility / Memory

#### heap_alloc (0x1800011B4, 54 bytes)

Allocates a block of memory from the process default heap using `HeapAlloc`. The size parameter specifies the number of bytes to allocate. On first call, lazily resolves `HeapAlloc` by walking the PEB export table with hash `0x95FB5B52` (-1780875694). The resolved function pointer is cached in `g_pfnHeapAlloc` for subsequent calls. Calls `HeapAlloc` with `dwFlags=64` which is not a standard flag combination, suggesting the caller treats it as `HEAP_ZERO_MEMORY` (`0x08`) or a custom value. Returns the pointer to the allocated memory block, or NULL on failure. This is the universal heap allocator used by every function in the Config plugin that needs dynamic memory.

#### heap_free (0x1800011EC, 53 bytes)

Frees a heap allocation via `HeapFree`. Takes a pointer parameter and performs a null-safety check before attempting to free, silently returning if the pointer is NULL. On first call, lazily resolves `HeapFree` by walking the PEB export table with hash `0xF3367B63` (-214305309). The resolved function pointer is cached in `g_pfnHeapFree` for subsequent calls. Does not return a value. This is the universal heap deallocator paired with `heap_alloc`, used throughout the Config plugin for cleanup of temporary buffers, decrypted strings, and config blob working copies.

#### memcpy_wrapper (0x180003028, 122 bytes)

Wrapper around msvcrt `memcpy`. Copies `param2` bytes from source buffer `param1` to destination buffer `this_ptr`. On first call, lazily resolves the `memcpy` function from msvcrt.dll by decrypting the string `memcpy` from `enc_memcpy` and calling `get_proc_from_dll_a`. The resolved function pointer is cached in `g_pfnmemcpy` for subsequent calls. Returns the destination pointer (standard `memcpy` behavior). This is the primary memory copy function used throughout the Config plugin for operations like copying the 2136-byte config blob between buffers, writing encrypted fields into the config structure, and assembling serialized response packets. Since the plugin has zero PE imports, all CRT functions must be resolved dynamically through this pattern.

#### decrypt_string (0x1800031A4, 215 bytes)

Decrypts an encrypted string blob using the ScatterBrain IMUL rolling XOR cipher. Takes an output string object pointer (`out_str`) and a pointer to the encrypted blob (`enc_blob`). Allocates a 4096-byte working buffer via `heap_alloc`. Reads the 2-byte little-endian cipher key from the first two bytes of the encrypted blob: `key = enc_blob[0] | (enc_blob[1] << 8)`. Decrypts each subsequent byte by XORing with the low byte of the running key, then advances the key using the IMUL PRNG formula: `key = -42860544 * key - 135791246 * HIWORD(key) - 1043215206`. Decryption terminates when a null byte is produced or the output exceeds 4090 bytes. Initializes the output string object to zeroes (clearing both narrow and wide buffer pointers and their lengths), then converts the decrypted narrow string to a wide string via `multibyte_to_wide` using UTF-8 codepage 65001. Frees the temporary working buffer via `HeapFree` (directly resolved, not through `heap_free` wrapper). Returns the output string object pointer. This cipher is identical to the IMUL cipher used across all ScatterBrain plugins.

#### string_obj_free (0x18000327C, 59 bytes)

Frees a dual-buffer string object that contains both narrow (ANSI/UTF-8) and wide (UTF-16) string representations. The string object layout is: offset 0 = narrow buffer pointer (8 bytes), offset 8 = narrow buffer length (4 bytes), offset 16 = wide buffer pointer (8 bytes), offset 24 = wide buffer length (4 bytes), totaling 28 bytes. First checks the narrow buffer pointer at offset 0; if non-NULL, frees it via `heap_free` and zeroes both the pointer and length fields. Then checks the wide buffer pointer at offset 16; if non-NULL, frees it via `heap_free` and zeroes both the pointer and length fields. This function is called extensively throughout the Config plugin to clean up temporary string objects produced by `decrypt_string`, `widechar_convert`, and `multibyte_to_wide` operations. Does not return a value.

#### widechar_convert (0x1800032B8, 200 bytes)

Converts the wide (UTF-16) string in a string object to a narrow (codepage-encoded) string using `WideCharToMultiByte`. Takes the string object pointer (`this_ptr`) and a codepage parameter (`param1`). If `param1` is 0, performs a standard UTF-16 to ANSI conversion and returns the raw narrow buffer pointer. If `param1` is nonzero (e.g. `0xFDE9` = 65001 for UTF-8), uses it as the target codepage. Calls `WideCharToMultiByte` twice: first with zero output buffer to determine the required size, allocates the buffer via `heap_alloc`, then calls again to perform the actual conversion. The source wide string is read from the string object at offset +16 (pointer) and +24 (length). After conversion, frees the old narrow buffer at offset 0 if non-NULL, then stores the new narrow buffer pointer and length. The `WideCharToMultiByte` function is lazily resolved via PEB export hash `0x98DA6E2E` (-1726302226) and cached in `g_pfnUnk_5100`. Returns the new narrow buffer pointer, or NULL on allocation failure.

#### multibyte_to_wide (0x180003380, 233 bytes)

Converts a multibyte (UTF-8) string to a wide (UTF-16) string using `MultiByteToWideChar` with codepage 65001 (`CP_UTF8`). Takes the string object pointer (`this_ptr`) and the source narrow string pointer (`param1`). Calls `MultiByteToWideChar` twice: first with zero output buffer and length -1 (null-terminated input) to determine the required wide character count, allocates a buffer of `(count * 2)` bytes via `heap_alloc` using `saturated_mul` for overflow protection, then calls again to perform the actual conversion. If heap allocation fails, returns error code 8 (`ERROR_NOT_ENOUGH_MEMORY`). After successful conversion, frees both the old narrow buffer (offset 0) and old wide buffer (offset 16) if they are non-NULL, zeroing their pointers and lengths. Stores the new wide buffer pointer at offset +16 and the wide character count at offset +24 in the string object. The `MultiByteToWideChar` function is lazily resolved via PEB export hash `0xB8E86378` (-1193924104) and cached in `g_pfnUnk_5108`. Returns 0 on success.

#### wstring_copy (0x18000346C, 303 bytes)

Copies a wide (UTF-16) string into a string object. Takes the destination string object pointer (`this_ptr`) and the source wide string pointer (`param1`). Measures the source string length via `lstrlenW` (lazily resolved from kernel32.dll), adds 1 for the null terminator, and allocates a wide buffer of `(length * 2)` bytes via `heap_alloc` using `saturated_mul` for overflow safety. If allocation fails, returns error code 8 (`ERROR_NOT_ENOUGH_MEMORY`). Copies the source string into the new buffer via `lstrcpyW` (lazily resolved from kernel32.dll). Frees both the old narrow buffer (offset 0) and old wide buffer (offset 16) in the destination string object if non-NULL, zeroing their pointers and lengths. Stores the new wide buffer at offset +16 and the character count (including null terminator) at offset +24. Returns 0 on success. This function is used to initialize string objects from literal wide strings, particularly for the config persistence path construction in `build_registry_path` and `vtfn_heartbeat_handler`.
