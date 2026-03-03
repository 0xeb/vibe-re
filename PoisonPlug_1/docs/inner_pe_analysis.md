# Inner PE Analysis

<a id="inner-overview"></a>
## Overview

The inner PE (analyzed from a private archive artifact) is a ScatterBrain plugin DLL exposing a **26-function vtable** to the C2 framework. It uses the same ROR-8/XOR/`0x7C35D9A3` hash algorithm as the outer loader for runtime API resolution.

- **76 functions** in `.text` (0x180001000–0x180006000)
- **Single import**: `KERNEL32.dll!GetSystemTime`
- **All other APIs** resolved dynamically via hash or LoadLibraryA+GetProcAddress with encrypted DLL names
- **476 "strings"** in `.rdata` — all encrypted (XOR with 2-byte key prefix)

For the cross-plugin command protocol and registration lifecycle in one place, see [how_plugins_work.md](how_plugins_work.md).
Sensitive databases and binary artifacts referenced in this analysis are not distributed in this public repo. See [ARTIFACT_ACCESS.md](../ARTIFACT_ACCESS.md).

<a id="inner-entry-dispatcher"></a>
## Entry Point: `DllMain_dispatcher` (0x180004344)

Custom command dispatcher using `fdwReason` as command ID:

| Command | Action |
|---------|--------|
| 0 | `cmd0_init_or_cleanup(hinstDLL, fdwReason, lpReserved)` |
| 1 | `cmd1_attach_handler(hinstDLL, lpReserved)` — main init |
| 101 | `*(DWORD*)lpReserved = 100` — returns version/capability |
| 102 | `cmd102_custom_command(lpReserved)` |
| 104 | `*(QWORD*)lpReserved = &g_vtable_status` — returns vtable pointer |

Returns TRUE (1) when handler returns 0 (success).

<a id="inner-init-handler"></a>
## Initialization: `cmd1_attach_handler` (0x180004054)

Called with command 1 (DLL_PROCESS_ATTACH equivalent). Performs:

1. **Process payload**: `init_payload_context(payload_arg)` — extracts context from outer loader
2. **Populate vtable**: Stores 26 function pointers + payload_ptr + config data ptr into globals at `0x18001C1B0`
3. **Init object**: Allocates 64 bytes, initializes via `init_object()`
4. **Mark initialized**: Sets flag at offset +32 to 1
5. **Spawn worker**: Resolves `CreateThread` + `CloseHandle` from encrypted DLL name, spawns `worker_thread_entry`
6. If payload has data (`*ctx_ptr != 0`), runs `worker_thread_entry` synchronously instead

<a id="inner-vtable"></a>
## Plugin Vtable (`sb_vtable_t` at 0x18001C1B0)

The vtable is accessible via CMD 104 of `DllMain_dispatcher`. 29 QWORDs (232 bytes):

| Offset | Global | Function | Size | Notes |
|--------|--------|----------|------|-------|
| 0x00 | `g_vtable_status` | — | — | State/status field (set to 0 on init) |
| 0x08 | `g_vtfn_handler_a` | `vtfn_plugin_loader` | 723 | Plugin registration: PE detection, blob decrypt, command protocol, linked-list insert |
| 0x10 | `g_vtfn_handler_b` | `vtfn_create_obj_b` | 450 | Object creator |
| 0x18 | `g_vtfn_handler_c` | `vtfn_create_obj_c` | 448 | Object creator (called with 103 by worker) |
| 0x20 | `g_vtfn_handler_d` | `vtfn_create_obj_d` | 561 | Object creator |
| 0x28 | `g_vtfn_handler_e` | `vtfn_create_obj_e` | 474 | Object creator |
| 0x30 | `g_vtfn_handler_f` | `vtfn_extract_filename` | 268 | Extracts filename from path (lstrcpyW) |
| 0x38 | `g_vtfn_handler_g` | `vtfn_create_obj_g` | 143 | Object creator (no args) |
| 0x40 | `g_vtfn_handler_h` | `vtfn_create_obj_h` | 143 | Object creator (no args) |
| 0x48 | `g_vtfn_handler_i` | `vtfn_create_obj_i` | 78 | Small allocator |
| 0x50 | `g_vtfn_handler_j` | `vtfn_create_obj_j` | 90 | Small allocator |
| 0x58 | `g_vtfn_handler_k` | `vtfn_compose_k` | 49 | Composition wrapper |
| 0x60 | `g_vtfn_resolve_api` | `resolve_api_dll3` | 538 | API resolver (HASH+DLL) |
| 0x68 | `g_vtfn_handler_m` | `vtfn_register_blob` | 49 | Blob registration wrapper |
| 0x70 | `g_vtfn_handler_n` | `vtfn_decrypt_and_load_blob` | 508 | IMUL decrypt + LZ77 decompress + validate magic 0x650001 |
| 0x78 | `g_vtfn_handler_o` | `vtfn_exec_reflective_loader` | 331 | Copy reflective loader to RWX, call with blob |
| 0x80 | `g_vtfn_handler_p` | `vtfn_thunk_multi_resolve` | 8 | Thunk to vtfn_multi_resolve |
| 0x88 | `g_vtfn_multi_resolve` | `vtfn_multi_resolve` | 1413 | Largest function, multi-API resolver |
| 0x90 | `g_vtfn_handler_r` | `vtfn_thunk_handler_s` | 5 | Thunk to vtfn_shellcode_trampoline |
| 0x98 | `g_vtfn_handler_s` | `vtfn_shellcode_trampoline` | 226 | Shellcode execution trampoline |
| 0xA0 | `g_vtfn_alloc` | `vtfn_alloc` | 39 | Allocator (sb_LocalAlloc) |
| 0xA8 | `g_vtfn_handler_u` | `vtfn_compress_encrypt` | 687 | LZ77 compress + IMUL cipher encrypt outbound data |
| 0xB0 | `g_vtfn_handler_v` | `vtfn_decrypt_decompress` | 805 | IMUL cipher decrypt + LZ77 decompress inbound data |
| 0xB8 | `g_vtfn_handler_w` | `vtfn_decrypt_packet_header` | 137 | IMUL cipher decrypt 20-byte packet header |
| 0xC0 | `g_vtfn_free` | `vtfn_free` | 21 | Free (sb_LocalFree) |
| 0xC8 | `g_vtfn_handler_y` | `vtfn_generate_packet_key` | 181 | Generate packet key (counter + QPC + GetSystemTime) |
| 0xD0 | `g_vtfn_handler_z` | `vtfn_base62_encode` | 59 | Base62 encoding utility |
| 0xD8 | `g_payload_ptr` | — | — | Payload context from outer loader |
| 0xE0 | `g_rdata_config` | — | — | Pointer to encrypted config at 0x1800068E0 |

<a id="inner-dynamic-api-resolution"></a>
## Dynamic API Resolution

### Direct hash resolution: `resolve_api_by_hash` (0x180003328)

PEB walk → find kernel32.dll (module hash `0xFD5B1261`) → walk exports → match hash. Same algorithm as outer loader.

Known hashes resolved directly:
| Hash | API |
|------|-----|
| `0x95D9FE52` | `LocalAlloc` |
| `0xF336A663` | `LocalFree` |
| `0xB8E03AF8` | `MultiByteToWideChar` |
| `0x98F9E06E` | `WideCharToMultiByte` |
| `0xBDA26FE6` | `LoadLibraryA` |
| `0xA16DC157` | `GetProcAddress` |

### Indirect resolution: `resolve_api_dllN` functions

Pattern: `decrypt_string(encrypted_dll_name)` → `sb_WideCharToMultiByte()` → `LoadLibraryA(dll_name)` → `GetProcAddress(handle, func_name)`.

4 different DLL resolver families (`dll0` through `dll3`), each loading APIs from a different encrypted DLL name.

### Utility wrappers

| Function | Purpose |
|----------|---------|
| `sb_LocalAlloc` (0x180003468) | Lazy LocalAlloc(LPTR=0x40, size), 36 callers |
| `sb_LocalFree` (0x180003428) | Lazy LocalFree with null check |
| `sb_MultiByteToWideChar` (0x1800043A8) | UTF-8 → wide, CP_UTF8, two-call pattern |
| `sb_WideCharToMultiByte` (0x180004498) | Wide → narrow, two-call pattern |
| `decrypt_string` (0x1800045B8) | XOR decrypt, 2-byte key prefix, 4096-byte buffer |
| `free_string_buffers` (0x180004568) | Free narrow+wide buffers from string struct |

<a id="inner-worker-thread"></a>
## Worker Thread: `worker_thread_entry` (0x180003E34)

1. Registers 8 encrypted data blobs from `.rdata` via `vtfn_compose_m`:
   - `0x180009100` (8873 bytes)
   - `0x18000D370` (16466 bytes)
   - `0x18000B3B0` (8113 bytes)
   - `0x1800070E0` (8214 bytes)
   - `0x1800113D0` (5223 bytes)
   - `0x180012840` (10002 bytes)
   - `0x180014F60` (12027 bytes)
   - `0x180017E60` (11464 bytes)
2. Initializes object if not already done
3. Calls `vtfn_create_obj_c(103)` — creates some handler object
4. If handler is null, resolves 3 APIs from encrypted DLL names:
   - API from `byte_180006050` (called with no args — likely `GetCurrentProcess`)
   - API from `byte_180006078` (called with `(handle, 0)` — check/query)
   - API from `byte_180006068` (called with `(0)` if previous fails — likely `ExitProcess`)
5. Returns via indirect call through object vtable

<a id="inner-encrypted-data"></a>
## Encrypted Data in `.rdata`

The 88KB `.rdata` section contains:
- Encrypted DLL names (short blobs at `byte_180006010`, `byte_180006050`, etc.)
- Encrypted API function names
- 8 large encrypted data blobs (registered by worker thread, totaling ~81KB)
- The reflective loader copy at RVA 0x6100 (for potential re-packing)
- Configuration data at `unk_1800068E0`

<a id="inner-global-state"></a>
## Global State

| Address | Name | Purpose |
|---------|------|---------|
| `0x18001C120` | `g_pfnLoadLibraryA` | Cached LoadLibraryA |
| `0x18001C128` | `g_pfnGetProcAddress` | Cached GetProcAddress |
| `0x18001C130` | `g_hModule_dll0` | Cached DLL handle (dll0) |
| `0x18001C180` | `g_pfnCreateThread` | Cached CreateThread |
| `0x18001C188` | `g_pfnCloseHandle` | Cached CloseHandle |
| `0x18001C190` | `g_initialized_obj` | Global init object (64 bytes) |
| `0x18001C1B0` | `g_vtable_status` | Vtable status/state |
| `0x18001C288` | `g_payload_ptr` | Payload context from outer loader |
| `0x18001C290` | `g_rdata_config` | Encrypted config data pointer |
| `0x18001C2A0` | `g_pfnLocalAlloc` | Cached LocalAlloc |
| `0x18001C2A8` | `g_pfnLocalFree` | Cached LocalFree |
| `0x18001C330` | `g_pfnWideCharToMultiByte` | Cached WideCharToMultiByte |
| `0x18001C338` | `g_pfnMultiByteToWideChar` | Cached MultiByteToWideChar |

<a id="inner-encrypted-strings"></a>
## Encrypted Strings (Decrypted)

All 34 encrypted string blobs decrypted — see [encrypted_strings_report.md](encrypted_strings_report.md) for full details.

**DLL resolver mapping:**
| Resolver | DLL |
|----------|-----|
| `resolve_api_dll0` | `kernel32.dll` |
| `resolve_api_dll1` | `msvcrt.dll` (memcpy) |
| `resolve_api_dll2` | `ws2_32.dll` (ntohl, htonl) |
| `resolve_api_dll3` | Caller-specified (FindFirstFileW, FindClose, FreeLibrary) |

**Vtable capability classification (from API usage):**
| Capability | Vtable Slots | Key APIs |
|-----------|-------------|----------|
| Process injection | `vtfn_multi_resolve` (0x80/0x88) | VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, ResumeThread |
| Process memory read | `resolve_multi_apis` | VirtualQueryEx, ReadProcessMemory |
| Blob decrypt + load | `vtfn_decrypt_and_load_blob` (0x70), `vtfn_exec_reflective_loader` (0x78) | IMUL cipher, LZ77, reflective loader copy |
| Packet crypto | `vtfn_decrypt_packet_header` (0xB8), `vtfn_decrypt_decompress` (0xB0), `vtfn_compress_encrypt` (0xA8) | ntohl, htonl, IMUL cipher, LZ77 |
| Packet key gen | `vtfn_generate_packet_key` (0xC8) | QueryPerformanceCounter, GetSystemTime |
| Plugin management | `vtfn_plugin_loader` (0x08) | GetModuleFileNameA, command protocol dispatch |
| Thread-safe objects | `vtfn_create_obj_b/c/d/e/g/h` | EnterCriticalSection, LeaveCriticalSection |
| Memory management | `vtfn_exec_reflective_loader` (0x78), `vtfn_shellcode_trampoline` (0x98) | VirtualAlloc, VirtualFree |
| Utility | `vtfn_base62_encode` (0xD0), `vtfn_extract_filename` (0x30) | Base62 encoding, path manipulation |
| Self-protection | `worker_thread_entry` | GetCurrentProcess, TerminateProcess, ExitProcess |

<a id="inner-analysis-status"></a>
## Analysis Status (All Complete)

- [x] Decrypt the DLL names — `kernel32.dll`, `msvcrt.dll`, `ws2_32.dll`
- [x] Decrypt all 34 encrypted strings statically (rolling polynomial XOR cipher) — see [encrypted_strings_report.md](encrypted_strings_report.md)
- [x] Identify vtable function purposes from API usage patterns
- [x] Analyze the 8 encrypted data blobs (~81KB) — all 8 are C2 plugin DLLs, fully decrypted and reconstructed. See [blob_index.md](blob_index.md)
- [x] Deep-dive `vtfn_main_handler` (723 bytes) — identified as `vtfn_plugin_loader`: plugin registration with PE detection (`GetModuleFileNameA`), blob magic validation, command protocol dispatch, linked-list management
- [x] Deep-dive `vtfn_multi_resolve` (1413 bytes) — process injection with 2 modes: CreateRemoteThread (6 APIs) and thread hijack (26-byte x64 stub). See [static_analysis_summary.md](static_analysis_summary.md#process-injection-vtfn_multi_resolve)
- [x] Investigate `init_object` and `init_critical_section` (formerly `sub_180005038`) — initializes 64-byte objects with flink/blink + critical section for thread-safe linked list operations
- [x] Analyze network protocol handlers — `vtfn_decrypt_packet_header` (137 bytes), `vtfn_decrypt_decompress` (805 bytes), `vtfn_compress_encrypt` (687 bytes): IMUL cipher + LZ77 with 20-byte packet header in network byte order
- [x] Decrypt the 8 large data blobs — IMUL stream cipher + LZ77 decompression, validated via magic 0x650001. All 337 functions across 8 plugins fully renamed

<a id="inner-function-reference"></a>
## Detailed Function Reference

All 76 functions in the inner PE `.text` section (0x180001000--0x180006000), grouped by category. Descriptions are derived from IDB function comments with full behavioral analysis.

---

### DllMain Dispatch / Plugin Protocol

#### DllMain_dispatcher (0x180004344, 100 bytes)

DllMain dispatcher entry point. Routes the `fdwReason` parameter as a command ID: 0 calls `cmd0_init_or_cleanup` (terminates the process via ExitProcess), 1 calls `cmd1_attach_handler` (main initialization and vtable population), 100 is a no-op, 101 writes the version constant 100 into `*lpReserved`, 102 calls `cmd102_custom_command` (returns the plugin identity string), 103 is a no-op, and 104 writes the pointer to `g_vtable_status` into `*lpReserved`. Returns TRUE (1) when the handler returns 0 (success). This overloaded DllMain is the standard ScatterBrain plugin dispatch protocol used by all 8 plugins and the inner PE itself.

#### cmd0_init_or_cleanup (0x180003D64, 84 bytes)

Plugin command 0 handler that terminates the host process by calling `ExitProcess(0)`. This serves as the framework's self-destruct or cleanup command, providing a way for the C2 server to instruct the implant to terminate cleanly. The ExitProcess API is resolved lazily on first invocation: the encrypted string `enc_ExitProcess` is decrypted to obtain the API name as a wide string, converted to narrow via `sb_WideCharToMultiByte`, then resolved through `resolve_api_dll0` (PEB hash-based API resolution from kernel32.dll). The resolved pointer is cached in `g_pfnExitProcess`. The function calls ExitProcess with exit code 0, which terminates all threads in the process. Despite having a return statement (`return 0`), execution never reaches it since ExitProcess does not return.

#### cmd1_attach_handler (0x180004054, 733 bytes)

Main attach handler (command 1 / DLL_PROCESS_ATTACH equivalent). Initializes the payload context via `init_payload_context`, populates the 26-entry framework vtable at `g_vtable_status+0x10..0xD8` with function pointers for plugin management, crypto, injection, and utilities. Registers the host DLL itself as a plugin via `vtfn_plugin_loader`. If a payload context is present (`*ctx_ptr != 0`), runs `worker_thread_entry` synchronously in the calling thread; otherwise spawns it as a new thread via CreateThread (lazily resolved from encrypted string) and closes the handle via CloseHandle.

#### cmd102_custom_command (0x180003CD4, 134 bytes)

Plugin command 102 handler that returns the plugin identity string to the caller. The function decrypts an encrypted wide string containing the plugin ID (stored at `unk_18001AB28`) using the framework's `decrypt_string` routine, then copies the resulting UTF-16 string into the caller's output buffer using `lstrcpyW`. The lstrcpyW API is resolved lazily on first call: its name is itself stored as an encrypted string (`enc_lstrcpyW`), decrypted to wide chars, converted to a narrow string via `sb_WideCharToMultiByte`, and then resolved through `resolve_api_dll0`. The resolved function pointer is cached in `g_pfnLstrcpyW`. After copying the plugin ID, the function frees the decrypted string buffers via `free_string_buffers` and returns 0. This command is part of the standard ScatterBrain plugin protocol where the framework queries each loaded plugin for its identity string during registration.

#### get_config_ptr (0x180003C84, 13 bytes)

Returns a pointer to the global vtable status structure (`g_vtable_status`) through the output parameter `a1`. This function is part of the plugin dispatch interface and allows callers to inspect framework-level configuration and status without directly accessing global variables. The pointer is stored at `*a1`, and the function always returns 0. The `g_vtable_status` structure contains state information used by the inner PE loader to track plugin registration, initialization status, and communication channel configuration.

#### get_version (0x180003CA4, 9 bytes)

Returns the version number of the inner PE loader framework through the output parameter `a1`. The version is hardcoded to 100 (0x64), identifying this as the base framework loader (as opposed to plugin DLLs which have version IDs 101--203). The function stores the version value at `*a1` as a DWORD and returns 0. This is invoked as part of the plugin command dispatch protocol, where command 102 queries the module version. The outer loader uses this version number to verify compatibility between the framework and loaded plugins.

#### stub_return_zero (0x180003CB4, 3 bytes)

Minimal stub function that unconditionally returns 0. Serves as a placeholder handler for an unimplemented plugin dispatch command. When the dispatcher receives a command code that maps to this slot, the stub returns success (0) without performing any action. This pattern is used throughout the ScatterBrain plugin architecture for commands that are defined in the protocol but not required by every module.

#### stub_return_zero_2 (0x180003CC4, 3 bytes)

Second minimal stub function that unconditionally returns 0, identical in behavior to `stub_return_zero`. This occupies a separate command dispatch slot in the plugin protocol. The existence of two separate stubs rather than reusing a single function pointer suggests the dispatch table is populated per-slot with distinct entries, possibly for future extensibility or to maintain a fixed table layout.

#### nullsub_1 (0x180003580, 3 bytes)

Empty no-operation stub function that performs no work and has no return value. Serves as a placeholder in the ScatterBrain framework callback or vtable infrastructure, occupying a slot that may be filled with a real implementation in other plugin variants. Its presence prevents null pointer dereference crashes when the dispatch mechanism invokes callbacks unconditionally.

#### init_payload_context (0x180003DC4, 106 bytes)

Initializes the global payload context from an `sb_payload_ctx_t` argument. Allocates a buffer via `sb_LocalAlloc`, copies payload data via `resolve_api_dll1` (memcpy), and stores the size and flags. If the argument is NULL, sets default flags to 3 (thread mode). Returns a pointer to the global context structure. This is called early in `cmd1_attach_handler` to capture the context passed from the outer loader.

#### worker_thread_entry (0x180003E34, 524 bytes)

Worker thread entry point that registers all 8 encrypted plugin blobs from `.rdata` via `vtfn_register_blob`. The blob keys (sizes) are 8873, 16466, 8113, 8214, 5223, 10002, 12027, and 11464 bytes. After registration, it looks up the Install plugin (ID 103) via `vtfn_create_obj_c` and calls its vtable[1] entry to begin the installation/persistence sequence. If the Install plugin is not found, the worker terminates the process via TerminateProcess and ExitProcess (both resolved from encrypted strings). This thread is the primary bootstrap path that brings all 8 C2 plugin DLLs online.

---

### API Resolution (PEB Walk, Hash Resolve)

#### resolve_api_by_hash (0x180003328, 241 bytes)

PEB walk API hash resolver. Walks the `InLoadOrderModuleList` from the PEB, hashing each module name with the algorithm `(tolower(ch) + ROR8(hash)) XOR 0x7C35D9A3`, and finds kernel32.dll (module hash `0xFD5B1261` / signed -44363167). Then walks the export table, hashing function names with the same algorithm to match `target_hash`. This is the same hash algorithm used by the outer loader. Known directly-resolved hashes include `0x95D9FE52` (LocalAlloc), `0xF3390E83` (LocalFree), `0xB8E3FF08` (MultiByteToWideChar), and `0x990C8BEE` (WideCharToMultiByte).

#### resolve_api_dll0 (0x180001000, 159 bytes)

Resolves an arbitrary API function from kernel32.dll by its ASCII name string. On first call, decrypts the encrypted kernel32.dll name string using the polynomial XOR cipher (`decrypt_string`), converts it from wide to narrow via `sb_WideCharToMultiByte`, then calls LoadLibraryA (resolved via PEB hash walk with hash 0xBDAD0946) to obtain the kernel32 module handle, which is cached in `g_hModule_dll0` for subsequent calls. Similarly lazy-resolves GetProcAddress using PEB hash 0xA1732C57 and caches it in `g_pfnGetProcAddress`. Returns the result of `GetProcAddress(hKernel32, szFuncName)`. This is the primary API resolution function used throughout the inner PE loader whenever a kernel32.dll export is needed.

#### resolve_api_dll1 (0x1800010A0, 274 bytes)

Resolves and invokes `msvcrt.dll!memcpy(dest, src, size)` with full lazy initialization. On first call, decrypts both the memcpy function name and msvcrt.dll module name using the polynomial XOR cipher, loads msvcrt.dll via LoadLibraryA (resolved by PEB hash 0xBDAD0946), and obtains the memcpy proc address via GetProcAddress (PEB hash 0xA1732C57). Both the module handle (`g_hModule_msvcrt`) and function pointer (`g_pfnMemcpy`) are cached in globals. Parameters are `dest` (destination buffer), `src` (source buffer), and `size` (byte count). This wrapper is used extensively throughout the framework for memory copy operations.

#### resolve_api_dll2 (0x180001474, 159 bytes)

Resolves a Windows Sockets API function by name from ws2_32.dll. The single parameter `func_name_str` is an ANSI string containing the target function name (e.g., `htons`, `ntohs`, `connect`). On first invocation, the function decrypts the encrypted string `enc_ws2_32_dll` to obtain the DLL name, converts it from wide to ANSI via `sb_WideCharToMultiByte`, and loads the library using a lazily-resolved LoadLibraryA (PEB hash 0xBDAE4BF6). The resulting module handle is cached in `g_hModule_ws2_32`. GetProcAddress is similarly lazy-resolved via PEB hash 0xA1751D67 and cached. This is the third DLL-specific API resolver in the framework, dedicated to Winsock network functions used by the TCP/UDP/DNS transport plugins.

#### resolve_api_dll3 (0x180002D34, 538 bytes)

Loads a DLL plugin by filesystem path. Calls LoadLibraryA to load the DLL, registers it via `vtfn_plugin_loader`, and queries file attributes via FindFirstFileW to extract the PE timestamp. On registration failure, calls FreeLibrary and returns 1114 (ERROR_DLL_INIT_FAILED). Both FindFirstFileW, FindClose, and FreeLibrary are lazily resolved through encrypted string decryption and `resolve_api_dll0`.

#### resolve_multi_apis (0x180001894, 604 bytes)

Scans a remote process memory space to locate the entry point of its main EXE image. Takes a process handle (`target_process`) and an output pointer (`out_entry_point`) that receives the resolved entry point address. The function first resolves VirtualQueryEx and ReadProcessMemory from kernel32.dll by decrypting their encrypted names, obtaining the kernel32 handle via GetModuleHandleA (also lazily resolved), and calling GetProcAddress. It then allocates a 4096-byte read buffer and iterates through the target process virtual address space using VirtualQueryEx with a MEMORY_BASIC_INFORMATION structure. For each region with PAGE_EXECUTE_READWRITE protection (0x1000) and MEM_IMAGE type (0x1000000), it reads the first 4096 bytes via ReadProcessMemory and checks for a valid PE image: MZ magic (0x5A4D), PE signature (0x4550), PE32+ optional header magic (0x20B), and the absence of the IMAGE_FILE_DLL flag (0x2000). When a matching non-DLL PE32+ image is found, the entry point is computed as `region_base + AddressOfEntryPoint`.

#### resolve_pe_entry_point (0x180001564, 34 bytes)

Resolves the entry point address of a PE image given its base address in memory. Performs a two-step validation: first checks for the MZ magic number (0x5A4D) at offset 0 of the base address, then follows the `e_lfanew` field at offset 0x3C to locate the NT headers and verifies the PE signature (0x00004550). If both signatures are valid, returns `base + IMAGE_NT_HEADERS.OptionalHeader.AddressOfEntryPoint` (at NT header offset +0x28). If either check fails, returns 0. Used throughout the framework to locate DllMain dispatch functions in both standard PE modules and custom-packed ScatterBrain plugin blobs.

---

### Cipher Systems (IMUL, Polynomial XOR)

#### decrypt_string (0x1800045B8, 185 bytes)

Decrypts an encrypted string using the polynomial XOR cipher. The key is derived from the first 2 bytes of the encrypted blob, then evolves per byte with the recurrence `key = -42860544*key - 135791246*HIWORD(key) - 1043215206`. The result is decrypted to a narrow (ANSI) string, then converted to wide (UTF-16) via `sb_MultiByteToWideChar`. Returns the result in an `sb_str_ctx_t` structure containing both narrow and wide representations. This is the core string decryption routine used for all 34+ encrypted strings in the inner PE, including DLL names, API names, and the plugin identity string.

#### vtfn_shellcode_trampoline (0x180004868, 226 bytes)

Shellcode trampoline that serves as the IMUL cipher engine. On first call, allocates 0x10A bytes of RWX memory via VirtualAlloc, then decodes shellcode from `byte_18001C010` using a per-byte transform (`add 0xD, xor 0xF3, sub 0xD`), and caches the decoded copy. On subsequent calls, invokes the decoded shellcode directly with four parameters forwarded from the caller: `(rcx, edx, r8, r9d)` corresponding to `(src_buffer, size, dst_buffer, key)`. The shellcode implements the IMUL stream cipher used for packet encryption/decryption throughout the framework.

#### vtfn_thunk_handler_s (0x180004958, 5 bytes)

Thunk function that forwards all four parameters directly to `vtfn_shellcode_trampoline` without modification. Provides a stable, fixed entry point in the framework vtable while the actual shellcode trampoline implementation may be located at a different address. The four parameters follow the IMUL cipher convention: source buffer, size, destination buffer, and key.

---

### LZ77 Compression / Decompression

#### hash12 (0x180003560, 13 bytes)

Computes a 12-bit hash value used as an index into the LZ77 compression hash table. The algorithm XORs the low 16 bits of the input value with the input right-shifted by 12 bits, then masks the result to 12 bits (AND 0xFFF), producing a value in the range 0--4095. This hash function is designed for fast match-finding during LZ77 compression, where the input is typically a DWORD read from the current position in the data stream. The 12-bit output directly indexes the 4096-entry hash table stored in the compression context.

#### hash12_ptr (0x180003940, 13 bytes)

Pointer-dereferencing variant of the 12-bit LZ77 hash function. Takes a DWORD pointer as input, reads the 4-byte value at that address, and computes `(value XOR (value >> 12)) AND 0xFFF`. Unlike `hash12` which takes the value directly as an integer parameter, this variant dereferences the pointer first, making it suitable for use during decompression or hash table update operations where the data is accessed through sliding window pointers.

#### hashtable_insert (0x180003960, 25 bytes)

Inserts a data pointer into the LZ77 hash table at the bucket determined by the 12-bit hash of the DWORD at that pointer. The hash table at base address `a1` is organized as 4096 entries of 8 bytes each (QWORD pointer slots) spanning offsets 0x0000--0x7FFF, followed by a 4096-byte used-flag array at offset 0x8000--0x8FFF. The function computes the hash as `(*a2 XOR (*a2 >> 12)) AND 0xFFF`, stores the pointer `a2` into `table[hash]` (at `a1 + 8*hash`), and sets the corresponding flag byte at `a1 + 0x8000 + hash` to 1 to mark the bucket as occupied. Returns the computed hash index.

#### lz_update_hashtable (0x180003980, 44 bytes)

Bulk hash table update for the LZ77 decompressor. Advances a cursor pointer (stored at `*a2`) from its current position up to the target address `a3`, inserting each intermediate position into the hash table at base `a1`. For each position, it increments the cursor, computes the 12-bit hash of the DWORD at that position, stores the pointer in the hash table slot, and sets the used flag. This is called after emitting a back-reference match during decompression to ensure all intermediate positions within the copied match region are indexed in the hash table.

#### lz_compress_block (0x1800035D0, 699 bytes)

Core LZ77 block compression engine that processes an input buffer and produces compressed output using literal bytes and back-reference (offset, length) pairs. Parameters: `a1` is the input data pointer, `a2` is the output buffer pointer, `a3` is the input data length, and `a4` is a pointer to the compression context containing the 4096-entry hash table (each entry is 8 bytes: 4-byte cached DWORD + 4-byte offset). The algorithm maintains a 32-bit flag word where each bit indicates whether the next element is a literal byte (0) or a back-reference (1); when the flag word is exhausted (bit 0 set), it is flushed to the output. Match finding uses the 12-bit hash to look up candidate positions. Short matches (3 bytes) are encoded as 2-byte tokens, longer matches (4--17 bytes) use 2-byte encoding with length-2, and matches 18--255 bytes use 3-byte encoding.

#### lz_decompress (0x1800039C0, 341 bytes)

LZ77 decompress core. Reads bit-flags to distinguish literals from (offset, length) back-references. Copies 3-byte aligned match runs, updates the hash table for future references via `lz_update_hashtable`. Returns the decompressed size. This is the inverse of `lz_compress_block` and handles the same variable-length encoding for short, medium, and long back-references.

#### lz_get_compressed_size (0x1800038A0, 59 bytes)

Reads the compressed data size from a ScatterBrain LZ77 compressed buffer header. The header begins with a flag byte at offset 0: if bit 1 is set, the size fields are 4 bytes each (DWORD); otherwise they are 1 byte each. The compressed size is stored immediately after the flag byte at offset 1. The function reads a full DWORD from that offset and masks it to the appropriate width based on the size field length. The mask is computed as `0xFFFFFFFF >> (8 * (4 - field_size))`.

#### lz_get_decompressed_size (0x1800038F0, 61 bytes)

Reads the decompressed (original) data size from a ScatterBrain LZ77 compressed buffer header. The decompressed size is stored after the compressed size field, at offset `(1 + field_size)` from the start of the header. The variable-length header format allows compact 3-byte headers for small payloads (flag + 1-byte compressed size + 1-byte decompressed size) while supporting up to 4 GB payloads in the 9-byte DWORD mode.

#### lz_decompress_wrapper (0x180003B20, 113 bytes)

Top-level LZ77 decompression wrapper that dispatches between actual decompression and raw memcpy based on the compression header flags. Takes three parameters: `a1` is the compressed data buffer (starting with the LZ77 header), `a2` is the output buffer, and `a3` is the decompression context (hash table workspace, must be at least 0x9001 bytes). The function first calls `lz_get_decompressed_size` to read the original data size from the header. It then checks bit 0 of the header flag byte: if set, the data is LZ77 compressed and `lz_decompress` is called; if clear, the data is stored uncompressed and is simply memcpied. After decompression, clears a sentinel QWORD at offset 0x9000 in the context buffer. Returns the number of decompressed bytes.

#### lz_compress (0x180003BA0, 225 bytes)

LZ77 compress wrapper. Initializes the 4096-entry hash table, calls `lz_compress_block`. Writes the header: flag byte (bit 0 = compressed, bit 1 = 4-byte sizes), compressed_size, decompressed_size. Falls back to memcpy if compression yields no size reduction. The header format matches what `lz_get_compressed_size` and `lz_get_decompressed_size` parse on the decompression side.

---

### PE Loader / Reflective Loading

#### vtfn_exec_reflective_loader (0x1800020A4, 331 bytes)

Executes the reflective loader locally. Copies the 2014-byte reflective loader stub from RVA 0x6100 into a freshly allocated RWX region (VirtualAlloc), calls it with the packed blob as parameter, stores the returned base address, and frees the RWX allocation. Returns 0 on success, or 0x505 if the returned base address is below 0x1000 (indicating loader failure). This function is the local-execution counterpart to the remote injection in `vtfn_multi_resolve`.

#### vtfn_multi_resolve (0x180001B04, 1413 bytes)

Remote process injector, the largest function in the inner PE. Operates in two modes: (1) **CreateRemoteThread** -- allocates RWX memory in the target process via VirtualAllocEx, writes the reflective loader (2014 bytes from RVA 0x6100) plus payload plus parameters via WriteProcessMemory, then spawns a remote thread with CreateRemoteThread. (2) **Thread hijack** -- builds a 26-byte x64 shellcode stub, writes it to the target process entry point, adjusts memory protection via VirtualProtectEx, and resumes the suspended thread via ResumeThread. All 6+ APIs (VirtualAllocEx, WriteProcessMemory, CreateRemoteThread, VirtualProtectEx, ResumeThread, GetThreadContext) are resolved lazily from encrypted strings. Exposed as vtable slot +0x88.

#### vtfn_thunk_multi_resolve (0x180002094, 8 bytes)

Simple thunk function that forwards to `vtfn_multi_resolve` with the `suspended_thread` parameter set to 0. This zero value indicates that the injection should use CreateRemoteThread mode exclusively, without attempting to hijack an existing suspended thread. Exposed as vtable slot +0x80.

#### unload_module (0x1800015B4, 268 bytes)

Unloads and destroys a plugin module entry from the framework. First locates the plugin dispatch function: for PE modules (`is_pe_module != 0`) it calls `resolve_pe_entry_point` to find DllMain, while for packed blob modules it validates the ScatterBrain magic (XOR of first two DWORDs == 0x7C3AC0A3) and computes the dispatch address from the blob entry point RVA at offset +0x28. It then invokes the dispatch function with command 101 (shutdown/cleanup), giving the plugin a chance to release its resources. After the shutdown callback, PE modules are freed via FreeLibrary while blob modules are freed via VirtualFree with MEM_RELEASE (0x8000). Both API pointers are resolved on first use through encrypted string decryption and `resolve_api_dll0`. Finally, the plugin entry structure itself is freed via `sb_LocalFree`. This function runs on the async teardown thread spawned by `vtfn_create_obj_d`.

#### get_module_path (0x1800016D4, 154 bytes)

Retrieves the full filesystem path of a loaded module as a wide string. The first parameter is the module handle (HMODULE), and the second is a pointer to an `sb_str_ctx_t` output structure. Allocates a 0x2000-byte (8192 bytes) temporary buffer via `sb_LocalAlloc`, then calls GetModuleFileNameW with a max character count of 4096. The GetModuleFileNameW API pointer is lazily resolved on first call by decrypting `enc_GetModuleFileNameW`, converting to ANSI, and looking up via `resolve_api_dll0`. After the API call populates the buffer, the result is stored into the output `sb_str_ctx_t` via `wstr_obj_set`, and the temporary buffer is freed. Used by `vtfn_extract_filename` as a fallback when a plugin does not respond to dispatch command 103.

#### vtfn_extract_filename (0x180001774, 268 bytes)

Extracts the filename of a loaded plugin for identification purposes. Takes a plugin context pointer (`a1`) and an output wide-string buffer (`a2`). First attempts to query the plugin directly by invoking its dispatch function with command 103 (name query), which allows plugins to self-report their identity string. If the dispatch returns an empty result (`a2[0] == 0`), the function falls back to path extraction: calls `get_module_path` with the module handle from `a1+0x30`, then scans backward through the wide string to find the last backslash character (0x5C). The substring after the last backslash (the basename) is copied to the output buffer using `lstrcpyW`. If no backslash is found, the function writes a literal asterisk (0x2A) as a placeholder. Exposed as vtable slot +0x30.

---

### Plugin Management (Linked List, Synced List)

#### vtfn_plugin_loader (0x180002844, 723 bytes)

Plugin loader and registration function. Accepts a module handle or packed blob pointer. Detects whether the module is a standard PE or a packed blob by probing with GetModuleFileNameA: if the call succeeds, it is a PE; otherwise it is a blob. Dispatches the standard plugin command protocol: command 100 (init), command 102 (get plugin ID string), and command 104 (get vtable pointer). Extracts the PE timestamp from the file metadata. Allocates an `sb_plugin_entry_t` structure (64 bytes), populates its fields (module handle, plugin ID, vtable pointer, timestamp, ref_count=1), and inserts the entry into the global synchronized list via `list_insert_front` under the critical section. Returns the allocated `sb_plugin_entry_t`. Exposed as vtable slot +0x08.

#### vtfn_decrypt_and_load_blob (0x180002B24, 508 bytes)

Decrypts and loads an encrypted plugin blob. IMUL-decrypts and LZ77-decompresses the blob via `vtfn_decrypt_decompress`, validates the ScatterBrain packed PE magic (ntohl of first DWORD == 0x650001), loads the packed PE via the reflective loader (`vtfn_exec_reflective_loader`), and registers the resulting plugin via `vtfn_plugin_loader` with the blob key. Exposed as vtable slot +0x70.

#### vtfn_register_blob (0x180002F54, 49 bytes)

Registers an encrypted blob as a plugin. Calls `vtfn_decrypt_and_load_blob` to decrypt and load the blob, finds the resulting entry via `vtfn_create_obj_b`, marks it as detached (`is_detached=1`), and then releases via `vtfn_create_obj_d` (which triggers async unload if ref_count reaches zero). Exposed as vtable slot +0x68.

#### vtfn_compose_k (0x180002F94, 49 bytes)

Loads a DLL plugin module via `resolve_api_dll3` (which calls LoadLibraryA and registers the plugin), then immediately marks the resulting plugin entry for deferred unloading. After `resolve_api_dll3` returns successfully, the function looks up the newly created entry by module handle via `vtfn_create_obj_b`, sets `is_detached=1`, and calls `vtfn_create_obj_d` to release the reference. This compose-and-teardown pattern is used for one-shot plugin operations where the framework needs to load a DLL, invoke its initialization, and then schedule cleanup without keeping the plugin persistently registered. Exposed as vtable slot +0x58.

#### vtfn_create_obj_b (0x180002264, 450 bytes)

Thread-safe lookup of a plugin entry by module handle (HMODULE or blob base address). The `search_key` parameter is the `module_or_blob` pointer to match against entries in the global synchronized plugin list. Lazy-initializes `g_initialized_obj` if needed, then acquires the embedded CRITICAL_SECTION via EnterCriticalSection. Under the lock, traverses the circular doubly-linked list from tail to head, comparing each entry's `module_or_blob` against `search_key` and checking that `is_detached` is false (only active plugins match). When a matching non-detached entry is found, its `ref_count` is incremented to prevent premature unloading. After traversal, LeaveCriticalSection releases the lock. Returns the matched `sb_plugin_entry_t` pointer with an elevated reference count, or NULL. Exposed as vtable slot +0x10.

#### vtfn_create_obj_c (0x180002434, 448 bytes)

Thread-safe lookup of a plugin entry by its integer plugin ID. The `plugin_id` parameter is compared against `entry->plugin_id` (a DWORD) for each node in the global synchronized plugin list. Follows the same synchronized access pattern as `vtfn_create_obj_b`: lazy-init, EnterCriticalSection, traverse circular list from tail to head, LeaveCriticalSection. For each candidate entry, checks two conditions: plugin_id match AND `is_detached == false`. When found, increments `ref_count` atomically under the lock. Returns the matched `sb_plugin_entry_t` or NULL. Used by the command dispatch system to route C2 commands to the appropriate plugin by numeric ID. Exposed as vtable slot +0x18.

#### vtfn_create_obj_d (0x180002604, 561 bytes)

Releases a reference to a plugin entry and triggers asynchronous unloading if the reference count reaches zero. Acquires the global list critical section, verifies the entry exists by traversing from tail to head, then decrements `ref_count`. If the count remains above zero, simply releases the lock and returns. If `ref_count` reaches zero, the entry is unlinked from the circular doubly-linked list by patching flink/blink pointers and decrementing the node count. After releasing the critical section, spawns a new thread via CreateThread (lazily resolved from `enc_CreateThread`) with `unload_module` as the thread start routine and the detached entry as the parameter. This asynchronous design prevents deadlocks that could occur if the plugin shutdown callback (command 101) attempted to acquire the same list lock. Exposed as vtable slot +0x20.

#### vtfn_create_obj_e (0x180002FD4, 474 bytes)

Detaches and unloads a plugin entry (thread-safe). Acquires the critical section, checks if the entry is already detached (returns 170 if so). If not, sets `is_detached=1`, calls `vtfn_create_obj_d` to decrement the reference count and spawn the async unload thread, then releases the critical section. The is_detached flag prevents the entry from being found by subsequent lookups via `vtfn_create_obj_b` or `vtfn_create_obj_c`, effectively scheduling it for teardown once all existing references are released. Exposed as vtable slot +0x28.

#### vtfn_create_obj_g (0x1800012A8, 143 bytes)

Acquires the global critical section lock protecting the plugin synced list (`sb_synced_list_t`). On first call, lazy-initializes `g_initialized_obj` by allocating a 64-byte buffer via `sb_LocalAlloc` and calling `init_object` to set up the circular doubly-linked list with an embedded CRITICAL_SECTION. Then resolves EnterCriticalSection from kernel32.dll (decrypting the API name via polynomial XOR cipher) and calls it on the embedded CS within `g_initialized_obj`. Returns 0 on success. Must be paired with `vtfn_create_obj_h` (vtable +0x40) which calls LeaveCriticalSection. Exposed as vtable slot +0x38.

#### vtfn_create_obj_h (0x180001338, 143 bytes)

Releases the global synchronized object lock by calling LeaveCriticalSection on the embedded CRITICAL_SECTION within `g_initialized_obj`. If the global `sb_synced_list_t` object has not been allocated yet, lazy-initializes it by allocating 64 bytes and calling `init_object`. The LeaveCriticalSection API pointer is resolved on first use by decrypting `enc_LeaveCriticalSection`, converting to ANSI, and looking it up through `resolve_api_dll0`. This is the counterpart to the EnterCriticalSection call in `vtfn_create_obj_g` and must be called after every lock acquisition to avoid deadlocks. Returns 0. Exposed as vtable slot +0x40.

#### vtfn_create_obj_i (0x1800013C8, 78 bytes)

Returns the first (tail) plugin entry from the global synchronized plugin list, or NULL if the list is empty. Lazy-initializes `g_initialized_obj` if not created yet. Determines emptiness by comparing the blink pointer (tail) against the list head: if they differ, blink points to the most recently inserted plugin entry which is returned. If the list is empty (blink == head, sentinel points to itself), NULL is returned. Does NOT acquire the critical section, so must only be called while the caller already holds the lock. Used as the iteration start point, paired with `vtfn_create_obj_j` to advance. Exposed as vtable slot +0x48.

#### vtfn_create_obj_j (0x180001418, 90 bytes)

Advances to the next plugin entry in the global synchronized list during iteration. Takes a pointer to the current `sb_plugin_entry_t` and returns `entry->blink` (the next node toward the tail), or NULL if the next node is the list head sentinel (indicating end of traversal). Lazy-initializes `g_initialized_obj` if not allocated. The end-of-list check compares `entry->blink` against the `g_initialized_obj` sentinel pointer: when they are equal, the traversal has wrapped around the circular list back to the head. Does not acquire the critical section and must only be called while the lock is held. Together, `vtfn_create_obj_i` and `vtfn_create_obj_j` implement the standard get-first / get-next iteration pattern. Exposed as vtable slot +0x50.

---

### Framework Vtable Functions

#### vtfn_generate_packet_key (0x1800011B4, 181 bytes)

Generates a 32-bit per-packet encryption key for the IMUL stream cipher by mixing multiple entropy sources. First, a monotonic counter at `dword_18001C000` is decremented by constant 0x35E5A7BE (904243134) each call, providing a sequential component. Second, QueryPerformanceCounter (lazy-resolved from kernel32.dll via encrypted string decryption) provides high-resolution timer entropy, with both the high and low 32-bit halves summed. Third, all eight fields of a SYSTEMTIME structure from GetSystemTime are summed. The final key is the XOR/sum combination of all three sources. This key is stored in the packet header and used by `vtfn_decrypt_packet_header` (vtable +0xB8) to seed the IMUL cipher. Exposed as vtable slot +0xC8.

#### vtfn_base62_encode (0x18000126C, 59 bytes)

Encodes a single byte value into a Base62 character for generating alphanumeric identifier strings. The input byte is reduced modulo 62, then mapped to three character ranges: values 0--25 map to uppercase A--Z (adding 65), values 26--51 map to lowercase a--z (adding 71), and values 52--61 map to digits 0--9 (subtracting 4). Used by the Online plugin (blob_3) for generating pseudo-random campaign identifiers and DGA domain labels. Exposed as vtable slot +0xD0.

#### vtfn_decrypt_packet_header (0x180004968, 137 bytes)

Decrypts a 20-byte packet header with the IMUL cipher. Extracts the key via `ntohl` from `encrypted_hdr->key`, decrypts the header via `vtfn_shellcode_trampoline(src, 0x14, dst, key)`, and stores the cleartext key in the output structure. The 20-byte header contains packet metadata (sizes, flags, command ID) in network byte order. Exposed as vtable slot +0xB8.

#### vtfn_decrypt_decompress (0x1800049F8, 805 bytes)

Inbound packet decryptor and decompressor. IMUL-decrypts the packet header to extract compressed/decompressed sizes and flags, then IMUL-decrypts the body using the same key. If the compressed flag (0x8000) is set, LZ77-decompresses the body via `lz_decompress_wrapper`. Validates sizes for consistency, allocates and returns an output envelope containing the cleartext payload. Returns 0 on success, 8 (ERROR_NOT_ENOUGH_MEMORY), or 13 (ERROR_INVALID_DATA). Exposed as vtable slot +0xB0.

#### vtfn_compress_encrypt (0x180004D28, 687 bytes)

Outbound packet builder. LZ77-compresses the payload body via `lz_compress` (skips compression if payload is 16 bytes or fewer, or if compression yields no size reduction). Fills the envelope header with `htonl`-encoded sizes, IMUL-encrypts the entire packet via `vtfn_shellcode_trampoline` with a freshly generated packet key from `vtfn_generate_packet_key`, and prepends `htonl(key)` as the first 4 bytes. Returns 0 on success, 8 (OOM), or 13 (size mismatch). Exposed as vtable slot +0xA8.

---

### String / Memory Utilities

#### sb_LocalAlloc (0x180003468, 54 bytes)

Allocates a zero-initialized memory block of the specified size using the Windows LocalAlloc API with the LPTR flag (0x40 = LMEM_FIXED | LMEM_ZEROINIT). On first invocation, the LocalAlloc function pointer is resolved via `resolve_api_by_hash` with hash 0x95D9FE52, which walks the PEB InLoadOrderModuleList to find kernel32.dll and locates the export by hash matching. The resolved pointer is cached in `g_pfnLocalAlloc`. The LPTR flag ensures returned memory is both fixed and zero-filled. This is the framework allocation primitive used throughout the inner PE for all dynamic memory needs.

#### sb_LocalFree (0x180003428, 53 bytes)

Frees a memory block previously allocated by `sb_LocalAlloc`, using the Windows LocalFree API. If the input pointer is NULL, the function is a safe no-op and returns immediately without calling the API. On first invocation, the LocalFree function pointer is resolved via `resolve_api_by_hash` with hash 0xF3390E83. The resolved pointer is cached in `g_pfnLocalFree`. This is the framework deallocation primitive used pervasively throughout the inner PE for freeing plugin entry structures, temporary string buffers, and all other dynamically allocated memory.

#### j_sb_LocalFree (0x1800034A8, 5 bytes)

Jump thunk that directly forwards to `sb_LocalFree`. This thunk exists as a separate function entry point to provide a distinct call target for callers that need an indirect reference to the free function, such as vtable slots or function pointer assignments. One of two identical `j_sb_LocalFree` thunks in the binary, likely generated by the MSVC linker to satisfy distinct call sites.

#### j_sb_LocalFree_0 (0x1800034B8, 5 bytes)

Second jump thunk that directly forwards to `sb_LocalFree`, identical in behavior to `j_sb_LocalFree`. This duplicate thunk is a common artifact in MSVC-compiled binaries where incremental linking or whole-program optimization creates distinct thunk stubs for the same target function.

#### j_sb_LocalAlloc (0x1800034C8, 5 bytes)

Jump thunk that directly forwards to `sb_LocalAlloc`. The single parameter specifying the allocation size in bytes is passed through unchanged. Mirrors the `j_sb_LocalFree` thunk pattern and is a standard MSVC linker artifact.

#### vtfn_alloc (0x180004838, 39 bytes)

Framework vtable allocation function exposed to plugins through the 26-slot vtable. Takes two parameters: `a1` is a pointer to a QWORD that receives the allocated memory pointer, and `a2` is the requested allocation size in bytes. Calls `sb_LocalAlloc(a2)`, stores the resulting pointer at `*a1`, and returns 0 on success. If allocation fails, returns 8 (ERROR_NOT_ENOUGH_MEMORY). Plugins use this vtable entry to allocate buffers without needing to resolve heap APIs themselves. Exposed as vtable slot +0xA0.

#### vtfn_free (0x180004818, 21 bytes)

Framework vtable free function exposed to plugins through the 26-slot vtable. Wraps `sb_LocalFree` with a NULL-safety check: if the input pointer is non-NULL, it is freed; if NULL, no action is taken. Always returns 0. Allows plugin DLLs to release memory allocated by the framework via `vtfn_alloc` without resolving the LocalFree API themselves. Exposed as vtable slot +0xC0.

#### sb_MultiByteToWideChar (0x1800043A8, 233 bytes)

Converts a narrow (ANSI/UTF-8) string to a wide (UTF-16LE) string within the `sb_str_ctx_t` context structure. The MultiByteToWideChar API is resolved lazily via PEB hash lookup (hash 0xB8E3FF08) and cached in `g_pfnMultiByteToWideChar`. Uses the standard two-call pattern: first call with null output buffer to determine buffer size, then allocate `(size * 2)` bytes via `sb_LocalAlloc` using `saturated_mul` to prevent integer overflow, then call again for the actual conversion. The code page is hardcoded to 65001 (CP_UTF8), indicating all narrow strings in the ScatterBrain framework are assumed to be UTF-8 encoded. After conversion, frees any previously allocated buffers and stores the new wide string pointer and character count. Returns 0 on success or 8 (ERROR_NOT_ENOUGH_MEMORY).

#### sb_WideCharToMultiByte (0x180004498, 188 bytes)

Converts a wide (UTF-16LE) string from the `sb_str_ctx_t` context to a narrow (ANSI) string. The WideCharToMultiByte API is resolved lazily via PEB hash lookup (hash 0x990C8BEE) and cached in `g_pfnWideCharToMultiByte`. Uses the standard two-call pattern. Unlike `sb_MultiByteToWideChar` which uses CP_UTF8 (65001), this function passes code page 0 (CP_ACP, the system's default ANSI code page). Reads the source wide string from `ctx->wide_buf` with length `ctx->wide_len`. Returns the pointer to the narrow string buffer on success, or NULL if allocation fails. Heavily used throughout the framework for converting decrypted API names from wide to narrow for GetProcAddress calls.

#### free_string_buffers (0x180004568, 59 bytes)

Frees both the narrow (ANSI) and wide (UTF-16) string buffers held in an `sb_str_ctx_t` context structure. For each buffer (`narrow_buf` and `wide_buf`), checks if the pointer is non-NULL, calls `sb_LocalFree`, then resets the pointer to NULL and the associated length field to 0. Handles partial initialization gracefully, skipping already-NULL buffers. The `sb_str_ctx_t` structure layout is: `narrow_buf` (offset 0), `narrow_len` (offset 8), `wide_buf` (offset 16), `wide_len` (offset 24), totaling 32 bytes. Paired with `decrypt_string` and the conversion routines that allocate these buffers.

#### wstr_obj_set (0x180004678, 299 bytes)

Sets a wide (UTF-16) string in the `sb_str_ctx_t` context structure by measuring, allocating, and copying from an input wide string pointer. Resolves `lstrlenW` (lazily, via encrypted string decryption and PEB hash resolution, cached in `g_pfnLstrlenW`) to measure the input string length. Allocates `(length + 1) * 2` bytes via `sb_LocalAlloc` with `saturated_mul` overflow protection. Resolves `lstrcpyW` (also lazily cached) and copies the source wide string into the new buffer. Before storing the new buffer, frees any pre-existing `narrow_buf` and `wide_buf`. Returns 0 on success or 8 (ERROR_NOT_ENOUGH_MEMORY).

#### wstr_obj_init_from (0x1800047B8, 38 bytes)

Initializes an `sb_str_ctx_t` context structure from an existing wide string source. First zeroes all four fields of the context to establish a clean state, then calls `wstr_obj_set` to measure, allocate, and copy the source wide string. This is a convenience constructor that combines zero-initialization with immediate population. After return, `ctx->wide_buf` contains a newly allocated copy of the source string.

#### wstr_obj_init (0x1800047E8, 45 bytes)

Initializes an `sb_str_ctx_t` context structure with an empty wide string. Zeroes all four fields, then calls `wstr_obj_set` with a static empty wide string constant (a single null wide character). After initialization, `ctx->wide_buf` points to a newly allocated buffer containing just the null terminator, and `ctx->wide_len` is 1. Serves as the default constructor for the string context type, producing a valid but empty string object.

---

### Object Creation / Initialization

#### init_object (0x180002234, 38 bytes)

Initializes an `sb_synced_list_t` structure to represent an empty synchronized circular doubly-linked list. Sets the node count to 0, then points both flink and blink to the structure itself, creating the circular sentinel node pattern where an empty list is detected by `head->flink == head` or `head->blink == head`. Calls `init_critical_section` on the embedded CRITICAL_SECTION at offset +0x18. Returns the initialized list pointer for convenience, allowing callers to chain the call. This is the constructor counterpart to `destroy_synced_list`. The 64-byte allocation size accommodates the list header fields (count, flink, blink at 24 bytes) plus the CRITICAL_SECTION structure (40 bytes on x64).

#### destroy_synced_list (0x180002204, 31 bytes)

Destroys a synchronized linked list object by first deleting its embedded CRITICAL_SECTION via `sb_DeleteCriticalSection`, then clearing all nodes from the list via `list_clear`. The list head structure itself is NOT freed by this function; the caller is responsible for freeing the head allocation. Used during framework shutdown to tear down the global plugin registry.

#### init_critical_section (0x180005038, 92 bytes)

Wrapper for the Windows InitializeCriticalSection API that lazily resolves the function on first call. Checks the global cache `g_pfnInitCriticalSection`; if NULL, decrypts `enc_InitializeCriticalSection` via `decrypt_string`, converts from wide to narrow, resolves through `resolve_api_dll0`, caches the pointer, and frees temporary buffers. Then calls InitializeCriticalSection with the pointer `a1`. Unlike `sb_DeleteCriticalSection`, returns the input pointer `a1` as a convenience, allowing callers to chain the initialization. The initialized critical section is used by the framework for thread synchronization during plugin loading and synced list operations.

#### sb_DeleteCriticalSection (0x180004FD8, 89 bytes)

Wrapper for the Windows DeleteCriticalSection API that lazily resolves the function on first call. Checks the global cache `g_pfnDeleteCriticalSection`; if NULL, decrypts `enc_DeleteCriticalSection` via `decrypt_string`, converts to narrow via `sb_WideCharToMultiByte`, resolves through `resolve_api_dll0`, caches the result, and frees temporary buffers. Used during plugin teardown and cleanup to release synchronization primitives that were initialized via `init_critical_section`. The lazy resolution pattern avoids importing the API statically, which would expose it in the PE import table.

#### list_init (0x180003280, 15 bytes)

Initializes an empty circular doubly-linked list by setting the head node to the sentinel state. Sets the count field to 0, then points both `head->flink` and `head->blink` to head itself. Unlike `init_object`, does NOT initialize a CRITICAL_SECTION, making it suitable for lists that do not require synchronization or manage their own external locking. The caller must provide a pre-allocated structure whose first three QWORD fields serve as the list header (count, flink, blink).

#### list_insert_front (0x180003210, 28 bytes)

Inserts a new node at the front (tail end) of a circular doubly-linked list, making it the most recently added entry. Sets `new_node->flink` to head and `new_node->blink` to `head->blink` (the current tail), then patches `head->blink->flink` to point to `new_node` and updates `head->blink`. Increments the list count by one. Because new nodes are inserted at the blink (tail) side of the sentinel, iteration via `vtfn_create_obj_i` (which starts from blink) encounters the most recently inserted entries first, implementing a LIFO traversal order. Returns 0.

#### list_unlink_node (0x1800031E0, 27 bytes)

Unlinks a node from its position in a circular doubly-linked list without freeing its memory. Patches the flink/blink pointers of adjacent nodes to skip over the target node and decrements the list head count. The unlinked node itself is NOT freed; the caller retains ownership. This is the low-level unlink primitive used by `list_remove_node` (which adds the `sb_LocalFree` call) and by `vtfn_create_obj_d` (which unlinks under the critical section before spawning the async teardown thread). Returns 0.

#### list_remove_node (0x1800032A0, 43 bytes)

Removes a specific node from a circular doubly-linked list and frees its memory. Unlinks the node by patching adjacent flink/blink pointers, decrements the list count, then frees the removed node via `sb_LocalFree`. Unlike `list_unlink_node`, the caller loses ownership of the node after this call as the memory is immediately freed. Used by `list_clear` during bulk teardown and whenever individual plugin entries need to be permanently destroyed. Returns 0.

#### list_clear (0x1800032E0, 43 bytes)

Removes and frees all nodes from a circular doubly-linked list, leaving it in the empty sentinel state. Iterates in a while loop, each iteration checking if `head->blink` differs from head (indicating at least one node remains). The tail node is passed to `list_remove_node`, which unlinks it, decrements the count, and frees its memory. The loop continues until `head->blink == head`. After completion, the list is in the same state as after `list_init`: count=0, flink=blink=head. Does not free the head sentinel itself, only the dynamically allocated nodes.
