# ScatterBrain Inner PE: Encrypted Strings Report

<a id="enc-discovery"></a>
## Discovery

The inner PE's `.rdata` section contains **476 data items** that IDA flags as "strings" — but all of them are encrypted. There are no plaintext strings anywhere in the binary. The single declared import (`KERNEL32.dll!GetSystemTime`) is a red herring; the real API surface is built entirely at runtime through encrypted name resolution.

<a id="enc-cipher"></a>
## The Cipher: `decrypt_string` (0x1800045B8)

Every encrypted blob in the binary passes through this function. It implements a **rolling polynomial XOR cipher**:

1. **Key seed**: 2-byte little-endian prefix at the start of each blob → `key = blob[0] | (blob[1] << 8)`
2. **XOR step**: `plaintext_byte = (key & 0xFF) ^ encrypted_byte`
3. **Key evolution**: `key = (-42860544 * key) - (135791246 * HIWORD(key)) - 1043215206` (mod 2^32)
4. **Termination**: null byte in plaintext output

Each blob is self-keyed (its own 2-byte prefix). The polynomial key update ensures that even similar plaintexts produce different ciphertexts. The cipher is NOT the same as the rolling XOR used for import names in the outer loader's packed blob format.

```python
def decrypt_blob(img, rva):
    blob = img[rva:]
    key = (blob[0] | (blob[1] << 8)) & 0xFFFFFFFF
    result = bytearray()
    for i in range(2, min(len(blob), 4092)):
        plain = (key & 0xFF) ^ blob[i]
        if plain == 0:
            break
        result.append(plain)
        key = ((-42860544 * key) - (135791246 * ((key >> 16) & 0xFFFF)) - 1043215206) & 0xFFFFFFFF
    return result.decode('ascii')
```

The function allocates a 4096-byte buffer, decrypts into it, then calls `sb_MultiByteToWideChar` to convert the narrow string to UTF-16 for Windows API consumption. The decrypted narrow buffer is freed afterward.

<a id="enc-what-was-found"></a>
## What Was Found: 34 Encrypted Strings

### Region 1: Early `.rdata` (RVA 0x6010–0x60F0) — 12 strings

These are used by the core infrastructure: DLL resolver families, worker thread, and the initialization path.

| RVA | VA | Decrypts To | Used By |
|-----|-----|-------------|---------|
| `0x06010` | `0x180006010` | `kernel32.dll` | `resolve_api_dll0` — DLL name |
| `0x06020` | `0x180006020` | `msvcrt.dll` | `resolve_api_dll1` — DLL name |
| `0x06030` | `0x180006030` | `memcpy` | `resolve_api_dll1` — function name |
| `0x06040` | `0x180006040` | `lstrcpyW` | `vtfn_extract_filename` — path→filename extraction |
| `0x06050` | `0x180006050` | `GetCurrentProcess` | `worker_thread_entry` — self-handle for termination |
| `0x06068` | `0x180006068` | `ExitProcess` | `worker_thread_entry` — clean exit |
| `0x06078` | `0x180006078` | `TerminateProcess` | `worker_thread_entry` — forced exit |
| `0x06090` | `0x180006090` | `QueryPerformanceCounter` | `vtfn_generate_packet_key` — packet key generation |
| `0x060B0` | `0x1800060B0` | `EnterCriticalSection` | `vtfn_create_obj_b/c/d/e/g`, `vtfn_plugin_loader` |
| `0x060C8` | `0x1800060C8` | `LeaveCriticalSection` | `vtfn_create_obj_b/c/d/e/h`, `vtfn_plugin_loader` |
| `0x060E0` | `0x1800060E0` | `CreateThread` | `cmd1_attach_handler`, `vtfn_create_obj_d` |
| `0x060F0` | `0x1800060F0` | `CloseHandle` | `cmd1_attach_handler`, `vtfn_create_obj_d`, `vtfn_multi_resolve` |

### Region 2: Late `.rdata` (RVA 0x1AB70–0x1AD58) — 22 strings

These are used by the operational vtable functions — the C2 plugin's actual capabilities.

| RVA | VA | Decrypts To | Used By |
|-----|-----|-------------|---------|
| `0x1AB70` | `0x18001AB70` | `GetLastError` | `resolve_api_dll3`, `resolve_multi_apis`, `vtfn_exec_reflective_loader`, `vtfn_multi_resolve` |
| `0x1AB80` | `0x18001AB80` | `InitializeCriticalSection` | `init_critical_section` (init_object callee) |
| `0x1ABC0` | `0x18001ABC0` | `ws2_32.dll` | `resolve_api_dll2` — DLL name |
| `0x1ABD0` | `0x18001ABD0` | `ntohl` | `vtfn_decrypt_and_load_blob`, `vtfn_compress_encrypt`, `vtfn_decrypt_decompress`, `vtfn_decrypt_packet_header` |
| `0x1ABE0` | `0x18001ABE0` | `htonl` | `vtfn_compress_encrypt` |
| `0x1ABF0` | `0x18001ABF0` | `VirtualAlloc` | `vtfn_exec_reflective_loader`, `vtfn_shellcode_trampoline` |
| `0x1AC00` | `0x18001AC00` | `kernel32.dll` | `vtfn_multi_resolve` — DLL for injection APIs |
| `0x1AC10` | `0x18001AC10` | `VirtualAllocEx` | `vtfn_multi_resolve` |
| `0x1AC28` | `0x18001AC28` | `WriteProcessMemory` | `vtfn_multi_resolve` |
| `0x1AC40` | `0x18001AC40` | `CreateRemoteThread` | `vtfn_multi_resolve` |
| `0x1AC58` | `0x18001AC58` | `VirtualFreeEx` | `vtfn_multi_resolve` |
| `0x1AC70` | `0x18001AC70` | `VirtualProtectEx` | `vtfn_multi_resolve` |
| `0x1AC88` | `0x18001AC88` | `kernel32.dll` | `resolve_multi_apis` — DLL for memory reading |
| `0x1AC98` | `0x18001AC98` | `VirtualQueryEx` | `resolve_multi_apis` |
| `0x1ACB0` | `0x18001ACB0` | `ReadProcessMemory` | `resolve_multi_apis` |
| `0x1ACC8` | `0x18001ACC8` | `FindFirstFileW` | `resolve_api_dll3` |
| `0x1ACE0` | `0x18001ACE0` | `FindClose` | `resolve_api_dll3` |
| `0x1ACF0` | `0x18001ACF0` | `GetModuleFileNameA` | `vtfn_plugin_loader` |
| `0x1AD20` | `0x18001AD20` | `ResumeThread` | `vtfn_multi_resolve` |
| `0x1AD30` | `0x18001AD30` | `VirtualFree` | `vtfn_exec_reflective_loader` |
| `0x1AD40` | `0x18001AD40` | `GetModuleHandleA` | `vtfn_multi_resolve`, `resolve_multi_apis` |
| `0x1AD58` | `0x18001AD58` | `FreeLibrary` | `resolve_api_dll3` |

<a id="enc-resolver-families"></a>
## DLL Resolver Families

The decrypted strings reveal 4 DLL resolver families, each loading APIs from a different DLL:

| Resolver | DLL | APIs Loaded | Purpose |
|----------|-----|-------------|---------|
| `resolve_api_dll0` | `kernel32.dll` | General-purpose (callers specify function name) | Core Windows APIs |
| `resolve_api_dll1` | `msvcrt.dll` | `memcpy` | C runtime memory operations |
| `resolve_api_dll2` | `ws2_32.dll` | `ntohl`, `htonl` (via callers) | **Network byte-order conversion** |
| `resolve_api_dll3` | (caller-specified) | `FindFirstFileW`, `FindClose`, `FreeLibrary` | File system + library management |

Note: `resolve_api_dll0` loads `kernel32.dll` once and caches the handle. Callers pass the function name (already decrypted) as an argument. This is the most-used resolver — 13 of the 34 strings are function names resolved through it.

<a id="enc-capability-classification"></a>
## Capability Classification

Decrypting the strings reveals the C2 plugin's complete operational surface:

### Process Injection (`vtfn_multi_resolve` — vtable slot 0x80/0x88)
The largest function (1413 bytes) resolves a full **CreateRemoteThread injection toolkit**:
- `VirtualAllocEx` — allocate memory in target process
- `WriteProcessMemory` — write payload into target
- `VirtualProtectEx` — set memory permissions
- `CreateRemoteThread` — execute payload in target
- `ResumeThread` — resume suspended thread
- `VirtualFreeEx` — clean up on failure
- `CloseHandle` — close thread handle
- `GetModuleHandleA` — find module in target

### Process Memory Reading (`resolve_multi_apis`)
Companion to the injector:
- `VirtualQueryEx` — query memory regions in target process
- `ReadProcessMemory` — read target process memory
- `GetModuleHandleA` — locate modules

### Packet Crypto / Network Protocol
Heavy use of `ntohl` and `htonl` — byte-order conversion for network protocols:
- `vtfn_decrypt_and_load_blob` (0x70): 4x `ntohl` — blob header parsing
- `vtfn_compress_encrypt` (0xA8): 2x `ntohl` + 3x `htonl` — outbound packet encrypt
- `vtfn_decrypt_decompress` (0xB0): 5x `ntohl` — inbound packet decrypt (805 bytes)
- `vtfn_decrypt_packet_header` (0xB8): 1x `ntohl` — 20-byte header decrypt

### Memory / Loader (`vtfn_exec_reflective_loader`, `vtfn_shellcode_trampoline`)
- `VirtualAlloc` — allocate executable memory for reflective loader copy
- `VirtualFree` — release memory
- `GetLastError` — error handling

### Thread Synchronization (`vtfn_create_obj_b/c/d/e/g/h`)
6 vtable functions use `EnterCriticalSection`/`LeaveCriticalSection` for thread-safe object creation and manipulation.

### Plugin Registration (`vtfn_plugin_loader`)
- `GetModuleFileNameA` — detects PE module handles vs raw blobs
- `EnterCriticalSection`/`LeaveCriticalSection` — thread-safe command dispatch
- `GetLastError` — error reporting

### Self-Protection (`worker_thread_entry`)
- `GetCurrentProcess` → `TerminateProcess` — self-terminate on failure
- `ExitProcess` — clean exit fallback

### Packet Key Generation (`vtfn_generate_packet_key`)
- `QueryPerformanceCounter` — high-resolution timing for packet encryption key generation

<a id="enc-large-blobs"></a>
## The 8 Large Encrypted Data Blobs

Separate from the 34 encrypted API/DLL name strings, the `worker_thread_entry` registers **8 large encrypted data blobs** via `vtfn_compose_m`. These are NOT decrypted by `decrypt_string` — they're registered as opaque data chunks for later use:

| Address | Size | Notes |
|---------|------|-------|
| `0x180009100` | 8,873 B | |
| `0x18000D370` | 16,466 B | Largest blob |
| `0x18000B3B0` | 8,113 B | |
| `0x1800070E0` | 8,214 B | |
| `0x1800113D0` | 5,223 B | |
| `0x180012840` | 10,002 B | |
| `0x180014F60` | 12,027 B | |
| `0x180017E60` | 11,464 B | |
| **Total** | **~81 KB** | |

All 8 blobs have been fully decrypted (IMUL cipher + LZ77), reconstructed as PE DLLs, and analyzed. They are **C2 plugin modules**: Install (process launcher), Plugins (registry persistence), Config (C2 config/file ops), Online (system recon + C2 router), TCP, HTTP, UDP (RUDP), and DNS (tunnel). See [blob_index.md](blob_index.md) for the complete analysis.

<a id="enc-plugin-loader"></a>
## vtfn_plugin_loader (0x180002844) — Nested Plugin Loading

The most significant vtable function, previously called `vtfn_main_handler`, is actually a **plugin loader**. It accepts either a loaded PE module handle or a raw ScatterBrain packed blob, initializes the nested plugin, and registers its vtable in a thread-safe linked list.

### Detection Logic

1. Calls `GetModuleFileNameA(input, buf, 1)` — buffer size 1 guarantees failure
2. If it returns non-zero OR `GetLastError() == ERROR_INSUFFICIENT_BUFFER (122)` → input is a valid PE module handle
3. **PE path**: resolves entry point via MZ → PE header → `AddressOfEntryPoint`
4. **ScatterBrain blob path**: checks `DWORD[0] ^ DWORD[1] == 0x7C35D9A3` (the packer magic), then uses `base + DWORD[10]` as the dispatch function offset
5. **Fallback**: null dispatch (crash) — invalid input

### Dispatch Protocol

The loader calls the discovered dispatch function three times with the standard DllMain_dispatcher command sequence:
- `dispatch(input, 100, &g_vtable_status)` — init
- `dispatch(input, 102, ctx+24)` — custom command (get capabilities?)
- `dispatch(input, 104, ctx+56)` — get vtable pointer

### PE Identification

For loaded PE modules, extracts `TimeDateStamp` from the Optional Header. For ScatterBrain blobs, reads `DWORD[13]` (offset 52 — likely a version or build stamp in the packed header).

### Linked List Registration

The plugin's context (64-byte object) is inserted into a doubly-linked list anchored at `g_initialized_obj`, protected by `EnterCriticalSection`/`LeaveCriticalSection`. This allows multiple plugins to coexist.

### Implication

This explains the reflective loader copy at inner PE RVA 0x6100 — the plugin can use it to reflectively load additional packed PE blobs received via C2 commands. The 8 large encrypted data blobs (~81KB) registered by the worker thread are likely **packed plugin modules** waiting to be loaded through this mechanism.

<a id="enc-config-blob"></a>
## Config Blob at 0x1800068E0

The config data (454 bytes of high-entropy data, followed by zeros) is stored at vtable offset 0xE0 via `g_rdata_config`. It has **zero cross-references** from within this DLL — it's purely exported to the C2 framework via the vtable pointer (CMD 104). The C2 orchestrator reads `vtable[0xE0/8]` to access the config.

The blob is NOT encrypted with the `decrypt_string` cipher (attempted decryption produces noise). It uses a different encryption scheme or format that is handled by the external C2 framework. It likely contains C2 server addresses, encryption keys, or beacon configuration.

<a id="enc-payload-context"></a>
## init_payload_context: What the Loader Passes

When the reflective loader calls `DllMain(base, 1, payload_ptr)`:
- If `payload_ptr == 0` (our sample): default mode, flag=3, spawns worker thread
- If `payload_ptr != 0`: expected struct is `{ QWORD data_ptr; DWORD size; DWORD type_flag; }`, data is memcpy'd into allocated buffer, runs synchronously

In our sample, `spawn_reflective_loader` passes 0 as the thread arg → `payload_ptr = 0` → worker thread mode.

<a id="enc-shellcode-trampoline"></a>
## vtfn_shellcode_trampoline (0x180004868) — Hidden Stream Cipher

Previously called `vtfn_handler_s`, this function is NOT a simple VirtualAlloc wrapper. It's a **shellcode decryptor and execution trampoline**:

### Mechanism

1. `VirtualAlloc(NULL, 266, MEM_COMMIT, PAGE_EXECUTE_READWRITE)` — allocate RWX memory
2. Decrypt 266 bytes from `byte_18001C010` (RVA `0x1C010`, in `.data1` section) using transform:
   ```
   decrypted[i] = ((encrypted[i] + 13) ^ 0xF3) - 13
   ```
3. Copy decrypted bytes to RWX allocation
4. Call the decrypted code as a function: `result = shellcode(arg1, arg2, arg3, arg4)`
5. `VirtualFree` the allocation, return result

### Decrypted Shellcode: 4-Round IMUL Stream Cipher (266 bytes)

The decrypted shellcode implements a **stream cipher** with signature:
```c
void cipher(BYTE* input, int size, BYTE* output, DWORD initial_key);
```

**Algorithm:**
- Iterates over each byte of input
- For each byte, selects one of 4 mixing rounds based on `index % 4`
- Each round uses a different pair of IMUL constants:

| Round | Constant 1 | IMUL Constant 2 |
|-------|-----------|-----------------|
| 0 | `0xCA1A5842` | `0x563446B7` |
| 1 | `0x5F7B88D1` | `0x2D93E75E` |
| 2 | `0xAD5BC1C9` | `0x7992708E` |
| 3 | `0x3223D2C1` | `0x10A75686` |

- The round updates an accumulator via XOR/SUB chain with the IMUL result
- Output byte = `input_byte ^ (accumulator & 0xFF)`
- The accumulator carries state across all bytes (stream cipher property)

### Implication

This is the **third distinct cipher** in the ScatterBrain system:
1. **Outer loader**: rolling XOR with encrypted-byte feedback (import names)
2. **Inner PE**: rolling polynomial XOR with 2-byte seed (API/DLL name strings)
3. **Shellcode**: 4-round IMUL stream cipher (large data blobs)

The 8 large encrypted data blobs (~81KB) registered by `worker_thread_entry` are almost certainly decrypted by this cipher. The initial key likely comes from the blob header or the worker's initialization context.

Saved as `decrypted_shellcode_266.bin` in the private artifact archive.

<a id="enc-complete-pipeline"></a>
## Complete Blob Processing Pipeline

The deep-dive of vtable handlers revealed a complete **encrypt→compress→encrypt** pipeline for plugin blob management:

### Sending (Outbound)
1. **`vtfn_generate_packet_key`** (0x1800011B4) — Generate per-packet encryption key
   - Mixes: monotonic counter (sub 0x35E5A7BE), `QueryPerformanceCounter`, `GetSystemTime` fields
   - This is why `GetSystemTime` is the only declared import — it's part of key generation
2. **`lz_compress`** (0x180003BA0) — LZ77 compression (36KB hash-table workspace)
3. **`vtfn_shellcode_trampoline`** → IMUL stream cipher encryption
4. **`vtfn_compress_encrypt`** (0x180004D28) — Orchestrates compress+encrypt
   - Packet format: `[htonl(key), field4, field8, htonl(compressed_size), htonl(decompressed_size), encrypted_payload...]`

### Receiving (Inbound)
1. **`vtfn_decrypt_packet_header`** (0x180004968) — Decrypt 20-byte packet header
2. **`vtfn_decrypt_decompress`** (0x1800049F8) — Orchestrates decrypt+decompress
   - Step 1: Decrypt 20-byte header with IMUL cipher (key = ntohl of first DWORD)
   - Step 2: Extract compressed_size, decompressed_size, flags from header
   - Step 3: Decrypt full payload
   - Step 4: LZ77 decompression if flag 0x8000 set and sizes differ
3. **`vtfn_decrypt_and_load_blob`** (0x180002B24) — Full blob loading orchestrator
   - Calls vtfn_decrypt_decompress → validates magic `0x650001` → loads via reflective loader → registers plugin

### Plugin Loading
1. **`vtfn_exec_reflective_loader`** (0x1800020A4) — Copy embedded reflective loader (RVA 0x6100, 2014 bytes) to RWX, call with packed blob
2. **`vtfn_plugin_loader`** (0x180002844) — Register loaded PE in thread-safe doubly-linked list

### Utility
- **`vtfn_base62_encode`** (0x18000126C) — `byte % 62 → [A-Za-z0-9]` for alphanumeric ID generation
- **`vtfn_extract_filename`** (0x1800015D8) — Extract filename from module path (scan for last `\`)

### LZ77 Compression
- **`lz_decompress`** (0x1800039C0) — LZ77 variant with hash-table back-references (12-bit offset, 4-bit/8-bit length)
- **`lz_compress`** (0x180003BA0) — Matching compressor
- **`lz_decompress_wrapper`** (0x180003B20) — Variable-length header parsing + decompress dispatch
- **`lz_get_compressed_size`** / **`lz_get_decompressed_size`** — Header field extractors
- **`lz_update_hashtable`** (0x180003980) — Update hash table during decompression

Compressed blob format:
```
[flags: 1 byte]  bit 0: is_compressed, bit 1: size fields are 4 bytes (else 1)
[compressed_size: 1 or 4 bytes]
[decompressed_size: 1 or 4 bytes]
[payload data]
```

<a id="enc-summary"></a>
## Summary

The encrypted string decryption reveals this inner PE to be a **ScatterBrain C2 plugin DLL** with:

1. **Process injection** capability (CreateRemoteThread-based)
2. **Network communication** infrastructure (ws2_32.dll byte-order APIs)
3. **Thread-safe object management** (critical sections)
4. **Self-protection** mechanisms (terminate on failure)
5. **8 encrypted payload modules** (~81KB total, registered at init)
6. Zero plaintext strings — every API name, DLL name, and string literal is encrypted with the rolling polynomial XOR cipher

The only declared import (`GetSystemTime`) serves as a minimal PE validity token. The real API surface of **31 unique functions from 3 DLLs** is constructed entirely at runtime.
