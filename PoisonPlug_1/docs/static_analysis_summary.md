# ScatterBrain Inner PE — Static Analysis Summary

<a id="summary-what-is-program"></a>
## What Is This Program?

This is a **modular C2 (Command & Control) plugin framework**. It's designed to:
1. Be injected into a target process via a reflective PE loader
2. Dynamically resolve all APIs at runtime (no static imports except GetSystemTime)
3. Receive encrypted/compressed command blobs from a C2 server
4. Load additional plugins (nested DLLs or packed blobs) on demand
5. Inject code into other processes via CreateRemoteThread or thread hijacking

<a id="summary-architecture-overview"></a>
## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                   HOST DLL                           │
│  DllMain → CreateThread → spawn_reflective_loader   │
│    └─ VirtualAlloc(RWX, 1MB)                        │
│    └─ memmove(bootstrap + packed blob, 106KB)       │
│    └─ call bootstrap                                │
│         └─ call-pop trick → blob address on stack   │
│         └─ reflective_loader(blob)                  │
│              └─ PEB walk, API hash, section map      │
│              └─ relocation, import resolution        │
│              └─ call inner DllMain                   │
└─────────────────────┬───────────────────────────────┘
                      │
                      ▼
┌─────────────────────────────────────────────────────┐
│                 INNER PE (this binary)               │
│                                                      │
│  DllMain_dispatcher (0x180004344)                   │
│    ├─ CMD 0: init/cleanup                           │
│    ├─ CMD 1: attach → cmd1_attach_handler           │
│    │    ├─ Populate 26-function vtable              │
│    │    ├─ Spawn worker_thread_entry                │
│    │    │    ├─ Register 8 encrypted data blobs     │
│    │    │    ├─ Create handler object                │
│    │    │    └─ Enter handler dispatch loop          │
│    │    └─ Return to caller                         │
│    ├─ CMD 101: return version (1)                   │
│    ├─ CMD 102: custom command dispatch              │
│    └─ CMD 104: return vtable pointer                │
│                                                      │
│  26-Function Vtable (at 0x18001C1B0)                │
│    ├─ Plugin management                             │
│    ├─ Crypto (encrypt/decrypt)                      │
│    ├─ Compression (LZ77)                            │
│    ├─ Process injection                             │
│    ├─ Object/thread management                      │
│    ├─ Network protocol helpers                      │
│    └─ Utility (base62, filename extract)            │
└─────────────────────────────────────────────────────┘
```

<a id="summary-api-resolution"></a>
## API Resolution Strategy

The inner PE has **only 1 declared import**: `KERNEL32.dll!GetSystemTime`. All other APIs are resolved dynamically through a layered system:

### Layer 1: Hash-Based Resolution (PEB Walk)
- `resolve_api_by_hash` (0x180003328): walks PEB → InLoadOrderModuleList → export table
- Algorithm: ROR-8 / XOR / constant 0x7C35D9A3
- Bootstraps: LoadLibraryA, GetProcAddress, LocalAlloc, LocalFree, MultiByteToWideChar, WideCharToMultiByte

### Layer 2: Encrypted String Resolution
- `decrypt_string` (0x1800045B8): rolling polynomial XOR cipher
  - Key formula: `key = (-42860544 * key) - (135791246 * HIWORD(key)) - 1043215206`
  - 2-byte LE seed prefix per blob
- 37 encrypted blobs → DLL names + API function names

### Layer 3: DLL-Specific Resolvers
| Resolver | DLL | Method |
|----------|-----|--------|
| resolve_api_dll0 | kernel32.dll | LoadLibraryA + GetProcAddress |
| resolve_api_dll1 | msvcrt.dll | Same pattern |
| resolve_api_dll2 | ws2_32.dll | Same pattern |
| resolve_api_dll3 | Caller-specified | Same pattern |

### Layer 4: Lazy Caching
All resolved function pointers are cached in global variables (0x18001C120–0x18001C340). Each function checks `if (!g_pfnXxx)` before resolving — classic lazy initialization.

**Total resolved APIs**: 37 functions across 3 DLLs (kernel32, msvcrt, ws2_32)

<a id="summary-three-ciphers"></a>
## Three Cipher Systems

### Cipher 1: Rolling XOR (Outer Loader Import Resolution)
- Used by reflective_loader to decrypt PE import names
- Key update uses ENCRYPTED byte: `key = (key + enc_byte) * PRNG_MULT + PRNG_ADD`
- Key seed from packed PE header `magic0` field

### Cipher 2: Rolling Polynomial XOR (Inner PE String Decryption)
- Used by `decrypt_string` to decrypt API/DLL names
- Key formula: `(-42860544 * key) - (135791246 * HIWORD(key)) - 1043215206`
- 2-byte LE key seed per blob
- 37 encrypted blobs, 3 DLL names + 34 API names

### Cipher 3: IMUL Stream Cipher (Large Blob Encryption)
- 266-byte shellcode decrypted from RVA 0x1C010 via `((byte+13) ^ 0xF3) - 13`
- 4-round cipher selected by `index % 4`:
  - Round 0: `0xCA1A5842 - 0x563446B7 * key`
  - Round 1: `0x5F7B88D1 - 0x2D93E75E * key`
  - Round 2: `0xAD5BC1C9 - 0x7992708E * key`
  - Round 3: `0x3223D2C1 - 0x10A75686 * key`
- Feistel-like mixing: `acc = k[3] ^ ((k[1] ^ (acc - k[0])) - k[2])`
- Output: `acc ^ input_byte`
- Used for: packet encryption/decryption, blob encryption

<a id="summary-blob-pipeline"></a>
## Blob Processing Pipeline

### Receiving Data (C2 → Plugin)
```
Network packet
  → vtfn_decrypt_packet_header: decrypt 20-byte header with IMUL cipher
  → Extract: key, compressed_size, decompressed_size (ntohl byte-order conversion)
  → vtfn_decrypt_decompress: decrypt payload with IMUL cipher
  → If compressed: lz_decompress (LZ77 with hash-table back-refs)
  → Plaintext data
```

### Sending Data (Plugin → C2)
```
Plaintext data
  → vtfn_generate_packet_key: counter + QueryPerformanceCounter + GetSystemTime
  → lz_compress: LZ77 compression
  → vtfn_compress_encrypt: IMUL cipher encryption
  → Build header: [htonl(key), field4, field8, htonl(comp_size), htonl(decomp_size)]
  → Network packet
```

### Loading Plugins (Blob → Execution)
```
Encrypted blob
  → vtfn_decrypt_and_load_blob: decrypt with IMUL cipher
  → Validate magic 0x650001 in decrypted header
  → vtfn_exec_reflective_loader:
      Copy 2014-byte reflective loader from RVA 0x6100 to RWX
      Call loader(decrypted_blob)
  → vtfn_plugin_loader: register plugin in linked list
```

<a id="summary-process-injection"></a>
## Process Injection (vtfn_multi_resolve)

Two modes for injecting into remote processes:

### Mode 1: CreateRemoteThread
1. GetModuleHandleA("kernel32.dll") → resolve 6 injection APIs
2. VirtualAllocEx(target, 0, 2014, RWX) → write reflective loader (2014 bytes from RVA 0x6100)
3. VirtualAllocEx(target, 0, payload_size, RWX) → write payload data
4. VirtualAllocEx(target, 0, 16, RWX) → write parameter struct {ptr, size, flags}
5. CreateRemoteThread(target, NULL, 0, remote_loader, remote_params, 0, &tid)
6. CloseHandle(thread)

### Mode 2: Thread Hijack
Steps 1-4 same, then:
5. Build 26-byte x64 stub: `mov rcx,param; push rcx; mov rax,loader; call rax; pop rcx; ret`
6. VirtualProtectEx + WriteProcessMemory to inject stub
7. ResumeThread(suspended_thread)

<a id="summary-plugin-management"></a>
## Plugin Management

- **Registration**: `vtfn_plugin_loader` accepts PE module handles or encrypted blobs
- **PE detection**: `GetModuleFileNameA(input, buf, 1)` — returns nonzero for valid module handles
- **Blob detection**: `DWORD[0] ^ DWORD[1] == 0x7C35D9A3` (packer magic)
- **Plugin protocol**: Commands 100 (init), 102 (capabilities), 104 (vtable pointer)
- **Storage**: Doubly-linked list with critical section protection
- **Identification**: PE TimeDateStamp extracted for tracking

## Object System

Thread-safe object factories (`vtfn_create_obj_b/c/d/e/g/h`):
- Pattern: EnterCriticalSection → traverse linked list → find/create object → LeaveCriticalSection
- Objects are 64-byte allocations initialized with flink/blink pointers + critical section
- Reference counting via `*(obj + 16)`

## Self-Protection

If handler object creation fails in `worker_thread_entry`:
1. GetCurrentProcess()
2. TerminateProcess(current, 0)
3. If that fails: ExitProcess(0)
→ Rather die than run without proper initialization

<a id="summary-key-data-structures"></a>
## Key Data Structures

### Global Payload Context (0x18001C348-0x18001C358)
| Offset | Type | Name | Description |
|--------|------|------|-------------|
| 0x00 | QWORD | g_payload_data | Allocated copy of payload from outer loader |
| 0x08 | DWORD | g_payload_size | Payload data size |
| 0x0C | DWORD | g_payload_flags | Flags (default 3 = thread mode) |

### Plugin List Entry (64 bytes)
| Offset | Type | Description |
|--------|------|-------------|
| 0x00 | QWORD | flink (next) |
| 0x08 | QWORD | blink (prev) |
| 0x10 | DWORD | ref_count |
| 0x14 | DWORD | timestamp (PE TimeDateStamp) |
| 0x18 | QWORD | critical_section |
| 0x24 | DWORD | is_pe_module flag |
| 0x28 | DWORD | unused |
| 0x30 | QWORD | module_handle_or_blob |
| 0x38 | QWORD | vtable_pointer (from CMD 104) |

### Packet Header (20 bytes, network byte order)
| Offset | Size | Description |
|--------|------|-------------|
| 0x00 | 4 | Encryption key (htonl) |
| 0x04 | 4 | Field 4 |
| 0x08 | 4 | Field 8 |
| 0x0C | 4 | Compressed size (htonl) |
| 0x10 | 4 | Decompressed size (htonl) |

<a id="summary-decrypted-blobs"></a>
## Decrypted Plugin Blobs (8 C2 Modules)

The 8 encrypted data blobs (~81KB total) registered by `worker_thread_entry` have been fully decrypted (IMUL cipher + LZ77), unpacked from ScatterBrain packed PE format, and reconstructed as valid PE32+ DLLs. Each is a **plugin module** following the same `DllMain_dispatcher` protocol (CMD 0/1/101/102/104) as the inner PE.

| Blob | Plugin ID | Image | Imports | Role | Key APIs |
|------|-----------|-------|---------|------|----------|
| blob_0 | `Install` (v103) | 0x6000 | 5 DLLs, 34 funcs | **Process Launcher + Anti-Analysis** | CreateProcessW, DuplicateTokenEx, OpenProcessToken, CreateToolhelp32Snapshot |
| blob_1 | `Plugins` (v101) | 0x7000 | 3 DLLs, 12 funcs | **Registry Persistence** | RegOpenKeyExW, RegEnumValueW, RegDeleteValueW, RegQueryValueExW |
| blob_2 | 102 (v—) | 0x7000 | (none) | **C2 Config / File Operations** | All dynamic — 37 encrypted strings reveal CreateFileW, WriteFile, ReadFile, DeleteFileW, GetVolumeInformationW |
| blob_3 | `Online` (v104) | 0xA000 | 5 DLLs, 31 funcs | **System Recon + C2 Router** | GetVersionExW, GetComputerNameW, GlobalMemoryStatusEx, InternetOpenA; DGA domain generation |
| blob_4 | `TCP` (v200) | 0x6000 | 3 DLLs, 21 funcs | **Raw TCP + SOCKS Proxy** | WSAIoctl, 15 WS2_32 ordinals; SOCKS4/5 + HTTP CONNECT proxy; custom DNS via dnsapi.dll |
| blob_5 | `HTTP` (v201) | 0x7000 | 5 DLLs, 38 funcs | **HTTP POST Transport** | HttpSendRequestExA, ObtainUserAgentString (UA spoofing), InternetSetOptionA (cert bypass) |
| blob_6 | `UDP` (v202) | 0x8000 | 2 DLLs, 35 funcs | **Reliable UDP (RUDP) Transport** | 14 WS2_32 ordinals; AIMD congestion control, SACK, 8 packet types, PRNG XOR per-packet |
| blob_7 | `DNS` (v203) | 0x8000 | 2 DLLs, 36 funcs | **DNS Tunnel Transport** | 13 WS2_32 ordinals; hex-encoded subdomain labels, TXT record responses, iphlpapi.dll adapter enum |

All compiled 2017-02-22/23 (timestamps 0x58AEBA59–0x58AEF8D6). All 337 functions across 8 plugins fully renamed. Blob_2's lack of imports confirms it operates entirely through the parent's 26-function vtable interface, using encrypted strings to resolve APIs dynamically.

### Plugin Architecture Pattern

Each blob follows the same architecture as the inner PE:
- `DllMain_dispatcher` entry with fdwReason-as-command protocol
- CMD 1 (attach): populate vtable, start worker
- CMD 104: return vtable pointer to parent
- Parent registers plugin in `sb_synced_list_t` linked list

The inner PE acts as the **plugin orchestrator**: it decrypts, loads, and manages these 8 modules, routing C2 commands to the appropriate plugin based on command type.

<a id="summary-analysis-status"></a>
## Analysis Status

All major items from the initial analysis have been resolved:

1. ~~**8 encrypted data blobs**~~ → **RESOLVED**: All 8 decrypted, decompressed (IMUL + LZ77), reconstructed as PE DLLs, and fully analyzed — see [blob_index.md](blob_index.md)
2. ~~**Handler dispatch loop**~~ → **RESOLVED**: `vtfn_plugin_loader` (723 bytes) manages plugin registration; `vtfn_decrypt_and_load_blob` handles blob→plugin pipeline; command routing via vtable dispatch documented in per-blob analyses
3. ~~**Network transport**~~ → **RESOLVED**: Four transport plugins — TCP (blob_4), HTTP (blob_5), UDP/RUDP (blob_6), DNS tunnel (blob_7) — with blob_3 "Online" as the C2 router selecting among 6 protocol schemes
4. ~~**ws2_32.dll usage**~~ → **RESOLVED**: Inner PE only uses ntohl/htonl for packet header byte-order conversion; all actual networking delegated to transport plugins
5. ~~**resolve_multi_apis**~~ → **RESOLVED**: Process injection with 2 modes — CreateRemoteThread (6 APIs) and thread hijack (26-byte x64 stub via VirtualProtectEx + WriteProcessMemory + ResumeThread)
6. ~~**sub_\* functions**~~ → **RESOLVED**: Inner PE has zero `sub_*` remaining (76 functions, all named). Outer DLL has 12 `sub_*` remaining, all CRT library stubs (3–56 bytes) not relevant to malware analysis
7. ~~**Individual plugin internals**~~ → **RESOLVED**: All 337 functions across 8 plugins fully renamed and documented — see per-blob analysis docs ([blob_0](blob_0_install_analysis.md) through [blob_7](blob_7_dns_analysis.md))
