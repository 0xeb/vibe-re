# Vibe Reverse Engineering with idasql: Dissecting a trivial malware sample

---

## Introduction

The sample -- SHA-256 `60678e352f3c849e36413f5de51b5eeca1180840c818f9ece0a0da803eb205a5` dubbed as **ScatterBrain** is fully disassembled and decompiled with the help of Claude Code + idasql.

By the end of this analysis, we had:

- Neutralized **80 opaque predicate** anti-disassembly blocks
- Traced a **4-stage execution chain** from DllMain to C2-ready runtime
- Reversed **3 custom cipher systems** (IMUL, polynomial XOR, rolling XOR)
- Extracted and reconstructed **8 encrypted plugin DLLs** from the host binary
- Renamed all **337 functions** across 9 modules (zero `sub_*` remaining)
- Produced consistent naming and type annotations across every plugin

This article walks through the architecture, the plugins, the ciphers, and the tooling that made it possible.

## The Execution Chain

The sample presents as a standard x86-64 PE DLL, but its real behavior unfolds across four stages:

```
Stage 1: Host DLL
  DllMain -> CreateThread -> spawn_reflective_loader
    VirtualAlloc(RWX, 1MB)
    memmove(bootstrap + packed blob)
    call into RWX memory

Stage 2: Reflective Loader (in RWX memory)
  PEB walk -> resolve LoadLibraryA, GetProcAddress
  Parse custom packed PE format
  Map sections, fix relocations
  Decrypt imports (rolling XOR cipher)
  Call inner PE's DllMain

Stage 3: Inner PE Orchestrator (75 functions)
  Command dispatcher via fdwReason
  26-function vtable
  Worker thread: decrypt + decompress 8 plugin blobs
  Load each as a DLL via reflective loader copy
  Register in plugin linked list

Stage 4: Plugin DLLs (8 modules, 337 functions total)
  Each plugin follows the same DllMain_dispatcher protocol
  Each exposes a small vtable for the orchestrator to call
  Specialization: install, persist, configure, recon, transport
```

The host DLL's `DllMain` does almost nothing visible -- it spawns a thread and returns. The thread copies a bootstrap stub and a 104KB packed blob into freshly allocated RWX memory, then calls into it. A call-pop trick (`call` pushes the return address, which *is* the blob) passes the blob's location to the reflective loader.

The reflective loader ([fully decompiled](../snips/0000000180021137_reflective_loader.c)) walks the PEB to find `LoadLibraryA` and `GetProcAddress`, then parses a custom packed PE format with its own header structure, section table, and encrypted import descriptors.

For full execution flow details, see the [execution walkthrough](execution_walkthrough.md).

## The Packer: A Custom PE Format

ScatterBrain doesn't use standard PE packing. Instead, it defines a custom 0x38-byte header followed by a section table:

| Offset | Field | Purpose |
|--------|-------|---------|
| 0x00 | magic0 | Validation |
| 0x04 | magic1 | Validation |
| 0x08 | size_of_image | Virtual image size |
| 0x18 | reloc_rva | Relocation table RVA |
| 0x20 | import_rva | Import table RVA |
| 0x28 | ep_rva | Entry point RVA |
| 0x2C | pe_magic | 0x20B for PE32+ |
| 0x30 | num_secs | Section count |
| 0x34 | timestamp | Compile timestamp |

Import names are encrypted with a rolling XOR cipher that decrypts each character using the previous ciphertext byte as part of the key. We reverse-engineered this cipher and built [`sb_ciphers.py`](../scripts/sb_ciphers.py) to decrypt imports statically, which enabled us to reconstruct valid PE DLLs from the packed format before even loading them into IDA.

Full packer format reference: [packed_pe_analysis.md](packed_pe_analysis.md).

## Three Cipher Systems

The malware uses three distinct cipher systems, each for a different purpose:

### 1. IMUL Cipher (blob encryption)

Used to encrypt the 8 plugin blobs inside the inner PE's data section. A 32-bit key drives a multiplicative PRNG:

```c
key = key * 0x22A43 + 1;
plaintext[i] ^= (key >> 16) & 0xFF;
```

Simple but effective for bulk data. We implemented decryption in `sb_ciphers.py:imul_cipher()`.

### 2. Polynomial XOR Cipher (string encryption)

Used for all 183+ encrypted strings across the 9 modules. Each encrypted blob starts with a 2-byte length and 2-byte key seed. The cipher generates a per-byte XOR key using polynomial arithmetic:

```c
// Simplified -- actual implementation involves IMUL with magic constants
state = key_seed;
for each byte:
    state = polynomial_transform(state);
    plaintext[i] ^= (state >> 8) & 0xFF;
```

Every API name, DLL name, registry path, and C2 URL is encrypted this way. We built [`decrypt_strings.py`](../scripts/decrypt_strings.py) with a `--scan` mode that finds and decrypts all encrypted string blobs in any PE.

### 3. Rolling XOR Cipher (import name encryption)

Used only by the reflective loader for import descriptor names in the packed PE format. Each byte is decrypted using the previous ciphertext byte:

```c
prev = key_byte;
for each byte:
    plaintext[i] = ciphertext[i] ^ prev;
    prev = ciphertext[i];
```

This cipher is implemented in `sb_ciphers.py:import_xor_decrypt_name()`.

For the full cipher analysis journey, see the [encrypted strings report](encrypted_strings_report.md).

## The Plugin Framework

The inner PE orchestrator manages plugins through a linked list. During initialization, its worker thread iterates over 8 encrypted data blobs, and for each:

1. Decrypts with the IMUL cipher
2. Validates magic `0x650001`
3. Decompresses with LZ77
4. Copies the reflective loader to fresh RWX memory
5. Calls the loader to map the plugin DLL
6. Sends `CMD 100` (store parent context pointer)
7. Sends `CMD 1` (populate vtable)
8. Sends `CMD 104` (retrieve vtable pointer)
9. Inserts into the plugin linked list

Every plugin follows the same `DllMain_dispatcher` protocol, using `fdwReason` as a command ID rather than the standard DLL attach/detach semantics.

### The Command Protocol

For the canonical plugin anatomy and lifecycle reference, see [how_plugins_work.md](how_plugins_work.md).

Win32 defines `fdwReason` values 0-3 for DLL load/unload events. ScatterBrain repurposes this parameter as a general-purpose command ID, with `lpReserved` serving as a polymorphic payload pointer whose meaning depends on the command:

| Command | Name | Direction | `lpReserved` semantics |
|---------|------|-----------|----------------------|
| 0 | Cleanup | Framework → Plugin | Context pointer (teardown) |
| 1 | Init vtable | Framework → Plugin | Context pointer (populate vtable globals) |
| 100 | Set framework ctx | Framework → Plugin | Framework vtable pointer (plugin caches it) |
| 102 | Get version | Framework → Plugin | `*(DWORD*)lpReserved` = version integer |
| 103 | Get name | Framework → Plugin | `lstrcpyW(lpReserved, name)` — copy plugin name string |
| 104 | Get vtable ptr | Framework → Plugin | `*(QWORD*)lpReserved` = &plugin_vtable |

The handshake follows a strict ordering. **CMD 100 must come first** — it delivers the framework vtable pointer that the plugin caches in a global. Without it, the plugin has no way to call framework services. **CMD 1 comes second** — the plugin populates its own vtable, potentially using framework services (API resolution, memory allocation) that it just received. **CMD 104 comes last** — the framework retrieves the plugin's vtable pointer and inserts the plugin into its linked list. Only after this sequence is the plugin fully registered and callable.

The inner PE itself follows the same protocol — from the outer loader's perspective, it *is* a plugin. This uniformity means the framework can load the inner PE and any of the 8 plugins through identical code paths.

### The Framework Vtable: 26 Shared Services

When a plugin receives CMD 100, it stores the framework vtable pointer in a global and uses it for all subsequent framework calls. This is dependency injection — no plugin links against the framework statically, and no plugin needs to know how the framework implements any service. The vtable at `0x18001C1B0` exposes 29 QWORD slots (27 function pointers + 2 data pointers), grouped by capability:

**Memory management:**
- `vtfn_alloc` (+0xA0) — `LocalAlloc(LPTR, size)`, the framework's heap allocator
- `vtfn_free` (+0xC0) — `LocalFree` with null check

**Inbound crypto (C2 → plugin):**
- `vtfn_decrypt_packet_header` (+0xB8) — IMUL cipher on 20-byte packet header, `ntohl` byte-order conversion
- `vtfn_decrypt_decompress` (+0xB0) — IMUL cipher decrypt followed by LZ77 decompression

**Outbound crypto (plugin → C2):**
- `vtfn_compress_encrypt` (+0xA8) — LZ77 compression followed by IMUL cipher encrypt
- `vtfn_generate_packet_key` (+0xC8) — key derivation from counter + `QueryPerformanceCounter` + `GetSystemTime`

**Blob loading:**
- `vtfn_decrypt_and_load_blob` (+0x70) — IMUL decrypt, validate magic `0x650001`, LZ77 decompress
- `vtfn_exec_reflective_loader` (+0x78) — copy 2014-byte reflective loader to RWX, call with decompressed PE

**Process injection:**
- `vtfn_multi_resolve` (+0x88) — the largest function at 1413 bytes, two injection modes: `CreateRemoteThread` (6 APIs) and thread hijack with a 26-byte x64 stub (`mov rcx,param; push rcx; mov rax,loader; call rax; pop rcx; ret`)
- `vtfn_thunk_multi_resolve` (+0x80) — 8-byte thunk to the above

**API resolution:**
- `resolve_api` (+0x60) — hash-based PEB walk + `LoadLibraryA`/`GetProcAddress` with encrypted DLL names

**Plugin management:**
- `vtfn_plugin_loader` (+0x08) — 723-byte function handling PE detection (`GetModuleFileNameA`), blob magic validation (`DWORD[0] ^ DWORD[1] == 0x7C35D9A3`), command protocol dispatch, and linked-list insertion
- `vtfn_register_blob` (+0x68) — blob registration wrapper

**Object system:**
- Slots +0x10 through +0x58 — thread-safe factories using `EnterCriticalSection`/`LeaveCriticalSection`, producing 64-byte objects with flink/blink linked-list pointers and reference counting

**Shellcode execution:**
- `vtfn_shellcode_trampoline` (+0x98) — `VirtualAlloc(RWX)`, copy shellcode, call, `VirtualFree`
- Thunk at +0x90

**Utility:**
- `vtfn_extract_filename` (+0x30) — extract filename from full path via `lstrcpyW`
- `vtfn_base62_encode` (+0xD0) — base62 encoding for URL-safe identifiers

**Data pointers (not function pointers):**
- `payload_ptr` (+0xD8) — context from outer loader
- `rdata_config` (+0xE0) — pointer to encrypted configuration data at `0x1800068E0`

blob_2 (Config) proves this abstraction is sufficient for complete plugin operation: it has **zero PE imports** and performs all file I/O, memory allocation, and API resolution entirely through the framework vtable.

### The Call Hierarchy: DllMain to Plugin Loading

Tracing the full call chain from the inner PE's entry point to actual plugin loading reveals two distinct paths -- one for startup, one for runtime:

```
DllMain_dispatcher (0x180004344)
  fdwReason == 1 (DLL_PROCESS_ATTACH)
  └─► cmd1_attach_handler (0x180004054)
        ├── init_payload_context()      — extract context from outer loader
        ├── populate 26-slot vtable     — store function pointers at 0x18001C1B0
        ├── init_object()               — allocate 64-byte synced list
        └── CreateThread() ─────────────────────────────────────────────┐
                                                                       │
        worker_thread_entry (0x180003E34)  ◄────────────────────────────┘
          ├── vtfn_register_blob(blob_rva_0, blob_size_0)   — 0x180009100
          ├── vtfn_register_blob(blob_rva_1, blob_size_1)   — 0x18000D370
          ├── vtfn_register_blob(blob_rva_2, blob_size_2)   — 0x18000B3B0
          ├── vtfn_register_blob(blob_rva_3, blob_size_3)   — 0x1800070E0
          ├── vtfn_register_blob(blob_rva_4, blob_size_4)   — 0x1800113D0
          ├── vtfn_register_blob(blob_rva_5, blob_size_5)   — 0x180012840
          ├── vtfn_register_blob(blob_rva_6, blob_size_6)   — 0x180014F60
          └── vtfn_register_blob(blob_rva_7, blob_size_7)   — 0x180017E60
                │
                └─► vtfn_decrypt_and_load_blob (0x180002B37)
                      ├── IMUL cipher decrypt (key from blob envelope)
                      ├── validate magic 0x650001
                      ├── LZ77 decompress
                      └─► vtfn_exec_reflective_loader
                            ├── VirtualAlloc(RWX) for loader copy
                            ├── call loader with decompressed PE
                            └── DllMain_dispatcher of loaded plugin:
                                  CMD 100: store parent context pointer
                                  CMD 1:   populate plugin vtable
                                  CMD 104: retrieve vtable pointer
                                  → insert into plugin linked list
```

At startup, the worker thread hardcodes all 8 blob addresses from `.rdata` and loads them sequentially. But `vtfn_decrypt_and_load_blob` also lives in the vtable at slot 0x70 (offset `+0x70`), meaning the orchestrator -- or any plugin with access to the framework vtable -- can load additional blobs at runtime through the same path. This dual-path design (direct startup loading + vtable-indirect runtime loading) is what makes ScatterBrain a genuinely modular framework rather than a monolithic implant.

## The Eight Plugins

All plugins compiled in a narrow window around 2017-02-22/23. Together they form a complete remote access toolkit:

### Three Vtable Types

Each plugin exposes its own vtable to the framework — but the vtable layout depends on the plugin's role. There are three distinct types:

**Transport vtable (6 slots)** — shared by TCP, HTTP, UDP, and DNS:

```c
typedef struct sb_transport_vtable_t {
  sb_func_ptr_t dispatch_handler; /* +0x00: Command dispatch (cmd1) */
  sb_func_ptr_t main_loop;        /* +0x08: Main polling loop */
  sb_func_ptr_t open_channel;     /* +0x10: Open communication channel */
  sb_func_ptr_t close_channel;    /* +0x18: Close channel + cleanup */
  sb_func_ptr_t read_channel;     /* +0x20: Read data from channel */
  sb_func_ptr_t write_channel;    /* +0x28: Write data to channel */
} sb_transport_vtable_t;
```

This uniform interface is what makes transports interchangeable. The Online router calls `open_channel`, `read_channel`, `write_channel`, and `close_channel` identically regardless of whether the underlying protocol is raw TCP, HTTP POST, custom RUDP, or DNS tunneling. Adding a new transport (ICMP, WebSocket, named pipes) would require implementing these 6 functions and nothing else — zero changes to the router or any other plugin.

**Online vtable (14 slots)** — blob_3 only. Extends the base transport interface with streaming (`stream_read_loop`, `stream_write`), bidirectional piping (`bidirectional_pipe` — spawns two relay threads), command processing (`process_command`), and channel lifecycle management (`channel_cancel`, `check_and_release`, `get_channel_type`). This is the C2 routing layer that sits between the framework and the transport plugins.

**Simple vtables** — Install (2 slots), Plugins (5 slots), Config (3 slots). These utility plugins don't participate in the transport abstraction. Install exposes just a dispatch handler and an anti-analysis trigger. Plugins exposes registry CRUD operations. Config exposes configuration read/write/update.

### blob_0: Install (50 functions)

**Role**: Token theft process launcher with comprehensive anti-analysis suite.

Targets `winlogon.exe` to steal SYSTEM-level tokens via `OpenProcessToken` + `DuplicateTokenEx`, then creates suspended processes under the stolen identity with `CreateProcessAsUserW`. After launch, calls back to the orchestrator's process injection vtable slot.

Devotes 9 of 50 functions (18%) to anti-analysis:
- **Code integrity**: Rolling checksum of .text section; infinite loop on mismatch
- **Export tampering**: Checks if `CreateFileW` starts with `0xCC` (INT3 breakpoint)
- **Debugger detection**: Dual `IsDebuggerPresent` (kernelbase + kernel32) + timing check (1000ms threshold)
- **Tool detection**: Opens `\\.\Regmon`, `\\.\FileMon`, `\\.\ProcmonDebugLogger`, `\\.\NTICE`
- **Window scanning**: EnumWindows for OllyDbg (4 class names) + WinDbg
- **Wireshark kill**: Detects via named mutex `{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}`, terminates process

All detections terminate via `ExitProcess(0)` -- a burn-the-evidence approach.

[Full analysis](blob_0_install_analysis.md)

### blob_1: Plugins (34 functions)

**Role**: Registry persistence manager under `SOFTWARE\Microsoft\{id}`.

Provides CRUD operations on registry values: create keys, set values, query, enumerate, and delete. Uses `RegNotifyChangeKeyValue` to watch for external modifications. Self-protects with `SetUnhandledExceptionFilter` to catch crashes and `TerminateThread` to kill itself cleanly.

[Full analysis](blob_1_plugins_analysis.md)

### blob_2: Config (27 functions)

**Role**: Configuration management with file I/O and zero static imports.

The only plugin with no import table at all -- every API is resolved dynamically via the parent orchestrator's context pointer and encrypted string lookups. Manages a 2,136-byte configuration blob containing:
- C2 URLs for all 5 transport protocols (TCP, HTTP, HTTPS, UDP, DNS)
- Proxy server addresses (4 slots)
- Installation path (`%ALLUSERSPROFILE%\...`)
- Crypto keys (`"12345678"`, `"hello"`)

Provides file read/write/delete and directory creation for persisting config to disk.

[Full analysis](blob_2_config_analysis.md)

### blob_3: Online (55 functions)

**Role**: System fingerprinting engine and C2 connection router. The largest and most complex plugin.

Collects 31 data points for system reconnaissance:
- CPU (MHz from registry), memory (GlobalMemoryStatusEx), disk (GetDiskFreeSpaceExA)
- Display (EnumDisplaySettingsW), network adapters, OS version (GetVersionExW)
- User/computer name, locale, current PID, module path
- Kernel32.dll file version (via VERSION.dll)

Routes C2 connections across 6 protocol types (TCP, HTTP, HTTPS, UDP, DNS, URL/FTP), implements a Domain Generation Algorithm (DGA) for beacon URLs, and supports SOCKS4/5 + HTTP CONNECT proxy configurations.

[Full analysis](blob_3_online_analysis.md)

### blob_4: TCP (23 functions)

**Role**: Raw TCP socket transport with proxy support and custom DNS resolution.

Implements 4 connection modes:
1. **Direct TCP** with custom DNS resolution via `dnsapi.dll!DnsQuery_A`
2. **SOCKS4 proxy** tunneling
3. **SOCKS5 proxy** with authentication
4. **HTTP CONNECT** proxy tunneling

Parses `HTTP/1.0 200` and `HTTP/1.1 200` response headers for the HTTP CONNECT handshake.

[Full analysis](blob_4_tcp_analysis.md)

### blob_5: HTTP (42 functions)

**Role**: HTTP POST transport using WinInet with user-agent spoofing and certificate bypass.

Uses `urlmon.dll!ObtainUserAgentString` to harvest the system's real browser user-agent string, making HTTP traffic blend with legitimate browsing. Communicates via HTTP POST requests with `Content-Length` headers. Supports multiple concurrent connections with a transport manager that polls connections in a background thread.

Bypasses certificate validation for HTTPS connections via `InternetSetOptionW`.

[Full analysis](blob_5_http_analysis.md)

### blob_6: UDP (55 functions)

**Role**: Custom Reliable UDP (RUDP) transport -- the most sophisticated transport plugin.

Implements a full reliable transport protocol on top of raw UDP sockets:
- **AIMD congestion control**: Additive increase / multiplicative decrease of the send window
- **Selective acknowledgment (SACK)**: Bitmap-encoded SACK for out-of-order packet recovery
- **Sequence numbering**: Full send/receive sequence tracking with segment ring buffers
- **Per-packet encryption**: PRNG-based XOR encryption where the key state evolves per packet
- **Connection handshake**: SYN/SYN-ACK/ACK three-way handshake, FIN for teardown
- **Keepalive and retransmission**: Timer-driven keepalive probes and retransmit logic

Also supports DNS-based address resolution via `dnsapi.dll` and performance counter-based timing via `QueryPerformanceCounter`/`QueryPerformanceFrequency`.

[Full analysis](blob_6_udp_analysis.md)

### blob_7: DNS (51 functions)

**Role**: DNS tunnel transport for covert C2 communication.

Encodes outbound data as hex-encoded subdomain labels in DNS queries (e.g., `414243.beacon.example.com` for payload `ABC`). Receives responses via DNS TXT records. Uses `GetAdaptersAddresses` from `iphlpapi.dll` to enumerate network adapters for interface selection.

Shares the same transport manager framework, segment ring buffers, and sequence tracking as the UDP plugin, adapted for the constraints of DNS tunneling (small payload per query, high latency).

[Full analysis](blob_7_dns_analysis.md)

## The C2 Data Path

With the plugin architecture, vtable system, and command protocol established, we can trace exactly how data flows between the C2 server and the malware at runtime.

### Inbound: C2 Server to Plugin

```
C2 Server
  │
  ▼
Transport plugin: read_channel()          ◄── raw bytes from wire
  │                                            (TCP recv / HTTP response body /
  │                                             UDP recvfrom / DNS TXT record)
  ▼
Online: process_command()                 ◄── route to framework crypto
  │
  ├─► Framework: decrypt_packet_header()  ◄── IMUL cipher on 20-byte header
  │     ntohl(magic, seq, payload_size,        extract key + sizes
  │           checksum, flags)
  │
  ├─► Framework: decrypt_decompress()     ◄── IMUL cipher decrypt payload
  │     LZ77 decompress                        using key from header
  │
  ▼
Online: cmd1_dispatch_handler()           ◄── route by command ID
  │                                            (0x680002=C2 thread,
  │                                             0x680003=recon, ...)
  ▼
Target plugin executes command
```

### Outbound: Plugin to C2 Server

```
Plugin generates response data
  │
  ▼
Framework: generate_packet_key()          ◄── counter + QueryPerformanceCounter
  │                                            + GetSystemTime → 32-bit key
  ▼
Framework: compress_encrypt()             ◄── LZ77 compress
  │                                            IMUL cipher encrypt
  ▼
Build 20-byte header                      ◄── htonl(key, seq, comp_size,
  │                                                  checksum, flags)
  ▼
Transport plugin: write_channel()         ◄── raw bytes to wire
  │
  ▼
C2 Server
```

### The Channel Abstraction

The `sb_channel_t` structure is the bridge between Online (the router) and the transport plugins:

```c
struct sb_channel_t {
  void *transport_ctx;           /* +0x00: Opaque per-transport context */
  sb_func_ptr_t *transport_vtbl; /* +0x08: 6-slot transport vtable pointer */
  __int64 channel_data;          /* +0x10: Channel-specific data */
  WORD protocol_id;              /* +0x18: Protocol ID (200=TCP, 201=HTTP, 202=UDP, 203=DNS) */
};
```

Online reads `protocol_id` to select which transport to use, then calls through `transport_vtbl` — the transport never sees decrypted payload content (crypto happens in the framework layer), and Online never sees wire protocol details (socket/HTTP/DNS operations happen inside the transport). The `transport_ctx` is opaque and varies dramatically by protocol: 112 bytes for TCP (socket + proxy state), 4448 bytes for HTTP (WinInet handles + URL buffers), 480 bytes for UDP and DNS (segment ring buffers + sequence state).

### Packet Header

Every C2 message, regardless of transport, begins with the same 20-byte encrypted header:

```c
typedef struct sb_packet_hdr_t {
  DWORD magic;        /* Session ID / magic value */
  DWORD sequence;     /* Monotonic sequence number */
  DWORD payload_size; /* Size of following encrypted payload */
  DWORD checksum;     /* Payload integrity check */
  DWORD flags;        /* Packet type flags */
} sb_packet_hdr_t;    /* All fields in network byte order (big-endian) */
```

The header is encrypted separately from the payload — `decrypt_packet_header` at vtable +0xB8 decrypts just these 20 bytes with the IMUL cipher, then `ntohl` converts each field before the framework processes the payload. This two-stage decryption means the framework can validate the header (check magic, verify sizes) before committing to the more expensive payload decryption and decompression.

## Design Philosophy

Reverse engineering ScatterBrain reveals deliberate architectural choices that go well beyond "make it work." The framework was designed by someone thinking about operational lifecycle, not just initial deployment.

**Modularity as operational security.** Each plugin is independently replaceable. If a transport gets detected and burned, the operator swaps only that DLL — the other 7 plugins remain untouched. All four transport plugins share the same 6-slot `sb_transport_vtable_t` interface, so a new protocol (ICMP, WebSocket, named pipes) requires implementing 6 functions and nothing else. Zero changes to the router, the framework, or any other plugin.

**Dependency injection over static linking.** No plugin imports functions from any other plugin. All inter-module communication flows through the framework vtable delivered via CMD 100. There are no load-order dependencies — any plugin can be loaded or unloaded independently. blob_2 (Config) demonstrates the extreme case: it has literally zero PE imports and performs every operation — file I/O, memory allocation, string decryption, API resolution — entirely through the framework vtable.

**Configuration externalized from code.** blob_2 manages a 2136-byte configuration blob containing C2 URLs for all 5 protocol types, 4 proxy server slots, installation paths, and crypto keys. This blob is updatable remotely via C2 commands without reloading any plugin — the operator can redirect all communications to new infrastructure by pushing a config update.

**Runtime extensibility.** `vtfn_decrypt_and_load_blob` at vtable slot +0x70 means any plugin with access to the framework pointer can load new plugins at runtime. blob_1 (Plugins) provides registry persistence for storing C2-delivered blobs across reboots under `SOFTWARE\Microsoft\{id}`. Together, these two capabilities turn ScatterBrain from a static implant into a delivery platform — the initial 8 plugins are a starting kit, not the final payload.

**Transport diversity for network resilience.** Four protocols serve four operational scenarios: TCP for raw throughput in permissive networks, HTTP for blending with legitimate web traffic, UDP for avoiding TCP state-tracking in firewalls and IDS, DNS for the most restricted environments where only DNS resolution is allowed. The Online router can try them in sequence or switch as directed by the C2 server, with proxy support (SOCKS4, SOCKS5, HTTP CONNECT) adding another layer of flexibility.

## SQL-Powered Reverse Engineering with idasql

A significant enabler of this analysis was [**idasql**](https://github.com/xsql-io/idasql), which exposes IDA Pro's analysis database as SQL virtual tables. Instead of writing IDAPython scripts or clicking through the IDA GUI, every query, annotation, and batch rename was done through SQL -- either interactively or via automation scripts.

### Why SQL for RE?

Traditional IDA workflows involve a lot of manual clicking: rename a variable, retype a parameter, add a comment, scroll to the next function, repeat. With idasql, these become bulk operations:

```sql
-- Find all functions that call GetProcAddress
SELECT func_at(from_ea) as caller, count(*) as call_count
FROM xrefs
WHERE to_ea = (SELECT address FROM names WHERE name = 'GetProcAddress')
  AND is_code = 1
GROUP BY caller
ORDER BY call_count DESC;

-- Rename a global variable
SELECT set_name(0x180004058, 'g_pfnMemset');

-- Rename a local variable in decompiled code
SELECT rename_lvar(0x180001280, 2, 'target_pid');

-- Decompile and see the result immediately
SELECT decompile(0x180001280, 1);
```

### Batch Annotation Recovery

For large-scale annotation cleanup, we wrote [`recover_source.py`](../scripts/recover_source.py) -- a Python script that automates the annotation pipeline via idasql's HTTP API:

1. **Launch idasql** as an HTTP server on each plugin's `.i64` database
2. **Discover unnamed globals** by scanning all decompiled code for `qword_*`, `byte_*`, `dword_*` patterns
3. **Rename globals** using the encrypted strings database (mapping addresses to decrypted values) and cross-reference analysis (identifying cached API pointers by their assignment context)
4. **Rename locals** heuristically: API call return values get named after the API (`GetLastError` -> `last_error`), arguments get named by function semantics, type-based inference for the rest
5. **Force re-decompile** all functions to pick up the new names
6. **Strip IDA artifacts** (`/* addr */` prefixes, `[lv:N]` hints) and export cleaned analysis artifacts
7. **Post-process** any remaining auto-generated names via text substitution
8. **Save the IDB** and shut down

The script processed all 8 plugins (337 functions) with **zero remaining generic names** in the output: no `qword_*`, no `byte_*`, no `v1`/`v2`, no `a1`/`a2`.

### Concurrent Analysis Across 9 IDA Databases

One practical advantage of idasql's HTTP server mode: we could have multiple IDA databases open simultaneously on different ports, querying them in parallel. During the blob analysis phase, we frequently had 3+ idasql instances running:

```bash
# Terminal 1: Inner PE orchestrator
idasql -s inner_pe.dll.pe.i64 --http 8144

# Terminal 2-9: Plugin blobs
idasql -s blob_0_Install.dll.pe.i64 --http 8200
idasql -s blob_1_Plugins.dll.pe.i64 --http 8201
# ... through port 8207
```

The full malware-derived IDA databases used for this workflow are maintained in a private archive and are not shipped in this public repository.

This enabled rapid cross-referencing: "the orchestrator calls vtable slot 3 with argument X -- what does plugin blob_3 do with that argument?" was answerable in seconds by querying both databases.

## The Full Pipeline

The complete analysis pipeline, from raw obfuscated binary to structured, annotated outputs, involved 6 automated stages:

```
Stage 1: sb_extract.py
  Parse host PE -> locate packed blob -> extract

Stage 2: sb_reconstruct_pe.py
  Parse packed header -> map sections -> decrypt imports -> build valid PE

Stage 3: decrypt_blobs.py
  IMUL cipher decrypt -> LZ77 decompress -> extract 8 plugin payloads

Stage 4: reconstruct_blob_pes.py
  Parse each plugin's packed PE -> reconstruct as valid DLL

Stage 5: decrypt_strings.py --scan
  Find + decrypt all 183 encrypted strings across all plugins

Stage 6: recover_source.py
  idasql annotation -> decompile -> strip artifacts -> cleaned analysis output
```

Each stage builds on the previous one's output. The scripts are designed to be re-runnable and composable. See the [scripts README](../scripts/README.md) for the full pipeline diagram.

## Architecture Summary

```
┌─────────────────────────────────────────────────────────────────┐
│  TRANSPORT LAYER                                                │
│                                                                 │
│  ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐           │
│  │  TCP     │  │  HTTP   │  │  UDP    │  │  DNS    │           │
│  │  23 func │  │  42 func│  │  55 func│  │  51 func│           │
│  │  v200    │  │  v201   │  │  v202   │  │  v203   │           │
│  └────┬─────┘  └────┬────┘  └────┬────┘  └────┬────┘           │
│       └──────────────┴───────────┴─────────────┘                │
│                      │  sb_transport_vtable_t (6 slots)         │
│                      │  open / close / read / write             │
├──────────────────────┼──────────────────────────────────────────┤
│  ROUTING LAYER       ▼                                          │
│                                                                 │
│  ┌──────────────────────────────────────────────┐               │
│  │  Online (blob_3) — 55 functions, 14-slot vtable              │
│  │  Protocol selection via sb_channel_t.protocol_id             │
│  │  System recon (31 data points) + DGA + proxy routing         │
│  └──────────────────────────┬───────────────────┘               │
│                             │                                   │
├─────────────────────────────┼───────────────────────────────────┤
│  FRAMEWORK CORE             ▼                                   │
│                                                                 │
│  ┌──────────────────────────────────────────────┐               │
│  │  Inner PE — 75 functions, 29-QWORD vtable                    │
│  │                                                              │
│  │  Crypto:      encrypt / decrypt / packet header / key gen    │
│  │  Blob loading: IMUL decrypt → LZ77 → reflective loader      │
│  │  Injection:   CreateRemoteThread + thread hijack (26B stub)  │
│  │  Objects:     thread-safe factories (CriticalSection)        │
│  │  Memory:      LocalAlloc / LocalFree wrappers                │
│  │  API:         PEB hash walk + encrypted name resolution      │
│  └──────────────────────────┬───────────────────┘               │
│                             │  CMD 100/1/104 protocol           │
├─────────────────────────────┼───────────────────────────────────┤
│  UTILITY PLUGINS            ▼                                   │
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐          │
│  │  Install     │  │  Plugins     │  │  Config      │          │
│  │  50 func     │  │  34 func     │  │  27 func     │          │
│  │  2-slot vtbl │  │  5-slot vtbl │  │  3-slot vtbl │          │
│  │  Token theft │  │  Registry    │  │  2136B blob  │          │
│  │  Anti-debug  │  │  persistence │  │  Zero imports│          │
│  └──────────────┘  └──────────────┘  └──────────────┘          │
└─────────────────────────────────────────────────────────────────┘
```

Data flows top-down (C2 → transport → Online → framework crypto → command dispatch) and bottom-up (plugin response → framework crypto → transport → C2). The framework core is the only layer that touches cryptography — transports handle raw bytes, and plugins handle plaintext. This separation means a compromise of any single transport's protocol logic reveals nothing about the crypto system, and a compromise of the crypto system reveals nothing about wire protocols.

## Indicators and Detection

### Encrypted String Artifacts

The polynomial XOR cipher leaves a distinctive structure: every encrypted string starts with a 2-byte little-endian length followed by a 2-byte key seed. A YARA rule targeting this pattern across `.rdata` sections would catch ScatterBrain-packed binaries.

### Anti-Analysis Signatures

blob_0's anti-analysis checks target specific tool artifacts:
- Device paths: `\\.\Regmon`, `\\.\FileMon`, `\\.\ProcmonDebugLogger`, `\\.\NTICE`
- Window classes: `ACPUASM`, `AOPOASM`, `AOPUASM`, `ACPOASM` (OllyDbg), `WinDbgFrameClass`
- Named mutex: `Wireshark-is-running-{9CA78EEA-EA4D-4490-9240-FC01FCEF464B}`

### Network Indicators

The default configuration (from blob_2) contains test C2 addresses:
- `TCP://127.0.0.1:44444`
- `HTTP://127.0.0.1:44444`
- `HTTPS://127.0.0.1:44444`
- `UDP://127.0.0.1:44444`
- `DNS://127.0.0.1:44444`

These are builder defaults -- operational samples would have real C2 infrastructure.

## Files and Resources

### Snippets

| File | Description |
|------|-------------|
| [`0000000180021137_reflective_loader.c`](../snips/0000000180021137_reflective_loader.c) | Reflective loader decompilation snippet |
| [`sb_types.h`](../snips/sb_types.h) | Shared type and structure declarations |

### Analysis Documentation

| Document | Description |
|----------|-------------|
| [Execution Walkthrough](execution_walkthrough.md) | Full execution chain from DllMain to C2 runtime |
| [Packed PE Analysis](packed_pe_analysis.md) | Custom packer format: header, sections, imports, cipher |
| [Inner PE Analysis](inner_pe_analysis.md) | Orchestrator: vtable, worker thread, plugin loading |
| [Plugin Anatomy](how_plugins_work.md) | Canonical plugin lifecycle and command protocol reference |
| [Static Analysis Summary](static_analysis_summary.md) | Architecture overview: ciphers, injection, data structures |
| [Encrypted Strings Report](encrypted_strings_report.md) | Cipher reverse engineering and 183 decrypted strings |
| [Plugin Blob Index](blob_index.md) | All 8 plugins: imports, strings, architecture diagram |
| Per-blob analysis | [blob_0_install](blob_0_install_analysis.md) [blob_1_plugins](blob_1_plugins_analysis.md) [blob_2_config](blob_2_config_analysis.md) [blob_3_online](blob_3_online_analysis.md) [blob_4_tcp](blob_4_tcp_analysis.md) [blob_5_http](blob_5_http_analysis.md) [blob_6_udp](blob_6_udp_analysis.md) [blob_7_dns](blob_7_dns_analysis.md) |

### Automation Scripts

| Script | Purpose |
|--------|---------|
| [`sb_ciphers.py`](../scripts/sb_ciphers.py) | Shared cipher library (IMUL, polynomial XOR, rolling XOR) |
| [`sb_packed_pe.py`](../scripts/sb_packed_pe.py) | Packed PE parser (header, sections, imports) |
| [`sb_extract.py`](../scripts/sb_extract.py) | Stage 1: Extract packed blob from host PE |
| [`sb_reconstruct_pe.py`](../scripts/sb_reconstruct_pe.py) | Stage 2: Reconstruct inner PE from packed blob |
| [`decrypt_blobs.py`](../scripts/decrypt_blobs.py) | Stage 3: IMUL decrypt + LZ77 decompress plugins |
| [`reconstruct_blob_pes.py`](../scripts/reconstruct_blob_pes.py) | Stage 4: Reconstruct plugin PE DLLs |
| [`decrypt_strings.py`](../scripts/decrypt_strings.py) | Stage 5: Decrypt all encrypted strings |
| [`recover_source.py`](../scripts/recover_source.py) | Stage 6: idasql annotation and artifact cleanup |
| [`deobf_sweep.py`](../scripts/deobf_sweep.py) | Opaque predicate neutralization |
| [`hash_resolve.py`](../scripts/hash_resolve.py) | API hash brute-force resolution |

## Conclusion

ScatterBrain is a well-engineered modular framework. The plugin architecture is clean -- each module follows the same command protocol, uses the same cipher for string encryption, and communicates through a shared vtable interface. The five transport plugins (TCP, HTTP, UDP, DNS, plus the Online router) provide redundant C2 channels with proxy support, user-agent spoofing, certificate bypass, DNS tunneling, and a custom reliable UDP protocol with congestion control.

The depth of the engineering is visible at every layer: a 6-command handshake protocol with strict ordering guarantees, a 29-QWORD framework vtable that provides complete runtime services (to the point where a plugin can operate with zero PE imports), a uniform 6-slot transport interface that makes protocols interchangeable, and a two-stage encrypted data path where crypto never leaks into transport code. These aren't ad-hoc decisions — they reflect a developer who understood interface segregation, dependency injection, and separation of concerns, and applied them systematically to build a framework designed for long-term operational use.

The analysis demonstrates that SQL-powered binary analysis tooling can significantly accelerate reverse engineering workflows. The ability to query, annotate, and batch-rename across multiple IDA databases simultaneously -- treating the disassembler as a database rather than a GUI application -- enabled us to process 337 functions across 8 plugins with full variable naming and type annotation.

---

*Sample SHA-256: `60678e352f3c849e36413f5de51b5eeca1180840c818f9ece0a0da803eb205a5`*
*Analysis tooling: IDA Pro + [idasql](https://github.com/xsql-io/idasql), Python (capstone, lief, angr, z3)*
