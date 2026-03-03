# Decompiled Functions Index

This index is query-driven with `idasql` over IDA databases, with final cross-checking in decompiler output.

| Address | Name | File | Description |
|---------|------|------|-------------|
| `0x0000000180001000` | `spawn_reflective_loader` | — | Thread entry: VirtualAlloc(RWX, 1MB), memmove bootstrap+blob (106101 bytes), call copy. |
| `0x0000000180001050` | `DllMain` | — | DLL_PROCESS_ATTACH: CreateThread(spawn_reflective_loader), CloseHandle. |
| `0x000000018000BCAB` | `reflective_loader_A` | — | Copy of reflective_loader inside packed blob (section 1, inner PE RVA 0x6100). Identical 9-stage loader. |
| `0x0000000180021137` | `reflective_loader` | [.c](../snips/0000000180021137_reflective_loader.c) | ScatterBrain reflective PE loader. PEB walk, API hash resolution, memory mapping, relocation fixup, encrypted import resolution, obfuscated call thunks, DllMain dispatch. |

<a id="index-packed-blob"></a>
## Packed PE Blob

| Property | Value |
|----------|-------|
| Blob VA | `0x180007AAF` |
| Blob size | `0x19676` (104054 bytes) |
| Blob end | `0x180021125` (immediately before shim) |
| Image base | `0x180000000` |
| Size of image | `0x1E000` (122880 bytes) |
| Entry point RVA | `0x4344` |
| Sections | 4 (table at blob offset 0x38) |
| Import desc RVA | `0x1B090` |
| PE magic | `0x20B` (PE32+) |
| Imports | `KERNEL32.dll!GetSystemTime` (1 DLL, 1 function) |

### Execution Chain

```
DllEntryPoint → __DllMainCRTStartup → DllMain
  DllMain (DLL_PROCESS_ATTACH) → CreateThread(spawn_reflective_loader)
    spawn_reflective_loader:
      VirtualAlloc(NULL, 0x100000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
      memmove(rwx, &bootstrap, 106101)
      call rwx_copy(0)
        bootstrap (0x180007AA0): push rbp; push 0x19676; call shim
          shim (0x180021125): mov rcx,rsp; call reflective_loader
            reflective_loader (0x180021137): [9-stage loader] → inner DllMain
```

Call-pop trick: the `call` at `0x180007AAA` pushes return address `0x180007AAF` onto the stack, which IS the packed PE blob. The shim passes `rsp` as `payload_ptr`.

### Region A: reflective_loader copy in blob

Region A (`0x18000BCAB`) is at blob offset `0x41FC`, which maps to inner PE section 1 RVA `0x6100`. It's the same 9-stage reflective loader code embedded in the packed blob's data. This means the inner PE has executable code in its `.rdata`-equivalent section.

<a id="index-output-files"></a>
## Output Files

### Binaries and IDA Databases

These malware-derived binaries and IDA databases are maintained in a private archive and are not distributed in this public repository. Access may be considered on vetted request (see [ARTIFACT_ACCESS.md](../ARTIFACT_ACCESS.md)).

| File | IDA Database | Description |
|------|-------------|-------------|
| `inner_pe.dll.pe` | `inner_pe.dll.pe.i64` | Inner PE orchestrator (76 functions, 26-slot vtable) |
| `blob_0_Install.dll.pe` | `.i64` | Plugin "Install" v103 — process launcher + anti-analysis (50 funcs) |
| `blob_1_Plugins.dll.pe` | `.i64` | Plugin "Plugins" v101 — registry persistence (34 funcs) |
| `blob_2_Config.dll.pe` | `.i64` | Plugin "Config" v102 — C2 config / file ops, zero imports (27 funcs) |
| `blob_3_Online.dll.pe` | `.i64` | Plugin "Online" v104 — system recon + C2 router (55 funcs) |
| `blob_4_TCP.dll.pe` | `.i64` | Plugin "TCP" v200 — raw TCP + DNS sockets (23 funcs) |
| `blob_5_HTTP.dll.pe` | `.i64` | Plugin "HTTP" v201 — HTTP POST transport (42 funcs) |
| `blob_6_UDP.dll.pe` | `.i64` | Plugin "UDP" v202 — reliable UDP transport (55 funcs) |
| `blob_7_DNS.dll.pe` | `.i64` | Plugin "DNS" v203 — DNS tunnel transport (51 funcs) |
| `decrypted_shellcode_266.bin` | `.i64` | Decrypted 266-byte shellcode stub |

### Intermediate Data

| File | Description |
|------|-------------|
| `packed_blob.bin` | Raw blob extracted from host PE (104054 bytes) |
| `mapped_image.bin` | Reconstructed mapped image after section copy (122880 bytes) |
| `sb_extract.json` | All parsed data: header, sections, relocations, decrypted imports |
| `encrypted_strings.json` | Inner PE encrypted strings (37 entries) |
| `blob_pe_summary.json` | Complete metadata, imports, sections for all blobs |
| `blob_analysis.json` | Redacted public decryption/decompression summary (sensitive fields removed) |
| `blob_encrypted_strings.json` | Redacted public string inventory summary (counts only; plaintext removed) |

### Host DLL IDA Databases

| File | Description |
|------|-------------|
| `60678e...5a5.bin.i64` | Outer loader — main annotated database (opaque predicates, reflective loader) |
| `60678e...5a5.bin_*195307.i64` | Snapshot before Region A patching |
| `60678e...5a5.bin_*213808.i64` | Snapshot before inner PE extraction |

<a id="index-inner-functions"></a>
## Inner PE Functions (76 functions from the analyzed inner PE)

### Entry Point + Command Dispatch

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x180004344` | `DllMain_dispatcher` | 100 | Command dispatcher (0=init, 1=attach, 101=version, 102=cmd, 104=vtable ptr) |
| `0x180004054` | `cmd1_attach_handler` | 733 | Main init: populate 26-fn vtable, spawn worker thread |
| `0x180003D64` | `cmd0_init_or_cleanup` | 84 | Cleanup/init handler |
| `0x180003CD4` | `cmd102_custom_command` | 134 | Custom command handler |
| `0x180003E34` | `worker_thread_entry` | 524 | Worker: registers 8 encrypted blobs, creates handler, enters dispatch loop |
| `0x180003DC4` | `init_payload_context` | 106 | Process payload arg from outer loader |
| `0x180003C84` | `get_config_ptr` | 13 | Return encrypted config data pointer |
| `0x180003CA4` | `get_version` | 9 | Return version constant |
| `0x180003CB4` | `stub_return_zero` | 3 | Return 0 stub |
| `0x180003CC4` | `stub_return_zero_2` | 3 | Return 0 stub |

### API Resolution

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x180003328` | `resolve_api_by_hash` | 241 | PEB walk + export hash resolver (ROR-8/XOR/0x7C35D9A3) |
| `0x180001000` | `resolve_api_dll0` | 159 | kernel32.dll resolver (LoadLibraryA + GetProcAddress) |
| `0x1800010A0` | `resolve_api_dll1` | 274 | msvcrt.dll resolver (memcpy) |
| `0x180001474` | `resolve_api_dll2` | 159 | ws2_32.dll resolver (ntohl, htonl) |
| `0x180002D34` | `resolve_api_dll3` | 538 | Caller-specified DLL resolver (FindFirstFileW, FindClose, FreeLibrary) |
| `0x180001894` | `resolve_multi_apis` | 604 | Multi-API resolver for process injection (VirtualQueryEx, ReadProcessMemory) |

### Memory + String Utilities

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x180003468` | `sb_LocalAlloc` | 54 | Lazy LocalAlloc(LPTR), hash 0x95D9FE52 |
| `0x180003428` | `sb_LocalFree` | 53 | Lazy LocalFree, hash 0xF336A663 |
| `0x1800034A8` | `j_sb_LocalFree` | 5 | Jump thunk to sb_LocalFree |
| `0x1800034B8` | `j_sb_LocalFree_0` | 5 | Jump thunk to sb_LocalFree |
| `0x1800034C8` | `j_sb_LocalAlloc` | 5 | Jump thunk to sb_LocalAlloc |
| `0x1800043A8` | `sb_MultiByteToWideChar` | 233 | CP_UTF8 conversion, hash 0xB8E03AF8 |
| `0x180004498` | `sb_WideCharToMultiByte` | 188 | Wide→narrow, hash 0x98F9E06E |
| `0x1800045B8` | `decrypt_string` | 185 | Polynomial XOR decrypt, 2-byte key prefix |
| `0x180004568` | `free_string_buffers` | 59 | Free narrow+wide string buffers |
| `0x180004678` | `wstr_obj_set` | 299 | Wide string object setter |
| `0x1800047B8` | `wstr_obj_init_from` | 38 | Init wide string object from source |
| `0x1800047E8` | `wstr_obj_init` | 45 | Init wide string object |
| `0x180004838` | `vtfn_alloc` | 39 | Vtable allocator (sb_LocalAlloc wrapper) |
| `0x180004818` | `vtfn_free` | 21 | Vtable free (sb_LocalFree wrapper) |
| `0x180004FD8` | `sb_DeleteCriticalSection` | 89 | Lazy DeleteCriticalSection |
| `0x180005038` | `init_critical_section` | 92 | Lazy InitializeCriticalSection |

### LZ77 Compression Engine

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x1800035D0` | `lz_compress_block` | 699 | Core LZ77 compression with hash-table back-references |
| `0x180003BA0` | `lz_compress` | 225 | LZ77 compress wrapper |
| `0x1800039C0` | `lz_decompress` | 341 | LZ77 decompress |
| `0x180003B20` | `lz_decompress_wrapper` | 113 | LZ77 decompress wrapper |
| `0x1800038A0` | `lz_get_compressed_size` | 59 | Read compressed size from header |
| `0x1800038F0` | `lz_get_decompressed_size` | 61 | Read decompressed size from header |
| `0x180003560` | `hash12` | 13 | 12-bit hash function for LZ77 hash table |
| `0x180003940` | `hash12_ptr` | 13 | Hash12 variant taking pointer |
| `0x180003960` | `hashtable_insert` | 25 | Hash table insertion |
| `0x180003980` | `lz_update_hashtable` | 44 | Update hash table during compression |
| `0x180003580` | `nullsub_1` | 3 | Empty function (unused) |

### Linked List Operations

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x180003280` | `list_init` | 15 | Initialize doubly-linked list |
| `0x180003210` | `list_insert_front` | 28 | Insert node at front |
| `0x1800031E0` | `list_unlink_node` | 27 | Unlink node from list |
| `0x1800032A0` | `list_remove_node` | 43 | Remove and free node |
| `0x1800032E0` | `list_clear` | 43 | Clear all nodes from list |

### Vtable Functions — Plugin Management

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x180002844` | `vtfn_plugin_loader` | 723 | Plugin registration: PE detection, blob decrypt, command protocol, linked-list insert |
| `0x180002B24` | `vtfn_decrypt_and_load_blob` | 508 | IMUL decrypt + validate magic 0x650001 + LZ77 decompress |
| `0x1800020A4` | `vtfn_exec_reflective_loader` | 331 | Copy reflective loader to RWX, call with blob |
| `0x180002F54` | `vtfn_register_blob` | 49 | Blob registration wrapper |
| `0x180002F94` | `vtfn_compose_k` | 49 | Composition wrapper |
| `0x180001564` | `resolve_pe_entry_point` | 34 | Resolve PE entry point from module handle |
| `0x1800015B4` | `unload_module` | 268 | Unload PE module |
| `0x1800016D4` | `get_module_path` | 154 | Get module file path |
| `0x180001774` | `vtfn_extract_filename` | 268 | Extract filename from full path |

### Vtable Functions — Crypto + Network

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x180004968` | `vtfn_decrypt_packet_header` | 137 | IMUL cipher decrypt 20-byte packet header |
| `0x1800049F8` | `vtfn_decrypt_decompress` | 805 | IMUL cipher decrypt + LZ77 decompress inbound data |
| `0x180004D28` | `vtfn_compress_encrypt` | 687 | LZ77 compress + IMUL cipher encrypt outbound data |
| `0x1800011B4` | `vtfn_generate_packet_key` | 181 | Generate packet key (counter + QPC + GetSystemTime) |
| `0x18000126C` | `vtfn_base62_encode` | 59 | Base62 encoding utility |

### Vtable Functions — Process Injection

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x180001B04` | `vtfn_multi_resolve` | 1413 | Process injection: 2 modes (CreateRemoteThread + thread hijack) |
| `0x180002094` | `vtfn_thunk_multi_resolve` | 8 | Thunk to vtfn_multi_resolve |
| `0x180004868` | `vtfn_shellcode_trampoline` | 226 | Shellcode execution trampoline |
| `0x180004958` | `vtfn_thunk_handler_s` | 5 | Thunk to vtfn_shellcode_trampoline |

### Vtable Functions — Thread-Safe Object Factories

| Address | Name | Size | Description |
|---------|------|------|-------------|
| `0x180002264` | `vtfn_create_obj_b` | 450 | Thread-safe object creator |
| `0x180002434` | `vtfn_create_obj_c` | 448 | Thread-safe object creator (handler object, called with 103) |
| `0x180002604` | `vtfn_create_obj_d` | 561 | Thread-safe object creator (spawns thread) |
| `0x180002FD4` | `vtfn_create_obj_e` | 474 | Thread-safe object creator |
| `0x1800012A8` | `vtfn_create_obj_g` | 143 | Object creator (no args) |
| `0x180001338` | `vtfn_create_obj_h` | 143 | Object creator (no args) |
| `0x1800013C8` | `vtfn_create_obj_i` | 78 | Small allocator |
| `0x180001418` | `vtfn_create_obj_j` | 90 | Small allocator |
| `0x180002234` | `init_object` | 38 | Object initializer |
| `0x180002204` | `destroy_synced_list` | 31 | Destroy synchronized list |

<a id="index-encrypted-data-blobs"></a>
## Encrypted Data Blobs (8 C2 Plugin DLLs)

All 8 encrypted data blobs registered by `worker_thread_entry` have been decrypted (IMUL cipher + LZ77), unpacked, and reconstructed as valid PE DLLs.

| Blob | Output | Image | EP RVA | Funcs | Imports | Plugin ID | Version | Role |
|------|--------|-------|--------|-------|---------|-----------|---------|------|
| blob_0 | `blob_0_Install.dll.pe` | 0x6000 | 0x2714 | 50 | 34 (5 DLLs) | `Install` | 103 | Process launcher + anti-analysis suite |
| blob_1 | `blob_1_Plugins.dll.pe` | 0x7000 | 0x10A4 | 34 | 12 (3 DLLs) | `Plugins` | 101 | Registry persistence |
| blob_2 | `blob_2_Config.dll.pe` | 0x7000 | 0x10A4 | 27 | 0 (all dynamic) | 102 (int) | — | C2 config / file ops |
| blob_3 | `blob_3_Online.dll.pe` | 0xA000 | 0x13E0 | 55 | 31 (5 DLLs) | `Online` | 104 | System recon + C2 router |
| blob_4 | `blob_4_TCP.dll.pe` | 0x6000 | 0x123C | 23 | 21 (3 DLLs) | `TCP` | 200 | Raw TCP + DNS sockets |
| blob_5 | `blob_5_HTTP.dll.pe` | 0x7000 | 0x157C | 42 | 38 (5 DLLs) | `HTTP` | 201 | HTTP POST transport |
| blob_6 | `blob_6_UDP.dll.pe` | 0x8000 | 0x1828 | 55 | 35 (2 DLLs) | `UDP` | 202 | Reliable UDP (RUDP) transport |
| blob_7 | `blob_7_DNS.dll.pe` | 0x8000 | 0x14F0 | 51 | 36 (2 DLLs) | `DNS` | 203 | DNS tunnel transport |

All 337 functions across 8 plugins fully renamed (zero `sub_*` remaining). All blobs compiled ~2017-02-22/23 (timestamps 0x58AEBA59-0x58AEF8D6). Full import details remain in `blob_pe_summary.json`; only sensitive decryption/string datasets are redacted in this public copy.

<a id="index-documentation"></a>
## Documentation

| File | Description |
|------|-------------|
| [scatterbrain_analysis.md](scatterbrain_analysis.md) | Public-facing, self-contained technical report of the full workflow with optional deep links and evidence trail |
| [packed_pe_analysis.md](packed_pe_analysis.md) | Full packed PE blob analysis: header format, section table, blob layout, import format, rolling XOR cipher, static reconstruction |
| [execution_walkthrough.md](execution_walkthrough.md) | Full execution walkthrough: DllMain → reflective loader → inner PE → worker thread → blob decrypt → plugin load → C2 routing |
| [inner_pe_analysis.md](inner_pe_analysis.md) | Inner PE analysis: entry point, vtable, API resolution, worker thread, encrypted data |
| [how_plugins_work.md](how_plugins_work.md) | Canonical plugin anatomy: handshake, framework context, vtable families, and dispatch lifecycle |
| [scatterbrain_packer_reference.md](scatterbrain_packer_reference.md) | Packer reimplementation reference |
| [encrypted_strings_report.md](encrypted_strings_report.md) | Encrypted string analysis: cipher reverse-engineering, 37 decrypted blobs, DLL/API mapping, vtable capability classification |
| [static_analysis_summary.md](static_analysis_summary.md) | **Big picture**: Complete static analysis — architecture, 3 cipher systems, blob pipeline, process injection, plugin framework, data structures |
| [blob_index.md](blob_index.md) | Plugin blob index: all 8 plugins, architecture diagram, import breakdown, file inventory |
| [blob_0_install_analysis.md](blob_0_install_analysis.md) | blob_0 "Install" — Process launcher + anti-analysis (50 functions) |
| [blob_1_plugins_analysis.md](blob_1_plugins_analysis.md) | blob_1 "Plugins" — Registry persistence (34 functions) |
| [blob_2_config_analysis.md](blob_2_config_analysis.md) | blob_2 "Config" — C2 config / file ops, zero imports (27 functions) |
| [blob_3_online_analysis.md](blob_3_online_analysis.md) | blob_3 "Online" — System recon + C2 router, DGA (55 functions) |
| [blob_4_tcp_analysis.md](blob_4_tcp_analysis.md) | blob_4 "TCP" — Raw TCP + DNS sockets, 4 proxy modes (23 functions) |
| [blob_5_http_analysis.md](blob_5_http_analysis.md) | blob_5 "HTTP" — HTTP POST transport, UA spoofing, cert bypass (42 functions) |
| [blob_6_udp_analysis.md](blob_6_udp_analysis.md) | blob_6 "UDP" — Reliable UDP (RUDP) with AIMD congestion control (55 functions) |
| [blob_7_dns_analysis.md](blob_7_dns_analysis.md) | blob_7 "DNS" — DNS tunnel transport, hex-encoded subdomains (51 functions) |
