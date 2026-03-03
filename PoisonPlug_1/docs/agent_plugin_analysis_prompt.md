# ScatterBrain Plugin DLL Analysis — Agent Reference

You are analyzing a **ScatterBrain C2 plugin DLL** extracted from an obfuscated loader chain. This document describes the plugin architecture, known structures, available tools, and analysis approach.

## Plugin Architecture

Each plugin DLL follows the **same architecture** as the parent inner PE. The entry point is a `DllMain_dispatcher` function that uses `fdwReason` as a **command ID** (not the standard DLL_PROCESS_ATTACH/DETACH semantics).

### Command Protocol (Verified against blob_0)

| fdwReason | Command | Behavior |
|-----------|---------|----------|
| 0 | Init/Cleanup | Initialize or clean up state (often no-op, returns 0) |
| 1 | Attach | Populate vtable with function pointers, optionally spawn worker |
| 100 | Store context | Stores `lpvReserved` pointer to a global — this is the **parent context** |
| 101 | Version query | Write version number to `*(DWORD*)lpvReserved` (blob_0 returns 103) |
| 102 | Custom command | Decrypt plugin ID string, copy to output via lstrcpyW |
| 104 | Get vtable | Write `&vtable_base` pointer to `*(QWORD*)lpvReserved` |

**NOTE**: CMD 100 was not documented in the inner PE analysis but is present in plugins. The parent context pointer (stored at a global like `qword_180004018`) provides access to the orchestrator's vtable at offset +136 (0x88) and state structures at offset +216 (0xD8).

The **DllMain_dispatcher** signature is effectively:
```c
// fdwReason is a command ID, NOT a standard DLL reason code
BOOL __stdcall DllMain_dispatcher(HINSTANCE hinstDLL, DWORD cmd_id, LPVOID cmd_data);
```

### How to Find the Entry Point

The entry point RVA is in the PE optional header. Look for a function that:
1. Switches on the second argument (fdwReason/cmd_id)
2. Has cases for 0, 1, 101, 102, 104
3. The CMD 1 handler is usually the largest and most interesting

### Vtable Interface (Verified)

CMD 1 (attach) populates a **vtable** — an array of function pointers that the parent orchestrator calls. The parent uses CMD 104 to retrieve this vtable pointer.

**IMPORTANT**: Plugin vtables are much smaller than the parent's 26-function vtable. Blob_0 has only **2 vtable entries**:
- Slot 0: Sub-command dispatcher (reads command ID from argument, dispatches to handlers)
- Slot 1: Worker/init function (decrypts APIs, sets up state, spawns threads)

The vtable is stored at a global address (e.g., `qword_180004000` in blob_0). CMD 1 writes function pointers to consecutive QWORDs starting at that address. CMD 104 returns `&vtable_base`.

### Parent Context Pointer

CMD 100 stores the parent's context pointer. Plugins use it to:
- Call back to the parent's vtable (at context + 136 / 0x88) — e.g., for process injection
- Read state (at context + 216 / 0xD8) — e.g., for mode selection
- The context provides the parent orchestrator's full capability surface to each plugin

## Known Structures

### sb_plugin_entry_t (64 bytes)
How the parent registers each plugin in its doubly-linked list:

```c
struct sb_plugin_entry_t {
    QWORD flink;           // 0x00 — next entry
    QWORD blink;           // 0x08 — prev entry
    DWORD ref_count;       // 0x10 — reference counter
    DWORD pe_timestamp;    // 0x14 — PE TimeDateStamp for identification
    BYTE  plugin_id[6];    // 0x18 — plugin ID bytes (from CMD 102)
    BYTE  _pad[2];         // 0x1E
    DWORD is_detached;     // 0x20 — detached flag
    DWORD is_pe_module;    // 0x24 — 1=disk PE, 0=packed blob
    DWORD _pad2[2];        // 0x28
    QWORD module_or_blob;  // 0x30 — module HINSTANCE or blob pointer
    QWORD vtable_ptr;      // 0x38 — plugin vtable (from CMD 104)
};
```

### sb_synced_list_t (64 bytes)
Thread-safe doubly-linked list header:

```c
struct sb_synced_list_t {
    QWORD flink;           // 0x00 — first node
    QWORD blink;           // 0x08 — last node
    DWORD count;           // 0x10 — node count
    DWORD _pad;            // 0x14
    CRITICAL_SECTION cs;   // 0x18 — 40 bytes
};
```

### Packet Header (20 bytes, network byte order)
Used for encrypted blob communication between plugins and C2:

```c
struct sb_packet_header_t {
    DWORD key;             // 0x00 — encryption key (htonl)
    DWORD field4;          // 0x04 — magic/flags
    DWORD field8;          // 0x08 — flags
    DWORD compressed_size; // 0x0C — compressed payload size (htonl)
    DWORD decomp_size;     // 0x10 — decompressed payload size (htonl)
};
```

### sb_packed_pe_hdr (0x38 bytes)
ScatterBrain's custom PE header format (used to validate blobs):

| Offset | Size | Field | Notes |
|--------|------|-------|-------|
| 0x00 | 4 | magic0 | XOR pair, magic0 ^ magic1 == 0x7C35D9A3 |
| 0x04 | 4 | magic1 | XOR pair |
| 0x08 | 4 | size_of_image | Virtual memory layout size |
| 0x0C | 4 | flags | Usually 0 |
| 0x10 | 4 | unknown_10 | Always 0x80000000 |
| 0x14 | 4 | unknown_14 | Always 0x00000001 |
| 0x18 | 4 | reloc_dir_rva | Relocation directory |
| 0x1C | 4 | reloc_dir_size | Relocation directory size |
| 0x20 | 4 | import_desc_rva | Import descriptors |
| 0x24 | 4 | import_desc_size | Import descriptor size |
| 0x28 | 4 | entry_point_rva | Entry point! |
| 0x2C | 2 | pe_magic | 0x020B = PE32+ |
| 0x2E | 2 | unknown_2E | 0x2022 in all samples |
| 0x30 | 4 | num_sections | Section count |
| 0x34 | 4 | timestamp | PE TimeDateStamp |

## Three Cipher Systems

### 1. Rolling XOR (Import Name Decryption)
- Used during reflective loading to decrypt PE import names
- Key seeded from packed PE header `magic0`
- Key update: `key = (key << 24) | (int8(encrypted_byte) + (key >> 8))`
- Per byte: `decrypted = encrypted ^ (key & 0xFF)`
- Key evolves across ALL names (not reset between DLL/function names)

### 2. Rolling Polynomial XOR (Encrypted Strings) — VERIFIED in plugins
- Used by `decrypt_string` to decrypt API/DLL name strings at runtime
- **Same cipher in plugins and inner PE** (verified with blob_0)
- 2-byte little-endian key seed prefix per encrypted blob
- Per byte: `plaintext = (key & 0xFF) ^ encrypted_byte` (XOR **BEFORE** key update!)
- Key update: `key = (-42860544 * key) - (135791246 * HIWORD(key)) - 1043215206 (mod 2^32)`
- Pattern: global function pointer initially NULL, lazy-resolved on first call
- Encrypted blobs are in `.rdata` section, referenced by pointer in code
- Some API names are in **plaintext** in `.rdata` (e.g., `ImpersonateLoggedOnUser` in blob_0) — resolved via GetProcAddress directly

### 3. IMUL Stream Cipher (Large Blob Encryption)
- 4-round cipher selected by `index % 4`
- Constants: [(0xCA1A5842, 0x563446B7), (0x5F7B88D1, 0x2D93E75E), (0xAD5BC1C9, 0x7992708E), (0x3223D2C1, 0x10A75686)]
- Key update: `k[r] = const[r] - k[r] * mult[r] (mod 2^32)`
- Accumulator: `acc -= k.byte0; acc ^= k.byte1; acc -= k.byte2; acc ^= k.byte3`
- Output: `input[i] ^ acc`
- Decrypted at runtime from 266-byte encoded shellcode via `((byte+13) ^ 0xF3) - 13`

## API Resolution Patterns

Plugins resolve APIs dynamically. Look for these patterns:

### Pattern 1: Hash-Based PEB Walk
```c
// resolve_api_by_hash(hash) — walks PEB → InLoadOrderModuleList → export table
// Algorithm: ROR-8 / XOR / constant 0x7C35D9A3
g_pfnLoadLibraryA = resolve_api_by_hash(0xBDA26FE6);
g_pfnGetProcAddress = resolve_api_by_hash(0xA16DC157);
```

### Pattern 2: Encrypted String + LoadLibrary/GetProcAddress
```c
// decrypt_string decrypts encrypted blob → DLL name or function name
// Then LoadLibraryA(dll_name) + GetProcAddress(module, func_name)
decrypt_string(enc_kernel32_dll, &dll_name);
hModule = g_pfnLoadLibraryA(dll_name.narrow);
decrypt_string(enc_CreateThread, &func_name);
g_pfnCreateThread = g_pfnGetProcAddress(hModule, func_name.narrow);
```

### Pattern 3: Lazy Caching
```c
// Every resolved API is cached in a global variable
// Functions check if (g_pfn == NULL) before resolving
if (!g_pfnVirtualAlloc)
    g_pfnVirtualAlloc = resolve_via_encrypted_name(...);
return g_pfnVirtualAlloc(args);
```

<a id="analysis-workflow-with-idasql"></a>
## Analysis Workflow with idasql

### Step 1: Orient
```sql
-- Database overview
SELECT * FROM welcome;

-- List all functions
SELECT printf('0x%X', address) as addr, name, size FROM funcs ORDER BY size DESC;

-- Find entry point
SELECT printf('0x%X', address) as addr, name FROM funcs
WHERE name LIKE '%DllMain%' OR name LIKE '%entry%' OR address = (SELECT value FROM db_info WHERE key = 'entry_point');
```

### Step 2: Find DllMain_dispatcher
```sql
-- Decompile the entry point — look for fdwReason switch
SELECT decompile(0xENTRY_POINT_HERE);

-- Look for functions with many comparison branches (switch cases)
SELECT func_at(func_addr) as name, COUNT(*) as branches
FROM instructions
WHERE func_addr IN (SELECT address FROM funcs ORDER BY size DESC LIMIT 20)
AND mnemonic = 'cmp'
GROUP BY func_addr ORDER BY branches DESC;
```

### Step 3: Trace CMD 1 (attach handler)
```sql
-- Once you find DllMain_dispatcher, decompile it
SELECT decompile(0xDISPATCHER_ADDR);

-- Look for the CMD 1 case — it calls the attach handler
-- Decompile the attach handler
SELECT decompile(0xATTACH_HANDLER_ADDR);
```

### Step 4: Map the Vtable
```sql
-- Find data references that look like vtable writes
-- Usually a series of MOV [base+offset], rax patterns
SELECT printf('0x%X', ea) as addr, line
FROM pseudocode WHERE func_addr = 0xATTACH_HANDLER
AND line LIKE '%vtable%' OR line LIKE '%result +%';
```

### Step 5: Analyze Imported APIs
```sql
-- Check what this plugin imports
SELECT * FROM imports;

-- Cross-reference imports with functions
SELECT func_at(x.from_ea) as caller, i.name as import_name
FROM imports i
JOIN xrefs x ON x.to_ea = i.address
ORDER BY caller;
```

### Step 6: Rename and Annotate
```sql
-- Rename functions as you discover their purpose
UPDATE funcs SET name = 'cmd1_attach_handler' WHERE address = 0xADDR;

-- Add comments to explain logic
UPDATE pseudocode SET comment = 'Populate plugin vtable'
WHERE func_addr = 0xADDR AND ea = 0xADDR;

-- Rename local variables
SELECT rename_lvar(0xFUNC_ADDR, IDX, 'new_name');

-- Save after annotation batch
SELECT save_database();
```

## Available Scripts

| Script | Purpose |
|--------|---------|
| `scripts/decrypt_blobs.py` | IMUL stream cipher + LZ77 decompressor for encrypted data blobs |
| `scripts/reconstruct_blob_pes.py` | Reconstruct PE32+ DLLs from ScatterBrain packed PE blobs |
| `scripts/sb_extract.py` | Full extraction: section mapping, import decryption, relocation processing |
| `scripts/sb_reconstruct_pe.py` | Two-pass PE reconstruction with lief |
| `scripts/deobf_sweep.py` | Capstone-based opaque predicate deobfuscator |
| `scripts/hash_resolve.py` | API hash brute-forcer for ROR-8/XOR/0x7C35D9A3 |
| `scripts/decrypt_strings.py` | Standalone decryptor for polynomial XOR encrypted strings |

## Output Files

Sensitive malware-derived output artifacts are retained in a private archive and are not distributed in this public repository.

| File | Description |
|------|-------------|
| `blob_N_Name.dll.pe` | Reconstructed PE DLLs (N=0..7) |
| `blob_N_payload.bin` | Raw decompressed packed PE data |
| `blob_pe_summary.json` | All blob metadata, imports, sections |
| `blob_analysis.json` | Redacted public decryption/decompression summary |
| `inner_pe.dll.pe` | Parent inner PE DLL |
| `encrypted_strings.json` | All 37 decrypted string blobs from inner PE |

## Plugin-Specific Context

### Blob Import Summary

| Blob | DLLs | Function Count | Key Capability |
|------|------|----------------|----------------|
| blob_0 | KERNEL32, USER32, ADVAPI32, WS2_32, USERENV | 34 | Process creation, token manipulation, mutex coordination |
| blob_1 | KERNEL32, USER32, ADVAPI32 | 12 | Registry persistence, value enumeration |
| blob_2 | (none) | 0 | Pure vtable consumer — shellcode or utility module |
| blob_3 | KERNEL32, USER32, ole32, WININET, VERSION | 31 | System fingerprinting, HTTP/FTP C2 communication |
| blob_4 | KERNEL32, USER32, WS2_32 | 21 | Raw socket management, WSAIoctl |
| blob_5 | KERNEL32, USER32, WS2_32, WININET, urlmon | 38 | HTTP C2 transport, user-agent spoofing |
| blob_6 | KERNEL32, WS2_32 | 35 | Reliable UDP (RUDP) transport — AIMD congestion, SACK, 8 packet types |
| blob_7 | KERNEL32, WS2_32 | 36 | DNS tunnel transport — hex subdomain labels, TXT responses |

### What to Look For in Each Plugin

1. **Entry point dispatch** — find the fdwReason switch with cases 0, 1, 101, 102, 104
2. **CMD 1 attach handler** — vtable population, worker thread spawn
3. **Vtable functions** — these are the plugin's capabilities exposed to the orchestrator
4. **CMD 102 response** — what string/ID does it return? This identifies the plugin
5. **API resolution** — are APIs resolved by hash, encrypted string, or direct import?
6. **Cross-references to imports** — which functions use which imported APIs?
7. **Data structures** — global buffers, linked lists, critical sections
8. **Network protocol** — for blobs 3-7: how are packets formatted, encrypted, sent?

### Naming Convention

Follow the established naming patterns:
- `DllMain_dispatcher` for the entry point
- `cmd1_attach_handler` for the CMD 1 handler
- `worker_thread_entry` for spawned threads
- `vtfn_*` prefix for vtable functions
- `g_pfn*` for cached function pointer globals
- `g_*` for other globals
- `enc_*` for encrypted string blob addresses
- `sb_*` prefix for ScatterBrain-specific utility functions
