# ScatterBrain: Full Execution Walkthrough

<a id="workflow-dllmain"></a>
## 1. `DllMain` (0x180001050)

Windows calls this when the DLL is loaded. On `DLL_PROCESS_ATTACH`, it does one thing: spawns a thread.

```
CreateThread(spawn_reflective_loader)
CloseHandle(thread_handle)
return TRUE
```

That's it — DllMain returns immediately so it doesn't block the loader. The real work happens on the new thread.

## 2. `spawn_reflective_loader` (0x180001000) — the thread entry

```
rwx = VirtualAlloc(NULL, 0x100000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)  // 1MB, RWX
memmove(rwx, &0x180007AA0, 106101)   // copy 106,101 bytes from the host DLL
result = rwx(0)                       // call the copy as a function
if (!result) ExitThread(0)
```

This copies a contiguous block from the host DLL (`0x180007AA0`–`0x180021915`) into freshly allocated executable memory, then jumps to it. Why copy first? Because the reflective loader is going to modify itself in-place (write section data, patch relocations, build import thunks) — it needs writable memory.

## 3. What gets copied (the 106,101-byte block)

```
Offset 0x0000: bootstrap          (15 bytes)    ← execution starts here
Offset 0x000F: packed PE blob      (104,054 bytes) ← the inner PE in custom format
Offset 0x19685: shim              (18 bytes)
Offset 0x19697: reflective_loader  (2,025 bytes) ← Region B
```

Region A (`reflective_loader_A`) sits at offset `0x420B` inside this block — it's **part of the blob data** (blob section 1, which maps to inner PE RVA `0x6100`). It's the same loader code, but stored as raw data inside the packed PE. It doesn't execute from here — it's just data that will later become code inside the inner PE.

## 4. Bootstrap (0x180007AA0, now at `rwx+0`) — the call-pop trick

```asm
push    rbp
mov     rbp, rsp
push    rcx            ; save the arg (0)
push    0x19676        ; blob size = 104,054
call    shim           ; at rwx+0x19685
```

The `call` pushes the return address onto the stack. That return address is `rwx+0xF` — which is the start of the packed PE blob. This is a classic position-independent way to get the blob's address without hardcoding it.

## 5. Shim (0x180021125, now at `rwx+0x19685`)

```asm
mov     rcx, rsp       ; rcx = stack pointer (points to: [blob_addr, blob_size, ...])
call    reflective_loader
```

Passes the stack pointer as the first argument. The loader reads `[rcx]` to get the blob address and `[rcx+8]` to get the size.

<a id="workflow-reflective-loader-nine-stages"></a>
## 6. `reflective_loader` (0x180021137, now at `rwx+0x19697`) — the 9 stages

This is where the inner PE gets unpacked:

1. **PEB walk** — walks the PEB loader data structures to find `kernel32.dll` by hashing each module name with ROR-8/XOR/`0x7C35D9A3`
2. **Export resolution** — walks kernel32's export table, resolves 4 APIs by hash: `LoadLibraryA`, `GetProcAddress`, `VirtualAlloc`, `Sleep`
3. **Validate blob** — checks `magic0 ^ magic1 == 0x7C35D9A3` and PE magic == `0x20B` (PE32+)
4. **Allocate + PRNG fill** — `VirtualAlloc(NULL, size_of_image + 0x4000, MEM_COMMIT, RWX)`, fills with PRNG garbage (anti-forensics)
5. **Copy sections** — reads the 4 section entries from the blob header, copies each section's raw data to its destination RVA in the new allocation. Byte transform: `0→0, 1→1, else copy` (identity with sentinel preservation)
6. **Base relocations** — applies reloc fixups (types 3=HIGHLOW, 10=DIR64) with a rolling XOR key to decrypt relocation entries
7. **Zero import dir** — wipes the original import descriptor area (anti-analysis)
8. **Decrypt + resolve imports** — rolling XOR cipher decrypts DLL and function names, calls `LoadLibraryA`/`GetProcAddress` to resolve each import, builds **obfuscated call thunks** (not normal IAT entries — each thunk is a small code snippet: `mov rax, ~addr; not rax; jmp rax`)
9. **Call entry point** — `DllMain(mapped_base, DLL_PROCESS_ATTACH, payload_ptr)`. If payload flag == 8, calls `Sleep(INFINITE)` to keep the thread alive.

**The result:** A fully mapped PE DLL in memory at the VirtualAlloc'd address, with relocations applied, imports resolved through obfuscated thunks, and its DllMain called. The inner PE is now running.

**Where Region A fits:** The reflective loader code itself is also stored inside blob section 1 (at inner PE RVA `0x6100`). So when the inner PE is mapped, it has a copy of the reflective loader in its own data section. The inner PE reuses this loader to reflectively load each of the 8 plugin blobs — see section 11.

---

## Part 2: Inner PE — Plugin Orchestrator

The reflective loader called `DllMain(mapped_base, DLL_PROCESS_ATTACH, payload_ptr)`. We're now inside the inner PE.

<a id="workflow-inner-pe-dispatcher"></a>
## 7. `DllMain_dispatcher` (0x180004344) — command protocol

The inner PE's entry point doesn't use `fdwReason` in the normal Windows sense. Instead, it repurposes it as a **command ID**:

| fdwReason | Action |
|-----------|--------|
| 0 | `cmd0_init_or_cleanup` — initialization or teardown |
| 1 | `cmd1_attach_handler` — main initialization (the one called by the reflective loader) |
| 101 | Write `100` to `*(DWORD*)lpReserved` — return version/capability code |
| 102 | `cmd102_custom_command` — custom command dispatch |
| 104 | Write vtable pointer to `*(QWORD*)lpReserved` — return vtable address |

The reflective loader passes `DLL_PROCESS_ATTACH` (= 1), which triggers `cmd1_attach_handler`. This same command protocol is shared by all 8 plugin blobs — the parent uses commands 100, 1, 101, 102, and 104 to communicate with each plugin.

## 8. `cmd1_attach_handler` (0x180004054) — vtable + worker thread

This 733-byte function is the inner PE's main setup:

1. **Extract payload context**: `init_payload_context(lpReserved)` saves the outer loader's payload pointer and flags into globals at `0x18001C348`
2. **Populate the 26-function vtable** at `0x18001C1B0`: stores function pointers for crypto, compression, process injection, object management, and network helpers
3. **Store metadata**: payload pointer at vtable+0xD8, config data pointer (encrypted config at `0x1800068E0`) at vtable+0xE0
4. **Initialize object**: allocates 64 bytes, calls `init_object` → `init_critical_section`
5. **Resolve threading APIs**: decrypts `"CreateThread"` and `"CloseHandle"` from encrypted strings
6. **Spawn worker thread**: `CreateThread(NULL, 0, worker_thread_entry, obj, 0, &tid)` + `CloseHandle(thread)`

If the payload data pointer is non-null (synchronous mode), it calls `worker_thread_entry` directly on the current thread instead of spawning.

<a id="workflow-worker-thread-registration"></a>
## 9. `worker_thread_entry` (0x180003E34) — blob registration

The worker thread (524 bytes) performs the critical step of registering the 8 encrypted plugin blobs:

```
For each of 8 hardcoded blob addresses in .rdata:
  vtfn_register_blob(blob_va, blob_size)
```

The 8 blobs and their `.rdata` locations:

| Blob | VA | Size | Plugin |
|------|-------|------|--------|
| 0 | `0x180009100` | 8,873 | Install |
| 1 | `0x18000D370` | 16,466 | Plugins |
| 2 | `0x18000B3B0` | 8,113 | Config |
| 3 | `0x1800070E0` | 8,214 | Online |
| 4 | `0x180011430` | 5,223 | TCP |
| 5 | `0x180012840` | 10,002 | HTTP |
| 6 | `0x180014F60` | 12,027 | UDP |
| 7 | `0x180017E60` | 11,464 | DNS |

After registration, the worker:
1. Initializes an object if not already done
2. Calls `vtfn_create_obj_c(103)` to create a handler object
3. If handler creation fails → **self-destruct**: resolves `GetCurrentProcess` + `TerminateProcess` from encrypted strings, kills the process. Falls back to `ExitProcess(0)` if that fails.
4. Returns via indirect call through the handler object's vtable — entering the command dispatch loop

<a id="workflow-blob-decryption-pipeline"></a>
## 10. Blob decryption pipeline

When a registered blob needs to be activated, `vtfn_decrypt_and_load_blob` (508 bytes) runs this pipeline:

```
Encrypted blob (from .rdata)
  │
  ├─ Step 1: IMUL stream cipher decrypt
  │    4-round cipher selected by (index % 4)
  │    Constants: 0xCA1A5842, 0x5F7B88D1, 0xAD5BC1C9, 0x3223D2C1
  │    Feistel mixing: acc = k[3] ^ ((k[1] ^ (acc - k[0])) - k[2])
  │    Output: acc ^ input_byte
  │
  ├─ Step 2: Validate magic
  │    First 4 bytes of decrypted header must be 0x650001
  │    (ScatterBrain packed PE magic)
  │
  ├─ Step 3: Read compressed/decompressed sizes from header
  │
  └─ Step 4: LZ77 decompress
       Hash-table-based back-reference compression
       Output: ScatterBrain packed PE blob
```

The same cipher is used for network packet encryption/decryption — `vtfn_decrypt_packet_header` and `vtfn_decrypt_decompress` use identical IMUL cipher logic.

<a id="workflow-plugin-loading-reuse"></a>
## 11. Plugin loading — reflective loader reuse

Each decompressed blob is a ScatterBrain packed PE. `vtfn_exec_reflective_loader` (331 bytes) loads it:

1. **Copy reflective loader**: `VirtualAlloc(NULL, 2014, MEM_COMMIT, RWX)`, then `memcpy` the 2,014-byte reflective loader from inner PE RVA `0x6100` (Region A — the same loader code that unpacked the inner PE itself)
2. **Build parameter struct**: `{blob_ptr, blob_size, flags}` on stack
3. **Call loader**: `loader_copy(param_struct)` — runs the full 9-stage unpack: PEB walk, section mapping, relocations, import thunks, DllMain dispatch

This is the payoff of Region A: the inner PE carries its own copy of the reflective loader specifically to load plugin blobs at runtime.

<a id="workflow-plugin-registration"></a>
## 12. Plugin registration — `vtfn_plugin_loader` (0x180002844)

After the reflective loader returns with a mapped plugin DLL, `vtfn_plugin_loader` (723 bytes) integrates it into the framework:

1. **Detect input type**: calls `GetModuleFileNameA(input, buf, 1)` — nonzero return means it's a loaded PE module handle; zero means it's an encrypted blob pointer
2. **For blobs**: verifies `DWORD[0] ^ DWORD[1] == 0x7C35D9A3` (packer magic), then calls `vtfn_decrypt_and_load_blob` to decrypt and load
3. **Extract timestamp**: reads `TimeDateStamp` from PE header for identification
4. **Initialize plugin via command protocol**:
   - `DllMain(module, 100, parent_vtable)` — pass parent context (gives plugin access to parent's crypto, injection, and allocation functions)
   - `DllMain(module, 1, NULL)` — CMD 1 attach: plugin populates its own vtable and starts its worker
   - `DllMain(module, 104, &vtable_out)` — CMD 104: retrieve plugin's vtable pointer
5. **Register in linked list**: allocates a 64-byte `sb_plugin_entry_t` node, stores `{flink, blink, ref_count, timestamp, critical_section, is_pe_flag, module_handle, vtable_pointer}`, inserts into the synchronized doubly-linked list (`sb_synced_list_t`)

After all 8 blobs are registered and loaded, the inner PE has a linked list of plugin entries, each with a vtable pointer for command dispatch.

<a id="workflow-c2-routing"></a>
## 13. C2 command routing

With all plugins loaded, the system is ready for C2 operations. The command flow:

```
C2 server
  │
  ├─ Network packet arrives via transport plugin
  │   (blob_4 TCP, blob_5 HTTP, blob_6 UDP, or blob_7 DNS)
  │
  ├─ vtfn_decrypt_packet_header: IMUL cipher decrypts 20-byte header
  │   Header: [key(4), field4(4), field8(4), compressed_size(4), decompressed_size(4)]
  │   All sizes in network byte order (ntohl conversion)
  │
  ├─ vtfn_decrypt_decompress: IMUL cipher decrypts payload → LZ77 decompress
  │
  ├─ Command dispatch: route to appropriate plugin via vtable
  │
  └─ Response path:
      vtfn_generate_packet_key → lz_compress → vtfn_compress_encrypt → send
```

### The 8 plugins and their roles

| Plugin | Role | Key Capability |
|--------|------|----------------|
| **Install** (blob_0, v103) | Process launcher + anti-analysis | Steals winlogon.exe SYSTEM token, creates processes under stolen tokens, 9 anti-debug/anti-tool detection functions |
| **Plugins** (blob_1, v101) | Registry persistence | CRUD operations under `HKLM\SOFTWARE\Microsoft\{id}`, stores encrypted plugin blobs in registry values |
| **Config** (blob_2, v102) | C2 configuration | Manages 2,136-byte encrypted config blob, protocol URLs (TCP/HTTP/HTTPS/UDP/DNS to configurable endpoints), file I/O |
| **Online** (blob_3, v104) | System recon + C2 router | 31-point system fingerprint (CPU, RAM, disk, network, OS, display), routes C2 traffic across 6 protocol schemes, DGA for beacon URLs |
| **TCP** (blob_4, v200) | Raw TCP transport | TCP socket with SOCKS4/5 + HTTP CONNECT proxy support, custom DNS resolution via dnsapi.dll |
| **HTTP** (blob_5, v201) | HTTP POST transport | WinInet-based HTTP/HTTPS, user agent spoofing (ObtainUserAgentString), TLS certificate bypass, SOCKS proxy auth |
| **UDP** (blob_6, v202) | Reliable UDP transport | Custom RUDP protocol: AIMD congestion control, selective ACK (SACK), 8 packet types, PRNG XOR per-packet encryption |
| **DNS** (blob_7, v203) | DNS tunnel transport | Encodes data as hex subdomain labels in DNS queries, extracts responses from TXT records, adapter enumeration via iphlpapi.dll |

Each plugin uses the same `DllMain_dispatcher` protocol and can call back to the parent's vtable for shared services: crypto (encrypt/decrypt), compression (LZ77), process injection (2 modes), memory allocation, and object management.

<a id="workflow-full-chain-summary"></a>
### Full execution chain summary

```
Host DLL
  └─ DllMain → CreateThread
      └─ spawn_reflective_loader
          └─ VirtualAlloc(RWX, 1MB) → copy bootstrap+blob → call
              └─ bootstrap: call-pop trick → shim → reflective_loader
                  └─ 9-stage unpack → inner PE DllMain(1)
                      └─ cmd1_attach_handler
                          ├─ Populate 26-function vtable
                          └─ CreateThread → worker_thread_entry
                              ├─ Register 8 encrypted blobs
                              ├─ For each blob:
                              │   IMUL decrypt → validate 0x650001 → LZ77 decompress
                              │   → copy reflective_loader to RWX → load packed PE
                              │   → CMD 100 (pass context) → CMD 1 (attach)
                              │   → CMD 104 (get vtable) → register in linked list
                              └─ Create handler → enter dispatch loop
                                  └─ C2 command routing via plugin vtables
```

For detailed analysis of individual components, see:
- [inner_pe_analysis.md](inner_pe_analysis.md) — vtable, API resolution, encrypted strings
- [static_analysis_summary.md](static_analysis_summary.md) — cipher systems, data structures, injection modes
- [blob_index.md](blob_index.md) — plugin architecture and import breakdown
- Per-blob docs: [blob_0](blob_0_install_analysis.md) through [blob_7](blob_7_dns_analysis.md)
