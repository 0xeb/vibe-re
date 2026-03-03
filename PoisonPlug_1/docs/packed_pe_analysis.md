# Packed PE Blob Analysis

<a id="packed-call-pop-discovery"></a>
## Discovery: Call-Pop Bootstrap

The packed PE payload is embedded directly in the binary at `0x180007AAF`, discovered by tracing the call chain to `reflective_loader`:

```
0x180007AA0: push    rbp
0x180007AA1: mov     rbp, rsp
0x180007AA4: push    rcx           ; save original argument
0x180007AA5: push    19676h        ; blob size = 0x19676 (104054 bytes)
0x180007AAA: call    shim          ; pushes ret addr 0x180007AAF onto stack
```

This is a **call-pop trick**: the `call` instruction pushes the return address (`0x180007AAF`) onto the stack, which is the address of the packed blob immediately following the call. The shim at `0x180021125` passes `rsp` (pointing to this return address) as `payload_ptr` to `reflective_loader`, which dereferences it to get the blob address.

```
Shim (0x180021125):
0x180021125: mov     rcx, rsp      ; rcx -> [ret_addr = 0x180007AAF]
0x180021128: push    rcx * 5       ; shadow space
0x18002112D: call    reflective_loader
```

The blob occupies `0x180007AAF` — `0x180021125` (104054 bytes), ending right where the shim code begins.

<a id="packed-header"></a>
## Parsed Header: sb_packed_pe_hdr

Bytes at `0x180007AAF`:
```
0B 74 D1 E9  A8 AD E4 95  00 E0 01 00  00 00 00 00
00 00 00 80  01 00 00 00  00 00 00 00  00 00 00 00
90 B0 01 00  28 00 00 00  44 43 00 00  0B 02 22 20
04 00 00 00  B4 A6 B1 58  00 10 00 00  68 00 00 00
```

### Parsing code (Python)

```python
import struct

# Read from binary at VA 0x180007AAF (or file offset via lief)
blob = pe_image.read_va(0x180007AAF, 0x40)

magic0      = struct.unpack_from('<I', blob, 0x00)[0]  # 0xE9D1740B
magic1      = struct.unpack_from('<I', blob, 0x04)[0]  # 0x95E4ADA8
size_of_img = struct.unpack_from('<I', blob, 0x08)[0]  # 0x1E000
flags       = struct.unpack_from('<I', blob, 0x0C)[0]  # 0x0
image_base  = struct.unpack_from('<Q', blob, 0x10)[0]  # 0x180000000
imp_dir_rva = struct.unpack_from('<I', blob, 0x18)[0]  # 0x0 (reloc dir RVA)
imp_dir_sz  = struct.unpack_from('<I', blob, 0x1C)[0]  # 0x0 (reloc dir size)
imp_desc    = struct.unpack_from('<I', blob, 0x20)[0]  # 0x1B090
iat_size    = struct.unpack_from('<I', blob, 0x24)[0]  # 0x28
ep_rva      = struct.unpack_from('<I', blob, 0x28)[0]  # 0x4344
pe_magic    = struct.unpack_from('<H', blob, 0x2C)[0]  # 0x20B
num_sec     = struct.unpack_from('<I', blob, 0x30)[0]  # 4
checksum    = struct.unpack_from('<I', blob, 0x34)[0]  # 0x58B1A6B4
# Section table starts at 0x38 (see parse_sections)
```

### Parsed fields

| Offset | Size | Field | Value | Notes |
|--------|------|-------|-------|-------|
| `0x00` | DWORD | `magic0` | `0xE9D1740B` | XOR key seed |
| `0x04` | DWORD | `magic1` | `0x95E4ADA8` | `magic0 ^ magic1 = 0x7C35D9A3` (validation) |
| `0x08` | DWORD | `size_of_image` | `0x1E000` (122880) | VirtualAlloc size + entry point RVA base |
| `0x0C` | DWORD | `flags` | `0x0` | If == 8, `Sleep(INFINITE)` after load |
| `0x10` | QWORD | `image_base` | `0x180000000` | Original image base for relocation delta |
| `0x18` | DWORD | `reloc_dir_rva` | `0x0` | Relocation directory RVA (misnamed `import_dir_rva` in IDA struct). Zero = no relocations. |
| `0x1C` | DWORD | `reloc_dir_size` | `0x0` | Relocation directory size (misnamed `import_dir_size` in IDA struct) |
| `0x20` | DWORD | `import_desc_rva` | `0x1B090` | Custom import descriptors table RVA |
| `0x24` | DWORD | `iat_size` | `0x28` | IAT zeroing size |
| `0x28` | DWORD | `entry_point_rva` | `0x4344` | AddressOfEntryPoint (DllMain) |
| `0x2C` | WORD | `pe_magic` | `0x20B` | PE32+ signature |
| `0x2E` | WORD | (padding) | `0x2022` | |
| `0x30` | DWORD | `num_sections` | `4` | Number of sections |
| `0x34` | DWORD | `checksum` | `0x58B1A6B4` | Copied to mapped image |
| `0x38` | 12*N | sections[] | ... | Section table starts here. 12-byte entries: `dest_rva`, `src_offset`, `raw_size` |

**Note on `prng_fill_size`**: The IDA struct `sb_packed_pe_hdr` (sizeof=0x40) has a field at offset 0x38 labeled `prng_fill_size` with value `0x1000`. This is actually **section 0's dest_rva** (the first DWORD of the section table). The PRNG fill count equals the first section's dest_rva by design: it fills exactly the PE header area (offsets 0 to first_section_start-1) with pseudo-random data before sections are copied.

<a id="packed-blob-layout"></a>
## Blob Layout

```
Blob offset  VA               Content
0x00         0x180007AAF      +--------------------------------------+
                              | sb_packed_pe_hdr (0x38 bytes)         |
0x38         0x180007AE7      +--------------------------------------+
                              | Section table (4 * 12 = 48 bytes)     |
0x68         0x180007B17      +--------------------------------------+
                              | Section 0 raw data (16532 bytes)      |
                              |   -> maps to RVA 0x1000 (.text)       |
0x40FC       0x18000BBAB      +--------------------------------------+
                              | Section 1 raw data (86246 bytes)      |
                              |   -> maps to RVA 0x6000 (.rdata/data) |
0x191E2      0x180020C91      +--------------------------------------+
                              | Section 2 raw data (512 bytes)        |
                              |   -> maps to RVA 0x1C000              |
0x193E2      0x180020E91      +--------------------------------------+
                              | Section 3 raw data (660 bytes)        |
                              |   -> maps to RVA 0x1D000              |
0x19676      0x180021125      +--------------------------------------+  <-- blob end = shim start
```

Total blob: `0x19676` bytes (104054 bytes), from `push 0x19676` at bootstrap.
Section data packs tightly — section 3 ends exactly at the blob boundary.

<a id="packed-section-table"></a>
## Section Table (at blob offset 0x38)

| Index | dest_rva | src_offset | raw_size | Description |
|-------|----------|------------|----------|-------------|
| 0 | `0x1000` | `0x68` | 16532 (0x4094) | Code section (.text). Entry point at RVA 0x4344 is within this section. |
| 1 | `0x6000` | `0x40FC` | 86246 (0x150E6) | Data section. Contains import descriptors at RVA 0x1B090. |
| 2 | `0x1C000` | `0x191E2` | 512 (0x200) | Small data section. |
| 3 | `0x1D000` | `0x193E2` | 660 (0x294) | Small data section. |

Mapped image coverage:
```
0x0000-0x0FFF  PRNG-filled header area (4096 bytes)
0x1000-0x5093  Section 0 (code)
0x5094-0x5FFF  (gap - zero-filled)
0x6000-0x1B0E5 Section 1 (data, includes import structures)
0x1B0E6-0x1BFFF (gap - zero-filled)
0x1C000-0x1C1FF Section 2
0x1C200-0x1CFFF (gap - zero-filled)
0x1D000-0x1D293 Section 3
0x1D294-0x1DFFF (gap - zero-filled)
```

<a id="packed-key-observations"></a>
## Key observations

1. **No classic import directory** — `import_dir_rva` and `import_dir_size` are both 0. Imports use the custom encrypted format at `import_desc_rva = 0x1B090`.
2. **Self-contained** — the blob contains everything needed: headers, sections, relocations, and encrypted imports.
3. **Image base matches host DLL** — `0x180000000` is the same as the containing binary, which means relocation delta = `mapped_base - 0x180000000`.
4. **Decryption key** — `magic0 = 0xE9D1740B` is the seed for both the rolling XOR import name decryption and the relocation entry XOR.

## Not a Standalone PE

The blob is **NOT** a standard PE file — no MZ/PE signature, no DOS header, cannot be loaded directly by Windows. It uses a proprietary format (`sb_packed_pe_hdr`) designed for the ScatterBrain reflective loader.

At runtime, the reflective loader performs the complete loading pipeline:

1. **VirtualAlloc** — allocates `size_of_image + 0x4000` bytes with PAGE_EXECUTE_READWRITE
2. **PRNG fill** — fills first `prng_fill_size` bytes with deterministic pseudo-random data (seed = allocation address, constant = `0xEF70ABEA`)
3. **Copy header fields** — writes magic0, magic1, entry_point_rva, checksum to the mapped image header
4. **Section copy** — copies 4 sections from blob to mapped image (identity byte transform: 0->0, 1->1, else copy)
5. **Base relocations** — processes relocation blocks using rolling XOR-encrypted entries *(not present in this sample: both reloc fields are 0)*
6. **Zero relocation region** — clears the relocation region in mapped image
7. **Decrypt + resolve imports** — rolling XOR cipher on DLL/function names, resolves via LoadLibraryA/GetProcAddress, builds obfuscated call thunks
8. **Zero import descriptor header** — clears the `iat_size` region at `import_desc_rva`
9. **Call entry point** — invokes `DllMain(mapped_base, DLL_PROCESS_ATTACH, original_arg)`

The mapped image is what actually executes. The blob is just storage.

## Field Naming Note

In the header, `import_dir_rva` (offset 0x18) and `import_dir_size` (offset 0x1C) are confusingly named — they are actually used for the **relocation directory** (Stage 6 in `reflective_loader`), not imports. The actual import descriptors use `import_desc_rva` (offset 0x20). In this sample, both relocation fields are 0, so no relocations are processed.

<a id="packed-import-format"></a>
## Import Descriptor Format

At `import_desc_rva` (0x1B090) in the mapped image, the loader walks an array of 20-byte descriptors (same layout as `IMAGE_IMPORT_DESCRIPTOR`):

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | DWORD | `ilt_rva` | Import Lookup Table RVA (array of QWORDs) |
| 0x04 | DWORD | (unused) | TimeDateStamp (not read) |
| 0x08 | DWORD | (unused) | ForwarderChain (not read) |
| 0x0C | DWORD | `name_rva` | Encrypted DLL name RVA |
| 0x10 | DWORD | `thunk_rva` | Thunk dispatch table RVA (overwritten with resolved thunks) |

Terminated by a descriptor with `ilt_rva == 0`.

Each ILT entry is a QWORD (`IMAGE_THUNK_DATA64`):
- **Bit 63 set**: ordinal import — lower 16 bits = ordinal number
- **Bit 63 clear**: name import — value is RVA to `(2-byte hint + encrypted function name)`

<a id="packed-rolling-xor"></a>
## Rolling XOR Cipher (Import Name Decryption)

DLL names and function names are encrypted with a rolling XOR cipher. The key is stateful across all names in sequence (DLL name, then each function name, then next DLL name, etc.).

**Initial key**: `magic0` (`0xE9D1740B`). If relocations were present, the key would first evolve through all relocation entries before being used for imports. In this sample, no relocations exist, so the key starts at `magic0`.

**Per-byte decryption**:
```
decrypted_byte = encrypted_byte XOR (key & 0xFF)
key = (key << 24) | (int8(encrypted_byte) + (key >> 8))
```

Where `int8(enc)` sign-extends the encrypted byte to a 32-bit signed integer (C cast: `(char)enc_byte`).

**Key details**:
- The key update uses the **encrypted** byte, not the decrypted byte
- The key state is NOT reset between names — the final key after one name becomes the starting key for the next
- For ordinal imports (no name to decrypt), the key does **not** evolve
- Decryption terminates when a decrypted byte is `0x00` (null terminator)

<a id="packed-obfuscated-thunks"></a>
## Obfuscated Call Thunks

After resolving each import, the loader builds an obfuscated indirect call thunk instead of storing the API address directly in the IAT:

1. Pick a 1-byte prefix based on `key % 5`: `E8` (0), `E9` (1), `FF` (2), `48` (3), `75` (4)
2. Write thunk body: `mov rax, ~api_addr` + padding + `not rax` + `jmp rax`
3. Store the thunk pointer in the thunk dispatch table

This means the mapped image's call table points to thunks, not directly to API addresses.

**Anti-breakpoint**: if a resolved API starts with `0xCC` (`int 3`), the loader skips past it by `key` bytes, evading software breakpoints on API entry points.

<a id="packed-decrypted-imports"></a>
## Decrypted Imports

Static extraction (`scripts/sb_extract.py`) successfully decrypted all imports:

| DLL | Function | Type | Hint |
|-----|----------|------|------|
| `KERNEL32.dll` | `GetSystemTime` | name | 638 |

Only 1 DLL with 1 function. The packed PE is minimal — it likely resolves additional APIs dynamically at runtime (similar to how the outer reflective loader uses API hashing). The `iat_size` field (0x28 = 40 bytes = 2 descriptors) confirms this: 1 real descriptor + 1 null terminator.

Import descriptor at RVA `0x1B090`:
- ILT RVA: `0x1B0B8`
- Encrypted name RVA: `0x1B0D8`
- Thunk RVA: `0x6000`

Decryption key evolution: `0xE9D1740B` (magic0) -> `0x83ABC261` (after all imports).

<a id="packed-static-reconstruction"></a>
## Static Reconstruction

Since section data and encrypted import names are stored within the blob, everything can be extracted statically:

- **Sections**: copy from blob offsets to their `dest_rva` positions in a zero-filled buffer
- **Import names**: decrypt using the rolling XOR cipher with `magic0` as initial key
- **Relocations**: not present in this sample (both reloc fields are zero), but the extraction tool supports them
- **Entry point**: at `mapped_base + 0x4344`

Tool: `scripts/sb_extract.py` — outputs:
- `packed_blob.bin` — raw blob from the PE
- `mapped_image.bin` — reconstructed mapped image after section copy
- `sb_extract.json` — all parsed data (header, sections, relocations, decrypted imports)

Sensitive malware-derived artifacts from this stage are retained in a private archive and are not distributed in this public repository.
