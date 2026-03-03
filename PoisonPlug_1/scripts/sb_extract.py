"""
ScatterBrain Packed PE Extractor

Extracts and parses the packed PE blob from a ScatterBrain-obfuscated DLL:
  - Parses sb_packed_pe_hdr (custom header at blob offset 0)
  - Parses section table (12-byte entries at offset 0x38)
  - Builds a mapped image by simulating section copy
  - Decrypts relocation entries (rolling XOR, if present)
  - Decrypts import descriptor names (rolling XOR cipher)
  - Dumps raw blob, mapped image, and JSON reconstruction data

Usage:
    python scripts/sb_extract.py
    python scripts/sb_extract.py --blob-va 0x180007AAF --blob-size 0x19676
    python scripts/sb_extract.py --out-dir output --no-dump
"""

import argparse
import json
import struct
import sys
from pathlib import Path

import lief

# ---------------------------------------------------------------------------
# Defaults (ScatterBrain sample-specific, overridable via CLI)
# ---------------------------------------------------------------------------

DEFAULT_PE = str(
    Path(__file__).resolve().parent.parent
    / "60678e352f3c849e36413f5de51b5eeca1180840c818f9ece0a0da803eb205a5.neutred"
)
DEFAULT_BLOB_VA = 0x180007AAF
DEFAULT_BLOB_SIZE = 0x19676
DEFAULT_OUT_DIR = str(Path(__file__).resolve().parent.parent / "output")

# ScatterBrain constants
SB_XOR_CONSTANT = 0x7C35D9A3
SB_HEADER_SIZE = 0x38        # actual header (before section table)
SB_SECTION_TABLE_OFFSET = 0x38  # section table starts here
SB_SECTION_ENTRY_SIZE = 12


# ---------------------------------------------------------------------------
# PE loading (VA-to-bytes via lief)
# ---------------------------------------------------------------------------

class PEImage:
    """Wraps a lief PE to provide VA-to-bytes access."""

    def __init__(self, path: str):
        self.pe = lief.parse(path)
        if self.pe is None:
            raise RuntimeError(f"lief could not parse {path}")
        self.imagebase = self.pe.optional_header.imagebase
        self._sections = []
        for sec in self.pe.sections:
            va_start = self.imagebase + sec.virtual_address
            va_end = va_start + sec.virtual_size
            raw = bytes(sec.content)
            self._sections.append((va_start, va_end, raw))

    def read_va(self, va: int, size: int) -> bytes:
        """Read `size` bytes starting at virtual address `va`."""
        for va_start, va_end, raw in self._sections:
            if va_start <= va < va_end:
                off = va - va_start
                return raw[off:off + size]
        raise ValueError(f"VA 0x{va:X} not found in any section")


# ---------------------------------------------------------------------------
# Header parsing
# ---------------------------------------------------------------------------

def parse_header(blob: bytes) -> dict:
    """
    Parse sb_packed_pe_hdr from the first 0x38 bytes of the blob.

    The header ends at offset 0x38 where the section table begins.
    Note: the IDA struct definition includes 2 extra DWORDs at 0x38/0x3C
    (labeled prng_fill_size/padding) which are actually the first section
    entry's dest_rva and src_offset. The PRNG fill count equals section 0's
    dest_rva by design (it fills the header area before the first section).

    See src/packed_pe_analysis.md for full field documentation.
    """
    if len(blob) < SB_HEADER_SIZE:
        raise ValueError(f"Blob too small for header: {len(blob)} bytes")

    h = {}
    h["magic0"]          = struct.unpack_from('<I', blob, 0x00)[0]
    h["magic1"]          = struct.unpack_from('<I', blob, 0x04)[0]
    h["size_of_image"]   = struct.unpack_from('<I', blob, 0x08)[0]
    h["flags"]           = struct.unpack_from('<I', blob, 0x0C)[0]
    h["image_base"]      = struct.unpack_from('<Q', blob, 0x10)[0]
    h["reloc_dir_rva"]   = struct.unpack_from('<I', blob, 0x18)[0]
    h["reloc_dir_size"]  = struct.unpack_from('<I', blob, 0x1C)[0]
    h["import_desc_rva"] = struct.unpack_from('<I', blob, 0x20)[0]
    h["iat_size"]        = struct.unpack_from('<I', blob, 0x24)[0]
    h["entry_point_rva"] = struct.unpack_from('<I', blob, 0x28)[0]
    h["pe_magic"]        = struct.unpack_from('<H', blob, 0x2C)[0]
    h["num_sections"]    = struct.unpack_from('<I', blob, 0x30)[0]
    h["checksum"]        = struct.unpack_from('<I', blob, 0x34)[0]

    # prng_fill_size = section_0.dest_rva (dual purpose by design)
    h["prng_fill_size"]  = struct.unpack_from('<I', blob, 0x38)[0]

    # Validation
    h["xor_constant"] = h["magic0"] ^ h["magic1"]
    h["valid_magic"] = (h["xor_constant"] == SB_XOR_CONSTANT)
    h["valid_pe_magic"] = (h["pe_magic"] == 0x20B)

    return h


# ---------------------------------------------------------------------------
# Section table
# ---------------------------------------------------------------------------

def parse_sections(blob: bytes, num_sections: int) -> list:
    """
    Parse section table entries at blob offset 0x38.

    The section table starts at offset 0x38 (immediately after the 0x38-byte
    header). Each entry is 12 bytes:
        DWORD dest_rva    -- destination RVA in mapped image
        DWORD src_offset  -- source offset within blob
        DWORD raw_size    -- number of bytes to copy

    Note: the IDA struct 'sb_packed_pe_hdr' (sizeof=0x40) overlaps with the
    first section entry. The struct's 'prng_fill_size' at 0x38 is actually
    section_0.dest_rva, and 'padding' at 0x3C is section_0.src_offset.
    """
    sections = []
    for i in range(num_sections):
        off = SB_SECTION_TABLE_OFFSET + i * SB_SECTION_ENTRY_SIZE
        if off + SB_SECTION_ENTRY_SIZE > len(blob):
            break
        dest_rva, src_off, raw_size = struct.unpack_from('<III', blob, off)
        sections.append({
            "index": i,
            "dest_rva": dest_rva,
            "src_offset": src_off,
            "raw_size": raw_size,
        })
    return sections


# ---------------------------------------------------------------------------
# Mapped image construction
# ---------------------------------------------------------------------------

def build_mapped_image(blob: bytes, header: dict, sections: list) -> bytearray:
    """
    Simulate reflective_loader's section copy to construct the mapped image.

    The loader does:
      1. VirtualAlloc(size_of_image + 0x4000, RWX)
      2. PRNG fill first prng_fill_size bytes (irrelevant for reconstruction)
      3. Copy magic0, magic1, entry_point_rva, checksum to header area
      4. Copy each section (identity byte transform: 0->0, 1->1, else copy)

    We skip PRNG fill and zero-fill instead.
    """
    img_size = header["size_of_image"]
    img = bytearray(img_size)

    # Copy header fields like the loader does (Stage 4)
    if img_size >= 0x38:
        struct.pack_into('<I', img, 0x00, header["magic0"])
        struct.pack_into('<I', img, 0x04, header["magic1"])
        struct.pack_into('<I', img, 0x28, header["entry_point_rva"])
        struct.pack_into('<I', img, 0x34, header["checksum"])

    # Copy sections (Stage 5)
    for sec in sections:
        dst = sec["dest_rva"]
        src = sec["src_offset"]
        size = sec["raw_size"]
        src_data = blob[src:src + size]
        # Byte transform is identity (0->0, 1->1, else copy)
        for j in range(min(size, len(src_data))):
            if dst + j < img_size:
                img[dst + j] = src_data[j]

    return img


# ---------------------------------------------------------------------------
# Rolling XOR cipher
# ---------------------------------------------------------------------------

def sb_key_update(key: int, enc_byte: int) -> int:
    """
    Update the rolling XOR key per ScatterBrain algorithm.

    C equivalent:
        key = (key << 24) | ((char)enc_byte + (key >> 8));

    The (char) cast sign-extends the encrypted byte before adding.
    """
    enc_signed = enc_byte if enc_byte < 128 else enc_byte - 256
    left = (key << 24) & 0xFFFFFFFF
    right = (enc_signed + (key >> 8)) & 0xFFFFFFFF
    return (left | right) & 0xFFFFFFFF


def sb_decrypt_name(data: bytes, key: int) -> tuple:
    """
    Decrypt a null-terminated name using ScatterBrain's rolling XOR cipher.

    Per-byte:
        decrypted = encrypted XOR (key & 0xFF)
        key = (key << 24) | (int8(encrypted) + (key >> 8))

    The key update uses the ENCRYPTED byte, not the decrypted byte.
    Key evolves even for the null terminator byte.

    Returns: (decrypted_string, evolved_key)
    """
    result = bytearray()
    for enc_byte in data:
        dec_byte = (key ^ enc_byte) & 0xFF
        key = sb_key_update(key, enc_byte)
        if dec_byte == 0:
            break
        result.append(dec_byte)
    return result.decode('ascii', errors='replace'), key


# ---------------------------------------------------------------------------
# Relocation extraction
# ---------------------------------------------------------------------------

def extract_relocations(img: bytes, reloc_rva: int, reloc_size: int,
                        key_seed: int) -> dict:
    """
    Walk relocation blocks and decrypt entries with rolling XOR key.

    Block format (same as IMAGE_BASE_RELOCATION):
        DWORD page_rva      -- base page RVA for this block
        DWORD block_size     -- total block size including 8-byte header
        WORD  entries[]      -- XOR-encrypted relocation entries

    Entry decryption:
        decrypted = key ^ raw_entry   (lower 16 bits)
        key = (key << 16) | (raw_entry + HIWORD(key))

    Decrypted entry:
        bits 12-15: relocation type (3=HIGHLOW, 10=DIR64, 0=padding)
        bits 0-11:  offset within page

    Block headers (page_rva, block_size) are NOT encrypted.
    The rolling key continues across blocks without resetting.
    """
    if not reloc_rva or not reloc_size:
        return {
            "blocks": [], "total_entries": 0,
            "key_seed": key_seed, "key_final": key_seed,
        }

    blocks = []
    total_entries = 0
    key = key_seed
    offset = reloc_rva

    while offset + 8 <= len(img):
        page_rva, block_size = struct.unpack_from('<II', img, offset)
        if block_size == 0:
            break

        num_entries = (block_size - 8) // 2
        entries = []

        for i in range(num_entries):
            entry_off = offset + 8 + i * 2
            if entry_off + 2 > len(img):
                break
            raw = struct.unpack_from('<H', img, entry_off)[0]
            xored = (key ^ raw) & 0xFFFF

            # Key update: (key << 16) | (raw + HIWORD(key))
            key = (((key << 16) & 0xFFFFFFFF)
                   | ((raw + ((key >> 16) & 0xFFFF)) & 0xFFFFFFFF)) & 0xFFFFFFFF

            reloc_type = (xored >> 12) & 0xF
            reloc_offset = xored & 0xFFF

            entries.append({
                "type": reloc_type,
                "offset": reloc_offset,
                "target_rva": page_rva + reloc_offset,
                "raw_encrypted": raw,
            })
            total_entries += 1

        blocks.append({
            "page_rva": page_rva,
            "block_size": block_size,
            "entries": entries,
        })

        offset += block_size

    return {
        "blocks": blocks,
        "total_entries": total_entries,
        "key_seed": key_seed,
        "key_final": key,
    }


# ---------------------------------------------------------------------------
# Import extraction
# ---------------------------------------------------------------------------

def extract_imports(img: bytes, import_desc_rva: int, iat_size: int,
                    key_seed: int) -> dict:
    """
    Walk import descriptors and decrypt DLL/function names.

    Descriptor format (20 bytes = 5 DWORDs, same as IMAGE_IMPORT_DESCRIPTOR):
        [0] ilt_rva       -- Import Lookup Table (array of QWORDs)
        [1] (unused)      -- TimeDateStamp
        [2] (unused)      -- ForwarderChain
        [3] name_rva      -- encrypted DLL name
        [4] thunk_rva     -- thunk dispatch table

    Terminated by descriptor with ilt_rva == 0.

    ILT entry (QWORD = IMAGE_THUNK_DATA64):
        bit 63 set:   ordinal import (lower 16 bits = ordinal)
        bit 63 clear: RVA to (2-byte hint + encrypted function name)

    Key continuity: the rolling XOR key is NOT reset between names.
    For ordinal imports, the key does not evolve.
    """
    if not import_desc_rva or not iat_size:
        return {
            "descriptors": [], "key_seed": key_seed, "key_final": key_seed,
        }

    descriptors = []
    key = key_seed
    desc_off = import_desc_rva
    max_name_len = 260

    while desc_off + 20 <= len(img):
        desc = struct.unpack_from('<IIIII', img, desc_off)
        ilt_rva = desc[0]

        if ilt_rva == 0:
            break  # end of descriptor list

        name_rva = desc[3]
        thunk_rva = desc[4]

        # Decrypt DLL name
        if name_rva < len(img):
            enc_data = img[name_rva:min(name_rva + max_name_len, len(img))]
            dll_name, key = sb_decrypt_name(enc_data, key)
        else:
            dll_name = f"<invalid_rva_0x{name_rva:X}>"

        # Walk ILT entries
        functions = []
        iat_off = ilt_rva
        while iat_off + 8 <= len(img):
            iat_val = struct.unpack_from('<Q', img, iat_off)[0]
            if iat_val == 0:
                break

            if iat_val & (1 << 63):
                # Ordinal import — key does NOT evolve
                ordinal = iat_val & 0xFFFF
                functions.append({
                    "type": "ordinal",
                    "ordinal": ordinal,
                })
            else:
                # Name import — RVA to (2-byte hint + encrypted name)
                name_off = iat_val & 0xFFFFFFFF  # RVA is 32-bit
                if name_off + 2 < len(img):
                    hint = struct.unpack_from('<H', img, name_off)[0]
                    enc_func = img[name_off + 2:min(name_off + 2 + max_name_len, len(img))]
                    func_name, key = sb_decrypt_name(enc_func, key)
                    functions.append({
                        "type": "name",
                        "hint": hint,
                        "name_rva": name_off,
                        "name": func_name,
                    })
                else:
                    functions.append({
                        "type": "name",
                        "name_rva": name_off,
                        "name": f"<invalid_rva_0x{name_off:X}>",
                    })

            iat_off += 8

        descriptors.append({
            "dll_name": dll_name,
            "dll_name_enc_rva": name_rva,
            "ilt_rva": ilt_rva,
            "thunk_rva": thunk_rva,
            "functions": functions,
        })

        desc_off += 20

    return {
        "descriptors": descriptors,
        "key_seed": key_seed,
        "key_final": key,
    }


# ---------------------------------------------------------------------------
# JSON formatting helpers
# ---------------------------------------------------------------------------

def format_header_json(h: dict) -> dict:
    return {
        "magic0": f"0x{h['magic0']:08X}",
        "magic1": f"0x{h['magic1']:08X}",
        "xor_constant": f"0x{h['xor_constant']:08X}",
        "valid_magic": h["valid_magic"],
        "valid_pe_magic": h["valid_pe_magic"],
        "size_of_image": h["size_of_image"],
        "size_of_image_hex": f"0x{h['size_of_image']:X}",
        "flags": h["flags"],
        "image_base": f"0x{h['image_base']:X}",
        "reloc_dir_rva": f"0x{h['reloc_dir_rva']:X}" if h["reloc_dir_rva"] else 0,
        "reloc_dir_size": h["reloc_dir_size"],
        "import_desc_rva": f"0x{h['import_desc_rva']:X}" if h["import_desc_rva"] else 0,
        "iat_size": h["iat_size"],
        "entry_point_rva": f"0x{h['entry_point_rva']:X}",
        "pe_magic": f"0x{h['pe_magic']:X}",
        "num_sections": h["num_sections"],
        "checksum": f"0x{h['checksum']:08X}",
        "prng_fill_size": h["prng_fill_size"],
    }


def format_sections_json(sections: list) -> list:
    return [
        {
            "index": s["index"],
            "dest_rva": f"0x{s['dest_rva']:X}",
            "src_offset": f"0x{s['src_offset']:X}",
            "raw_size": s["raw_size"],
            "raw_size_hex": f"0x{s['raw_size']:X}",
        }
        for s in sections
    ]


def format_relocs_json(relocs: dict) -> dict:
    formatted_blocks = []
    for block in relocs["blocks"]:
        fmt_entries = []
        for e in block["entries"]:
            if e["type"] != 0:  # skip padding entries in output
                fmt_entries.append({
                    "type": e["type"],
                    "type_name": {3: "HIGHLOW", 10: "DIR64"}.get(e["type"], f"UNKNOWN({e['type']})"),
                    "offset": f"0x{e['offset']:03X}",
                    "target_rva": f"0x{e['target_rva']:X}",
                })
        formatted_blocks.append({
            "page_rva": f"0x{block['page_rva']:X}",
            "block_size": block["block_size"],
            "num_entries": len(fmt_entries),
            "entries": fmt_entries,
        })
    return {
        "total_entries": relocs["total_entries"],
        "num_blocks": len(relocs["blocks"]),
        "key_seed": f"0x{relocs['key_seed']:08X}",
        "key_final": f"0x{relocs['key_final']:08X}",
        "blocks": formatted_blocks,
    }


def format_imports_json(imports: dict) -> dict:
    formatted_descs = []
    for desc in imports["descriptors"]:
        fmt_funcs = []
        for f in desc["functions"]:
            if f["type"] == "ordinal":
                fmt_funcs.append({"type": "ordinal", "ordinal": f["ordinal"]})
            else:
                entry = {
                    "type": "name",
                    "name": f["name"],
                    "hint": f.get("hint", 0),
                }
                if isinstance(f.get("name_rva"), int):
                    entry["name_rva"] = f"0x{f['name_rva']:X}"
                fmt_funcs.append(entry)
        formatted_descs.append({
            "dll_name": desc["dll_name"],
            "dll_name_enc_rva": f"0x{desc['dll_name_enc_rva']:X}",
            "ilt_rva": f"0x{desc['ilt_rva']:X}",
            "thunk_rva": f"0x{desc['thunk_rva']:X}",
            "num_functions": len(desc["functions"]),
            "functions": fmt_funcs,
        })
    return {
        "num_dlls": len(imports["descriptors"]),
        "key_seed": f"0x{imports['key_seed']:08X}",
        "key_final": f"0x{imports['key_final']:08X}",
        "descriptors": formatted_descs,
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_int(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def main():
    parser = argparse.ArgumentParser(
        description="Extract and parse ScatterBrain packed PE blob"
    )
    parser.add_argument(
        "--pe", default=DEFAULT_PE,
        help="Path to the PE DLL file",
    )
    parser.add_argument(
        "--blob-va", type=parse_int, default=DEFAULT_BLOB_VA,
        help="VA of the packed PE blob (default: 0x180007AAF)",
    )
    parser.add_argument(
        "--blob-size", type=parse_int, default=DEFAULT_BLOB_SIZE,
        help="Size of the packed PE blob (default: 0x19676)",
    )
    parser.add_argument(
        "--out-dir", default=DEFAULT_OUT_DIR,
        help="Output directory (default: output/)",
    )
    parser.add_argument(
        "--no-dump", action="store_true",
        help="Skip dumping binary files, only output JSON",
    )
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    # == Stage 1: Load PE and extract blob ================================
    print(f"[*] Loading PE: {args.pe}", file=sys.stderr)
    pe = PEImage(args.pe)

    print(f"[*] Extracting blob: VA=0x{args.blob_va:X}, size=0x{args.blob_size:X}",
          file=sys.stderr)
    blob = pe.read_va(args.blob_va, args.blob_size)
    print(f"[*] Got {len(blob)} bytes", file=sys.stderr)

    # == Stage 2: Parse header ============================================
    print("[*] Parsing sb_packed_pe_hdr...", file=sys.stderr)
    header = parse_header(blob)

    if not header["valid_magic"]:
        print(f"[!] Magic validation FAILED: "
              f"0x{header['magic0']:08X} ^ 0x{header['magic1']:08X} = "
              f"0x{header['xor_constant']:08X} (expected 0x{SB_XOR_CONSTANT:08X})",
              file=sys.stderr)
    else:
        print(f"[+] Magic validation OK: magic0 ^ magic1 = "
              f"0x{header['xor_constant']:08X}", file=sys.stderr)

    if not header["valid_pe_magic"]:
        print(f"[!] PE magic FAILED: 0x{header['pe_magic']:X} (expected 0x20B)",
              file=sys.stderr)
    else:
        print("[+] PE magic OK: PE32+ (0x20B)", file=sys.stderr)

    print(f"[*] Size of image: 0x{header['size_of_image']:X} "
          f"({header['size_of_image']} bytes)", file=sys.stderr)
    print(f"[*] Entry point RVA: 0x{header['entry_point_rva']:X}", file=sys.stderr)
    print(f"[*] Sections: {header['num_sections']}", file=sys.stderr)
    print(f"[*] Reloc dir: RVA=0x{header['reloc_dir_rva']:X}, "
          f"size=0x{header['reloc_dir_size']:X}", file=sys.stderr)
    print(f"[*] Import desc: RVA=0x{header['import_desc_rva']:X}, "
          f"iat_size=0x{header['iat_size']:X}", file=sys.stderr)

    # == Stage 3: Parse section table =====================================
    print("[*] Parsing section table...", file=sys.stderr)
    sections = parse_sections(blob, header["num_sections"])
    for sec in sections:
        print(f"    Section {sec['index']}: "
              f"dest=0x{sec['dest_rva']:X}, "
              f"src=0x{sec['src_offset']:X}, "
              f"size=0x{sec['raw_size']:X} ({sec['raw_size']} bytes)",
              file=sys.stderr)

    # == Stage 4: Build mapped image ======================================
    print("[*] Building mapped image...", file=sys.stderr)
    mapped = build_mapped_image(blob, header, sections)
    print(f"[*] Mapped image: {len(mapped)} bytes", file=sys.stderr)

    # == Stage 5: Extract relocations =====================================
    print("[*] Extracting relocations...", file=sys.stderr)
    relocs = extract_relocations(
        mapped,
        header["reloc_dir_rva"],
        header["reloc_dir_size"],
        header["magic0"],
    )
    print(f"[*] Relocations: {relocs['total_entries']} entries "
          f"in {len(relocs['blocks'])} blocks", file=sys.stderr)

    # == Stage 6: Extract imports =========================================
    # Import decryption key = final reloc key (if no relocs, stays magic0)
    import_key = relocs["key_final"]
    print(f"[*] Decrypting imports (key=0x{import_key:08X})...", file=sys.stderr)
    imports = extract_imports(
        mapped,
        header["import_desc_rva"],
        header["iat_size"],
        import_key,
    )
    print(f"[*] Imports: {len(imports['descriptors'])} DLLs", file=sys.stderr)
    for desc in imports["descriptors"]:
        print(f"    {desc['dll_name']}: {len(desc['functions'])} functions",
              file=sys.stderr)
        for func in desc["functions"]:
            if func["type"] == "ordinal":
                print(f"      #{func['ordinal']} (ordinal)", file=sys.stderr)
            else:
                print(f"      {func['name']}", file=sys.stderr)

    # == Stage 7: Dump files ==============================================
    files = {}

    if not args.no_dump:
        blob_path = out_dir / "packed_blob.bin"
        blob_path.write_bytes(blob)
        print(f"[*] Raw blob -> {blob_path}", file=sys.stderr)
        files["raw_blob"] = str(blob_path)

        mapped_path = out_dir / "mapped_image.bin"
        mapped_path.write_bytes(mapped)
        print(f"[*] Mapped image -> {mapped_path}", file=sys.stderr)
        files["mapped_image"] = str(mapped_path)

    # == Stage 8: Output JSON =============================================
    output = {
        "source": {
            "pe_file": str(Path(args.pe).name),
            "blob_va": f"0x{args.blob_va:X}",
            "blob_size": args.blob_size,
            "blob_size_hex": f"0x{args.blob_size:X}",
        },
        "header": format_header_json(header),
        "sections": format_sections_json(sections),
        "relocations": format_relocs_json(relocs),
        "imports": format_imports_json(imports),
        "files": files,
    }

    json_path = out_dir / "sb_extract.json"
    with open(json_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"[*] JSON -> {json_path}", file=sys.stderr)

    # Also print JSON summary to stdout
    print(json.dumps(output, indent=2))


if __name__ == "__main__":
    main()
