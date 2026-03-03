"""
sb_reconstruct_pe.py - Reconstruct a valid PE32+ DLL from ScatterBrain packed PE data.

Two-pass approach:
  Pass 1: lief builds a PE skeleton (headers, section table, imports) with empty sections.
  Pass 2: We patch actual section content into the file at the offsets lief chose.

Reads:
  - output/sb_extract.json   (parsed header, sections, decrypted imports)
  - output/mapped_image.bin   (flat memory layout with sections at their RVA positions)

Writes:
  - output/inner_pe.bin       (valid PE32+ DLL parseable by lief / IDA)
"""

import json
import sys
from pathlib import Path

import lief


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
OUTPUT_DIR = ROOT_DIR / "output"

EXTRACT_JSON = OUTPUT_DIR / "sb_extract.json"
MAPPED_IMAGE = OUTPUT_DIR / "mapped_image.bin"
OUTPUT_PE = OUTPUT_DIR / "inner_pe.bin"

# Section characteristics constants
SCN_CNT_CODE = lief.PE.Section.CHARACTERISTICS.CNT_CODE
SCN_MEM_EXECUTE = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
SCN_MEM_READ = lief.PE.Section.CHARACTERISTICS.MEM_READ
SCN_MEM_WRITE = lief.PE.Section.CHARACTERISTICS.MEM_WRITE
SCN_CNT_INITIALIZED_DATA = lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA

# File alignment for raw size rounding
FILE_ALIGNMENT = 0x200


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def main():
    # --- Load inputs ---
    with open(EXTRACT_JSON, "r") as f:
        meta = json.load(f)

    mapped_data = MAPPED_IMAGE.read_bytes()
    print(f"[*] Loaded mapped image: {len(mapped_data)} bytes")
    print(f"[*] Metadata: {len(meta['sections'])} sections, "
          f"{meta['imports']['num_dlls']} import DLL(s)")

    # --- Parse metadata ---
    image_base = int(meta["header"]["image_base"], 16)
    entry_rva = int(meta["header"]["entry_point_rva"], 16)
    size_of_image = meta["header"]["size_of_image"]

    sections_info = []
    for s, sdef in zip(meta["sections"], [
        (".text",  0x5000,  SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ),
        (".rdata", 0x16000, SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE),
        (".data1", 0x1000,  SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE),
        (".data2", 0x1000,  SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE),
    ]):
        sections_info.append({
            "name": sdef[0],
            "rva": int(s["dest_rva"], 16),
            "raw_size": s["raw_size"],
            "vsize": sdef[1],
            "chars": sdef[2],
        })

    # =========================================================
    # PASS 1: Build PE skeleton with lief (placeholder content)
    # =========================================================
    factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)

    # Add sections via factory so RVAs are baked into the section table
    for si in sections_info:
        sec = lief.PE.Section(si["name"])
        # Give each section a file-aligned blob of zeros as placeholder
        placeholder_size = align(si["raw_size"], FILE_ALIGNMENT)
        sec.content = memoryview(bytes(placeholder_size))
        sec.virtual_address = si["rva"]
        sec.virtual_size = si["vsize"]
        sec.sizeof_raw_data = placeholder_size
        sec.characteristics = si["chars"]
        factory.add_section(sec)
        print(f"[+] Section {si['name']:8s}  RVA=0x{si['rva']:05X}  "
              f"raw={si['raw_size']:6d}  vsize=0x{si['vsize']:05X}")

    pe = factory.get()
    if pe is None:
        print("[!] FAIL: Factory.get() returned None")
        return 1

    # Configure headers
    pe.optional_header.imagebase = image_base
    pe.optional_header.addressof_entrypoint = entry_rva
    pe.optional_header.section_alignment = 0x1000
    pe.optional_header.file_alignment = FILE_ALIGNMENT
    pe.optional_header.subsystem = lief.PE.OptionalHeader.SUBSYSTEM.WINDOWS_GUI
    pe.optional_header.sizeof_image = size_of_image
    pe.optional_header.dll_characteristics = (
        lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE |
        lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT
    )
    pe.header.add_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)

    # Add imports
    for desc in meta["imports"]["descriptors"]:
        dll_name = desc["dll_name"]
        lib = pe.add_import(dll_name)
        for func in desc["functions"]:
            lib.add_entry(func["name"])
            print(f"[+] Import: {dll_name}!{func['name']}")

    # Build skeleton
    config = lief.PE.Builder.config_t()
    config.imports = True
    builder = lief.PE.Builder(pe, config)
    builder.build()
    builder.write(str(OUTPUT_PE))
    print(f"\n[*] Pass 1: skeleton written ({OUTPUT_PE.stat().st_size} bytes)")

    # =========================================================
    # PASS 2: Patch actual section content into the file
    # =========================================================
    skeleton = lief.PE.parse(str(OUTPUT_PE))
    if skeleton is None:
        print("[!] FAIL: could not re-parse skeleton")
        return 1

    pe_bytes = bytearray(OUTPUT_PE.read_bytes())

    # Build a name -> section info map for our 4 sections
    our_names = {si["name"] for si in sections_info}
    patched = 0

    for sec in skeleton.sections:
        if sec.name not in our_names:
            continue

        # Find matching section info
        si = next(s for s in sections_info if s["name"] == sec.name)
        rva = si["rva"]
        raw_size = si["raw_size"]

        # Source data from mapped image
        src = mapped_data[rva : rva + raw_size]

        # File offset where this section's raw data lives
        file_off = sec.pointerto_raw_data
        file_raw_size = sec.sizeof_raw_data

        if file_raw_size == 0:
            # Section has no file space — we need to allocate it.
            # Compute aligned size and append to file
            padded = align(raw_size, FILE_ALIGNMENT)
            file_off = len(pe_bytes)
            pe_bytes.extend(bytes(padded))
            file_raw_size = padded

            # We also need to update the section header in the file.
            # Find this section header in the COFF section table and patch
            # PointerToRawData (offset 20) and SizeOfRawData (offset 16).
            coff_offset = skeleton.dos_header.addressof_new_exeheader
            sizeof_opt = skeleton.header.sizeof_optional_header
            sec_table_off = coff_offset + 24 + sizeof_opt  # COFF header = 24 bytes

            for idx, s in enumerate(skeleton.sections):
                if s.name == sec.name:
                    entry_off = sec_table_off + idx * 40
                    # SizeOfRawData at +16 (4 bytes LE)
                    pe_bytes[entry_off + 16 : entry_off + 20] = padded.to_bytes(4, "little")
                    # PointerToRawData at +20 (4 bytes LE)
                    pe_bytes[entry_off + 20 : entry_off + 24] = file_off.to_bytes(4, "little")
                    break

        # Patch content
        pe_bytes[file_off : file_off + raw_size] = src
        patched += 1
        print(f"[+] Patched {sec.name:8s}  fileoff=0x{file_off:05X}  "
              f"size={raw_size} into {file_raw_size} slot")

    OUTPUT_PE.write_bytes(bytes(pe_bytes))
    print(f"\n[*] Pass 2: patched {patched} sections ({len(pe_bytes)} bytes total)")

    # =========================================================
    # VERIFY
    # =========================================================
    print("\n" + "=" * 60)
    print("VERIFICATION")
    print("=" * 60)

    parsed = lief.PE.parse(str(OUTPUT_PE))
    if parsed is None:
        print("[!] FAIL: lief could not parse the final file!")
        return 1

    print(f"PE type:      {parsed.optional_header.magic}")
    print(f"Image base:   0x{parsed.optional_header.imagebase:X}")
    print(f"Entry point:  0x{parsed.optional_header.addressof_entrypoint:X}")
    print(f"Subsystem:    {parsed.optional_header.subsystem}")
    print(f"DLL:          {bool(parsed.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL))}")

    print(f"\nSections ({len(parsed.sections)}):")
    for sec in parsed.sections:
        chars_str = []
        if sec.has_characteristic(SCN_CNT_CODE):
            chars_str.append("CODE")
        if sec.has_characteristic(SCN_MEM_EXECUTE):
            chars_str.append("EXEC")
        if sec.has_characteristic(SCN_MEM_READ):
            chars_str.append("READ")
        if sec.has_characteristic(SCN_MEM_WRITE):
            chars_str.append("WRITE")
        if sec.has_characteristic(SCN_CNT_INITIALIZED_DATA):
            chars_str.append("IDATA")
        content = bytes(sec.content)
        nonzero = sum(1 for b in content[:256] if b != 0)
        print(f"  {sec.name:10s}  RVA=0x{sec.virtual_address:05X}  "
              f"VSize=0x{sec.virtual_size:05X}  "
              f"Raw=0x{sec.sizeof_raw_data:05X}  "
              f"[{', '.join(chars_str)}]  "
              f"content={len(content)}B (first256: {nonzero} nonzero)")

    print(f"\nImports:")
    for imp in parsed.imports:
        for entry in imp.entries:
            name = entry.name if entry.name else f"ord#{entry.data}"
            print(f"  {imp.name}!{name}")

    print("\n[*] Verification complete.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
