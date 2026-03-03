"""
Reconstruct valid PE32+ DLLs from ScatterBrain packed PE blob payloads.

Reads decompressed blob payloads from output/blobs/blob_N_payload.bin,
parses the sb_packed_pe_hdr, maps sections, decrypts imports, and builds
valid PE DLLs using lief (two-pass: skeleton + binary patch).

Packed PE Header Layout (0x38 bytes):
  [0x00] magic0          (u32) - XOR pair, magic0 ^ magic1 == 0x7C35D9A3
  [0x04] magic1          (u32) - XOR pair
  [0x08] size_of_image   (u32) - Virtual memory size
  [0x0C] flags           (u32) - Unknown flags (always 0)
  [0x10] unknown_10      (u32) - Always 0x80000000
  [0x14] unknown_14      (u32) - Always 0x00000001
  [0x18] reloc_dir_rva   (u32) - Relocation directory RVA
  [0x1C] reloc_dir_size  (u32) - Relocation directory size
  [0x20] import_desc_rva (u32) - Import descriptor table RVA
  [0x24] import_desc_size(u32) - Import descriptor table size
  [0x28] entry_point_rva (u32) - AddressOfEntryPoint
  [0x2C] pe_magic        (u16) - PE magic (0x020B = PE32+)
  [0x2E] unknown_2E      (u16) - Unknown (0x2022 in all samples)
  [0x30] num_sections    (u32) - Number of sections
  [0x34] timestamp       (u32) - PE TimeDateStamp

Section Table (at offset 0x38, 12 bytes per entry):
  [+0] dest_rva   (u32) - Destination RVA in virtual image
  [+4] src_offset (u32) - Source offset within blob data
  [+8] raw_size   (u32) - Raw data size in bytes

Rolling XOR Cipher (for import name decryption):
  - Key seeded from magic0
  - Per-byte: decrypted = encrypted ^ (key & 0xFF)
  - Key update: key = (key << 24) | (int8(enc_byte) + (key >> 8))
  - Key evolves across ALL names (not reset between DLLs/functions)
"""

import struct
import sys
import json
import os
from pathlib import Path

import lief

# Import shared modules
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sb_packed_pe import (
    parse_packed_header, build_mapped_image, extract_imports,
    HEADER_SIZE, SECTION_ENTRY_SIZE, MAGIC_XOR,
)

SCRIPT_DIR = Path(__file__).resolve().parent
ROOT_DIR = SCRIPT_DIR.parent
BLOB_DIR = ROOT_DIR / "output" / "blobs"

FILE_ALIGNMENT = 0x200

# lief section characteristics
SCN_CNT_CODE = lief.PE.Section.CHARACTERISTICS.CNT_CODE
SCN_MEM_EXECUTE = lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE
SCN_MEM_READ = lief.PE.Section.CHARACTERISTICS.MEM_READ
SCN_MEM_WRITE = lief.PE.Section.CHARACTERISTICS.MEM_WRITE
SCN_CNT_INITIALIZED_DATA = lief.PE.Section.CHARACTERISTICS.CNT_INITIALIZED_DATA


def align(value, alignment):
    return (value + alignment - 1) & ~(alignment - 1)


def reconstruct_pe(blob_idx, blob_data, output_dir):
    """Reconstruct a valid PE32+ DLL from packed blob data."""
    hdr = parse_packed_header(blob_data)
    if hdr is None:
        print(f"  [!] Invalid packed PE header")
        return None

    print(f"  Header: image=0x{hdr['size_of_image']:X} ep=0x{hdr['entry_point_rva']:X} "
          f"sections={hdr['num_sections']} ts=0x{hdr['timestamp']:X}")

    # Build mapped image
    img = build_mapped_image(blob_data, hdr)

    # Decrypt imports
    imports = extract_imports(
        img, hdr['import_desc_rva'], hdr['import_desc_size'], hdr['magic0']
    )

    for desc in imports['descriptors']:
        funcs = ', '.join(
            f['name'] if f['type'] == 'name' else f"ord#{f['ordinal']}"
            for f in desc['functions']
        )
        print(f"  Import: {desc['dll_name']} -> [{funcs}]")

    if not imports['descriptors']:
        print(f"  No imports")

    # Compute section layout
    sections_info = []
    for i, sec in enumerate(hdr['sections']):
        rva = sec['dest_rva']
        raw_size = sec['raw_size']

        # Determine virtual size (gap to next section or end of image)
        if i + 1 < len(hdr['sections']):
            next_rva = hdr['sections'][i + 1]['dest_rva']
        else:
            next_rva = hdr['size_of_image']
        vsize = next_rva - rva

        # First section is code, rest are data
        if i == 0:
            name = ".text"
            chars = SCN_CNT_CODE | SCN_MEM_EXECUTE | SCN_MEM_READ
        else:
            name = f".data{i}" if i > 1 else ".rdata"
            chars = SCN_CNT_INITIALIZED_DATA | SCN_MEM_READ | SCN_MEM_WRITE

        sections_info.append({
            'name': name, 'rva': rva, 'raw_size': raw_size,
            'vsize': vsize, 'chars': chars,
        })

    # ── PASS 1: Build PE skeleton ──
    factory = lief.PE.Factory.create(lief.PE.PE_TYPE.PE32_PLUS)

    for si in sections_info:
        sec = lief.PE.Section(si['name'])
        placeholder_size = align(max(si['raw_size'], 1), FILE_ALIGNMENT)
        sec.content = memoryview(bytes(placeholder_size))
        sec.virtual_address = si['rva']
        sec.virtual_size = si['vsize']
        sec.sizeof_raw_data = placeholder_size
        sec.characteristics = si['chars']
        factory.add_section(sec)

    pe = factory.get()
    if pe is None:
        print(f"  [!] Factory.get() returned None")
        return None

    pe.optional_header.imagebase = 0x180000000
    pe.optional_header.addressof_entrypoint = hdr['entry_point_rva']
    pe.optional_header.section_alignment = 0x1000
    pe.optional_header.file_alignment = FILE_ALIGNMENT
    pe.optional_header.subsystem = lief.PE.OptionalHeader.SUBSYSTEM.WINDOWS_GUI
    pe.optional_header.sizeof_image = hdr['size_of_image']
    pe.optional_header.dll_characteristics = (
        lief.PE.OptionalHeader.DLL_CHARACTERISTICS.DYNAMIC_BASE |
        lief.PE.OptionalHeader.DLL_CHARACTERISTICS.NX_COMPAT
    )
    pe.header.add_characteristic(lief.PE.Header.CHARACTERISTICS.DLL)
    pe.header.time_date_stamps = hdr['timestamp']

    # Add imports
    for desc in imports['descriptors']:
        lib = pe.add_import(desc['dll_name'])
        for func in desc['functions']:
            if func['type'] == 'name':
                lib.add_entry(func['name'])
            else:
                entry = lief.PE.ImportEntry(func['ordinal'], lief.PE.PE_TYPE.PE32_PLUS)
                lib.add_entry(entry)

    # Build and write skeleton
    out_path = output_dir / f"blob_{blob_idx}.dll"
    config = lief.PE.Builder.config_t()
    config.imports = bool(imports['descriptors'])
    builder = lief.PE.Builder(pe, config)
    builder.build()
    builder.write(str(out_path))

    # ── PASS 2: Patch actual section content ──
    skeleton = lief.PE.parse(str(out_path))
    if skeleton is None:
        print(f"  [!] Could not re-parse skeleton")
        return None

    pe_bytes = bytearray(out_path.read_bytes())
    our_names = {si['name'] for si in sections_info}

    for sec in skeleton.sections:
        if sec.name not in our_names:
            continue

        si = next(s for s in sections_info if s['name'] == sec.name)
        rva = si['rva']
        raw_size = si['raw_size']

        if raw_size == 0:
            continue

        src = img[rva:rva + raw_size]
        file_off = sec.pointerto_raw_data
        file_raw_size = sec.sizeof_raw_data

        if file_raw_size == 0:
            padded = align(raw_size, FILE_ALIGNMENT)
            file_off = len(pe_bytes)
            pe_bytes.extend(bytes(padded))
            file_raw_size = padded

            coff_offset = skeleton.dos_header.addressof_new_exeheader
            sizeof_opt = skeleton.header.sizeof_optional_header
            sec_table_off = coff_offset + 24 + sizeof_opt

            for idx, s in enumerate(skeleton.sections):
                if s.name == sec.name:
                    entry_off = sec_table_off + idx * 40
                    pe_bytes[entry_off + 16:entry_off + 20] = padded.to_bytes(4, 'little')
                    pe_bytes[entry_off + 20:entry_off + 24] = file_off.to_bytes(4, 'little')
                    break

        pe_bytes[file_off:file_off + raw_size] = src

    out_path.write_bytes(bytes(pe_bytes))

    # Build result summary
    result = {
        'name': f'blob_{blob_idx}',
        'output': str(out_path),
        'size_of_image': hdr['size_of_image'],
        'entry_point_rva': hdr['entry_point_rva'],
        'num_sections': hdr['num_sections'],
        'timestamp': hdr['timestamp'],
        'pe_size': len(pe_bytes),
        'imports': [
            {
                'dll': d['dll_name'],
                'functions': [
                    f['name'] if f['type'] == 'name' else f"ord#{f['ordinal']}"
                    for f in d['functions']
                ]
            }
            for d in imports['descriptors']
        ],
        'sections': [
            {
                'name': si['name'],
                'rva': si['rva'],
                'raw_size': si['raw_size'],
                'vsize': si['vsize'],
            }
            for si in sections_info
        ],
    }

    print(f"  [+] Written: {out_path} ({len(pe_bytes)} bytes)")
    return result


def main():
    results = []

    for i in range(8):
        payload_path = BLOB_DIR / f"blob_{i}_payload.bin"
        if not payload_path.exists():
            print(f"\n[!] blob_{i}: payload not found at {payload_path}")
            continue

        blob_data = payload_path.read_bytes()
        print(f"\n{'='*60}")
        print(f"[*] blob_{i}: {len(blob_data)} bytes")

        result = reconstruct_pe(i, blob_data, BLOB_DIR)
        if result:
            results.append(result)

    # Save summary
    summary_path = BLOB_DIR / "blob_pe_summary.json"
    with open(summary_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n{'='*60}")
    print(f"Summary saved to {summary_path}")

    # Print overview table
    print(f"\n{'='*60}")
    print(f"{'Name':8s} {'Image':>8s} {'EP RVA':>8s} {'Secs':>4s} {'Imports':>8s} {'PE Size':>8s}")
    print(f"{'-'*8} {'-'*8} {'-'*8} {'-'*4} {'-'*8} {'-'*8}")
    for r in results:
        imp_count = sum(len(d['functions']) for d in r['imports'])
        print(f"{r['name']:8s} 0x{r['size_of_image']:05X} 0x{r['entry_point_rva']:05X} "
              f"{r['num_sections']:4d} {imp_count:8d} {r['pe_size']:8d}")


if __name__ == '__main__':
    main()
