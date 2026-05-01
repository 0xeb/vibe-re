"""
diff_ntoskrnl.py — Compare live ntoskrnl dump vs on-disk PE

Usage:
    python diff_ntoskrnl.py <live_dump> <ondisk_pe>

The live dump comes from: procexp_client ntdump <outfile>
The on-disk PE is:         C:\Windows\System32\ntoskrnl.exe

The script parses both PE section tables, aligns sections by RVA,
and compares each section byte-by-byte. It also processes the
relocation table (.reloc) to distinguish relocation patches from
genuine data changes.
"""

import struct
import sys
import os

# ---------------------------------------------------------------------------
# PE parser (minimal, just what we need)
# ---------------------------------------------------------------------------

def parse_pe(data, label=""):
    if data[:2] != b'MZ':
        print(f"  [{label}] Not a PE (no MZ header)")
        return None

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    if data[e_lfanew:e_lfanew+4] != b'PE\x00\x00':
        print(f"  [{label}] Invalid PE signature")
        return None

    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff_off + 2)[0]
    opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]
    opt_off = coff_off + 20
    magic = struct.unpack_from('<H', data, opt_off)[0]
    is_pe32plus = (magic == 0x20B)

    image_base_off = opt_off + 24 if is_pe32plus else opt_off + 28
    image_base = struct.unpack_from('<Q' if is_pe32plus else '<I', data, image_base_off)[0]

    # Data directories
    dd_off = opt_off + (112 if is_pe32plus else 96)
    num_dd = struct.unpack_from('<I', data, dd_off - 4)[0]

    data_dirs = {}
    dd_names = ['Export','Import','Resource','Exception','Certificate','BaseReloc',
                'Debug','Architecture','GlobalPtr','TLS','LoadConfig','BoundImport',
                'IAT','DelayImport','CLR','Reserved']
    for i in range(min(num_dd, 16)):
        rva, size = struct.unpack_from('<II', data, dd_off + i*8)
        if size > 0:
            data_dirs[dd_names[i]] = (rva, size)

    # Sections
    sec_off = coff_off + 20 + opt_hdr_size
    sections = []
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize, vaddr, rawsize, rawaddr = struct.unpack_from('<IIII', data, off+8)
        chars = struct.unpack_from('<I', data, off+36)[0]
        sections.append({
            'name': name,
            'vaddr': vaddr,
            'vsize': vsize,
            'rawaddr': rawaddr,
            'rawsize': rawsize,
            'chars': chars,
        })

    return {
        'image_base': image_base,
        'is_pe32plus': is_pe32plus,
        'sections': sections,
        'data_dirs': data_dirs,
        'data': data,
    }


def parse_relocs(pe):
    """Parse .reloc section to get set of RVAs that have relocations."""
    if 'BaseReloc' not in pe['data_dirs']:
        return set()

    reloc_rva, reloc_size = pe['data_dirs']['BaseReloc']
    # Find the section containing this RVA
    reloc_raw = None
    for s in pe['sections']:
        if s['vaddr'] <= reloc_rva < s['vaddr'] + s['rawsize']:
            reloc_raw = s['rawaddr'] + (reloc_rva - s['vaddr'])
            break
    if reloc_raw is None:
        return set()

    data = pe['data']
    reloc_addrs = set()
    off = reloc_raw
    end = reloc_raw + reloc_size

    while off < end - 8:
        block_rva, block_size = struct.unpack_from('<II', data, off)
        if block_size == 0:
            break
        num_entries = (block_size - 8) // 2
        for i in range(num_entries):
            entry = struct.unpack_from('<H', data, off + 8 + i*2)[0]
            rtype = entry >> 12
            roffset = entry & 0xFFF
            if rtype == 10:  # IMAGE_REL_BASED_DIR64
                rva = block_rva + roffset
                # Mark 8 bytes at this RVA as relocated
                for b in range(8):
                    reloc_addrs.add(rva + b)
            elif rtype == 3:  # IMAGE_REL_BASED_HIGHLOW
                rva = block_rva + roffset
                for b in range(4):
                    reloc_addrs.add(rva + b)
        off += block_size

    return reloc_addrs


def get_section_data_by_rva(pe, rva, size):
    """Get raw bytes for a given RVA range from the PE."""
    for s in pe['sections']:
        if s['vaddr'] <= rva < s['vaddr'] + s['rawsize']:
            raw_off = s['rawaddr'] + (rva - s['vaddr'])
            avail = s['rawsize'] - (rva - s['vaddr'])
            return pe['data'][raw_off:raw_off + min(size, avail)]
    return None


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def compare_sections(live_pe, disk_pe, reloc_set):
    """Compare each section between live dump and on-disk PE."""

    print("\n" + "="*78)
    print("SECTION-BY-SECTION COMPARISON")
    print("="*78)

    # Build section map from disk PE
    disk_secs = {s['name']: s for s in disk_pe['sections']}

    for ls in live_pe['sections']:
        name = ls['name']
        ds = disk_secs.get(name)

        print(f"\n--- {name} ---")
        print(f"  Live:  RVA=0x{ls['vaddr']:08X}  VSize=0x{ls['vsize']:X}")

        if not ds:
            print(f"  Disk:  (not found)")
            continue

        print(f"  Disk:  RVA=0x{ds['vaddr']:08X}  VSize=0x{ds['vsize']:X}  RawSize=0x{ds['rawsize']:X}")

        # Get comparable data
        # Live dump: the data IS at the RVA offset (it's a mapped image)
        live_data = live_pe['data'][ls['vaddr']:ls['vaddr'] + ls['vsize']]
        # Disk: data is at raw offset
        disk_data = disk_pe['data'][ds['rawaddr']:ds['rawaddr'] + ds['rawsize']]

        # Truncate to minimum
        cmp_len = min(len(live_data), len(disk_data), ls['vsize'], ds['vsize'])
        if cmp_len == 0:
            print(f"  (no data to compare)")
            continue

        live_cmp = live_data[:cmp_len]
        disk_cmp = disk_data[:cmp_len]

        # Count diffs
        total_diffs = 0
        reloc_diffs = 0
        real_diffs = 0
        diff_offsets = []

        for i in range(cmp_len):
            if live_cmp[i] != disk_cmp[i]:
                total_diffs += 1
                rva = ls['vaddr'] + i
                if rva in reloc_set:
                    reloc_diffs += 1
                else:
                    real_diffs += 1
                    if len(diff_offsets) < 32:  # collect first 32 non-reloc diffs
                        diff_offsets.append(i)

        pct = (total_diffs / cmp_len * 100) if cmp_len > 0 else 0
        reloc_pct = (reloc_diffs / total_diffs * 100) if total_diffs > 0 else 0

        is_code = (ls['chars'] & 0x20000000) != 0  # IMAGE_SCN_MEM_EXECUTE
        is_write = (ls['chars'] & 0x80000000) != 0  # IMAGE_SCN_MEM_WRITE

        tag = ""
        if is_code: tag += " [CODE]"
        if is_write: tag += " [WRITABLE]"

        print(f"  Compared: {cmp_len:,} bytes{tag}")
        print(f"  Total diffs:       {total_diffs:,} ({pct:.2f}%)")
        print(f"    Due to relocs:   {reloc_diffs:,} ({reloc_pct:.1f}% of diffs)")
        print(f"    Genuine diffs:   {real_diffs:,}")

        if total_diffs == 0:
            print(f"  >> IDENTICAL")
        elif real_diffs == 0:
            print(f"  >> ALL DIFFS ARE RELOCATIONS (code is identical)")
        elif is_code and real_diffs > 0:
            print(f"  >> CODE MODIFIED! {real_diffs} non-relocation bytes differ")
        elif is_write:
            print(f"  >> EXPECTED: writable section, {real_diffs} live globals changed")

        # Show sample diffs (non-reloc only)
        if diff_offsets and real_diffs > 0:
            print(f"\n  Sample non-relocation diffs (first {min(len(diff_offsets), 16)}):")
            shown = 0
            i = 0
            while i < len(diff_offsets) and shown < 16:
                off = diff_offsets[i]
                rva = ls['vaddr'] + off
                # Show 8 bytes of context
                ctx = min(8, cmp_len - off)
                live_hex = ' '.join(f'{live_cmp[off+j]:02X}' for j in range(ctx))
                disk_hex = ' '.join(f'{disk_cmp[off+j]:02X}' for j in range(ctx))
                print(f"    RVA 0x{rva:08X}: disk=[{disk_hex}] live=[{live_hex}]")
                shown += 1
                # Skip consecutive bytes in the same diff region
                while i < len(diff_offsets) - 1 and diff_offsets[i+1] - diff_offsets[i] <= 8:
                    i += 1
                i += 1


def main():
    if len(sys.argv) < 3:
        print("Usage: python diff_ntoskrnl.py <live_dump> <ondisk_pe>")
        print("  live_dump:  output of 'procexp_client ntdump'")
        print("  ondisk_pe:  C:\\Windows\\System32\\ntoskrnl.exe")
        sys.exit(1)

    live_path = sys.argv[1]
    disk_path = sys.argv[2]

    print(f"Live dump: {live_path} ({os.path.getsize(live_path):,} bytes)")
    print(f"On-disk:   {disk_path} ({os.path.getsize(disk_path):,} bytes)")

    with open(live_path, 'rb') as f:
        live_data = f.read()
    with open(disk_path, 'rb') as f:
        disk_data = f.read()

    print(f"\nParsing live dump...")
    live_pe = parse_pe(live_data, "live")
    if not live_pe:
        sys.exit(1)

    print(f"Parsing on-disk PE...")
    disk_pe = parse_pe(disk_data, "disk")
    if not disk_pe:
        sys.exit(1)

    print(f"\nLive image base:  0x{live_pe['image_base']:X}")
    print(f"Disk image base:  0x{disk_pe['image_base']:X}")

    print(f"\nLive sections:")
    for s in live_pe['sections']:
        print(f"  {s['name']:8s}  RVA=0x{s['vaddr']:08X}  VSize=0x{s['vsize']:X}")
    print(f"\nDisk sections:")
    for s in disk_pe['sections']:
        chars = s['chars']
        flags = []
        if chars & 0x20000000: flags.append('X')
        if chars & 0x40000000: flags.append('R')
        if chars & 0x80000000: flags.append('W')
        print(f"  {s['name']:8s}  RVA=0x{s['vaddr']:08X}  VSize=0x{s['vsize']:X}  "
              f"Raw=0x{s['rawsize']:X}  {''.join(flags)}")

    print(f"\nParsing relocation table...")
    relocs = parse_relocs(disk_pe)
    print(f"  {len(relocs):,} relocated bytes")

    compare_sections(live_pe, disk_pe, relocs)

    print(f"\n{'='*78}")
    print("SUMMARY")
    print(f"{'='*78}")
    print(f"The live dump is the kernel image as mapped in memory.")
    print(f"Relocations are applied by the loader (ASLR) — these are expected diffs.")
    print(f"Genuine .data diffs are runtime globals (process lists, config, etc.).")
    print(f"Any genuine .text diffs would indicate patching (PatchGuard, hotpatching, etc.).")


if __name__ == '__main__':
    main()
