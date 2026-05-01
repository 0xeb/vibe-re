"""
extract_driver.py — Extract PROCEXP152.sys from handle64.exe PE resources

The driver is stored as a PE resource of type "BINRES", ID 0x67 (103).
This script parses the .rsrc section directly to avoid LoadLibraryEx issues.

Usage:
    python extract_driver.py <handle64.exe> <output.sys>
    python extract_driver.py C:\path\to\handle64.exe PROCEXP152.sys
"""

import struct
import sys
import os


def extract_binres(pe_path, resource_id=0x67):
    with open(pe_path, 'rb') as f:
        data = f.read()

    if data[:2] != b'MZ':
        print("Not a PE file")
        return None

    e_lfanew = struct.unpack_from('<I', data, 0x3C)[0]
    coff_off = e_lfanew + 4
    num_sections = struct.unpack_from('<H', data, coff_off + 2)[0]
    opt_hdr_size = struct.unpack_from('<H', data, coff_off + 16)[0]

    # Find .rsrc section
    sec_off = coff_off + 20 + opt_hdr_size
    rsrc_va = rsrc_raw = 0
    for i in range(num_sections):
        off = sec_off + i * 40
        name = data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
        vsize, vaddr, rawsize, rawaddr = struct.unpack_from('<IIII', data, off+8)
        if name == '.rsrc':
            rsrc_va = vaddr
            rsrc_raw = rawaddr
            break

    if rsrc_raw == 0:
        print("No .rsrc section found")
        return None

    def rva_to_raw(rva):
        return rva - rsrc_va + rsrc_raw

    def parse_dir(offset):
        base = rsrc_raw
        num_named = struct.unpack_from('<H', data, offset + 12)[0]
        num_id = struct.unpack_from('<H', data, offset + 14)[0]
        entries = []
        for i in range(num_named + num_id):
            eoff = offset + 16 + i * 8
            name_or_id, data_or_sub = struct.unpack_from('<II', data, eoff)

            if name_or_id & 0x80000000:
                noff = base + (name_or_id & 0x7FFFFFFF)
                nlen = struct.unpack_from('<H', data, noff)[0]
                ename = data[noff+2:noff+2+nlen*2].decode('utf-16-le', errors='replace')
            else:
                ename = name_or_id  # integer ID

            if data_or_sub & 0x80000000:
                sub = parse_dir(base + (data_or_sub & 0x7FFFFFFF))
                entries.append((ename, 'dir', sub))
            else:
                doff = base + data_or_sub
                drva, dsize = struct.unpack_from('<II', data, doff)
                entries.append((ename, 'data', drva, dsize))

            return entries

    tree = parse_dir(rsrc_raw)

    # Find BINRES type, then the requested ID
    for entry in tree:
        if entry[0] == 'BINRES' and entry[1] == 'dir':
            for sub in entry[2]:
                sub_id = sub[0] if isinstance(sub[0], int) else None
                if sub[1] == 'dir':
                    for leaf in sub[2]:
                        if leaf[1] == 'data':
                            raw_off = rva_to_raw(leaf[2])
                            return data[raw_off:raw_off + leaf[3]]
                elif sub[1] == 'data':
                    raw_off = rva_to_raw(sub[2])
                    return data[raw_off:raw_off + sub[3]]

    print("BINRES resource not found")
    return None


def main():
    if len(sys.argv) < 3:
        print("Usage: python extract_driver.py <handle64.exe> <output.sys>")
        sys.exit(1)

    driver_data = extract_binres(sys.argv[1])
    if driver_data is None:
        sys.exit(1)

    with open(sys.argv[2], 'wb') as f:
        f.write(driver_data)

    print(f"Extracted {len(driver_data)} bytes to {sys.argv[2]}")
    if driver_data[:2] == b'MZ':
        print("Valid PE (MZ header confirmed)")


if __name__ == '__main__':
    main()
