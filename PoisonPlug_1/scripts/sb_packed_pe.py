"""
ScatterBrain Packed PE format parser — shared library module.

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

Usage:
    from sb_packed_pe import parse_packed_header, build_mapped_image, extract_imports
"""
import struct
from sb_ciphers import import_xor_decrypt_name

__all__ = [
    'MAGIC_XOR',
    'HEADER_SIZE',
    'SECTION_ENTRY_SIZE',
    'parse_packed_header',
    'build_mapped_image',
    'extract_imports',
]

MAGIC_XOR = 0x7C35D9A3
HEADER_SIZE = 0x38
SECTION_ENTRY_SIZE = 12


def parse_packed_header(data: bytes) -> dict | None:
    """Parse sb_packed_pe_hdr from raw blob data.

    Args:
        data: Raw packed PE blob bytes

    Returns:
        Parsed header dict with 'sections' list, or None if invalid
    """
    if len(data) < HEADER_SIZE:
        return None

    magic0 = struct.unpack_from('<I', data, 0x00)[0]
    magic1 = struct.unpack_from('<I', data, 0x04)[0]

    if (magic0 ^ magic1) != MAGIC_XOR:
        return None

    hdr = {
        'magic0':          magic0,
        'magic1':          magic1,
        'size_of_image':   struct.unpack_from('<I', data, 0x08)[0],
        'flags':           struct.unpack_from('<I', data, 0x0C)[0],
        'unknown_10':      struct.unpack_from('<I', data, 0x10)[0],
        'unknown_14':      struct.unpack_from('<I', data, 0x14)[0],
        'reloc_dir_rva':   struct.unpack_from('<I', data, 0x18)[0],
        'reloc_dir_size':  struct.unpack_from('<I', data, 0x1C)[0],
        'import_desc_rva': struct.unpack_from('<I', data, 0x20)[0],
        'import_desc_size':struct.unpack_from('<I', data, 0x24)[0],
        'entry_point_rva': struct.unpack_from('<I', data, 0x28)[0],
        'pe_magic':        struct.unpack_from('<H', data, 0x2C)[0],
        'unknown_2E':      struct.unpack_from('<H', data, 0x2E)[0],
        'num_sections':    struct.unpack_from('<I', data, 0x30)[0],
        'timestamp':       struct.unpack_from('<I', data, 0x34)[0],
    }

    sections = []
    for i in range(hdr['num_sections']):
        off = HEADER_SIZE + i * SECTION_ENTRY_SIZE
        if off + SECTION_ENTRY_SIZE > len(data):
            break
        dest_rva  = struct.unpack_from('<I', data, off + 0)[0]
        src_off   = struct.unpack_from('<I', data, off + 4)[0]
        raw_size  = struct.unpack_from('<I', data, off + 8)[0]
        sections.append({
            'dest_rva': dest_rva,
            'src_offset': src_off,
            'raw_size': raw_size,
        })
    hdr['sections'] = sections

    return hdr


def build_mapped_image(blob_data: bytes, hdr: dict) -> bytes:
    """Build flat mapped image from section data.

    Args:
        blob_data: Raw packed PE blob
        hdr: Parsed header from parse_packed_header()

    Returns:
        Flat memory image with sections placed at their RVAs
    """
    img = bytearray(hdr['size_of_image'])

    for sec in hdr['sections']:
        rva = sec['dest_rva']
        src = sec['src_offset']
        size = sec['raw_size']
        if size == 0:
            continue
        if src + size > len(blob_data):
            size = len(blob_data) - src
        if rva + size > len(img):
            size = len(img) - rva
        img[rva:rva + size] = blob_data[src:src + size]

    return bytes(img)


def extract_imports(img: bytes, import_desc_rva: int, import_desc_size: int,
                    key_seed: int) -> dict:
    """Walk import descriptors, decrypt DLL/function names.

    Args:
        img: Flat mapped image
        import_desc_rva: RVA of import descriptor table
        import_desc_size: Size of import descriptor table
        key_seed: Initial XOR key (from sb_packed_pe_hdr.magic0)

    Returns:
        Dict with 'descriptors' list, 'key_seed', 'key_final'
    """
    if not import_desc_rva or not import_desc_size:
        return {'descriptors': [], 'key_seed': key_seed, 'key_final': key_seed}

    descriptors = []
    key = key_seed
    desc_off = import_desc_rva
    max_name_len = 260

    while desc_off + 20 <= len(img):
        desc = struct.unpack_from('<IIIII', img, desc_off)
        ilt_rva = desc[0]
        if ilt_rva == 0:
            break

        name_rva = desc[3]

        if name_rva < len(img):
            enc_data = img[name_rva:min(name_rva + max_name_len, len(img))]
            dll_name, key = import_xor_decrypt_name(enc_data, key)
        else:
            dll_name = f"unknown_{name_rva:X}"

        functions = []
        iat_off = ilt_rva
        while iat_off + 8 <= len(img):
            iat_val = struct.unpack_from('<Q', img, iat_off)[0]
            if iat_val == 0:
                break

            if iat_val & (1 << 63):
                ordinal = iat_val & 0xFFFF
                functions.append({'type': 'ordinal', 'ordinal': ordinal})
            else:
                name_off = iat_val & 0xFFFFFFFF
                if name_off + 2 < len(img):
                    hint = struct.unpack_from('<H', img, name_off)[0]
                    enc_func = img[name_off + 2:min(name_off + 2 + max_name_len, len(img))]
                    func_name, key = import_xor_decrypt_name(enc_func, key)
                    functions.append({
                        'type': 'name', 'name': func_name, 'hint': hint
                    })

            iat_off += 8

        descriptors.append({
            'dll_name': dll_name,
            'thunk_rva': desc[4],
            'functions': functions,
        })
        desc_off += 20

    return {
        'descriptors': descriptors,
        'key_seed': key_seed,
        'key_final': key,
    }
