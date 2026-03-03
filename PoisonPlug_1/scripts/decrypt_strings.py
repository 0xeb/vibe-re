"""
ScatterBrain encrypted string decryptor — works with inner PE and all plugin blobs.

Cipher: Rolling polynomial XOR (from sb_ciphers module)
  - 2-byte little-endian key seed at blob start
  - plaintext_byte = (key & 0xFF) ^ encrypted_byte  (XOR BEFORE key update!)
  - key = (-42860544 * key) - (135791246 * HIWORD(key)) - 1043215206 (mod 2^32)

Usage:
    python scripts/decrypt_strings.py                                        # inner PE known blobs
    python scripts/decrypt_strings.py --image output/blobs/blob_0.dll        # any PE DLL
    python scripts/decrypt_strings.py --image output/mapped_image.bin --rva 0x6010  # single RVA
    python scripts/decrypt_strings.py --scan                                 # scan for encrypted blobs
    python scripts/decrypt_strings.py --json                                 # JSON output
    python scripts/decrypt_strings.py --idasql 8200 --scan                   # scan via idasql
"""
import argparse
import json
import struct
import sys
from pathlib import Path

# Import shared cipher module
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sb_ciphers import poly_xor_decrypt, poly_xor_decrypt_blob

IMAGE_BASE = 0x180000000
ROOT_DIR = Path(__file__).resolve().parent.parent
DEFAULT_IMAGE = ROOT_DIR / "output" / "mapped_image.bin"

# Known blob RVAs for the inner PE (mapped_image.bin)
INNER_PE_BLOBS = [
    0x06010, 0x06020, 0x06030, 0x06040, 0x06050, 0x06068, 0x06078,
    0x06090, 0x060B0, 0x060C8, 0x060E0, 0x060F0,
    0x1AB70, 0x1AB80, 0x1ABC0, 0x1ABD0, 0x1ABE0, 0x1ABF0,
    0x1AC00, 0x1AC10, 0x1AC28, 0x1AC40, 0x1AC58, 0x1AC70,
    0x1AC88, 0x1AC98, 0x1ACB0, 0x1ACC8, 0x1ACE0, 0x1ACF0,
    0x1AD20, 0x1AD30, 0x1AD40, 0x1AD58,
]


def decrypt_blob_at_rva(image_data: bytes, rva: int, max_len: int = 4092) -> str:
    """Decrypt a single encrypted string blob at the given RVA offset."""
    return poly_xor_decrypt_blob(image_data[rva:], max_len)


def rva_to_file_offset(pe_data: bytes, rva: int) -> int | None:
    """Convert RVA to file offset in a PE file."""
    if len(pe_data) < 0x40:
        return None
    if pe_data[:2] != b'MZ':
        return rva  # raw image, RVA == offset
    e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
    if e_lfanew + 24 > len(pe_data):
        return None
    num_secs = struct.unpack_from('<H', pe_data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from('<H', pe_data, e_lfanew + 20)[0]
    sec_start = e_lfanew + 24 + opt_size
    for i in range(num_secs):
        off = sec_start + i * 40
        if off + 40 > len(pe_data):
            break
        sec_rva = struct.unpack_from('<I', pe_data, off + 12)[0]
        sec_vsize = struct.unpack_from('<I', pe_data, off + 8)[0]
        sec_rawptr = struct.unpack_from('<I', pe_data, off + 20)[0]
        sec_rawsize = struct.unpack_from('<I', pe_data, off + 16)[0]
        if sec_rva <= rva < sec_rva + max(sec_vsize, sec_rawsize):
            return sec_rawptr + (rva - sec_rva)
    return None


def scan_for_encrypted_blobs(image_data: bytes, is_pe: bool = False,
                              pe_data: bytes = None, min_len: int = 3,
                              max_len: int = 256) -> list:
    """Scan image for potential encrypted string blobs.

    Heuristic: look for short sequences where decryption produces printable ASCII.
    Scans .rdata-like regions for 2-byte key prefix + encrypted data that decrypts
    to printable ASCII strings of at least min_len characters.
    """
    results = []
    scan_data = image_data

    # For PE files, find .rdata section bounds
    sections = []
    if is_pe and pe_data and pe_data[:2] == b'MZ':
        e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
        num_secs = struct.unpack_from('<H', pe_data, e_lfanew + 6)[0]
        opt_size = struct.unpack_from('<H', pe_data, e_lfanew + 20)[0]
        sec_start = e_lfanew + 24 + opt_size
        for i in range(num_secs):
            off = sec_start + i * 40
            if off + 40 > len(pe_data):
                break
            name = pe_data[off:off+8].rstrip(b'\x00').decode('ascii', errors='replace')
            sec_rva = struct.unpack_from('<I', pe_data, off + 12)[0]
            sec_rawptr = struct.unpack_from('<I', pe_data, off + 20)[0]
            sec_rawsize = struct.unpack_from('<I', pe_data, off + 16)[0]
            sections.append({
                'name': name, 'rva': sec_rva,
                'file_off': sec_rawptr, 'file_size': sec_rawsize,
            })

    # Determine scan regions (prefer .rdata/.data sections)
    scan_ranges = []
    if sections:
        for sec in sections:
            if any(n in sec['name'].lower() for n in ('rdata', 'data')):
                start = sec['file_off']
                end = start + sec['file_size']
                rva_base = sec['rva']
                scan_ranges.append((start, end, rva_base - sec['file_off']))
    if not scan_ranges:
        # Scan entire image
        scan_ranges = [(0, len(scan_data), 0)]

    for range_start, range_end, rva_delta in scan_ranges:
        offset = range_start
        while offset < range_end - 4:
            try:
                plaintext = poly_xor_decrypt_blob(scan_data[offset:offset + max_len + 2])
                if len(plaintext) >= min_len and all(
                    32 <= ord(c) < 127 for c in plaintext
                ):
                    rva = offset + rva_delta
                    key_seed = scan_data[offset] | (scan_data[offset + 1] << 8)
                    results.append({
                        'rva': rva,
                        'file_offset': offset,
                        'key_seed': key_seed,
                        'decrypted': plaintext,
                        'length': len(plaintext),
                    })
                    offset += 2 + len(plaintext) + 1  # skip past this blob
                    continue
            except (ValueError, IndexError):
                pass
            offset += 1

    # Deduplicate and sort
    seen = set()
    unique = []
    for r in results:
        if r['rva'] not in seen:
            seen.add(r['rva'])
            unique.append(r)
    return sorted(unique, key=lambda x: x['rva'])


def decrypt_via_idasql(port: int, rvas: list) -> list:
    """Decrypt encrypted strings by reading bytes from idasql server.

    Args:
        port: idasql HTTP port
        rvas: List of RVAs (as VA addresses) to decrypt

    Returns:
        List of result dicts
    """
    try:
        import requests
    except ImportError:
        # Fall back to curl
        import subprocess
        results = []
        for rva in rvas:
            cmd = f'curl -s http://127.0.0.1:{port}/query -d "SELECT bytes(0x{rva:X}, 256)"'
            p = subprocess.run(cmd, capture_output=True, text=True, shell=True)
            try:
                data = json.loads(p.stdout)
                if data.get('success') and data['rows']:
                    hex_str = data['rows'][0][0]
                    raw = bytes.fromhex(hex_str)
                    plaintext = poly_xor_decrypt_blob(raw)
                    key_seed = raw[0] | (raw[1] << 8)
                    results.append({
                        'va': f'0x{rva:X}',
                        'key_seed': f'0x{key_seed:04X}',
                        'decrypted': plaintext,
                    })
            except (json.JSONDecodeError, ValueError, IndexError):
                results.append({'va': f'0x{rva:X}', 'error': 'failed to read/decrypt'})
        return results

    url = f"http://127.0.0.1:{port}/query"
    results = []
    for rva in rvas:
        try:
            resp = requests.post(url, data=f"SELECT bytes(0x{rva:X}, 256)")
            data = resp.json()
            if data.get('success') and data['rows']:
                hex_str = data['rows'][0][0]
                raw = bytes.fromhex(hex_str)
                plaintext = poly_xor_decrypt_blob(raw)
                key_seed = raw[0] | (raw[1] << 8)
                results.append({
                    'va': f'0x{rva:X}',
                    'key_seed': f'0x{key_seed:04X}',
                    'decrypted': plaintext,
                })
        except Exception as e:
            results.append({'va': f'0x{rva:X}', 'error': str(e)})
    return results


def load_image(path: Path) -> bytes:
    """Load PE image or raw mapped image."""
    data = path.read_bytes()
    print(f"Loaded {len(data)} bytes from {path}", file=sys.stderr)
    return data


def main():
    parser = argparse.ArgumentParser(
        description="ScatterBrain string decryptor (inner PE + plugins)")
    parser.add_argument("--image", type=Path, default=None,
                        help="PE DLL or mapped image (default: output/mapped_image.bin)")
    parser.add_argument("--rva", type=lambda x: int(x, 0),
                        help="Decrypt single blob at RVA (file offset or VA)")
    parser.add_argument("--va", type=lambda x: int(x, 0),
                        help="Decrypt single blob at VA (0x180000000-based)")
    parser.add_argument("--scan", action="store_true",
                        help="Scan for encrypted blobs automatically")
    parser.add_argument("--idasql", type=int, metavar="PORT",
                        help="Read bytes from idasql HTTP server instead of file")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--min-len", type=int, default=3,
                        help="Minimum string length for scan mode (default: 3)")
    args = parser.parse_args()

    # Handle idasql mode
    if args.idasql:
        if args.va:
            results = decrypt_via_idasql(args.idasql, [args.va])
        elif args.rva:
            va = IMAGE_BASE + args.rva
            results = decrypt_via_idasql(args.idasql, [va])
        else:
            print("idasql mode requires --rva or --va", file=sys.stderr)
            sys.exit(1)
        if args.json:
            sys.stdout.buffer.write(json.dumps(results, indent=2).encode('utf-8'))
        else:
            for r in results:
                if 'error' in r:
                    print(f"{r['va']} -> ERROR: {r['error']}")
                else:
                    print(f"{r['va']} (key=0x{r['key_seed']}) -> {r['decrypted']}")
        return

    # Determine image path
    image_path = args.image or DEFAULT_IMAGE
    image_data = load_image(image_path)

    # Detect if this is a PE file
    is_pe = image_data[:2] == b'MZ'

    # Convert VA to RVA if needed
    if args.va:
        rva = args.va - IMAGE_BASE
        if is_pe:
            file_off = rva_to_file_offset(image_data, rva)
            if file_off is None:
                print(f"Cannot map VA 0x{args.va:X} (RVA 0x{rva:X})", file=sys.stderr)
                sys.exit(1)
            plaintext = poly_xor_decrypt_blob(image_data[file_off:])
        else:
            plaintext = poly_xor_decrypt_blob(image_data[rva:])
        if args.json:
            print(json.dumps({"va": f"0x{args.va:X}", "decrypted": plaintext}))
        else:
            print(f"VA 0x{args.va:X} -> {plaintext}")
        return

    # Single RVA mode
    if args.rva is not None:
        if is_pe:
            file_off = rva_to_file_offset(image_data, args.rva)
            if file_off is None:
                print(f"Cannot map RVA 0x{args.rva:X}", file=sys.stderr)
                sys.exit(1)
            plaintext = poly_xor_decrypt_blob(image_data[file_off:])
        else:
            plaintext = poly_xor_decrypt_blob(image_data[args.rva:])
        if args.json:
            print(json.dumps({"rva": f"0x{args.rva:X}", "decrypted": plaintext}))
        else:
            print(f"RVA 0x{args.rva:05X} -> {plaintext}")
        return

    # Scan mode
    if args.scan:
        print(f"Scanning {image_path.name} for encrypted blobs...", file=sys.stderr)
        results = scan_for_encrypted_blobs(
            image_data, is_pe=is_pe, pe_data=image_data if is_pe else None,
            min_len=args.min_len,
        )
        if args.json:
            json_results = [
                {'rva': f'0x{r["rva"]:X}', 'key_seed': f'0x{r["key_seed"]:04X}',
                 'decrypted': r['decrypted'], 'length': r['length']}
                for r in results
            ]
            sys.stdout.buffer.write(json.dumps(json_results, indent=2).encode('utf-8'))
            sys.stdout.buffer.write(b'\n')
        else:
            print(f"{'RVA':<10} {'Key':<8} {'Len':>4}  {'Decrypted'}")
            print("-" * 70)
            for r in results:
                print(f"0x{r['rva']:05X}  0x{r['key_seed']:04X}  {r['length']:4d}  {r['decrypted']}")
            print(f"\nFound {len(results)} encrypted strings")
        return

    # Default: inner PE known blobs
    if not is_pe and image_path == DEFAULT_IMAGE:
        results = []
        for rva in INNER_PE_BLOBS:
            try:
                plaintext = poly_xor_decrypt_blob(image_data[rva:])
                results.append({
                    "rva": f"0x{rva:05X}",
                    "va": f"0x{IMAGE_BASE + rva:X}",
                    "decrypted": plaintext,
                })
            except Exception as e:
                results.append({
                    "rva": f"0x{rva:05X}",
                    "va": f"0x{IMAGE_BASE + rva:X}",
                    "error": str(e),
                })

        if args.json:
            sys.stdout.buffer.write(json.dumps(results, indent=2).encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
        else:
            lines = [f"{'RVA':<10} {'VA':<18} {'Decrypted'}", "-" * 60]
            for r in results:
                if "error" in r:
                    lines.append(f"{r['rva']:<10} {r['va']:<18} ERROR: {r['error']}")
                else:
                    lines.append(f"{r['rva']:<10} {r['va']:<18} {r['decrypted']}")
            lines.append(f"\nTotal: {len([r for r in results if 'decrypted' in r])} strings decrypted")
            sys.stdout.buffer.write("\n".join(lines).encode("utf-8"))
            sys.stdout.buffer.write(b"\n")
    else:
        # For any other image, default to scan mode
        print(f"No known blob list for {image_path.name}, use --scan to search", file=sys.stderr)
        print(f"  Example: python {sys.argv[0]} --image {image_path} --scan", file=sys.stderr)


if __name__ == "__main__":
    main()
