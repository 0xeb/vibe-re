"""
ScatterBrain IMUL Stream Cipher + LZ77 Decompressor for Encrypted Data Blobs.

IMUL cipher (from decoded shellcode at RVA 0x1C010):
  - 4 round key states, all initialized to master key
  - For each byte at index i:
    1. round = i % 4
    2. k[round] = constant[round] - k[round] * multiplier[round] (mod 2^32)
    3. Accumulator: acc -= k.byte0; acc ^= k.byte1; acc -= k.byte2; acc ^= k.byte3
    4. output[i] = input[i] ^ acc

LZ77 (from lz_decompress at 0x1800039C0):
  - Bitstream-driven with 4096-entry hash table
  - Control word: 32-bit, each bit = match(1) or literal(0)
  - Match: 12-bit hash index + 4-bit length (or extended byte length)
  - Literal: 1-4 bytes copied from compressed stream
"""
import struct, sys, os, json, socket
from pathlib import Path

# Import shared cipher module
sys.path.insert(0, str(Path(__file__).resolve().parent))
from sb_ciphers import imul_cipher

# ── LZ77 decompressor ───────────────────────────────────────────

# Literal count lookup table (indexed by shift_reg & 0xF)
LIT_COUNT = [4, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0]

def hash12(val):
    return ((val & 0xFFFF) ^ ((val >> 12) & 0xFFFF)) & 0xFFF

def lz_decompress(compressed: bytes, decompressed_size: int) -> bytes:
    """Decompress LZ77 data matching ScatterBrain's lz_decompress."""
    fmt_byte = compressed[0]
    if (fmt_byte & 2) == 2:
        size_width = 4
    else:
        size_width = 1

    data_start = 1 + 2 * size_width
    output = bytearray(decompressed_size + 16)  # extra padding for DWORD writes
    hash_table = [0] * 4096  # position pointers
    last_hashed = -1  # v22 equivalent

    cp = data_start  # compressed pointer
    op = 0           # output pointer
    shift_reg = 1    # triggers first control word read
    safe_end = decompressed_size - 11

    def read_u32(offset):
        if offset + 4 <= len(compressed):
            return struct.unpack_from('<I', compressed, offset)[0]
        return 0

    def update_hash_table(up_to):
        nonlocal last_hashed
        while last_hashed < up_to:
            last_hashed += 1
            if last_hashed + 3 < len(output):
                val = struct.unpack_from('<I', output, last_hashed)[0]
                h = hash12(val)
                hash_table[h] = last_hashed

    # Main loop (safe zone)
    while op < safe_end:
        if shift_reg == 1:
            shift_reg = read_u32(cp)
            cp += 4

        cur_dword = read_u32(cp)

        if shift_reg & 1:  # Match
            shift_reg >>= 1
            hash_idx = (cur_dword >> 4) & 0xFFF
            length_ind = cur_dword & 0xF

            if length_ind:
                match_len = length_ind + 2
                cp += 2
            else:
                match_len = compressed[cp + 2] if cp + 2 < len(compressed) else 0
                cp += 3

            # Copy from hash table position
            src_pos = hash_table[hash_idx]
            for j in range(match_len):
                if src_pos + j < len(output) and op + j < len(output):
                    output[op + j] = output[src_pos + j]

            # Update hash table for positions we just wrote
            old_op = op
            op += match_len
            update_hash_table(old_op)
            last_hashed = op - 1

        else:  # Literal(s)
            num_lits = LIT_COUNT[shift_reg & 0xF]
            # Write up to 4 bytes from compressed stream
            for j in range(min(4, num_lits)):
                if op + j < len(output) and cp + j < len(compressed):
                    output[op + j] = compressed[cp + j]

            update_hash_table(op + num_lits - 3)
            op += num_lits
            cp += num_lits
            shift_reg >>= num_lits

    # Tail loop (byte-at-a-time)
    while op < decompressed_size:
        if shift_reg == 1:
            cp += 4  # skip control word
            shift_reg = 0x80000000

        if cp < len(compressed):
            output[op] = compressed[cp]
        cp += 1
        op += 1
        shift_reg >>= 1

    return bytes(output[:decompressed_size])

# ── Blob extraction ──────────────────────────────────────────────

BLOBS = [
    ("blob_0", 0x70E0,  8214),
    ("blob_1", 0x9100,  8873),
    ("blob_2", 0xB3B0,  8113),
    ("blob_3", 0xD370, 16466),
    ("blob_4", 0x113D0, 5223),
    ("blob_5", 0x12840, 10002),
    ("blob_6", 0x14F60, 12027),
    ("blob_7", 0x17E60, 11464),
]

def rva_to_file_offset(pe_data, rva):
    e_lfanew = struct.unpack_from('<I', pe_data, 0x3C)[0]
    num_secs = struct.unpack_from('<H', pe_data, e_lfanew + 6)[0]
    opt_size = struct.unpack_from('<H', pe_data, e_lfanew + 20)[0]
    sec_start = e_lfanew + 24 + opt_size
    for i in range(num_secs):
        off = sec_start + i * 40
        sec_rva = struct.unpack_from('<I', pe_data, off + 12)[0]
        sec_vsize = struct.unpack_from('<I', pe_data, off + 8)[0]
        sec_rawptr = struct.unpack_from('<I', pe_data, off + 20)[0]
        if sec_rva <= rva < sec_rva + sec_vsize:
            return sec_rawptr + (rva - sec_rva)
    return None

def main():
    base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    inner_pe_path = os.path.join(base, "output", "inner_pe.dll.pe")
    output_dir = os.path.join(base, "output", "blobs")
    os.makedirs(output_dir, exist_ok=True)

    with open(inner_pe_path, 'rb') as f:
        pe = f.read()

    results = []

    for name, rva, total_size in BLOBS:
        file_off = rva_to_file_offset(pe, rva)
        if file_off is None:
            print(f"[!] {name}: Cannot map RVA 0x{rva:X}")
            continue

        blob = pe[file_off:file_off + total_size]
        if len(blob) < 20:
            print(f"[!] {name}: Too small ({len(blob)} bytes)")
            continue

        # Step 1: Extract key
        raw_key = struct.unpack_from('>I', blob, 0)[0]
        print(f"\n{'='*60}")
        print(f"[*] {name}: RVA=0x{rva:X}, size={total_size}, key=0x{raw_key:08X}")

        # Step 2: Decrypt 20-byte header
        header_dec = imul_cipher(blob, 20, raw_key)
        hdr_field4 = struct.unpack_from('>I', header_dec, 4)[0]
        hdr_field8 = struct.unpack_from('>I', header_dec, 8)[0]
        hdr_comp   = struct.unpack_from('>I', header_dec, 12)[0]
        hdr_decomp = struct.unpack_from('>I', header_dec, 16)[0]
        is_compressed_flag = (hdr_field4 & 0x8000) != 0

        print(f"    Magic=0x{hdr_field4:08X} field8=0x{hdr_field8:02X} "
              f"comp_size={hdr_comp} decomp_size={hdr_decomp}")

        if hdr_field4 != 0x650001:
            print(f"    [-] Magic check FAILED")
            continue
        print(f"    [+] Magic 0x650001 validated")

        # Step 3: Decrypt full payload
        decrypt_size = hdr_comp + 20
        if decrypt_size > total_size:
            decrypt_size = total_size
        full_dec = imul_cipher(blob, decrypt_size, raw_key)

        # Step 4: Decompress if needed
        payload_data = full_dec[20:]
        needs_decomp = (hdr_comp != hdr_decomp)

        result = {
            "name": name,
            "rva": f"0x{rva:X}",
            "total_size": total_size,
            "key": f"0x{raw_key:08X}",
            "magic": f"0x{hdr_field4:08X}",
            "field8": f"0x{hdr_field8:02X}",
            "compressed_size": hdr_comp,
            "decompressed_size": hdr_decomp,
        }

        if needs_decomp:
            print(f"    LZ77 decompression: {hdr_comp} -> {hdr_decomp} bytes...")
            try:
                decompressed = lz_decompress(payload_data, hdr_decomp)
                print(f"    [+] Decompressed OK: {len(decompressed)} bytes")

                # Build final output: 20-byte header + decompressed data
                final = bytearray(20 + len(decompressed))
                final[:20] = full_dec[:20]
                # Update compressed size in header to match decompressed size
                struct.pack_into('>I', final, 12, hdr_decomp)
                final[20:] = decompressed
                payload_data = decompressed
                result["decompression"] = "success"
            except Exception as e:
                print(f"    [-] Decompression failed: {e}")
                result["decompression"] = f"failed: {e}"
                # Save raw decrypted data for manual inspection
                out_path = os.path.join(output_dir, f"{name}_decrypted_raw.bin")
                with open(out_path, 'wb') as f:
                    f.write(full_dec)
                result["raw_output"] = out_path
                results.append(result)
                continue
        else:
            print(f"    No decompression needed (sizes equal)")

        # Analyze payload
        out_path = os.path.join(output_dir, f"{name}_payload.bin")
        with open(out_path, 'wb') as f:
            f.write(payload_data)
        print(f"    Saved payload ({len(payload_data)} bytes) -> {out_path}")
        result["output"] = out_path

        # Check for ScatterBrain packed PE format
        if len(payload_data) >= 0x38:
            # sb_packed_pe_hdr: magic0 ^ magic1 == 0x7C35D9A3
            magic0 = struct.unpack_from('<I', payload_data, 0)[0]
            magic1 = struct.unpack_from('<I', payload_data, 4)[0]
            xor_magic = magic0 ^ magic1

            if xor_magic == 0x7C35D9A3:
                print(f"    [!] ScatterBrain packed PE detected! (magic0=0x{magic0:08X})")
                ep_rva = struct.unpack_from('<I', payload_data, 0x10)[0]
                img_size = struct.unpack_from('<I', payload_data, 0x14)[0]
                num_secs = struct.unpack_from('<H', payload_data, 0x2C)[0]
                print(f"        EntryPoint RVA: 0x{ep_rva:X}")
                print(f"        Image size: 0x{img_size:X} ({img_size} bytes)")
                print(f"        Sections: {num_secs}")
                result["type"] = "ScatterBrain packed PE"
                result["entry_point_rva"] = f"0x{ep_rva:X}"
                result["image_size"] = img_size
                result["num_sections"] = num_secs
            else:
                # Check for MZ header
                if payload_data[:2] == b'MZ':
                    print(f"    [!] MZ PE header detected!")
                    result["type"] = "PE"
                else:
                    print(f"    Payload header: {payload_data[:32].hex()}")
                    result["type"] = "unknown"
        else:
            print(f"    Payload too small for header analysis")
            result["type"] = "small"

        results.append(result)

    # Save summary
    summary_path = os.path.join(output_dir, "blob_analysis.json")
    with open(summary_path, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\n{'='*60}")
    print(f"Summary saved to {summary_path}")

    # Print overview
    print(f"\n{'='*60}")
    print("OVERVIEW:")
    for r in results:
        typ = r.get("type", "?")
        print(f"  {r['name']}: {typ} (comp={r['compressed_size']}, "
              f"decomp={r['decompressed_size']})")

if __name__ == '__main__':
    main()
