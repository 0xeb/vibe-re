"""
ScatterBrain cipher implementations — shared library module.

Three cipher systems used across the ScatterBrain loader chain:

1. IMUL Stream Cipher — large blob encryption/decryption
   Used by: worker_thread_entry (inner PE) for C2 plugin blobs
   Source: decoded shellcode at RVA 0x1C010

2. Rolling Polynomial XOR — encrypted string decryption
   Used by: decrypt_string (0x1800045B8) in inner PE and all plugins
   Pattern: lazy-resolved function pointers, 2-byte LE key seed prefix

3. Rolling XOR — PE import name decryption
   Used by: reflective_loader during packed PE loading
   Key seeded from sb_packed_pe_hdr.magic0, evolves across all names

Usage:
    from sb_ciphers import (
        imul_cipher,
        poly_xor_decrypt,
        import_xor_decrypt_name,
        import_xor_key_update,
    )
"""
import struct

__all__ = [
    'imul_cipher',
    'poly_xor_decrypt',
    'poly_xor_decrypt_blob',
    'import_xor_key_update',
    'import_xor_decrypt_name',
]


# ══════════════════════════════════════════════════════════════
# 1. IMUL Stream Cipher (large blob encryption)
# ══════════════════════════════════════════════════════════════
#
# 4 round key states, each initialized to master key.
# For each byte at index i:
#   round = i % 4
#   k[round] = constant[round] - k[round] * multiplier[round]  (mod 2^32)
#   Accumulator: acc -= k.byte0; acc ^= k.byte1; acc -= k.byte2; acc ^= k.byte3
#   output[i] = input[i] ^ acc

IMUL_ROUNDS = [
    (0xCA1A5842, 0x563446B7),
    (0x5F7B88D1, 0x2D93E75E),
    (0xAD5BC1C9, 0x7992708E),
    (0x3223D2C1, 0x10A75686),
]


def imul_cipher(data: bytes, size: int, key: int) -> bytes:
    """Encrypt/decrypt data using the IMUL stream cipher (symmetric).

    Args:
        data: Input bytes (encrypted or plaintext)
        size: Number of bytes to process
        key:  32-bit master key (from packet header)

    Returns:
        Decrypted/encrypted bytes
    """
    k = [key & 0xFFFFFFFF] * 4
    acc = 0
    out = bytearray(size)
    for i in range(size):
        r = i % 4
        const, mult = IMUL_ROUNDS[r]
        k[r] = (const - (k[r] * mult)) & 0xFFFFFFFF
        kb = k[r].to_bytes(4, 'little')
        acc = (acc - kb[0]) & 0xFF
        acc ^= kb[1]
        acc = (acc - kb[2]) & 0xFF
        acc ^= kb[3]
        out[i] = data[i] ^ acc
    return bytes(out)


# ══════════════════════════════════════════════════════════════
# 2. Rolling Polynomial XOR (encrypted string decryption)
# ══════════════════════════════════════════════════════════════
#
# Each encrypted blob: 2-byte LE key seed prefix, then encrypted bytes.
# Per byte:
#   plain = (key & 0xFF) ^ encrypted_byte    (XOR BEFORE key update!)
#   key   = (-42860544 * key) - (135791246 * HIWORD(key)) - 1043215206  (mod 2^32)
#
# CRITICAL: XOR happens BEFORE key update, not after.

POLY_MULT_A = -42860544 & 0xFFFFFFFF   # 0xFD71A000
POLY_MULT_B = 135791246
POLY_CONST  = 1043215206


def poly_xor_key_update(key: int) -> int:
    """Update the polynomial XOR cipher key."""
    hiword = (key >> 16) & 0xFFFF
    return ((-42860544 * key) - (135791246 * hiword) - 1043215206) & 0xFFFFFFFF


def poly_xor_decrypt(data: bytes, key: int, max_len: int = 4092) -> str:
    """Decrypt a byte sequence using rolling polynomial XOR.

    Args:
        data: Raw encrypted bytes (WITHOUT the 2-byte key prefix)
        key:  Initial key value (from the 2-byte LE prefix)
        max_len: Maximum bytes to process

    Returns:
        Decrypted ASCII string (null-terminated)
    """
    result = bytearray()
    for i in range(min(len(data), max_len)):
        plain = (key & 0xFF) ^ data[i]
        if plain == 0:
            break
        result.append(plain)
        key = poly_xor_key_update(key)
    return result.decode('ascii', errors='replace')


def poly_xor_decrypt_blob(blob: bytes, max_len: int = 4092) -> str:
    """Decrypt an encrypted string blob (with 2-byte LE key prefix).

    Args:
        blob: Raw blob bytes (key_lo, key_hi, encrypted_data...)
        max_len: Maximum output length

    Returns:
        Decrypted ASCII string
    """
    if len(blob) < 3:
        raise ValueError(f"Blob too short ({len(blob)} bytes)")
    key = (blob[0] | (blob[1] << 8)) & 0xFFFFFFFF
    return poly_xor_decrypt(blob[2:], key, max_len)


# ══════════════════════════════════════════════════════════════
# 3. Rolling XOR (PE import name decryption)
# ══════════════════════════════════════════════════════════════
#
# Key seeded from sb_packed_pe_hdr.magic0
# Per byte:
#   decrypted = encrypted ^ (key & 0xFF)
#   key = (key << 24) | (int8(encrypted_byte) + (key >> 8))
#
# Key evolves across ALL names (not reset between DLL/function names).

def import_xor_key_update(key: int, enc_byte: int) -> int:
    """Update the rolling XOR key using the ENCRYPTED byte.

    Args:
        key: Current 32-bit key
        enc_byte: The encrypted byte value (0-255)

    Returns:
        Updated 32-bit key
    """
    enc_signed = enc_byte if enc_byte < 128 else enc_byte - 256
    left = (key << 24) & 0xFFFFFFFF
    right = (enc_signed + (key >> 8)) & 0xFFFFFFFF
    return (left | right) & 0xFFFFFFFF


def import_xor_decrypt_name(data: bytes, key: int) -> tuple:
    """Decrypt a null-terminated import name.

    Args:
        data: Raw encrypted bytes
        key:  Current rolling XOR key state

    Returns:
        Tuple of (decrypted_string, evolved_key)
    """
    result = bytearray()
    for enc_byte in data:
        dec_byte = (key ^ enc_byte) & 0xFF
        key = import_xor_key_update(key, enc_byte)
        if dec_byte == 0:
            break
        result.append(dec_byte)
    return result.decode('ascii', errors='replace'), key
