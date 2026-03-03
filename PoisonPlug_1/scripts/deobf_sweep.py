"""
Deobfuscation via Capstone linear sweep — removes opaque predicate anti-disassembly.

Opaque predicate pattern (5 bytes):
    Jcc_true  +3    (2 bytes)  — always-taken branch
    Jcc_false +1    (2 bytes)  — never-taken, targets same addr
    Junk byte       (1 byte)   — E8 (CALL) or E9 (JMP)

Both jumps target current_address + 5 (past the junk byte).
Real code continues at +5.

Usage:
    python scripts/deobf_sweep.py --start 0x180021137 --end 0x180021920
    python scripts/deobf_sweep.py --start 0x180021137 --end 0x180021920 --patch
    python scripts/deobf_sweep.py --start 0x180021137 --end 0x180021920 --apply --server http://127.0.0.1:8104
"""

import argparse
import struct
import sys
from pathlib import Path
from typing import Optional

import capstone
import lief
import requests

# Default binary path
DEFAULT_PE = str(
    Path(__file__).resolve().parent.parent
    / "60678e352f3c849e36413f5de51b5eeca1180840c818f9ece0a0da803eb205a5.neutred"
)

DEFAULT_SERVER = "http://127.0.0.1:8104"


# ---------------------------------------------------------------------------
# PE loading + VA <-> file offset mapping
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
            self._sections.append((va_start, va_end, sec.offset, raw))

    def read_va(self, va: int, size: int) -> bytes:
        """Read `size` bytes starting at virtual address `va`."""
        for va_start, va_end, _offset, raw in self._sections:
            if va_start <= va < va_end:
                off = va - va_start
                end = min(off + size, len(raw))
                data = raw[off:end]
                if len(data) < size:
                    # Might span sections (unlikely), just return what we have
                    pass
                return data
        raise ValueError(f"VA 0x{va:X} not found in any section")


def load_pe(path: str) -> PEImage:
    return PEImage(path)


# ---------------------------------------------------------------------------
# Opaque predicate detection
# ---------------------------------------------------------------------------

def is_short_jcc_byte(b: int) -> bool:
    """Check if byte is a short Jcc opcode (0x70-0x7F)."""
    return 0x70 <= b <= 0x7F


def are_complementary(b1: int, b2: int) -> bool:
    """Check if two Jcc opcodes are complementary (differ only in bit 0)."""
    return (b1 ^ b2) == 1 and is_short_jcc_byte(b1) and is_short_jcc_byte(b2)


def check_opaque_predicate(code: bytes, offset: int) -> bool:
    """
    At `offset` in `code`, check if the 5-byte opaque predicate pattern exists:
      [Jcc +3] [complement_Jcc +1] [E8|E9]
    """
    if offset + 5 > len(code):
        return False

    b0 = code[offset]      # first Jcc opcode
    d0 = code[offset + 1]  # displacement = 0x03
    b1 = code[offset + 2]  # second Jcc opcode
    d1 = code[offset + 3]  # displacement = 0x01
    junk = code[offset + 4]  # E8 or E9

    return (
        is_short_jcc_byte(b0)
        and d0 == 0x03
        and are_complementary(b0, b1)
        and d1 == 0x01
        and junk in (0xE8, 0xE9)
    )


# ---------------------------------------------------------------------------
# Capstone linear sweep
# ---------------------------------------------------------------------------

# Mapping Jcc opcodes to mnemonics for display
JCC_NAMES = {
    0x70: "jo",   0x71: "jno",
    0x72: "jb",   0x73: "jnb",
    0x74: "jz",   0x75: "jnz",
    0x76: "jbe",  0x77: "ja",
    0x78: "js",   0x79: "jns",
    0x7A: "jp",   0x7B: "jnp",
    0x7C: "jl",   0x7D: "jge",
    0x7E: "jle",  0x7F: "jg",
}


def sweep(code_bytes: bytes, start_va: int):
    """
    Linear disassembly sweep with opaque predicate detection.

    Returns:
        listing: list of (va, text) — either instruction text or opaque-predicate marker
        opaques: list of (va, 5_bytes) — opaque predicate locations
    """
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    listing = []
    opaques = []
    offset = 0

    while offset < len(code_bytes):
        # Check for opaque predicate FIRST by looking at the raw bytes.
        # We do this before Capstone decodes, because Capstone will decode
        # the first Jcc just fine — but we want to catch the pattern early
        # and check if this Jcc is the start of a 5-byte trick.
        b = code_bytes[offset]
        if is_short_jcc_byte(b) and code_bytes[offset + 1:offset + 2] == b'\x03':
            if check_opaque_predicate(code_bytes, offset):
                raw = code_bytes[offset:offset + 5]
                va = start_va + offset
                hex_str = " ".join(f"{x:02X}" for x in raw)
                listing.append((va, f"<opaque_predicate: {hex_str} -- NOP>"))
                opaques.append((va, raw))
                offset += 5
                continue

        # Normal Capstone decode — one instruction at a time
        decoded = list(md.disasm(code_bytes[offset:], start_va + offset, count=1))

        if not decoded:
            va = start_va + offset
            # Show up to 16 bytes of context at the failure point
            context = code_bytes[offset:offset + 16]
            hex_ctx = " ".join(f"{x:02X}" for x in context)
            listing.append((va, f"<DECODE_ERROR: {hex_ctx}>"))
            print(
                f"[!] Decode failure at 0x{va:X}: {hex_ctx}",
                file=sys.stderr,
            )
            break

        insn = decoded[0]
        listing.append((insn.address, f"{insn.mnemonic:<8s} {insn.op_str}"))
        offset += insn.size

    return listing, opaques


# ---------------------------------------------------------------------------
# Output: disassembly listing
# ---------------------------------------------------------------------------

def print_listing(listing, file=sys.stdout):
    for va, text in listing:
        print(f"0x{va:X}:  {text}", file=file)


# ---------------------------------------------------------------------------
# Patch generation
# ---------------------------------------------------------------------------

def gen_patches(opaques):
    """Generate idasql SQL UPDATE statements to NOP out each opaque predicate."""
    stmts = []
    for va, raw_bytes in opaques:
        for i in range(len(raw_bytes)):
            stmts.append(
                f"UPDATE bytes SET value = 0x90 WHERE address = 0x{va + i:X};"
            )
    return stmts


def gen_patch_batch(opaques, server_url: str):
    """Generate a single batch SQL that patches all opaques via patch_byte()."""
    calls = []
    for va, raw_bytes in opaques:
        for i in range(len(raw_bytes)):
            calls.append(f"patch_byte(0x{va + i:X}, 0x90)")
    # Use a SELECT with all patch_byte calls joined
    # idasql supports multiple statements, so just issue them individually
    return [f"SELECT {c};" for c in calls]


def apply_patches(opaques, server_url: str):
    """Apply NOP patches to IDA via idasql HTTP server."""
    url = server_url.rstrip("/") + "/query"
    patched = 0
    errors = 0

    for va, raw_bytes in opaques:
        for i in range(len(raw_bytes)):
            addr = va + i
            sql = f"SELECT patch_byte(0x{addr:X}, 0x90);"
            try:
                resp = requests.post(url, data=sql, timeout=5)
                result = resp.json() if resp.status_code == 200 else {}
                if resp.status_code == 200 and result.get("success"):
                    patched += 1
                else:
                    print(
                        f"[!] Patch at 0x{addr:X} returned HTTP {resp.status_code}: {resp.text}",
                        file=sys.stderr,
                    )
                    errors += 1
            except requests.RequestException as e:
                print(f"[!] Patch at 0x{addr:X} failed: {e}", file=sys.stderr)
                errors += 1

    print(f"\n[*] Patched {patched} bytes, {errors} errors.", file=sys.stderr)
    return patched, errors


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def parse_int(s: str) -> int:
    """Parse an integer from hex (0x...) or decimal string."""
    s = s.strip()
    if s.startswith("0x") or s.startswith("0X"):
        return int(s, 16)
    return int(s)


def main():
    parser = argparse.ArgumentParser(
        description="Deobfuscate opaque predicates via Capstone linear sweep"
    )
    parser.add_argument(
        "--pe",
        default=DEFAULT_PE,
        help="Path to the PE DLL file (default: auto-detected relative to script)",
    )
    parser.add_argument(
        "--start",
        required=True,
        type=parse_int,
        help="Start VA for the sweep (hex, e.g. 0x180021137)",
    )
    parser.add_argument(
        "--end",
        required=True,
        type=parse_int,
        help="End VA for the sweep (hex, e.g. 0x180021920)",
    )
    parser.add_argument(
        "--patch",
        action="store_true",
        help="Emit NOP patch SQL statements to stdout",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="Apply NOP patches live to IDA via idasql HTTP",
    )
    parser.add_argument(
        "--server",
        default=DEFAULT_SERVER,
        help=f"idasql HTTP server URL (default: {DEFAULT_SERVER})",
    )
    parser.add_argument(
        "--out",
        default=None,
        help="Write disassembly listing to file instead of stdout",
    )

    args = parser.parse_args()

    if args.end <= args.start:
        print("[!] --end must be greater than --start", file=sys.stderr)
        sys.exit(1)

    # Load PE
    print(f"[*] Loading PE: {args.pe}", file=sys.stderr)
    pe = load_pe(args.pe)

    # Read byte range
    size = args.end - args.start
    print(
        f"[*] Reading 0x{size:X} bytes: 0x{args.start:X} — 0x{args.end:X}",
        file=sys.stderr,
    )
    code_bytes = pe.read_va(args.start, size)
    if len(code_bytes) < size:
        print(
            f"[!] Warning: only got {len(code_bytes)} bytes (requested {size})",
            file=sys.stderr,
        )

    # Sweep
    print(f"[*] Starting linear sweep at 0x{args.start:X}...", file=sys.stderr)
    listing, opaques = sweep(code_bytes, args.start)

    # Report
    print(f"[*] Found {len(opaques)} opaque predicates.", file=sys.stderr)
    if opaques:
        print("[*] Opaque predicate addresses:", file=sys.stderr)
        for va, raw in opaques:
            hex_str = " ".join(f"{x:02X}" for x in raw)
            print(f"     0x{va:X}: {hex_str}", file=sys.stderr)

    # Listing output
    if args.out:
        with open(args.out, "w") as f:
            print_listing(listing, file=f)
        print(f"[*] Listing written to {args.out}", file=sys.stderr)
    else:
        print_listing(listing)

    # Patch SQL
    if args.patch:
        print("\n-- idasql NOP patch commands:", file=sys.stdout)
        for stmt in gen_patches(opaques):
            print(stmt)

    # Apply patches
    if args.apply:
        print(f"\n[*] Applying patches to {args.server}...", file=sys.stderr)
        apply_patches(opaques, args.server)


if __name__ == "__main__":
    main()
