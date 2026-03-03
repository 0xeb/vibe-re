"""
Capstone disassembler for raw binary blobs.

Usage:
    python scripts/disasm.py output/mapped_image.bin --start 0x4344 --count 40
    python scripts/disasm.py output/mapped_image.bin --start 0x1000 --count 100
    python scripts/disasm.py output/mapped_image.bin --start 0x4344 --base 0x180000000
"""

import argparse
import sys
from pathlib import Path

import capstone


def parse_int(s: str) -> int:
    s = s.strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    return int(s)


def main():
    parser = argparse.ArgumentParser(description="Disassemble raw binary blob with Capstone")
    parser.add_argument("file", help="Path to binary file")
    parser.add_argument("--start", type=parse_int, default=0, help="Offset into file to start disassembly (default: 0)")
    parser.add_argument("--count", type=parse_int, default=50, help="Number of instructions (default: 50)")
    parser.add_argument("--base", type=parse_int, default=0, help="Base address for display (default: 0)")
    parser.add_argument("--arch", default="x64", choices=["x64", "x86"], help="Architecture (default: x64)")
    args = parser.parse_args()

    data = Path(args.file).read_bytes()
    if args.start >= len(data):
        print(f"[!] Start offset 0x{args.start:X} beyond file size 0x{len(data):X}", file=sys.stderr)
        sys.exit(1)

    code = data[args.start:]
    display_addr = args.base + args.start

    mode = capstone.CS_MODE_64 if args.arch == "x64" else capstone.CS_MODE_32
    md = capstone.Cs(capstone.CS_ARCH_X86, mode)
    md.detail = True

    count = 0
    for insn in md.disasm(code, display_addr):
        hex_bytes = " ".join(f"{b:02X}" for b in insn.bytes)
        print(f"  0x{insn.address:X}:  {hex_bytes:<24s}  {insn.mnemonic:<8s} {insn.op_str}")
        count += 1
        if count >= args.count:
            break

    print(f"\n[*] {count} instructions from offset 0x{args.start:X}", file=sys.stderr)


if __name__ == "__main__":
    main()
