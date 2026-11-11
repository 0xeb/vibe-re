"""Inspect a PavoTube II 6C application image (``.upd``) that you obtained yourself.

The ``.upd`` file is a raw Cortex-M flash image with no header, footer or CRC.
It is linked to run at ``0x08010000``; the region below that is assumed to hold
a bootloader. This module:

* checks size and SHA-256 against known releases,
* decodes the vector table,
* finds and parses the ARM-Compiler scatter-load table,
* reimplements the RW-data decompressor so the initialised SRAM image
  (``.data``) can be reconstructed, which is where the firmware version string,
  colour tables and BLE/AT constants live.

Nothing from the vendor image ships with this package; you supply the file.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

FLASH_BASE = 0x08010000
SRAM_BASE = 0x20000000

KNOWN_RELEASES = {
    "ec51bdf9d11a40f2fd7963545434c0183aa6569278d1290f7283ed62e18047dc": "V1.00.11",
}

# Cortex-M exception names for vector slots 1..15
_EXC_NAMES = {
    1: "Reset", 2: "NMI", 3: "HardFault", 4: "MemManage", 5: "BusFault",
    6: "UsageFault", 11: "SVCall", 12: "DebugMon", 14: "PendSV", 15: "SysTick",
}

# STM32F4 IRQ names that this firmware actually uses (see docs/hardware.md)
_IRQ_NAMES = {
    9: "EXTI3 (nRF24 IRQ, PB3)",
    24: "TIM1_BRK_TIM9 (delay tick)",
    30: "TIM4 (empty handler)",
    37: "USART1 (BLE module UART)",
    40: "EXTI15_10 (empty handler)",
    50: "TIM5 (UART end-of-frame timer)",
}


@dataclass
class ScatterEntry:
    src: int
    dst: int
    size: int
    func: int
    kind: str  # "lz" (compressed RW), "zero" (ZI) or "copy"/"unknown"


@dataclass
class FirmwareImage:
    data: bytes
    base: int = FLASH_BASE
    sha256: str = ""
    release: str | None = None
    initial_sp: int = 0
    reset: int = 0
    vectors: list[int] = field(default_factory=list)
    scatter_addr: int | None = None
    scatter: list[ScatterEntry] = field(default_factory=list)
    sram: bytearray | None = None  # reconstructed initialised SRAM (.data + .bss)

    # -- helpers ---------------------------------------------------------
    def u32(self, addr: int) -> int:
        off = addr - self.base
        return struct.unpack_from("<I", self.data, off)[0]

    def in_flash(self, addr: int) -> bool:
        return self.base <= addr < self.base + len(self.data)

    def sram_bytes(self, addr: int, length: int) -> bytes:
        if self.sram is None:
            raise ValueError("SRAM image not reconstructed")
        off = addr - SRAM_BASE
        return bytes(self.sram[off:off + length])

    def sram_cstring(self, addr: int, max_len: int = 64) -> str:
        raw = self.sram_bytes(addr, max_len)
        return raw.split(b"\0", 1)[0].decode("latin-1")

    def find_sram(self, needle: bytes) -> list[int]:
        if self.sram is None:
            return []
        hits, start = [], 0
        while (i := self.sram.find(needle, start)) >= 0:
            hits.append(SRAM_BASE + i)
            start = i + 1
        return hits


def decompress_rw(src: bytes, pos: int, out_size: int) -> bytes:
    """ARM Compiler RW-data decompressor (the variant used at 0x0801088C).

    Each token byte ``t``:
      * ``lit = t & 7``  (if 0, the next byte holds it); ``lit - 1`` literal
        bytes follow and are copied verbatim.
      * ``run = t >> 4`` (if 0, the next byte holds it). The length bytes are
        read in that order: literal count first, then run.
      * if ``t & 8``: next byte is a back-reference distance ``d``; copy
        ``run + 2`` bytes from ``out[-d]`` (overlap allowed).
      * else: emit ``run`` zero bytes.
    Stops once ``out_size`` bytes have been produced.
    """
    out = bytearray()
    while len(out) < out_size:
        t = src[pos]; pos += 1
        lit = t & 7
        if lit == 0:
            lit = src[pos]; pos += 1
        run = t >> 4
        if run == 0:
            run = src[pos]; pos += 1
        n = lit - 1
        out += src[pos:pos + n]; pos += n
        if t & 8:
            d = src[pos]; pos += 1
            for _ in range(run + 2):
                out.append(out[-d])
        else:
            out += bytes(run)
    return bytes(out[:out_size])


def _find_scatter_table(img: FirmwareImage) -> int | None:
    """Locate the scatter-load table: 16-byte entries {src, dst, size, func}
    where src is in flash, dst in SRAM and func is a Thumb flash address."""
    d = img.data
    for off in range(0, len(d) - 32, 4):
        src, dst, size, func = struct.unpack_from("<IIII", d, off)
        if not (img.in_flash(src) and SRAM_BASE <= dst < SRAM_BASE + 0x20000
                and 0 < size < 0x20000 and img.in_flash(func & ~1)):
            continue
        # the table must be followed by its own end (src of first entry is
        # usually right after the table) or another valid entry
        src2, dst2, size2, func2 = struct.unpack_from("<IIII", d, off + 16)
        if SRAM_BASE <= dst2 < SRAM_BASE + 0x20000 and img.in_flash(func2 & ~1):
            return img.base + off
    return None


def load(data: bytes) -> FirmwareImage:
    img = FirmwareImage(data=data)
    img.sha256 = hashlib.sha256(data).hexdigest()
    img.release = KNOWN_RELEASES.get(img.sha256)
    n_vec = 98
    img.vectors = list(struct.unpack_from(f"<{n_vec}I", data, 0))
    img.initial_sp, img.reset = img.vectors[0], img.vectors[1]

    img.scatter_addr = _find_scatter_table(img)
    if img.scatter_addr is not None:
        addr = img.scatter_addr
        funcs: dict[int, int] = {}
        raw = []
        while True:
            src, dst, size, func = struct.unpack_from("<IIII", data, addr - img.base)
            if not (SRAM_BASE <= dst < SRAM_BASE + 0x20000 and img.in_flash(func & ~1)):
                break
            raw.append((src, dst, size, func))
            funcs[func] = funcs.get(func, 0) + 1
            addr += 16
        sram_end = max(dst + size for _, dst, size, _ in raw)
        img.sram = bytearray(sram_end - SRAM_BASE)
        for src, dst, size, func in raw:
            kind = "unknown"
            if img.in_flash(src) and src - img.base < len(data):
                try:
                    blob = decompress_rw(data, src - img.base, size)
                    kind = "lz"
                except IndexError:
                    blob = None
            else:
                blob = None
            if kind != "lz":
                blob = bytes(size)
                kind = "zero"
            img.sram[dst - SRAM_BASE: dst - SRAM_BASE + size] = blob
            img.scatter.append(ScatterEntry(src, dst, size, func, kind))
    return img


def vector_name(index: int) -> str:
    if index < 16:
        return _EXC_NAMES.get(index, f"reserved{index}")
    irq = index - 16
    return f"IRQ{irq}" + (f" {_IRQ_NAMES[irq]}" if irq in _IRQ_NAMES else "")


def report(img: FirmwareImage) -> str:
    lines = []
    w = lines.append
    w(f"size        : {len(img.data)} bytes (flash 0x{img.base:08X}-0x{img.base + len(img.data):08X})")
    w(f"sha256      : {img.sha256}")
    w(f"release     : {img.release or 'unknown (not a known build)'}")
    w(f"initial SP  : 0x{img.initial_sp:08X}")
    w(f"reset       : 0x{img.reset:08X}")
    default = max(set(img.vectors[16:]), key=img.vectors[16:].count)
    w(f"default IRQ : 0x{default:08X}")
    w("vectors     :")
    for i, v in enumerate(img.vectors[1:], start=1):
        if v == 0 or (i >= 16 and v == default):
            continue
        w(f"  [{i:2d}] {vector_name(i):40s} 0x{v:08X}")
    if img.scatter_addr is None:
        w("scatter     : not found")
        return "\n".join(lines)
    w(f"scatter     : table at 0x{img.scatter_addr:08X}")
    for e in img.scatter:
        w(f"  src 0x{e.src:08X} -> dst 0x{e.dst:08X} size 0x{e.size:X} via 0x{e.func:08X} [{e.kind}]")
    hits = [a for a in img.find_sram(b"V1.") if img.sram_bytes(a, 8)[3:4].isdigit()]
    for a in hits[:4]:
        w(f"version str : {img.sram_cstring(a, 16)!r} at 0x{a:08X}")
    return "\n".join(lines)


def load_file(path: str) -> FirmwareImage:
    with open(path, "rb") as f:
        return load(f.read())
