"""Byte-level structures recovered from firmware V1.00.11 (docs/structures.md).

All multi-byte protocol fields are big-endian. Structures that live only in
the MCU's memory (LedOutput, PixelCal) are little-endian, because that is
the Cortex-M native byte order.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass

# flags byte (ble_cmd_t.flags)
FLAG_REPLY = 0x01        # bit 0: reply requested
FLAG_FROM_DEVICE = 0x02  # bit 1: set by the light in its replies
FLAG_ECHO = 0x04         # bit 2: echoed back unchanged (meaning unknown)
FLAG_HDR_MASK = 0x18     # bits 3-4: header type (0 normal, 2 = short-header/pixel page)
FLAG_SET = 0x20          # bit 5: 1 = SET (write), 0 = GET (read)
FLAG_FRAGMENT = 0x80     # bit 7: packet is one fragment of a larger one

BROADCAST = 0xFFFF       # address value; the light does not enforce addressing


@dataclass
class Flags:
    reply: bool = True
    set: bool = True
    echo: bool = False
    header_type: int = 0
    fragment: bool = False
    from_device: bool = False

    def pack(self) -> int:
        v = 0
        v |= FLAG_REPLY if self.reply else 0
        v |= FLAG_FROM_DEVICE if self.from_device else 0
        v |= FLAG_ECHO if self.echo else 0
        v |= (self.header_type & 3) << 3
        v |= FLAG_SET if self.set else 0
        v |= FLAG_FRAGMENT if self.fragment else 0
        return v

    @classmethod
    def unpack(cls, v: int) -> "Flags":
        return cls(reply=bool(v & FLAG_REPLY), set=bool(v & FLAG_SET), echo=bool(v & FLAG_ECHO),
                   header_type=(v >> 3) & 3, fragment=bool(v & FLAG_FRAGMENT),
                   from_device=bool(v & FLAG_FROM_DEVICE))


@dataclass
class BleCmd:
    """ble_cmd_t: the 8-byte short app packet.

    ``[seq, flags, category, sub, val_h, val_l, addr_h, addr_l]``
    """
    seq: int
    flags: int
    category: int
    sub: int
    value: int = 0          # [4..5] big-endian
    address: int = BROADCAST  # [6..7] big-endian

    FORMAT = ">BBBBHH"

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, self.seq & 0xFF, self.flags, self.category,
                           self.sub, self.value & 0xFFFF, self.address & 0xFFFF)

    @classmethod
    def unpack(cls, b: bytes) -> "BleCmd":
        return cls(*struct.unpack(cls.FORMAT, b[:8]))


@dataclass
class LedOutput:
    """led_output_t (10 bytes): PWM targets for the 5 channels (0..2100).

    Pins: ch1 TIM3_CH4/PC9, ch2 TIM1_CH1/PA8, red TIM3_CH3/PC8,
    green TIM3_CH2/PC7, blue TIM3_CH1/PC6. The IDB calls ch1/ch2 warm/cool,
    but the colour math suggests ch1 rises with Kelvin, so the labels may be
    swapped.
    """
    ch1: int
    ch2: int
    red: int
    green: int
    blue: int

    FORMAT = "<5H"

    def pack(self) -> bytes:
        return struct.pack(self.FORMAT, self.ch1, self.ch2, self.red, self.green, self.blue)

    @classmethod
    def unpack(cls, b: bytes) -> "LedOutput":
        return cls(*struct.unpack(cls.FORMAT, b[:10]))


@dataclass
class ChannelCal:
    low: int
    high: int
    slope: float
    intercept: float


@dataclass
class PixelCal:
    """led_pixel_cal_t (60 bytes): 5 x {u16 low, u16 high, f32 slope, f32 intercept}.

    low/high come from EEPROM 230..248. The firmware derives:
        white channels: slope = (high - low) / 1853, intercept = low - slope * 100
        RGB channels:   slope = (high - low) / 1835, intercept = low - slope * 76
    """
    channels: list[ChannelCal]

    FORMAT = "<HHff"

    @classmethod
    def unpack(cls, b: bytes) -> "PixelCal":
        return cls([ChannelCal(*struct.unpack_from(cls.FORMAT, b, i * 12)) for i in range(5)])

    @staticmethod
    def derive(low: int, high: int, white: bool) -> ChannelCal:
        slope = (high - low) / (1853 if white else 1835)
        return ChannelCal(low, high, slope, low - slope * (100 if white else 76))
