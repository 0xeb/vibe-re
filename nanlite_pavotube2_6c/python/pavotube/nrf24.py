"""Packets for the PavoTube II 6C 2.4 GHz remote link (nRF24L01-compatible).

The light is always the *receiver*. To control it you need an nRF24L01(+)
radio (e.g. an RF24/pyrf24 setup) configured to match. This module only
builds payloads and radio parameters; it does not drive hardware.

See docs/nrf24-remote.md for the full description.

Radio settings (both protocol versions):
    5-byte address, CRC 2 bytes, 1 Mbps, auto-ack on pipe 0,
    static payload, no dynamic payloads / ACK payloads.
    V1.0: RF_CH 115 (2515 MHz), payload 4 bytes
    V2.0: RF_CH 60  (2460 MHz), payload 32 bytes  (factory default)

The address is derived from the light's "CH" menu value (1..512):
    address bytes, in the order clocked into TX_ADDR/RX_ADDR_P0:
        00 00 00 CH_hi CH_lo
    nRF24 shifts multi-byte addresses LSByte first, so libraries that take
    the address as an integer/bytes in "LSByte first" order (RF24's
    openWritingPipe(uint8_t*)) should be given exactly these 5 bytes.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import WirelessProto

CCT_MIN, CCT_MAX = 2700, 7500


@dataclass(frozen=True)
class RadioConfig:
    channel: int           # RF_CH
    payload_size: int      # RX_PW_P0
    address: bytes         # 5 bytes, as written to TX_ADDR / RX_ADDR_P0
    data_rate_mbps: int = 1
    crc_bytes: int = 2
    auto_ack: bool = True

    @property
    def frequency_mhz(self) -> int:
        return 2400 + self.channel


def address_for_channel(ch: int) -> bytes:
    """5-byte pipe address for the light's CH setting (1..512)."""
    if not 1 <= ch <= 512:
        raise ValueError("CH must be 1..512")
    return bytes([0, 0, 0, ch >> 8, ch & 0xFF])


def radio_config(ch: int, proto: WirelessProto = WirelessProto.V2) -> RadioConfig:
    if proto == WirelessProto.V1:
        return RadioConfig(channel=115, payload_size=4, address=address_for_channel(ch))
    return RadioConfig(channel=60, payload_size=32, address=address_for_channel(ch))


# --- V1.0: 4-byte payloads -------------------------------------------------

def cct_index(kelvin: int) -> int:
    """Kelvin -> CCT index byte (0..100). The light computes
    ``K = 100 * ((48 * idx + 2700) // 100)``; this returns the closest index."""
    kelvin = max(CCT_MIN, min(CCT_MAX, kelvin))
    return min(range(101), key=lambda i: abs(index_to_kelvin(i) - kelvin))


def index_to_kelvin(idx: int) -> int:
    return 100 * ((48 * idx + 2700) // 100)


def v1_cct(brightness: int, kelvin: int) -> bytes:
    """CCT packet: ``[bri, idx, bri+idx, ~(bri+idx)]``.

    Accepted by ble_parse_cct_packet (0x080169C4). Switches the light to CCT.
    """
    b0 = _pct(brightness)
    b1 = cct_index(kelvin)
    s = b0 + b1
    return bytes([b0, b1, s, s ^ 0xFF])


def v1_cct_tint(brightness: int, kelvin: int, tint: int) -> bytes:
    """CCT + green/magenta packet: ``[bri, idx, tint, bri+idx]``.

    ``tint`` is 0..100 (50 = neutral); the light stores ``2*tint`` (0..200,
    100 = neutral). Accepted by ble_parse_cct_packet_ext (0x08028DD8), which
    requires ``tint != (bri+idx) ^ 0xFF``.
    """
    b0, b1, b2 = _pct(brightness), cct_index(kelvin), _pct(tint)
    s = b0 + b1
    if b2 == s ^ 0xFF:
        raise ValueError("this combination collides with the plain CCT packet; nudge tint by 1")
    return bytes([b0, b1, b2, s])


def v1_hsi(brightness: int, hue: int, saturation: int) -> bytes:
    """HSI packet: ``[0xF0 | hue>>8, bri, hue & 0xFF, sat]`` (no checksum).

    Accepted by ble_parse_hsi_packet (0x08029544). Switches the light to HSI.
    """
    if not 0 <= hue <= 360:
        raise ValueError("hue must be 0..360")
    return bytes([0xF0 | (hue >> 8), _pct(brightness), hue & 0xFF, _pct(saturation)])


def v1_decode(p: bytes) -> dict:
    """Classify a 4-byte payload the way the firmware does (CCT, HSI, CCT+tint)."""
    if len(p) < 4:
        raise ValueError("need 4 bytes")
    b0, b1, b2, b3 = p[:4]
    out: dict = {}
    if b0 + b1 == b2 and b2 == b3 ^ 0xFF:
        out["cct"] = {"brightness": b0, "kelvin": index_to_kelvin(b1)}
    if b0 in (0xF0, 0xF1) and b1 <= 100 and b3 <= 100:
        out["hsi"] = {"brightness": b1, "hue": ((b0 & 0xF) << 8) | b2, "saturation": b3}
    if b0 + b1 == b3 and b2 != b3 ^ 0xFF:
        out["cct_tint"] = {"brightness": b0, "kelvin": index_to_kelvin(b1), "tint": b2}
    return out


# --- V2.0: 32-byte payloads -----------------------------------------------

V2_CMD_POWER_TOGGLE = 1
V2_CMD_MODE = 2
V2_CMD_BRIGHTNESS = 3
V2_CMD_CCT_WHEEL = 4
V2_CMD_HSI_WHEEL = 5
V2_CMD_BOTH_WHEELS = 6

V2_UP, V2_DOWN, V2_AUX_UP, V2_AUX_DOWN = 1, 2, 3, 4


def v2_checksum(body: bytes) -> int | None:
    """8-bit sum + 1. Returns None if the sum is 0xFF (the light can never
    accept such a frame; change a don't-care byte)."""
    s = sum(body) & 0xFF
    return None if s == 0xFF else s + 1


def v2_frame(cmd: int, arg: int = 0, sub: int = 0, length: int = 16,
             filler: int = 0) -> bytes:
    """Build a 32-byte V2.0 payload.

    Layout (big-endian words)::

        [0..2]   don't care
        [3]      L, frame length used for the checksum (14..32)
        [4..5]   don't care
        [6..7]   cmd
        [8..9]   arg
        [10..11] sub
        [12..13] flags, must be 0
        [L-2]    don't care (not summed)
        [L-1]    checksum = (sum(bytes[0 .. L-3]) & 0xFF) + 1
        rest     padding to 32

    Validated by ble_validate_and_dispatch (0x08037B1C).
    """
    if not 14 <= length <= 32:
        raise ValueError("length must be 14..32")
    p = bytearray([filler] * 32)
    p[3] = length
    p[6:8] = cmd.to_bytes(2, "big")
    p[8:10] = arg.to_bytes(2, "big")
    p[10:12] = sub.to_bytes(2, "big")
    p[12:14] = b"\0\0"
    ck = v2_checksum(bytes(p[:length - 2]))
    if ck is None:
        p[0] = (p[0] + 1) & 0xFF
        ck = v2_checksum(bytes(p[:length - 2]))
    p[length - 1] = ck
    return bytes(p)


def v2_power_toggle() -> bytes:
    """Toggle output between 0 and the last brightness."""
    return v2_frame(V2_CMD_POWER_TOGGLE)


def v2_mode(mode: str) -> bytes:
    """mode: 'cct', 'hsi', 'effect' or 'next_effect' (cycles 1..17, saved)."""
    table = {"cct": (1, 1), "hsi": (2, 1), "effect": (3, 1), "next_effect": (3, 2)}
    arg, sub = table[mode]
    return v2_frame(V2_CMD_MODE, arg, sub)


def v2_brightness_step(up: bool) -> bytes:
    """Brightness +1 / -1 (clamped 0..100)."""
    return v2_frame(V2_CMD_BRIGHTNESS, V2_UP if up else V2_DOWN)


def v2_cct_wheel(action: int) -> bytes:
    """CCT screen: 1 = +100 K, 2 = -100 K, 3 = tint +1, 4 = tint -1.
    On an effect screen it edits that effect's CCT/GM-type field instead."""
    return v2_frame(V2_CMD_CCT_WHEEL, action)


def v2_hsi_wheel(action: int) -> bytes:
    """HSI screen: 1 = hue +1, 2 = hue -1 (wraps 1..360), 3 = sat +1, 4 = sat -1.
    On an effect screen it edits that effect's hue/saturation-type field."""
    return v2_frame(V2_CMD_HSI_WHEEL, action)


def v2_decode(p: bytes) -> dict:
    if len(p) < 14:
        raise ValueError("need at least 14 bytes")
    length = p[3]
    ok = 14 <= length <= len(p) and v2_checksum(p[:length - 2]) == p[length - 1]
    return {
        "length": length,
        "checksum_ok": ok,
        "cmd": int.from_bytes(p[6:8], "big"),
        "arg": int.from_bytes(p[8:10], "big"),
        "sub": int.from_bytes(p[10:12], "big"),
        "flags": int.from_bytes(p[12:14], "big"),
    }


def _pct(v: int) -> int:
    if not 0 <= v <= 100:
        raise ValueError("value must be 0..100")
    return v
