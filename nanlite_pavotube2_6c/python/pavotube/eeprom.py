"""Decode a dump of the PavoTube II 6C settings EEPROM.

Settings live in an external I2C EEPROM (device address 0xA0, 256 bytes,
bit-banged on PC2 = SCL / PC1 = SDA). 16-bit values are stored big-endian.
Each value is written individually; there is no page layout, header or CRC.
Defaults are applied at boot by range check and replace (see
docs/eeprom-layout.md). Addresses below come from sys_load_saved_settings
(0x08035294), flash_load_all_effect_params (0x08033DF4),
eeprom_read_calibration and flash_save_pending_params (0x08034718).

Usage::

    from pavotube.eeprom import decode
    for item in decode(open("eeprom.bin", "rb").read()):
        print(item)
"""

from __future__ import annotations

from dataclasses import dataclass

MAGIC_A, MAGIC_B = 0x59A3, 0xA65C
CAL_MAGIC = 0x55AA


@dataclass(frozen=True)
class Field:
    addr: int
    size: int            # 1 = byte, 2 = big-endian word
    group: str
    name: str
    valid: str = ""      # human-readable validity rule applied at load
    default: str = ""    # value substituted when invalid


def _b(a, g, n, v="", d=""):
    return Field(a, 1, g, n, v, d)


def _w(a, g, n, v="", d=""):
    return Field(a, 2, g, n, v, d)


FIELDS: list[Field] = [
    # -- general --------------------------------------------------------
    _w(10, "general", "cct_kelvin", "2700..7500", "2700"),
    _w(12, "general", "hsi_hue", "not checked"),
    _w(14, "general", "hsi_saturation", "<=100", "100"),
    _w(16, "general", "offset_word_16", "5000..15000", "4200"),
    _w(18, "general", "offset_word_18", "5000..15000", "4200"),
    _w(20, "general", "offset_word_20", "5000..15000", "4200"),
    _w(22, "general", "offset_word_22", "5000..15000", "4200"),
    _w(24, "general", "offset_word_24", "5000..15000", "4200"),
    _w(26, "general", "brightness", "<=100", "0"),
    _w(28, "general", "output_mode", "0 CCT, 1 HSI, 2 effect"),
    _w(52, "general", "ch_number", "1..512 (nRF24 address / BLE name number)", "1"),
    _w(56, "general", "standby_mode"),
    _w(62, "general", "cct_range_magic_a", f"== 0x{MAGIC_A:04X}"),
    _w(64, "general", "cct_range_magic_b", f"== 0x{MAGIC_B:04X}"),
    _w(66, "general", "cct_range_start", "used only if magic ok", "3200"),
    _w(68, "general", "cct_range_end", "used only if magic ok", "5600"),
    _w(70, "general", "hsi_range_magic_a", f"== 0x{MAGIC_A:04X}"),
    _w(72, "general", "hsi_range_magic_b", f"== 0x{MAGIC_B:04X}"),
    _w(74, "general", "hsi_range_start", "used only if magic ok", "3200"),
    _w(76, "general", "hsi_range_end", "used only if magic ok", "5600"),
    _b(84, "general", "cct_gm_tint", "<=200 (100 = neutral); overlaps fx CCT LOOP low word", "50"),
    _b(192, "general", "active_effect", "1..17", "1"),
    _w(194, "general", "display_size", "0 small / 1 large", "0"),
    _b(250, "general", "wireless_proto", "0 = V1.0, 1 = V2.0", "1"),
    _b(252, "general", "ble_bound_flag", "g_ble_device_id"),
    # -- calibration ----------------------------------------------------
    _w(218, "calibration", "cal_magic", f"== 0x{CAL_MAGIC:04X} enables 230..248"),
    _w(230, "calibration", "ch1_low"), _w(232, "calibration", "ch1_high"),
    _w(234, "calibration", "ch2_low"), _w(236, "calibration", "ch2_high"),
    _w(238, "calibration", "red_low"), _w(240, "calibration", "red_high"),
    _w(242, "calibration", "green_low"), _w(244, "calibration", "green_high"),
    _w(246, "calibration", "blue_low"), _w(248, "calibration", "blue_high"),
    # -- effects (UI numbering) -----------------------------------------
    _w(78, "fx01 HUE LOOP", "hue_start", "<= hue_end", "0"),
    _w(80, "fx01 HUE LOOP", "hue_end", "<=360", "360"),
    _b(82, "fx01 HUE LOOP", "speed", "2..30", "8"),
    _w(84, "fx02 CCT LOOP", "cct_low", "2700..cct_high", "3200"),
    _w(86, "fx02 CCT LOOP", "cct_high", "<=7500", "5600"),
    _b(88, "fx02 CCT LOOP", "speed", "2..30", "8"),
    _b(90, "fx03 INT LOOP", "low_brightness", "<= brightness", "0"),
    _b(92, "fx03 INT LOOP", "speed", "2..30", "8"),
    _b(94, "fx03 INT LOOP", "source", "0 CCT / 1 HSI", "0"),
    _w(96, "fx03 INT LOOP", "cct", "2700..7500", "5600"),
    _w(98, "fx03 INT LOOP", "hue", "<=360", "0"),
    _w(100, "fx04 CCT FLASH", "cct", "2700..7500", "5600"),
    _b(102, "fx04 CCT FLASH", "gm", "<=200", "100"),
    _b(104, "fx04 CCT FLASH", "speed", "<=100", "10"),
    _w(106, "fx05 HUE FLASH", "hue", "<=360", "0"),
    _b(108, "fx05 HUE FLASH", "saturation", "<=100", "100"),
    _b(110, "fx05 HUE FLASH", "speed", "<=100", "10"),
    _w(112, "fx06 CCT PULSE", "cct", "2700..7500", "5600"),
    _b(114, "fx06 CCT PULSE", "gm (shared with fx07 saturation)", "<=200", "100"),
    _b(116, "fx06 CCT PULSE", "bpm (shared with fx07)", "<=240", "40"),
    _w(118, "fx07 HUE PULSE", "hue", "<=360", "0"),
    _w(124, "fx08 STORM", "cct", "2700..7500", "5600"),
    _b(126, "fx08 STORM", "interval_min", "<= interval_max", "2"),
    _b(128, "fx08 STORM", "interval_max", "<=60", "6"),
    _b(130, "fx09 POLICE CAR", "pattern", "<=3", "1"),
    _b(132, "fx09 POLICE CAR", "speed", "<=100", "50"),
    _w(134, "fx10 TV", "cct", "2700..7500", "5600"),
    _b(136, "fx10 TV", "gm", "<=200", "100"),
    _b(138, "fx10 TV", "speed", "<=100", "50"),
    _b(140, "fx10 TV", "brightness_floor", "<= brightness", "0"),
    _w(142, "fx11 PAPARAZZI", "cct", "2700..7500", "5600"),
    _b(146, "fx11 PAPARAZZI", "gm", "<=200", "100"),
    _b(148, "fx11 PAPARAZZI", "speed", "<=100", "50"),
    _w(150, "fx12 CANDLE/FIRE", "cct", "2700..7500", "5600"),
    _b(152, "fx12 CANDLE/FIRE", "gm", "<=200", "100"),
    _b(154, "fx12 CANDLE/FIRE", "speed", "<=100", "50"),
    _b(156, "fx12 CANDLE/FIRE", "brightness_floor", "<= brightness", "0"),
    _b(158, "fx13 DISCO", "palette", "<=24", "3"),
    _b(160, "fx13 DISCO", "speed", "<=100", "50"),
    _b(162, "fx14 BAD BULB", "gm", "<=200", "100"),
    _w(164, "fx14 BAD BULB", "cct", "2700..7500", "5600"),
    _b(166, "fx14 BAD BULB", "speed", "<=100", "50"),
    _b(168, "fx15 FIREWORK", "colors", "<=24", "3"),
    _b(170, "fx15 FIREWORK", "saturation", "<=100", "50"),
    _b(172, "fx15 FIREWORK", "speed", "<=100", "50"),
    _w(174, "fx16 EXPLOSION", "cct", "2700..7500", "5600"),
    _b(176, "fx16 EXPLOSION", "gm", "<=200", "100"),
    _b(178, "fx16 EXPLOSION", "speed", "<=100", "50"),
    _b(180, "fx16 EXPLOSION", "intensity", "<=100", "50"),
    _b(182, "fx17 WELDING", "brightness_floor", "<= brightness", "0"),
    _w(184, "fx17 WELDING", "cct", "2700..7500", "5600"),
    _b(188, "fx17 WELDING", "gm", "<=200", "100"),
    _b(190, "fx17 WELDING", "speed", "<=100", "50"),
    _b(196, "fx17 WELDING", "source", "0 CCT / 1 HSI", "0"),
]


@dataclass
class Value:
    field: Field
    raw: int

    def __str__(self) -> str:
        f = self.field
        rule = f"  [{f.valid}{'; default ' + f.default if f.default else ''}]" if f.valid else ""
        return f"{f.addr:3d} 0x{f.addr:02X} {'w' if f.size == 2 else 'b'}  {f.group:18s} {f.name:34s} = {self.raw}{rule}"


def decode(dump: bytes) -> list[Value]:
    """Decode a raw EEPROM image (>= 254 bytes; the 24C02 is 256)."""
    if len(dump) < 254:
        raise ValueError("dump must be at least 254 bytes")
    out = []
    for f in sorted(FIELDS, key=lambda f: (f.addr, f.group)):
        raw = dump[f.addr] if f.size == 1 else int.from_bytes(dump[f.addr:f.addr + 2], "big")
        out.append(Value(f, raw))
    return out


def get(dump: bytes, group: str, name: str) -> int:
    for v in decode(dump):
        if v.field.group == group and v.field.name == name:
            return v.raw
    raise KeyError((group, name))
