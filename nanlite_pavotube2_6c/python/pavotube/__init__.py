"""Unofficial interop library for the Nanlite PavoTube II 6C (firmware V1.00.11).

Built from static analysis only; not tested on hardware. Not affiliated with
or endorsed by Nanlite.

Modules:
    protocol  build/parse BLE app packets (Builder, parse_state_dump, ...)
    framing   FA 55 transport frames (binary BLE module) and AT-module helpers
    effects   BLE effect sub-modes 4..18 and their parameter sub-commands
    enums     categories, modes, effects, save-reason codes
    structs   ble_cmd_t, flags, led_output_t, led_pixel_cal_t
    nrf24     2.4 GHz remote payloads and radio settings
    eeprom    decode a settings EEPROM dump
    firmware  inspect your own .upd image (vector table, scatter-load, .data)
    ble       bleak-based transport (optional extra: pavotube[ble])
"""

from .enums import Category, Effect, LightMode, LightSub, WirelessProto
from .framing import decode_frame, encode_frame
from .protocol import Builder, parse_reply, parse_state_dump

__version__ = "0.1.0"

__all__ = [
    "Builder", "parse_reply", "parse_state_dump", "encode_frame", "decode_frame",
    "Category", "Effect", "LightMode", "LightSub", "WirelessProto",
]
