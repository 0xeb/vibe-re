"""Enumerations recovered from firmware V1.00.11 (see docs/structures.md)."""

from __future__ import annotations

from enum import IntEnum


class Category(IntEnum):
    """App-packet command category (byte [2] of a short packet)."""
    LIGHT = 1          # light_control_handler: brightness, CCT, GM, hue, sat, effect params
    CONFIG = 3         # ble_config_handler: state dump, versions, ID, clock, serial
    SYNC = 4           # no handler; forces "apply pending values"
    DEVICE_INFO = 5    # protocol version / status
    MODE = 9           # select light mode (+ optional sub-mode)
    SUBMODE = 10       # select sub-mode only


class LightMode(IntEnum):
    """Light mode as used on the BLE wire (category 9, state dump)."""
    CCT = 2
    HSI = 3
    EFFECT = 7


class OutputMode(IntEnum):
    """g_led_output_mode / EEPROM word 28 (light_mode_t in the IDB)."""
    CCT = 0
    HSI = 1
    EFFECT = 2
    SOURCE = 3


class UiMode(IntEnum):
    """g_ui_mode: the on-device screen."""
    CCT = 1
    HSI = 2
    EFFECT = 3
    SETTINGS = 4


class Effect(IntEnum):
    """Effect numbering used by the UI and EEPROM (1..17).

    Names are the firmware's own on-screen names (effect name table in .data
    at 0x20000A96). Most names in the IDA database's ``effect_id_t`` do not
    match; the IDB name is given in each comment. The BLE sub-mode number is
    ``value + 3`` (see :pyattr:`ble_id`).
    """
    HUE_LOOP = 1        # "HUE LOOP"     IDB: CCT_SWEEP
    CCT_LOOP = 2        # "CCT LOOP"     IDB: CCT_RANGE
    INT_LOOP = 3        # "INT LOOP"     IDB: HSI_SOURCE
    CCT_FLASH = 4       # "CCT FLASH"    IDB: CCT_TINT
    HUE_FLASH = 5       # "HUE FLASH"    IDB: HSI_HUE
    CCT_PULSE = 6       # "CCT PULSE"
    HUE_PULSE = 7       # "HUE PULSE"    IDB: HSI_PULSE
    STORM = 8           # "STORM"        IDB: PIXEL_CHASE
    POLICE_CAR = 9      # "POLICE CAR"   IDB: LIGHTNING
    TV = 10             # "TV"           IDB: TV_SIM
    PAPARAZZI = 11      # "PAPARAZZI"    IDB: CANDLE
    CANDLE_FIRE = 12    # "CANDLE/FIRE"  IDB: PARTY
    DISCO = 13          # "DISCO"        IDB: COLOR_PRESET
    BAD_BULB = 14       # "BAD BULB"     IDB: COP
    FIREWORK = 15       # "FIREWORK"     IDB: RAINBOW
    EXPLOSION = 16      # "EXPLOSION"    IDB: FIREWORKS
    WELDING = 17        # "WELDING"      IDB: CUSTOM

    @property
    def label(self) -> str:
        return self.name.replace("_", " ").replace("CANDLE FIRE", "CANDLE/FIRE")

    @property
    def ble_id(self) -> int:
        """BLE sub-mode number (4..20) for category 9/10 commands."""
        return int(self) + 3

    @classmethod
    def from_ble(cls, ble_id: int) -> "Effect":
        return cls(ble_id - 3)


class CctSubMode(IntEnum):
    """Sub-mode accepted with LightMode.CCT (category 9 [5] / category 10 [3])."""
    CCT = 2
    CCT_ALT = 3   # second CCT sub-mode accepted by the parser; meaning unconfirmed


class LightSub(IntEnum):
    """Category-1 sub-commands that are not effect parameters."""
    BRIGHTNESS = 0x01       # u16 0..100
    FADE = 0x02             # [4..5] target brightness, [6..7] seconds
    CCT = 0x03              # u16 Kelvin 2700..7500
    GM = 0x04               # green/magenta, wire value -100..+100 (inferred) -> tint 0..200
    HUE = 0x05              # u16 0..360
    SATURATION = 0x0C       # u8 0..100
    MODEL_ID = 0x32         # GET
    DEVICE_NUMBER = 0x34    # SET/GET the 1..512 "CH" word (also renames the module)
    MODULE_REINIT = 0x5A    # binary module only
    CONNECTION_STATUS = 0x5B
    APPLY_PENDING = 0x5D
    CACHE_WRITE = 0x5E
    SYSTEM_DATA = 0x62      # GET u32
    BIND = 0x64             # SET u32 clock + g_ble_device_id = 1
    UNBIND = 0x65


class ConfigSub(IntEnum):
    STATE_DUMP = 1
    HW_MODEL = 3
    DEVICE_NUMBER = 4
    CLOCK = 5
    SERIAL = 6


class FrameType(IntEnum):
    """TYPE byte of an FA 55 transport frame."""
    COMMAND = 1
    OTA = 2


class ProtoType(IntEnum):
    """g_ble_protocol_type: which BLE module was detected at boot."""
    NONE = 0
    AT_TEXT = 1   # "NanGuang" AT-command module (+DATA= / AT+NDRPT=)
    BINARY = 2    # transparent UART module (FA 55 frames)


class FlashSaveReason(IntEnum):
    """g_flash_save_pending: deferred EEPROM write reason codes."""
    NONE = 0
    CCT = 1
    HSI_HUE = 2
    HSI_SAT = 3
    BRIGHTNESS = 4
    OUTPUT_MODE = 5
    EFFECT_SELECT = 11
    DEVICE_SETTINGS = 18
    DIRECT_RANGES = 21
    FX_HUE_LOOP = 22
    CCT_TINT = 23
    FX_CCT_LOOP = 25
    FX_INT_LOOP = 26
    FX_CCT_FLASH = 27
    FX_HUE_FLASH = 28
    FX_CCT_PULSE = 29
    FX_HUE_PULSE = 30
    FX_STORM = 31
    FX_POLICE_CAR = 32
    FX_TV = 33
    FX_PAPARAZZI = 34
    FX_CANDLE_FIRE = 35
    FX_DISCO = 36
    FX_BAD_BULB = 37
    FX_FIREWORK = 38
    FX_EXPLOSION = 39
    FX_WELDING = 40


class WirelessProto(IntEnum):
    """EEPROM byte 250 / g_dimmer_curve_type: 2.4 GHz remote protocol (menu "V1.0"/"V2.0")."""
    V1 = 0   # RF_CH 115, 4-byte payload
    V2 = 1   # RF_CH 60, 32-byte payload (default)
