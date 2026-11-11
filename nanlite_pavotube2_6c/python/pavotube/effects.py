"""BLE effect parameter tables (category 1 sub-commands per effect sub-mode).

Over BLE the light exposes 15 effect sub-modes, numbered 4..18. Each one has
its own staging block of parameters (0x200051F2..0x200052D6). The firmware
copies that block into the effect engine (ble_uart_process_data, 0x08016BC8).
Sub-modes 7 and 8 each cover two on-screen effects, chosen by their
``type`` field.

Every parameter is set with a category-1 packet whose sub-command is ``sub``.
The value goes in ``[4]`` (u8) or ``[4..5]`` (big-endian u16). The firmware
does **no range checking** on these writes. The ranges shown are what the
effect engine and the on-device UI use. The same field order (the "tail") is
used by the full-state SET (category-1 extended packet, selector 1) and by
the state dump (category 3 sub 1).

Names are derived from where each value ends up in the engine. Entries
marked with ``?`` are inferred and have not been checked on hardware. See
docs/effects.md.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import Effect


@dataclass(frozen=True)
class Param:
    sub: int
    width: int    # 1 or 2 bytes
    name: str
    note: str = ""


@dataclass(frozen=True)
class BleEffect:
    ble_id: int
    label: str
    ui: tuple[Effect, ...]   # on-screen effect(s) this sub-mode drives
    engine: int               # effect engine index (= ble_id - 4)
    params: tuple[Param, ...]  # tail order

    @property
    def tail_len(self) -> int:
        return sum(p.width for p in self.params)

    @property
    def block_len(self) -> int:
        """The ``L`` byte of a full-state SET / state dump block."""
        return 4 + self.tail_len

    def param(self, name: str) -> Param:
        for p in self.params:
            if p.name == name:
                return p
        raise KeyError(f"{self.label}: no parameter {name!r} (have {[p.name for p in self.params]})")


P = Param
_LOOP_TAIL = (
    P(0x54, 1, "speed", "loop period = speed x 1 s (UI 2..30)"),
    P(0x19, 1, "direction", "? wire 1..3 -> engine 0 forward, 1 ping-pong, 2 reverse"),
    P(0x1A, 1, "overlay", "? wire value - 1 = overlay mode (strobe / random / BPM)"),
    P(0x1B, 2, "duration"),
    P(0x1C, 1, "strobe", "? strobe overlay parameter"),
    P(0x1D, 1, "random", "? random-flash overlay parameter"),
    P(0x55, 1, "bpm", "? BPM overlay parameter"),
)

BLE_EFFECTS: dict[int, BleEffect] = {e.ble_id: e for e in [
    BleEffect(4, "HUE LOOP", (Effect.HUE_LOOP,), 0, (
        P(0x06, 2, "hue_start", "0..360"),
        P(0x07, 2, "hue_end", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
    ) + _LOOP_TAIL),
    BleEffect(5, "CCT LOOP", (Effect.CCT_LOOP,), 1, (
        P(0x1E, 2, "cct_start", "Kelvin 2700..7500"),
        P(0x1F, 2, "cct_end", "Kelvin 2700..7500"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
    ) + _LOOP_TAIL),
    BleEffect(6, "INT LOOP", (Effect.INT_LOOP,), 2, (
        P(0x20, 2, "low_brightness", "0..brightness"),
        P(0x21, 1, "source", "1 = CCT, 2 = HSI"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x05, 2, "hue", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
    ) + _LOOP_TAIL),
    BleEffect(7, "CCT/HUE FLASH", (Effect.CCT_FLASH, Effect.HUE_FLASH), 3, (
        P(0x21, 1, "type", "1 = CCT FLASH, 2 = HUE FLASH"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x05, 2, "hue", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
        P(0x1B, 2, "duration", "period in ms (engine uses duration // 100 x 100 ms)"),
        P(0x1C, 1, "strobe", "? duty / frequency"),
        P(0x22, 1, "random", "? non-zero = random timing"),
    )),
    BleEffect(8, "CCT/HUE PULSE", (Effect.CCT_PULSE, Effect.HUE_PULSE), 4, (
        P(0x21, 1, "type", "1 = CCT PULSE, 2 = HUE PULSE"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x05, 2, "hue", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
        P(0x1D, 1, "bpm", "pulse rate, period = 60000 / bpm ms (UI <= 240)"),
    )),
    BleEffect(9, "STORM", (Effect.STORM,), 5, (
        P(0x23, 1, "type", "? 1 or 2 (engine variant)"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x24, 1, "interval_min", "seconds between bursts, min"),
        P(0x25, 1, "interval_max", "seconds between bursts, max (UI <= 60)"),
        P(0x26, 1, "flashes_min", "? flashes per burst, min"),
        P(0x27, 1, "flashes_max", "? flashes per burst, max"),
        P(0x22, 1, "flag", "? engine flag = (value != 1)"),
    )),
    BleEffect(10, "POLICE CAR", (Effect.POLICE_CAR,), 6, (
        P(0x21, 1, "family", "? colour family; engine family = value - 3 (0..3)"),
        P(0x28, 1, "pattern", "? engine pattern = value - 1 (0..3)"),
        P(0x53, 1, "speed", "0..100"),
    )),
    BleEffect(11, "TV", (Effect.TV,), 7, (
        P(0x21, 1, "type", "? engine variant = value - 1"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x05, 2, "hue", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
        P(0x29, 2, "param_29", "?"),
        P(0x2A, 2, "param_2a", "?"),
        P(0x53, 1, "speed", "0..100"),
        P(0x20, 2, "brightness_floor", "0..brightness"),
    )),
    BleEffect(12, "PAPARAZZI", (Effect.PAPARAZZI,), 8, (
        P(0x03, 2, "cct", "Kelvin (clamped to 7500)"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x53, 1, "speed", "0..100"),
    )),
    BleEffect(13, "CANDLE/FIRE", (Effect.CANDLE_FIRE,), 9, (
        P(0x21, 1, "type", "? engine variant = value - 1"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x05, 2, "hue", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
        P(0x29, 2, "param_29", "?"),
        P(0x2A, 2, "param_2a", "?"),
        P(0x53, 1, "speed", "0..100"),
        P(0x20, 2, "brightness_floor", "0..brightness"),
        P(0x2C, 1, "lightning", "? non-zero enables random lightning flashes"),
    )),
    BleEffect(14, "DISCO", (Effect.DISCO,), 10, (
        P(0x21, 1, "type", "? 7 = palette, 8 = alternate source"),
        P(0x2E, 1, "palette", "colour table index (UI <= 24)"),
        P(0x2F, 1, "param_2f", "?"),
        P(0x53, 1, "speed", "0..100"),
        P(0x06, 2, "hue_start", "0..360"),
        P(0x07, 2, "hue_end", "0..360"),
        P(0x08, 2, "cct_start", "Kelvin"),
        P(0x09, 2, "cct_end", "Kelvin"),
        P(0x0A, 2, "gm_start"),
        P(0x0B, 2, "gm_end"),
        P(0x0C, 1, "param_0c", "?"),
        P(0x0D, 1, "param_0d", "?"),
        P(0x0E, 1, "param_0e", "?"),
        P(0x0F, 1, "param_0f", "? (reply-layout bug in firmware)"),
        P(0x10, 1, "param_10", "?"),
        P(0x11, 1, "param_11", "?"),
        P(0x12, 1, "param_12", "?"),
    )),
    BleEffect(15, "BAD BULB", (Effect.BAD_BULB,), 11, (
        P(0x21, 1, "type", "? engine variant = value - 1"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x05, 2, "hue", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
        P(0x30, 1, "param_30", "?"),
        P(0x53, 1, "speed", "0..100"),
    )),
    BleEffect(16, "FIREWORK", (Effect.FIREWORK,), 12, (
        P(0x21, 1, "type", "? 7 or 8 selects colour source"),
        P(0x2E, 1, "colors", "colour count / table (UI <= 24)"),
        P(0x2F, 1, "param_2f", "?"),
        P(0x53, 1, "speed", "0..100"),
        P(0x31, 1, "saturation", "0..100"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x29, 2, "hue", "0..360"),
        P(0x06, 2, "param_06", "?"),
        P(0x07, 2, "param_07", "?"),
        P(0x08, 2, "param_08", "?"),
        P(0x09, 2, "param_09", "?"),
        P(0x0A, 2, "param_0a", "? (reply-layout bug in firmware)"),
        P(0x0B, 2, "param_0b", "?"),
        P(0x0C, 1, "param_0c", "?"),
        P(0x0D, 1, "param_0d", "?"),
        P(0x0E, 1, "param_0e", "?"),
        P(0x0F, 1, "param_0f", "?"),
        P(0x10, 1, "param_10", "?"),
        P(0x11, 1, "param_11", "?"),
        P(0x12, 1, "on_off", "?"),
    )),
    BleEffect(17, "EXPLOSION", (Effect.EXPLOSION,), 13, (
        P(0x23, 1, "trigger_mode", "? 2 = one-shot (fire with sub 0x5D)"),
        P(0x21, 1, "type", "? engine flag = (value != 1)"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x05, 2, "hue", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
        P(0x53, 1, "speed", "0..100"),
        P(0x31, 1, "intensity", "0..100"),
    )),
    BleEffect(18, "WELDING", (Effect.WELDING,), 14, (
        P(0x21, 1, "type", "? engine flag = (value != 1)"),
        P(0x03, 2, "cct", "Kelvin"),
        P(0x04, 2, "gm", "signed -100..+100 ?"),
        P(0x05, 2, "hue", "0..360"),
        P(0x0C, 1, "saturation", "0..100"),
        P(0x53, 1, "speed", "0..100"),
        P(0x20, 2, "brightness_floor", "0..brightness"),
        P(0x22, 1, "source", "? engine on_off = (value != 1)"),
    )),
]}


def for_effect(effect: Effect) -> BleEffect:
    """BLE sub-mode block that drives an on-screen effect."""
    for e in BLE_EFFECTS.values():
        if effect in e.ui:
            return e
    raise KeyError(effect)


def type_value_for(effect: Effect) -> int | None:
    """For sub-modes 7/8 the ``type`` field picks the CCT (1) or HUE (2) variant."""
    if effect in (Effect.CCT_FLASH, Effect.CCT_PULSE):
        return 1
    if effect in (Effect.HUE_FLASH, Effect.HUE_PULSE):
        return 2
    return None


def by_name(name: str) -> BleEffect:
    key = name.upper().replace("_", " ").replace("-", " ")
    for e in BLE_EFFECTS.values():
        if key == e.label or key in e.label.split("/") or key == e.label.replace("/", " "):
            return e
        if any(key == u.label for u in e.ui):
            return e
    raise KeyError(name)


def decode_tail(ble_id: int, tail: bytes) -> dict[str, int]:
    eff = BLE_EFFECTS[ble_id]
    out, pos = {}, 0
    for p in eff.params:
        chunk = tail[pos:pos + p.width]
        if len(chunk) < p.width:
            break
        out[p.name] = int.from_bytes(chunk, "big")
        pos += p.width
    return out


def encode_tail(ble_id: int, values: dict[str, int]) -> bytes:
    eff = BLE_EFFECTS[ble_id]
    out = bytearray()
    for p in eff.params:
        out += (values.get(p.name, 0) & ((1 << (8 * p.width)) - 1)).to_bytes(p.width, "big")
    return bytes(out)
