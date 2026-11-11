"""Build and parse PavoTube II 6C app packets (the payload inside FA 55 frames).

Short packet (8 bytes, ``ble_cmd_t``)::

    [0] seq        must differ from the previous packet's seq (duplicates are dropped)
    [1] flags      bit0 reply wanted, bit5 SET(1)/GET(0), bits3-4 header type, bit7 fragment
    [2] category   1 light, 3 config, 4 apply, 5 device info, 9 mode, 10 sub-mode
    [3] sub        sub-command (category-specific)
    [4..5] value   big-endian u16 (u8 values go in [4])
    [6..7] addr    big-endian; not enforced by the light, 0xFFFF = broadcast

Extended packet (> 8 bytes)::

    [0] seq  [1] flags  [2..3] addr  [4] frag index  [5] frag total  [6] selector  ...
    selector 1 = full-state SET, 4 = timer/scene (fade, time sync)

See docs/ble-protocol.md for every command and reply layout.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import effects as fx
from .enums import Category, ConfigSub, Effect, LightMode, LightSub
from .structs import BROADCAST, FLAG_FRAGMENT, FLAG_REPLY, FLAG_SET, BleCmd, Flags

CCT_MIN, CCT_MAX = 2700, 7500
STATE_DUMP_MAGIC = bytes([1, 1, 4, 3, 1])


class SeqCounter:
    """Sequence numbers 0..255. Consecutive packets must not repeat a seq."""

    def __init__(self, start: int = 1) -> None:
        self._v = start & 0xFF

    def next(self) -> int:
        v = self._v
        self._v = (self._v + 1) & 0xFF
        return v


@dataclass
class Builder:
    """Stateful packet builder: tracks seq and the target address.

    Every method returns raw app-packet bytes. Wrap them with
    :func:`pavotube.framing.encode_frame` before writing to a binary/transparent
    BLE module.
    """
    address: int = BROADCAST
    reply: bool = True
    seq: SeqCounter = field(default_factory=SeqCounter)

    # -- generic --------------------------------------------------------
    def short(self, category: int, sub: int, value: int = 0, *, set_: bool = True,
              value_bytes: bytes | None = None, tail: bytes | None = None) -> bytes:
        """Generic 8-byte packet. ``value_bytes`` overrides [4..5]; ``tail``
        overrides [6..7] (used where the firmware reads data from the address
        slot, e.g. fade seconds or a u32 clock)."""
        flags = Flags(reply=self.reply, set=set_).pack()
        b = bytearray(BleCmd(self.seq.next(), flags, category, sub, value, self.address).pack())
        if value_bytes is not None:
            b[4:6] = value_bytes[:2].ljust(2, b"\0")
        if tail is not None:
            b[6:8] = tail[:2].ljust(2, b"\0")
        return bytes(b)

    def set_u16(self, sub: int, value: int) -> bytes:
        return self.short(Category.LIGHT, sub, value & 0xFFFF)

    def set_u8(self, sub: int, value: int) -> bytes:
        return self.short(Category.LIGHT, sub, value_bytes=bytes([value & 0xFF, 0]))

    def get_light(self, sub: int) -> bytes:
        """GET a category-1 value (reply carries it in [4] or [4..5])."""
        return self.short(Category.LIGHT, sub, set_=False)

    # -- direct light control ------------------------------------------
    def brightness(self, percent: int) -> bytes:
        """Brightness 0..100 (category 1 sub 0x01)."""
        _check(percent, 0, 100, "brightness")
        return self.set_u16(LightSub.BRIGHTNESS, percent)

    def fade(self, percent: int, seconds: int) -> bytes:
        """Fade to ``percent`` over ``seconds`` (category 1 sub 0x02; seconds sit in [6..7])."""
        _check(percent, 0, 100, "brightness")
        return self.short(Category.LIGHT, LightSub.FADE, percent, tail=seconds.to_bytes(2, "big"))

    def cct(self, kelvin: int) -> bytes:
        """Colour temperature in Kelvin, 2700..7500 (sub 0x03). In effect mode
        this sets the active effect's CCT instead."""
        _check(kelvin, CCT_MIN, CCT_MAX, "kelvin")
        return self.set_u16(LightSub.CCT, kelvin)

    def gm(self, value: int) -> bytes:
        """Green/magenta -100..+100 (sub 0x04). The light stores value+100
        (0..200, 100 = neutral). The signed wire encoding is inferred."""
        _check(value, -100, 100, "gm")
        return self.set_u16(LightSub.GM, value & 0xFFFF)

    def hue(self, degrees: int) -> bytes:
        """HSI hue 0..360 (sub 0x05, HSI mode)."""
        _check(degrees, 0, 360, "hue")
        return self.set_u16(LightSub.HUE, degrees)

    def saturation(self, percent: int) -> bytes:
        """HSI saturation 0..100 (sub 0x0C, u8)."""
        _check(percent, 0, 100, "saturation")
        return self.set_u8(LightSub.SATURATION, percent)

    # -- modes ------------------------------------------------------------
    def mode(self, mode: LightMode, submode: int | None = None) -> bytes:
        """Select light mode (category 9). ``submode``: CCT 2/3, effect 4..18."""
        if submode is None:
            return self.short(Category.MODE, int(mode), 0)
        return self.short(Category.MODE, int(mode), value_bytes=bytes([10, submode]))

    def submode(self, submode: int) -> bytes:
        """Select a sub-mode without changing mode (category 10). Firmware bug:
        in effect mode the light validates the *current* sub-mode, not this one."""
        return self.short(Category.SUBMODE, submode, 0)

    def cct_mode(self) -> bytes:
        return self.mode(LightMode.CCT)

    def hsi_mode(self) -> bytes:
        return self.mode(LightMode.HSI)

    def effect(self, effect: Effect) -> list[bytes]:
        """Packets to start an on-screen effect (1..17). For flash and pulse
        effects this also sets the CCT/HUE ``type`` field."""
        blk = fx.for_effect(effect)
        pkts = [self.mode(LightMode.EFFECT, blk.ble_id)]
        t = fx.type_value_for(effect)
        if t is not None:
            # parameter writes only land while that effect is active, so the
            # CCT/HUE type must follow the mode select
            pkts.append(self.set_u8(0x21, t))
        return pkts

    def effect_param(self, effect: Effect, name: str, value: int) -> bytes:
        """Set one named parameter of an on-screen effect (see pavotube.effects).
        The light must already be showing that effect."""
        return self.effect_param_ble(fx.for_effect(effect).ble_id, name, value)

    def effect_param_ble(self, ble_id: int, name: str, value: int) -> bytes:
        """Same as effect_param, addressed by BLE sub-mode (4..18)."""
        p = fx.BLE_EFFECTS[ble_id].param(name)
        return self.set_u16(p.sub, value) if p.width == 2 else self.set_u8(p.sub, value)

    def apply(self) -> bytes:
        """Category 4: no handler, but forces the light to apply staged values."""
        return self.short(Category.SYNC, 0, 0)

    def trigger(self) -> bytes:
        """Sub 0x5D: apply pending changes for STORM / EXPLOSION (fire a burst)."""
        return self.set_u8(LightSub.APPLY_PENDING, 1)

    # -- queries ----------------------------------------------------------
    def get_state(self) -> bytes:
        """Category 3 sub 1: full state dump (see parse_state_dump)."""
        return self.short(Category.CONFIG, ConfigSub.STATE_DUMP, set_=False)

    def get_hw_model(self) -> bytes:
        return self.short(Category.CONFIG, ConfigSub.HW_MODEL, set_=False)

    def get_device_number(self) -> bytes:
        return self.short(Category.CONFIG, ConfigSub.DEVICE_NUMBER, set_=False)

    def get_serial(self) -> bytes:
        return self.short(Category.CONFIG, ConfigSub.SERIAL, set_=False)

    def get_clock(self) -> bytes:
        return self.short(Category.CONFIG, ConfigSub.CLOCK, set_=False)

    def set_clock(self, value: int) -> bytes:
        v = (value & 0xFFFFFFFF).to_bytes(4, "big")
        return self.short(Category.CONFIG, ConfigSub.CLOCK, value_bytes=v[:2], tail=v[2:])

    def get_protocol_version(self) -> bytes:
        return self.short(Category.DEVICE_INFO, 0, set_=False)

    def set_device_number(self, number: int) -> bytes:
        """Sub 0x34: change the 1..512 CH number. This also changes the nRF24
        address and the binary module's advertised name."""
        _check(number, 1, 512, "device number")
        return self.set_u16(LightSub.DEVICE_NUMBER, number)

    def bind(self, clock: int = 0) -> bytes:
        """Sub 0x64: store a u32 clock and mark the light as bound (name prefix '..')."""
        v = (clock & 0xFFFFFFFF).to_bytes(4, "big")
        return self.short(Category.LIGHT, LightSub.BIND, value_bytes=v[:2], tail=v[2:])

    def unbind(self) -> bytes:
        return self.set_u8(LightSub.UNBIND, 0)

    # -- extended packets ---------------------------------------------------
    def _ext(self, body: bytes) -> bytes:
        flags = Flags(reply=self.reply, set=True).pack()
        return bytes([self.seq.next(), flags]) + self.address.to_bytes(2, "big") + b"\0\0" + body

    def full_state(self, brightness: int, mode: LightMode, submode: int, tail: bytes) -> bytes:
        """Extended selector 1: push brightness, mode, sub-mode and the
        mode-specific tail in one packet (layouts in docs/ble-protocol.md)."""
        L = 4 + len(tail)
        return self._ext(bytes([1, L]) + brightness.to_bytes(2, "big")
                         + bytes([int(mode), submode]) + tail)

    def full_state_cct(self, brightness: int, kelvin: int, gm: int = 0, sub_param: int = 2) -> bytes:
        tail = bytes([0]) + kelvin.to_bytes(2, "big") + (gm & 0xFFFF).to_bytes(2, "big") + bytes([0])
        return self.full_state(brightness, LightMode.CCT, sub_param, tail)

    def full_state_hsi(self, brightness: int, hue: int, sat: int) -> bytes:
        return self.full_state(brightness, LightMode.HSI, 1, hue.to_bytes(2, "big") + bytes([sat]))

    def full_state_effect(self, brightness: int, effect: Effect, **values: int) -> bytes:
        blk = fx.for_effect(effect)
        t = fx.type_value_for(effect)
        if t is not None:
            values.setdefault("type", t)
        return self.full_state(brightness, LightMode.EFFECT, blk.ble_id, fx.encode_tail(blk.ble_id, values))

    def timer_fade(self, brightness: int, seconds: int) -> bytes:
        """Extended selector 4, op 2: fade brightness over seconds."""
        return self._ext(bytes([4, 1, 2]) + brightness.to_bytes(2, "big") + seconds.to_bytes(2, "big"))

    def time_sync(self, value: int) -> bytes:
        """Extended selector 4, op 0x63: 32-bit time value."""
        return self._ext(bytes([4, 1, 0x63]) + (value & 0xFFFFFFFF).to_bytes(4, "big"))


def fragment(packet: bytes, max_len: int) -> list[bytes]:
    """Split an extended packet into fragments (flags bit 7). The 1-based
    index/total go in [4]/[5]; fragments after the first carry only data
    after the 6-byte header. The 1-based index is inferred."""
    if len(packet) <= max_len:
        return [packet]
    hdr, body = bytearray(packet[:6]), packet[6:]
    room = max_len - 6
    chunks = [body[i:i + room] for i in range(0, len(body), room)]
    out = []
    for i, c in enumerate(chunks, start=1):
        h = bytearray(hdr)
        h[1] |= FLAG_FRAGMENT
        h[4], h[5] = i, len(chunks)
        out.append(bytes(h) + c)
    return out


# --- parsing -----------------------------------------------------------------

@dataclass
class Reply:
    raw: bytes
    seq: int
    flags: int
    category: int
    sub: int

    @property
    def value_u16(self) -> int:
        return int.from_bytes(self.raw[4:6], "big") if len(self.raw) >= 6 else 0

    @property
    def value_u8(self) -> int:
        return self.raw[4] if len(self.raw) >= 5 else 0

    @property
    def value_u32(self) -> int:
        return int.from_bytes(self.raw[4:8], "big") if len(self.raw) >= 8 else 0

    @property
    def is_ack(self) -> bool:
        return self.category == 2 and self.sub == 1

    def describe(self) -> str:
        f = Flags.unpack(self.flags)
        kind = "ACK" if self.is_ack else ("ERR" if (self.category, self.sub) == (2, 4) else "reply")
        return (f"{kind} seq={self.seq} flags=0x{self.flags:02X} (hdr={f.header_type}, echo={int(f.echo)}) "
                f"cat={self.category} sub=0x{self.sub:02X} raw={self.raw.hex(' ')}")


def parse_reply(b: bytes) -> Reply:
    b = bytes(b)
    if len(b) < 4:
        raise ValueError("reply too short")
    return Reply(b, b[0], b[1], b[2], b[3])


@dataclass
class StateDump:
    raw: bytes
    seq: int
    address: int
    hw_version: int
    model: int
    block_len: int
    brightness: int
    mode: int
    submode: int
    fields: dict[str, int]

    def describe(self) -> str:
        try:
            mode = LightMode(self.mode).name
        except ValueError:
            mode = str(self.mode)
        label = ""
        if self.mode == LightMode.EFFECT and self.submode in fx.BLE_EFFECTS:
            label = f" ({fx.BLE_EFFECTS[self.submode].label})"
        lines = [f"hw={self.hw_version} model={self.model} brightness={self.brightness} "
                 f"mode={mode} submode={self.submode}{label}"]
        lines += [f"  {k} = {v}" for k, v in self.fields.items()]
        return "\n".join(lines)


def is_state_dump(b: bytes) -> bool:
    return len(b) >= 13 and b[4:9] == STATE_DUMP_MAGIC


def parse_state_dump(b: bytes) -> StateDump:
    """Parse a category-3 sub-1 reply. Header: [seq, flags, addr(2), 01 01 04 03 01,
    hw, model, ?, 0, L, bri(2), mode, sub, tail...]."""
    if not is_state_dump(b):
        raise ValueError("not a state dump")
    if len(b) < 18:
        return StateDump(b, b[0], int.from_bytes(b[2:4], "big"), b[9], b[10], 0, 0, 0, 0, {})
    L = b[13]
    bri = int.from_bytes(b[14:16], "big")
    mode, sub = b[16], b[17]
    tail = b[18:]
    fields: dict[str, int] = {}
    if mode == LightMode.CCT and len(tail) >= 6:
        gm = int.from_bytes(tail[3:5], "big")
        fields = {"sub_param2": tail[0], "cct": int.from_bytes(tail[1:3], "big"),
                  "gm": gm - 0x10000 if gm >= 0x8000 else gm, "gm_offset": tail[5]}
    elif mode == LightMode.HSI and len(tail) >= 3:
        fields = {"hue": int.from_bytes(tail[0:2], "big"), "saturation": tail[2]}
    elif mode == LightMode.EFFECT and sub in fx.BLE_EFFECTS:
        if sub == 11 and len(tail) > 12:   # firmware inserts a stray 0 byte at tail[12]
            tail = tail[:12] + tail[13:]
        fields = fx.decode_tail(sub, tail)
    return StateDump(b, b[0], int.from_bytes(b[2:4], "big"), b[9], b[10], L, bri, mode, sub, fields)


def describe_packet(b: bytes) -> str:
    """Human-readable decoding of a request packet."""
    b = bytes(b)
    if len(b) == 8:
        c = BleCmd.unpack(b)
        f = Flags.unpack(c.flags)
        try:
            cat = Category(c.category).name
        except ValueError:
            cat = str(c.category)
        head = f"short seq={c.seq} {'SET' if f.set else 'GET'}{' +reply' if f.reply else ''} cat={cat}"
        if c.category == Category.MODE:
            try:
                m = LightMode(c.sub).name
            except ValueError:
                m = str(c.sub)
            extra = f" submode={b[5]}" if b[4] == 10 else ""
            if b[4] == 10 and c.sub == LightMode.EFFECT and b[5] in fx.BLE_EFFECTS:
                extra += f" ({fx.BLE_EFFECTS[b[5]].label})"
            return f"{head} mode={m}{extra}"
        if c.category == Category.SUBMODE:
            return f"{head} submode={c.sub}"
        name = ""
        if c.category == Category.LIGHT:
            try:
                name = f" ({LightSub(c.sub).name})"
            except ValueError:
                name = " (effect parameter)" if any(p.sub == c.sub for e in fx.BLE_EFFECTS.values()
                                                     for p in e.params) else ""
        return (f"{head} sub=0x{c.sub:02X}{name} [4..5]=0x{c.value:04X} (u16 {c.value}, u8 {b[4]}) "
                f"[6..7]=0x{c.address:04X}")
    if len(b) > 8:
        f = Flags.unpack(b[1])
        sel = b[6]
        what = {1: "full-state SET", 4: "timer/scene"}.get(sel, f"selector {sel}")
        return (f"extended seq={b[0]} flags=0x{b[1]:02X}{' fragment %d/%d' % (b[4], b[5]) if f.fragment else ''} "
                f"addr=0x{int.from_bytes(b[2:4], 'big'):04X} {what}: {b[7:].hex(' ')}")
    return f"? {b.hex(' ')}"


def _check(v: int, lo: int, hi: int, what: str) -> None:
    if not lo <= v <= hi:
        raise ValueError(f"{what} must be {lo}..{hi} (got {v})")


__all__ = [
    "Builder", "SeqCounter", "fragment", "Reply", "parse_reply", "StateDump",
    "parse_state_dump", "is_state_dump", "describe_packet", "FLAG_REPLY", "FLAG_SET",
]
