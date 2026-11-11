"""Command-line interface: ``pavotube --help``.

Offline commands (no hardware needed):
    pavotube encode cct 5600 --brightness 40      print the bytes that would be sent
    pavotube decode "FA 55 00 11 01 ..."          decode a frame or app packet
    pavotube effects                              list effects and parameters
    pavotube nrf24 cct --ch 1 -b 50 -k 5600       build 2.4 GHz remote payloads
    pavotube eeprom dump.bin                      decode an EEPROM dump
    pavotube fw PavoTubeII6C_V1.00.11.upd         inspect your firmware image

BLE commands (needs ``pip install pavotube[ble]``):
    pavotube scan
    pavotube services ADDRESS
    pavotube send ADDRESS cct 5600 --brightness 40
    pavotube send ADDRESS state
"""

from __future__ import annotations

import argparse
import asyncio
import sys

from . import effects as fx
from . import framing, nrf24, protocol
from .enums import Effect, LightMode, WirelessProto
from .protocol import Builder


# --- shared light commands --------------------------------------------------

def _add_light_commands(sp: argparse._SubParsersAction) -> None:
    p = sp.add_parser("brightness", help="set brightness 0..100")
    p.add_argument("percent", type=int)

    p = sp.add_parser("fade", help="fade to brightness over N seconds")
    p.add_argument("percent", type=int)
    p.add_argument("seconds", type=int)

    p = sp.add_parser("cct", help="CCT mode at Kelvin (2700..7500)")
    p.add_argument("kelvin", type=int)
    p.add_argument("-b", "--brightness", type=int)
    p.add_argument("--gm", type=int, help="green/magenta -100..+100")

    p = sp.add_parser("hsi", help="HSI mode: hue 0..360, saturation 0..100")
    p.add_argument("hue", type=int)
    p.add_argument("saturation", type=int)
    p.add_argument("-b", "--brightness", type=int)

    p = sp.add_parser("effect", help="start an effect, optionally set parameters")
    p.add_argument("name", help="effect name or number 1..17 (see `pavotube effects`)")
    p.add_argument("-p", "--param", action="append", default=[], metavar="NAME=VALUE")
    p.add_argument("-b", "--brightness", type=int)

    p = sp.add_parser("fullstate", help="one extended packet with brightness+mode+params")
    p.add_argument("mode", choices=["cct", "hsi", "effect"])
    p.add_argument("-b", "--brightness", type=int, default=50)
    p.add_argument("-k", "--kelvin", type=int, default=5600)
    p.add_argument("--gm", type=int, default=0)
    p.add_argument("--hue", type=int, default=0)
    p.add_argument("--sat", type=int, default=100)
    p.add_argument("--effect", default="1")
    p.add_argument("-p", "--param", action="append", default=[], metavar="NAME=VALUE")

    p = sp.add_parser("param", help="set a raw category-1 sub-command")
    p.add_argument("sub", type=lambda s: int(s, 0))
    p.add_argument("value", type=lambda s: int(s, 0))
    p.add_argument("--u8", action="store_true", help="value is a byte at [4]")

    p = sp.add_parser("get", help="query a value")
    p.add_argument("what", choices=["state", "hw", "serial", "clock", "number", "proto", "model", "sub"])
    p.add_argument("sub", nargs="?", type=lambda s: int(s, 0), help="for `get sub`: category-1 sub-command")

    sp.add_parser("state", help="request the full state dump")
    sp.add_parser("apply", help="category 4: apply staged values")
    sp.add_parser("trigger", help="fire STORM / EXPLOSION burst (sub 0x5D)")

    p = sp.add_parser("number", help="set the 1..512 CH/device number")
    p.add_argument("value", type=int)

    p = sp.add_parser("raw", help="send a hex app packet as-is")
    p.add_argument("hex")


def _effect_arg(s: str) -> Effect:
    if s.isdigit():
        return Effect(int(s))
    blk = fx.by_name(s)
    return blk.ui[0]


def _params(items: list[str]) -> dict[str, int]:
    out = {}
    for it in items:
        k, _, v = it.partition("=")
        out[k.strip()] = int(v, 0)
    return out


def build_packets(a: argparse.Namespace, b: Builder) -> list[bytes]:
    c = a.cmd
    if c == "brightness":
        return [b.brightness(a.percent)]
    if c == "fade":
        return [b.fade(a.percent, a.seconds)]
    if c == "cct":
        pk = [b.cct_mode(), b.cct(a.kelvin)]
        if a.gm is not None:
            pk.append(b.gm(a.gm))
        if a.brightness is not None:
            pk.append(b.brightness(a.brightness))
        return pk
    if c == "hsi":
        pk = [b.hsi_mode(), b.hue(a.hue), b.saturation(a.saturation)]
        if a.brightness is not None:
            pk.append(b.brightness(a.brightness))
        return pk
    if c == "effect":
        e = _effect_arg(a.name)
        pk = b.effect(e)
        for k, v in _params(a.param).items():
            pk.append(b.effect_param(e, k, v))
        if a.brightness is not None:
            pk.append(b.brightness(a.brightness))
        return pk
    if c == "fullstate":
        if a.mode == "cct":
            return [b.full_state_cct(a.brightness, a.kelvin, a.gm)]
        if a.mode == "hsi":
            return [b.full_state_hsi(a.brightness, a.hue, a.sat)]
        return [b.full_state_effect(a.brightness, _effect_arg(a.effect), **_params(a.param))]
    if c == "param":
        return [b.set_u8(a.sub, a.value) if a.u8 else b.set_u16(a.sub, a.value)]
    if c == "get":
        m = {"state": b.get_state, "hw": b.get_hw_model, "serial": b.get_serial, "clock": b.get_clock,
             "number": b.get_device_number, "proto": b.get_protocol_version,
             "model": lambda: b.get_light(0x32)}
        if a.what == "sub":
            if a.sub is None:
                raise SystemExit("get sub needs a sub-command number")
            return [b.get_light(a.sub)]
        return [m[a.what]()]
    if c == "state":
        return [b.get_state()]
    if c == "apply":
        return [b.apply()]
    if c == "trigger":
        return [b.trigger()]
    if c == "number":
        return [b.set_device_number(a.value)]
    if c == "raw":
        return [bytes.fromhex(a.hex.replace(":", " "))]
    raise SystemExit(f"unknown command {c}")


def _hexs(b: bytes) -> str:
    return b.hex(" ").upper()


# --- offline ------------------------------------------------------------------

def cmd_encode(a: argparse.Namespace) -> int:
    b = Builder(address=a.address, reply=not a.no_reply)
    for p in build_packets(a, b):
        print(f"packet : {_hexs(p)}")
        print(f"         {protocol.describe_packet(p)}")
        if not a.no_frame:
            print(f"frame  : {_hexs(framing.encode_frame(p))}")
        print()
    return 0


def _decode_payload(p: bytes) -> None:
    print(f"payload: {_hexs(p)}")
    if protocol.is_state_dump(p):
        print("state dump:")
        print("  " + protocol.parse_state_dump(p).describe().replace("\n", "\n  "))
        return
    print(f"  as request: {protocol.describe_packet(p)}")
    if len(p) >= 4:
        print(f"  as reply  : {protocol.parse_reply(p).describe()}")


def cmd_decode(a: argparse.Namespace) -> int:
    data = bytes.fromhex(" ".join(a.hex).replace(":", " "))
    if data[:2] == framing.MAGIC:
        dec = framing.FrameDecoder()
        frames = dec.feed(data)
        if not frames:
            print("incomplete or invalid FA 55 frame")
            return 1
        for fr in frames:
            print(f"frame  : type={fr.ftype} checksum={'ok' if fr.checksum_ok else 'BAD'} len={len(fr.payload)}")
            _decode_payload(fr.payload)
    else:
        _decode_payload(data)
    return 0


def cmd_effects(a: argparse.Namespace) -> int:
    for e in fx.BLE_EFFECTS.values():
        ui = ", ".join(f"{u.value} {u.label}" for u in e.ui)
        print(f"BLE {e.ble_id:2d}  {e.label:14s} UI: {ui}   (block L={e.block_len})")
        if a.verbose:
            for p in e.params:
                print(f"      sub 0x{p.sub:02X} {'u16' if p.width == 2 else 'u8 '} {p.name:18s} {p.note}")
    return 0


def cmd_nrf24(a: argparse.Namespace) -> int:
    proto = WirelessProto.V1 if a.proto == "v1" else WirelessProto.V2
    cfg = nrf24.radio_config(a.ch, proto)
    print(f"radio  : RF_CH={cfg.channel} ({cfg.frequency_mhz} MHz), {cfg.data_rate_mbps} Mbps, "
          f"CRC {cfg.crc_bytes} bytes, auto-ack, payload {cfg.payload_size} bytes")
    print(f"address: {_hexs(cfg.address)}  (TX_ADDR and RX_ADDR_P0, LSByte first)")
    k = a.kind
    if k == "config":
        return 0
    if k == "cct":
        p = nrf24.v1_cct(a.brightness, a.kelvin)
    elif k == "cct-tint":
        p = nrf24.v1_cct_tint(a.brightness, a.kelvin, a.tint)
    elif k == "hsi":
        p = nrf24.v1_hsi(a.brightness, a.hue, a.sat)
    elif k == "power":
        p = nrf24.v2_power_toggle()
    elif k == "mode":
        p = nrf24.v2_mode(a.value)
    elif k == "bright-up":
        p = nrf24.v2_brightness_step(True)
    elif k == "bright-down":
        p = nrf24.v2_brightness_step(False)
    elif k == "cct-wheel":
        p = nrf24.v2_cct_wheel(int(a.value))
    elif k == "hsi-wheel":
        p = nrf24.v2_hsi_wheel(int(a.value))
    else:
        raise SystemExit(k)
    v1 = k in ("cct", "cct-tint", "hsi")
    if v1 != (proto == WirelessProto.V1):
        print(f"note   : '{k}' is a {'V1.0' if v1 else 'V2.0'} payload; set the light's wireless menu accordingly")
    print(f"payload: {_hexs(p)}")
    print(f"decoded: {nrf24.v1_decode(p) if v1 else nrf24.v2_decode(p)}")
    return 0


def cmd_eeprom(a: argparse.Namespace) -> int:
    from . import eeprom
    with open(a.file, "rb") as f:
        for v in eeprom.decode(f.read()):
            print(v)
    return 0


def cmd_fw(a: argparse.Namespace) -> int:
    from . import firmware
    img = firmware.load_file(a.file)
    print(firmware.report(img))
    if a.dump_data and img.sram is not None:
        with open(a.dump_data, "wb") as f:
            f.write(bytes(img.sram))
        print(f"wrote reconstructed SRAM image (base 0x20000000, {len(img.sram)} bytes) to {a.dump_data}")
    return 0


# --- BLE ----------------------------------------------------------------------

def cmd_scan(a: argparse.Namespace) -> int:
    from . import ble
    found = asyncio.run(ble.scan(a.timeout, a.all))
    if not found:
        print("no matching devices (try --all)")
    for f in found:
        print(f"{f.address}  rssi={f.rssi}  {f.name!r}")
    return 0


def cmd_services(a: argparse.Namespace) -> int:
    from . import ble
    print(asyncio.run(ble.services(a.address)))
    return 0


def cmd_send(a: argparse.Namespace) -> int:
    from . import ble

    async def run() -> None:
        async with ble.PavoTube(a.address, write_uuid=a.write_uuid, notify_uuid=a.notify_uuid,
                                framing_mode="raw" if a.no_frame else "fa55", verbose=a.verbose) as light:
            light.b.address = a.target
            light.b.reply = not a.no_reply
            for p in build_packets(a, light.b):
                print(f"-> {_hexs(p)}   {protocol.describe_packet(p)}")
                for r in await light.send(p, wait=a.wait):
                    print(f"<- {_hexs(r)}")
                    if protocol.is_state_dump(r):
                        print("   " + protocol.parse_state_dump(r).describe().replace("\n", "\n   "))
                    elif len(r) >= 4:
                        print(f"   {protocol.parse_reply(r).describe()}")

    asyncio.run(run())
    return 0


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="pavotube", description="Nanlite PavoTube II 6C interop tool "
                                 "(unofficial; built from static analysis of firmware V1.00.11)")
    sub = ap.add_subparsers(dest="top", required=True)

    p = sub.add_parser("encode", help="print the packets/frames for a command (offline)")
    p.add_argument("--address", type=lambda s: int(s, 0), default=0xFFFF)
    p.add_argument("--no-reply", action="store_true", help="clear the reply-wanted flag")
    p.add_argument("--no-frame", action="store_true", help="don't show the FA 55 frame")
    _add_light_commands(p.add_subparsers(dest="cmd", required=True))
    p.set_defaults(func=cmd_encode)

    p = sub.add_parser("decode", help="decode an FA 55 frame or app packet (offline)")
    p.add_argument("hex", nargs="+")
    p.set_defaults(func=cmd_decode)

    p = sub.add_parser("effects", help="list BLE effect sub-modes and parameters")
    p.add_argument("-v", "--verbose", action="store_true")
    p.set_defaults(func=cmd_effects)

    p = sub.add_parser("nrf24", help="build 2.4 GHz remote payloads (offline)")
    p.add_argument("kind", choices=["config", "cct", "cct-tint", "hsi", "power", "mode",
                                    "bright-up", "bright-down", "cct-wheel", "hsi-wheel"])
    p.add_argument("--ch", type=int, default=1, help="light's CH number 1..512")
    p.add_argument("--proto", choices=["v1", "v2"], default=None,
                   help="radio protocol (default: v1 for cct/cct-tint/hsi, else v2)")
    p.add_argument("-b", "--brightness", type=int, default=50)
    p.add_argument("-k", "--kelvin", type=int, default=5600)
    p.add_argument("--tint", type=int, default=50)
    p.add_argument("--hue", type=int, default=0)
    p.add_argument("--sat", type=int, default=100)
    p.add_argument("--value", default="1", help="mode: cct|hsi|effect|next_effect; wheels: 1..4")
    p.set_defaults(func=cmd_nrf24)

    p = sub.add_parser("eeprom", help="decode a 256-byte settings EEPROM dump")
    p.add_argument("file")
    p.set_defaults(func=cmd_eeprom)

    p = sub.add_parser("fw", help="inspect your own .upd firmware image")
    p.add_argument("file")
    p.add_argument("--dump-data", metavar="OUT", help="write the reconstructed SRAM (.data/.bss) image")
    p.set_defaults(func=cmd_fw)

    p = sub.add_parser("scan", help="scan for lights (BLE)")
    p.add_argument("--timeout", type=float, default=8.0)
    p.add_argument("--all", action="store_true", help="list every advertiser")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("services", help="dump a device's GATT table (BLE)")
    p.add_argument("address")
    p.set_defaults(func=cmd_services)

    p = sub.add_parser("send", help="send a command to a light (BLE)")
    p.add_argument("address")
    p.add_argument("--write-uuid")
    p.add_argument("--notify-uuid")
    p.add_argument("--no-frame", action="store_true", help="write bare app packets (no FA 55)")
    p.add_argument("--no-reply", action="store_true")
    p.add_argument("--target", type=lambda s: int(s, 0), default=0xFFFF, help="address field [6..7]")
    p.add_argument("--wait", type=float, default=1.0, help="seconds to collect replies per packet")
    p.add_argument("-v", "--verbose", action="store_true")
    _add_light_commands(p.add_subparsers(dest="cmd", required=True))
    p.set_defaults(func=cmd_send)

    a = ap.parse_args(argv)
    if a.top == "nrf24" and a.proto is None:
        a.proto = "v1" if a.kind in ("cct", "cct-tint", "hsi") else "v2"
    try:
        return a.func(a)
    except (ValueError, KeyError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
