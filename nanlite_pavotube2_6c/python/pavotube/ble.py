"""BLE transport built on `bleak` (``pip install pavotube[ble]``).

The GATT layout lives in the light's BLE module, not in the MCU firmware, so
the UUIDs are not known from static analysis. This module therefore:

* discovers the service table (`services()`; CLI: ``pavotube services``),
* picks a write characteristic and a notify characteristic automatically
  (preferring one service that has both), unless you pass UUIDs explicitly,
* writes app packets wrapped in FA 55 frames (``framing="fa55"``, for the
  transparent/binary module) or bare (``framing="raw"``, for experiments).

Untested on hardware. If auto-selection picks the wrong characteristic, run
``pavotube services ADDRESS`` and pass ``--write-uuid`` / ``--notify-uuid``.
"""

from __future__ import annotations

import asyncio
import re
from dataclasses import dataclass

from . import framing
from .protocol import Builder, Reply, StateDump, is_state_dump, parse_reply, parse_state_dump

try:
    from bleak import BleakClient, BleakScanner
except ImportError as e:  # pragma: no cover
    raise ImportError("BLE support needs bleak: pip install 'pavotube[ble]'") from e

# Names the firmware makes the module advertise:
#   binary module: "``NL ### XXXXXX" (unbound) or "..NL ### XXXXXX" (bound)
#   AT module:     "PavoTube II 6C" (default name written by the MCU)
NAME_RE = re.compile(r"^(``|\.\.)?NL \d{3}\b|PavoTube", re.IGNORECASE)
_STD_SERVICES = {"00001800", "00001801", "0000180a", "0000180f"}


@dataclass
class Found:
    address: str
    name: str
    rssi: int | None


async def scan(timeout: float = 8.0, show_all: bool = False) -> list[Found]:
    seen = await BleakScanner.discover(timeout=timeout, return_adv=True)
    out = []
    for dev, adv in seen.values():
        name = adv.local_name or dev.name or ""
        if show_all or NAME_RE.search(name):
            out.append(Found(dev.address, name, adv.rssi))
    return sorted(out, key=lambda f: -(f.rssi or -999))


async def services(address: str, timeout: float = 15.0) -> str:
    lines = []
    async with BleakClient(address, timeout=timeout) as c:
        lines.append(f"connected to {address}, mtu={getattr(c, 'mtu_size', '?')}")
        for s in c.services:
            lines.append(f"service {s.uuid}  {s.description}")
            for ch in s.characteristics:
                lines.append(f"  char {ch.uuid}  [{', '.join(ch.properties)}]  handle={ch.handle}  {ch.description}")
                for d in ch.descriptors:
                    lines.append(f"    desc {d.uuid}  handle={d.handle}")
    return "\n".join(lines)


def _pick(client: "BleakClient") -> tuple[str, str | None]:
    best: tuple[int, str, str | None] | None = None
    for s in client.services:
        if s.uuid[:8].lower() in _STD_SERVICES:
            continue
        writes = [c for c in s.characteristics if {"write", "write-without-response"} & set(c.properties)]
        notifies = [c for c in s.characteristics if {"notify", "indicate"} & set(c.properties)]
        if not writes:
            continue
        both = [c for c in writes if c in notifies]
        if both:
            cand = (3, both[0].uuid, both[0].uuid)
        elif notifies:
            cand = (2, writes[0].uuid, notifies[0].uuid)
        else:
            cand = (1, writes[0].uuid, None)
        if best is None or cand[0] > best[0]:
            best = cand
    if best is None:
        raise RuntimeError("no writable vendor characteristic found; pass write_uuid explicitly")
    return best[1], best[2]


class PavoTube:
    """Async client.

    Example::

        async with PavoTube("AA:BB:CC:DD:EE:FF") as light:
            await light.send(light.b.cct_mode())
            await light.send(light.b.brightness(40))
            print(await light.state())
    """

    def __init__(self, address: str, *, write_uuid: str | None = None,
                 notify_uuid: str | None = None, framing_mode: str = "fa55",
                 response: bool | None = None, timeout: float = 15.0, verbose: bool = False) -> None:
        self.address = address
        self.write_uuid = write_uuid
        self.notify_uuid = notify_uuid
        self.framing_mode = framing_mode
        self.response = response
        self.timeout = timeout
        self.verbose = verbose
        self.b = Builder()
        self._client: BleakClient | None = None
        self._decoder = framing.FrameDecoder()
        self._rx: asyncio.Queue[bytes] = asyncio.Queue()

    async def __aenter__(self) -> "PavoTube":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.disconnect()

    async def connect(self) -> None:
        self._client = BleakClient(self.address, timeout=self.timeout)
        await self._client.connect()
        if self.write_uuid is None:
            self.write_uuid, auto_notify = _pick(self._client)
            if self.notify_uuid is None:
                self.notify_uuid = auto_notify
        if self.notify_uuid:
            await self._client.start_notify(self.notify_uuid, self._on_notify)
        if self.verbose:
            print(f"[ble] write={self.write_uuid} notify={self.notify_uuid}")

    async def disconnect(self) -> None:
        if self._client is not None:
            await self._client.disconnect()
            self._client = None

    def _on_notify(self, _sender, data: bytearray) -> None:
        if self.verbose:
            print(f"[ble] <- {bytes(data).hex(' ')}")
        if self.framing_mode == "fa55":
            for fr in self._decoder.feed(bytes(data)):
                self._rx.put_nowait(fr.payload)
        else:
            self._rx.put_nowait(bytes(data))

    async def write_raw(self, data: bytes) -> None:
        assert self._client is not None, "not connected"
        ch = self._client.services.get_characteristic(self.write_uuid)
        response = self.response
        if response is None:
            response = "write-without-response" not in ch.properties
        size = max(20, getattr(self._client, "mtu_size", 23) - 3)
        for i in range(0, len(data), size):
            chunk = data[i:i + size]
            if self.verbose:
                print(f"[ble] -> {chunk.hex(' ')}")
            await self._client.write_gatt_char(ch, chunk, response=response)

    async def send(self, packet: bytes | list[bytes], wait: float = 0.0) -> list[bytes]:
        """Send one app packet (or a list). If ``wait`` > 0, collect replies
        that arrive within that many seconds after the last send."""
        pkts = packet if isinstance(packet, list) else [packet]
        for p in pkts:
            data = framing.encode_frame(p) if self.framing_mode == "fa55" else p
            await self.write_raw(data)
            await asyncio.sleep(0.05)
        replies = []
        if wait > 0:
            end = asyncio.get_running_loop().time() + wait
            while (left := end - asyncio.get_running_loop().time()) > 0:
                try:
                    replies.append(await asyncio.wait_for(self._rx.get(), left))
                except asyncio.TimeoutError:
                    break
        return replies

    async def request(self, packet: bytes, timeout: float = 2.0) -> bytes | None:
        """Send a packet and return the first reply payload (or None)."""
        while not self._rx.empty():
            self._rx.get_nowait()
        r = await self.send(packet, wait=timeout)
        return r[0] if r else None

    async def state(self, timeout: float = 2.0) -> StateDump | Reply | None:
        raw = await self.request(self.b.get_state(), timeout)
        if raw is None:
            return None
        return parse_state_dump(raw) if is_state_dump(raw) else parse_reply(raw)
