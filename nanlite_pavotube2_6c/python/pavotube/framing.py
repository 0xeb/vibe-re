"""Transport framing between the BLE module and the light's MCU.

Two BLE modules are supported by the firmware (docs/ble-transport.md):

* **Binary / transparent module** (``ProtoType.BINARY``): app packets travel
  inside ``FA 55`` frames. Because the module is transparent, a BLE client is
  expected to write these frames to the module's GATT characteristic as-is.

      FA 55 | LEN_H LEN_L | TYPE | payload ... | CK_H CK_L | 0D 0A
      LEN  = len(payload) + 9           (whole frame, big-endian)
      CK   = (sum(FA .. last payload byte) + 1) & 0xFFFF, big-endian

* **AT-text "NanGuang" module** (``ProtoType.AT_TEXT``): the module wraps data
  as ``+DATA=`` lines towards the MCU and the MCU replies with ``AT+NDRPT=``.
  This is the UART side only; what a phone writes over GATT in that case is
  not visible in the MCU firmware. Helpers are provided for UART sniffing.
"""

from __future__ import annotations

from dataclasses import dataclass

from .enums import FrameType

MAGIC = b"\xFA\x55"
TRAILER = b"\r\n"
OVERHEAD = 9
MAX_TX_FRAGMENT = 503   # device-side TX fragment limit


def checksum16(data: bytes) -> int:
    """Sum of all bytes plus one, truncated to 16 bits."""
    return (sum(data) + 1) & 0xFFFF


def encode_frame(payload: bytes, ftype: int = FrameType.COMMAND) -> bytes:
    """Wrap an app packet in an FA 55 frame."""
    total = len(payload) + OVERHEAD
    if total > 0xFFFF:
        raise ValueError("payload too long")
    head = MAGIC + total.to_bytes(2, "big") + bytes([ftype])
    ck = checksum16(head + payload)
    return head + payload + ck.to_bytes(2, "big") + TRAILER


@dataclass
class Frame:
    ftype: int
    payload: bytes
    checksum_ok: bool


def decode_frame(frame: bytes) -> Frame:
    """Decode one complete FA 55 frame (raises ValueError if malformed)."""
    if len(frame) < OVERHEAD or frame[:2] != MAGIC:
        raise ValueError("not an FA 55 frame")
    total = int.from_bytes(frame[2:4], "big")
    if total != len(frame):
        raise ValueError(f"length field {total} != frame length {len(frame)}")
    if frame[-2:] != TRAILER:
        raise ValueError("missing CR LF trailer")
    body = frame[:-4]
    ck = int.from_bytes(frame[-4:-2], "big")
    return Frame(frame[4], frame[5:-4], ck == checksum16(body))


class FrameDecoder:
    """Incremental decoder for a byte stream (e.g. GATT notifications)."""

    def __init__(self) -> None:
        self._buf = bytearray()

    def feed(self, data: bytes) -> list[Frame]:
        self._buf += data
        out: list[Frame] = []
        while True:
            i = self._buf.find(MAGIC)
            if i < 0:
                # keep a trailing 0xFA in case the magic is split
                self._buf = self._buf[-1:] if self._buf[-1:] == b"\xFA" else bytearray()
                return out
            if i:
                del self._buf[:i]
            if len(self._buf) < 4:
                return out
            total = int.from_bytes(self._buf[2:4], "big")
            if total < OVERHEAD:
                del self._buf[:2]
                continue
            if len(self._buf) < total:
                return out
            raw = bytes(self._buf[:total])
            del self._buf[:total]
            try:
                out.append(decode_frame(raw))
            except ValueError:
                continue


# --- AT-text module (UART side) -------------------------------------------

def encode_at_ndrpt(session: bytes, payload: bytes) -> bytes:
    """What the MCU sends to an AT-text module to report data (``AT+NDRPT=``).

    Layout: ``AT+NDRPT=`` + session(4) + ``,`` + decimal(len+1) + ``,`` + 0xC1
    + payload + CR LF. ``session`` is the 4-byte header the module supplied in
    its last ``+DATA=`` line.
    """
    if len(session) != 4:
        raise ValueError("session must be 4 bytes")
    return (b"AT+NDRPT=" + session + b"," + str(len(payload) + 1).encode()
            + b"," + b"\xC1" + payload + b"\r\n")


def encode_at_data(session: bytes, b_field: bytes, payload: bytes, x: int = 0) -> bytes:
    """What an AT-text module sends to the MCU (``+DATA=``), for emulation.

    Layout: CR LF ``+DATA=`` + A(4) + ``,`` + B(4) + ``,`` + decimal(len+1)
    + ``,`` + X + payload + CR LF. The MCU skips X and ignores B.
    The separator characters are assumed to be commas.
    """
    return (b"\r\n+DATA=" + session + b"," + b_field + b"," + str(len(payload) + 1).encode()
            + b"," + bytes([x]) + payload + b"\r\n")
