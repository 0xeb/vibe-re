# pavotube

An unofficial Python library and CLI for the **Nanlite PavoTube II 6C**. It covers:

- BLE app packets and FA 55 framing
- 2.4 GHz (nRF24) remote payloads
- EEPROM dump decoding
- firmware image inspection

> **Status: built from static analysis of firmware V1.00.11 and not tested on hardware.**
> The BLE GATT UUIDs are not known (they live in the BLE module), so the
> client discovers them at connect time. Please report what works and what doesn't.
> Not affiliated with or endorsed by Nanlite.

## Install

```sh
pip install -e ".[ble]"      # from this directory; drop [ble] for the offline-only core
```

Requires Python 3.10 or later. The core has no dependencies; `bleak` is only needed for BLE.

## Quick start

### Offline: see exactly what goes on the wire

```sh
pavotube encode cct 5600 --brightness 40
pavotube encode hsi 240 100
pavotube encode effect "police car" -p speed=70
pavotube encode fullstate cct -b 60 -k 4300 --gm -20
pavotube decode FA 55 00 11 01 01 21 09 02 00 00 FF FF 03 8D 0D 0A
pavotube effects -v                       # every effect and its parameters
```

### BLE

```sh
pavotube scan                             # lights advertise "``NL 001 …", "..NL …" or "PavoTube II 6C"
pavotube services AA:BB:CC:DD:EE:FF       # dump GATT: find the write / notify characteristics
pavotube send AA:BB:CC:DD:EE:FF cct 3200 -b 50
pavotube send AA:BB:CC:DD:EE:FF effect storm -p interval_min=2 -p interval_max=10
pavotube send AA:BB:CC:DD:EE:FF state     # request and decode the state dump
pavotube send ADDR --write-uuid <uuid> --notify-uuid <uuid> -v brightness 80
```

`send` options:

| Option | Default | Meaning |
|---|---|---|
| `--write-uuid` / `--notify-uuid` | auto-selected | characteristics to use; auto-selection prefers one vendor service that has both |
| `--no-frame` | off | write bare app packets instead of FA 55 frames |
| `--no-reply` | off | clear the reply-wanted flag |
| `--wait SECONDS` | 1.0 | how long to collect replies after each packet |
| `-v` | off | hex-dump all traffic |

### Library

```python
import asyncio
from pavotube import Builder, encode_frame, Effect
from pavotube.ble import PavoTube

b = Builder()
print(encode_frame(b.brightness(40)).hex(" "))          # FA 55 00 11 01 01 21 01 01 00 28 FF FF 03 AC 0D 0A

async def main():
    async with PavoTube("AA:BB:CC:DD:EE:FF", verbose=True) as light:
        await light.send([light.b.cct_mode(), light.b.cct(5600), light.b.brightness(30)])
        await light.send(light.b.effect(Effect.CANDLE_FIRE))
        await light.send(light.b.effect_param(Effect.CANDLE_FIRE, "speed", 40))
        print(await light.state())

asyncio.run(main())
```

### 2.4 GHz remote payloads

```sh
pavotube nrf24 config --ch 1                    # radio settings and address
pavotube nrf24 cct -b 50 -k 5600                # V1.0 4-byte payload
pavotube nrf24 bright-up --ch 1                 # V2.0 32-byte payload
```

```python
from pavotube import nrf24
cfg = nrf24.radio_config(ch=1)                  # RF_CH 60, 32 B, 1 Mbps, CRC16, address 00 00 00 00 01
payload = nrf24.v2_mode("next_effect")
```

You need your own nRF24L01 radio to transmit these. See [../docs/nrf24-remote.md](../docs/nrf24-remote.md).

### Hardware hacking

```sh
pavotube eeprom dump.bin                        # decode a 24C02 dump (I2C 0xA0)
pavotube fw PavoTubeII6C_V1.00.11.upd           # vectors, scatter table, version
pavotube fw PavoTubeII6C_V1.00.11.upd --dump-data sram.bin   # decompressed .data image at 0x20000000
```

`fw` works on an image you supply. No firmware data ships with this package.

## Modules

| Module | Contents |
|---|---|
| `protocol` | `Builder` (one method per command; tracks `seq`), `fragment`, `parse_reply`, `parse_state_dump`, `describe_packet` |
| `framing` | `encode_frame` / `decode_frame` / `FrameDecoder` (FA 55), `encode_at_ndrpt` / `encode_at_data` (AT module UART side) |
| `effects` | `BLE_EFFECTS`: sub-modes 4..18 with parameter sub-commands, widths and tail order; `for_effect`, `encode_tail`, `decode_tail` |
| `enums` | `Category`, `LightMode`, `OutputMode`, `UiMode`, `Effect`, `LightSub`, `ConfigSub`, `FlashSaveReason`, `ProtoType`, `WirelessProto` |
| `structs` | `BleCmd`, `Flags`, `LedOutput`, `PixelCal` |
| `nrf24` | `radio_config`, `address_for_channel`, `v1_cct` / `v1_cct_tint` / `v1_hsi`, `v2_frame` and helpers, decoders |
| `eeprom` | `FIELDS` map and `decode()` |
| `firmware` | `load_file`, `decompress_rw`, `report` |
| `ble` | `scan`, `services`, `PavoTube` async client (requires bleak) |

## Caveats

- **GATT is unknown.** The library assumes a transparent module that passes FA 55 frames straight through. If your unit has the "NanGuang" AT module, the GATT-side format may be different ([../docs/ble-transport.md](../docs/ble-transport.md)).
- **Parameters marked `?`** in `pavotube effects -v` are inferred from where the firmware routes the value; their exact meaning and units still need confirming.
- **No range checks in the firmware.** Category-1 SETs are stored as sent. The builder validates the common ones (brightness, CCT, hue, saturation, GM), but not raw `param` or effect values.
- **No authentication.** The light accepts commands from any client in range.
