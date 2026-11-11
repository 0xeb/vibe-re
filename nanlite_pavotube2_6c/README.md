# Nanlite PavoTube II 6C Firmware

Static reverse-engineering analysis of the Nanlite PavoTube II 6C LED tube light firmware, aimed at **interoperability**. It documents the BLE app protocol, the 2.4 GHz remote protocol, the settings EEPROM, the memory map and the hardware, and includes a Python client library.

> **Status:** static analysis only, not yet tested on hardware. Each statement in the docs carries a confidence mark (✅ confirmed / ⚠ inferred / ❓ unknown).

## Firmware

| Field | Value |
|-------|-------|
| File | `PavoTubeII6C_V1.00.11.upd` |
| Version | V1.00.11 |
| Size | 186,036 bytes |
| SHA-256 | `ec51bdf9d11a40f2fd7963545434c0183aa6569278d1290f7283ed62e18047dc` |
| MD5 | `fd946ff8228edd58858055c11d3f5926` |
| Target | STM32F4 / ARM Cortex-M4F, 84 MHz from the internal HSI |
| Format | Raw application image with no header or CRC, linked at `0x08010000` (bootloader below). `SP=0x20008740`, `Reset=0x0801019D` |

The firmware image is **not** distributed in this repository. Obtain it from Nanlite's official firmware update channel and check it against the hash above with `pavotube fw FILE`.

## Analysis Tool

[idasql](https://github.com/0xeb/idasql): SQL-driven analysis over an IDA database.

## Scope

- Boot path, scatter loading, super-loop and interrupt roles
- BLE: the two BLE module types, UART framing (FA 55 / `+DATA=`), every app command and reply, effect parameters
- 2.4 GHz nRF24 remote: radio configuration, CH-based addressing, V1.0 and V2.0 payloads
- Settings storage in an external I2C EEPROM: full byte map, defaults, save-reason codes
- Output: 5 PWM channels (2 white + RGB, about 40 kHz), colour math, calibration. The light has no addressable pixels
- 17 effects driven by 15 engines, with their algorithms and the PRNG
- Firmware bugs, misnamed IDB symbols, and open questions

## Repository Layout

| Path | Contents |
|------|----------|
| [`docs/README.md`](docs/README.md) | Index and reading order |
| [`docs/howitworks.md`](docs/howitworks.md) | Architecture overview |
| [`docs/ble-transport.md`](docs/ble-transport.md) | BLE module detection, AT dialogues, FA 55 frames, GATT discovery |
| [`docs/ble-protocol.md`](docs/ble-protocol.md) | App packets: all categories and sub-commands, replies, worked examples |
| [`docs/effects.md`](docs/effects.md) | Effect numbering, per-effect BLE parameters, engine algorithms |
| [`docs/nrf24-remote.md`](docs/nrf24-remote.md) | 2.4 GHz remote protocol and how to build a remote |
| [`docs/eeprom-layout.md`](docs/eeprom-layout.md) | Settings EEPROM map |
| [`docs/memory-map.md`](docs/memory-map.md) | Flash and SRAM layout, `.upd` format, key globals |
| [`docs/hardware.md`](docs/hardware.md) | Clocks, pin map, timers, power monitor |
| [`docs/color-pipeline.md`](docs/color-pipeline.md) | From CCT/HSI values to PWM duty |
| [`docs/structures.md`](docs/structures.md) | C and Python structure and enum definitions |
| [`docs/firmware-notes.md`](docs/firmware-notes.md) | Bugs, misnamed IDB symbols, open questions |
| [`python/`](python/README.md) | `pavotube` library and CLI: BLE client (bleak), packet builder and decoder, nRF24 payloads, EEPROM and firmware inspectors |

## Quick Start

```sh
cd python && pip install -e ".[ble]"
pavotube encode cct 5600 --brightness 40     # show the bytes (no hardware needed)
pavotube scan                                # find lights
pavotube services <ADDRESS>                  # discover GATT characteristics
pavotube send <ADDRESS> cct 5600 -b 40
```

Then read [docs/ble-protocol.md](docs/ble-protocol.md) for the protocol, or [docs/howitworks.md](docs/howitworks.md) for the architecture.

## Disclaimer

This analysis is for **education and interoperability** only. It is not affiliated with or endorsed by Nanlite. "Nanlite" and "PavoTube" are used only to identify the product. No vendor code or firmware image is distributed here. The docs describe the behaviour in prose and hand-written pseudocode, and the library is an independent implementation.
See the repository [LICENSE](../LICENSE) and [Disclaimer](../README.md#disclaimer).
