# PavoTube II 6C Documentation

Unofficial technical reference for the Nanlite PavoTube II 6C, firmware **V1.00.11**, produced by static analysis. **None of it has been tested on hardware.**

## Confidence legend

| Mark | Meaning |
|---|---|
| ✅ | Read directly from the code or initialised data |
| ⚠ | Inferred: consistent with the code, but not proven |
| ❓ | Unknown: needs a real device, an app capture, or the BLE module's firmware |

## Reading order

**Writing a BLE client or app**

1. [ble-transport.md](ble-transport.md): the BLE module, FA 55 framing, GATT discovery
2. [ble-protocol.md](ble-protocol.md): every app command, its replies, and worked examples
3. [effects.md](effects.md): effect sub-modes and their parameter sub-commands
4. [structures.md](structures.md): C and Python definitions
5. [../python/README.md](../python/README.md): the `pavotube` library and CLI

**Building a 2.4 GHz remote**

1. [nrf24-remote.md](nrf24-remote.md): radio settings, addressing, the V1.0/V2.0 payloads

**Firmware and hardware reverse engineering**

1. [howitworks.md](howitworks.md): architecture overview
2. [memory-map.md](memory-map.md): flash, `.upd` format, scatter loading, SRAM globals
3. [hardware.md](hardware.md): clocks, pin map, timers, power monitor
4. [eeprom-layout.md](eeprom-layout.md): settings storage
5. [color-pipeline.md](color-pipeline.md): how values become PWM duty
6. [firmware-notes.md](firmware-notes.md): misnamed IDB symbols, bugs, open questions

## Conventions

- Addresses are given as `0x0801xxxx` (flash) and `0x2000xxxx` (SRAM).
- Function names are the IDA database names, even when they are misleading; the real role is given alongside.
- Multi-byte protocol fields are big-endian unless stated otherwise.
- The pseudocode was written by hand from the analysis. No vendor code or firmware data is reproduced beyond the protocol constants needed for interoperability.
