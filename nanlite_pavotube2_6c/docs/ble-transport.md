# BLE Transport

The light's MCU does not run a BLE stack. A separate BLE module is wired to USART1 (PB6/PB7), and the MCU exchanges **app packets** ([ble-protocol.md](ble-protocol.md)) with it over that UART. This page covers the layer underneath the app packets: how the module is detected, how bytes are framed on the UART, and what a phone or PC client should write over GATT.
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown, needs a real device

```
 phone / PC  ──BLE GATT──►  BLE module  ──UART──►  STM32 (this firmware)
                            (vendor fw)          ble_comm_tick → ble_parse_rx_packet
                                                 → ble_cmd_dispatch → handlers
```

## What static analysis can't tell you ❓

- The **GATT service and characteristic UUIDs**, which characteristic to write and which to subscribe to, the MTU, and the advertising data. These all live in the module's own firmware.
- For the AT ("NanGuang") module: what a phone writes over GATT, and whether the module needs mesh-style provisioning before it will pass data.
- Which module a given unit has. It may differ between production runs.

**Finding the UUIDs.** Run `pavotube scan`, then `pavotube services ADDRESS`. Look for a vendor service (not 0x1800/0x1801/0x180A) with a write or write-without-response characteristic and a notify characteristic. Transparent UART modules commonly expose a single characteristic that does both, or a write/notify pair; `pavotube send` picks one of these layouts automatically. If it picks wrong, pass `--write-uuid` and `--notify-uuid`. If you confirm the UUIDs on real hardware, please add them here.

## UART link ✅

| Item | Value |
|---|---|
| Peripheral | USART1, PB6 TX / PB7 RX (AF7), IRQ37 |
| Format | 8N1, no flow control, 16× oversampling |
| Baud | **115200** at boot (`BRR = 0x2D9` at 84 MHz). Switches to **57600** (`BRR = 0x5B2`) once a binary module is detected |
| Frame end | an idle gap. TIM5 is restarted on every byte, and a gap of `g_uart_timeout_ms` (3000 µs) ends the frame |
| RX buffer | 256-byte ring (`g_uart_rx_buf`) |
| Module reset | PA10 is pulsed low at boot and when the module is re-initialised |

## Module detection ✅

After reset, `uart_check_at_response` (0x08014818) listens without sending anything and classifies the module's power-up message:

| Power-up message | Result | `g_ble_protocol_type` |
|---|---|---|
| 19 bytes with `"NanGuang"` at bytes 2..9 | AT-text module | 1 |
| anything else longer than 5 bytes | binary / transparent module | 2 |
| nothing | no module | 0 |

## Binary / transparent module (type 2) ✅

### Configuration dialogue (MCU → module, every command ends in CR LF)

| Step | MCU sends | Expects |
|---|---|---|
| Enter command mode | `+++` | `a` |
| | `a` | `+ok\r\n` |
| Read name | `AT+NAME?` | name |
| Set name | `AT+NAME=<name>` | `+ok` |
| Read mode | `AT+MODE?` | mode |
| Set mode | `AT+MODE=S` | `+ok` (mode `S` is required; F, M and B also exist) |
| Return to data mode | `AT+ENTM` | `…ENTM…ok…` |

The MCU then switches to 57600 baud and reads the bound flag from EEPROM 0xFC.

### Advertised name ✅

Built by `ble_build_device_name` (0x08036918):

```
"``NL 001 00000A"    unbound   (prefix 0x60 0x60)
"..NL 001 00000A"    bound     (prefix "..", after command 0x64)
     │   │   └─ 24-bit serial, 6 hex digits
     │   └───── CH number 1..512 as 3 decimal digits
     └───────── literal "NL "
```

The IDB calls the CH number `g_fw_version_ptr`; it is really the 1..512 CH word. `ble_init_device_info` hardcodes the serial to `0x00000A` ⚠.

### FA 55 frame ✅

Frames in both directions use this format. The MCU builds them in `ble_send_packet` (0x08015910) and parses them in `ble_parse_rx_packet` (0x08012D10):

```
offset  0    1    2      3      4      5 … n+4      n+5   n+6   n+7  n+8
       ┌────┬────┬──────┬──────┬──────┬───────────┬─────┬─────┬────┬────┐
       │ FA │ 55 │ LEN_H│ LEN_L│ TYPE │ payload(n)│ CK_H│ CK_L│ 0D │ 0A │
       └────┴────┴──────┴──────┴──────┴───────────┴─────┴─────┴────┴────┘
LEN  = n + 9   (the whole frame, big-endian)
TYPE = 1 command/app packet, 2 OTA (handler is a stub)
CK   = (sum of bytes 0 .. n+4) + 1, truncated to 16 bits, big-endian
```

Worked example: CCT mode, a category-9 app packet `01 21 09 02 00 00 FF FF`.

```
FA 55 00 11 01 | 01 21 09 02 00 00 FF FF | 03 8D | 0D 0A
sum(FA..FF) = 0x38C, +1 = 0x038D
```

Details:

- For unfragmented TYPE-1 frames the MCU takes the payload length from byte 3 alone, so keep frames under 256 bytes.
- The MCU sends fragments of at most 503 bytes.
- Because the module is transparent, **the client is expected to write FA 55 frames to the GATT characteristic as-is** ⚠ (strong inference). `pavotube` does this by default; use `--no-frame` to send bare app packets instead.

## AT-text "NanGuang" module (type 1) ✅ (UART side only)

### Dialogue

| MCU sends | Reply |
|---|---|
| (waits for an 11-byte message with `+UNPROV` or `+PROVED` at bytes 2..8) | |
| `AT+VER` | `+VER=<fw>,<hw>` |
| `AT+NAME?` / `AT+NAME=<name>` | |
| `AT+MODE` / `AT+MODE=0` or `AT+MODE=2` | `+MODE=…` |
| `AT+NDUUID` / `AT+NDUUID=<10 raw bytes>` | loads the device-info blob below |
| `AT+REBOOT` | |
| `AT+NDID` | `+NDID=xxxx` (`0000` means not provisioned) |
| `AT+NDRESET` | (sent from the "Reset bluetooth" menu) |

The module can also send these lines unprompted:

| Line | Effect |
|---|---|
| `\r\nOK\r\n` | acknowledges a transmit |
| `\r\n+PROVED\r\n` | provisioned: sets `g_ble_mode_set` and re-reads NDID |
| `\r\n+UNPROV\r\n` | unprovisioned: reruns setup |

### Data framing

From the module to the MCU (parsed in `ble_comm_tick`):

```
\r\n+DATA=<A:4 bytes>,<B:4 bytes>,<N in decimal>,<X:1 byte><payload: N-1 bytes>\r\n
```

The MCU stores A as the session field and ignores B and X. A partial frame is dropped after 100 ticks.

From the MCU to the module (`ble_send_packet`, the string is in `.data` at `0x20003CDB`):

```
AT+NDRPT=<A:4 bytes>,<N+1 in decimal>,<0xC1><payload>\r\n
```

The MCU sends at most 128 bytes per chunk and waits for `\r\nOK\r\n` after each one.

### Device-info blob (`AT+NDUUID=`) ✅

Built by `ble_build_device_info_packet` (0x0801F85C):

```
[CH_hi, CH_lo, 0, 0, serial(3, big-endian), pixel_ready, 'N', sum8(bytes 0..8)]
```

Whether this ends up in the advertising data is ❓.

## Timeouts and housekeeping

- The idle gap of 3 ms marks the end of a UART frame.
- AT replies get longer windows; for example `AT+NDRESET` waits 320 ms.
- About every 300k main-loop passes (600k once provisioned), the MCU sends `AT+NDUUID` and later re-initialises the module (`sys_auto_sleep_timer`).
