# 2.4 GHz Remote (nRF24) Protocol

The light has an nRF24L01(+)-compatible receiver for Nanlite's 2.4 GHz remotes. It is always the **receiver**, so anything that can transmit nRF24 packets can control it: an Arduino with RF24, a Raspberry Pi with pyrf24, and so on.
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown, needs a real device

The IDB mislabels several of these functions. `ble_parse_cct_packet`, `ble_parse_hsi_packet`, `ble_parse_cct_packet_ext`, `ble_validate_and_dispatch`, `ble_dispatch_by_cmd_word`, `ble_adjust_brightness`, `ble_remote_wheel_handler` and `ble_handle_mode_command` are all nRF24-remote code, not BLE. In the same way, `wireless_init_nrf24_rx` and `wireless_init_nrf24_tx` are really the init routines for protocol V1.0 and V2.0.

## Protocol version: menu "V1.0" / "V2.0" ✅

The version is stored at EEPROM byte 250 (`g_dimmer_curve_type`): 0 = V1.0, 1 = V2.0 (the default). It is shown in the settings menu (`bt_reset_handler` @0x08030F54).

## Radio configuration ✅

Both init routines write the same registers apart from the channel and payload width:

| Register | V1.0 | V2.0 | Meaning |
|---|---|---|---|
| `TX_ADDR` (0x10), 5 bytes | address | address | |
| `RX_ADDR_P0` (0x0A), 5 bytes | address | address | |
| `EN_AA` (0x01) | 0x01 | 0x01 | auto-ack on pipe 0 |
| `EN_RXADDR` (0x02) | 0x01 | 0x01 | pipe 0 only |
| `RF_CH` (0x05) | **0x73 = 115 → 2515 MHz** | **0x3C = 60 → 2460 MHz** | fixed, no hopping |
| `RX_PW_P0` (0x11) | **4** | **32** | static payload width |
| `RF_SETUP` (0x06) | 0x07 | 0x07 | **1 Mbps**, 0 dBm |
| `CONFIG` (0x00) | 0x0F | 0x0F | CRC on, **2-byte CRC**, PWR_UP, PRIM_RX |

`SETUP_AW`, `SETUP_RETR`, `DYNPD` and `FEATURE` are never written, so the chip defaults apply: 5-byte address, no dynamic payload, no ACK payload. The init comments in the IDB ("115 retries", "7 dBm", "channel 15") are wrong.

**Channel 115 (2515 MHz) is outside the 2.400–2.4835 GHz ISM band.** Many nRF24 modules and libraries clamp the channel to ≤ 125, which still allows it, but transmitting there may not be legal where you live. V2.0 uses channel 60, which is inside the band.

### Pins (bit-banged SPI, mode 0, MSB first) ✅

| Signal | Pin |
|---|---|
| CSN | PC10 |
| SCK | PC11 |
| MOSI | PC12 |
| MISO | PD2 |
| CE | PA15 |
| IRQ | PB3 (EXTI3, falling edge) |

After each RX interrupt the firmware reads 32 bytes with `R_RX_PAYLOAD` (0x61), writes `STATUS = 0xFF`, and sends `FLUSH_RX` (0xE2).

## Address: the "CH" setting ✅

There is no pairing. The pipe address comes from the light's **CH** menu value (1..512, stored in EEPROM word 52):

```
address bytes, in the order written to TX_ADDR / RX_ADDR_P0:
    00 00 00 CH_hi CH_lo
```

`sys_check_wireless_params` (0x08037B60) runs every main-loop pass and re-initialises the radio whenever CH or the protocol version changes. The initial "previous" value is 1000, so the first pass always initialises the radio with the real address.

The nRF24 clocks address bytes LSByte first, and the firmware writes `buf[0]` first. So pass exactly these 5 bytes to RF24's `openWritingPipe(const uint8_t*)`. If your library takes the address as an integer, use `CH_lo << 32 | CH_hi << 24`. For example, CH = 1 gives the bytes `00 00 00 00 01`, which is `0x0100000000` as an integer.

Auto-ack is enabled, so your transmitter also needs `RX_ADDR_P0` set to the same address to receive the ACKs. RF24 handles this automatically.

## V1.0: 4-byte payloads ✅

`sys_wireless_receive_handler` (0x08037BF0) tries three parsers in turn. A parser that accepts the packet overwrites the buffer with `AA BB CC DD`, which also stops the later parsers from matching it.

| Order | Parser | Accepted when | `b0` | `b1` | `b2` | `b3` |
|---|---|---|---|---|---|---|
| 1 | CCT `ble_parse_cct_packet` @0x080169C4 | `b0+b1 == b2` and `b2 == b3 ^ 0xFF` | brightness 0..100 | CCT index | `b0+b1` | `~(b0+b1)` |
| 2 | HSI `ble_parse_hsi_packet` @0x08029544 | `b0 ∈ {F0,F1}`, `b1 ≤ 100`, `b3 ≤ 100` | `0xF0 \| hue>>8` | brightness | `hue & 0xFF` | saturation 0..100 |
| 3 | CCT+tint `ble_parse_cct_packet_ext` @0x08028DD8 | `b0+b1 == b3` and `b2 != b3 ^ 0xFF` | brightness | CCT index | tint 0..100 | `b0+b1` |

Encodings:

- **Kelvin from the CCT index:** `K = 100 · ((48·idx + 2700) // 100)`. idx 0..100 covers 2700..7500 K; for example idx 61 gives 5600 K.
- **Tint:** the light stores `2 × tint`, giving 0..200 with 100 as neutral, so send 50 for neutral.
- **Hue:** 0..360, using the 9th bit in `b0`.
- **Mode switching:** the first CCT packet puts the light in CCT mode, and the first HSI packet puts it in HSI mode.

Examples (`pavotube nrf24 …`):

| Command | Payload |
|---|---|
| CCT 5600 K, 50 % | `32 3D 6F 90` |
| CCT+tint 3200 K, 50 %, tint 60 | `32 0B 3C 3D` |
| HSI hue 300, sat 60, 80 % | `F1 50 2C 3C` |

## V2.0: 32-byte payloads ✅

Validated by `ble_validate_and_dispatch` (0x08037B1C) and dispatched by `ble_dispatch_by_cmd_word` (0x0802D114).

```
[0..2]   don't care
[3]      L: checked length, 14..32
[4..5]   don't care
[6..7]   cmd   (BE)
[8..9]   arg   (BE)
[10..11] sub   (BE)
[12..13] flags (BE), must be 0
[L-2]    not covered by the checksum
[L-1]    checksum = (sum(bytes[0 .. L-3]) mod 256) + 1
```

The checksum comparison is done in `int`, so a frame whose 8-bit sum is `0xFF` can never validate; change a don't-care byte in that case. There is no magic number and no ID check: only the RF address filters which light responds.

| cmd | Action | arg / sub |
|---|---|---|
| 1 | power toggle: brightness ↔ 0 | — |
| 2 | mode | arg 1 + sub 1 = CCT · arg 2 + sub 1 = HSI · arg 3 + sub 1 = effects · arg 3 + sub 2 = next effect (1..17, saved) |
| 3 | brightness step | arg 1 = +1, 2 = −1 (clamped 0..100) |
| 4 | CCT wheel (CCT screen) | 1 = +100 K × step, 2 = −100 K × step (2700..7500), 3 = tint +1, 4 = tint −1. On an effect screen it adjusts that effect's CCT-type field |
| 5 | HSI wheel (HSI screen) | 1 = hue +1, 2 = hue −1 (wraps 1..360), 3 = sat +1, 4 = sat −1. On an effect screen it adjusts that effect's hue-type field |
| 6 | cmd 4 followed by cmd 5 | |

Example, brightness +1 with L = 16:

```
00 00 00 10 00 00 00 03 00 01 00 00 00 00 00 15  00 … (pad to 32)
                                              └─ (0x10+0x03+0x01) + 1
```

## Building a remote

Python (pyrf24) sketch, untested:

```python
from pyrf24 import RF24, RF24_1MBPS, RF24_CRC_16
from pavotube import nrf24

cfg = nrf24.radio_config(ch=1)                  # V2.0: RF_CH 60, 32-byte payload
radio = RF24(22, 0)                             # CE pin, SPI CSN
radio.begin()
radio.channel = cfg.channel
radio.data_rate = RF24_1MBPS
radio.crc_length = RF24_CRC_16
radio.payload_size = cfg.payload_size
radio.dynamic_payloads = False
radio.set_auto_ack(True)
radio.open_tx_pipe(cfg.address)                 # 00 00 00 00 01
radio.listen = False
radio.write(nrf24.v2_brightness_step(up=True))
```

For V1.0, use `nrf24.radio_config(ch, WirelessProto.V1)` and send 4-byte payloads such as `nrf24.v1_cct(50, 5600)`.
