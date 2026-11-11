# Firmware Notes: Bugs, Misnomers, Open Questions

Notes for anyone continuing the reverse engineering, or anyone wondering why the light behaves oddly.

## IDB names that are wrong

The annotated database (kept privately, not distributed) still carries these names. The right-hand column is what the code actually does.

| IDB name | Address | Real role |
|---|---|---|
| `spi_init_spi2_dma` | 0x08038854 | USART1 init (PB6/PB7) for the BLE module |
| `spi_bitbang_*`, `spi_write_bytes`, `spi_read_bytes` | 0x08034550… | nRF24 bit-banged bus |
| `led_driver_write_regs` | 0x0801A9D8 | nRF24 `STATUS = 0xFF` + `FLUSH_RX` |
| `exti9_5_nrf24_irq_handler` | 0x0801D6D0 | EXTI **line 3** handler (PB3) |
| `wireless_init_nrf24_rx` / `_tx` | 0x08038AB0 / 0x0802B014 | V1.0 / V2.0 radio init; both are receivers |
| `ble_parse_cct_packet`, `ble_parse_hsi_packet`, `ble_parse_cct_packet_ext` | — | nRF24 V1.0 parsers |
| `ble_validate_and_dispatch`, `ble_dispatch_by_cmd_word`, `ble_adjust_brightness`, `ble_remote_wheel_handler`, `ble_handle_mode_command` | — | nRF24 V2.0 path |
| `g_dimmer_curve_type` | 0x20000E96 | wireless protocol version (V1.0/V2.0) |
| `g_dimmer_curve_setting` | 0x20000F9C | CH number 1..512 |
| `g_fw_version_ptr` | 0x20003CB8 | points at the CH number, not a version |
| `g_hsi_speed` | 0x20003D36 | HSI saturation |
| `led_effect_driver` | 0x0802B408 | 50 ms button poller (called from SysTick) |
| `sys_auto_white_balance` | 0x08036D80 | battery / external-power monitor |
| `sys_auto_sleep_timer` | 0x0802B218 | BLE module keep-alive / re-init timer |
| `tim5_ble_send_irq_handler` | 0x080357FC | UART end-of-frame timer; sends nothing |
| `gpio_reset_PD10` | 0x0801F2C4 | drives **PA10** (BLE module reset) |
| `gpio_PE15_timeout_set` | — | drives **PB15** |
| `flash_*` save/load functions | — | I2C **EEPROM**; internal flash is never written |
| `effect_id_t` members | — | see the name table in [effects.md](effects.md) |
| `ui_mode_t` | — | doesn't match `g_ui_mode` |
| `eeprom_addr_t` members | — | many point at the wrong field; use raw addresses |
| comments saying "168 MHz", "SPI2+DMA pixel output", "channel 15" | — | 84 MHz, no pixel output, RF_CH 115/60 |

## Firmware bugs

| Area | Bug |
|---|---|
| EEPROM | The CCT tint byte (84) overlaps effect 2's CCT-low word (84–85) |
| EEPROM | HUE PULSE saturation/BPM share bytes 114/116 with CCT PULSE GM/BPM |
| Calibration | The blue slope is computed from `green_low` |
| CCT output | Packing two channels as `a + 0xFFFF·b` gives an off-by-one when `a < b` |
| BLE cat 10 | Validates the current sub-mode instead of the requested one |
| BLE replies | Cat 9/10 and pixel-page replies overwrite `seq`/`flags` with `2, 1` |
| BLE replies | Category-1 subs 0x0A/0x0F replies are shifted by one byte; the sub 0x11 ACK has `[3] = 0` |
| BLE state dump | Effect 11 (TV) inserts a stray zero byte but still reports the original L |
| BLE full-state | Never writes `[0..1]` of its reply |
| BLE address | The group/broadcast classification exists, but every branch is accepted |
| nRF24 V2.0 | A checksum position whose 8-bit sum is 0xFF can never validate |
| nRF24 V1.0 | `g_wired_remote_lock` gates the parsers but is never set |
| OTA | The handler accepts blocks and discards them |

## Security observations

These are relevant to anyone deploying the light where others are in radio range.

- BLE has no authentication, pairing requirement, or address enforcement. Any client in range can change light output, rename the module (sub 0x34) or toggle the bound flag.
- The nRF24 path has no authentication. Knowing (or brute-forcing) the CH value, 1..512, is enough to control the light.
- I found no path that writes firmware, because OTA is a stub, so a remote attacker cannot reflash the light through these interfaces.

## Open questions ❓

1. GATT UUIDs, and the write/notify layout, of both BLE module variants.
2. What a phone writes over GATT to the NanGuang AT module, and whether mesh provisioning is required first.
3. The exact semantics of the ⚠ and ❓ effect parameters, which need captures from the official app.
4. The meaning of the five "offset words" at EEPROM 16..24.
5. Output mode 3 ("source") and light modes 8/9: the code handles them, but nothing sets them.
6. The board's ADC divider (to convert battery counts to volts), and which white channel is warm.
7. The bootloader at 0x08000000: its update protocol (USB? UART?) and whether it checks signatures.
