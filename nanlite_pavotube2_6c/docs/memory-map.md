# Memory Map

Firmware V1.00.11 (`PavoTubeII6C_V1.00.11.upd`, SHA-256 `ec51bdf9…8047dc`).
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown

## Address space

| Range | Size | Contents | |
|---|---|---|---|
| `0x08000000–0x0800FFFF` | 64 KB | Bootloader (not part of the `.upd`) | ⚠ |
| `0x08010000–0x0803D6B3` | 186,036 B | Application image = the `.upd` file, byte for byte | ✅ |
| `0x20000000–0x20003D17` | 15,640 B | `.data` (RW, initialised from a compressed copy in flash) | ✅ |
| `0x20003D18–0x2000873F` | 18,984 B | `.bss` (ZI, zero-filled); the stack sits at the top | ✅ |
| `0x20008740` | — | Initial stack pointer (vector 0) | ✅ |
| `0x40000000–…` | — | STM32F4 peripherals (see [hardware.md](hardware.md)) | ✅ |
| `0xE0000000–…` | — | Cortex-M4 private peripheral bus (SysTick, NVIC, SCB) | ✅ |

Nothing above `0x20008740` is referenced. The IDA SRAM segment extends to `0x20010E80`, but only because that is the default segment size.

### Why a bootloader is assumed ⚠

- `sys_clock_init` (stock CMSIS SystemInit, 0x080357xx) first sets `SCB->VTOR = 0x08000000`. `sys_main` (0x08038C0C) then sets `VTOR = 0x08010000` itself.
- The image is linked at `0x08010000`, 64 KB above the start of flash.
- The only in-application update path, BLE OTA (`ble_ota_update_handler` @0x0801B350), receives blocks but **never writes flash**. It is a stub.
- So whatever flashes `.upd` files lives below `0x08010000`: a USB/UART bootloader, or the vendor's own updater. Its protocol is not in this image.

## `.upd` file format ✅

The `.upd` is a raw binary image with no container, header, footer, signature or checksum.

| File offset | Address | Contents |
|---|---|---|
| `0x00000` | `0x08010000` | Vector table, 98 words (16 system + 82 IRQ) |
| `0x00188` | `0x08010188` | Code: C library helpers first, then application code |
| `0x2B554` | `0x0803B554` | Scatter-load table (2 entries × 16 bytes) |
| `0x2B574` | `0x0803B574` | Compressed `.data` initialiser |
| `0x2D6B2` | `0x0803D6B2` | 2 padding bytes; end of file at `0x2D6B4` |

The firmware version is **not** at a fixed offset. `"V1.00.11"` lives in `.data` at `0x20000005`. In this build it happens to appear as literal bytes inside the compressed stream (file offset `0x2B577`), but another build could encode it differently. Decompress `.data` to read it reliably: `pavotube fw FILE` does this.

## Vector table ✅

Every unused IRQ slot points at the default handler `0x080101B7`.

| Slot | Exception / IRQ | Handler | IDB name → real role |
|---|---|---|---|
| 0 | Initial SP | `0x20008740` | |
| 1 | Reset | `0x0801019D` | `Reset_handler` |
| 2–6 | NMI, HardFault, MemManage, BusFault, UsageFault | `0x080314C1`, `0x0802A6A5`, `0x08030D81`, `0x080180ED`, `0x08036CB9` | spin loops |
| 11, 12, 14 | SVCall, DebugMon, PendSV | `0x0803469D`, `0x0801AFB1`, `0x080336BD` | empty |
| 15 | SysTick | `0x08035235` | 1 ms tick |
| 25 | IRQ9 EXTI3 | `0x0801D6D1` | `exti9_5_nrf24_irq_handler` → really EXTI **line 3** (nRF24 IRQ on PB3) |
| 40 | IRQ24 TIM1_BRK_TIM9 | `0x080357D9` | `delay_tick_timer_irq_handler` (TIM9, 1 kHz) |
| 46 | IRQ30 TIM4 | `0x080357F9` | empty |
| 53 | IRQ37 USART1 | `0x08036679` | BLE module UART receive |
| 56 | IRQ40 EXTI15_10 | `0x0801D6CD` | empty |
| 66 | IRQ50 TIM5 | `0x080357FD` | `tim5_ble_send_irq_handler` → really the UART **end-of-frame** (idle-gap) timer |

There are 82 IRQ slots, IRQ0 to IRQ81 (FPU). That matches the STM32F405/407 vector layout ⚠.

## Startup and scatter loading ✅

```
Reset_handler (0x0801019C)
  sys_clock_init()                  CMSIS SystemInit + PLL (84 MHz from HSI)
  call_init_array() (0x08010868)    walks the scatter table:
     for each {src, dst, size, fn}: fn(src, dst, size)
  system_reset_thunk() -> sys_main() (0x08038C0C, never returns)
```

| Entry | `src` | `dst` | `size` | Routine |
|---|---|---|---|---|
| 0 | `0x0803B574` | `0x20000000` | `0x3D18` | `0x0801088C`: decompress RW data |
| 1 | `0x0803D6B4` | `0x20003D18` | `0x4A28` | `0x0803837C`: zero-fill |

### RW decompressor (ARM Compiler RW compression) ✅

This is my own pseudocode of the decompressor at `0x0801088C`; it is the format reimplemented in `pavotube/firmware.py`:

```
until out reaches size:
    t   = next byte
    lit = t & 7;  if lit == 0: lit = next byte
    run = t >> 4; if run == 0: run = next byte     # read after lit
    copy (lit - 1) literal bytes from the input
    if t & 8:  d = next byte; copy (run + 2) bytes from out[-d], one at a time (may overlap)
    else:      write run zero bytes
```

Constants that look "missing" in IDA (strings, tables, AT prefixes) are in `.data` and only appear after decompression. Run `pavotube fw FILE --dump-data sram.bin` to get a 34,624-byte image of SRAM at `0x20000000` that you can load into a disassembler.

## Key globals ✅

Names are the IDB's, and several of them are misleading; the *Role* column gives the real use.

| Address | IDB name | Type | Role |
|---|---|---|---|
| `20000005` | `g_fw_version_string` | char[] | `"V1.00.11"` |
| `20000034` | `g_cct_lookup_table` | u16[] | Kelvin calibration LUT (starts 2700, 3000, 3200, 3400 …) |
| `20000A96` | effect name table | char[18][20] | `"HUE LOOP"` … `"WELDING"` (index 1..17) |
| `20000E6D` | `g_ui_mode` | u8 | screen: 1 CCT, 2 HSI, 3 effect, 4 settings |
| `20000E6E` | `g_ui_edit_param` | u8 | highlighted field (mode-dependent) |
| `20000E70` | `g_flash_save_pending` | u8 | deferred **EEPROM** save reason ([eeprom-layout.md](eeprom-layout.md)) |
| `20000E71` | `g_wireless_tx_buf` | u8[5] | nRF24 pipe address `00 00 00 CHhi CHlo` |
| `20000E76` | `g_nrf24_rx_buf` | u8[32] | nRF24 RX payload |
| `20000E96` | `g_dimmer_curve_type` | u8 | **wireless protocol** 0 = V1.0, 1 = V2.0 |
| `20000ECE` | `g_wheel_step_size` | u8 | remote CCT step multiplier (initial 1) |
| `20000ED6–20000F59` | `g_fx_*` | — | on-device effect parameters ([effects.md](effects.md)) |
| `20000F5C–20000F97` | `g_pixel_cal_*` | `led_pixel_cal_t` | per-channel PWM calibration |
| `20000F9C` | `g_dimmer_curve_setting` | u16 | **CH number** 1..512 |
| `20000FA8/FAC` | `g_iir_alpha/beta` | float | output smoothing (0.999/0.001 or 0.9/0.1) |
| `20000FB4` | `g_device_config_block` | u8[8] | [0] hw version, [1] model id, [4..7] clock |
| `20000FF4–20001004` | `g_pwm_ch1..5_filtered` | float | smoothed PWM values |
| `200023E8` | `g_pwm_arr_period` | u16 | 2100 |
| `200023FC` | `g_prng_state` | u32 | effect PRNG state (initial 457) |
| `20003318–200034FB` | effect tables | — | strobe patterns, hue orders, palettes |
| `200034FC/500` | `g_gamma_slope/intercept` | float | 0.97778 / 2.222 (linear) |
| `20003C7C–20003CB4` | BLE callback table | fn ptrs | HAL hooks used by the BLE stack |
| `20003CD8` | `g_uart_timeout_ms` | u16 | UART idle gap in µs (3000) |
| `20003CDB` | `g_at_tx_frame_buf` | char[] | `"AT+NDRPT="` + session + length + `,` + 0xC1 |
| `20003CF0/CF7` | `g_ble_sig_string_1/2` | char[7] | `"+UNPROV"`, `"+PROVED"` |
| `20003D0E/0F` | `g_ble_last_seq_*` | u8 | duplicate-seq filters |
| `20003D18` | `g_brightness_level` | u16 | 0..100 |
| `20003D22` | `g_cct_temp_direct` | u16 | Kelvin |
| `20003D30` | `g_cct_tint_offset` | u8 | 0..200, 100 = neutral |
| `20003D31` | `g_led_output_mode` | u8 | 0 CCT, 1 HSI, 2 effect |
| `20003D34` | `g_hsi_hue_angle` | u16 | 0..360 |
| `20003D36` | `g_hsi_speed` | u8 | actually HSI **saturation** 0..100 |
| `20003D66` | `g_wired_remote_lock` | u8 | gates the nRF24 V1 parsers; never written, so always 0 |
| `20003D6B` | `g_active_effect_mode` | u8 | effect 1..17 |
| `20003D86` | `g_display_page_buffer` | u8[1024] | 128×64 OLED frame buffer |
| `20004654` | `g_ble_protocol_type` | u8 | 0 none, 1 AT module, 2 binary module |
| `2000465C` | `g_uart_rx_buf` | u8[256] | UART ring buffer |
| `20004762` | `g_ble_rx_packet` | u8[2052] | reassembled app packet |
| `20004FEA` | `g_ble_tx_buf` | u8[300] | reply buffer |
| `20005173` | `g_ble_device_name` | char[33] | advertised name (binary module) |
| `20005194–97` | `g_at_session_hdr_0..3` | u8 | 4-byte session field echoed to the AT module |
| `200051A7` | `g_ble_device_id` | u8 | bound flag (0/1) |
| `200051F0` | `g_ble_effect_sub_mode` | u8 | BLE effect sub-mode 4..18 |
| `200051F2–200052D6` | `g_ble_fx4_*` … `g_ble_fx18_*` | — | BLE effect staging blocks ([effects.md](effects.md)) |
| `20005618` | `g_device_serial_number` | u24 | serial reported over BLE |
| `2000563D` | `g_pixel_page_buffer` | u8[4096] | target of the pixel-page write command (unused by the output path) |
