# Settings EEPROM Layout

All persistent settings are stored in an **external 256-byte I2C EEPROM**, not in the STM32's internal flash. The firmware never unlocks, erases or programs internal flash; the IDB names `flash_*` are misleading.
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown

| Item | Value | |
|---|---|---|
| Bus | bit-banged I2C, SCL = PC2, SDA = PC1 | ✅ |
| Device address | `0xA0` (write) / `0xA1` (read); `0xA0 \| (addr_hi << 1)` for the word routines | ✅ |
| Part | 24C02-class, 256 bytes | ⚠ |
| Word format | **big-endian** (MSB at `addr`, LSB at `addr+1`) | ✅ |
| Write granularity | one byte or word per transaction, 10 retries, no page writes | ✅ |
| Integrity | none: no CRC or version byte. Each value is range-checked at boot and replaced with its default if out of range | ✅ |

Driver functions:

| Function | Role |
|---|---|
| `i2c_eeprom_read_word` @0x08038958 / `i2c_eeprom_write_word` @0x08038A28 | 16-bit access |
| `i2c_read_byte` @0x080388FC / `i2c_write_word` @0x080389E0 | 8-bit access (the second is misnamed) |
| `sys_load_saved_settings` @0x08035294 | loads the general settings |
| `flash_load_all_effect_params` @0x08033DF4 | loads the effect pages |
| `eeprom_read_calibration` | loads the calibration block |
| `flash_save_pending_params` @0x08034718 | the single writer |

To decode a dump, run `pavotube eeprom dump.bin`.

## General settings

| Addr | Size | Field | Valid at boot | Default |
|---|---|---|---|---|
| 10 (0x0A) | w | CCT, Kelvin | 2700..7500 | 2700 |
| 12 (0x0C) | w | HSI hue | not checked | — |
| 14 (0x0E) | w | HSI saturation (IDB: "speed") | ≤ 100 | 100 |
| 16, 18, 20, 22, 24 | w ×5 | offset words (IDB: "DMX ch2/4/3/0/1 offset") ❓ | 5000..15000 | 4200 |
| 26 (0x1A) | w | brightness | ≤ 100 | 0 |
| 28 (0x1C) | w | output mode: 0 CCT, 1 HSI, 2 effect | — | — |
| 52 (0x34) | w | **CH number**: nRF24 address and BLE name number | 1..512 | 1 |
| 56 (0x38) | w | standby mode | — | — |
| 62, 64 | w, w | magic `0x59A3`, `0xA65C` | guards 66/68 | rewritten if bad |
| 66, 68 | w, w | CCT direct range start / end | used only if the magic is valid | 3200 / 5600 |
| 70, 72 | w, w | magic `0x59A3`, `0xA65C` | guards 74/76 | rewritten if bad |
| 74, 76 | w, w | HSI direct range start / end | used only if the magic is valid | 3200 / 5600 |
| 84 (0x54) | b | CCT green/magenta tint, 0..200 (100 = neutral) | ≤ 200 | 50 |
| 192 (0xC0) | b | active effect 1..17 | 1..17 | 1 |
| 194 (0xC2) | w | display size: 0 small / 1 large | 0/1 | 0 |
| 250 (0xFA) | b | wireless protocol: 0 = V1.0, 1 = V2.0 | 0/1 | 1 |
| 252 (0xFC) | b | BLE "bound" flag (`g_ble_device_id`) | — | — |

## Calibration block

| Addr | Field |
|---|---|
| 218 (0xDA) | w: magic `0x55AA`. The block below is only used if this matches |
| 230 / 232 | w: PWM ch1 low / high |
| 234 / 236 | w: PWM ch2 low / high |
| 238 / 240 | w: red low / high |
| 242 / 244 | w: green low / high |
| 246 / 248 | w: blue low / high |

These are factory per-unit values. `led_compute_calibration` (0x08019F60) turns each low/high pair into a slope and intercept ([color-pipeline.md](color-pipeline.md)). `led_pixel_calibration` (0x08011830) is a service-menu routine that writes them.

## Effect pages (on-screen effect numbering)

w = big-endian word, b = byte. "≤ bri" means the value must not exceed the current brightness.

| # | Effect | Fields (addr: name, valid → default) |
|---|---|---|
| 1 | HUE LOOP | 78 w hue start (≤ end → 0) · 80 w hue end (≤ 360 → 360) · 82 b speed (2..30 → 8) |
| 2 | CCT LOOP | 84 w CCT low (2700..high → 3200) · 86 w CCT high (≤ 7500 → 5600) · 88 b speed (2..30 → 8) |
| 3 | INT LOOP | 90 b low brightness (≤ bri → 0) · 92 b speed (2..30 → 8) · 94 b source 0 CCT/1 HSI · 96 w CCT (→ 5600) · 98 w hue (≤ 360 → 0) |
| 4 | CCT FLASH | 100 w CCT (→ 5600) · 102 b GM (≤ 200 → 100) · 104 b speed (≤ 100 → 10) |
| 5 | HUE FLASH | 106 w hue (→ 0) · 108 b saturation (≤ 100 → 100) · 110 b speed (≤ 100 → 10) |
| 6 | CCT PULSE | 112 w CCT (→ 5600) · 114 b GM (≤ 200 → 100) · 116 b BPM (≤ 240 → 40) |
| 7 | HUE PULSE | 118 w hue (→ 0) · **114** b saturation · **116** b BPM (shared with #6) |
| 8 | STORM | 124 w CCT (→ 5600) · 126 b interval min (≤ max → 2) · 128 b interval max (≤ 60 → 6) |
| 9 | POLICE CAR | 130 b pattern (≤ 3 → 1) · 132 b speed (≤ 100 → 50) |
| 10 | TV | 134 w CCT · 136 b GM · 138 b speed (→ 50) · 140 b brightness floor (≤ bri → 0) |
| 11 | PAPARAZZI | 142 w CCT · 146 b GM · 148 b speed |
| 12 | CANDLE/FIRE | 150 w CCT · 152 b GM · 154 b speed · 156 b brightness floor |
| 13 | DISCO | 158 b palette (≤ 24 → 3) · 160 b speed (≤ 100 → 50) |
| 14 | BAD BULB | 162 b GM · 164 w CCT · 166 b speed |
| 15 | FIREWORK | 168 b colours (≤ 24 → 3) · 170 b saturation (→ 50) · 172 b speed (→ 50) |
| 16 | EXPLOSION | 174 w CCT · 176 b GM · 178 b speed · 180 b intensity (≤ 100 → 50) |
| 17 | WELDING | 182 b brightness floor · 184 w CCT · 188 b GM · 190 b speed · 196 b source 0/1 |

Unless stated otherwise: CCT words are valid in 2700..7500 (default 5600), GM bytes ≤ 200 (default 100), and speed bytes ≤ 100 (default 50).

### Layout bugs ⚠

These come straight from the addresses above.

- **Address 84 is shared.** It is the CCT-mode tint byte and also the high byte of effect 2's "CCT low" word, so saving one corrupts the other.
- **Effects 6 and 7 share 114 and 116.** HUE PULSE saturation overwrites CCT PULSE GM, and both effects use one BPM.
- **194 is used twice.** The display size is read from 194 as a word, and the IDB's address enum also maps "custom on/off" there. Effect 17's on/off byte is actually at 196.
- `led_compute_calibration` uses `green_low` when computing the blue slope.

## Deferred save reasons (`g_flash_save_pending` @0x20000E70) ✅

Code that changes a value sets this reason code. The main loop then calls `flash_save_pending_params`, which writes the matching EEPROM cells and clears the code. Brightness has its own path: it is debounced for 1000 ticks and then written to address 26.

| Code | Saves | Code | Saves |
|---|---|---|---|
| 1 | CCT (10) | 28 | effect 5 HUE FLASH |
| 2 | HSI hue (12) | 29 | effect 6 CCT PULSE |
| 3 | HSI saturation (14) | 30 | effect 7 HUE PULSE |
| 4 | brightness (26) | 31 | effect 8 STORM |
| 5 | output mode (28) | 32 | effect 9 POLICE CAR |
| 11 | active effect (192) | 33 | effect 10 TV |
| 18 | device settings | 34 | effect 11 PAPARAZZI |
| 21 | direct-mode ranges (66–76) | 35 | effect 12 CANDLE/FIRE |
| 22 | effect 1 HUE LOOP | 36 | effect 13 DISCO |
| 23 | CCT tint (84) | 37 | effect 14 BAD BULB |
| 25 | effect 2 CCT LOOP | 38 | effect 15 FIREWORK |
| 26 | effect 3 INT LOOP | 39 | effect 16 EXPLOSION |
| 27 | effect 4 CCT FLASH | 40 | effect 17 WELDING |
