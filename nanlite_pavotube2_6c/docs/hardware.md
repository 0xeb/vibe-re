# Hardware (as seen from the firmware)

Everything here was decoded from register writes in firmware V1.00.11. Nobody has checked it against a board.
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown

## MCU and clocks

| Item | Value | |
|---|---|---|
| Core | ARM Cortex-M4F, STM32F4 family | ✅ |
| Part | 82-entry IRQ table matches STM32F405/407 ❓ (an F401-class part would also run at 84 MHz) | ⚠ |
| Clock source | **HSI 16 MHz** internal RC; no crystal is configured | ✅ |
| PLL | `RCC_PLLCFGR = 0x07015410`: M=16, N=336, P=4, Q=7 | ✅ |
| SYSCLK / HCLK | **84 MHz** (the IDB comments saying 168 MHz are wrong) | ✅ |
| APB1 / APB2 | 42 MHz / 84 MHz; APB1 timers run at 84 MHz | ✅ |
| Flash wait states | `FLASH_ACR = 0x705` | ✅ |
| SysTick | 1 ms | ✅ |
| Watchdog | WWDG CR written with 0x7F every loop; no WDGA enable write found | ⚠ |

## Pin map

| Function | Pin | Peripheral / mode | Notes | |
|---|---|---|---|---|
| BLE UART TX/RX | PB6 / PB7 | USART1, AF7, pull-up | 8N1, no flow control | ✅ |
| BLE module reset/enable | PA10 | GPIO out | IDB name `gpio_reset_PD10` is wrong; the write goes to GPIOA | ✅ |
| PWM ch1 ("warm") | PC9 | TIM3_CH4, AF2 | channel labels may be swapped, see [color-pipeline.md](color-pipeline.md) | ✅ |
| PWM ch2 ("cool") | PA8 | TIM1_CH1, AF1 | | ✅ |
| PWM red | PC8 | TIM3_CH3 | | ✅ |
| PWM green | PC7 | TIM3_CH2 | | ✅ |
| PWM blue | PC6 | TIM3_CH1 | | ✅ |
| nRF24 CSN | PC10 | GPIO out (bit-bang) | active low | ✅ |
| nRF24 SCK | PC11 | GPIO out | idle low, SPI mode 0, MSB first | ✅ |
| nRF24 MOSI | PC12 | GPIO out | | ✅ |
| nRF24 MISO | PD2 | GPIO in | | ✅ |
| nRF24 CE | PA15 | GPIO out | driven high after init (RX) | ✅ |
| nRF24 IRQ | PB3 | EXTI3, falling edge | NVIC IRQ9 | ✅ |
| (unknown) | PA2 | GPIO out | configured together with PA15 in the radio init | ❓ |
| EEPROM SCL / SDA | PC2 / PC1 | GPIO (bit-bang I2C) | 24C02-class, device 0xA0 | ✅ |
| OLED CLK / MOSI | PB13 / PB14 | GPIO (bit-bang SPI) | SSD1306 128×64 | ✅ |
| OLED RES / D/C | PB12 / PA9 | GPIO out | | ✅ |
| ADC battery | PC0 | ADC1 ch10 | | ⚠ |
| ADC ext. power | PC3 | ADC1 ch13 | ≥ ~1750 counts means a charger/DC is present | ⚠ |
| Main button | PB5 | GPIO in | holding for 5000 polls triggers factory reset + `NVIC_SystemReset` | ✅ |
| Keys | PA3–PA6 | GPIO in, pull-up | key codes 10–13 | ✅ |
| Standby toggle | PE2 | GPIO in | | ⚠ |
| Power latch | PB4 | GPIO out | | ⚠ |
| Delayed output | PB15 | GPIO out | forced high after 6000 loop passes (IDB: `gpio_PE15_timeout_set`) | ⚠ |
| Power-path / current-range | PC13–PC15, PH0, PH1 | GPIO out | PH1 tracks brightness ≤ 60 | ⚠ |

The light has **no SPI peripheral, no DMA and no addressable pixels.** The functions named `spi_init_spi2_dma` and `spi_*` are either the USART1 setup or the bit-banged nRF24/OLED buses.

## Timers

| Timer | Config | Use | |
|---|---|---|---|
| TIM1, TIM3 | PSC 0, ARR **2100** at 84 MHz, about **40 kHz** | 5 PWM channels; duty written **inverted** (`CCR = 2100 − value`) | ✅ |
| TIM5 | PSC 167 → 2 µs per tick, ARR = timeout/2 | UART end-of-frame detector: restarted on every received byte; expiry marks the frame complete | ✅ |
| TIM9 | PSC 83, ARR 1000 → 1 kHz | `delay_ms`-style tick | ✅ |
| SysTick | 1 kHz | ms counters, fade ramp, button poll every 50 ms | ✅ |

## BLE module

A separate BLE module is attached to USART1, and the MCU never touches the radio directly. The firmware supports two module types and detects which one is fitted at boot ([ble-transport.md](ble-transport.md)):

| Type | Detection | UART | Host-side protocol |
|---|---|---|---|
| "NanGuang" AT module | 19-byte power-up message with `"NanGuang"` at bytes 2..9 | 115200 8N1 | `+DATA=` / `AT+NDRPT=` text framing, mesh-style provisioning (`+PROVED` / `+UNPROV`) |
| Transparent module | any other power-up message > 5 bytes | **57600** 8N1 after detection | `FA 55` binary frames passed straight through to GATT |

The +++ / `a` / `+ok` / `AT+ENTM` escape sequence used for the transparent module matches USR-IOT-style UART-BLE modules ⚠.

## 2.4 GHz remote radio

An nRF24L01(+)-compatible transceiver is bit-banged on PC10–PC12/PD2/PA15/PB3. The light only ever runs it as a receiver. See [nrf24-remote.md](nrf24-remote.md).

## Settings EEPROM

A 256-byte I2C EEPROM at device address 0xA0 holds all settings; internal flash is never erased or programmed. See [eeprom-layout.md](eeprom-layout.md).

## Display

An SSD1306 128×64 OLED is driven over bit-banged SPI. The init sequence (stored at `0x08038D88`) is the usual SSD1306 sequence for 128×64 with the charge pump on and the COM scan direction reversed. Fonts are bitmap tables in flash at `0x08038D9F`, `0x08039097`, `0x08039B5A`, `0x08039FCE` and `0x0803A5BE` (8, 14, 12, 16 and 24 px). UI strings exist in ASCII and GBK versions.

## Power and battery ⚠

`sys_auto_white_balance` (0x08036D80) is misnamed: it is really the power monitor. It averages 100 ADC samples from each channel.

| Signal | Rule |
|---|---|
| ch13 (PC3) ≥ 1800 | external power present; clears the low-battery flag |
| ch13 between 1750 and 3499 | "charging" display state |
| ch10 (PC0) battery, load-compensated | `shown = batt + 0.8·brightness − 80` |
| battery bars | < 1240 → 0, < 1470 → 1, < 1650 → 2, otherwise 3 |
| cut-off (no external power) | batt < 1150 at brightness ≤ 20, or batt < 1000 above that: sets a flag and calls `NVIC_SystemReset` |

The values are raw 12-bit ADC counts. Converting them to volts needs the board's resistor divider, which is not in the firmware. I found no temperature sensor; the IDB's "overtemp" and "thermal" names refer to the battery logic above.

`sys_auto_sleep_timer` (0x0802B218) does not put the light to sleep. It counts main-loop passes (300,000, or 600,000 once the BLE module is provisioned). At 150,000 it sends `AT+NDUUID`, and at 0 it re-initialises the BLE module. The user powers off from the menu, which calls `sys_power_down` (0x080344EC).
