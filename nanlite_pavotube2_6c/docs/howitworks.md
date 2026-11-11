# PavoTube II 6C Firmware Logic Overview

Nanlite PavoTube II 6C LED tube light firmware, version `V1.00.11`.
Target: STM32F4 / ARM Cortex-M4F at 84 MHz (internal HSI + PLL).

> This is the architecture overview. The detailed references are linked from
> [README.md](README.md): BLE ([ble-transport.md](ble-transport.md),
> [ble-protocol.md](ble-protocol.md)), the 2.4 GHz remote
> ([nrf24-remote.md](nrf24-remote.md)), [effects.md](effects.md),
> [eeprom-layout.md](eeprom-layout.md), [memory-map.md](memory-map.md),
> [hardware.md](hardware.md) and [color-pipeline.md](color-pipeline.md).
> Several names below are the IDA database's, and some of them are misleading;
> [firmware-notes.md](firmware-notes.md) gives the real role of each.

This document describes the firmware as a control system: how execution starts,
how the main loop is organized, how inputs flow into shared state, how that
state becomes light output, and how settings are persisted.

---

## Execution Hierarchy

```text
Reset_handler
  -> sys_clock_init()
  -> call_init_array()
  -> sys_main()                                  [never returns]
       -> sys_peripheral_init()
       -> while (1)
            -> watchdog refresh
            -> poll buttons
            -> process wireless remote input
            -> run ui_mode_state_machine()
            -> flush deferred EEPROM saves
            -> battery monitor / BLE-module keep-alive timers
            -> run the effect engine, compute and emit PWM output
            -> process BLE UART traffic

SysTick_handler() runs in parallel every 1 ms
  -> led_effect_driver()   (despite the name: the 50 ms button poller)
  -> timing counters
  -> fade_ramp_tick()
```

At a high level, the firmware is a classic embedded super-loop with a few
important interrupt-driven ingress points:

- buttons and some housekeeping are polled in the main loop
- BLE bytes arrive through `USART1` interrupt service
- the nRF24 wireless receiver is serviced through its external interrupt path
- the 1 ms SysTick interrupt advances fades and software timers (effects are
  rendered in the main loop and timed from those counters)

Everything converges into shared SRAM globals. The main loop and periodic ticks
turn that state into PWM values, display updates, and persisted settings.

---

## Boot and Bring-Up

### Reset Path

Execution begins at `Reset_handler` from the vector table in flash. The reset
path:

1. configures the clock tree and PLL (84 MHz)
2. walks the ARM scatter-load table: decompresses `.data` and zero-fills `.bss`
   (`call_init_array` calls the table's routines rather than C++ constructors)
3. transfers control into `sys_main()`

`sys_main()` is the real firmware entrypoint and never returns.

### `sys_main()`

`sys_main()` performs one-time platform setup before entering the steady-state
super-loop:

- points `VTOR` at the flash vector table
- masks interrupts during critical setup
- configures interrupt priority grouping
- computes runtime clock frequencies
- calls `sys_peripheral_init()`

After initialization, the rest of the firmware is driven by the endless loop.

### `sys_peripheral_init()`

`sys_peripheral_init()` is the hardware bring-up hub. Its responsibilities are:

- enable interrupts
- initialize SysTick and auxiliary timing
- initialize USART1 for the BLE module and detect which module type is fitted
- initialize ADC channels used for battery / external-power sensing
- initialize buttons and GPIO
- load saved settings from the external I2C EEPROM
- load all saved effect parameter pages (also from EEPROM)
- initialize the OLED display
- apply the saved light mode into the UI state machine
- initialize the 5-channel PWM output (TIM1 + TIM3, about 40 kHz)
- initialize USART1 (the function is misnamed `spi_init_spi2_dma`; there is no
  SPI/DMA pixel output on this light)
- initialize the nRF24 wireless path
- register callback pointers used by the BLE stack

The callback registration layer is important: the BLE protocol logic is not
tightly coupled to the hardware drivers. Instead, a table of function pointers
is populated at boot so the BLE stack can call timers, UART, GPIO, delays, and
command dispatch indirectly.

---

## Main Loop Responsibilities

Once initialization is complete, the firmware spends the rest of its life
cycling through a fixed sequence of jobs:

| Phase | Core functions | Purpose |
|-------|----------------|---------|
| Safety | `wwdg_refresh()` | Prevent watchdog reset |
| Local input | `sys_button_poll_handler()` | Read physical controls |
| Wireless input | `sys_wireless_receive_handler()` | Handle nRF24 remote packets |
| UI / display | `ui_mode_state_machine()` | Update screen, mode transitions, edit focus |
| Persistence | `flash_save_pending_params()` | Commit deferred parameter changes to EEPROM |
| Power | `sys_auto_white_balance()` | Battery / external-power monitor (misnamed) |
| Output | `cct_calc_white_pwm()`, `led_output_tick()`, `check_and_update_light()` | Run effects and turn state into PWM duty |
| Housekeeping | `gpio_PE15_timeout_set()`, `sys_auto_sleep_timer()` | PB15 delayed enable; BLE-module keep-alive / re-init |
| BLE | `ble_process_incoming()` | Process UART-based app commands |

This organization tells us a lot about the design philosophy:

- the firmware keeps most logic in one place instead of distributing it across
  many independent tasks
- input paths mostly stage data into globals, then the main loop reconciles the
  new state
- settings are written lazily through a deferred-save mechanism rather than
  immediately from interrupt or parser code

---

## Input and Control Paths

### Physical Buttons

Button input is handled through `sys_button_poll_handler()` in the main loop.
Those button actions ultimately feed the same shared state used by the display,
the light engine, and the persistence layer.

The UI logic is centralized in `ui_mode_state_machine()`, which means button
actions are best understood as "requests to change current mode / parameter /
value" rather than direct hardware operations.

---

## Wireless Remote Path (nRF24)

The wireless remote path uses an nRF24L01-compatible radio, bit-banged on
PC10–PC12/PD2/PA15/PB3. It supports two protocol versions, selected in the
settings menu (EEPROM byte 250): **V1.0** uses RF channel 115 with 4-byte
payloads, and **V2.0** (the default) uses channel 60 with 32-byte payloads.
The pipe address is derived from the user's CH number (1..512). Full details
are in [nrf24-remote.md](nrf24-remote.md).

### Buffering Model

The receive staging buffer is:

```c
uint8_t g_nrf24_rx_buf[32];
```

This is one shared buffer, not a set of unrelated byte globals.

- bytes `0..3` are the V1.0 payload, read by the direct CCT / HSI parsers
- the full 32-byte buffer is the V2.0 payload, read by the checksum validator
  and command-word dispatcher

### Receive Flow

The receive side revolves around `spi_chip_read_if_ready(int pipe, uint8_t *out)`.
Its logic is simple and very revealing:

1. read nRF24 register `STATUS` (`0x07`)
2. test bit `RX_DR` (`0x40`) to see whether payload data is ready
3. if ready, issue `R_RX_PAYLOAD` (`0x61`) and read `32` bytes into the caller
   buffer
4. clear pending status bits by writing to `STATUS`
5. issue `FLUSH_RX` (`0xE2`) to drop any stale FIFO state

In other words, the firmware treats the radio receive path as:

- check ready
- read one fixed-size payload block
- clear and flush aggressively

That is a good fit for a simple remote-control protocol where freshness matters
more than queued history.

### Wireless Packet Consumers

The direct wireless parsers are:

- `ble_parse_cct_packet()`
- `ble_parse_cct_packet_ext()`
- `ble_parse_hsi_packet()`

Despite the `ble_` naming, these routines belong to the nRF24 path only. The
BLE app protocol is completely separate.

At the higher level, the radio path feeds:

- `ble_validate_and_dispatch()`
- `sys_wireless_receive_handler()`

So the wireless remote is not a separate lighting subsystem. It is another front
end into the same state machine and parameter model used by the BLE app.
V1.0 payloads set absolute values (brightness, CCT, tint, hue, saturation).
V2.0 payloads are button-style commands: power toggle, mode, brightness ±1,
and wheel steps.

---

## BLE / UART Control Path

The BLE path is UART-driven and logically split into three layers:

1. byte ingress
2. packet assembly / validation
3. command dispatch

### UART Ingress

`usart1_ble_uart_irq_handler()` captures incoming BLE UART bytes into a
256-byte ring. Frames are delimited by an idle gap, not by a delimiter:

- each received byte restarts TIM5; when TIM5 expires after a 3 ms gap,
  `tim5_ble_send_irq_handler()` marks the frame complete (it sends nothing,
  despite the name)
- `delay_tick_timer_irq_handler()` (TIM9) provides a 1 ms delay tick

The module probe logic uses `uart_check_at_response()`, whose observed results
are:

| Value | Meaning |
|-------|---------|
| 0 | No usable module response |
| 1 | AT-text module response (`NanGuang` signature) |
| 2 | Binary-protocol module response |

That probe result decides which BLE transport the firmware uses at runtime. The
AT-text module wraps data in `+DATA=` / `AT+NDRPT=` lines. The binary module
uses `FA 55 len type payload checksum CR LF` frames at 57600 baud. See
[ble-transport.md](ble-transport.md).

### Packet Processing

The main loop drives BLE processing through `ble_process_incoming()`.

The core parser/dispatcher chain is:

```text
ble_process_incoming()
  -> ble_parse_rx_packet()
  -> ble_cmd_dispatch()
```

Short packets are 8 bytes:

| Byte | Meaning |
|------|---------|
| 0 | sequence number |
| 1 | flags |
| 2 | command category |
| 3 | sub-command |
| 4-5 | value (big-endian u16, or u8 in byte 4) |
| 6-7 | address (big-endian, not enforced; some commands reuse it for data) |

The flags byte contains:

- bit `0`: reply wanted
- bit `1`: set by the device in its replies
- bit `2`: echoed back
- bits `3..4`: header type (2 = short-header/pixel-page form)
- bit `5`: SET (1) or GET (0)
- bit `7`: fragmented packet (it is not a "response required" bit)

A packet whose sequence number equals the previous one is dropped as a
duplicate, so clients must change `seq` on every packet. There is no
authentication. All commands and replies are documented in
[ble-protocol.md](ble-protocol.md).

### `ble_cmd_dispatch()`

`ble_cmd_dispatch()` is the top-level BLE command router.

For 8-byte packets, the command categories currently decode as:

| Category | Handler | Meaning |
|----------|---------|---------|
| mode field `== 2` | `ble_mode2_noop_handler()` | Stub / reserved path |
| 1 | `light_control_handler()` | Direct light control: brightness, CCT, HSI, effects |
| 3 | `ble_config_handler()` | Device configuration and status exchange |
| 4 | none | No handler; the packet still triggers "apply staged values" |
| 5 | `ble_device_info_status_handler()` | Device info / status response path |
| 6 | `ble_cmd_cat6_noop_handler()` | Stub |
| 7 | `ble_cmd_cat7_noop_handler()` | Stub |
| 8 | `ble_cmd_cat8_noop_handler()` | Stub |
| 9 | `ble_light_mode_select_handler()` | Select light mode (2 CCT, 3 HSI, 7 effect) and optional sub-mode (CCT 2/3, effect 4..18) |
| 10 | `ble_light_submode_select_handler()` | Select active CCT/effect sub-mode |

For extended packets (`pkt_len > 8`), routing is based on the parsed mode field
and an additional selector byte:

| Condition | Handler | Meaning |
|-----------|---------|---------|
| parsed mode `== 2` | `ble_pixel_page_write_handler()` | Pixel-page / staged data write |
| `pkt[6] == 4` | `ble_timer_scene_sync_handler()` | Timer / scene sync handling |
| `pkt[6] == 1` | `ble_full_state_set_handler()` | Push a full brightness/effect state block |

### `light_control_handler()`

`light_control_handler()` is the largest function in the firmware and acts like
a command interpreter for day-to-day light control.

It is effectively the center of the user-facing feature set:

- brightness
- CCT control
- HSI control
- power state
- mode changes
- effect selection
- effect parameter updates (about 60 sub-commands, listed per effect in
  [effects.md](effects.md))
- device number, bind/unbind and module housekeeping

The "remote wheel" handlers are part of the nRF24 path, not this one.

This is the best function to read when the question is "what can the light
actually do?" rather than "how is the system wired?"

---

## State Model

The firmware is driven by a handful of globals that behave like explicit state
machine variables even when they were not originally declared that way in the
binary.

### `g_ui_mode`

`g_ui_mode` is the UI/state-machine mode byte used by `ui_mode_state_machine()`.

Observed values:

| Value | Name | Meaning |
|-------|------|---------|
| 1 | `UI_MODE_CCT` | Direct white / CCT editing screen |
| 2 | `UI_MODE_HSI` | HSI color editing screen |
| 3 | `UI_MODE_EFFECT` | Effect editing / effect control screen |
| 4 | `UI_MODE_SETTINGS` | Settings / system-management screen |

This numbering is distinct from the BLE light-mode protocol values. The BLE-side
working mode IDs observed in the control path are:

| Value | Meaning |
|-------|---------|
| 2 | CCT mode |
| 3 | HSI mode |
| 7 | Effect mode |

The output mode stored in EEPROM and `g_led_output_mode` uses a third
numbering: 0 CCT, 1 HSI, 2 effect.

`ble_apply_mode_selection()` bridges the saved/output-mode representation into
the UI-facing mode state.

### `g_ui_edit_param`

`g_ui_edit_param` is not one universal enum. It is a mode-dependent selector for
which field is currently active on the screen.

Observed meanings:

| UI mode | Value | Meaning |
|---------|-------|---------|
| any | 0 | No active field |
| CCT | 1 | Brightness |
| CCT | 2 | CCT temperature |
| CCT | 3 | Green/magenta tint |
| HSI | 3 | Hue |
| HSI | 4 | Saturation (stored in `g_hsi_speed`, which is misnamed) |
| HSI | 5 | Brightness / intensity |

Value `3` is intentionally overloaded by the firmware:

- in CCT mode it means tint
- in HSI mode it means hue

That overloading matches the display/highlight behavior seen in the UI refresh
logic and the BLE packet parsers.

### Effect Editing and Mode State

The effect path is split between:

- active UI mode selection
- effect/submode selection
- per-effect parameter pages in SRAM
- deferred persistence into EEPROM

`ui_mode_state_machine()` owns screen-level behavior. The effect engine runs
from the main loop: `check_and_update_light()` calls `effect_dispatch_handler()`,
which uses millisecond counters maintained by SysTick.

---

## Light Generation and Effects

The lighting engine is built around two cooperating models:

1. direct parameter control
2. periodic effect generation

### Direct Parameter Control

For direct output modes, the firmware maintains globals for values like:

- brightness
- CCT temperature
- tint / green-magenta offset (0..200, 100 = neutral)
- HSI hue (0..360)
- HSI saturation (0..100)

The main loop turns those values into output through:

- `cct_calc_white_pwm()`
- `check_and_update_light()`
- `led_output_tick()`

These end up as five PWM duties (ch1, ch2, red, green, blue; 0..2100 counts,
written inverted) that pass through an IIR smoothing filter. The light has no
addressable pixels. See [color-pipeline.md](color-pipeline.md).

### Periodic Effect Engine

`SysTick_handler()` runs every 1 ms and advances software timing counters and
fade ramps. It also calls `led_effect_driver()`, which is really the 50 ms
button poller. The effects themselves are computed in the main loop
(`effect_dispatch_handler()`), but they are timed from the SysTick counters,
so animation speed does not depend on how fast the loop iterates.

### Effect Families

The firmware has 17 on-screen effects, rendered by 15 engines. The names below
are the firmware's own display strings. Over BLE the effects are sub-modes
4..18, and 7 and 8 each cover two effects; see [effects.md](effects.md).

| UI # | Effect | BLE sub-mode |
|----|--------|----|
| 1 | HUE LOOP | 4 |
| 2 | CCT LOOP | 5 |
| 3 | INT LOOP | 6 |
| 4 | CCT FLASH | 7 (type 1) |
| 5 | HUE FLASH | 7 (type 2) |
| 6 | CCT PULSE | 8 (type 1) |
| 7 | HUE PULSE | 8 (type 2) |
| 8 | STORM | 9 |
| 9 | POLICE CAR | 10 |
| 10 | TV | 11 |
| 11 | PAPARAZZI | 12 |
| 12 | CANDLE/FIRE | 13 |
| 13 | DISCO | 14 |
| 14 | BAD BULB | 15 |
| 15 | FIREWORK | 16 |
| 16 | EXPLOSION | 17 |
| 17 | WELDING | 18 |

The effect parameter pages are loaded from EEPROM at boot and written back
through the deferred-save path.

---

## Persistence Model

Settings are stored in an external 256-byte I2C EEPROM (device 0xA0,
bit-banged on PC2/PC1). Internal flash is never written, despite the
`flash_*` names. The byte map is in [eeprom-layout.md](eeprom-layout.md).

The firmware does not immediately write settings every time a parameter changes.
Instead, most writers set a single global reason code and let the main loop
commit the change later through `flash_save_pending_params()`.

That deferred-write global is `g_flash_save_pending`.

Observed meanings:

| Value | Meaning |
|-------|---------|
| 0 | No pending save |
| 1 | Save direct CCT temperature |
| 2 | Save direct HSI hue |
| 3 | Save direct HSI speed |
| 4 | Save brightness |
| 5 | Save output mode |
| 11 | Save active effect-mode selection |
| 18 | Save device settings |
| 21 | Save direct-mode range bounds |
| 22 | Save HUE LOOP effect parameters |
| 23 | Save direct CCT tint / GM offset |
| 25 | Save CCT LOOP effect parameters |
| 26 | Save INT LOOP effect parameters |
| 27 | Save CCT FLASH effect parameters |
| 28 | Save HUE FLASH effect parameters |
| 29 | Save CCT PULSE effect parameters |
| 30 | Save HUE PULSE effect parameters |
| 31 | Save STORM effect parameters |
| 32 | Save POLICE CAR effect parameters |
| 33 | Save TV effect parameters |
| 34 | Save PAPARAZZI effect parameters |
| 35 | Save CANDLE/FIRE effect parameters |
| 36 | Save DISCO effect parameters |
| 37 | Save BAD BULB effect parameters |
| 38 | Save FIREWORK effect parameters |
| 39 | Save EXPLOSION effect parameters |
| 40 | Save WELDING effect parameters |

This design has two benefits:

- parser/UI code can stay fast and simple
- EEPROM writes are centralized in one predictable place

---

## Interrupt Roles

The interrupt picture is straightforward once the generic placeholder names are
replaced with semantic ones:

| Handler | Role |
|---------|------|
| `SysTick_handler()` | 1 ms system tick, effects, fades, timing |
| `usart1_ble_uart_irq_handler()` | BLE UART receive ingress (USART1, IRQ37) |
| `exti9_5_nrf24_irq_handler()` | nRF24 IRQ on PB3 (it is actually EXTI line 3, IRQ9) |
| `tim5_ble_send_irq_handler()` | UART end-of-frame (idle gap) detection (TIM5, IRQ50) |
| `delay_tick_timer_irq_handler()` | 1 ms delay tick (TIM9, IRQ24) |

There are also still-unused vector slots in the image, but the active behavior
is concentrated in the handlers above.

---

## Numeric / Runtime Helpers

The firmware uses software floating-point helpers instead of relying on a full
floating-point runtime library path.

### `math_double_normalize()`

`math_double_normalize()` is the core IEEE-754 packing helper used by:

- `math_double_add()`
- `math_double_mul()`
- `int_to_double()`
- `uint_to_double()`

Its job is to:

1. count leading zeros in a 64-bit significand
2. normalize that significand by shifting it into position
3. merge in extra low-order tail bits so guard/sticky information is preserved
4. combine the normalized mantissa with a caller-supplied sign contribution and
   exponent seed
5. call `__dround()` to emit the final packed double bit pattern

That helper explains why integer conversion uses an exponent seed of `1075`
(`1023` bias + `52` mantissa bits): the conversion path is sharing the same
general pack-and-round logic as the arithmetic helpers.

---

## Hardware-Oriented Summary

At the highest level, the firmware sits between three input domains and one
output domain:

```text
Buttons
Wireless remote (nRF24)
BLE app / UART module
        |
        v
Shared SRAM state
  - ui mode
  - edit focus
  - direct light parameters
  - effect parameter pages
  - deferred EEPROM-save reason
        |
        v
Main loop + SysTick effect engine
        |
        v
5 PWM channels (2 white + RGB) + OLED feedback
```

The key design idea is consistency:

- every control source writes into the same shared model
- one UI state machine decides how the device presents and edits that model
- one deferred persistence path writes the model back to the EEPROM
- one light engine turns the model into visible output

That makes the firmware feel much more like a single coherent appliance than a
collection of unrelated handlers.
