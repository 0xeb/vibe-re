# Effects

The light has 17 on-screen effects, driven by 15 effect engines that are exposed over BLE as sub-modes 4..18.
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown, needs a real device

## Numbering ✅

Three numbering schemes are in play, and the IDA database's `effect_id_t` names are mostly wrong. The names below are the firmware's own on-screen strings, from the table in `.data` at `0x20000A96`.

| UI / EEPROM # | Name on screen | IDB `effect_id_t` | BLE sub-mode | Engine | Engine function |
|---|---|---|---|---|---|
| 1 | HUE LOOP | CCT_SWEEP | 4 | 0 | `hsi_calc_output` @0x0802F034 |
| 2 | CCT LOOP | CCT_RANGE | 5 | 1 | `cct_calc_output` @0x0802D6F0 |
| 3 | INT LOOP | HSI_SOURCE | 6 | 2 | `effect_fade_pulse` @0x0802F81C |
| 4 | CCT FLASH | CCT_TINT | 7, `type` = 1 | 3 | `effect_compute_fade_color` @0x0802EF34 |
| 5 | HUE FLASH | HSI_HUE | 7, `type` = 2 | 3 | 〃 |
| 6 | CCT PULSE | CCT_PULSE | 8, `type` = 1 | 4 | `effect_compute_breathing` @0x0802FE24 |
| 7 | HUE PULSE | HSI_PULSE | 8, `type` = 2 | 4 | 〃 |
| 8 | STORM | PIXEL_CHASE | 9 | 5 | `effect_thunder_flicker` @0x0802FFF8 |
| 9 | POLICE CAR | LIGHTNING | 10 | 6 | `effect_select_color_convert` @0x0802FF84 → `effect_strobe_*` |
| 10 | TV | TV_SIM | 11 | 7 | `effect_candle_flicker` @0x080301C0 |
| 11 | PAPARAZZI | CANDLE | 12 | 8 | `effect_step_timer_fade` @0x0802FDA8 |
| 12 | CANDLE/FIRE | PARTY | 13 | 9 | `cct_transition_engine` @0x0802DFA4 |
| 13 | DISCO | COLOR_PRESET | 14 | 10 | `effect_color_chase` @0x0802E60C |
| 14 | BAD BULB | COP | 15 | 11 | `effect_compute_lightning` @0x0802D554 |
| 15 | FIREWORK | RAINBOW | 16 | 12 | `effect_color_cycle` @0x0802EBF8 |
| 16 | EXPLOSION | FIREWORKS | 17 | 13 | `effect_burst_fade` @0x0802E984 |
| 17 | WELDING | CUSTOM | 18 | 14 | `effect_lightning_flash` @0x0803037C |

- BLE sub-mode N always drives engine N − 4 (`ble_uart_process_data` @0x08016BC8).
- For sub-modes 7 and 8, the `type` parameter (sub `0x21`) picks the CCT or HUE variant.
- The old howitworks.md listed IDs 4..20. That was the wrong idea: BLE uses 4..18.

## Starting an effect over BLE

1. Category 9: `[3]=7, [4]=10, [5]=sub-mode`, for example `01 21 09 07 0A 0A FF FF` for POLICE CAR.
2. Then send each parameter as a category-1 SET with the effect's sub-command. **Parameter writes only land while that effect is the active one**; otherwise the SET is ignored.
3. Alternatively, push everything in one packet with the full-state SET (extended selector 1), using the tail layout below.

```
pavotube encode effect "police car" -p speed=70 -b 80
pavotube encode fullstate effect --effect 1 -p hue_start=0 -p hue_end=240 -p speed=10
```

## BLE parameters per effect ✅ / ⚠

Each table lists the fields **in tail order**, which is the order used by the full-state SET and the state dump. *Width*: 1 means u8 in `[4]`; 2 means u16 BE in `[4..5]`. The firmware stores these values without checking ranges. Field names come from where each value ends up in the engine; names marked ⚠ are inferred.

### Sub-modes 4–6: loops (HUE LOOP, CCT LOOP, INT LOOP)

| Sub-mode | Lead fields |
|---|---|
| 4 HUE LOOP (L=17) | `0x06` hue_start (2) · `0x07` hue_end (2) · `0x0C` saturation (1) |
| 5 CCT LOOP (L=18) | `0x1E` cct_start (2) · `0x1F` cct_end (2) · `0x04` gm (2) |
| 6 INT LOOP (L=22) | `0x20` low_brightness (2) · `0x21` source 1=CCT/2=HSI (1) · `0x03` cct (2) · `0x04` gm (2) · `0x05` hue (2) · `0x0C` saturation (1) |

All three continue with the same loop fields:

| Sub | Width | Field | |
|---|---|---|---|
| `0x54` | 1 | speed: loop period = speed × 1 s; the UI allows 2..30 | ✅ |
| `0x19` | 1 | direction: engine value = wire − 1 (0 forward with wrap, 1 ping-pong, 2 reverse) | ⚠ |
| `0x1A` | 1 | overlay: engine value = wire − 1 (strobe / random flashes / BPM) | ⚠ |
| `0x1B` | 2 | duration | ⚠ |
| `0x1C` | 1 | strobe overlay parameter | ⚠ |
| `0x1D` | 1 | random overlay parameter | ⚠ |
| `0x55` | 1 | BPM overlay parameter | ⚠ |

### Sub-mode 7: CCT/HUE FLASH (L=16)

| Sub | Width | Field |
|---|---|---|
| `0x21` | 1 | type: 1 = CCT FLASH, 2 = HUE FLASH |
| `0x03` | 2 | CCT |
| `0x04` | 2 | GM |
| `0x05` | 2 | hue |
| `0x0C` | 1 | saturation |
| `0x1B` | 2 | duration: the engine period is `duration // 100` × 100 ms |
| `0x1C` | 1 | strobe/duty ⚠ |
| `0x22` | 1 | random flag ⚠ |

### Sub-mode 8: CCT/HUE PULSE (L=13)

| Sub | Width | Field |
|---|---|---|
| `0x21` | 1 | type: 1 = CCT PULSE, 2 = HUE PULSE |
| `0x03` | 2 | CCT |
| `0x04` | 2 | GM |
| `0x05` | 2 | hue |
| `0x0C` | 1 | saturation |
| `0x1D` | 1 | BPM: period = 60000 / BPM ms; the UI allows ≤ 240 |

### Sub-mode 9: STORM (L=12)

| Sub | Width | Field |
|---|---|---|
| `0x23` | 1 | type ⚠ (1/2) |
| `0x03` | 2 | CCT |
| `0x24` | 1 | interval_min (s) |
| `0x25` | 1 | interval_max (s, ≤ 60) |
| `0x26` | 1 | flashes_min ⚠ |
| `0x27` | 1 | flashes_max ⚠ |
| `0x22` | 1 | flag ⚠ |

Sub `0x5D` fires a burst immediately.

### Sub-mode 10: POLICE CAR (L=7)

| Sub | Width | Field |
|---|---|---|
| `0x21` | 1 | colour family: engine value = wire − 3, giving 0..3 ⚠ |
| `0x28` | 1 | pattern: engine value = wire − 1, giving 0..3 ⚠ |
| `0x53` | 1 | speed |

### Sub-modes 11, 13: TV (L=19), CANDLE/FIRE (L=20)

| Sub | Width | Field |
|---|---|---|
| `0x21` | 1 | type ⚠ |
| `0x03` | 2 | CCT |
| `0x04` | 2 | GM |
| `0x05` | 2 | hue |
| `0x0C` | 1 | saturation |
| `0x29` | 2 | ❓ |
| `0x2A` | 2 | ❓ |
| `0x53` | 1 | speed |
| `0x20` | 2 | brightness floor |
| `0x2C` | 1 | *(CANDLE/FIRE only)* lightning on/off ⚠ |

### Sub-mode 12: PAPARAZZI (L=9)

| Sub | Width | Field |
|---|---|---|
| `0x03` | 2 | CCT (clamped to 7500) |
| `0x04` | 2 | GM |
| `0x53` | 1 | speed |

### Sub-mode 14: DISCO (L=27)

| Sub | Width | Field |
|---|---|---|
| `0x21` | 1 | type ⚠: 7 = palette, 8 = alternate |
| `0x2E` | 1 | palette (≤ 24) |
| `0x2F` | 1 | ❓ |
| `0x53` | 1 | speed |
| `0x06`, `0x07` | 2, 2 | hue range |
| `0x08`, `0x09` | 2, 2 | CCT range |
| `0x0A`, `0x0B` | 2, 2 | GM range |
| `0x0C`–`0x12` | 1 each | ❓ |

### Sub-mode 15: BAD BULB (L=14)

| Sub | Width | Field |
|---|---|---|
| `0x21` | 1 | type ⚠ |
| `0x03` | 2 | CCT |
| `0x04` | 2 | GM |
| `0x05` | 2 | hue |
| `0x0C` | 1 | saturation |
| `0x30` | 1 | ❓ |
| `0x53` | 1 | speed |

### Sub-mode 16: FIREWORK (L=34)

| Sub | Width | Field |
|---|---|---|
| `0x21` | 1 | type ⚠: 7/8 |
| `0x2E` | 1 | colours (≤ 24) |
| `0x2F` | 1 | ❓ |
| `0x53` | 1 | speed |
| `0x31` | 1 | saturation |
| `0x03` | 2 | CCT |
| `0x04` | 2 | GM |
| `0x29` | 2 | hue |
| `0x06`–`0x0B` | 2 each | ❓ |
| `0x0C`–`0x11` | 1 each | ❓ |
| `0x12` | 1 | on/off ⚠ |

### Sub-mode 17: EXPLOSION (L=15)

| Sub | Width | Field |
|---|---|---|
| `0x23` | 1 | trigger mode ⚠: 2 = one-shot, fired with `0x5D` |
| `0x21` | 1 | type flag ⚠ |
| `0x03` | 2 | CCT |
| `0x04` | 2 | GM |
| `0x05` | 2 | hue |
| `0x0C` | 1 | saturation |
| `0x53` | 1 | speed |
| `0x31` | 1 | intensity |

### Sub-mode 18: WELDING (L=16)

| Sub | Width | Field |
|---|---|---|
| `0x21` | 1 | type flag ⚠ |
| `0x03` | 2 | CCT |
| `0x04` | 2 | GM |
| `0x05` | 2 | hue |
| `0x0C` | 1 | saturation |
| `0x53` | 1 | speed |
| `0x20` | 2 | brightness floor |
| `0x22` | 1 | source flag ⚠ |

Subs `0x2B`, `0x2D` and `0x42` only affect light modes 8 and 9, which BLE never selects. No-op subs are listed in [ble-protocol.md](ble-protocol.md).

## Effect engine ✅

The engine runs in the **main loop**, not in an interrupt. `check_and_update_light` calls `effect_dispatch_handler` (0x0802FC38), which:

1. advances the effect timers from the 1 ms SysTick counter (`timer_adjust_period_counters`), and
2. switches on the engine index stored in byte 0 of the light-state buffer.

The UI's values are copied into the engine by `light_state_build_response` (0x0801E1E0). On the way, GM is remapped from 0..200 to about −50..+50:

```
gm ≤ 100:  −(50 − gm·0.49)
gm > 100:  (gm − 100)·0.495 + 0.505
```

(`led_effect_driver`, despite its name, is the 50 ms button poller.)

### PRNG ✅

`sys_prng_range` (0x08038424). The state lives at 0x200023FC and starts at 457.

```
rand(lo, hi):
    state = (state * 65) mod 2^32
    if state == 0: state = 451
    return (state // 100) % (hi − lo + 1) + lo
```

### Per-engine behaviour

The pseudocode below is my own description. `s` is speed (0..100), `B` is brightness, and all times are in ms.

| Engine | Effect | Behaviour |
|---|---|---|
| 0 | HUE LOOP | Interpolates the hue from start to end in milli-degrees over a period of `speed × 1000`. The direction byte selects forward (wrapping), ping-pong or reverse. Overlay modes: 1 = strobe duty; 2 = 45 ms on, then `rand(40, 10(100−p)+160) + 45` off; 3 = BPM triangle wave |
| 1 | CCT LOOP | Same as engine 0, but over Kelvin. The white mix uses `ratio = (K − 2700) / 4800` |
| 2 | INT LOOP | Lerps between low and full intensity, in CCT or HSI. The ramp shape is a sawtooth up, a triangle or a sawtooth down; period `speed × 1000` |
| 3 | CCT/HUE FLASH | On while `t < period·duty/100`, with period = `speed × 100` |
| 4 | CCT/HUE PULSE | Triangle wave with period `60000 / BPM` |
| 5 | STORM | Waits `rand(min, max)` seconds, then fires a burst of `rand(n1, n2)` flashes. The first flash is on 300–400 / off 40–60 ms; the rest are on 60–100 / off 50–110 ms |
| 6 | POLICE CAR | Plays one of 4 pattern families × 4 patterns (tables of 4/8/24/16 steps). Step time = `table[i] × (1 + 0.02(100 − s))`; even steps are on |
| 7 | TV | Every `rand(200, 10(100−s)+650)` ms, jumps to brightness `rand(floor, B)` and a CCT within ±range/2, snapped to 100 K. No smoothing |
| 8 | PAPARAZZI | 45 ms flash, then dark for `rand(40, 10(100−s)+160) + 45` |
| 9 | CANDLE/FIRE | Alternates lerping to a random CCT/hue with holding at a dim level, each phase lasting `rand(200, 10(100−s)+400)`. Optional lightning: after `rand(2000, 8000)`, 1–3 flashes of 120–200 ms |
| 10 | DISCO | Picks a random palette colour, ramps up over `rand(0, 5(101−s)) + 200`, holds 300, fades, then stays off for `(100−s)/4 + 20` |
| 11 | BAD BULB | Off for `rand(1000, 135(100−s)+1500)`, then 5–15 steps of 30–120 ms, each at `B·(100 − rand(min, 100))/100` |
| 12 | FIREWORK | Random hue from a 24-entry order table, a custom list, or a random CCT. Envelope: ramp `rand(10, 110−s)`, hold `rand(10, 2(100−s)+10)`, decay `rand(200, 30p+300)`, off `rand(20, 10(100−s)+20)` |
| 13 | EXPLOSION | Triggered. Ramp `rand(10, (100−s)/2+10)`, hold `rand(20, 120−s)`, exponential decay over `rand(500, 25·intensity+500)` using `soft_powf`, off `rand(0, 40(100−s)) + 1000`, then it re-arms |
| 14 | WELDING | Dim level `rand(floor, floor + (B−floor)/2)`, then ramp to full, hold, decay and off, each phase randomised by speed |

Effects output through the same 5 PWM channels as the direct modes. In effect mode the output smoothing is faster (IIR 0.9/0.1 instead of 0.999/0.001), and an extra scale is applied: ×0.93 on the white channels and ×0.91 on RGB ([color-pipeline.md](color-pipeline.md)).

### Tables used by effects

These are in `.data`; decompress them with `pavotube fw FILE --dump-data`.

| Address | Contents |
|---|---|
| `0x200030DC` | CCT steps 2700..7500 in 100 K steps |
| `0x20003144` | CCT steps 1800..20000 |
| `0x20003378` | 24-entry hue order (0, 120, 240, 60, 180, 300, …) |
| `0x200033F0…` | police strobe patterns |
| `~0x20002568` | 42 gel/colour presets of 68 bytes each (CTO/CTB, colour names) ⚠ |
