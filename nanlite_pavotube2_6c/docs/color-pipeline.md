# Colour and Output Pipeline

How brightness, Kelvin, tint and HSI values become the light's five PWM outputs.
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown, needs a real device

## Output stage ✅

| Item | Value |
|---|---|
| Channels | 5: ch1 (PC9, TIM3_CH4), ch2 (PA8, TIM1_CH1), red (PC8), green (PC7), blue (PC6) |
| PWM | ARR = 2100 at 84 MHz, about **40 kHz**, so 0..2100 counts per channel |
| Polarity | every write is inverted: `CCR = 2100 − value` (`pwm_set_all_channels_inv` @0x0802D048) |
| Smoothing | per-channel IIR `y = α·y + β·target`: α/β = 0.999/0.001 in CCT and HSI modes, 0.9/0.1 in effects (`set_filter_speed`) |
| Pixel output | **none**: no SPI, DMA or addressable LEDs |

**Channel labels ⚠.** The IDB calls ch1/ch2 "warm/cool". In `cct_to_pwm_channels`, however, ch1 *rises* with Kelvin, so the labels may be swapped. Check on hardware before relying on which is which.

## Brightness curve ✅

There is no real gamma; the mapping is linear.

- `pwm_scale_calibrated(x) = 0.97778·x + 2.222` for x > 0, otherwise 0. The coefficients are in `gamma_coeff_t` @0x200034FC.
- Effects first apply `0.93·b + 7.93`, then scale the output by 0.93 on the white channels and 0.91 on RGB.

## Direct CCT (`cct_calc_white_pwm` @0x08030AFC) ✅

My own pseudocode:

```
B     = min(2100, 20.131·brightness + 86.87)
K'    = remap(K) piecewise through the factory points for 3200 K and 5600 K
        (segments 2700–3200, 3200–5600, 5600–7500)
mix   = LUT[K'/100 − 27] · 0.4375 − 1181.2     # ≈ (K' − 2700)/4800 · 2100
(chA, chB) = dual_white(level = 0.93·B, mix, 2100)
```

`dual_white` (`cct_compute_dual_white` @0x0801A9EC):

```
tint_scale = 1 − |tint − 100|/100 · 0.2
level      = max(level · tint_scale, 107)
base       = (cal_low ± 20) · (100 − brightness)/99
chA        = base + level·mix/2100
chB        = base + level·(2100 − mix)/2100
clamp each to 1953, then apply the per-channel calibration (below), then clamp to cal_high
```

The two results are packed as `chA + 0xFFFF·chB` and unpacked with HIWORD and `% 0xFFFF`. This gives an off-by-one in one channel whenever chA < chB (a firmware bug).

The main loop (`led_output_tick` @0x0801B648) then:

- ramps each white channel ±1 count per pass toward its target, after a 5998-pass start-up delay;
- adds tint:
  - tint > 100 drives **green**: `(tint−100)/2 · 6·b/100 + cal`;
  - tint < 100 drives **red only**: the same formula with `(100 − tint)`.

## Direct HSI (`dmx_rgb_to_pwm` @0x080339BC) ✅

```
h = hue · 5.84          # 0..2100
s = sat · 21
three 700-count sectors: R→G, G→B, B→R, with a floor of 76 counts
unsaturated remainder → white: 0.7 on ch1, 0.2 on ch2
output ramps one step every 3rd call
```

## Effect colour (`hsi_to_pwm_channels` @0x08030760, `cct_to_pwm_channels` @0x0802D1EC) ✅

HSI:

```
chroma = B·S, split into linear 120° sectors (hsi_hue_to_rgb @0x0801C2CC)
white  = (1 − S)·B, split between ch1 and ch2 by the Kelvin LUT
```

`hsi_calc_output` uses a fixed ratio of 2900/4800 instead.

CCT:

```
ratio  = (K − Kmin)/(Kmax − Kmin)
main   = ((50 − |gm|)/385 + 0.87) · B          # split between ch1/ch2 by ratio
gm_out = B·|gm|/50 · 0.13 · 2100               # green if gm > 0, red if gm < 0
```

Here gm is the engine's −50..+50 value ([effects.md](effects.md)).

## Per-unit calibration ✅

EEPROM 230..248 holds five low/high pairs, guarded by the magic `0x55AA` at 218. `led_compute_calibration` derives a linear map for each channel:

```
white: slope = (high − low)/1853,  intercept = low − slope·100
RGB:   slope = (high − low)/1835,  intercept = low − slope·76
```

Bug: the blue slope is computed with `green_low`.

## Fades ✅

- `fade_ramp_tick` (0x0801B560) is a 1 ms counter.
- `led_brightness_transition` (0x0801B4BC) steps brightness by ±1 every `timer / |Δbrightness|` ms. This is how BLE category-1 sub 0x02 and the timer-scene fade run.
