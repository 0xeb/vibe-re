# Structures and Enums

The C definitions below were written by hand from the recovered field layouts, and each one has a matching Python `struct` format string. Wire structures are big-endian; in-memory MCU structures are little-endian. The Python equivalents are in `pavotube/structs.py`, `pavotube/enums.py` and `pavotube/effects.py`.
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown

## Wire structures

### `ble_cmd_t`: short app packet, 8 bytes ✅

```c
typedef struct {
    uint8_t  seq;        /* must change between packets            */
    uint8_t  flags;      /* BLE_F_* below                          */
    uint8_t  category;   /* 1,3,4,5,9,10                           */
    uint8_t  sub;        /* sub-command / mode                     */
    uint16_t value_be;   /* big-endian; u8 values use the high byte */
    uint16_t addr_be;    /* big-endian, 0xFFFF; not enforced       */
} ble_cmd_t;             /* Python: ">BBBBHH"                      */

#define BLE_F_REPLY      0x01  /* reply wanted                  */
#define BLE_F_FROMDEV    0x02  /* set in device replies         */
#define BLE_F_ECHO       0x04  /* echoed, meaning unknown       */
#define BLE_F_HDR(x)     (((x) & 3) << 3)  /* 2 = pixel-page form */
#define BLE_F_SET        0x20  /* 1 = SET, 0 = GET              */
#define BLE_F_FRAGMENT   0x80  /* fragmented extended packet    */
```

The IDB's `ble_flags_t` (6 bytes) is the firmware's *unpacked* copy of the flags byte: `bit0, bit1, bit2, bits3_4, bit5, bit7`, one byte each.

### Extended packet header ✅

```c
typedef struct {
    uint8_t  seq, flags;
    uint16_t addr_be;
    uint8_t  frag_index, frag_total;   /* when flags & BLE_F_FRAGMENT */
    uint8_t  selector;                 /* 1 full-state SET, 4 timer/scene */
    /* selector data follows */
} ble_ext_hdr_t;                       /* Python: ">BBHBBB" */

typedef struct {                       /* selector 1 */
    uint8_t  block_len;                /* 4 + tail length */
    uint16_t brightness_be;
    uint8_t  mode;                     /* 2 CCT, 3 HSI, 7 effect */
    uint8_t  sub_mode;
    uint8_t  tail[];                   /* see ble-protocol.md / effects.md */
} ble_full_state_t;
```

### FA 55 transport frame ✅

```c
/* FA 55 | len_be | type | payload[len-9] | ck_be | 0D 0A
   len = total frame length; ck = (sum of bytes up to the end of payload) + 1 */
typedef struct {
    uint8_t  magic[2];   /* 0xFA, 0x55 */
    uint16_t len_be;
    uint8_t  type;       /* 1 command, 2 OTA */
} fa55_hdr_t;            /* Python: ">2sHB" */
```

### nRF24 V2.0 payload, 32 bytes ✅

```c
typedef struct {
    uint8_t  dc0[3];
    uint8_t  len;        /* 14..32; the checksum sits at [len-1] */
    uint8_t  dc1[2];
    uint16_t cmd_be, arg_be, sub_be, flags_be;   /* flags must be 0 */
    uint8_t  rest[18];
} nrf24_v2_t;            /* Python: ">3sB2sHHHH18s" */
```

## In-memory structures (little-endian)

### `led_output_t`: PWM targets, 10 bytes ✅

```c
typedef struct { uint16_t ch1, ch2, red, green, blue; } led_output_t;   /* "<5H", 0..2100 each */
```

### `led_pixel_cal_t`: per-channel calibration, 60 bytes ✅

```c
typedef struct { uint16_t low, high; float slope, intercept; } led_pixel_cal_ch_t;  /* "<HHff" */
typedef struct { led_pixel_cal_ch_t ch[5]; } led_pixel_cal_t;  /* ch1, ch2, R, G, B @0x20000F5C */
```

### `gamma_coeff_t` ✅

```c
typedef struct { float slope, intercept; } gamma_coeff_t;   /* 0.97778, 2.222 @0x200034FC */
```

### `cct_calc_timer_t` ✅

```c
typedef struct { uint16_t frame_counter, sweep_counter; } cct_calc_timer_t;
```

### On-device effect parameter globals (`g_fx_*`) ⚠

The IDB defines `effect_*_t` structs for these, but never applies them, and several have the wrong size or field offsets. Treat the per-field EEPROM table in [eeprom-layout.md](eeprom-layout.md) as authoritative. The globals start at `0x20000ED6`:

| Base | Effect | Notes |
|---|---|---|
| `20000ED6` | HUE LOOP | start, end (u16), speed |
| `20000EDC` | CCT LOOP | low, high (u16), speed |
| `20000EE2` | INT LOOP | low brightness, source, CCT, hue, speed (the struct is off by one) |
| `20000EEC` | POLICE CAR | pattern, speed |
| `20000EF0` | CCT FLASH | CCT, GM, speed |
| `20000EF6` | HUE FLASH | hue, saturation, speed |
| `20000EFC` | HUE PULSE | hue, saturation, BPM |
| `20000F02` | CCT PULSE | CCT, GM, BPM |
| `20000F08` | STORM | CCT, interval min/max, variant |
| `20000F10` | TV | CCT, GM, speed, floor, runtime |
| `20000F1C` | PAPARAZZI | CCT, GM, speed |
| `20000F22` | CANDLE/FIRE | 12 bytes (the IDB says 14) |
| `20000F2E` | DISCO | palette, speed |
| `20000F32` | BAD BULB | 10 bytes (the IDB says 14) |
| `20000F3C` | FIREWORK | colours, saturation, speed |
| `20000F42` | EXPLOSION | CCT, GM, speed, intensity, burst state |
| `20000F4E` | WELDING | floor, CCT, GM, speed, source |

## Enums

### Light mode ✅

| Wire (BLE category 9, state dump) | Output mode (`g_led_output_mode`, EEPROM 28) | UI screen (`g_ui_mode`) |
|---|---|---|
| 2 CCT | 0 CCT | 1 CCT |
| 3 HSI | 1 HSI | 2 HSI |
| 7 effect | 2 effect | 3 effect |
| — | 3 source ❓ | 4 settings |

The IDB's `ui_mode_t` (0..4) does **not** match `g_ui_mode`, and its `light_mode_t` is the output-mode column.

### Effects ✅

See [effects.md](effects.md). UI/EEPROM numbers are 1..17, BLE sub-modes are 4..18, and engine indices are 0..14.

### BLE module type (`ble_proto_type_t`) ✅

| Value | Meaning |
|---|---|
| 0 | none |
| 1 | AT-text "NanGuang" module |
| 2 | binary / transparent module |

### `ble_conn_state_t` ✅

| Value | Meaning |
|---|---|
| 0 | idle |
| 1 | ready |
| 2 | connected |

### `ble_at_cmd_t` ✅

| Value | Command |
|---|---|
| 0 | NDRESET |
| 1 | NDID |
| 2 | VER |
| 3 | MODE |
| 4 | NAME |
| 5 | REBOOT |
| 6 | NDUUID |
| 7 | ENTM |
| 8 | MODE? |
| 9 | NAME? |

### Save reasons (`g_flash_save_pending`) ✅

See [eeprom-layout.md](eeprom-layout.md#deferred-save-reasons-g_flash_save_pending-0x20000e70).

### Python quick reference

```python
from pavotube.structs import BleCmd, Flags, LedOutput, PixelCal
from pavotube.enums import Category, LightMode, Effect, LightSub, ConfigSub, FlashSaveReason
from pavotube.effects import BLE_EFFECTS, for_effect

pkt = BleCmd(seq=1, flags=Flags(reply=True, set=True).pack(),
             category=Category.LIGHT, sub=LightSub.BRIGHTNESS, value=40).pack()
for p in for_effect(Effect.POLICE_CAR).params:
    print(hex(p.sub), p.width, p.name)
```
