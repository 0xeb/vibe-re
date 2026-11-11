# BLE App Protocol

These are the packets that the light's MCU parses once the transport layer ([ble-transport.md](ble-transport.md)) has unwrapped them. With the transparent BLE module, each packet travels inside one `FA 55` frame.
Legend: ✅ confirmed by static analysis · ⚠ inferred · ❓ unknown, needs a real device

Code path: `ble_process_incoming` (0x08018014) → `ble_parse_rx_packet` (0x08012D10) → `ble_cmd_dispatch` (0x0801AFB4) → handlers.

All multi-byte fields are **big-endian**.

## Rules every client must follow ✅

1. **Change `seq` every time.** A packet, or a fragment, whose `seq` equals the previous one is dropped as a duplicate. The time query has its own separate duplicate slot.
2. **There is no authentication.** Anyone in radio range can send these packets; "binding" only sets a flag ([Binding](#binding)).
3. **The address field is not enforced.** The firmware classifies it (`0xFFFF` broadcast, `0xFFFE`, group if `(a & 0xC000) == 0x8000`), but every branch ends at the same label (disassembly 0x0801B0A4–0x0801B0EA). Use `0xFFFF`.
4. **No range checks on category-1 SETs.** Values are stored as sent, so clamp them in the client.
5. **Values take effect on the next main-loop pass.** After any recognised category other than 3, the MCU applies the staged values for the current mode, clamps brightness to 0..100, and schedules the EEPROM save.

## Short packet (8 bytes, `ble_cmd_t`) ✅

| Byte | Field | Notes |
|---|---|---|
| 0 | `seq` | must change between packets |
| 1 | `flags` | see below |
| 2 | category | 1, 3, 4, 5, 9, 10 |
| 3 | sub-command | category-specific (the mode, for category 9) |
| 4–5 | value | u16 BE; u8 values go in `[4]`, with `[5] = 0` |
| 6–7 | address | u16 BE, `0xFFFF`. Some commands reuse it for data (fade seconds, a u32 clock) |

### Flags byte ✅

| Bit | Meaning |
|---|---|
| 0 | **Reply wanted.** Handlers only build a reply when this is set |
| 1 | Set by the device in replies; ignored on input |
| 2 | Echoed back in replies (meaning unknown) |
| 3–4 | Header type. 0 = normal; 2 = short-header form, which routes extended packets to the pixel-page writer |
| 5 | **1 = SET (write), 0 = GET (read)** |
| 7 | **Fragment** (see [Fragmentation](#fragmentation)). The old howitworks.md called this "response required"; that was wrong |

Typical values: `0x21` = SET with a reply, `0x01` = GET with a reply, `0x20` = SET with no reply.

Reply flags are `(bit2 << 2) | (header_type << 3) | 0x02`.

## Extended packet (> 8 bytes) ✅

| Byte | Field |
|---|---|
| 0 | `seq` |
| 1 | `flags` |
| 2–3 | address |
| 4, 5 | fragment index / total (when flags bit 7 is set) |
| 6 | selector: **1** = full-state SET, **4** = timer/scene |
| 7… | selector-specific |

If the header type (flags bits 3–4) is 2, the packet goes to `ble_pixel_page_write_handler` instead: `[4]` page, `[6]` offset (1-based), `[8]` length, data from `[9]`. It writes into a 4 KB buffer that the light-output path never reads.

### Fragmentation ⚠

When flags bit 7 is set, the fragment index and total are at `[4]` and `[5]` (or at `[2]`/`[3]` when header type = 2). The first fragment keeps its full header; later fragments contribute only the bytes after their 6-byte (or 4-byte) header. The packet is complete when index == total. The reassembly buffer holds 2052 bytes. Whether the index starts at 1 is inferred.

## Category 1: light control (`light_control_handler` @0x08021F40) ✅

How a sub-command is interpreted depends on the current mode. In **CCT** mode (2) and **HSI** mode (3):

| Sub | Width | SET meaning | Range |
|---|---|---|---|
| `0x01` | u16 | brightness | 0..100 |
| `0x02` | u16 + u16 | fade: `[4..5]` target brightness, `[6..7]` duration in **seconds** | |
| `0x03` | u16 | CCT in Kelvin (CCT mode). In effect mode, sets that effect's CCT | 2700..7500 |
| `0x04` | u16 | green/magenta (CCT mode). The light stores `value + 100` as a byte (0..200, 100 = neutral), so the wire value is a signed −100..+100 ⚠ | |
| `0x05` | u16 | hue (HSI mode) | 0..360 |
| `0x0C` | u8 | saturation (HSI mode) | 0..100 |

In **effect** mode (7), the effect-parameter sub-commands apply. Most of them keep the same meaning across effects: `0x03` CCT, `0x04` GM, `0x05` hue, `0x0C` saturation, `0x21` variant/type, `0x53` speed, `0x20` brightness floor. The complete per-effect tables are in [effects.md](effects.md) and `pavotube/effects.py`.

Device and service sub-commands:

| Sub | Dir | Meaning |
|---|---|---|
| `0x32` | GET | model id (u8 in `[4]`) |
| `0x34` | SET/GET | **CH number** 1..512. Also changes the nRF24 address and renames the binary module. (IDB: `g_fw_version_ptr`) |
| `0x3A–0x3F` | SET | acknowledged, nothing else |
| `0x5A` | SET | re-initialise the binary module |
| `0x5B` | GET | `g_ble_connection_status` |
| `0x5D` | SET | apply pending changes for BLE effects 9 (STORM) and 17 (EXPLOSION); fires a burst |
| `0x5E` | SET | `cache[[6..7] − 1] = [4]`, index 1..512 |
| `0x62` | GET | u32 `g_system_data` in `[4..7]` |
| `0x64` | SET | u32 clock from `[4..7]`; sets `g_ble_device_id = 1` (bind) |
| `0x65` | SET | `g_ble_device_id = 0` (unbind) |
| `0x33, 0x35, 0x36, 0x40, 0x58, 0x13–0x18` | — | not handled; no reply |

## Category 3: config (`ble_config_handler` @0x0801FDFC) ✅

| Sub | Dir | Reply (`[0]` seq, `[1]` flags) |
|---|---|---|
| 1 | GET | full **state dump** (below) |
| 3 | GET | `[2]=3 [3]=3 [4]=hw version [5]=model [6..7]=address` |
| 4 | GET | `[2]=3 [3]=4 [4..5]=CH number` |
| 5 | GET/SET | u32 clock in `[4..7]`. SET writes it even when no reply is requested |
| 6 | GET | `[2]=3 [3]=6 [4..6]=24-bit serial [7]=0` |

## Category 4: apply ✅

There is no handler for category 4; the dispatcher just returns 0. Because the category is valid, the main loop still applies the staged values, so a category-4 packet works as an "apply now" nudge.

## Category 5: device info (`ble_device_info_status_handler` @0x0801F8D4) ✅

- A GET replies `[5, 2]`: protocol version 2.
- A SET replies `[2, 4]`.

## Category 9: select mode (`ble_light_mode_select_handler` @0x0801FA44) ✅

| Byte | Value |
|---|---|
| `[3]` | mode: **2 = CCT, 3 = HSI, 7 = effect** |
| `[4]` | `10` means "a sub-mode follows in `[5]`" |
| `[5]` | sub-mode: CCT 2 or 3, effect 4..18 |

Example: `01 21 09 07 0A 0A FF FF` selects effect mode with BLE effect 10 (POLICE CAR).

## Category 10: select sub-mode (`ble_light_submode_select_handler` @0x080289FC) ✅

Sets the sub-mode from `[3]`. **Bug:** in effect mode the handler validates the *current* sub-mode instead of the requested one, so prefer category 9 with `[4] = 10`.

## Full-state SET (extended, selector 1) (`ble_full_state_set_handler` @0x080315DC) ✅

```
[0] seq [1] flags [2..3] addr [4..5] 0 [6] 1
[7] L   (= 4 + tail length)
[8..9] brightness  [10] mode  [11] sub-mode  [12…] tail
```

| Mode | L | Tail |
|---|---|---|
| CCT (2) | 10 | `[0]` sub-param (u8) · `[1..2]` Kelvin · `[3..4]` GM (signed) · `[5]` GM offset (only read if L ≥ 10). Sub-mode must be 2 or 3 |
| HSI (3) | 7 | `[0..1]` hue · `[2]` saturation. The sub-mode byte is ignored (send 1) |
| effect (7) | per effect | the effect's parameter block, in the order listed in [effects.md](effects.md) |

Example: CCT 4300 K, GM −20, brightness 60.

```
01 21 FF FF 00 00 01 0A 00 3C 02 02 00 10 CC FF EC 00
```

Quirks:

- Nothing is applied unless the internal "ctrl flags" are non-zero ⚠ (the SET bit appears to be enough).
- The ACK puts `pkt[2..3]` in `[6..7]`.
- An unknown effect sub-mode leaves the mode set to 7 and keeps the old sub-mode.

## Timer / scene (extended, selector 4) (`ble_timer_scene_sync_handler` @0x08032254) ✅

`[7]` must be 1. `[8]` selects the operation:

| `[8]` | Meaning |
|---|---|
| `0x02` | fade: `[9..10]` brightness, `[11..12]` seconds |
| `0x5C` | 6-byte scene ❓ |
| `0x63` | 32-bit time sync in `[9..12]` |
| `0x61` | stub |

## Replies ✅

The light never sends unsolicited notifications. It only replies when flags bit 0 was set.

| Reply type | Layout |
|---|---|
| SET ACK | `[seq, flags', 2, 1, 0, 0, addr_h, addr_l]` |
| GET u16 | `[seq, flags', cat, sub, val_h, val_l, addr_h, addr_l]` |
| GET u8 | `[seq, flags', cat, sub, val, 0, addr_h, addr_l]` |
| error | `[…, 2, 4, …]` |

Firmware bugs in replies, confirmed in the disassembly:

- Category 9, category 10 and the pixel-page writer overwrite `[0..1]` with `2, 1`, so their replies don't echo your `seq`.
- In category 1, the replies for sub `0x0A` and `0x0F` are shifted by one byte, and the sub `0x11` ACK has `[3] = 0`.
- `ble_full_state_set_handler` never writes `[0..1]`.

### State dump (category 3 sub 1) ✅

```
[0] seq   [1] flags = ((2·hdr+1) << 3) | 2   [2..3] addr
[4..8] 01 01 04 03 01   (constant)
[9] hw version  [10] model  [11] ❓ (serial byte?)  [12] 0
[13] L  [14..15] brightness  [16] mode  [17] sub-mode  [18…] tail
```

The tail uses the same layout as the full-state SET, so dump offset = SET offset + 6. For CCT mode the sub-mode slot holds the CCT sub-param. If the mode isn't 2/3/7, or the effect isn't 4..18, only the 13-byte header is sent.

**Bug:** for effect 11 (TV) the dump inserts a stray `0x00` at tail offset 12, after `param_2a`; `pavotube.protocol.parse_state_dump` skips it.

## Binding

| Command | Effect |
|---|---|
| `0x64` | stores a u32 clock and sets `g_ble_device_id = 1` (saved to EEPROM 0xFC) |
| `0x65` | clears the flag |

The only visible effect of binding is the binary module's name prefix changing from ``` `` ``` to `..`. It doesn't restrict who can send commands.

## OTA (TYPE 2 frames) ✅

`ble_ota_update_handler` (0x0801B350) tracks phases 1/2/3 and checks block numbers, but **writes nothing to flash**: the data loop discards the payload. Firmware updates use a different path ([memory-map.md](memory-map.md)).

## Worked examples

Generated with `pavotube encode …`, address 0xFFFF, reply wanted.

| Action | App packet | FA 55 frame |
|---|---|---|
| CCT mode | `01 21 09 02 00 00 FF FF` | `FA 55 00 11 01 01 21 09 02 00 00 FF FF 03 8D 0D 0A` |
| 3200 K | `02 21 01 03 0C 80 FF FF` | `FA 55 00 11 01 02 21 01 03 0C 80 FF FF 04 13 0D 0A` |
| brightness 40 | `01 21 01 01 00 28 FF FF` | `FA 55 00 11 01 01 21 01 01 00 28 FF FF 03 AC 0D 0A` |
| fade to 0 over 5 s | `01 21 01 02 00 00 00 05` | `FA 55 00 11 01 01 21 01 02 00 00 00 05 01 8C 0D 0A` |
| HSI mode | `01 21 09 03 00 00 FF FF` | `FA 55 00 11 01 01 21 09 03 00 00 FF FF 03 8E 0D 0A` |
| hue 240 | `02 21 01 05 00 F0 FF FF` | `FA 55 00 11 01 02 21 01 05 00 F0 FF FF 04 79 0D 0A` |
| saturation 100 | `03 21 01 0C 64 00 FF FF` | `FA 55 00 11 01 03 21 01 0C 64 00 FF FF 03 F5 0D 0A` |
| POLICE CAR effect | `01 21 09 07 0A 0A FF FF` | `FA 55 00 11 01 01 21 09 07 0A 0A FF FF 03 A6 0D 0A` |
| …speed 70 | `02 21 01 53 46 00 FF FF` | `FA 55 00 11 01 02 21 01 53 46 00 FF FF 04 1D 0D 0A` |
| get state | `01 01 03 01 00 00 FF FF` | `FA 55 00 11 01 01 01 03 01 00 00 FF FF 03 66 0D 0A` |
| get hw/model | `01 01 03 03 00 00 FF FF` | `FA 55 00 11 01 01 01 03 03 00 00 FF FF 03 68 0D 0A` |
| set CH = 7 | `01 21 01 34 00 07 FF FF` | `FA 55 00 11 01 01 21 01 34 00 07 FF FF 03 BE 0D 0A` |
