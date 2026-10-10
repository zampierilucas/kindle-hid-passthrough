# Compatible devices

Every Kindle and Bluetooth device that someone reported working in the issues and pull requests of this repo and [kindle-button-mapper-rs](https://github.com/zampierilucas/kindle-button-mapper-rs), up to v3.17.4. Problems that were fixed later are not listed, only the ones still open. If your device isn't here or behaves differently, open an issue.

## Kindles

| Kindle | Bluetooth | Status | Reported working with | Open problems |
|---|---|---|---|---|
| Basic 2 (2016, KT3) | Broadcom | Works | UltraThin for Air keyboard [#33](https://github.com/zampierilucas/kindle-hid-passthrough/issues/33) | |
| Oasis 1 (2016) | Broadcom, kernel 3.0.35 | Works | Bluetooth keyboard and Free 2 with the backported uhid.ko [#73](https://github.com/zampierilucas/kindle-hid-passthrough/issues/73) [#90](https://github.com/zampierilucas/kindle-hid-passthrough/issues/90) | |
| Oasis 2 (2017) | Broadcom | Works | Q36 keyboard [#106](https://github.com/zampierilucas/kindle-hid-passthrough/issues/106), BLE remote [#120](https://github.com/zampierilucas/kindle-hid-passthrough/issues/120) | Firmware build 409745 has no matching uinput.ko, so button mapper key injection is unavailable there (script actions still work) [#120](https://github.com/zampierilucas/kindle-hid-passthrough/issues/120) |
| Paperwhite 4 (2018) | Broadcom | Works | COIDEA KM [#61](https://github.com/zampierilucas/kindle-hid-passthrough/issues/61), BT1818 remote [#102](https://github.com/zampierilucas/kindle-hid-passthrough/issues/102), Xbox Wireless Controller [#225](https://github.com/zampierilucas/kindle-hid-passthrough/issues/225) | Firmware 5.12.4 (build 360278) has no working uhid.ko yet [#167](https://github.com/zampierilucas/kindle-hid-passthrough/issues/167) |
| Basic 3 (2019) | Broadcom | Works | Maintainer test device [#33](https://github.com/zampierilucas/kindle-hid-passthrough/issues/33) [#113](https://github.com/zampierilucas/kindle-hid-passthrough/issues/113) | |
| Oasis 3 (2019) | Broadcom | Works | 8BitDo Zero 2 [#117](https://github.com/zampierilucas/kindle-hid-passthrough/issues/117), KeyKey Mini BLE3 and a page turner [#100](https://github.com/zampierilucas/kindle-hid-passthrough/issues/100), BLE remote [#124](https://github.com/zampierilucas/kindle-hid-passthrough/issues/124), Free 2 [#152](https://github.com/zampierilucas/kindle-hid-passthrough/issues/152), IINE keyboard [#33](https://github.com/zampierilucas/kindle-hid-passthrough/issues/33) | |
| Paperwhite 5 (2021) and PW5 SE | MediaTek | Works | Maintainer's daily device with an 8BitDo Mini [#279](https://github.com/zampierilucas/kindle-hid-passthrough/issues/279), Keychron K2 [#179](https://github.com/zampierilucas/kindle-hid-passthrough/issues/179), Joy-Con (R) and Pro Controller [#191](https://github.com/zampierilucas/kindle-hid-passthrough/issues/191) [#241](https://github.com/zampierilucas/kindle-hid-passthrough/issues/241), Bluetooth mouse [#126](https://github.com/zampierilucas/kindle-hid-passthrough/issues/126), Redmi AirDots audio [#247](https://github.com/zampierilucas/kindle-hid-passthrough/issues/247) | |
| Basic 4 (2022, KT5) | MediaTek | Works | Maintainer's main test device with an Xbox Wireless Controller, a phone as media remote and an S18 [#228](https://github.com/zampierilucas/kindle-hid-passthrough/issues/228) [#239](https://github.com/zampierilucas/kindle-hid-passthrough/issues/239) [#189](https://github.com/zampierilucas/kindle-hid-passthrough/issues/189), Free 2 [#154](https://github.com/zampierilucas/kindle-hid-passthrough/issues/154), Bluetooth remote [#264](https://github.com/zampierilucas/kindle-hid-passthrough/issues/264) | |
| Scribe (2022) | MediaTek | Works | FBX53C keyboard [#99](https://github.com/zampierilucas/kindle-hid-passthrough/issues/99) [#111](https://github.com/zampierilucas/kindle-hid-passthrough/issues/111), Russian layout through button mapper [kbm#15](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/15) | Shift types extra characters in the native UI when a button mapper layout is set [kbm#29](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/29). BTManager top bar stays empty on 5.17.2 [#110](https://github.com/zampierilucas/kindle-hid-passthrough/issues/110) |
| Basic 5 (2024, KT6) | MediaTek | Works | E1 Control and a classic keyboard [#45](https://github.com/zampierilucas/kindle-hid-passthrough/issues/45), page turns on 5.18.3 [kbm#49](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/49) | |
| Paperwhite 6 (2024) and PW6 SE | MediaTek | Works | 8BitDo Ultimate 2 and E2 Control [#172](https://github.com/zampierilucas/kindle-hid-passthrough/issues/172), BLE-M9 [#275](https://github.com/zampierilucas/kindle-hid-passthrough/issues/275), Keychron K2 [#216](https://github.com/zampierilucas/kindle-hid-passthrough/issues/216), Free 2 and an AR remote [#180](https://github.com/zampierilucas/kindle-hid-passthrough/issues/180), Redmi AirDots audio [#247](https://github.com/zampierilucas/kindle-hid-passthrough/issues/247) | White screen reboot loop after a full install on 5.19.5 [#226](https://github.com/zampierilucas/kindle-hid-passthrough/issues/226) |
| Scribe 2 (2024) | MediaTek | Untested | Tap page turns tested by the maintainer [kbm#57](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/57) | |
| Colorsoft (2024) | MediaTek | Untested | Warmth mappings tested on a Signature Edition [kbm#81](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/81) | |
| Scribe 3 and Scribe Colorsoft (2025) | MediaTek | Untested | | |

## Gamepads

| Device | Link | Kindle | Notes |
|---|---|---|---|
| 8BitDo Mini | | PW5 | [#279](https://github.com/zampierilucas/kindle-hid-passthrough/issues/279) |
| 8BitDo Ultimate 2 Wireless | BLE | PW6 | [#172](https://github.com/zampierilucas/kindle-hid-passthrough/issues/172) |
| 8BitDo Zero 2 | Classic | Oasis 3 | Reconnect without re-pairing needs v3.10.0 [#117](https://github.com/zampierilucas/kindle-hid-passthrough/issues/117) |
| IINE Gamebrick Mini | BLE | Basic 4 | Auto-reconnect after reboot needs v3.5.0 [#65](https://github.com/zampierilucas/kindle-hid-passthrough/issues/65) |
| Nintendo Joy-Con (R) | Classic | PW5 | Player lights need v3.16.0 [#241](https://github.com/zampierilucas/kindle-hid-passthrough/issues/241) |
| Nintendo Pro Controller | Classic | PW5 | Page-turn lag fixed in v3.17.4 [#283](https://github.com/zampierilucas/kindle-hid-passthrough/issues/283), one report of it coming back after sleep, not yet confirmed [#280](https://github.com/zampierilucas/kindle-hid-passthrough/issues/280) |
| Shanwan gamepad | | PW5 | Only X mode works. One report of no button response after sleep [#265](https://github.com/zampierilucas/kindle-hid-passthrough/issues/265) |
| Xbox Wireless Controller | Classic and BLE | Basic 4, PW4, PW6 | [#67](https://github.com/zampierilucas/kindle-hid-passthrough/issues/67) [#225](https://github.com/zampierilucas/kindle-hid-passthrough/issues/225) [#239](https://github.com/zampierilucas/kindle-hid-passthrough/issues/239). The guide LED can't be controlled over Bluetooth [#241](https://github.com/zampierilucas/kindle-hid-passthrough/issues/241) |

## Keyboards

| Device | Link | Kindle | Notes |
|---|---|---|---|
| ASUS KW100 | BLE | | Press a key to wake it before reconnecting [#34](https://github.com/zampierilucas/kindle-hid-passthrough/issues/34) |
| FBX53C | BLE | Scribe | [#99](https://github.com/zampierilucas/kindle-hid-passthrough/issues/99) |
| IINE keyboard | BLE | Oasis 3 | [#33](https://github.com/zampierilucas/kindle-hid-passthrough/issues/33) |
| Keychron K2 | Classic | PW5, PW6 | [#179](https://github.com/zampierilucas/kindle-hid-passthrough/issues/179) [#216](https://github.com/zampierilucas/kindle-hid-passthrough/issues/216) |
| KeyKey Mini BLE3 | BLE | Oasis 3 | [#100](https://github.com/zampierilucas/kindle-hid-passthrough/issues/100) |
| Logitech MX Keys S | BLE | | [#34](https://github.com/zampierilucas/kindle-hid-passthrough/issues/34) |
| Q36 for Android | Classic | Oasis 2 | [#106](https://github.com/zampierilucas/kindle-hid-passthrough/issues/106) |
| UltraThin for Air | Classic | Basic 2 | [#33](https://github.com/zampierilucas/kindle-hid-passthrough/issues/33) |

## Mice

| Device | Link | Kindle | Notes |
|---|---|---|---|
| BT5.4 Mouse | BLE | PW5 | Connection drops fixed in v3.15.0, not yet retested by the reporter [#179](https://github.com/zampierilucas/kindle-hid-passthrough/issues/179) |
| HREBOS-526 | BLE | PW5 | Same fix as above [#179](https://github.com/zampierilucas/kindle-hid-passthrough/issues/179) |
| Keychron M6 | | Basic 4 | [#161](https://github.com/zampierilucas/kindle-hid-passthrough/issues/161) |

## Page turners and remotes

| Device | Link | Kindle | Notes |
|---|---|---|---|
| AB Shutter3 | BLE | PW6 | Dropped key events fixed in v3.15.0, not yet retested by the reporter [#179](https://github.com/zampierilucas/kindle-hid-passthrough/issues/179) |
| AR remote | BLE | PW6 | [#180](https://github.com/zampierilucas/kindle-hid-passthrough/issues/180) |
| BLE-M3 | BLE | | Battery level can't be read, the remote only exposes a vendor service [#222](https://github.com/zampierilucas/kindle-hid-passthrough/issues/222) |
| BLE-M9 | BLE | PW6 | Needs v3.17.1 [#275](https://github.com/zampierilucas/kindle-hid-passthrough/issues/275) |
| BT1818 | | PW4 | [#102](https://github.com/zampierilucas/kindle-hid-passthrough/issues/102) |
| COIDEA KM | BLE | PW4 | [#61](https://github.com/zampierilucas/kindle-hid-passthrough/issues/61) |
| E1 Control | BLE | Basic 5, PW5 | [#45](https://github.com/zampierilucas/kindle-hid-passthrough/issues/45) [#51](https://github.com/zampierilucas/kindle-hid-passthrough/issues/51) |
| E2 Control | BLE | PW6 | Use BLE mode, Classic mode gives no input [#172](https://github.com/zampierilucas/kindle-hid-passthrough/issues/172) |
| Free 2 | BLE | Basic 4, Oasis 1, Oasis 3, PW6 | Use BLE mode, Classic mode gives no input on PW6 [#154](https://github.com/zampierilucas/kindle-hid-passthrough/issues/154) |
| Generic BLE remote | BLE | PW5 | 30s disconnects fixed in v3.17.1 [#277](https://github.com/zampierilucas/kindle-hid-passthrough/issues/277) |
| HBTR002 | | | Fixed in v3.14.0, not yet retested by the reporter [#171](https://github.com/zampierilucas/kindle-hid-passthrough/issues/171) |
| JX-11 | BLE | PW5 | Fixed in v3.3.4, not yet retested by the reporter [#53](https://github.com/zampierilucas/kindle-hid-passthrough/issues/53) |
| K02 remote | BLE | | D-pad mappings need button mapper v1.6.0 [kbm#70](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/70) |
| Kobo Remote | | | [kbm#36](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/36) |
| S18 | | Basic 4 | [#189](https://github.com/zampierilucas/kindle-hid-passthrough/issues/189) |
| Smart 1-P | | | [#187](https://github.com/zampierilucas/kindle-hid-passthrough/issues/187) [kbm#43](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/43) |

## Other

| Device | Kindle | Notes |
|---|---|---|
| Redmi AirDots | PW5 SE, PW6 SE | A2DP audio and headset pause [#247](https://github.com/zampierilucas/kindle-hid-passthrough/issues/247) |
| Android phone as media remote | Basic 4 | Volume keys mapped to page turns [#228](https://github.com/zampierilucas/kindle-hid-passthrough/issues/228) |

## Things that look like bugs but aren't

- Install with the release installer. Copying only the koplugin gives "Daemon binary not found", and `;kpm add-repo` from the Kindle search bar is dropped by the firmware, so run it from kterm or SSH [#253](https://github.com/zampierilucas/kindle-hid-passthrough/issues/253).
- If BTManager is missing from the home screen, install the KindleModding hotfix [#153](https://github.com/zampierilucas/kindle-hid-passthrough/issues/153).
- On the Oasis line the physical page buttons swap while a keyboard is attached. That comes from KOReader's external keyboard plugin, not from KHP [#83](https://github.com/zampierilucas/kindle-hid-passthrough/issues/83).
