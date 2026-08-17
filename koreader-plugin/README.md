# KOReader Plugin: HID Passthrough

KOReader plugin that lets users start/stop the kindle-hid-passthrough Bluetooth HID daemon from within KOReader, and bind any key on a connected device to any KOReader action.

Originally created by [@alllexx88](https://github.com/alllexx88) (see [issue #40](https://github.com/zampierilucas/kindle-hid-passthrough/issues/40)).

![Plugin menu in KOReader](screenshots/menu.png)

## Features

Full feature parity with the BTManager WAF app — you can manage everything from inside KOReader, no need to exit.

- Adds a "BT Manager - HID Passthrough" entry under Settings > Network
- **Daemon control**: start / stop / toggle the HID daemon (also bindable to gestures via Dispatcher actions)
- **Scan for devices**: discovers nearby BLE and Classic HID devices, with live-updating results menu
- **Paired devices**: list paired devices with connect / disconnect / remove (forget) actions
- **Recent logs**: in-app log viewer with refresh, useful for debugging pairing issues
- **Clear descriptor cache**: drop cached HID descriptors
- **Daemon status**: version, configured devices, connected device, scanning / pairing flags
- **Key mappings**: bind any key on any connected device to any KOReader action

## Key mappings

**Settings → Network → BT Manager - HID Passthrough → Key mappings**

Pick the device, tap "Map a button…", press the control you want, then choose what it should do. Buttons, D-pad directions and triggers all register. Analog sticks don't yet.

<p align="center">
  <img src="screenshots/key-mappings.png" width="48%" alt="Key mappings">
  <img src="screenshots/key-actions.png" width="48%" alt="Choosing an action">
</p>

The action list opens on the everyday ones (page turns, menu, night mode, frontlight, font size, rotate) since the whole thing runs to several pages. Under that sits KOReader's entire Dispatcher list, grouped the way KOReader groups it for gestures and profiles, and after it the actions that drive the native Kindle reader.

Page turns, menu and brightness come from the `auto` group, which tries KOReader first and falls back to the Kindle reader, so those keep doing something once you leave KOReader. Everything picked out of the KOReader list only ever fires inside KOReader.

"Handled by" at the top of each device decides who ends up holding the evdev grab, since only one process can have it. Gamepads go to the mapper and keyboards stay with KOReader by default, and you can force it either way per device.

Open a mapping's row to change the action or remove it.

This is a frontend for [kindle-button-mapper](https://github.com/zampierilucas/kindle-button-mapper-rs), which ships with the release and is what reads the device and runs the action. Mappings live in its `/mnt/us/kindle-button-mapper/config.ini`, so a binding made here is the one the Mapper Manager app shows.

KOReader actions ride on KOReader's HTTP Inspector, so it needs to be enabled with auto-start on. The `auto` and Kindle reader ones don't.

### Keys that KOReader normally ignores

KOReader drops key events whose scancode isn't in its input event map, which is why media keys, F13–F24 and gamepad buttons normally do nothing. `event_map_extra.lua` fills those gaps so they can be bound. It only ever adds codes KOReader left unset, so stock key behavior is untouched.

If a key still doesn't register when you try to bind it, it's likely being sent as a HID consumer-control usage the daemon isn't translating to an evdev key code. Check with:

```bash
ssh kindle "cat /proc/bus/input/devices"
just logs
```

### Gamepads

KOReader's `externalkeyboard` plugin only ever looks for keyboards, so a gamepad, which FBInk classifies as `JOYSTICK`, is never opened and its buttons reach nothing. This plugin opens those itself, so `BtnA` and friends arrive as ordinary keys whenever the mapper isn't holding the node. Set "Handled by" to "KOReader only" if that's what you're after.

The D-pad and the triggers are `EV_ABS` and never become key events, so map those the way described above, the mapper reads the axes directly. Analog sticks are out for now, [kindle-button-mapper#40](https://github.com/zampierilucas/kindle-button-mapper-rs/issues/40).

## Requirements

KOReader 2026.07 "Sailing Walrus" or newer. Keyboards that connect while KOReader is running are picked up by KOReader's own `externalkeyboard` plugin, via the uevent input hot-plug support added in [koreader/koreader-base#2327](https://github.com/koreader/koreader-base/pull/2327) and [koreader/koreader#15248](https://github.com/koreader/koreader/pull/15248).

On older builds this plugin's daemon controls still work, but a keyboard connected after KOReader started won't be seen until you restart KOReader.

## Installation

Copy the `hidpassthrough.koplugin` directory to your KOReader plugins folder:

```
cp -r hidpassthrough.koplugin /mnt/us/koreader/plugins/
```

Then restart KOReader.

The kindle-hid-passthrough daemon must already be installed on the device at `/mnt/us/kindle_hid_passthrough/kindle-hid-passthrough`. See the main project README for installation instructions.

## Opening the menu

In KOReader, tap the top of the screen to bring up the menu bar, then:

**cog icon (Settings) → Network → BT Manager - HID Passthrough**

The sub-menu shows the daemon toggle, scan, paired devices and key mappings, with status, logs and cache tucked under Debug. Long-pressing the parent entry toggles the daemon without descending into the sub-menu.
