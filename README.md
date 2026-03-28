# Kindle HID Passthrough

A userspace Bluetooth HID host for Amazon Kindle e-readers. Connects Bluetooth HID devices (gamepads, keyboards, remotes) and passes input directly to Linux via UHID.

## Overview

This project implements a complete Bluetooth stack in userspace using [Google Bumble](https://github.com/google/bumble), bypassing the Kindle's buggy kernel Bluetooth drivers. HID reports are forwarded to the Linux input subsystem via `/dev/uhid`, making devices appear as native input devices.

```
BT HID Device  -->  /dev/stpbt  -->  Bumble (userspace BT stack)  -->  /dev/uhid  -->  Linux input (/dev/input/eventX)  -->  Keypresses
```

## Features

- **Generic HID support** - Works with any Bluetooth HID device (Classic or BLE)
- **Mixed protocol support** - Configure both BLE and Classic devices simultaneously
- **UHID passthrough** - Devices appear as native Linux input devices
- **UDEV keyboard device** - Devices can be treated as keyboard and keypresses used for text input.
- **Auto-reconnection** - Daemon mode with automatic reconnection
- **Hybrid connection** - Passive (device connects) + active (host connects) for Classic
- **SDP descriptor query** - Fetches real HID report descriptors from devices
- **Pairing support** - Interactive pairing with link key persistence
- **Support for international layouts** - Country-specific layouts (azerty, qwertz) and other layouts (dvorak, bepo) are supported.

As this project replaces the original Bluetooth stack, you can't use the default Bluetooth services (as listening to audiobooks) while service is active.

## Requirements

- SSH access on Kindle (via USBNetwork or similar)
- Linux kernel with UHID support (`CONFIG_UHID`) - enabled by default on Kindle

## Deployment

Pre-built ARM binaries are available from [GitHub Releases](https://github.com/zampierilucas/kindle-hid-passthrough/releases).
1. Download and extract:
   ```bash
   VERSION=v3.0.0
   wget "https://github.com/zampierilucas/kindle-hid-passthrough/releases/download/${VERSION}/kindle-hid-passthrough-${VERSION}-armv7.tar.gz"
   tar -xzf kindle-hid-passthrough-${VERSION}-armv7.tar.gz
   ```

   The release contains a `dist/` directory with a bundled Python runtime and all dependencies — no Python installation required on the Kindle.

2. Pair your device and test:
   ```bash
   /mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --pair
   /mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --daemon
   ```

   Bluetooth hardware setup (kernel module loading, killing conflicting processes) is handled automatically on startup.

3. (Optional) Install the upstart config for autostart:
   ```bash
   cp /mnt/us/kindle_hid_passthrough/hid-passthrough.upstart /etc/upstart/hid-passthrough.conf
   ```

## Usage

Run the provided installation script from ssh or kterm:

```bash
/mnt/us/kindle_hid_passthrough/install.sh
```

It allows to:

- **Pair a new device**
- **List paired devices**
- **Install udev rules** - needed to configure connected devices as keyboards. Not required for other input devices (page turners, game controllers)
- **Install upstart** - makes *kindle-hid-passthrough* start automatically at boot. Use this if you plan to often use the Kindle for writing
- **Install BTManager app** - installs a touchscreen UI for managing devices directly on the Kindle (see below)
- **Set custom keyboard layout** - switch to a custom keyboard layout (French, German, Dvorak...)

### BTManager WAF App

A built-in Kindle app for managing Bluetooth HID devices from the touchscreen — no SSH needed. Scan for devices, pair, remove, start/stop the daemon, all from the Kindle UI.

![BTManager scan & pair](docs/screenshots/btmanager-scan.png)

Install via option 5 in `install.sh`, or directly:

```bash
/mnt/us/kindle_hid_passthrough/illusion/install-waf-app.sh
```

### Manual usage

Here are the commands you can use to control manually *kindle-hid-passthrough*.

#### Install the udev rules

These files are necessary to tell the system that a connected input device is a keyboard.

Run the following commands in a terminal (over ssh or kterm):

```bash
cd /mnt/us/kindle_hid_passthrough/assets
mntroot rw
cp dev_is_keyboard.sh /usr/local/bin/
cp 99-hid-keyboard.rules /etc/udev/rules.d
udevadm control --reload-rules
mntroot ro
```

*Without these files, the keypresses will be captured (appear in `/dev/input/eventX`) but won't be translated to keystrokes. You can still use programs like [kindle-button-mapper-rs](https://github.com/zampierilucas/kindle-button-mapper-rs) to map the events to actions.*

#### Install upstart service

Run the following commands in a terminal (over ssh or kterm):

```bash
mntroot rw
cp /mnt/us/kindle_hid_passthrough/hid-passthrough.upstart /etc/upstart/hid-passthrough.conf
mntroot ro
```

#### Pairing a New Device

```bash
# Interactive pairing (scans for both BLE and Classic devices)
ssh kindle "/mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --pair"
```

### Running the Daemon

```bash
# Run directly
ssh kindle "/mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --daemon"

# Or via upstart (if installed)
ssh kindle "start hid-passthrough"
ssh kindle "stop hid-passthrough"

# View logs
ssh kindle "tail -f /var/log/hid_passthrough.log"

# Test events sent by the device
ssh kindle "evtest /dev/input/event2"
```

#### Device Configuration

Paired devices are stored in `devices.conf`:

```bash
# Format: ADDRESS PROTOCOL [NAME]
98:B9:EA:01:67:68/P classic Xbox Wireless Controller
5C:2B:3E:50:4F:04/P ble BLE-M3
```

**Mixed Protocol Support**: You can configure both BLE and Classic devices. The daemon automatically detects mixed protocols and uses a unified host that handles both simultaneously - the first device to connect wins.

```bash
# View configured devices
ssh kindle "cat /mnt/us/kindle_hid_passthrough/devices.conf"

# Edit devices (add/remove)
ssh kindle "vi /mnt/us/kindle_hid_passthrough/devices.conf"
```

#### Changing layout

```bash
# View configured devices
ssh kindle "/mnt/us/kindle_hid_passthrough/setlayout.sh <layout>"

# Get available layouts
ssh kindle "ls /usr/share/X11/xkb/symbols"
```

where `<layout>` can be the country code (`fr`, `de`, `cz` etc.) or country+variant (`'fr(oss)'`,`'fr(bepo)'`)

## How It Works

### Why Userspace?

The Kindle's kernel Bluetooth stack has bugs that prevent proper HID pairing. By implementing the entire Bluetooth stack in userspace with Bumble, we bypass these limitations entirely.

### Architecture

1. **Transport**: Bumble communicates with the Bluetooth hardware via `/dev/stpbt`
2. **Protocol**: Supports both Classic Bluetooth (BR/EDR) and BLE HID profiles
3. **Pairing**: Handles SSP (Secure Simple Pairing) with link key persistence
4. **HID Reports**: Received via L2CAP (Classic) or GATT notifications (BLE)
5. **UHID**: Reports are forwarded to `/dev/uhid`, creating virtual input devices
6. **Linux Input**: The kernel parses the HID descriptor and creates `/dev/input/eventX`
7. **Udev**: Defines the input device as a keyboard and translates keypresses to keyboard input.

### Supported Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| Classic Bluetooth (BR/EDR) | Working | Gamepads, keyboards |
| BLE (Bluetooth Low Energy) | Working | Page turners, remotes |

## Mapping Inputs to Specific Actions

On **Kindle**, the reading application ignores standard input devices, so you need a separate input mapper to trigger actions like page turns. Recommended: [kindle-button-mapper-rs](https://github.com/zampierilucas/kindle-button-mapper-rs) - A lightweight daemon that maps HID inputs to Kindle actions.

On more **open devices like Kobo**, applications may read directly from `/dev/input/eventX`, so the HID devices created by this project could work out of the box without additional mapping.

## Hardware

Tested on:
- **Device**: Kindle MT8110 Bellatrix
- **SoC**: MediaTek MT8512 (ARMv7-A Cortex-A53)
- **Kernel**: Linux 4.9.77-lab126
- **Bluetooth**: MediaTek CONSYS via `/dev/stpbt`

## Development

```bash
just deploy      # Deploy files to Kindle
just restart     # Restart daemon
just logs        # Follow logs
just devices     # Show configured devices
just keys        # Show pairing keys
```

## References

- [Google Bumble](https://github.com/google/bumble)
- [Linux UHID Documentation](https://www.kernel.org/doc/html/latest/hid/uhid.html)
- [Bluetooth HID Profile Specification](https://www.bluetooth.com/specifications/specs/human-interface-device-profile-1-1-1/)
- [BLE HID Service Specification](https://www.bluetooth.com/specifications/specs/hid-service-1-0/)

## This software is distributed under the MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the “Software”), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
