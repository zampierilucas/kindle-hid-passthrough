# Kindle HID Passthrough

A userspace Bluetooth HID host for Amazon Kindle e-readers. Connects Bluetooth HID devices (gamepads, keyboards, remotes) and passes input directly to Linux via UHID.

## Overview

This project implements a complete Bluetooth stack in userspace using [Google Bumble](https://github.com/google/bumble), bypassing the Kindle's buggy kernel Bluetooth drivers. HID reports are forwarded to the Linux input subsystem via `/dev/uhid`, making devices appear as native input devices.

```
BT HID Device  -->  /dev/stpbt  -->  Bumble (userspace BT stack)  -->  /dev/uhid  -->  Linux input (/dev/input/eventX)
```

## Features

- **Generic HID support** - Works with any Bluetooth HID device (Classic or BLE)
- **UHID passthrough** - Devices appear as native Linux input devices
- **Auto-reconnection** - Daemon mode with automatic reconnection
- **SDP descriptor query** - Fetches real HID report descriptors from devices
- **Pairing support** - Interactive pairing with link key persistence

## Requirements

- Python 3.10 for Kindle - available from [MobileRead forums](https://www.mobileread.com/forums/showthread.php?t=367713)
- Root access on Kindle (via USBNetwork or similar)
- Linux kernel with UHID support (`CONFIG_UHID`) - enabled by default on Kindle

## Installation

### From Release (Recommended)

1. Install Python 3.10 on your Kindle at `/mnt/us/python3.10-kindle/`

2. Download the latest release from [GitHub Releases](https://github.com/zampierilucas/kindle-hid-passthrough/releases)

3. Copy to Kindle and run:
   ```bash
   scp kindle-hid-passthrough kindle:/mnt/us/
   ssh kindle '/mnt/us/kindle-hid-passthrough'
   ```

   On first run, it extracts to `/mnt/us/hid-passthrough/` and runs automatically.

4. Configure your device in `/mnt/us/hid-passthrough/devices.conf`:
   ```
   AA:BB:CC:DD:EE:FF classic
   ```

### Building from Source

Build the self-extracting archive locally:

```bash
# Requires Docker with QEMU support for ARM emulation
./build-arm-binary.sh

# Or manually:
docker buildx build --platform linux/arm/v7 -f Dockerfile.arm -t kindle-hid-arm --load .
docker cp $(docker create kindle-hid-arm):/build/dist/kindle-hid-passthrough dist/
```

Output: `dist/kindle-hid-passthrough` (~1.5MB self-extracting archive)

## Usage

### Pairing a New Device

```bash
# Interactive pairing (Classic Bluetooth)
ssh kindle '/mnt/us/hid-passthrough/run.sh --pair --protocol classic'

# Interactive pairing (BLE)
ssh kindle '/mnt/us/hid-passthrough/run.sh --pair --protocol ble'
```

### Running the Daemon

```bash
# Start daemon (auto-reconnect mode)
ssh kindle '/mnt/us/hid-passthrough/run.sh --daemon'

# View logs
ssh kindle 'tail -f /var/log/hid_passthrough.log'
```

### Manual Execution (Debug)

```bash
# Run once (connects to device in devices.conf)
ssh kindle '/mnt/us/hid-passthrough/run.sh'

# Show help
ssh kindle '/mnt/us/hid-passthrough/run.sh --help'
```

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

### Supported Protocols

| Protocol | Status | Notes |
|----------|--------|-------|
| Classic Bluetooth (BR/EDR) | Working | Gamepads, keyboards |
| BLE (Bluetooth Low Energy) | Working | Page turners, remotes |

## Mapping Inputs to Actions

This project creates standard Linux input devices (`/dev/input/eventX`) but does not handle mapping button presses to actions.

On **Kindle**, the reading application ignores standard input devices, so you need a separate input mapper to trigger actions like page turns. Recommended: [kindle-button-mapper-rs](https://github.com/zampierilucas/kindle-button-mapper-rs) - A lightweight daemon that maps HID inputs to Kindle actions.

On more **open devices like Kobo**, applications may read directly from `/dev/input/eventX`, so the HID devices created by this project could work out of the box without additional mapping.

## Hardware

Tested on:
- **Device**: Kindle MT8110 Bellatrix
- **SoC**: MediaTek MT8512 (ARMv7-A Cortex-A53)
- **Kernel**: Linux 4.9.77-lab126
- **Bluetooth**: MediaTek CONSYS via `/dev/stpbt`

## Development

### Deploy to Kindle

```bash
just deploy      # Deploy files to Kindle
just restart     # Restart daemon
just logs        # Follow logs
```

### Creating a Release

Releases are automated via GitHub Actions. Push a version tag to create a release:

```bash
git tag v1.0.0
git push origin v1.0.0
```

This triggers the build workflow which compiles the ARM binary and attaches it to the GitHub release.

## References

- [Google Bumble](https://github.com/google/bumble)
- [Linux UHID Documentation](https://www.kernel.org/doc/html/latest/hid/uhid.html)
- [Bluetooth HID Profile Specification](https://www.bluetooth.com/specifications/specs/human-interface-device-profile-1-1-1/)
- [BLE HID Service Specification](https://www.bluetooth.com/specifications/specs/hid-service-1-0/)

## License

MIT
