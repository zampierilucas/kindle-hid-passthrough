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

- Python 3.8+ (soft-float build for Kindle)
- Google Bumble >= 0.0.193
- Root access on Kindle
- Linux kernel with UHID support (`CONFIG_UHID`)

## Installation

1. Install Python 3.8 on your Kindle at `/mnt/us/python3.8-kindle/`

2. Copy the project to Kindle:
   ```bash
   scp -r kindle_hid_passthrough kindle:/mnt/us/kindle_hid_passthrough/
   ```

3. Install the init script:
   ```bash
   ssh kindle "cp /mnt/us/kindle_hid_passthrough/hid-passthrough.init /etc/init.d/hid-passthrough && chmod +x /etc/init.d/hid-passthrough"
   ```

4. Configure your device in `/mnt/us/kindle_hid_passthrough/devices.conf`:
   ```
   AA:BB:CC:DD:EE:FF classic
   ```

## Usage

### Pairing a New Device

```bash
# Interactive pairing (Classic Bluetooth)
ssh kindle "/mnt/us/python3.8-kindle/python3-wrapper.sh /mnt/us/kindle_hid_passthrough/main.py --pair --protocol classic"

# Interactive pairing (BLE)
ssh kindle "/mnt/us/python3.8-kindle/python3-wrapper.sh /mnt/us/kindle_hid_passthrough/main.py --pair --protocol ble"
```

### Running the Daemon

```bash
# Start daemon
ssh kindle "/etc/init.d/hid-passthrough start"

# Check status
ssh kindle "/etc/init.d/hid-passthrough status"

# View logs
ssh kindle "tail -f /var/log/hid_passthrough.log"

# Stop daemon
ssh kindle "/etc/init.d/hid-passthrough stop"
```

### Manual Execution (Debug)

```bash
ssh kindle "/mnt/us/python3.8-kindle/python3-wrapper.sh /mnt/us/kindle_hid_passthrough/main.py"
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

### Project Structure

```
kindle_hid_passthrough/
├── main.py              # Entry point (--pair, --daemon modes)
├── daemon.py            # Daemon with auto-reconnect
├── config.py            # Configuration management
├── host.py              # BLE HID host implementation
├── classic_host.py      # Classic Bluetooth HID host
├── uhid_handler.py      # UHID device creation
├── pairing.py           # Pairing and keystore
├── device_cache.py      # Report descriptor caching
├── logging_utils.py     # Logging utilities
├── devices.conf         # Device configuration
└── hid-passthrough.init # Init script
```

## References

- [Google Bumble](https://github.com/google/bumble)
- [Linux UHID Documentation](https://www.kernel.org/doc/html/latest/hid/uhid.html)
- [Bluetooth HID Profile Specification](https://www.bluetooth.com/specifications/specs/human-interface-device-profile-1-1-1/)
- [BLE HID Service Specification](https://www.bluetooth.com/specifications/specs/hid-service-1-0/)

## License

MIT
