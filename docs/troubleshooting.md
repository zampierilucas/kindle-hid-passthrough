# Troubleshooting

## Manual Commands

Commands for controlling kindle-hid-passthrough via SSH or kterm.

### Daemon

```bash
# Run directly
/mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --daemon

# Via upstart (if installed)
start hid-passthrough
stop hid-passthrough

# Check status
status hid-passthrough

# View logs
tail -f /var/log/hid_passthrough.log
```

### Pairing

```bash
# Interactive pairing (scans for both BLE and Classic devices)
/mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --pair
```

### Device Configuration

Paired devices are stored in `devices.conf`:

```bash
# Format: ADDRESS PROTOCOL [NAME]
98:B9:EA:01:67:68/P classic Xbox Wireless Controller
5C:2B:3E:50:4F:04/P ble BLE-M3
```

**Mixed Protocol Support**: You can configure both BLE and Classic devices. The daemon automatically detects mixed protocols and uses a unified host that handles both simultaneously - the first device to connect wins.

```bash
# View configured devices
cat /mnt/us/kindle_hid_passthrough/devices.conf

# Edit devices (add/remove)
vi /mnt/us/kindle_hid_passthrough/devices.conf
```

### Testing Input Events

```bash
# Find the input device
ls /dev/input/event*

# Monitor raw events
evtest /dev/input/event2
```

## Manual Installation Steps

### udev rules

These files tell the system that a connected input device is a keyboard. Without them, keypresses will be captured in `/dev/input/eventX` but won't be translated to keystrokes. You can still use programs like [kindle-button-mapper-rs](https://github.com/zampierilucas/kindle-button-mapper-rs) to map the events to actions.

```bash
cd /mnt/us/kindle_hid_passthrough
mntroot rw
cp scripts/dev_is_keyboard.sh /usr/local/bin/
cp assets/99-hid-keyboard.rules /etc/udev/rules.d
udevadm control --reload-rules
mntroot ro
```

### Upstart service

```bash
mntroot rw
cp /mnt/us/kindle_hid_passthrough/assets/hid-passthrough.upstart /etc/upstart/hid-passthrough.conf
mntroot ro
```

### BTManager WAF app

```bash
sh /mnt/us/kindle_hid_passthrough/illusion/install-waf-app.sh
```

### Keyboard layout

```bash
/mnt/us/kindle_hid_passthrough/scripts/setlayout.sh <layout>

# Available layouts
ls /usr/share/X11/xkb/symbols
```

Where `<layout>` can be the country code (`fr`, `de`, `cz` etc.) or country+variant (`'fr(oss)'`, `'fr(bepo)'`).

## Common Issues

### Keypresses captured but no text input

udev rules are not installed. Install them (see above) so the system recognizes the device as a keyboard.

### Daemon won't start

Check if the Bluetooth module is loaded:
```bash
lsmod | grep wmt_cdev_bt
```

Check if conflicting processes are running:
```bash
ps | grep -E "bluetoothd|vhci_stpbt"
```

The daemon handles both automatically on startup, but if it fails check the logs:
```bash
tail -50 /var/log/hid_passthrough.log
```

### Device pairs but won't reconnect

Check that the device is in `devices.conf` and the pairing keys are cached:
```bash
cat /mnt/us/kindle_hid_passthrough/devices.conf
ls /mnt/us/kindle_hid_passthrough/cache/
```

Try clearing the cache and re-pairing:
```bash
rm -rf /mnt/us/kindle_hid_passthrough/cache/*.json
/mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --pair
```
