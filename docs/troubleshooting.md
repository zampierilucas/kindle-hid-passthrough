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

# Verbose logs, including a timestamped line per HID report
KINDLE_HID_DEBUG=1 /mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --daemon &

# Also log raw HCI, SMP, L2CAP and ATT traffic (very verbose)
KINDLE_HID_DEBUG=hci /mnt/us/kindle_hid_passthrough/kindle-hid-passthrough --daemon &
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

**Multi-device support**: Every configured device connects and stays connected at the same time, across both protocols. Sessions are tracked per address, so a keyboard over Classic and a mouse over BLE (or several of each) work together.

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

## Common Issues

### Keypresses captured but no text input

udev rules are not installed. Install them (see above) so the system recognizes the device as a keyboard.

### BTManager doesn't show up on the home screen

BTManager is launched by a scriptlet, and scriptlets need the [Hotfix](https://github.com/KindleModding/Hotfix/releases/tag/v2.3.7) package. Kindles jailbroken with older methods don't support them at all, so the app installs fine and then never appears. Install the hotfix as an mrpi package and the entry shows up.

Everything else works without it — start the daemon over SSH or from the KOReader plugin and page turns behave normally.

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

### Missed keypresses after idle on i.MX Kindles (8th-10th gen)

Presses a few seconds apart work, but one after 10-30 seconds of reading does
nothing, then recovers on its own. The SoC is entering a cpuidle state whose
exit latency is longer than the UART RX FIFO can cover at 2 Mbaud, so the first
bytes of the HCI packet are lost.

The daemon holds a CPU latency ceiling while the transport is open. Confirm it
took effect:
```bash
grep -E "cpuidle budget|CPU latency|cpuidle state" /var/log/hid_passthrough.log
```

Check what the kernel offers and how deep each state is:
```bash
for s in /sys/devices/system/cpu/cpu0/cpuidle/state*; do
    echo "$(basename $s) $(cat $s/name) $(cat $s/latency)us disable=$(cat $s/disable)"
done
ls -l /dev/cpu_dma_latency
```

Resync messages mean bytes were lost but the parser recovered:
```bash
grep "HCI resync" /var/log/hid_passthrough.log
```
