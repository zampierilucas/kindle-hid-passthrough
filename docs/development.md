# Development

## Setup

Requires SSH access to the Kindle (via USBNetwork or similar) and Python 3.10+ on the Kindle for the dev path.

The SSH host alias `kindle` should be configured in `~/.ssh/config`.

## Commands

```bash
just deploy      # Deploy files to Kindle
just restart     # Restart daemon
just logs        # Follow logs
just devices     # Show configured devices
just keys        # Show pairing keys
just check       # Check Python syntax
```

## File Locations on Kindle

- Code: `/mnt/us/kindle_hid_passthrough/`
- Upstart config: `/etc/upstart/hid-passthrough.conf`
- Logs: `/var/log/hid_passthrough.log`
- Device config: `/mnt/us/kindle_hid_passthrough/devices.conf`
- Pairing keys: `/mnt/us/kindle_hid_passthrough/cache/pairing_keys.json`

## Manual System File Installation

### udev rules

These files tell the system that a connected input device is a keyboard. Without them, keypresses will be captured in `/dev/input/eventX` but won't be translated to keystrokes.

```bash
cd /mnt/us/kindle_hid_passthrough/assets
mntroot rw
cp /mnt/us/kindle_hid_passthrough/scripts/dev_is_keyboard.sh /usr/local/bin/
cp 99-hid-keyboard.rules /etc/udev/rules.d
udevadm control --reload-rules
mntroot ro
```

### Upstart service

```bash
mntroot rw
cp /mnt/us/kindle_hid_passthrough/assets/hid-passthrough.upstart /etc/upstart/hid-passthrough.conf
mntroot ro
```

### BTManager WAF app (dev install)

```bash
sh /mnt/us/kindle_hid_passthrough/illusion/install-waf-app.sh
```

## Upstart Configs

Two upstart configs are available:

- `assets/hid-passthrough.upstart` - For binary releases (runs compiled binary)
- `kindle_hid_passthrough/hid-passthrough-dev.upstart` - For development (runs Python script)

The `just deploy` command installs the dev version.

## Cache Management

```bash
just clear-cache  # Clear descriptor cache
just show-cache   # Show cached device data
```
