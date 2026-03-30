# Kindle HID Passthrough

Userspace Bluetooth HID host for Kindle with UHID passthrough.

## SSH Configuration

The Kindle is accessed via SSH using the host alias `kindle`.

## Deployment

Use `just` commands for all deployment and management:

```bash
just deploy       # Deploy files to Kindle
just restart      # Restart daemon
just ssh          # SSH into Kindle
```

## Daemon Management

```bash
just start        # Start daemon
just stop         # Stop daemon
just restart      # Restart daemon
just status       # Check daemon status
```

## Logs

```bash
just logs         # Follow daemon logs (tail -f)
just logs-recent  # Show last 50 lines
```

## Local Development

```bash
just check        # Check Python syntax
```

## Cache Management

```bash
just clear-cache  # Clear descriptor cache
just show-cache   # Show cached device data
```

## File Locations on Kindle

- Code: `/mnt/us/kindle_hid_passthrough/`
- Upstart config: `/etc/upstart/hid-passthrough.conf`
- Logs: `/var/log/hid_passthrough.log`
- Device config: `/mnt/us/kindle_hid_passthrough/devices.conf`
- Pairing keys: `/mnt/us/kindle_hid_passthrough/cache/pairing_keys.json`

## Manual System File Installation

### udev rules

```bash
cd /mnt/us/kindle_hid_passthrough
mntroot rw
cp scripts/dev_is_keyboard.sh /usr/local/bin/
cp assets/99-hid-keyboard.rules /etc/udev/rules.d
udevadm control --reload-rules
mntroot ro
```

### BTManager WAF app (dev install)

```bash
sh /mnt/us/kindle_hid_passthrough/illusion/install-waf-app.sh
```

## Autostart (Upstart)

The Kindle uses Upstart for service management. Two upstart configs are available:

- `hid-passthrough.upstart` - For binary releases (runs compiled binary)
- `hid-passthrough-dev.upstart` - For development (runs Python script)

The `just deploy` command installs the dev version. Binary releases include the production version.

```bash
just remove-autostart  # Disable autostart (removes upstart config)
```
