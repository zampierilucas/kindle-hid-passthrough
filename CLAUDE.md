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
- Init script: `/etc/init.d/hid-passthrough`
- Logs: `/var/log/hid_passthrough.log`
- Device config: `/mnt/us/kindle_hid_passthrough/devices.conf`
- Pairing keys: `/mnt/us/kindle_hid_passthrough/cache/pairing_keys.json`
