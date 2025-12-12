#!/usr/bin/env python3
"""
Kindle HID Passthrough

Userspace Bluetooth HID host with UHID passthrough.
Supports both BLE and Classic Bluetooth HID devices.
Forwards all HID reports to Linux via UHID.

Usage:
    main.py                    # Run normally (connect to configured device)
    main.py --pair             # Interactive pairing mode
    main.py --daemon           # Run as daemon with auto-reconnect
    main.py --address XX:XX:XX:XX:XX:XX  # Connect to specific address

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import argparse
import asyncio
import sys
import os

# Add current directory to path for imports
sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

from config import config, Protocol, create_host
from logging_utils import log


async def pair_mode(protocol: Protocol):
    """Interactive pairing mode - scan and pair with a device."""
    log.info(f"Pairing mode ({protocol.value})")

    host = create_host(protocol)

    try:
        await host.start()

        # Both Classic and BLE use scan-and-select flow
        log.info("Put your device in pairing mode...")
        devices = []
        while not devices:
            devices = await host.scan(duration=10.0)
            if not devices:
                log.warning("No HID devices found. Scanning again...")
                await asyncio.sleep(2)

        # Show device list
        print("\nFound devices:")
        for i, dev in enumerate(devices):
            print(f"  {i+1}. {dev['name']} ({dev['address']})")

        # Get user choice
        while True:
            try:
                choice = input("\nSelect device (number): ").strip()
                idx = int(choice) - 1
                if 0 <= idx < len(devices):
                    break
                print("Invalid selection")
            except ValueError:
                print("Enter a number")
            except (EOFError, KeyboardInterrupt):
                print("\nCancelled")
                return

        selected = devices[idx]
        log.info(f"Selected: {selected['name']} ({selected['address']})")

        # Pair
        success = await host.pair_device(selected['address'])

        if success:
            log.success(f"Paired with {selected['name']}")

            # Offer to save to devices.conf
            save = input("\nSave to devices.conf? [Y/n]: ").strip().lower()
            if save != 'n':
                save_device_config(selected['address'], protocol)
                log.success("Saved! Run without --pair to connect.")
        else:
            log.error("Pairing failed")

    finally:
        await host.cleanup()


def save_device_config(address: str, protocol: Protocol):
    """Save device address to devices.conf."""
    conf_file = config.devices_config_file
    log.info(f"Saving to: {conf_file}")

    # Ensure directory exists
    dir_path = os.path.dirname(conf_file)
    if dir_path:
        os.makedirs(dir_path, exist_ok=True)

    try:
        with open(conf_file, 'w') as f:
            f.write(f"# Device address and protocol\n")
            f.write(f"{address} {protocol.value}\n")
        log.info(f"Written: {address} {protocol.value}")
    except Exception as e:
        log.error(f"Failed to save: {e}")


async def run_mode(address: str, protocol: Protocol):
    """Normal run mode - connect and forward reports."""
    log.info(f"Connecting to {address} ({protocol.value})")

    host = create_host(protocol)

    try:
        await host.run(address)
    except KeyboardInterrupt:
        log.warning("\nInterrupted")
    except Exception as e:
        log.error(f"Error: {e}")
        raise
    finally:
        await host.cleanup()


async def daemon_mode(address: str, protocol: Protocol):
    """Daemon mode - auto-reconnect on disconnection."""
    log.info(f"Daemon mode: {address} ({protocol.value})")

    while True:
        host = create_host(protocol)

        try:
            log.info("=== Starting connection ===")
            await host.run(address)
        except KeyboardInterrupt:
            log.warning("\nDaemon interrupted")
            await host.cleanup()
            break
        except Exception as e:
            log.error(f"Connection error: {e}")
        finally:
            try:
                await host.cleanup()
            except Exception:
                pass

        log.info(f"Reconnecting in {config.reconnect_delay}s...")
        await asyncio.sleep(config.reconnect_delay)


def main():
    parser = argparse.ArgumentParser(
        description='Kindle HID Passthrough - Userspace Bluetooth HID host'
    )
    parser.add_argument('--pair', action='store_true',
                        help='Interactive pairing mode')
    parser.add_argument('--daemon', action='store_true',
                        help='Run as daemon with auto-reconnect')
    parser.add_argument('--address', type=str,
                        help='Device address (overrides devices.conf)')
    parser.add_argument('--protocol', type=str, choices=['ble', 'classic'],
                        help='Bluetooth protocol (default: from config)')

    args = parser.parse_args()

    # Determine protocol
    if args.protocol:
        protocol = Protocol.CLASSIC if args.protocol == 'classic' else Protocol.BLE
    else:
        protocol = config.protocol

    # Pair mode
    if args.pair:
        asyncio.run(pair_mode(protocol))
        return

    # Get device address
    address = args.address
    if not address:
        device_config = config.get_device_config()
        if device_config:
            address, protocol = device_config
            log.info(f"Using device from devices.conf: {address}")
        else:
            log.error("No device address specified. Use --address or create devices.conf")
            log.info("Run with --pair to set up a new device")
            sys.exit(1)

    log.info(f"Using {protocol.value.upper()} protocol")

    # Run mode
    if args.daemon:
        asyncio.run(daemon_mode(address, protocol))
    else:
        asyncio.run(run_mode(address, protocol))


if __name__ == '__main__':
    main()
