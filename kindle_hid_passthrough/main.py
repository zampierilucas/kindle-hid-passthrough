#!/usr/bin/env python3
"""
Kindle HID Passthrough

Userspace Bluetooth HID host with UHID passthrough.
Supports both BLE and Classic Bluetooth HID devices.
Forwards all HID reports to Linux via UHID.

Usage:
    main.py                    # Run normally (connect to configured device)
    main.py --pair             # Interactive pairing mode (scans BLE + Classic)
    main.py --daemon           # Run as daemon with auto-reconnect + API server
    main.py --address XX:XX:XX:XX:XX:XX  # Connect to specific address
"""

import argparse
import asyncio
import sys

# Add current directory to path for imports
sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

from config import Protocol, __version__, config
from daemon import main as daemon_main
from host import HIDHost
from logging_utils import log
from scanner import Scanner


async def pair_mode(protocol_filter: Protocol = None, sequential: bool = False):
    """Interactive pairing mode - scan and pair with HID device.

    Args:
        protocol_filter: If set, only show devices of this protocol
        sequential: If True, scan BLE then Classic sequentially
    """
    mode = "sequentially" if sequential else "concurrently"
    if protocol_filter:
        log.info(f"Pairing mode (scanning {protocol_filter.value} {mode})")
    else:
        log.info(f"Pairing mode (scanning BLE + Classic {mode})")

    scanner = Scanner()

    try:
        await scanner.start()

        selected = None
        while selected is None:
            log.info("Put your device in pairing mode...")
            print("Press Enter to stop scanning early.")
            devices = []
            while not devices:
                stop_event = asyncio.Event()
                loop = asyncio.get_event_loop()
                loop.add_reader(sys.stdin.fileno(), stop_event.set)
                try:
                    all_devices = await scanner.scan(
                        duration=10.0, concurrent=not sequential,
                        stop_event=stop_event
                    )
                finally:
                    loop.remove_reader(sys.stdin.fileno())
                    if stop_event.is_set():
                        sys.stdin.readline()  # consume the Enter
                if protocol_filter:
                    devices = [d for d in all_devices if d.protocol == protocol_filter]
                else:
                    devices = all_devices
                if not devices:
                    log.warning("No HID devices found. Scanning again...")
                    await asyncio.sleep(2)

            print("\nFound devices:")
            for i, dev in enumerate(devices):
                proto_tag = "[BLE]" if dev.protocol == Protocol.BLE else "[Classic]"
                print(f"  {i+1}. {proto_tag} {dev.name} ({dev.address})")

            while True:
                try:
                    choice = input("\nSelect device (number, or 'r' to rescan): ").strip()
                    if choice.lower() == 'r':
                        print("Restarting search...")
                        break
                    idx = int(choice) - 1
                    if 0 <= idx < len(devices):
                        selected = devices[idx]
                        break
                    print("Invalid selection")
                except ValueError:
                    print("Enter a number or 'r' to rescan")
                except (EOFError, KeyboardInterrupt):
                    print("\nCancelled")
                    return

        log.info(f"Selected: {selected.name} ({selected.address}) [{selected.protocol.value}]")

    finally:
        await scanner.cleanup()

    host = HIDHost()

    try:
        success = await host.pair_device(selected.address, selected.protocol)

        if success:
            log.success(f"Paired with {selected.name}")
            config.add_device(selected.address, selected.protocol, selected.name)

            # Continue into run mode if host supports it
            if hasattr(host, 'continue_after_pairing'):
                log.info("Continuing with paired device...")
                await host.continue_after_pairing()
            else:
                log.success("Saved to devices.conf. Run without --pair to connect.")
        else:
            log.error("Pairing failed")

    finally:
        await host.cleanup()


async def run_mode(address: str):
    """Normal run mode - connect and forward reports."""
    log.info(f"Connecting to {address}")
    host = HIDHost()

    try:
        await host.run()
    except KeyboardInterrupt:
        log.warning("\nInterrupted")
    except Exception as e:
        log.error(f"Error: {e}")
        raise
    finally:
        await host.cleanup()


def main():
    parser = argparse.ArgumentParser(
        description='Kindle HID Passthrough - Userspace Bluetooth HID host'
    )
    parser.add_argument('--pair', action='store_true',
                        help='Interactive pairing mode (scans BLE + Classic)')
    parser.add_argument('--daemon', action='store_true',
                        help='Run as daemon with auto-reconnect + API server')
    parser.add_argument('--address', type=str,
                        help='Device address (overrides devices.conf)')
    parser.add_argument('--protocol', type=str, choices=['ble', 'classic'],
                        help='Filter by protocol (pairing) or override (run)')
    parser.add_argument('--sequential', action='store_true',
                        help='Scan BLE and Classic sequentially')

    args = parser.parse_args()

    log.info(f"Kindle HID Passthrough v{__version__}")
    log.info(f"Config base path: {config.base_path}")

    protocol_override = None
    if args.protocol:
        protocol_override = Protocol.CLASSIC if args.protocol == 'classic' else Protocol.BLE

    if args.pair:
        asyncio.run(pair_mode(protocol_override, sequential=args.sequential))
        return

    address = args.address

    if not address:
        all_devices = config.get_all_devices()
        if all_devices:
            # Show all configured devices
            if len(all_devices) == 1:
                addr, protocol, name = all_devices[0]
                display = f"{name} ({addr})" if name else addr
                log.info(f"Using device from {config.devices_config_file}: {display}")
            else:
                log.info(f"Using {len(all_devices)} devices from {config.devices_config_file}:")
                for addr, protocol, name in all_devices:
                    display = f"{name} ({addr})" if name else addr
                    log.info(f"  - [{protocol.value}] {display}")
            # Use first device's address for compatibility (unified host reads all from config)
            address = all_devices[0][0]
        else:
            if args.daemon:
                log.info("No devices configured. Starting API server for pairing.")
            else:
                log.error("No device address specified. Use --address or create devices.conf")
                log.info("Run with --pair to set up a new device")
                sys.exit(1)

    if args.daemon:
        # Use daemon module for proper reconnect handling
        asyncio.run(daemon_main())
    else:
        asyncio.run(run_mode(address))


if __name__ == '__main__':
    main()
