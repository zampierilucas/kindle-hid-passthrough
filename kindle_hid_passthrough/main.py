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
import os
import sys
import threading

# Add current directory to path for imports
sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

from config import Protocol, config, get_version
from daemon import main as daemon_main
from bt_setup import prepare_bt
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
        prepare_bt()
        await scanner.start()

        # Only a tty can send that Enter. A pipe or redirect (ssh without -t,
        # nohup, upstart) is readable at EOF, so the reader fires immediately
        # and every scan returns in ~0s with 0 devices (issue #179).
        try:
            interactive = sys.stdin.isatty()
        except (AttributeError, ValueError):
            interactive = False

        selected = None
        while selected is None:
            log.info("Put your device in pairing mode...")
            if interactive:
                print("Press Enter to stop scanning early.")
            devices = []
            while not devices:
                stop_event = asyncio.Event()
                loop = asyncio.get_event_loop()
                stdin_watched = False
                if interactive:
                    try:
                        loop.add_reader(sys.stdin.fileno(), stop_event.set)
                        stdin_watched = True
                    except (OSError, ValueError):
                        pass  # stdin not pollable (headless/service): just scan
                try:
                    all_devices = await scanner.scan(
                        duration=10.0, concurrent=not sequential,
                        stop_event=stop_event
                    )
                finally:
                    if stdin_watched:
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
        success = await host.pair_device(selected.address, selected.protocol, selected.name)

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


async def run_mode():
    """Normal run mode - connect and forward reports."""
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


def _close_inherited_sockets():
    """Close socket fds inherited from the spawning process, e.g. KOReader's
    HTTP Inspector listener when spawned from the koplugin (#86)."""
    for entry in os.listdir('/proc/self/fd'):
        fd = int(entry)
        if fd <= 2:
            continue
        try:
            if os.readlink(f'/proc/self/fd/{entry}').startswith('socket:'):
                os.close(fd)
        except OSError:
            pass


def _clear_boot_attempts():
    try:
        os.unlink(os.path.join(config.base_path, 'boot_attempts'))
    except OSError:
        pass


def main():
    _close_inherited_sockets()

    parser = argparse.ArgumentParser(
        description='Kindle HID Passthrough - Userspace Bluetooth HID host'
    )
    parser.add_argument('--pair', action='store_true',
                        help='Interactive pairing mode (scans BLE + Classic)')
    parser.add_argument('--daemon', action='store_true',
                        help='Run as daemon with auto-reconnect + API server')
    parser.add_argument('--address', type=str,
                        help='Device address (overrides devices.conf)')
    parser.add_argument('--protocol', type=str,
                        choices=['ble', 'classic', 'classic_audio'],
                        help='Filter by protocol (pairing) or override (run)')
    parser.add_argument('--sequential', action='store_true',
                        help='Scan BLE and Classic sequentially')
    parser.add_argument('--diagnostics', action='store_true',
                        help='Print a read-only diagnostics dump for bug reports')

    args = parser.parse_args()

    if args.daemon:
        timer = threading.Timer(120, _clear_boot_attempts)
        timer.daemon = True
        timer.start()

    if args.diagnostics:
        from diagnostics import run_diagnostics
        run_diagnostics()
        return

    log.info(f"Kindle HID Passthrough v{get_version()}")
    log.info(f"Config base path: {config.base_path}")

    if not config.transport:
        log.error("No HCI transport available - unsupported Kindle model or "
                  "missing BT device node (see errors above)")
        sys.exit(1)

    protocol_override = None
    if args.protocol:
        try:
            protocol_override = Protocol(args.protocol)
        except ValueError:
            protocol_override = Protocol.CLASSIC if args.protocol == 'classic' else Protocol.BLE

    if args.pair:
        asyncio.run(pair_mode(protocol_override, sequential=args.sequential))
        return

    address = args.address

    if not address:
        all_devices = config.get_all_devices()
        if all_devices:
            # Show all configured devices (the host reads them from config)
            if len(all_devices) == 1:
                addr, protocol, name = all_devices[0]
                display = f"{name} ({addr})" if name else addr
                log.info(f"Using device from {config.devices_config_file}: {display}")
            else:
                log.info(f"Using {len(all_devices)} devices from {config.devices_config_file}:")
                for addr, protocol, name in all_devices:
                    display = f"{name} ({addr})" if name else addr
                    log.info(f"  - [{protocol.value}] {display}")
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
        asyncio.run(run_mode())


if __name__ == '__main__':
    main()
