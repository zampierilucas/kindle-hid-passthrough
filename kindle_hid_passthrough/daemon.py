#!/usr/bin/env python3
"""
Kindle HID Passthrough - Daemon

Persistent connection manager for Bluetooth HID devices.
Maintains connection with auto-reconnect.

For use with init scripts / systemd.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

__version__ = "2.0.0"

import asyncio
import logging
import signal
import sys

sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

from config import config, create_host
from logging_utils import setup_daemon_logging

logger = logging.getLogger(__name__)


class HIDDaemon:
    """Daemon that maintains persistent connection to an HID device."""

    def __init__(self):
        self.device_address = None
        self.protocol = None
        self.running = False
        self.host = None

    def load_device(self) -> bool:
        """Load device(s) from config file."""
        devices = config.get_all_devices()
        if not devices:
            logger.error(f"No devices in {config.devices_config_file}")
            return False

        # Use first device's protocol, but we'll accept any from the list
        self.device_address, self.protocol = devices[0]

        if len(devices) == 1 and self.device_address != '*':
            logger.info(f"Device: {self.device_address} ({self.protocol.value})")
        else:
            logger.info(f"Accepting {len(devices)} device(s) ({self.protocol.value}):")
            for addr, proto in devices:
                logger.info(f"  - {addr} ({proto.value})")

        return True

    async def run(self):
        """Main daemon loop."""
        self.running = True

        if not self.load_device():
            return

        logger.info(f"HID Daemon v{__version__}")

        while self.running:
            try:
                logger.info("=== Starting connection ===")
                self.host = create_host(self.protocol)
                await self.host.run(self.device_address)

            except asyncio.CancelledError:
                logger.info("Cancelled")
                break

            except Exception as e:
                logger.error(f"Error: {e}")

            finally:
                # Check for auth failure before cleanup
                auth_fail_addr = None
                if self.host and hasattr(self.host, 'get_auth_failure_address'):
                    auth_fail_addr = self.host.get_auth_failure_address()

                if self.host:
                    try:
                        await self.host.cleanup()
                    except Exception:
                        pass

                # Handle auth failure - clear stale key and retry immediately
                if auth_fail_addr:
                    logger.info(f"Auth failure detected for {auth_fail_addr}")
                    try:
                        # Create new host just for key cleanup
                        temp_host = create_host(self.protocol)
                        if hasattr(temp_host, 'clear_stale_key'):
                            await temp_host.clear_stale_key(auth_fail_addr)
                    except Exception as e:
                        logger.warning(f"Failed to clear stale key: {e}")
                    logger.info("Retrying connection immediately...")
                    self.host = None
                    continue  # Skip the delay, retry now

                self.host = None

            if not self.running:
                break

            logger.info(f"Reconnecting in {config.reconnect_delay}s...")
            await asyncio.sleep(config.reconnect_delay)

        logger.info("Daemon stopped")

    async def stop(self):
        """Stop the daemon."""
        logger.info("Stopping...")
        self.running = False
        if self.host:
            try:
                await self.host.cleanup()
            except Exception:
                pass


async def main():
    setup_daemon_logging(config.log_file)

    daemon = HIDDaemon()
    shutdown = asyncio.Event()

    def on_signal():
        logger.info("Shutdown signal received")
        shutdown.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, on_signal)

    task = asyncio.create_task(daemon.run())

    await asyncio.wait(
        [task, asyncio.create_task(shutdown.wait())],
        return_when=asyncio.FIRST_COMPLETED
    )

    if shutdown.is_set():
        await daemon.stop()
        if not task.done():
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    logger.info("Daemon stopped")


if __name__ == '__main__':
    asyncio.run(main())
