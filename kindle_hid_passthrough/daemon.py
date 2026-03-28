#!/usr/bin/env python3
"""
Kindle HID Passthrough - Daemon

Persistent connection manager for Bluetooth HID devices.
Maintains connection with auto-reconnect.

For use with init scripts / systemd.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import asyncio
import logging
import signal
import sys
import threading

sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

from api_server import APIServer, RequestHandler, PORT
from config import __version__, config, normalize_addr
from controller import DaemonController
from host import HIDHost
from logging_utils import log, setup_daemon_logging

logger = logging.getLogger(__name__)


class HIDDaemon:
    """Daemon that maintains persistent connection to an HID device."""

    def __init__(self):
        self.device_address = None
        self.running = False
        self.host = None
        self._host_task = None
        self._suspended = False
        self._resume_event = asyncio.Event()

    @property
    def connection_state(self) -> dict:
        """Current connection state for API."""
        if self.host and self.host._is_connection_alive() and not self._suspended:
            return {
                "connected": True,
                "address": normalize_addr(self.host.current_device_address) if self.host.current_device_address else None,
                "protocol": self.host.connected_protocol.value if self.host.connected_protocol else None,
                "name": self.host.device_name,
            }
        return {"connected": False}

    async def suspend(self):
        """Disconnect and release transport for scan/pair."""
        logger.info("Daemon suspending...")
        self._suspended = True
        self._resume_event.clear()

        # Cancel the host task first — this stops host.run()'s connect loop
        if self._host_task and not self._host_task.done():
            self._host_task.cancel()
            try:
                await self._host_task
            except (asyncio.CancelledError, Exception):
                pass
            self._host_task = None

        # Then clean up any remaining resources
        if self.host:
            try:
                await self.host.cleanup()
            except Exception:
                pass
            self.host = None

        logger.info("Daemon suspended")

    async def resume(self):
        """Resume connections after scan/pair."""
        logger.info("Daemon resuming...")
        self._suspended = False
        self._resume_event.set()

    def load_device(self) -> bool:
        """Load device(s) from config file."""
        devices = config.get_all_devices()
        if not devices:
            logger.error(f"No devices in {config.devices_config_file}")
            return False

        # Use first device's address
        self.device_address, protocol, name = devices[0]

        if len(devices) == 1 and self.device_address != '*':
            display = f"{name} ({self.device_address})" if name else self.device_address
            logger.info(f"Device: {display} ({protocol.value})")
        else:
            logger.info(f"Accepting {len(devices)} device(s):")
            for addr, proto, dev_name in devices:
                display = f"{dev_name} ({addr})" if dev_name else addr
                logger.info(f"  - {display} ({proto.value})")

        return True

    async def run(self):
        """Main daemon loop."""
        self.running = True

        if not self.load_device():
            logger.info("No devices configured, waiting for pairing...")
            while self.running and not self.load_device():
                self._resume_event.clear()
                await self._resume_event.wait()
            if not self.running:
                return

        logger.info(f"HID Daemon v{__version__}")

        while self.running:
            # Handle suspension
            if self._suspended:
                logger.info("Daemon suspended, waiting for resume...")
                await self._resume_event.wait()
                self._resume_event.clear()
                if not self.running:
                    break
                # Re-read devices.conf after resume
                if not self.load_device():
                    continue
                continue

            skip_delay = False

            try:
                logger.info("=== Starting connection ===")
                self.host = HIDHost()
                self._host_task = asyncio.create_task(
                    self.host.run()
                )
                await self._host_task

            except asyncio.CancelledError:
                if self._suspended:
                    logger.info("Connection cancelled (suspend)")
                elif not self.running:
                    logger.info("Cancelled (shutdown)")
                    break
                else:
                    logger.info("Connection cancelled, will reconnect")

            except Exception as e:
                logger.error(f"Error: {e}")

            finally:
                self._host_task = None
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
                        temp_host = HIDHost()
                        if hasattr(temp_host, 'clear_stale_key'):
                            await temp_host.clear_stale_key(auth_fail_addr)
                    except Exception as e:
                        logger.warning(f"Failed to clear stale key: {e}")
                    logger.info("Retrying connection immediately...")
                    skip_delay = True

                self.host = None

            if not self.running:
                break

            # Don't delay if we got suspended during connection
            if self._suspended:
                continue

            if not skip_delay:
                logger.info(f"Reconnecting in {config.reconnect_delay}s...")
                try:
                    await asyncio.wait_for(
                        self._resume_event.wait(),
                        timeout=config.reconnect_delay
                    )
                    # Resume event fired during delay — go back to top
                    self._resume_event.clear()
                except asyncio.TimeoutError:
                    pass  # Normal delay elapsed

        logger.info("Daemon stopped")

    async def stop(self):
        """Stop the daemon."""
        logger.info("Stopping...")
        self.running = False
        # Wake up if suspended (waiting on _resume_event)
        self._resume_event.set()
        if self.host:
            try:
                await self.host.cleanup()
            except Exception:
                pass


async def main():
    setup_daemon_logging(config.log_file)

    daemon = HIDDaemon()
    controller = DaemonController(daemon)
    controller.loop = asyncio.get_event_loop()

    # Start embedded API server
    server = APIServer(('127.0.0.1', PORT), RequestHandler)
    server.controller = controller
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log.info(f"API server listening on port {PORT}")

    # Signal handling
    shutdown = asyncio.Event()

    def on_signal():
        logger.info("Shutdown signal received")
        shutdown.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, on_signal)

    log.info(f"Kindle HID Passthrough v{__version__} (daemon)")
    daemon_task = asyncio.create_task(daemon.run())

    await asyncio.wait(
        [daemon_task, asyncio.create_task(shutdown.wait())],
        return_when=asyncio.FIRST_COMPLETED,
    )

    if shutdown.is_set():
        await daemon.stop()
        if not daemon_task.done():
            daemon_task.cancel()
            try:
                await daemon_task
            except asyncio.CancelledError:
                pass

    server.shutdown()
    logger.info("Daemon stopped")


if __name__ == '__main__':
    asyncio.run(main())
