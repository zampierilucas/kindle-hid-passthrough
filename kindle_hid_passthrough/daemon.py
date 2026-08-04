#!/usr/bin/env python3
"""Persistent connection manager with auto-reconnect + embedded API server."""

import asyncio
import logging
import signal
import sys
import threading

sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

import button_mapper
from api_server import PORT, APIServer, RequestHandler
from bt_setup import chip, prepare_bt
from config import config, get_version
from controller import DaemonController
from host import HIDHost
from logging_utils import errstr, log, setup_daemon_logging
from power_monitor import PowerMonitor
from scanner import Scanner

logger = logging.getLogger(__name__)


class HIDDaemon:
    """Daemon that maintains persistent connection to an HID device."""

    def __init__(self):
        self.running = False
        self.host = None
        self._host_task = None
        self._suspended = False
        self._resume_event = asyncio.Event()
        self._paired_host = None

    @property
    def connection_state(self) -> dict:
        """Current connection state for API."""
        if self.host and not self._suspended:
            return self.host.connection_state
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

    async def scan(self, duration=10.0, on_device_found=None):
        """Scan for BT devices. Must be called while suspended."""
        scanner = Scanner()
        if on_device_found:
            scanner.on_device_found = on_device_found
        try:
            await scanner.start()
            await scanner.scan(duration=duration)
        finally:
            await scanner.cleanup()

    async def pair(self, address, protocol, name=None) -> bool:
        """Pair with a device. Must be called while suspended."""
        host = HIDHost()
        try:
            success = await host.pair_device(address, protocol, name)
            if success:
                self._paired_host = host
                return True
            await host.cleanup()
            return False
        except Exception:
            await host.cleanup()
            raise

    async def disconnect(self):
        """Drop the active connection; daemon keeps running and will reconnect."""
        if self.host and self.host._is_connection_alive():
            await self.host.connection.disconnect()
        else:
            logger.info("No active connection to disconnect")
        if self._host_task and not self._host_task.done():
            self._host_task.cancel()

    async def resume(self):
        """Resume connections after scan/pair."""
        logger.info("Daemon resuming...")
        self._suspended = False
        self._resume_event.set()

    def _has_devices(self, log_details=False) -> bool:
        """Check if any devices are configured."""
        devices = config.get_all_devices()
        if not devices:
            return False

        if log_details:
            if len(devices) == 1 and devices[0][0] != '*':
                addr, proto, name = devices[0]
                display = f"{name} ({addr})" if name else addr
                logger.info(f"Device: {display} ({proto.value})")
            else:
                logger.info(f"Accepting {len(devices)} device(s):")
                for addr, proto, name in devices:
                    display = f"{name} ({addr})" if name else addr
                    logger.info(f"  - {display} ({proto.value})")

        return True

    async def run(self):
        """Main daemon loop."""
        self.running = True

        logger.info(f"HID Daemon v{get_version()}")

        while self.running:
            # Wait for devices if none configured or after suspend
            if self._suspended:
                logger.info("Daemon suspended, waiting for resume...")
                await self._resume_event.wait()
                self._resume_event.clear()
                if not self.running:
                    break

            if not self._has_devices(log_details=True):
                logger.info("No devices configured, waiting for pairing...")
                self._resume_event.clear()
                await self._resume_event.wait()
                self._resume_event.clear()  # else the next reconnect delay is skipped
                if not self.running:
                    break
                continue

            skip_delay = False
            chip().ensure_powered()

            try:
                # Use handed-off host from controller pairing if available
                if self._paired_host:
                    logger.info("=== Continuing with paired device ===")
                    self.host = self._paired_host
                    self._paired_host = None
                    self._host_task = asyncio.create_task(
                        self.host.continue_after_pairing()
                    )
                else:
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
                logger.error(f"Error: {errstr(e)}")

            finally:
                self._host_task = None
                # When suspended, suspend() owns cleanup of self.host. Skipping
                # here avoids a race where both paths run host.cleanup() in
                # parallel and deadlock on transport/connection teardown.
                auth_fail_addr = None
                vc_unplug_addr = None
                if self.host and not self._suspended:
                    auth_fail_addr = self.host.get_auth_failure_address()
                    vc_unplug_addr = self.host.get_virtual_cable_unplug_address()
                    try:
                        await self.host.cleanup()
                    except Exception:
                        pass
                    self.host = None

                if vc_unplug_addr:
                    logger.info(f"Virtual cable unplugged by {vc_unplug_addr}, removing device")
                    config.remove_device(vc_unplug_addr)
                    skip_delay = True

                if auth_fail_addr:
                    logger.info(f"Auth failure for {auth_fail_addr}, clearing stale key")
                    config.remove_pairing_key(auth_fail_addr)
                    skip_delay = True

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

    # Devices paired before the mapper was installed (or before this existed)
    # get their block on the next daemon start.
    button_mapper.register_all(config.get_all_devices())

    prepare_bt()

    daemon = HIDDaemon()
    controller = DaemonController(daemon)
    controller.loop = asyncio.get_event_loop()

    # Start embedded API server
    server = APIServer(('127.0.0.1', PORT), RequestHandler)
    server.controller = controller
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log.info(f"API server listening on port {PORT}")

    monitor = None
    if not chip().survives_suspend:
        monitor = PowerMonitor(controller)
        monitor.start()
        log.info("Watching powerd for system suspend")

    # Signal handling
    shutdown = asyncio.Event()

    def on_signal():
        logger.info("Shutdown signal received")
        shutdown.set()

    loop = asyncio.get_event_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, on_signal)

    log.info(f"Kindle HID Passthrough v{get_version()} (daemon)")
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

    if monitor:
        monitor.stop()
    server.shutdown()
    logger.info("Daemon stopped")


if __name__ == '__main__':
    asyncio.run(main())
