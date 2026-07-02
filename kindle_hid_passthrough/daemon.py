#!/usr/bin/env python3
"""Persistent connection manager with auto-reconnect + embedded API server."""

import asyncio
import logging
import signal
import sys
import threading

sys.path.insert(0, '/mnt/us/kindle_hid_passthrough')

from api_server import APIServer, RequestHandler, PORT
from config import config, get_version
from controller import DaemonController
from host import HIDHost
from power_events import KindlePowerEventMonitor
from scanner import Scanner
from logging_utils import log, setup_daemon_logging

logger = logging.getLogger(__name__)


class HIDDaemon:
    """Daemon that maintains persistent connection to an HID device."""

    def __init__(self):
        self.running = False
        self.host = None
        self._host_task = None
        self._suspended = False
        self._suspend_reason = None
        self._resume_event = asyncio.Event()
        self._lifecycle_lock = asyncio.Lock()
        self._power_resume_task = None
        self._power_blocked = False
        self._resume_after_power = False
        self._resume_after_power_reason = None
        self.last_pair_error = None

    @property
    def connection_state(self) -> dict:
        """Current connection state for API."""
        if self.host and not self._suspended:
            return self.host.connection_state
        return {"connected": False}

    async def suspend(self, reason="manual"):
        """Disconnect and release transport for scan/pair."""
        async with self._lifecycle_lock:
            if reason == "power":
                self._power_blocked = True
            elif reason == "manual":
                self._resume_after_power = False
                self._resume_after_power_reason = None

            if self._suspended:
                if reason != "power":
                    self._suspend_reason = reason
                logger.info(
                    f"Daemon already suspended"
                    f"{f' ({self._suspend_reason})' if self._suspend_reason else ''}"
                )
                return

            logger.info(f"Daemon suspending ({reason})...")
            self._suspended = True
            self._suspend_reason = reason
            self._resume_event.clear()

            if self._host_task and not self._host_task.done():
                self._host_task.cancel()
                try:
                    await self._host_task
                except (asyncio.CancelledError, Exception):
                    pass
                self._host_task = None

            if self.host:
                try:
                    await self.host.cleanup()
                except Exception:
                    pass
                self.host = None

            logger.info(f"Daemon suspended ({reason})")

    async def scan(self, duration=10.0, on_device_found=None, stop_event=None):
        """Scan for BT devices. Must be called while suspended."""
        scanner = Scanner()
        if on_device_found:
            scanner.on_device_found = on_device_found
        try:
            await scanner.start()
            await scanner.scan(duration=duration, stop_event=stop_event)
        finally:
            await scanner.cleanup()

    async def pair(self, address, protocol, name=None) -> bool:
        """Pair with a device. Must be called while suspended."""
        host = HIDHost()
        self.last_pair_error = None
        try:
            success = await host.pair_device(address, protocol, name)
            self.last_pair_error = host.last_pair_error
            if success:
                await host.cleanup()
                return True
            await host.cleanup()
            return False
        except Exception:
            await host.cleanup()
            raise

    async def disconnect(self):
        """Drop the active connection; daemon keeps running and will reconnect."""
        if self.host:
            disconnected = await self.host.disconnect_all()
        else:
            disconnected = False
        if not disconnected:
            logger.info("No active connection to disconnect")
        if self._host_task and not self._host_task.done():
            self._host_task.cancel()

    async def resume(self, reason=None):
        """Resume connections after scan/pair."""
        async with self._lifecycle_lock:
            if self._power_blocked and reason != "power":
                if reason == "user" or self._suspend_reason != "manual":
                    self._resume_after_power = True
                    self._resume_after_power_reason = reason
                logger.info(
                    f"Resume deferred during WMT/Wi-Fi recovery"
                    f"{f' ({reason})' if reason else ''}"
                )
                return

            if reason == "power":
                self._power_blocked = False
                if not self._suspended:
                    self._resume_after_power = False
                    return
                if self._suspend_reason != "power":
                    if (
                        self._resume_after_power
                        and (
                            self._suspend_reason != "manual"
                            or self._resume_after_power_reason == "user"
                        )
                    ):
                        logger.info("Power recovery complete; applying deferred resume")
                    else:
                        logger.info(
                            f"Power resume ignored; daemon suspended by "
                            f"{self._suspend_reason}"
                        )
                        self._resume_after_power = False
                        self._resume_after_power_reason = None
                        return
            elif not self._suspended:
                return
            logger.info(
                f"Daemon resuming"
                f"{f' ({reason})' if reason else ''}..."
            )
            self._suspended = False
            self._suspend_reason = None
            self._resume_after_power = False
            self._resume_after_power_reason = None
            self._resume_event.set()

    async def handle_power_event(self, event: str):
        """Suspend/resume around Kindle power lifecycle events."""
        if event in ("readyToSuspend", "suspending"):
            if self._power_resume_task and not self._power_resume_task.done():
                self._power_resume_task.cancel()
            await self.suspend(reason="power")
            return

        if event not in ("wakeupFromSuspend", "resuming", "outOfScreenSaver"):
            return

        if self._power_resume_task and not self._power_resume_task.done():
            return
        self._power_resume_task = asyncio.create_task(
            self._delayed_power_resume(),
            name="power_resume_delay",
        )

    async def _delayed_power_resume(self):
        delay = config.power_resume_delay
        if delay > 0:
            logger.info(f"Power resume: waiting {delay:.0f}s for WMT/Wi-Fi")
            try:
                await asyncio.sleep(delay)
            except asyncio.CancelledError:
                return
        await self.resume(reason="power")

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
                if not self.running:
                    break
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

            if self._suspended:
                continue

            if not skip_delay:
                logger.info(f"Reconnecting in {config.reconnect_delay}s...")
                try:
                    await asyncio.wait_for(
                        self._resume_event.wait(),
                        timeout=config.reconnect_delay
                    )
                    self._resume_event.clear()
                except asyncio.TimeoutError:
                    pass

        logger.info("Daemon stopped")

    async def stop(self):
        """Stop the daemon."""
        logger.info("Stopping...")
        self.running = False
        if self._power_resume_task and not self._power_resume_task.done():
            self._power_resume_task.cancel()
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

    log.info(f"Kindle HID Passthrough v{get_version()} (daemon)")
    power_monitor = KindlePowerEventMonitor(
        daemon.handle_power_event,
        enabled=config.power_monitor_enabled,
    )
    power_monitor.start()

    if config.power_startup_delay > 0:
        logger.info(
            f"Startup: waiting {config.power_startup_delay:.0f}s for WMT/Wi-Fi"
        )
        await asyncio.sleep(config.power_startup_delay)

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

    await power_monitor.stop()
    server.shutdown()
    logger.info("Daemon stopped")


if __name__ == '__main__':
    asyncio.run(main())
