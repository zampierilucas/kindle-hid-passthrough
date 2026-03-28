#!/usr/bin/env python3
"""
Daemon Controller - Coordination layer between HTTP thread and async daemon.

Provides thread-safe access to daemon operations (scan, pair, connect,
disconnect) from the HTTP server thread via asyncio.run_coroutine_threadsafe().
"""

import asyncio
import logging

from config import Protocol, config, normalize_addr
from host import HIDHost
from scanner import Scanner

logger = logging.getLogger(__name__)

__all__ = ['DaemonController']


class DaemonController:
    """Coordinates between the HTTP server thread and the async daemon.

    All request_* methods are called from the HTTP thread and schedule
    coroutines on the daemon's event loop via run_coroutine_threadsafe().
    """

    def __init__(self, daemon):
        self.daemon = daemon
        self.loop = None  # Set when event loop starts

        self._op_lock = asyncio.Lock()

        # Scan state
        self.scan_result = None
        self.is_scanning = False
        self._scan_live_devices = []

        # Pair state
        self.pair_result = None
        self.is_pairing = False

    def get_status(self) -> dict:
        """Thread-safe read of daemon state. Called from HTTP thread."""
        status = {
            "daemon_running": self.daemon.running and not self.daemon._suspended,
        }

        conn = self.daemon.connection_state
        if conn.get("connected"):
            status["connected_device"] = conn.get("address")
            status["connected_protocol"] = conn.get("protocol")
            status["connected_name"] = conn.get("name")

        status["scanning"] = self.is_scanning
        status["pairing"] = self.is_pairing

        return status

    # ---- Scan ----

    def request_scan(self):
        """From HTTP thread: schedule scan on event loop."""
        if self.is_scanning:
            return
        self.scan_result = None
        asyncio.run_coroutine_threadsafe(self._do_scan(), self.loop)

    def _on_device_found(self, device):
        """Callback from scanner when a device is discovered."""
        self._scan_live_devices.append({
            "address": device.address,
            "name": device.name,
            "protocol": device.protocol.value,
            "rssi": device.rssi,
        })

    async def _do_scan(self):
        async with self._op_lock:
            self.is_scanning = True
            self._scan_live_devices = []
            try:
                await self.daemon.suspend()
                config.validate_keystore()

                scanner = Scanner()
                scanner.on_device_found = self._on_device_found
                await scanner.start()
                devices = await scanner.scan(duration=10.0)
                await scanner.cleanup()

                self.scan_result = {
                    "ok": True,
                    "devices": self._scan_live_devices,
                }
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                self.scan_result = {"ok": False, "error": str(e)}
            finally:
                self.is_scanning = False
                await self.daemon.resume()

    # ---- Pair ----

    def request_pair(self, address, protocol, name=None):
        """From HTTP thread: schedule pair on event loop."""
        if self.is_pairing:
            return
        self.pair_result = None
        asyncio.run_coroutine_threadsafe(
            self._do_pair(address, protocol, name), self.loop
        )

    async def _do_pair(self, address, protocol, name):
        async with self._op_lock:
            self.is_pairing = True
            try:
                await self.daemon.suspend()
                config.validate_keystore()

                host = HIDHost()
                try:
                    success = await host.pair_device(address, protocol)
                    if success:
                        config.add_device(address, protocol, name)
                        self.pair_result = {
                            "ok": True,
                            "address": address,
                            "message": "Paired successfully",
                        }
                    else:
                        self.pair_result = {
                            "ok": False,
                            "address": address,
                            "error": "Pairing failed",
                        }
                finally:
                    await host.cleanup()
            except Exception as e:
                logger.error(f"Pair failed: {e}")
                self.pair_result = {
                    "ok": False,
                    "address": address,
                    "error": str(e),
                }
            finally:
                self.is_pairing = False
                await self.daemon.resume()

    # ---- Connect ----

    def request_connect(self, address, protocol_str):
        """From HTTP thread: schedule connect on event loop.

        Suspends daemon, saves device to config if needed, then resumes
        so the daemon reconnects to the specified device.
        """
        protocol = Protocol.CLASSIC if protocol_str == 'classic' else Protocol.BLE
        asyncio.run_coroutine_threadsafe(
            self._do_connect(address, protocol), self.loop
        )

    async def _do_connect(self, address, protocol):
        async with self._op_lock:
            try:
                await self.daemon.suspend()
                # Add device to config if not already there
                config.add_device(address, protocol)
                await self.daemon.resume()
            except Exception as e:
                logger.error(f"Connect failed: {e}")
                await self.daemon.resume()

    # ---- Resume (for /start endpoint) ----

    def request_connect_resume(self):
        """From HTTP thread: resume daemon if suspended."""
        if self.daemon._suspended:
            asyncio.run_coroutine_threadsafe(self.daemon.resume(), self.loop)

    # ---- Disconnect ----

    def request_disconnect(self):
        """From HTTP thread: suspend daemon (disconnects current device)."""
        asyncio.run_coroutine_threadsafe(self._do_disconnect(), self.loop)

    async def _do_disconnect(self):
        async with self._op_lock:
            try:
                await self.daemon.suspend()
            except Exception as e:
                logger.error(f"Disconnect failed: {e}")
