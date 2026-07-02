#!/usr/bin/env python3
"""
Daemon Controller - Coordination layer between HTTP thread and async daemon.

Provides thread-safe access to daemon operations (scan, pair, connect,
disconnect) from the HTTP server thread via asyncio.run_coroutine_threadsafe().
"""

import asyncio
import logging
import os
import threading

from config import Protocol, config, normalize_addr
from device_cache import DeviceCache

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
        self._scan_stop_event = None

        # Pair state
        self.pair_result = None
        self.is_pairing = False

        # Device list cache (mtime-based)
        self._devices_cache = None
        self._devices_mtime = 0
        self._devices_lock = threading.Lock()

    def get_status(self) -> dict:
        """Thread-safe read of daemon state. Called from HTTP thread."""
        devices = self._get_devices_cached()

        status = {
            "daemon_running": self.daemon.running and not self.daemon._suspended,
            "devices": devices,
            "device_count": len(devices),
            "scanning": self.is_scanning,
            "pairing": self.is_pairing,
        }

        conn = self.daemon.connection_state
        if conn.get("connected"):
            if conn.get("connections"):
                status["connections"] = conn["connections"]
            status["connected_device"] = conn.get("address")
            status["connected_protocol"] = conn.get("protocol")
            status["connected_name"] = conn.get("name")
            if conn.get("uhid_name"):
                status["uhid_name"] = conn["uhid_name"]
            if conn.get("input_paths"):
                status["input_paths"] = conn["input_paths"]
            if conn.get("descriptor_size"):
                status["descriptor_size"] = conn["descriptor_size"]

        return status

    def _get_devices_cached(self) -> list:
        """Device list from devices.conf, cached by file mtime."""
        try:
            mtime = os.path.getmtime(config.devices_config_file)
        except OSError:
            mtime = 0

        with self._devices_lock:
            if self._devices_cache is not None and mtime == self._devices_mtime:
                return self._devices_cache

            devices = config.get_all_devices()
            self._devices_cache = [
                {
                    "address": addr,
                    "protocol": proto.value,
                    **({"name": name} if name else {}),
                }
                for addr, proto, name in devices
            ]
            self._devices_mtime = mtime
            return self._devices_cache

    # ---- Scan ----

    def request_scan(self):
        """From HTTP thread: schedule scan on event loop."""
        if self.is_scanning:
            return
        self.scan_result = None
        self.is_scanning = True
        self._scan_stop_event = asyncio.Event()
        asyncio.run_coroutine_threadsafe(self._do_scan(), self.loop)

    def request_scan_stop(self):
        """Ask an in-flight scan to stop early."""
        if self._scan_stop_event:
            self._scan_stop_event.set()

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
            self._scan_live_devices = []
            try:
                await self.daemon.suspend(reason="operation")
                config.validate_keystore()

                await self.daemon.scan(
                    duration=10.0,
                    on_device_found=self._on_device_found,
                    stop_event=self._scan_stop_event,
                )
                self.scan_result = {
                    "ok": True,
                    "devices": self._scan_live_devices,
                }
            except Exception as e:
                logger.error(f"Scan failed: {e}")
                self.scan_result = {"ok": False, "error": str(e)}
            finally:
                self.is_scanning = False
                self._scan_stop_event = None
                await self.daemon.resume(reason="operation")

    # ---- Pair ----

    def request_pair(self, address, protocol, name=None):
        """From HTTP thread: schedule pair on event loop."""
        if self.is_pairing:
            return
        self.pair_result = None
        self.is_pairing = True
        asyncio.run_coroutine_threadsafe(
            self._do_pair(address, protocol, name), self.loop
        )

    async def _do_pair(self, address, protocol, name):
        async with self._op_lock:
            try:
                await self.daemon.suspend(reason="operation")
                config.validate_keystore()

                success = await self.daemon.pair(address, protocol, name)
                if success:
                    config.add_device(address, protocol, name)
                error = self.daemon.last_pair_error or "Pairing failed"
                self.pair_result = {
                    "ok": success,
                    "address": address,
                    **({"message": "Paired successfully"} if success
                       else {"error": error}),
                }
            except Exception as e:
                error = str(e) or repr(e)
                logger.error(f"Pair failed: {error}")
                self.pair_result = {"ok": False, "address": address, "error": error}
            finally:
                self.is_pairing = False
                await self.daemon.resume(reason="operation")

    # ---- Connect / Resume ----

    def request_connect(self, address=None, protocol_str=None):
        """From HTTP thread: connect to a device or resume the daemon.

        With address: suspend → save device to config → resume.
        Without address: just resume if suspended (used by /start).
        """
        if not address:
            asyncio.run_coroutine_threadsafe(self._do_resume(), self.loop)
            return

        protocol = Protocol.CLASSIC if protocol_str == 'classic' else Protocol.BLE
        asyncio.run_coroutine_threadsafe(
            self._do_connect(address, protocol), self.loop
        )

    async def _do_resume(self):
        async with self._op_lock:
            if self.daemon._suspended:
                await self.daemon.resume(reason="user")

    async def _do_connect(self, address, protocol):
        async with self._op_lock:
            try:
                await self.daemon.suspend(reason="operation")
                config.add_device(address, protocol)
                await self.daemon.resume(reason="operation")
            except Exception as e:
                logger.error(f"Connect failed: {e}")
                await self.daemon.resume(reason="operation")

    # ---- Remove ----

    def request_remove(self, address: str) -> dict:
        """Remove a device from config, clear its cache, and disconnect."""
        result = config.remove_device(address)
        if result["removed"]:
            DeviceCache(config.cache_dir).clear(normalize_addr(address))
            self.request_disconnect()
        return result

    # ---- Clear Cache ----

    def request_clear_cache(self) -> int:
        """Clear all descriptor cache files. Returns count of files removed."""
        return DeviceCache(config.cache_dir).clear()

    # ---- Disconnect / Stop ----

    def request_disconnect(self, suspend=False):
        """From HTTP thread: drop connection.

        suspend=False: drop connection, daemon keeps running (reconnect loop).
        suspend=True:  suspend daemon entirely (/stop).
        """
        asyncio.run_coroutine_threadsafe(
            self._do_disconnect(suspend), self.loop
        )

    async def _do_disconnect(self, suspend):
        async with self._op_lock:
            try:
                if suspend:
                    await self.daemon.suspend(reason="manual")
                else:
                    await self.daemon.disconnect()
            except Exception as e:
                logger.error(f"Disconnect failed: {e}")
