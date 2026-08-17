#!/usr/bin/env python3
"""
Daemon Controller - Coordination layer between HTTP thread and async daemon.

Provides thread-safe access to daemon operations (scan, pair, connect,
disconnect) from the HTTP server thread via asyncio.run_coroutine_threadsafe().
"""

import asyncio
import logging
import os
import subprocess
import threading

from bt_setup import chip
from config import Protocol, config, normalize_addr
from device_cache import DeviceCache
from logging_utils import errstr

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
        self._suspended_by_system = False

        # Scan state
        self.scan_result = None
        self.is_scanning = False
        self._scan_live_devices = []

        # Pair state
        self.pair_result = None
        self.is_pairing = False

        # Device list cache (mtime-based)
        self._devices_cache = None
        self._devices_mtime = 0
        self._devices_lock = threading.Lock()

        # Mouse cursor overlay process
        self._cursor_proc = None
        self._cursor_lock = threading.Lock()

    def get_status(self) -> dict:
        """Thread-safe read of daemon state. Called from HTTP thread."""
        devices = self._get_devices_cached()

        status = {
            "daemon_running": self.daemon.running and not self.daemon._suspended,
            "devices": devices,
            "device_count": len(devices),
            "scanning": self.is_scanning,
            "pairing": self.is_pairing,
            "cursor_running": self.cursor_running(),
        }

        conn = self.daemon.connection_state
        status["connections"] = conn.get("connections", [])

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

                # Re-warm the chip if a prior /stop powered it off; opening the
                # transport against a cold chip makes HCI Reset time out.
                chip().ensure_powered()

                await self.daemon.scan(
                    duration=10.0,
                    on_device_found=self._on_device_found,
                )
                self.scan_result = {
                    "ok": True,
                    "devices": self._scan_live_devices,
                }
            except Exception as e:
                logger.error(f"Scan failed: {errstr(e)}")
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
        self.is_pairing = True  # Set immediately so status polls see it
        asyncio.run_coroutine_threadsafe(
            self._do_pair(address, protocol, name), self.loop
        )

    async def _do_pair(self, address, protocol, name):
        async with self._op_lock:
            try:
                await self.daemon.suspend()
                config.validate_keystore()

                # Re-warm the chip if a prior /stop powered it off; opening the
                # transport against a cold chip makes HCI Reset time out.
                chip().ensure_powered()

                success = await self.daemon.pair(address, protocol, name)
                if success:
                    config.add_device(address, protocol, name)
                self.pair_result = {
                    "ok": success,
                    "address": address,
                    **({"message": "Paired successfully"} if success
                       else {"error": "Pairing failed"}),
                }
            except Exception as e:
                logger.error(f"Pair failed: {errstr(e)}")
                self.pair_result = {"ok": False, "address": address, "error": str(e)}
            finally:
                self.is_pairing = False
                await self.daemon.resume()

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
            self._suspended_by_system = False
            if self.daemon._suspended:
                await self.daemon.resume()

    async def _do_connect(self, address, protocol):
        async with self._op_lock:
            try:
                await self.daemon.suspend()
                config.add_device(address, protocol)
                await self.daemon.resume()
            except Exception as e:
                logger.error(f"Connect failed: {errstr(e)}")
                await self.daemon.resume()

    # ---- System suspend (powerd) ----

    def on_system_suspend(self, event):
        """From power monitor thread: BT off before the system sleeps."""
        asyncio.run_coroutine_threadsafe(self._do_system_suspend(event), self.loop)

    async def _do_system_suspend(self, event):
        async with self._op_lock:
            keeps_radio = chip().survives_suspend
            # A chip that outlives the screensaver keeps serving the remote
            # with the screen off; only a real suspend has to detach, and it
            # must, or the peer holds a dead link and stops page scanning.
            if keeps_radio and event != 'readyToSuspend':
                return
            if self.daemon._suspended:
                return
            logger.info(f"System suspend ({event}): releasing BT")
            self._suspended_by_system = True
            await self.daemon.suspend()
            if not keeps_radio:
                chip().power_off()

    def on_system_resume(self, event):
        """From power monitor thread: re-warm BT after wake."""
        asyncio.run_coroutine_threadsafe(self._do_system_resume(event), self.loop)

    async def _do_system_resume(self, event):
        async with self._op_lock:
            if not self._suspended_by_system:
                return
            self._suspended_by_system = False
            if not self.daemon._suspended:
                return
            logger.info(f"System resume ({event}): restarting BT")
            await self.daemon.resume()

    # ---- Remove ----

    def request_remove(self, address: str) -> dict:
        """Remove a device from config, clear its cache, and disconnect it."""
        result = config.remove_device(address)
        if result["removed"]:
            DeviceCache(config.cache_dir).clear(normalize_addr(address))
            self.request_disconnect(address=address)
        return result

    # ---- Clear Cache ----

    def request_clear_cache(self) -> int:
        """Clear all descriptor cache files. Returns count of files removed."""
        return DeviceCache(config.cache_dir).clear()

    # ---- Mouse Cursor Overlay ----

    def cursor_running(self) -> bool:
        with self._cursor_lock:
            return self._cursor_proc is not None and self._cursor_proc.poll() is None

    def request_cursor_start(self):
        """Launch the mousecursor overlay binary (driven by pointer connect)."""
        with self._cursor_lock:
            if self._cursor_proc is not None and self._cursor_proc.poll() is None:
                return
            # reap any stray overlay (e.g. orphaned by a prior daemon restart)
            subprocess.run(['killall', '-q', 'mousecursor'], capture_output=True)
            binary = os.path.join(config.base_path, 'scripts', 'mousecursor')
            errlog = os.path.join(config.base_path, 'cache', 'mousecursor.log')
            try:
                err = open(errlog, 'ab')
                self._cursor_proc = subprocess.Popen(
                    [binary], stdout=subprocess.DEVNULL, stderr=err)
                logger.info(f"Cursor overlay started (pid {self._cursor_proc.pid})")
            except OSError as e:
                logger.error(f"Cursor overlay failed to launch ({binary}): {e}")
                self._cursor_proc = None

    def request_cursor_stop(self):
        """Kill the mousecursor overlay binary (driven by pointer disconnect)."""
        with self._cursor_lock:
            proc = self._cursor_proc
            self._cursor_proc = None
            if proc is not None and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.wait()
            # safety net: reap any stray/orphaned overlay too
            subprocess.run(['killall', '-q', 'mousecursor'], capture_output=True)

    # ---- Disconnect / Stop ----

    def request_disconnect(self, suspend=False, address=None):
        """From HTTP thread: drop one connection, or all.

        address given: drop that device's session, daemon keeps running.
        address None:  drop every session (reconnect loops bring them back).
        suspend=True:  suspend daemon entirely (/stop).
        """
        asyncio.run_coroutine_threadsafe(
            self._do_disconnect(suspend, address), self.loop
        )

    async def _do_disconnect(self, suspend, address=None):
        async with self._op_lock:
            try:
                if suspend:
                    await self.daemon.suspend()
                    chip().power_off()
                else:
                    await self.daemon.disconnect(address)
            except Exception as e:
                logger.error(f"Disconnect failed: {errstr(e)}")
