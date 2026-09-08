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

# The stock binary the audio bypass swaps out, and where it keeps it. The
# wrapper delegates to .real, so the pair is what "installed" means.
GST_BIN = "/usr/bin/gst-launch-0.10"
GST_REAL_BIN = GST_BIN + ".real"

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
        # HID on/off survives a reboot: /start and /stop write it to disk
        # and boot honours what the user left. It used to always come up on.
        self._bt_enabled = self._load_bt_state()
        # The bypass stops the stock audiomgrd and puts a mock in its place, so
        # it is opt-in and off until asked for: a device where it does not work
        # has to be able to keep its own audio daemon.
        self._audio_enabled = self._load_audio_state()
        if not self._bt_enabled:
            logger.info("HID was left off; daemon starts suspended")
            daemon._suspended = True
        elif self._audio_enabled:
            self._spawn_audio_hack(True)

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

    # ---- Persisted HID state + audio bypass hack ----

    # Shipped location first, development checkout second.
    _AUDIO_HACK_DIRS = ("assets/audio-hack", "teamwork_audio_hack")

    def _bt_state_path(self):
        return os.path.join(config.cache_dir, "bt_enabled")

    def _audio_state_path(self):
        return config.audio_state_file

    def _load_audio_state(self) -> bool:
        """Off unless the user turned it on. Unlike HID, which the daemon
        exists for, the bypass replaces a system daemon and cannot be the
        default on hardware nobody has tested it on."""
        return config.audio_enabled()

    def _persist_audio_state(self, value: bool):
        try:
            os.makedirs(config.cache_dir, exist_ok=True)
            tmp = self._audio_state_path() + ".tmp"
            with open(tmp, "w") as f:
                f.write("1" if value else "0")
            os.replace(tmp, self._audio_state_path())
        except OSError as e:
            logger.warning(f"Could not persist audio_enabled: {errstr(e)}")

    def _load_bt_state(self) -> bool:
        try:
            with open(self._bt_state_path()) as f:
                return f.read().strip() != "0"
        except OSError:
            return True

    def _persist_bt_state(self, value: bool):
        try:
            os.makedirs(config.cache_dir, exist_ok=True)
            tmp = self._bt_state_path() + ".tmp"
            with open(tmp, "w") as f:
                f.write("1" if value else "0")
            os.replace(tmp, self._bt_state_path())
        except OSError as e:
            logger.warning(f"Could not persist bt_enabled: {errstr(e)}")

    def _audio_mock_running(self) -> bool:
        """Whether our LIPC mock is the audiomgrd that is actually up.

        The switch records what the user asked for; this reports what is
        happening. They drifted apart in practice -- the stock daemon came
        back while /status still said the bypass was on -- and an application
        asking audiomgrd for an output then correctly got "none".
        """
        try:
            pids = os.listdir("/proc")
        except OSError:
            return False
        for pid in pids:
            if not pid.isdigit():
                continue
            try:
                with open(f"/proc/{pid}/cmdline", "rb") as f:
                    if b"lipc_audio_mock.lua" in f.read():
                        return True
            except OSError:
                continue
        return False

    def _gst_wrapper_installed(self) -> bool:
        """Whether our gst-launch wrapper is the binary the system will run.

        The mock alone is not the bypass. It answers audioOutputConnected,
        but nothing writes into the FIFO until the wrapper rewrites the
        pipeline's sink, so the reader drains an empty pipe and the sink
        receives silence while every switch still reads as on.
        """
        if not os.path.isfile(GST_REAL_BIN):
            return False
        try:
            with open(GST_BIN, "rb") as f:
                return f.read(2) == b"#!"
        except OSError:
            return False

    def _audio_hack_script(self, enable: bool):
        name = "start_audio_hack.sh" if enable else "stop_audio_hack.sh"
        for d in self._AUDIO_HACK_DIRS:
            path = os.path.join(config.base_path, d, name)
            if os.path.isfile(path):
                return path
        return None

    def _spawn_audio_hack(self, enable: bool):
        """Bring the audio LIPC mock up or down together with HID."""
        threading.Thread(target=self._run_audio_hack, args=(enable,),
                         daemon=True).start()

    def _run_audio_hack(self, enable: bool):
        script = self._audio_hack_script(enable)
        if script is None:
            return
        action, done = ("start", "started") if enable else ("stop", "stopped")
        try:
            proc = subprocess.run(["/bin/sh", script], timeout=30,
                                  stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT)
        except Exception as e:
            logger.warning(f"Audio hack {action} failed: {errstr(e)}")
            return

        # Report what the script actually did. Discarding its output and
        # logging success unconditionally hid a real failure: on a device
        # whose /mnt/us is FUSE the script aborted creating a symlink while
        # the log still said the hack had started.
        if proc.returncode == 0:
            logger.info(f"Audio hack {done}")
            return
        logger.warning(f"Audio hack {action} failed (exit {proc.returncode})")
        output = (proc.stdout or b"").decode("utf-8", "replace")
        for line in output.splitlines():
            if line.strip():
                logger.warning(f"[audio-hack] {line.rstrip()}")

    @property
    def bt_enabled(self) -> bool:
        return self._bt_enabled

    @bt_enabled.setter
    def bt_enabled(self, value):
        value = bool(value)
        changed = value != getattr(self, "_bt_enabled", None)
        self._bt_enabled = value
        if changed:
            self._persist_bt_state(value)
            if self._audio_enabled:
                self._spawn_audio_hack(value)

    @property
    def audio_enabled(self) -> bool:
        return self._audio_enabled

    @property
    def audio_running(self) -> bool:
        """Whether the bypass is actually up, both halves of it."""
        return self._audio_mock_running() and self._gst_wrapper_installed()

    @audio_enabled.setter
    def audio_enabled(self, value):
        value = bool(value)
        changed = value != getattr(self, "_audio_enabled", None)
        self._audio_enabled = value
        if not changed:
            return
        self._persist_audio_state(value)
        # Only touch the stock daemon while HID is on. With HID off there is no
        # Bluetooth sink to route to, and stopping audiomgrd then would leave
        # the device with no audio at all instead of with its own.
        if self._bt_enabled:
            self._spawn_audio_hack(value)

    def get_status(self) -> dict:
        """Thread-safe read of daemon state. Called from HTTP thread."""
        devices = self._get_devices_cached()

        status = {
            "daemon_running": self.bt_enabled and self.daemon.running,
            "devices": devices,
            "device_count": len(devices),
            "scanning": self.is_scanning,
            "pairing": self.is_pairing,
            "cursor_running": self.cursor_running(),
            "audio_enabled": self.audio_enabled,
            "audio_running": self.audio_running,
        }

        conn = self.daemon.connection_state
        status["connections"] = conn.get("connections", [])

        return status

    def request_discoverable(self, duration: float) -> bool:
        """From HTTP thread: open a phone-pairing window on the host."""
        future = asyncio.run_coroutine_threadsafe(
            self._do_discoverable(duration), self.loop)
        try:
            return future.result(timeout=5)
        except Exception as e:
            logger.error(f"Discoverable failed: {errstr(e)}")
            return False

    async def _do_discoverable(self, duration: float) -> bool:
        host = self.daemon.host
        if host is None or self.daemon._suspended:
            return False
        return await host.make_discoverable(duration)

    async def _resume_if_enabled(self):
        """Resume unless BT was toggled off while the op ran."""
        if not self.bt_enabled:
            return
        self._restore_audio_hack_if_needed()
        await self.daemon.resume()

    def _restore_audio_hack_if_needed(self):
        """Put the bypass back if it went away while we were not looking.

        audiomgrd is an upstart job with respawn, so anything that starts it
        keeps it alive and takes the LIPC name with it. An update restores
        the stock gst-launch the same way. The start script is idempotent and
        checks both halves itself, so this costs nothing when the bypass is
        healthy.
        """
        if self._audio_enabled and not self.audio_running:
            logger.info("Audio bypass was down, restoring it")
            self._spawn_audio_hack(True)

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
                await self._resume_if_enabled()

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
                await self._resume_if_enabled()

    # ---- Connect / Resume ----

    def request_connect(self, address=None, protocol_str=None):
        """From HTTP thread: connect to a device or resume the daemon.

        With address: suspend → save device to config → resume.
        Without address: just resume if suspended (used by /start).
        """
        if not address:
            asyncio.run_coroutine_threadsafe(self._do_resume(), self.loop)
            return

        try:
            protocol = Protocol(protocol_str or 'ble')
        except ValueError:
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
                await self._resume_if_enabled()
            except Exception as e:
                logger.error(f"Connect failed: {errstr(e)}")
                await self._resume_if_enabled()

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
            if not self.bt_enabled or not self.daemon._suspended:
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

    def request_set_lights(self, address, on, timeout=5.0):
        """From HTTP thread: toggle player lights. Blocks, unlike the others,
        so the caller can say whether the device got it."""
        future = asyncio.run_coroutine_threadsafe(
            self._do_set_lights(address, on), self.loop
        )
        return future.result(timeout=timeout)

    async def _do_set_lights(self, address, on):
        host = self.daemon.host
        if host is None:
            raise RuntimeError("daemon is not running")
        return host.set_lights(address, on)

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
