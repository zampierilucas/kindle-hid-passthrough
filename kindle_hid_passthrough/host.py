#!/usr/bin/env python3
"""HID Host — runs BLE + Classic handlers on a single Bumble device."""

import asyncio
from dataclasses import dataclass
from typing import List, Optional

from bumble.core import InvalidStateError
from bumble.hci import HCI_LE_SET_PRIVACY_MODE_COMMAND, HCI_LE_Set_Privacy_Mode_Command, HCI_Write_Class_Of_Device_Command, HCI_Write_Local_Name_Command

from ble import BLEMixin
from bt_setup import ensure_uhid
from classic import ClassicMixin
from config import Protocol, clean_device_name, config, get_version, normalize_addr
from device_cache import DeviceCache
from logging_utils import log
from pairing import create_keystore, create_pairing_config
from transport import create_bumble_device
from uhid_handler import Bus, UHIDDevice, descriptor_is_pointer, sanitize_digitizer

__all__ = ['HIDHost']


@dataclass
class DeviceConfig:
    """Device configuration from devices.conf."""
    address: str
    protocol: Protocol
    name: Optional[str] = None


class DeviceSession:
    """Live state for one connected device, keyed by normalized address."""

    def __init__(self, address: str, protocol: Protocol, connection):
        self.address = address
        self.raw_address = str(connection.peer_address)
        self.protocol = protocol
        self.connection = connection
        self.peer = None
        self.channels = None
        self.name = None
        self.report_map: Optional[bytes] = None
        self.hid_reports = []
        self.uhid_device = None
        self.is_pointer = False
        self.last_report = None
        self.setup_task = None
        self.closed = False
        self.teardown_done = asyncio.Event()
        self.auth_failure = False
        self.vc_unplug = False

    def is_alive(self) -> bool:
        conn = self.connection
        if conn is None:
            return False
        if not hasattr(conn, 'handle') or conn.handle is None:
            return False
        if getattr(conn, 'is_disconnected', False):
            return False
        return True

    def state_dict(self) -> dict:
        entry = {
            "address": self.address,
            "protocol": self.protocol.value,
            "name": self.name,
            "hid_ready": self.uhid_device is not None,
        }
        if self.uhid_device:
            entry["uhid_name"] = self.uhid_device.name
            if self.uhid_device.input_paths:
                entry["input_paths"] = self.uhid_device.input_paths
        if self.report_map:
            entry["descriptor_size"] = len(self.report_map)
        return entry

    async def cleanup(self):
        """Idempotent release of session-owned resources."""
        if self.closed:
            await self.teardown_done.wait()
            return
        self.closed = True
        try:
            if self.uhid_device:
                try:
                    self.uhid_device.destroy()
                except Exception:
                    pass
                self.uhid_device = None
            if self.channels:
                if self.is_alive():
                    await self.channels.disconnect()
                self.channels = None
            if self.is_alive():
                try:
                    await asyncio.wait_for(self.connection.disconnect(), timeout=2.0)
                except asyncio.TimeoutError:
                    log.warning(f"Disconnect timed out for {self.address}")
                except Exception as e:
                    log.debug(f"Disconnect cleanup: {e}")
            self.connection = None
            self.peer = None
        finally:
            self.teardown_done.set()


class HIDHost(ClassicMixin, BLEMixin):
    """HID Host supporting both BLE and Classic Bluetooth.

    Protocol-specific handlers live in ClassicMixin and BLEMixin.
    This class owns init, start, run, sessions, pairing dispatch, and cleanup.
    """

    PROTOCOL_NAME = "HID"

    ACTIVE_DELAY = 2.0
    ACTIVE_RETRY_INTERVAL = 5.0
    ACTIVE_RETRY_INTERVAL_CONNECTED = 60.0
    ACTIVE_CONNECT_TIMEOUT = 10
    FIRST_SESSION_TIMEOUT = 60.0
    SETUP_TIMEOUT = 45.0

    def __init__(self, transport_spec: str = None):
        self.transport_spec = transport_spec or config.transport
        self.transport = None
        self.device = None

        self.sessions = {}
        self._pairing_session = None
        self._classic_psm_registered = False

        self._connection_tasks: set = set()

        self.classic_devices: List[DeviceConfig] = []
        self.ble_devices: List[DeviceConfig] = []
        self._keystore_addresses: set = set()
        self._keystore_address_types: dict = {}

        self.keystore = create_keystore(config.pairing_keys_file)
        self.device_cache = DeviceCache(config.cache_dir)

        # Set by the daemon: called with True when the first pointer device
        # gets its UHID device, False when the last goes away (drives the cursor).
        self.on_pointer_change = None

        self._sessions_changed = None
        self._radio_lock = None

    @property
    def connection_state(self) -> dict:
        """Current connection state as a dict for API consumers."""
        connections = [s.state_dict() for s in list(self.sessions.values())
                       if s.is_alive()]
        return {"connected": bool(connections), "connections": connections}

    def _parse_devices(self):
        """Parse devices from config and group by protocol."""
        devices = config.get_all_devices()
        self.classic_devices = []
        self.ble_devices = []

        for addr, protocol, name in devices:
            dev = DeviceConfig(address=addr, protocol=protocol, name=name)
            if protocol == Protocol.CLASSIC:
                self.classic_devices.append(dev)
            else:
                self.ble_devices.append(dev)

        log.info(f"Devices: {len(self.classic_devices)} Classic, {len(self.ble_devices)} BLE")

    async def start(self, pairing: bool = False):
        """Initialize the Bumble device with both protocols."""
        log.info(f"HID Host v{get_version()}")

        def configure(device):
            device.classic_enabled = bool(self.classic_devices)
            device.le_enabled = bool(self.ble_devices)
            if pairing:
                # No inbound links while pairing; run mode re-enables page scan.
                device.connectable = False
                device.discoverable = False
            device.keystore = self.keystore
            device.pairing_config_factory = create_pairing_config
            if self.classic_devices:
                device.classic_ssp_enabled = True
                device.classic_sc_enabled = True

        self.transport, self.device = await create_bumble_device(
            self.transport_spec, configure=configure)

        if self.device.address_resolution_offload:
            await self._set_device_privacy_modes()
            log.info("Controller address resolution enabled")

        # Classic-specific setup
        if self.classic_devices:
            class_of_device = 0x000104  # Computer/Desktop
            await self.device.host.send_command(
                HCI_Write_Class_Of_Device_Command(class_of_device=class_of_device),
                check_result=True
            )
            log.info(f"Classic enabled: CoD 0x{class_of_device:06X}")

            local_name_bytes = config.device_name.encode('utf-8') + b'\x00'
            await self.device.host.send_command(
                HCI_Write_Local_Name_Command(local_name=local_name_bytes),
                check_result=True
            )

        if self.ble_devices:
            log.info("BLE enabled")

        # Load keystore addresses
        await self._load_keystore_addresses()


    async def _set_device_privacy_modes(self):
        """Keep bonded peers visible when they advertise with their
        identity address instead of an RPA."""
        if not self.device.host.supports_command(HCI_LE_SET_PRIVACY_MODE_COMMAND):
            return
        for _, address in await self.keystore.get_resolving_keys():
            try:
                await self.device.send_command(
                    HCI_LE_Set_Privacy_Mode_Command(
                        peer_identity_address_type=address.address_type,
                        peer_identity_address=address,
                        privacy_mode=HCI_LE_Set_Privacy_Mode_Command.PrivacyMode.DEVICE_PRIVACY_MODE,
                    ), check_result=True)
            except Exception as e:
                log.warning(f"Privacy mode for {address}: {e}")

    async def _load_keystore_addresses(self):
        """Load addresses from keystore for connection filtering."""
        self._keystore_addresses = set()
        self._keystore_address_types = {}
        if self.keystore:
            try:
                keys = await self.keystore.get_all()
                if keys:
                    for entry in keys:
                        addr = str(entry[0]) if isinstance(entry, (list, tuple)) else str(entry)
                        self._keystore_addresses.add(normalize_addr(addr))
                        pairing_keys = entry[1] if isinstance(entry, (list, tuple)) and len(entry) > 1 else None
                        if pairing_keys is not None and pairing_keys.address_type is not None:
                            self._keystore_address_types[normalize_addr(addr)] = pairing_keys.address_type
                    log.info(f"Keystore has {len(self._keystore_addresses)} entries")
            except Exception as e:
                log.warning(f"Failed to load keystore: {e}")

    def _configured_name(self, addr: str) -> Optional[str]:
        """Return the configured devices.conf name for addr, if any."""
        if not addr:
            return None
        norm = normalize_addr(addr)
        for dev in self.classic_devices + self.ble_devices:
            if normalize_addr(dev.address) == norm and dev.name:
                return dev.name
        return None

    def _format_device(self, addr: str) -> str:
        """Format device address with name if available."""
        name = self._configured_name(addr)
        return f"{name} ({addr})" if name else addr

    async def run(self):
        """Main run loop - serve all configured devices concurrently."""
        self._sessions_changed = asyncio.Event()
        self._radio_lock = asyncio.Lock()

        self._parse_devices()
        await self.start()

        for dev in self.classic_devices + self.ble_devices:
            if dev.address != '*':
                cache = self.device_cache.load(dev.address)
                if cache and 'report_map' in cache:
                    log.info(f"Cached descriptor for {self._format_device(dev.address)}")

        await self._serve()

    async def _serve(self):
        """Run the protocol handlers and watchdog until failure or cancel."""
        tasks = []

        if self.classic_devices:
            tasks.append(asyncio.create_task(
                self._run_classic_handler(),
                name="classic_handler"
            ))

        if self.ble_devices:
            tasks.append(asyncio.create_task(
                self._run_ble_handler(),
                name="ble_handler"
            ))

        if not tasks:
            log.error("No devices configured")
            return

        log.info(f"Serving devices (Classic: {len(self.classic_devices)}, BLE: {len(self.ble_devices)})")

        tasks.append(asyncio.create_task(
            self._session_watchdog(), name="session_watchdog"))

        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in done:
                task.result()
            raise InvalidStateError(
                f"{next(iter(done)).get_name()} exited unexpectedly")
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except (asyncio.CancelledError, Exception):
                        pass

    async def _session_watchdog(self):
        """Ask the daemon for a transport rebuild if nothing ever connects.

        Once a device has connected, an empty session set is a device that
        went to sleep, not a broken transport: the handlers keep initiating
        on the open radio, so rebuilding would only make us deaf for a while.
        """
        had_session = False
        while True:
            self._sessions_changed.clear()
            if self.sessions or had_session:
                had_session = True
                await self._sessions_changed.wait()
                continue
            try:
                await asyncio.wait_for(
                    self._sessions_changed.wait(),
                    timeout=self.FIRST_SESSION_TIMEOUT)
            except asyncio.TimeoutError:
                log.warning("Connection timeout - no device connected")
                raise InvalidStateError("No device connected within timeout")

    def _notify_sessions_changed(self):
        if self._sessions_changed:
            self._sessions_changed.set()

    def _track_task(self, task):
        self._connection_tasks.add(task)
        task.add_done_callback(self._connection_tasks.discard)
        return task

    # ==================== SESSIONS ====================

    def _new_session(self, address: str, protocol: Protocol, connection) -> DeviceSession:
        """Session factory for the protocol mixins (avoids circular imports)."""
        return DeviceSession(address, protocol, connection)

    def _register_session(self, session: DeviceSession):
        self.sessions[session.address] = session
        self._notify_sessions_changed()
        session.connection.on(
            'disconnection',
            lambda reason: self._on_session_disconnection(session, reason))

    async def _reject_connection(self, connection):
        try:
            await connection.disconnect()
        except Exception:
            pass

    def _on_session_disconnection(self, session: DeviceSession, reason):
        proto = session.protocol.value.upper()
        log.warning(f"[{proto}] Device disconnected: {session.address} (reason={reason})")

        if reason == 5 and session.protocol == Protocol.CLASSIC:
            log.info("[Classic] Authentication failure - will clear stale key and retry")
            session.auth_failure = True

        self._track_task(asyncio.create_task(self._teardown_session(session)))

    async def _run_session_setup(self, session: DeviceSession, setup):
        """Drive a session's HID setup, tearing it down on failure."""
        try:
            await asyncio.wait_for(setup, timeout=self.SETUP_TIMEOUT)
        except asyncio.CancelledError:
            raise
        except asyncio.TimeoutError:
            log.warning(f"Setup timed out for {self._format_device(session.address)}")
            await self._teardown_session(session)
        except Exception as e:
            log.warning(f"Setup failed for {self._format_device(session.address)}: {e}")
            await self._teardown_session(session)

    async def _teardown_session(self, session: DeviceSession):
        """End one session and apply its post-disconnect policy."""
        if self.sessions.get(session.address) is session:
            del self.sessions[session.address]
            self._notify_sessions_changed()

        setup = session.setup_task
        if setup and not setup.done() and setup is not asyncio.current_task():
            setup.cancel()
            try:
                await setup
            except (asyncio.CancelledError, Exception):
                pass

        if session.closed:
            await session.teardown_done.wait()
            return
        was_pointer = session.is_pointer and session.uhid_device is not None
        await session.cleanup()
        if was_pointer and self._pointer_count() == 0:
            self._notify_pointer(False)

        if session.auth_failure:
            log.info(f"Auth failure for {session.address}, clearing stale key")
            config.remove_pairing_key(session.address)
        if session.vc_unplug:
            log.info(f"Virtual cable unplugged by {session.address}, removing device")
            config.remove_device(session.address)

        self._parse_devices()
        await self._load_keystore_addresses()

    async def end_session(self, address: str = None):
        """Disconnect one session by address, or all when address is None."""
        if address is None:
            targets = list(self.sessions.values())
        else:
            session = self.sessions.get(normalize_addr(address))
            targets = [session] if session else []
        if not targets:
            log.info("No matching connection to disconnect")
            return
        for session in targets:
            await self._teardown_session(session)

    # ==================== PAIRING ====================

    async def pair_device(self, address: str, protocol: Protocol = None, name: str = None) -> bool:
        """Pair with a device (first-time setup)."""
        if protocol is None:
            protocol = Protocol.BLE

        self._parse_devices()

        bucket = self.classic_devices if protocol == Protocol.CLASSIC else self.ble_devices
        norm = normalize_addr(address)
        if not any(d.address != '*' and normalize_addr(d.address) == norm for d in bucket):
            bucket.append(DeviceConfig(address=address, protocol=protocol, name=name))

        await self.start(pairing=True)

        if protocol == Protocol.CLASSIC:
            return await self._pair_classic(address)
        else:
            return await self._pair_ble(address)

    async def continue_after_pairing(self):
        """Serve all configured devices, adopting the paired session."""
        session = self._pairing_session
        if not session:
            raise InvalidStateError("No paired device - call pair_device first")
        self._pairing_session = None

        self._sessions_changed = asyncio.Event()
        self._radio_lock = asyncio.Lock()

        if session.is_alive():
            self._register_session(session)
            if session.protocol == Protocol.CLASSIC:
                await self._continue_classic_after_pairing(session)
            else:
                await self._continue_ble_after_pairing(session)
            proto_name = session.protocol.value.upper()
            log.success(f"\n[{proto_name}] Paired and receiving HID reports.")
        else:
            log.info("Paired device disconnected; the connect loops will pick it up")

        self._parse_devices()
        await self._load_keystore_addresses()
        await self._serve()

    # ==================== COMMON ====================

    def _forward_report(self, session: DeviceSession, data: bytes):
        """Deduplicate the log line and forward an HID report to UHID."""
        if data != session.last_report:
            log.debug(f"Report: {data.hex()}")
            session.last_report = data
        if session.uhid_device:
            try:
                session.uhid_device.send_input(data)
            except Exception as e:
                log.warning(f"UHID send failed: {e}")

    def _load_cached_descriptor(self, session: DeviceSession) -> bool:
        """Load report descriptor and device name from cache. Returns True if found."""
        cache = self.device_cache.load(session.address) or \
            self.device_cache.load(session.raw_address)
        if cache and 'report_map' in cache:
            session.report_map = bytes.fromhex(cache['report_map'])
            session.name = clean_device_name(cache.get('device_name') or '') or None
            log.success(f"Loaded cached descriptor ({len(session.report_map)} bytes)")
            return True
        return False

    def _create_uhid_device(self, session: DeviceSession):
        """Create UHID virtual device."""
        if not session.report_map:
            log.warning("No report descriptor for UHID")
            return

        if not ensure_uhid():
            log.error("uhid unavailable; connected device will have no input path")
            return

        try:
            name = self._configured_name(session.address) or session.name or "HID Device"
            descriptor = sanitize_digitizer(session.report_map)
            session.uhid_device = UHIDDevice(
                name=name,
                report_descriptor=descriptor,
                bus=Bus.BLUETOOTH,
                vendor=0,
                product=0,
                uniq=session.address,
            )
            log.success(f"UHID device created: {name}")
            asyncio.get_event_loop().call_later(
                0.5, session.uhid_device.discover_input_paths)
            session.is_pointer = descriptor_is_pointer(descriptor)
            if session.is_pointer:
                log.info("Pointer device: cursor overlay on")
                if self._pointer_count() == 1:
                    self._notify_pointer(True)
        except Exception as e:
            log.error(f"Failed to create UHID device: {e}")

    def _pointer_count(self) -> int:
        return sum(1 for s in self.sessions.values()
                   if s.is_pointer and s.uhid_device)

    def _notify_pointer(self, active: bool):
        """Tell the daemon a pointer device appeared/left, so it can toggle the cursor."""
        if not self.on_pointer_change:
            return
        try:
            self.on_pointer_change(active)
        except Exception as e:
            log.warning(f"cursor hook failed: {e}")

    async def cleanup(self):
        """Clean up resources."""
        if self._connection_tasks:
            pending = list(self._connection_tasks)
            for task in pending:
                if not task.done():
                    task.cancel()
            try:
                await asyncio.gather(*pending, return_exceptions=True)
            except Exception:
                pass
            self._connection_tasks.clear()

        had_pointer = self._pointer_count() > 0
        for session in list(self.sessions.values()):
            self.sessions.pop(session.address, None)
            try:
                await session.cleanup()
            except Exception:
                pass
        if had_pointer:
            self._notify_pointer(False)

        if self._pairing_session:
            try:
                await self._pairing_session.cleanup()
            except Exception:
                pass
            self._pairing_session = None

        if hasattr(self, '_classic_connection_listener') and self._classic_connection_listener:
            try:
                self.device.remove_listener('connection', self._classic_connection_listener)
            except Exception:
                pass
            self._classic_connection_listener = None

        if self.transport:
            try:
                await asyncio.wait_for(self.transport.close(), timeout=3.0)
            except asyncio.TimeoutError:
                log.warning("Transport close timed out, fd may leak")
            except Exception:
                pass
            self.transport = None
            from bt_setup import chip
            chip().on_transport_close()
