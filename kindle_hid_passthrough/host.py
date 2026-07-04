#!/usr/bin/env python3
"""HID Host — runs BLE + Classic handlers on a single Bumble device."""

import asyncio
import time
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import List, Optional

from bumble.core import InvalidStateError
from bumble.hci import HCI_LE_SET_PRIVACY_MODE_COMMAND, HCI_LE_Set_Privacy_Mode_Command, HCI_Write_Class_Of_Device_Command, HCI_Write_Local_Name_Command

from ble import BLEMixin
from classic import ClassicMixin
from config import Protocol, config, get_version, normalize_addr
from device_cache import DeviceCache
from logging_utils import log
from pairing import create_keystore, create_pairing_config
from transport import create_bumble_device
from uhid_handler import Bus, UHIDDevice, strip_digitizer_collections

__all__ = ['HIDHost']


@dataclass
class DeviceConfig:
    """Device configuration from devices.conf."""
    address: str
    protocol: Protocol
    name: Optional[str] = None


@dataclass
class DeviceSession:
    """Finalized connection state for one HID peripheral."""
    protocol: Protocol
    address: str
    connection: object
    peer: object = None
    hid_host: object = None
    device_name: Optional[str] = None
    report_map: Optional[bytes] = None
    hid_reports: list = field(default_factory=list)
    uhid_device: Optional[UHIDDevice] = None
    disconnection_event: Optional[asyncio.Event] = None
    last_report: Optional[bytes] = None
    keyboard_last_keys: tuple = field(default_factory=tuple)
    established_at: float = 0.0


class HIDHost(ClassicMixin, BLEMixin):
    """HID Host supporting both BLE and Classic Bluetooth.

    Protocol-specific handlers live in ClassicMixin and BLEMixin.
    This class owns init, start, run, pairing dispatch, and cleanup.
    """

    PROTOCOL_NAME = "HID"

    ACTIVE_DELAY = 2.0
    ACTIVE_RETRY_INTERVAL = 5.0
    CLASSIC_BACKOFF_POLL_INTERVAL = 30.0
    ACTIVE_CONNECT_TIMEOUT = 10
    CLASSIC_AUTH_RETRY_DELAY = 8.0
    CLASSIC_AUTH_RETRY_DELAY_WITH_PENDING_BLE = 20.0

    # A session that ends this quickly, by the remote's choice, without ever
    # sending input counts as a flap (e.g. a phone whose HID app is closed).
    CLASSIC_FLAP_WINDOW = 30.0
    CLASSIC_FLAP_BACKOFF_BASE = 20.0
    CLASSIC_FLAP_BACKOFF_MAX = 300.0
    # HCI: remote user terminated / low resources / power off
    CLASSIC_REMOTE_DISCONNECT_REASONS = frozenset({0x13, 0x14, 0x15})

    def __init__(self, transport_spec: str = None):
        self.transport_spec = transport_spec or config.transport
        self.transport = None
        self.device = None
        self.connection = None
        self.peer = None

        self.hid_host = None
        self.connected_protocol = None

        self._connection_tasks: set = set()

        self.current_device_address = None
        self.device_name = None
        self.report_map: Optional[bytes] = None
        self.hid_reports = []

        self.classic_devices: List[DeviceConfig] = []
        self.ble_devices: List[DeviceConfig] = []
        self._keystore_addresses: set = set()
        self._keystore_address_types: dict = {}

        self.keystore = create_keystore(config.pairing_keys_file)
        self.device_cache = DeviceCache(config.cache_dir)

        self.uhid_device = None
        self.sessions: dict[Protocol, DeviceSession] = {}
        self._pending_sessions: dict[Protocol, DeviceSession] = {}

        self._disconnection_event = None
        self._connection_future = None
        self._session_setup_lock = None
        self._allow_legacy_connection_state = False
        self._last_report = None
        self._auth_failure_address = None
        self._virtual_cable_unplug_address = None
        self._classic_retry_not_before = 0.0
        self._classic_flap_counts: dict[str, int] = {}
        self._classic_flap_until: dict[str, float] = {}
        self._classic_page_scan_enabled = False
        self.last_pair_error = None
        self._radio_lock = None

    @property
    def connection_state(self) -> dict:
        """Current connection state as a dict for API consumers."""
        connections = [
            self._session_state(session)
            for session in self.sessions.values()
            if self._is_session_alive(session)
        ]
        if not connections:
            if self._allow_legacy_connection_state and self._is_connection_alive():
                return self._legacy_connection_state()
            return {"connected": False}

        primary = connections[0]
        state = {"connected": True, "connections": connections}
        state.update({
            "address": primary.get("address"),
            "protocol": primary.get("protocol"),
            "name": primary.get("name"),
        })
        for key in ("uhid_name", "input_paths", "descriptor_size"):
            if key in primary:
                state[key] = primary[key]
        return state

    def _session_state(self, session: DeviceSession) -> dict:
        """Format one live session for API consumers."""
        state = {
            "address": normalize_addr(session.address) if session.address else None,
            "protocol": session.protocol.value,
            "name": session.device_name,
        }
        if session.uhid_device:
            state["uhid_name"] = session.uhid_device.name
            if session.uhid_device.input_paths:
                state["input_paths"] = session.uhid_device.input_paths
        if session.report_map:
            state["descriptor_size"] = len(session.report_map)
        return state

    def _legacy_connection_state(self) -> dict:
        """Connection state for pairing/continue paths that use singleton fields."""
        state = {
            "connected": True,
            "address": normalize_addr(self.current_device_address) if self.current_device_address else None,
            "protocol": self.connected_protocol.value if self.connected_protocol else None,
            "name": self.device_name,
        }
        if self.uhid_device:
            state["uhid_name"] = self.uhid_device.name
            if self.uhid_device.input_paths:
                state["input_paths"] = self.uhid_device.input_paths
        if self.report_map:
            state["descriptor_size"] = len(self.report_map)
        return state

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

    async def start(self):
        """Initialize the Bumble device with both protocols."""
        log.info(f"HID Host v{get_version()}")

        def configure(device):
            device.classic_enabled = bool(self.classic_devices)
            device.le_enabled = bool(self.ble_devices)
            device.keystore = self.keystore
            device.pairing_config_factory = lambda conn: create_pairing_config()
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
        """Main run loop - handle both protocols concurrently."""
        self._disconnection_event = asyncio.Event()
        self._connection_future = asyncio.get_event_loop().create_future()
        self._session_setup_lock = asyncio.Lock()
        self._allow_legacy_connection_state = False
        self._radio_lock = asyncio.Lock()

        self._parse_devices()
        await self.start()

        for dev in self.classic_devices + self.ble_devices:
            if dev.address != '*':
                cache = self.device_cache.load(dev.address)
                if cache and 'report_map' in cache:
                    log.info(f"Cached descriptor for {self._format_device(dev.address)}")

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

        log.info(f"Waiting for connection (Classic: {len(self.classic_devices)}, BLE: {len(self.ble_devices)})")

        try:
            await asyncio.wait_for(self._connection_future, timeout=60.0)
            log.success("\nReceiving HID reports. Press Ctrl+C to exit.")
            await self._disconnection_event.wait()
        except asyncio.TimeoutError:
            log.warning("Connection timeout - no device connected")
            raise InvalidStateError("No device connected within timeout")
        finally:
            for task in tasks:
                if not task.done():
                    task.cancel()
                    try:
                        await task
                    except asyncio.CancelledError:
                        pass

    # ==================== PAIRING ====================

    async def pair_device(self, address: str, protocol: Protocol = None, name: str = None) -> bool:
        """Pair with a device (first-time setup)."""
        if protocol is None:
            protocol = Protocol.BLE

        self._parse_devices()

        if protocol == Protocol.CLASSIC:
            self.classic_devices = [DeviceConfig(address=address, protocol=protocol, name=name)]
            self.ble_devices = []
        else:
            self.ble_devices = [DeviceConfig(address=address, protocol=protocol, name=name)]
            self.classic_devices = []

        await self.start()

        if protocol == Protocol.CLASSIC:
            return await self._pair_classic(address)
        else:
            return await self._pair_ble(address)

    async def continue_after_pairing(self):
        """Continue into run mode after successful pairing."""
        if not self.connected_protocol:
            raise InvalidStateError("No paired device - call pair_device first")

        if self.connected_protocol == Protocol.CLASSIC and not self.connection:
            raise InvalidStateError("No connection - call pair_device first")

        self._disconnection_event = asyncio.Event()
        self._allow_legacy_connection_state = True

        if self.connection:
            self.connection.on('disconnection', self._on_disconnection)

        if self.connected_protocol == Protocol.CLASSIC:
            await self._continue_classic_after_pairing()
        else:
            await self._continue_ble_after_pairing()

        proto_name = self.connected_protocol.value.upper()
        log.success(f"\n[{proto_name}] Paired and receiving HID reports. Press Ctrl+C to exit.")

        await self._disconnection_event.wait()

    # ==================== COMMON ====================

    def _on_disconnection(self, reason):
        """Handle disconnection of the legacy pairing/continue connection."""
        proto = self.connected_protocol.value.upper() if self.connected_protocol else "Unknown"
        addr = self.current_device_address or "unknown"
        log.warning(f"[{proto}] Device disconnected: {addr} (reason={reason})")
        if self._disconnection_event:
            self._disconnection_event.set()

    def _on_session_disconnection(self, session: DeviceSession, reason):
        """Handle disconnection of a run-mode session."""
        protocol = session.protocol
        proto = protocol.value.upper()
        log.warning(f"[{proto}] Device disconnected: {session.address} (reason={reason})")

        if reason == 5 and protocol == Protocol.CLASSIC:
            log.info("[Classic] Authentication failure; keeping bond and retrying")
            retry_delay = self.CLASSIC_AUTH_RETRY_DELAY
            if self.ble_devices and not self._is_protocol_connected(Protocol.BLE):
                retry_delay = self.CLASSIC_AUTH_RETRY_DELAY_WITH_PENDING_BLE
            self._classic_retry_not_before = time.monotonic() + retry_delay
            log.info(f"[Classic] Deferring retry for {retry_delay:.0f}s")

        finalized = self.sessions.get(protocol) is session
        if finalized:
            self.sessions.pop(protocol, None)
        if self._pending_sessions.get(protocol) is session:
            self._pending_sessions.pop(protocol, None)
        if session.disconnection_event:
            session.disconnection_event.set()
        if session.uhid_device:
            try:
                session.uhid_device.destroy()
            except Exception:
                pass

        if finalized and protocol == Protocol.CLASSIC:
            self._update_classic_flap_backoff(session, reason)

        live_sessions = any(
            self._is_session_alive(s) for s in self.sessions.values()
        )
        if self._disconnection_event:
            if (
                finalized
                and protocol == Protocol.CLASSIC
                and self.ble_devices
                and not self._is_protocol_connected(Protocol.BLE)
            ):
                retry_delay = self.CLASSIC_AUTH_RETRY_DELAY_WITH_PENDING_BLE
                self._classic_retry_not_before = time.monotonic() + retry_delay
                log.info(
                    "[Classic] Waiting for BLE before restarting Classic "
                    f"after {retry_delay:.0f}s"
                )
            elif finalized and self._has_configured_devices(protocol):
                log.info(f"[{proto}] Restoring configured device")
            elif not live_sessions and not self._has_any_configured_devices():
                self._disconnection_event.set()

    def _forward_report_for_protocol(self, protocol: Protocol, data: bytes):
        """Log changed HID reports and forward every report for one protocol."""
        session = self.sessions.get(protocol)
        if session:
            self._forward_report_for_session(session, data)
            return
        if data != self._last_report:
            log.debug(f"Report: {data.hex()}")
            self._last_report = data
        if self.uhid_device:
            try:
                self.uhid_device.send_input(data)
            except Exception as e:
                log.warning(f"UHID send failed: {e}")

    def _forward_report_for_session(self, session: DeviceSession, data: bytes):
        """Log changed HID reports and forward every report for one session."""
        for report in self._reports_for_session(session, data):
            self._send_report_for_session(session, report)

    def _send_report_for_session(self, session: DeviceSession, data: bytes):
        if data != session.last_report:
            log.debug(f"Report: {data.hex()}")
            session.last_report = data
        if session.uhid_device:
            try:
                session.uhid_device.send_input(data)
            except Exception as e:
                log.warning(f"UHID send failed: {e}")

    def _reports_for_session(self, session: DeviceSession, data: bytes):
        if (
            session.protocol != Protocol.CLASSIC
            or not config.classic_serialize_keyboard_reports
        ):
            return (data,)

        parsed = self._parse_classic_keyboard_report(data)
        if not parsed:
            session.keyboard_last_keys = ()
            return (data,)

        modifier, keys = parsed
        previous = set(session.keyboard_last_keys)
        current = tuple(key for key in keys if key)
        session.keyboard_last_keys = current

        release = self._make_classic_keyboard_report(0, ())
        if not current:
            return (release,)

        new_keys = [key for key in current if key not in previous]
        reports = []
        for key in new_keys:
            reports.append(self._make_classic_keyboard_report(modifier, (key,)))
            reports.append(release)
        return tuple(reports)

    def _parse_classic_keyboard_report(self, data: bytes):
        if len(data) != 8 or data[0] != 1:
            return None
        return data[1], tuple(data[3:8])

    def _make_classic_keyboard_report(self, modifier: int, keys):
        slots = list(keys[:5])
        slots.extend([0] * (5 - len(slots)))
        return bytes([1, modifier, 0, *slots])

    def _load_cached_descriptor(
        self,
        address: str = None,
        session: DeviceSession = None,
    ) -> bool:
        """Load report descriptor and device name from cache. Returns True if found."""
        address = address or (session.address if session else self.current_device_address)
        cache = self.device_cache.load(address)
        if cache and 'report_map' in cache:
            report_map = bytes.fromhex(cache['report_map'])
            device_name = cache.get('device_name')
            if session:
                session.report_map = report_map
                session.device_name = device_name
            else:
                self.report_map = report_map
                self.device_name = device_name
            log.success(f"Loaded cached descriptor ({len(report_map)} bytes)")
            return True
        return False

    def _create_uhid_device(self, session: DeviceSession = None):
        """Create UHID virtual device."""
        report_map = session.report_map if session else self.report_map
        if not report_map:
            log.warning("No report descriptor for UHID")
            return

        try:
            address = session.address if session else self.current_device_address
            device_name = session.device_name if session else self.device_name
            name = self._configured_name(address) or device_name or "HID Device"
            descriptor = strip_digitizer_collections(report_map)
            uhid_device = UHIDDevice(
                name=name,
                report_descriptor=descriptor,
                bus=Bus.BLUETOOTH,
                vendor=0,
                product=0,
                uniq=address or "",
            )
            if session:
                session.uhid_device = uhid_device
            else:
                self.uhid_device = uhid_device
            log.success(f"UHID device created: {name}")
            asyncio.get_event_loop().call_later(
                0.5, uhid_device.discover_input_paths)
        except Exception as e:
            log.error(f"Failed to create UHID device: {e}")

    def _new_session(
        self,
        protocol: Protocol,
        address: str,
        connection,
        *,
        peer=None,
        hid_host=None,
    ) -> DeviceSession:
        return DeviceSession(
            protocol=protocol,
            address=address,
            connection=connection,
            peer=peer,
            hid_host=hid_host,
            device_name=self._configured_name(address),
            disconnection_event=asyncio.Event(),
        )

    def _track_pending_session(self, session: DeviceSession):
        self._pending_sessions[session.protocol] = session

    def _clear_pending_session(self, session: DeviceSession):
        if self._pending_sessions.get(session.protocol) is session:
            self._pending_sessions.pop(session.protocol, None)

    def _record_session(self, session: DeviceSession):
        """Record a finalized live protocol session."""
        self._clear_pending_session(session)
        session.established_at = time.monotonic()
        self.sessions[session.protocol] = session
        if not self._connection_future.done():
            self._connection_future.set_result(session)

    def _session_event_is_set(self, session: DeviceSession) -> bool:
        return bool(session.disconnection_event and session.disconnection_event.is_set())

    async def _wait_for_protocol_disconnection(self, protocol: Protocol):
        """Wait until the protocol's session drops or the whole host is stopping."""
        session = self.sessions.get(protocol)
        if not session or not session.disconnection_event:
            return
        wait_tasks = [asyncio.create_task(session.disconnection_event.wait())]
        if self._disconnection_event:
            wait_tasks.append(asyncio.create_task(self._disconnection_event.wait()))
        try:
            await asyncio.wait(wait_tasks, return_when=asyncio.FIRST_COMPLETED)
        finally:
            for task in wait_tasks:
                if not task.done():
                    task.cancel()

    def _is_connection_alive(self) -> bool:
        """Check if the connection is still alive and usable."""
        if self._disconnection_event and self._disconnection_event.is_set():
            return False
        return self._is_raw_connection_alive(self.connection)

    def _is_session_alive(self, session: DeviceSession) -> bool:
        """Check if a finalized session is still alive."""
        if session.disconnection_event and session.disconnection_event.is_set():
            return False
        return self._is_raw_connection_alive(session.connection)

    def _is_protocol_connected(self, protocol: Protocol) -> bool:
        """Check if a protocol already has a live session."""
        session = self.sessions.get(protocol)
        return bool(session and self._is_session_alive(session))

    def _is_protocol_connecting(self, protocol: Protocol) -> bool:
        """Check if a protocol has an unfinalized live connection."""
        pending = self._pending_sessions.get(protocol)
        if pending and self._is_session_alive(pending):
            return True
        return (
            self.connected_protocol == protocol
            and protocol not in self.sessions
            and self._is_raw_connection_alive(self.connection)
        )

    def _protocol_retry_delay(self, protocol: Protocol) -> float:
        """Return seconds before the protocol should retry a connection."""
        if protocol == Protocol.CLASSIC:
            return max(0.0, self._classic_retry_not_before - time.monotonic())
        return 0.0

    def _update_classic_flap_backoff(self, session: DeviceSession, reason):
        """Escalate the dial backoff for a device that keeps accepting a
        session and then dropping it, and clear it after a healthy session."""
        addr = normalize_addr(session.address)
        duration = (
            time.monotonic() - session.established_at
            if session.established_at else 0.0
        )
        if session.last_report is not None or duration >= self.CLASSIC_FLAP_WINDOW:
            if self._classic_flap_counts.pop(addr, None) is not None:
                self._classic_flap_until.pop(addr, None)
                log.info(
                    f"[Classic] {self._format_device(addr)} session healthy; "
                    "clearing flap backoff"
                )
            return

        if reason not in self.CLASSIC_REMOTE_DISCONNECT_REASONS:
            return

        count = self._classic_flap_counts.get(addr, 0) + 1
        self._classic_flap_counts[addr] = count
        delay = min(
            self.CLASSIC_FLAP_BACKOFF_BASE * (2 ** (count - 1)),
            self.CLASSIC_FLAP_BACKOFF_MAX,
        )
        self._classic_flap_until[addr] = time.monotonic() + delay
        log.warning(
            f"[Classic] {self._format_device(addr)} dropped by remote after "
            f"{duration:.0f}s without input ({count} in a row); "
            f"deferring dial for {delay:.0f}s"
        )

    def _classic_dial_delay(self, addr: str) -> float:
        """Seconds before we should dial this address again (flap backoff).
        Inbound connections from the device are still accepted immediately."""
        until = self._classic_flap_until.get(normalize_addr(addr), 0.0)
        return max(0.0, until - time.monotonic())

    def _has_configured_devices(self, protocol: Protocol) -> bool:
        """Check if a protocol should be restored after a live session drops."""
        if protocol == Protocol.CLASSIC:
            return bool(self.classic_devices)
        if protocol == Protocol.BLE:
            return bool(self.ble_devices)
        return False

    def _has_any_configured_devices(self) -> bool:
        return bool(self.classic_devices or self.ble_devices)

    @asynccontextmanager
    async def _use_radio(self):
        await self._radio_lock.acquire()
        try:
            yield
        finally:
            self._radio_lock.release()

    def _is_raw_connection_alive(self, connection) -> bool:
        """Check if a Bumble connection object is still alive."""
        if connection is None:
            return False
        if not hasattr(connection, 'handle') or connection.handle is None:
            return False
        if hasattr(connection, 'is_disconnected') and connection.is_disconnected:
            return False
        return True

    async def cleanup(self):
        """Clean up resources."""
        had_sessions = bool(self.sessions)
        session_connection_ids = {id(s.connection) for s in self.sessions.values()}
        session_uhid_ids = {
            id(s.uhid_device) for s in self.sessions.values() if s.uhid_device
        }

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

        all_sessions = list(self.sessions.values()) + list(self._pending_sessions.values())
        for session in all_sessions:
            if session.uhid_device:
                try:
                    session.uhid_device.destroy()
                except Exception:
                    pass
            if session.hid_host and self._is_session_alive(session):
                if session.hid_host.l2cap_intr_channel:
                    try:
                        await asyncio.wait_for(
                            session.hid_host.disconnect_interrupt_channel(), timeout=1.0)
                    except Exception:
                        pass
                if session.hid_host.l2cap_ctrl_channel:
                    try:
                        await asyncio.wait_for(
                            session.hid_host.disconnect_control_channel(), timeout=1.0)
                    except Exception:
                        pass
            if self._is_session_alive(session):
                try:
                    await asyncio.wait_for(session.connection.disconnect(), timeout=2.0)
                except asyncio.TimeoutError:
                    log.warning("Connection disconnect timed out")
                except Exception as e:
                    log.debug(f"Disconnect cleanup: {e}")
        self.sessions.clear()
        self._pending_sessions.clear()

        peer_already_disconnected = (
            self._disconnection_event is not None
            and self._disconnection_event.is_set()
        )

        if (
            self.uhid_device
            and (not had_sessions or id(self.uhid_device) not in session_uhid_ids)
        ):
            try:
                self.uhid_device.destroy()
            except Exception:
                pass
        self.uhid_device = None

        if not had_sessions and self.hid_host:
            if self._is_connection_alive():
                if self.hid_host.l2cap_intr_channel:
                    try:
                        await asyncio.wait_for(
                            self.hid_host.disconnect_interrupt_channel(), timeout=1.0)
                    except Exception:
                        pass
                if self.hid_host.l2cap_ctrl_channel:
                    try:
                        await asyncio.wait_for(
                            self.hid_host.disconnect_control_channel(), timeout=1.0)
                    except Exception:
                        pass
            self.hid_host = None

        unrecorded_connection = (
            self._is_connection_alive()
            and id(self.connection) not in session_connection_ids
        )
        if unrecorded_connection and not peer_already_disconnected:
            try:
                await asyncio.wait_for(self.connection.disconnect(), timeout=2.0)
            except asyncio.TimeoutError:
                log.warning("Connection disconnect timed out")
            except Exception as e:
                log.debug(f"Disconnect cleanup: {e}")
        self.connection = None
        self.peer = None
        if had_sessions:
            self.hid_host = None

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

    async def disconnect_all(self):
        """Disconnect all live sessions, or the legacy singleton connection."""
        disconnected = False
        for session in list(self.sessions.values()):
            if self._is_session_alive(session):
                try:
                    await session.connection.disconnect()
                    disconnected = True
                except Exception as e:
                    log.debug(f"Disconnect request failed for {session.address}: {e}")
        if not disconnected and self._is_connection_alive():
            await self.connection.disconnect()
            disconnected = True
        return disconnected

    def get_auth_failure_address(self) -> str:
        """Get address that had auth failure, if any."""
        addr = self._auth_failure_address
        self._auth_failure_address = None
        return addr

    def get_virtual_cable_unplug_address(self) -> str:
        """Get address that sent a virtual cable unplug, if any."""
        addr = self._virtual_cable_unplug_address
        self._virtual_cable_unplug_address = None
        return addr
