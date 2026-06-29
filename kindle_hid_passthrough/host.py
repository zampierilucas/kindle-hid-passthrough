#!/usr/bin/env python3
"""HID Host — runs BLE + Classic handlers on a single Bumble device."""

import asyncio
import time
from dataclasses import dataclass
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
    uhid_device: Optional[UHIDDevice] = None
    disconnection_event: Optional[asyncio.Event] = None
    last_report: Optional[bytes] = None


class HIDHost(ClassicMixin, BLEMixin):
    """HID Host supporting both BLE and Classic Bluetooth.

    Protocol-specific handlers live in ClassicMixin and BLEMixin.
    This class owns init, start, run, pairing dispatch, and cleanup.
    """

    PROTOCOL_NAME = "HID"

    ACTIVE_DELAY = 2.0
    ACTIVE_RETRY_INTERVAL = 5.0
    ACTIVE_CONNECT_TIMEOUT = 10
    CLASSIC_AUTH_RETRY_DELAY = 8.0
    CLASSIC_AUTH_RETRY_DELAY_WITH_PENDING_BLE = 20.0

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

        self._disconnection_event = None
        self._protocol_disconnection_events: dict[Protocol, asyncio.Event] = {}
        self._connection_future = None
        self._session_setup_lock = None
        self._allow_legacy_connection_state = False
        self._last_report = None
        self._auth_failure_address = None
        self._virtual_cable_unplug_address = None
        self._classic_retry_not_before = 0.0
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
        self._protocol_disconnection_events = {
            Protocol.CLASSIC: asyncio.Event(),
            Protocol.BLE: asyncio.Event(),
        }
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
        """Handle device disconnection."""
        self._on_protocol_disconnection(
            self.connected_protocol, self.current_device_address, reason)

    def _on_protocol_disconnection(self, protocol, address, reason):
        """Handle disconnection for a specific protocol session."""
        proto = protocol.value.upper() if protocol else "Unknown"
        addr = address or "unknown"
        log.warning(f"[{proto}] Device disconnected: {addr} (reason={reason})")

        if reason == 5 and address and proto == "CLASSIC":
            log.info("[Classic] Authentication failure; keeping bond and retrying")
            retry_delay = self.CLASSIC_AUTH_RETRY_DELAY
            if self.ble_devices and not self._is_protocol_connected(Protocol.BLE):
                retry_delay = self.CLASSIC_AUTH_RETRY_DELAY_WITH_PENDING_BLE
            self._classic_retry_not_before = time.monotonic() + retry_delay
            log.info(f"[Classic] Deferring retry for {retry_delay:.0f}s")

        session = self.sessions.pop(protocol, None) if protocol else None
        if session and session.uhid_device:
            try:
                session.uhid_device.destroy()
            except Exception:
                pass

        if protocol in self._protocol_disconnection_events:
            self._protocol_disconnection_events[protocol].set()
        live_sessions = any(
            self._is_session_alive(s) for s in self.sessions.values()
        )
        if self._disconnection_event:
            if (
                session
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
            elif session and self._has_configured_devices(protocol):
                log.info(f"[{proto}] Restarting host to restore configured device")
                self._disconnection_event.set()
            elif not live_sessions:
                self._disconnection_event.set()
        if protocol == self.connected_protocol and protocol not in self.sessions:
            self.connection = None
            self.peer = None
            self.current_device_address = None
            self.connected_protocol = None

    def _forward_report(self, data: bytes):
        """Deduplicate, log, and forward an HID report to UHID."""
        self._forward_report_for_protocol(self.connected_protocol, data)

    def _forward_report_for_protocol(self, protocol: Protocol, data: bytes):
        """Deduplicate, log, and forward an HID report for one protocol."""
        session = self.sessions.get(protocol)
        if session:
            last_report = session.last_report
            uhid_device = session.uhid_device
        else:
            last_report = self._last_report
            uhid_device = self.uhid_device

        if data != last_report:
            log.debug(f"Report: {data.hex()}")
            if session:
                session.last_report = data
            else:
                self._last_report = data
        if uhid_device:
            try:
                uhid_device.send_input(data)
            except Exception as e:
                log.warning(f"UHID send failed: {e}")

    def _load_cached_descriptor(self, address: str = None) -> bool:
        """Load report descriptor and device name from cache. Returns True if found."""
        address = address or self.current_device_address
        cache = self.device_cache.load(address)
        if cache and 'report_map' in cache:
            self.report_map = bytes.fromhex(cache['report_map'])
            self.device_name = cache.get('device_name')
            log.success(f"Loaded cached descriptor ({len(self.report_map)} bytes)")
            return True
        return False

    def _create_uhid_device(self):
        """Create UHID virtual device."""
        if not self.report_map:
            log.warning("No report descriptor for UHID")
            return

        try:
            name = self._configured_name(self.current_device_address) or self.device_name or "HID Device"
            descriptor = strip_digitizer_collections(self.report_map)
            self.uhid_device = UHIDDevice(
                name=name,
                report_descriptor=descriptor,
                bus=Bus.BLUETOOTH,
                vendor=0,
                product=0,
                uniq=self.current_device_address or "",
            )
            log.success(f"UHID device created: {name}")
            asyncio.get_event_loop().call_later(
                0.5, self.uhid_device.discover_input_paths)
        except Exception as e:
            log.error(f"Failed to create UHID device: {e}")

    def _record_current_session(self, protocol: Protocol):
        """Promote the singleton setup fields into a live protocol session."""
        event = self._protocol_disconnection_events.get(protocol)
        session = DeviceSession(
            protocol=protocol,
            address=self.current_device_address,
            connection=self.connection,
            peer=self.peer,
            hid_host=self.hid_host if protocol == Protocol.CLASSIC else None,
            device_name=self.device_name,
            report_map=self.report_map,
            uhid_device=self.uhid_device,
            disconnection_event=event,
        )
        self.sessions[protocol] = session
        if not self._connection_future.done():
            self._connection_future.set_result(session)

    def _protocol_event_is_set(self, protocol: Protocol) -> bool:
        event = self._protocol_disconnection_events.get(protocol)
        return bool(event and event.is_set())

    def _clear_protocol_event(self, protocol: Protocol):
        event = self._protocol_disconnection_events.get(protocol)
        if event:
            event.clear()

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

    def _has_configured_devices(self, protocol: Protocol) -> bool:
        """Check if a protocol should be restored after a live session drops."""
        if protocol == Protocol.CLASSIC:
            return bool(self.classic_devices)
        if protocol == Protocol.BLE:
            return bool(self.ble_devices)
        return False

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

        for session in list(self.sessions.values()):
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
                    except (asyncio.TimeoutError, Exception):
                        pass
                if session.hid_host.l2cap_ctrl_channel:
                    try:
                        await asyncio.wait_for(
                            session.hid_host.disconnect_control_channel(), timeout=1.0)
                    except (asyncio.TimeoutError, Exception):
                        pass
            if self._is_session_alive(session):
                try:
                    await asyncio.wait_for(session.connection.disconnect(), timeout=2.0)
                except asyncio.TimeoutError:
                    log.warning("Connection disconnect timed out")
                except Exception as e:
                    log.debug(f"Disconnect cleanup: {e}")
        self.sessions.clear()

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
                    except (asyncio.TimeoutError, Exception):
                        pass
                if self.hid_host.l2cap_ctrl_channel:
                    try:
                        await asyncio.wait_for(
                            self.hid_host.disconnect_control_channel(), timeout=1.0)
                    except (asyncio.TimeoutError, Exception):
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
