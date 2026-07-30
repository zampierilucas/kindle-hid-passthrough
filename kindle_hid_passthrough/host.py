#!/usr/bin/env python3
"""HID Host — runs BLE + Classic handlers on a single Bumble device."""

import asyncio
from dataclasses import dataclass
from typing import List, Optional

from bumble.core import InvalidStateError
from bumble.hci import HCI_LE_SET_PRIVACY_MODE_COMMAND, HCI_LE_Set_Privacy_Mode_Command, HCI_Write_Class_Of_Device_Command, HCI_Write_Local_Name_Command

import keep_awake
from ble import BLEMixin
from bt_setup import ensure_uhid
from classic import ClassicMixin
from config import Protocol, clean_device_name, config, get_version, normalize_addr
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


class HIDHost(ClassicMixin, BLEMixin):
    """HID Host supporting both BLE and Classic Bluetooth.

    Protocol-specific handlers live in ClassicMixin and BLEMixin.
    This class owns init, start, run, pairing dispatch, and cleanup.
    """

    PROTOCOL_NAME = "HID"

    ACTIVE_DELAY = 2.0
    ACTIVE_RETRY_INTERVAL = 5.0
    ACTIVE_CONNECT_TIMEOUT = 10

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

        self._disconnection_event = None
        self._connection_future = None
        self._last_report = None
        self._auth_failure_address = None
        self._virtual_cable_unplug_address = None
        self._radio_lock = None

    @property
    def connection_state(self) -> dict:
        """Current connection state as a dict for API consumers."""
        if not self._is_connection_alive():
            return {"connected": False}

        state = {
            "connected": True,
            "address": normalize_addr(self.current_device_address) if self.current_device_address else None,
            "protocol": self.connected_protocol.value if self.connected_protocol else None,
            "name": self.device_name,
            "hid_ready": self.uhid_device is not None,
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
        """Main run loop - handle both protocols concurrently."""
        self._disconnection_event = asyncio.Event()
        self._connection_future = asyncio.get_event_loop().create_future()
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

        if self.connected_protocol == Protocol.CLASSIC:
            await self._handle_classic_connection()
        else:
            await self._handle_ble_connection()

        proto_name = self.connected_protocol.value.upper()
        log.success(f"\n[{proto_name}] Receiving HID reports. Press Ctrl+C to exit.")

        # Daemon owns the reconnect + stale-key-clear policy: on auth
        # failure it reads get_auth_failure_address(), removes the key,
        # and restarts us on a fresh transport. Only a Classic auth
        # failure while BLE is connected is absorbed here.
        while True:
            await self._disconnection_event.wait()

            if self._auth_failure_address and self.connected_protocol == Protocol.BLE and self.connection:
                log.info("[Classic] Auth failure ignored - BLE connection is active")
                self._auth_failure_address = None
                self._disconnection_event.clear()
                continue
            break

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
        proto = self.connected_protocol.value.upper() if self.connected_protocol else "Unknown"
        addr = self.current_device_address or "unknown"
        log.warning(f"[{proto}] Device disconnected: {addr} (reason={reason})")

        if reason == 5 and self.current_device_address and proto == "CLASSIC":
            log.info("[Classic] Authentication failure - will clear stale key and retry")
            self._auth_failure_address = self.current_device_address

        self._disconnection_event.set()

    def _forward_report(self, data: bytes):
        """Deduplicate, log, and forward an HID report to UHID."""
        if data != self._last_report:
            log.debug(f"Report: {data.hex()}")
            self._last_report = data
            # Changed reports only, so a stick parked at rest can't pin the screen on.
            keep_awake.on_activity()
        if self.uhid_device:
            try:
                self.uhid_device.send_input(data)
            except Exception as e:
                log.warning(f"UHID send failed: {e}")

    def _load_cached_descriptor(self, address: str = None) -> bool:
        """Load report descriptor and device name from cache. Returns True if found."""
        address = address or self.current_device_address
        cache = self.device_cache.load(address)
        if cache and 'report_map' in cache:
            self.report_map = bytes.fromhex(cache['report_map'])
            self.device_name = clean_device_name(cache.get('device_name') or '') or None
            log.success(f"Loaded cached descriptor ({len(self.report_map)} bytes)")
            return True
        return False

    def _create_uhid_device(self):
        """Create UHID virtual device."""
        if not self.report_map:
            log.warning("No report descriptor for UHID")
            return

        if not ensure_uhid():
            log.error("uhid unavailable; connected device will have no input path")
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

    def _is_connection_alive(self) -> bool:
        """Check if the connection is still alive and usable."""
        if self.connection is None:
            return False
        if not hasattr(self.connection, 'handle') or self.connection.handle is None:
            return False
        if hasattr(self.connection, 'is_disconnected') and self.connection.is_disconnected:
            return False
        return True

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

        if self.uhid_device:
            try:
                self.uhid_device.destroy()
            except Exception:
                pass
            self.uhid_device = None

        if self.hid_host:
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

        peer_already_disconnected = (
            self._disconnection_event is not None
            and self._disconnection_event.is_set()
        )
        if self._is_connection_alive() and not peer_already_disconnected:
            try:
                await asyncio.wait_for(self.connection.disconnect(), timeout=2.0)
            except asyncio.TimeoutError:
                log.warning("Connection disconnect timed out")
            except Exception as e:
                log.debug(f"Disconnect cleanup: {e}")
        self.connection = None
        self.peer = None

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
