#!/usr/bin/env python3
"""Classic Bluetooth HID handler mixin for HIDHost."""

import asyncio
from typing import List, Optional

from bumble.core import BT_BR_EDR_TRANSPORT, BT_HUMAN_INTERFACE_DEVICE_SERVICE, InvalidStateError, TimeoutError as BumbleTimeoutError
from bumble.hci import (
    Address,
    HCI_Write_Scan_Enable_Command,
)
from bumble.hid import HID_CONTROL_PSM, HID_INTERRUPT_PSM, Message
from bumble.hid import Host as BumbleHIDHost
from bumble.sdp import Client as SDPClient

from config import Protocol, config, normalize_addr
from logging_utils import log

FALLBACK_HID_DESCRIPTOR = bytes([
    0x05, 0x01, 0x09, 0x05, 0xa1, 0x01, 0x85, 0x01,
    0x05, 0x01, 0x09, 0x30, 0x09, 0x31, 0x09, 0x32, 0x09, 0x35,
    0x16, 0x00, 0x00, 0x26, 0xff, 0xff, 0x75, 0x10, 0x95, 0x04, 0x81, 0x02,
    0x05, 0x02, 0x09, 0xc5, 0x09, 0xc4,
    0x16, 0x00, 0x00, 0x26, 0xff, 0x03, 0x75, 0x10, 0x95, 0x02, 0x81, 0x02,
    0x05, 0x01, 0x09, 0x39, 0x15, 0x01, 0x25, 0x08,
    0x35, 0x00, 0x46, 0x3b, 0x01, 0x65, 0x14, 0x75, 0x08, 0x95, 0x01, 0x81, 0x42,
    0x05, 0x09, 0x19, 0x01, 0x29, 0x10,
    0x15, 0x00, 0x25, 0x01, 0x75, 0x01, 0x95, 0x10, 0x81, 0x02,
    0xc0,
])


class ClassicMixin:
    """Classic Bluetooth methods for HIDHost."""

    async def _run_classic_handler(self):
        """Handle Classic Bluetooth connections."""
        if hasattr(self, '_classic_connection_listener') and self._classic_connection_listener:
            try:
                self.device.remove_listener('connection', self._classic_connection_listener)
            except Exception:
                pass
            self._classic_connection_listener = None

        classic_hid_host = BumbleHIDHost(self.device)
        self.hid_host = classic_hid_host
        classic_hid_host.on(BumbleHIDHost.EVENT_INTERRUPT_DATA, self._on_classic_interrupt_data)
        classic_hid_host.on(BumbleHIDHost.EVENT_VIRTUAL_CABLE_UNPLUG, self._on_virtual_cable_unplug)
        log.info(f"[Classic] HID Host ready (PSM 0x{HID_CONTROL_PSM:04X}, 0x{HID_INTERRUPT_PSM:04X})")

        log.info("[Classic] Enabling Page Scan...")
        await self.device.host.send_command(
            HCI_Write_Scan_Enable_Command(scan_enable=0x02),
            check_result=True
        )

        async def on_classic_connection(connection):
            if self._is_protocol_connected(Protocol.CLASSIC):
                log.info("[Classic] Connection received but Classic is already connected")
                try:
                    await connection.disconnect()
                except Exception:
                    pass
                return

            if not classic_hid_host:
                log.warning("[Classic] Connection received but hid_host not ready, ignoring")
                try:
                    await connection.disconnect()
                except Exception:
                    pass
                return

            addr_str = str(connection.peer_address)
            log.info(f"[Classic] Device connected: {self._format_device(addr_str)}")

            if not self._is_classic_allowed(addr_str):
                log.warning(f"[Classic] Rejecting {addr_str} (not allowed)")
                try:
                    await connection.disconnect()
                except Exception:
                    pass
                return

            async with self._session_setup_lock:
                if self._is_protocol_connected(Protocol.CLASSIC):
                    try:
                        await connection.disconnect()
                    except Exception:
                        pass
                    return

                session = self._new_session(
                    Protocol.CLASSIC,
                    addr_str,
                    connection,
                    hid_host=classic_hid_host,
                )
                self._track_pending_session(session)

                connection.on(
                    'disconnection',
                    lambda reason, s=session:
                    self._on_session_disconnection(s, reason)
                )

                try:
                    await self._setup_classic_connection(session)
                finally:
                    if Protocol.CLASSIC not in self.sessions:
                        self._clear_pending_session(session)

        def on_connection_event(connection):
            is_classic = (hasattr(connection, 'transport')
                          and connection.transport == BT_BR_EDR_TRANSPORT) \
                          or not hasattr(connection, 'transport')
            if not is_classic:
                return
            task = asyncio.create_task(on_classic_connection(connection))
            self._connection_tasks.add(task)
            task.add_done_callback(self._connection_tasks.discard)

        self._classic_connection_listener = on_connection_event
        self.device.on('connection', on_connection_event)

        active_addresses = [d.address for d in self.classic_devices if d.address != '*']
        if active_addresses:
            while not self._disconnection_event.is_set():
                await self._classic_active_connect_loop(active_addresses)
                if self._disconnection_event.is_set():
                    break
                if self._is_protocol_connected(Protocol.CLASSIC):
                    await self._wait_for_protocol_disconnection(Protocol.CLASSIC)
                elif not self._disconnection_event.is_set():
                    await asyncio.sleep(self.ACTIVE_RETRY_INTERVAL)

    async def _setup_classic_connection(self, session):
        """Authenticate, open HID channels, and create the Classic UHID session."""
        connection = session.connection
        hid_host = session.hid_host
        addr_str = session.address

        hid_host.on_device_connection(connection)

        if not getattr(connection, 'is_encrypted', False):
            log.info("[Classic] Authenticating...")
            try:
                await asyncio.wait_for(connection.authenticate(), timeout=8.0)
                log.success("[Classic] Authentication complete")
            except Exception as e:
                log.warning(f"[Classic] Authentication: {e}")

        if not getattr(connection, 'is_encrypted', False):
            log.info("[Classic] Requesting encryption...")
            try:
                await asyncio.wait_for(connection.encrypt(enable=True), timeout=10.0)
                log.success("[Classic] Link encrypted")
            except Exception as e:
                log.warning(f"[Classic] Encryption: {e}")

        if self._session_event_is_set(session):
            log.warning("[Classic] Connection lost during authentication")
            return

        log.info("[Classic] Waiting for HID channels...")
        for _ in range(30):
            if self._session_event_is_set(session):
                log.warning("[Classic] Connection lost while waiting for HID channels")
                return
            if hid_host.l2cap_intr_channel and hid_host.l2cap_ctrl_channel:
                log.success("[Classic] HID channels opened")
                break
            await asyncio.sleep(0.1)

        if self._session_event_is_set(session):
            log.warning("[Classic] Connection lost during HID setup")
            return

        if not hid_host.l2cap_ctrl_channel:
            try:
                await asyncio.wait_for(hid_host.connect_control_channel(), timeout=5.0)
            except Exception:
                pass

        if not hid_host.l2cap_intr_channel:
            try:
                await asyncio.wait_for(hid_host.connect_interrupt_channel(), timeout=5.0)
            except Exception:
                pass

        if self._session_event_is_set(session):
            log.warning("[Classic] Connection lost during channel setup")
            return

        if not hid_host.l2cap_intr_channel:
            log.warning("[Classic] HID interrupt channel failed to connect, dropping link")
            try:
                await connection.disconnect()
            except Exception:
                pass
            return

        self._classic_set_report_protocol(session)
        if not await self._handle_classic_connection(session):
            return
        self._record_session(session)
        log.success(f"[Classic] Session ready: {self._format_device(addr_str)}")

    def _is_classic_allowed(self, addr_str: str) -> bool:
        """Check if Classic address is allowed."""
        norm_addr = normalize_addr(addr_str)

        for dev in self.classic_devices:
            if dev.address == '*':
                return True
            if dev.address == norm_addr:
                return True

        if norm_addr in self._keystore_addresses:
            return True

        return False

    def _has_live_classic_connection(self, addr: str) -> bool:
        """True if bumble already holds a live Classic link to addr."""
        norm = normalize_addr(addr)
        connections = getattr(self.device, 'connections', None) or {}
        for conn in list(connections.values()):
            try:
                if normalize_addr(str(conn.peer_address)) != norm:
                    continue
                transport = getattr(conn, 'transport', None)
                if transport is not None and transport != BT_BR_EDR_TRANSPORT:
                    continue
                if self._is_raw_connection_alive(conn):
                    return True
            except Exception:
                continue
        return False

    async def _classic_active_connect_loop(self, addresses: List[str]):
        """Actively try to connect to Classic devices."""
        log.info(f"[Classic] Active: {len(addresses)} device(s)")
        await asyncio.sleep(self.ACTIVE_DELAY)

        attempt = 0
        while not self._is_protocol_connected(Protocol.CLASSIC):
            retry_delay = self._protocol_retry_delay(Protocol.CLASSIC)
            if retry_delay > 0:
                await asyncio.sleep(min(retry_delay, 1.0))
                continue

            if self._is_protocol_connecting(Protocol.CLASSIC):
                await asyncio.sleep(0.5)
                continue

            attempt += 1
            for addr in addresses:
                if self._is_protocol_connected(Protocol.CLASSIC):
                    return
                if self._is_protocol_connecting(Protocol.CLASSIC):
                    break

                if self._has_live_classic_connection(addr):
                    log.info(
                        f"[Classic] {self._format_device(addr)} already linked; "
                        "skipping active connect"
                    )
                    await asyncio.sleep(1.0)
                    continue

                log.info(f"[Classic] Attempt {attempt}: {self._format_device(addr)}")

                target = Address(addr, Address.PUBLIC_DEVICE_ADDRESS)
                async with self._use_radio():
                    connect_task = asyncio.create_task(
                        self.device.connect(target, transport=BT_BR_EDR_TRANSPORT)
                    )
                    backoff = 0.0
                    try:
                        timed_out = True
                        for _ in range(self.ACTIVE_CONNECT_TIMEOUT):
                            if self._is_protocol_connected(Protocol.CLASSIC):
                                return
                            done, _ = await asyncio.wait([connect_task], timeout=0.5)
                            if done:
                                timed_out = False
                                break

                        if timed_out:
                            log.info(f"[Classic] {addr} timed out")
                            backoff = 3.0
                        else:
                            await connect_task

                    except Exception as e:
                        if "DISALLOWED" in str(e) or "PENDING" in str(e):
                            log.warning("[Classic] HCI busy, waiting...")
                            backoff = 5.0
                        else:
                            log.info(f"[Classic] Connect failed: {e}")
                            backoff = 2.0

                    finally:
                        if not connect_task.done():
                            connect_task.cancel()
                        try:
                            await connect_task
                        except (asyncio.CancelledError, Exception):
                            pass

                if backoff:
                    await asyncio.sleep(backoff)

            if not self._is_protocol_connected(Protocol.CLASSIC):
                await asyncio.sleep(self.ACTIVE_RETRY_INTERVAL)

    def _classic_set_report_protocol(self, session=None):
        """Send HIDP SET_PROTOCOL(Report) on the control channel."""
        hid_host = session.hid_host if session else self.hid_host
        if not hid_host or not hid_host.l2cap_ctrl_channel:
            return
        try:
            hid_host.set_protocol(Message.ProtocolMode.REPORT_PROTOCOL)
            log.info("[Classic] Sent SET_PROTOCOL (Report)")
        except Exception as e:
            log.warning(f"[Classic] SET_PROTOCOL failed: {e}")

    def _finalize_classic_hid(self, session=None):
        """Apply fallback descriptor if needed and create UHID."""
        if session:
            if not session.report_map:
                session.report_map = FALLBACK_HID_DESCRIPTOR
                log.warning("[Classic] Using fallback descriptor")
            self._create_uhid_device(session)
            return
        if not self.report_map:
            self.report_map = FALLBACK_HID_DESCRIPTOR
            log.warning("[Classic] Using fallback descriptor")
        self._create_uhid_device()

    async def _handle_classic_connection(self, session=None) -> bool:
        """Finalize Classic connection setup."""
        hid_host = session.hid_host if session else self.hid_host
        connection = session.connection if session else self.connection
        if not hid_host.l2cap_intr_channel:
            raise InvalidStateError("HID interrupt channel not connected")

        if config.classic_require_live_descriptor:
            if session:
                session.report_map = None
            else:
                self.report_map = None
            live = await self._query_classic_sdp(session=session)
            if live is None and self._load_cached_descriptor(session=session):
                log.warning("[Classic] SDP query failed; using cached descriptor")
            elif not live:
                log.warning(
                    "[Classic] No live HID descriptor; dropping link without "
                    "creating a Kindle input device"
                )
                try:
                    await connection.disconnect()
                except Exception:
                    pass
                return False
        elif not self._load_cached_descriptor(session=session):
            await self._query_classic_sdp(session=session)

        self._finalize_classic_hid(session)
        return (session.uhid_device if session else self.uhid_device) is not None

    def _parse_hid_descriptor_list(self, data_element, session=None):
        """Parse HID Descriptor List from SDP."""
        try:
            if hasattr(data_element, 'value'):
                data_element = data_element.value

            if isinstance(data_element, (list, tuple)):
                for descriptor in data_element:
                    if hasattr(descriptor, 'value'):
                        descriptor = descriptor.value

                    if isinstance(descriptor, (list, tuple)) and len(descriptor) >= 2:
                        desc_type = descriptor[0]
                        desc_data = descriptor[1]

                        if hasattr(desc_type, 'value'):
                            desc_type = desc_type.value

                        if desc_type == 0x22:  # Report Descriptor
                            if hasattr(desc_data, 'value'):
                                desc_data = desc_data.value

                            report_map = None
                            if isinstance(desc_data, bytes):
                                report_map = desc_data
                            elif isinstance(desc_data, (list, tuple)):
                                report_map = bytes(desc_data)
                            if report_map is None:
                                return
                            if session:
                                session.report_map = report_map
                            else:
                                self.report_map = report_map
                            log.success(f"[Classic] Got descriptor: {len(report_map)} bytes")
                            return
        except Exception as e:
            log.warning(f"[Classic] Failed to parse descriptor: {e}")

    def _on_classic_interrupt_data(self, pdu: bytes):
        """Handle Classic HID report."""
        if len(pdu) < 1:
            return
        if (pdu[0] >> 4) != Message.MessageType.DATA or \
                (pdu[0] & 0x0F) != Message.ReportType.INPUT_REPORT:
            log.debug(f"[Classic] Ignoring non-input interrupt PDU: 0x{pdu[0]:02X}")
            return
        self._forward_report_for_protocol(Protocol.CLASSIC, pdu[1:])

    def _on_virtual_cable_unplug(self):
        """Handle virtual cable unplug."""
        log.warning("[Classic] Virtual cable unplugged")
        session = (
            self.sessions.get(Protocol.CLASSIC)
            or self._pending_sessions.get(Protocol.CLASSIC)
        )
        self._virtual_cable_unplug_address = (
            session.address if session else self.current_device_address
        )
        if session and session.disconnection_event:
            session.disconnection_event.set()
        if self._disconnection_event:
            self._disconnection_event.set()

    async def _pair_classic(self, address: str) -> bool:
        """Pair with a Classic Bluetooth device."""
        log.info(f"[Classic] Pairing with {address}...")

        try:
            target_address = Address(address, Address.PUBLIC_DEVICE_ADDRESS)
            self.connection = await self.device.connect(
                target_address,
                transport=BT_BR_EDR_TRANSPORT,
                timeout=config.connect_timeout,
            )
            log.success(f"[Classic] Connected to {address}")
        except (asyncio.TimeoutError, BumbleTimeoutError):
            self.last_pair_error = (
                f"Classic connection timeout after {config.connect_timeout}s"
            )
            log.error(f"[Classic] Connection timeout after {config.connect_timeout}s")
            return False
        except Exception as e:
            self.last_pair_error = f"Classic connection failed: {e}"
            log.error(f"[Classic] Connection failed: {e}")
            return False

        self.current_device_address = address
        self.connected_protocol = Protocol.CLASSIC
        self.report_map = None
        self.device_name = None

        link_key_received = asyncio.Event()

        def on_device_link_key(_bd_addr, link_key, key_type):
            log.success(f"[Classic] Link key received: type={key_type}")
            link_key_received.set()

        self.device.host.on('link_key', on_device_link_key)

        try:
            log.info("[Classic] Authenticating...")
            try:
                await asyncio.wait_for(self.connection.authenticate(), timeout=30.0)
                log.success("[Classic] Authentication complete")
            except Exception as e:
                self.last_pair_error = f"Classic authentication failed: {e}"
                log.warning(f"[Classic] Authentication: {e}")

            log.info("[Classic] Waiting for link key...")
            try:
                await asyncio.wait_for(link_key_received.wait(), timeout=5.0)
                log.success("[Classic] Link key saved")
            except asyncio.TimeoutError:
                log.warning("[Classic] Link key event timeout (may already be saved)")

            if not self.connection.is_encrypted:
                log.info("[Classic] Requesting encryption...")
                try:
                    await asyncio.wait_for(
                        self.connection.encrypt(enable=True),
                        timeout=10.0
                    )
                except Exception as e:
                    log.warning(f"[Classic] Encryption: {e}")

            await self._query_classic_sdp(address)

            if not self.report_map:
                log.warning(
                    "[Classic] No HID descriptor in SDP; "
                    "using fallback keyboard descriptor"
                )

            if self.keystore:
                keys = await self.keystore.get(address)
                if keys and keys.link_key:
                    log.success("[Classic] Link key verified")
                else:
                    log.warning("[Classic] Link key not found in keystore!")

            self.device.host.remove_listener('link_key', on_device_link_key)
            return True

        except Exception as e:
            self.last_pair_error = f"Classic pairing failed: {e or repr(e)}"
            log.error(f"[Classic] Pairing failed: {e}")
            self.device.host.remove_listener('link_key', on_device_link_key)
            if self.connection:
                try:
                    await self.connection.disconnect()
                except Exception:
                    pass
                self.connection = None
            return False

    async def _query_classic_sdp(self, address: str = None, session=None) -> Optional[bool]:
        """Query SDP for the HID descriptor and cache it.

        Returns True when a descriptor was found, False when the peer answered
        without one, and None when the query itself failed.
        """
        connection = session.connection if session else self.connection
        if not connection:
            return None

        address = address or (session.address if session else self.current_device_address)

        log.info("[Classic] Querying SDP...")
        try:
            sdp_client = SDPClient(connection)
            await asyncio.wait_for(sdp_client.connect(), timeout=5.0)
            try:
                result = await asyncio.wait_for(
                    sdp_client.search_attributes(
                        [BT_HUMAN_INTERFACE_DEVICE_SERVICE],
                        [0x0100, 0x0206]
                    ),
                    timeout=10.0
                )
            finally:
                try:
                    await sdp_client.disconnect()
                except Exception:
                    pass
        except Exception as e:
            log.warning(f"[Classic] SDP query failed: {e}")
            return None

        try:
            for record in result or []:
                for attr in record:
                    if hasattr(attr, 'id') and attr.id == 0x0206:
                        self._parse_hid_descriptor_list(attr.value, session=session)
                    elif hasattr(attr, 'id') and attr.id == 0x0100:
                        try:
                            name = attr.value.value
                            if isinstance(name, bytes):
                                name = name.decode('utf-8', errors='replace')
                            if session:
                                session.device_name = str(name)
                            else:
                                self.device_name = str(name)
                        except Exception:
                            pass
        except Exception as e:
            log.warning(f"[Classic] SDP parse failed: {e}")

        report_map = session.report_map if session else self.report_map
        if not report_map:
            return False
        device_name = session.device_name if session else self.device_name
        self.device_cache.save(address, {
            'report_map': report_map.hex(),
            'device_name': device_name or 'Unknown'
        })
        log.success(f"[Classic] Cached descriptor ({len(report_map)} bytes)")
        return True

    async def _continue_classic_after_pairing(self):
        """Continue Classic connection after pairing."""
        self.hid_host = BumbleHIDHost(self.device)
        self.hid_host.on(BumbleHIDHost.EVENT_INTERRUPT_DATA, self._on_classic_interrupt_data)
        self.hid_host.on(BumbleHIDHost.EVENT_VIRTUAL_CABLE_UNPLUG, self._on_virtual_cable_unplug)
        log.info("[Classic] HID Host created")

        self.hid_host.on_device_connection(self.connection)

        log.info("[Classic] Connecting to HID control channel...")
        try:
            await asyncio.wait_for(self.hid_host.connect_control_channel(), timeout=5.0)
            log.success("[Classic] HID control channel connected")
        except Exception as e:
            log.warning(f"[Classic] Control channel: {e}")

        log.info("[Classic] Connecting to HID interrupt channel...")
        try:
            await asyncio.wait_for(self.hid_host.connect_interrupt_channel(), timeout=5.0)
            log.success("[Classic] HID interrupt channel connected")
        except Exception as e:
            log.warning(f"[Classic] Interrupt channel: {e}")

        if not self.hid_host.l2cap_intr_channel:
            log.error("[Classic] Failed to connect HID interrupt channel")
            return

        self._classic_set_report_protocol()
        self._finalize_classic_hid()
