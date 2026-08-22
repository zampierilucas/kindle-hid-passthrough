#!/usr/bin/env python3
"""Classic Bluetooth HID handler mixin for HIDHost."""

import asyncio

from bumble.core import BT_BR_EDR_TRANSPORT, BT_HUMAN_INTERFACE_DEVICE_SERVICE, InvalidStateError, TimeoutError as BumbleTimeoutError
from bumble.hci import (
    Address,
    HCI_DIFFERENT_TRANSACTION_COLLISION_ERROR,
    HCI_LMP_ERROR_TRANSACTION_COLLISION_OR_LL_PROCEDURE_COLLISION_ERROR,
    HCI_Error,
    HCI_Write_Scan_Enable_Command,
    Role,
)
from bumble.hid import HID_CONTROL_PSM, HID_INTERRUPT_PSM, Message, SetProtocolMessage
from bumble.l2cap import ClassicChannelSpec
from bumble.sdp import Client as SDPClient

from config import Protocol, config, normalize_addr, clean_device_name
from logging_utils import errstr, log

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


CLASSIC_PEER_CHANNEL_WAIT = 5.0

COLLISION_ERRORS = (
    HCI_LMP_ERROR_TRANSACTION_COLLISION_OR_LL_PROCEDURE_COLLISION_ERROR,
    HCI_DIFFERENT_TRANSACTION_COLLISION_ERROR,
)


def _is_collision(e: BaseException) -> bool:
    return isinstance(e, HCI_Error) and e.error_code in COLLISION_ERRORS


class ClassicHIDChannels:
    """HID L2CAP channel pair (control 0x11, interrupt 0x13) for one connection."""

    def __init__(self, connection, on_interrupt_data, on_virtual_cable_unplug):
        self.connection = connection
        self.ctrl_channel = None
        self.intr_channel = None
        self._on_interrupt_data = on_interrupt_data
        self._on_virtual_cable_unplug = on_virtual_cable_unplug

    def attach(self, channel):
        """Adopt an incoming channel opened by the peer."""
        if channel.psm == HID_CONTROL_PSM:
            channel.sink = self._on_ctrl_pdu
            self.ctrl_channel = channel
        else:
            channel.sink = self._on_intr_pdu
            self.intr_channel = channel
        channel.on(channel.EVENT_CLOSE, lambda: self._on_channel_close(channel))

    async def connect_control_channel(self):
        channel = await self.connection.create_l2cap_channel(
            ClassicChannelSpec(HID_CONTROL_PSM))
        channel.sink = self._on_ctrl_pdu
        channel.on(channel.EVENT_CLOSE, lambda: self._on_channel_close(channel))
        self.ctrl_channel = channel

    async def connect_interrupt_channel(self):
        channel = await self.connection.create_l2cap_channel(
            ClassicChannelSpec(HID_INTERRUPT_PSM))
        channel.sink = self._on_intr_pdu
        channel.on(channel.EVENT_CLOSE, lambda: self._on_channel_close(channel))
        self.intr_channel = channel

    def _on_channel_close(self, channel):
        if channel is self.ctrl_channel:
            self.ctrl_channel = None
        elif channel is self.intr_channel:
            self.intr_channel = None

    def set_report_protocol(self):
        """Send HIDP SET_PROTOCOL(Report) on the control channel."""
        self.ctrl_channel.write(
            bytes(SetProtocolMessage(protocol_mode=Message.ProtocolMode.REPORT_PROTOCOL)))

    async def disconnect(self):
        """Close both channels, interrupt first, 1s cap each."""
        for attr in ('intr_channel', 'ctrl_channel'):
            channel = getattr(self, attr)
            if channel is None:
                continue
            setattr(self, attr, None)
            try:
                await asyncio.wait_for(channel.disconnect(), timeout=1.0)
            except Exception:
                pass

    def _on_ctrl_pdu(self, pdu):
        if len(pdu) < 1:
            return
        message_type = pdu[0] >> 4
        param = pdu[0] & 0x0F
        if message_type == Message.MessageType.HANDSHAKE:
            log.debug(f"[Classic] HID handshake: 0x{param:X}")
        elif message_type == Message.MessageType.CONTROL and \
                param == Message.ControlCommand.VIRTUAL_CABLE_UNPLUG:
            self._on_virtual_cable_unplug()

    def _on_intr_pdu(self, pdu):
        self._on_interrupt_data(pdu)


class ClassicMixin:
    """Classic Bluetooth methods for HIDHost."""

    def _ensure_classic_psm_servers(self):
        """Register the HID L2CAP servers once per bumble device."""
        if self._classic_psm_registered:
            return
        for psm in (HID_CONTROL_PSM, HID_INTERRUPT_PSM):
            self.device.create_l2cap_server(
                ClassicChannelSpec(psm), self._on_classic_l2cap_channel)
        self._classic_psm_registered = True

    def _on_classic_l2cap_channel(self, channel):
        """Route an incoming HID L2CAP channel to its connection's session."""
        def on_open():
            addr = normalize_addr(str(channel.connection.peer_address))
            session = self.sessions.get(addr)
            if session is None or session.channels is None or \
                    session.channels.connection is not channel.connection:
                log.warning(f"[Classic] Unexpected HID channel from "
                            f"{channel.connection.peer_address}")
                return
            session.channels.attach(channel)
        channel.on(channel.EVENT_OPEN, on_open)

    async def _run_classic_handler(self):
        """Handle Classic Bluetooth connections."""
        if hasattr(self, '_classic_connection_listener') and self._classic_connection_listener:
            try:
                self.device.remove_listener('connection', self._classic_connection_listener)
            except Exception:
                pass
            self._classic_connection_listener = None

        self._ensure_classic_psm_servers()
        log.info(f"[Classic] HID Host ready (PSM 0x{HID_CONTROL_PSM:04X}, 0x{HID_INTERRUPT_PSM:04X})")

        log.info("[Classic] Enabling Page Scan...")
        await self.device.host.send_command(
            HCI_Write_Scan_Enable_Command(scan_enable=0x02),
            check_result=True
        )

        def on_connection_event(connection):
            is_classic = (hasattr(connection, 'transport')
                          and connection.transport == BT_BR_EDR_TRANSPORT) \
                          or not hasattr(connection, 'transport')
            if not is_classic:
                return

            addr_str = str(connection.peer_address)
            if not self._is_classic_allowed(addr_str):
                log.warning(f"[Classic] Rejecting {addr_str} (not allowed)")
                self._track_task(asyncio.create_task(self._reject_connection(connection)))
                return

            addr = normalize_addr(addr_str)
            old = self.sessions.get(addr)
            session = self._new_session(addr, Protocol.CLASSIC, connection)
            session.channels = ClassicHIDChannels(
                connection,
                lambda pdu: self._on_classic_interrupt_data(session, pdu),
                lambda: self._on_virtual_cable_unplug(session))
            self._register_session(session)
            session.setup_task = self._track_task(asyncio.create_task(
                self._run_session_setup(
                    session, self._setup_classic_session(session, old))))

        self._classic_connection_listener = on_connection_event
        self.device.on('connection', on_connection_event)

        await self._classic_active_connect_loop()

    async def _setup_classic_session(self, session, old=None):
        """Authenticate, open HID channels, and finalize one Classic session."""
        connection = session.connection
        log.info(f"[Classic] Device connected: {self._format_device(session.raw_address)}")

        if old is not None:
            await self._teardown_session(old)

        is_peripheral = connection.role != Role.CENTRAL
        peer_driving = False

        if is_peripheral:
            log.info("[Classic] Requesting role switch to central...")
            try:
                await asyncio.wait_for(connection.switch_role(Role.CENTRAL), timeout=5.0)
                log.success("[Classic] Role switch complete, now central")
                is_peripheral = False
            except Exception as e:
                log.warning(f"[Classic] Role switch failed: {errstr(e)}")
                peer_driving = _is_collision(e)

        if is_peripheral or peer_driving:
            log.info("[Classic] Peer is driving security, standing by")
        elif not connection.is_encrypted:
            log.info("[Classic] Restoring bonding (authenticate + encrypt)...")
            try:
                if not connection.authenticated:
                    await asyncio.wait_for(connection.authenticate(), timeout=5.0)
                await asyncio.wait_for(connection.encrypt(enable=True), timeout=5.0)
                log.success("[Classic] Bonding restored")
            except Exception as e:
                log.warning(f"[Classic] Bonding restore failed: {errstr(e)}")
                peer_driving = _is_collision(e)
                if peer_driving:
                    log.info("[Classic] Security collision, the peer is driving; standing by")

        channels = session.channels

        if (is_peripheral or peer_driving) and not channels.intr_channel:
            log.info("[Classic] Waiting for the peer to open the HID channels...")
            loop = asyncio.get_running_loop()
            deadline = loop.time() + CLASSIC_PEER_CHANNEL_WAIT
            while loop.time() < deadline and not channels.intr_channel:
                await asyncio.sleep(0.05)
            if channels.intr_channel:
                log.success("[Classic] Peer opened the HID channels")
            else:
                log.info("[Classic] Peer did not open them, paging outward")

        if not channels.ctrl_channel:
            log.info("[Classic] Connecting to HID control channel...")
            try:
                await asyncio.wait_for(channels.connect_control_channel(), timeout=5.0)
                log.success("[Classic] HID control channel connected")
            except Exception as e:
                log.warning(f"[Classic] Control channel: {errstr(e)}")

        if not channels.intr_channel:
            log.info("[Classic] Connecting to HID interrupt channel...")
            try:
                await asyncio.wait_for(channels.connect_interrupt_channel(), timeout=5.0)
                log.success("[Classic] HID interrupt channel connected")
            except Exception as e:
                log.warning(f"[Classic] Interrupt channel: {errstr(e)}")

        if not channels.intr_channel:
            raise InvalidStateError("[Classic] HID channels not opened by peer")

        self._classic_set_report_protocol(session)

        if not self._load_cached_descriptor(session):
            await self._query_classic_sdp(session)

        self._finalize_classic_hid(session)
        log.success(f"[Classic] {self._format_device(session.address)} receiving HID reports")

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

    async def _classic_active_connect_loop(self):
        """Actively page configured Classic devices lacking a session."""
        await asyncio.sleep(self.ACTIVE_DELAY)

        attempt = 0
        while True:
            attempt += 1
            addresses = [d.address for d in self.classic_devices if d.address != '*']
            for addr in addresses:
                if normalize_addr(addr) in self.sessions:
                    continue

                log.info(f"[Classic] Attempt {attempt}: {self._format_device(addr)}")

                target = Address(addr, Address.PUBLIC_DEVICE_ADDRESS)
                await self._radio_lock.acquire()
                connect_task = asyncio.create_task(
                    self.device.connect(target, transport=BT_BR_EDR_TRANSPORT)
                )
                # The finally below guarantees connect_task is cancelled and
                # awaited on every exit path, including suspend cancellation,
                # otherwise it leaks and asyncio logs an unretrieved exception
                # when bumble eventually raises HCI_PAGE_TIMEOUT.
                try:
                    timed_out = True
                    for _ in range(self.ACTIVE_CONNECT_TIMEOUT):
                        done, _ = await asyncio.wait([connect_task], timeout=0.5)
                        if done:
                            timed_out = False
                            break

                    if timed_out:
                        log.info(f"[Classic] {addr} timed out")
                        await asyncio.sleep(3.0)
                        continue

                    await connect_task

                except Exception as e:
                    msg = str(e)
                    if "CONNECTION_ALREADY_EXISTS" in msg:
                        log.info("[Classic] Peer paged us first; yielding to incoming link")
                        await asyncio.sleep(2.0)
                    elif "DISALLOWED" in msg or "PENDING" in msg:
                        log.warning("[Classic] HCI busy, waiting...")
                        await asyncio.sleep(5.0)
                    else:
                        log.info(f"[Classic] Connect failed: {e}")
                        await asyncio.sleep(2.0)

                finally:
                    if not connect_task.done():
                        connect_task.cancel()
                    try:
                        await connect_task
                    except (asyncio.CancelledError, Exception):
                        pass
                    self._radio_lock.release()

            # Page scan catches powered-on devices instantly; active paging is
            # the fallback, so with live links yield the radio to them and wifi.
            if self.sessions:
                await asyncio.sleep(self.ACTIVE_RETRY_INTERVAL_CONNECTED)
            else:
                await asyncio.sleep(self.ACTIVE_RETRY_INTERVAL)

    def _classic_set_report_protocol(self, session):
        """Send HIDP SET_PROTOCOL(Report) on the control channel."""
        channels = session.channels
        if not channels or not channels.ctrl_channel:
            return
        try:
            channels.set_report_protocol()
            log.info("[Classic] Sent SET_PROTOCOL (Report)")
        except Exception as e:
            log.warning(f"[Classic] SET_PROTOCOL failed: {e}")

    def _finalize_classic_hid(self, session):
        """Apply fallback descriptor if needed and create UHID."""
        if not session.report_map:
            session.report_map = FALLBACK_HID_DESCRIPTOR
            log.warning("[Classic] Using fallback descriptor")
        self._create_uhid_device(session)

    def _parse_hid_descriptor_list(self, session, data_element):
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

                            if isinstance(desc_data, bytes):
                                session.report_map = desc_data
                            elif isinstance(desc_data, (list, tuple)):
                                session.report_map = bytes(desc_data)

                            log.success(f"[Classic] Got descriptor: {len(session.report_map)} bytes")
                            return
        except Exception as e:
            log.warning(f"[Classic] Failed to parse descriptor: {e}")

    def _on_classic_interrupt_data(self, session, pdu: bytes):
        """Handle Classic HID report."""
        if len(pdu) < 1:
            return
        if (pdu[0] >> 4) != Message.MessageType.DATA or \
                (pdu[0] & 0x0F) != Message.ReportType.INPUT_REPORT:
            log.debug(f"[Classic] Ignoring non-input interrupt PDU: 0x{pdu[0]:02X}")
            return
        self._forward_report(session, pdu[1:])

    def _on_virtual_cable_unplug(self, session):
        """Handle virtual cable unplug."""
        log.warning(f"[Classic] Virtual cable unplugged by {session.address}")
        session.vc_unplug = True
        self._track_task(asyncio.create_task(self._teardown_session(session)))

    async def _pair_classic(self, address: str) -> bool:
        """Pair with a Classic Bluetooth device."""
        log.info(f"[Classic] Pairing with {address}...")

        try:
            target_address = Address(address, Address.PUBLIC_DEVICE_ADDRESS)
            connection = await self.device.connect(
                target_address,
                transport=BT_BR_EDR_TRANSPORT,
                timeout=config.connect_timeout,
            )
            log.success(f"[Classic] Connected to {address}")
        except (asyncio.TimeoutError, BumbleTimeoutError):
            log.error(f"[Classic] Connection timeout after {config.connect_timeout}s")
            return False
        except Exception as e:
            log.error(f"[Classic] Connection failed: {e}")
            return False

        session = self._new_session(normalize_addr(address), Protocol.CLASSIC, connection)
        self._pairing_session = session

        link_key_received = asyncio.Event()

        def on_device_link_key(_bd_addr, link_key, key_type):
            log.success(f"[Classic] Link key received: type={key_type}")
            link_key_received.set()

        self.device.host.on('link_key', on_device_link_key)

        try:
            log.info("[Classic] Authenticating...")
            try:
                await asyncio.wait_for(connection.authenticate(), timeout=30.0)
                log.success("[Classic] Authentication complete")
            except Exception as e:
                log.warning(f"[Classic] Authentication: {errstr(e)}")

            log.info("[Classic] Waiting for link key...")
            try:
                await asyncio.wait_for(link_key_received.wait(), timeout=5.0)
                log.success("[Classic] Link key saved")
            except asyncio.TimeoutError:
                log.warning("[Classic] Link key event timeout (may already be saved)")

            if not connection.is_encrypted:
                log.info("[Classic] Requesting encryption...")
                try:
                    await asyncio.wait_for(
                        connection.encrypt(enable=True),
                        timeout=10.0
                    )
                except Exception as e:
                    log.warning(f"[Classic] Encryption: {errstr(e)}")

            await self._query_classic_sdp(session)

            if self.keystore:
                keys = await self.keystore.get(str(connection.peer_address))
                if keys and keys.link_key:
                    log.success("[Classic] Link key verified")
                else:
                    log.warning("[Classic] Link key not found in keystore!")

            self.device.host.remove_listener('link_key', on_device_link_key)
            return True

        except Exception as e:
            log.error(f"[Classic] Pairing failed: {e}")
            self.device.host.remove_listener('link_key', on_device_link_key)
            await session.cleanup()
            self._pairing_session = None
            return False

    async def _query_classic_sdp(self, session):
        """Query SDP for HID descriptor and cache it."""
        if not session.is_alive():
            return

        log.info("[Classic] Querying SDP...")
        try:
            sdp_client = SDPClient(session.connection)
            await asyncio.wait_for(sdp_client.connect(), timeout=5.0)

            result = await asyncio.wait_for(
                sdp_client.search_attributes(
                    [BT_HUMAN_INTERFACE_DEVICE_SERVICE],
                    [0x0100, 0x0206]
                ),
                timeout=10.0
            )

            if result:
                for record in result:
                    for attr in record:
                        if hasattr(attr, 'id') and attr.id == 0x0206:
                            self._parse_hid_descriptor_list(session, attr.value)
                        elif hasattr(attr, 'id') and attr.id == 0x0100:
                            try:
                                name = clean_device_name(attr.value.value)
                                if name:
                                    session.name = name
                            except Exception:
                                pass

            await sdp_client.disconnect()

            if session.report_map:
                self.device_cache.save(session.address, {
                    'report_map': session.report_map.hex(),
                    'device_name': session.name or 'Unknown'
                })
                log.success(f"[Classic] Cached descriptor ({len(session.report_map)} bytes)")
        except Exception as e:
            log.warning(f"[Classic] SDP query failed: {e}")

    async def _continue_classic_after_pairing(self, session):
        """Continue Classic connection after pairing."""
        self._ensure_classic_psm_servers()
        session.channels = ClassicHIDChannels(
            session.connection,
            lambda pdu: self._on_classic_interrupt_data(session, pdu),
            lambda: self._on_virtual_cable_unplug(session))
        channels = session.channels
        log.info("[Classic] HID Host created")

        log.info("[Classic] Connecting to HID control channel...")
        try:
            await asyncio.wait_for(channels.connect_control_channel(), timeout=5.0)
            log.success("[Classic] HID control channel connected")
        except Exception as e:
            log.warning(f"[Classic] Control channel: {errstr(e)}")

        log.info("[Classic] Connecting to HID interrupt channel...")
        try:
            await asyncio.wait_for(channels.connect_interrupt_channel(), timeout=5.0)
            log.success("[Classic] HID interrupt channel connected")
        except Exception as e:
            log.warning(f"[Classic] Interrupt channel: {errstr(e)}")

        if not channels.intr_channel:
            log.error("[Classic] Failed to connect HID interrupt channel")
            return

        self._classic_set_report_protocol(session)
        self._finalize_classic_hid(session)
