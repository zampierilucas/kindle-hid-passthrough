import asyncio
import os
import sys
import tempfile
import types
import unittest


PROJECT_ROOT = os.path.dirname(os.path.dirname(__file__))
MODULE_ROOT = os.path.join(PROJECT_ROOT, "kindle_hid_passthrough")
if MODULE_ROOT not in sys.path:
    sys.path.insert(0, MODULE_ROOT)


def install_bumble_stubs():
    bumble = types.ModuleType("bumble")
    sys.modules.setdefault("bumble", bumble)

    core = types.ModuleType("bumble.core")

    class InvalidStateError(Exception):
        pass

    class BumbleTimeoutError(Exception):
        pass

    class AdvertisingData:
        COMPLETE_LOCAL_NAME = 0x09
        SHORTENED_LOCAL_NAME = 0x08
        APPEARANCE = 0x19
        COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS = 0x03
        INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS = 0x02

    class DeviceClass:
        @staticmethod
        def split_class_of_device(class_of_device):
            return (0, (class_of_device >> 8) & 0x1F, 0)

        @staticmethod
        def major_device_class_name(major_class):
            return {
                0x02: "Phone",
                0x05: "Peripheral",
            }.get(major_class, "Unknown")

    core.InvalidStateError = InvalidStateError
    core.TimeoutError = BumbleTimeoutError
    core.BT_BR_EDR_TRANSPORT = 1
    core.BT_LE_TRANSPORT = 2
    core.BT_HUMAN_INTERFACE_DEVICE_SERVICE = 0x1124
    core.AdvertisingData = AdvertisingData
    core.DeviceClass = DeviceClass
    sys.modules.setdefault("bumble.core", core)

    hci = types.ModuleType("bumble.hci")

    class Address:
        PUBLIC_DEVICE_ADDRESS = 0
        RANDOM_DEVICE_ADDRESS = 1
        ANY = "00:00:00:00:00:00"

        def __init__(self, value, address_type=PUBLIC_DEVICE_ADDRESS):
            self.value = value
            self.address_type = address_type
            self.is_resolvable = False

        def __str__(self):
            return str(self.value)

    class OwnAddressType:
        PUBLIC = 0

    class PrivacyMode:
        DEVICE_PRIVACY_MODE = 0

    class HCI_LE_Set_Privacy_Mode_Command:
        def __init__(self, **_kwargs):
            pass

    HCI_LE_Set_Privacy_Mode_Command.PrivacyMode = PrivacyMode

    class Command:
        def __init__(self, **_kwargs):
            pass

    hci.Address = Address
    hci.OwnAddressType = OwnAddressType
    hci.HCI_LE_SET_PRIVACY_MODE_COMMAND = object()
    hci.HCI_LE_Set_Privacy_Mode_Command = HCI_LE_Set_Privacy_Mode_Command
    hci.HCI_Write_Class_Of_Device_Command = Command
    hci.HCI_Write_Local_Name_Command = Command
    hci.HCI_LE_Add_Device_To_Filter_Accept_List_Command = Command
    hci.HCI_LE_Clear_Filter_Accept_List_Command = Command
    hci.HCI_LE_Create_Connection_Cancel_Command = Command
    hci.HCI_LE_Create_Connection_Command = Command
    hci.HCI_Write_Scan_Enable_Command = Command
    hci.HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND = object()

    class LeFeatureMask:
        LL_PRIVACY = object()

    hci.LeFeatureMask = LeFeatureMask
    sys.modules.setdefault("bumble.hci", hci)

    device = types.ModuleType("bumble.device")

    class Device:
        EVENT_CONNECTION = "connection"
        EVENT_CONNECTION_FAILURE = "connection_failure"

        @classmethod
        def with_hci(cls, *_args, **_kwargs):
            return cls()

    class Peer:
        def __init__(self, connection):
            self.connection = connection
            self.services = []

    device.Device = Device
    device.Peer = Peer
    sys.modules.setdefault("bumble.device", device)

    gatt = types.ModuleType("bumble.gatt")
    gatt.GATT_DEVICE_NAME_CHARACTERISTIC = "device-name"
    gatt.GATT_GENERIC_ACCESS_SERVICE = "gap"
    gatt.GATT_HID_CONTROL_POINT_CHARACTERISTIC = "hid-cp"
    gatt.GATT_HUMAN_INTERFACE_DEVICE_SERVICE = "hid"
    gatt.GATT_PROTOCOL_MODE_CHARACTERISTIC = "protocol-mode"
    gatt.GATT_REPORT_CHARACTERISTIC = "report"
    gatt.GATT_REPORT_MAP_CHARACTERISTIC = "report-map"
    gatt.GATT_REPORT_REFERENCE_DESCRIPTOR = "report-reference"
    sys.modules.setdefault("bumble.gatt", gatt)

    hid = types.ModuleType("bumble.hid")

    class Message:
        class MessageType:
            DATA = 0x0A

        class ReportType:
            INPUT_REPORT = 0x01

        class ProtocolMode:
            REPORT_PROTOCOL = 1

    class BumbleHIDHost:
        EVENT_INTERRUPT_DATA = "interrupt"
        EVENT_VIRTUAL_CABLE_UNPLUG = "unplug"

    hid.HID_CONTROL_PSM = 0x11
    hid.HID_INTERRUPT_PSM = 0x13
    hid.Message = Message
    hid.Host = BumbleHIDHost
    sys.modules.setdefault("bumble.hid", hid)

    sdp = types.ModuleType("bumble.sdp")

    class SDPClient:
        pass

    sdp.Client = SDPClient
    sys.modules.setdefault("bumble.sdp", sdp)

    keys = types.ModuleType("bumble.keys")

    class JsonKeyStore:
        def __init__(self, *_args, **_kwargs):
            pass

    keys.JsonKeyStore = JsonKeyStore
    sys.modules.setdefault("bumble.keys", keys)

    pairing = types.ModuleType("bumble.pairing")

    class PairingDelegate:
        DISPLAY_OUTPUT_AND_YES_NO_INPUT = object()

        def __init__(self, *_args, **_kwargs):
            pass

    class PairingConfig:
        def __init__(self, **_kwargs):
            pass

    pairing.PairingConfig = PairingConfig
    pairing.PairingDelegate = PairingDelegate
    sys.modules.setdefault("bumble.pairing", pairing)

    transport = types.ModuleType("bumble.transport")

    async def open_transport(*_args, **_kwargs):
        raise RuntimeError("not available in tests")

    transport.open_transport = open_transport
    sys.modules.setdefault("bumble.transport", transport)


install_bumble_stubs()

from config import Protocol, config  # noqa: E402
from daemon import HIDDaemon  # noqa: E402
from host import DeviceConfig, HIDHost  # noqa: E402


class FakeConnection:
    def __init__(self):
        self.handle = 1
        self.is_disconnected = False

    async def disconnect(self):
        self.is_disconnected = True
        self.handle = None


class DummyFuture:
    def __init__(self):
        self.result = None

    def done(self):
        return self.result is not None

    def set_result(self, result):
        self.result = result


class FakeUhidDevice:
    def __init__(self):
        self.inputs = []

    def send_input(self, data):
        self.inputs.append(data)


class FakeHidHost:
    l2cap_intr_channel = object()


class HostDisconnectionTests(unittest.TestCase):
    def make_host(self):
        cache_dir = tempfile.mkdtemp(prefix="hid-host-test-")
        config.cache_dir = cache_dir
        config.pairing_keys_file = os.path.join(cache_dir, "pairing_keys.json")
        host = HIDHost()
        host._disconnection_event = asyncio.Event()
        host._protocol_disconnection_events = {
            Protocol.CLASSIC: asyncio.Event(),
            Protocol.BLE: asyncio.Event(),
        }
        host._connection_future = DummyFuture()
        return host

    def test_session_uses_own_event_and_protocol_loop_owns_reconnect(self):
        host = self.make_host()
        host.ble_devices = [
            DeviceConfig("AA:BB:CC:DD:EE:FF", Protocol.BLE, "Keyboard")
        ]
        session = host._new_session(
            Protocol.BLE,
            "AA:BB:CC:DD:EE:FF",
            FakeConnection(),
        )

        self.assertIsNot(
            session.disconnection_event,
            host._protocol_disconnection_events[Protocol.BLE],
        )

        host._record_session(session)
        host._on_session_disconnection(session, reason=19)

        self.assertTrue(session.disconnection_event.is_set())
        self.assertFalse(host._protocol_disconnection_events[Protocol.BLE].is_set())
        self.assertFalse(host._disconnection_event.is_set())
        self.assertNotIn(Protocol.BLE, host.sessions)

    def test_no_configured_devices_stops_host_when_last_session_drops(self):
        host = self.make_host()
        session = host._new_session(
            Protocol.BLE,
            "AA:BB:CC:DD:EE:FF",
            FakeConnection(),
        )
        host._record_session(session)

        host._on_session_disconnection(session, reason=19)

        self.assertTrue(host._disconnection_event.is_set())

    def test_pending_session_disconnect_marks_only_that_attempt(self):
        host = self.make_host()
        host.ble_devices = [
            DeviceConfig("AA:BB:CC:DD:EE:FF", Protocol.BLE, "Keyboard")
        ]
        session = host._new_session(
            Protocol.BLE,
            "AA:BB:CC:DD:EE:FF",
            FakeConnection(),
        )
        host._track_pending_session(session)

        host._on_session_disconnection(session, reason=19)

        self.assertTrue(session.disconnection_event.is_set())
        self.assertNotIn(Protocol.BLE, host._pending_sessions)
        self.assertFalse(host._disconnection_event.is_set())


class ClassicDescriptorFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_classic_uses_cached_descriptor_when_live_sdp_has_no_descriptor(self):
        old_require = config.classic_require_live_descriptor
        config.classic_require_live_descriptor = True
        try:
            cache_dir = tempfile.mkdtemp(prefix="hid-host-test-")
            config.cache_dir = cache_dir
            config.pairing_keys_file = os.path.join(cache_dir, "pairing_keys.json")
            host = HIDHost()
            session = host._new_session(
                Protocol.CLASSIC,
                "AA:BB:CC:DD:EE:FF",
                FakeConnection(),
                hid_host=FakeHidHost(),
            )

            async def query_sdp(*_args, **_kwargs):
                return False

            def load_cached(*_args, **_kwargs):
                session.report_map = b"\x05\x01"
                return True

            def finalize(classic_session=None):
                classic_session.uhid_device = FakeUhidDevice()

            host._query_classic_sdp = query_sdp
            host._load_cached_descriptor = load_cached
            host._finalize_classic_hid = finalize

            connected = await host._handle_classic_connection(session)

            self.assertTrue(connected)
            self.assertFalse(session.connection.is_disconnected)
            self.assertEqual(b"\x05\x01", session.report_map)
        finally:
            config.classic_require_live_descriptor = old_require


class BleReportForwardingTests(unittest.TestCase):
    def make_host(self):
        cache_dir = tempfile.mkdtemp(prefix="hid-host-test-")
        config.cache_dir = cache_dir
        config.pairing_keys_file = os.path.join(cache_dir, "pairing_keys.json")
        return HIDHost()

    def test_ble_report_id_zero_forwards_payload_without_synthetic_prefix(self):
        host = self.make_host()
        session = host._new_session(
            Protocol.BLE,
            "AA:BB:CC:DD:EE:FF",
            FakeConnection(),
        )
        session.uhid_device = FakeUhidDevice()

        host._on_ble_hid_report(b"\x00\x00\x04\x00\x00\x00\x00\x00", 0, session)

        self.assertEqual(
            [b"\x00\x00\x04\x00\x00\x00\x00\x00"],
            session.uhid_device.inputs,
        )

    def test_ble_numbered_report_preserves_report_id_prefix(self):
        host = self.make_host()
        session = host._new_session(
            Protocol.BLE,
            "AA:BB:CC:DD:EE:FF",
            FakeConnection(),
        )
        session.uhid_device = FakeUhidDevice()

        host._on_ble_hid_report(b"\x00\x00\x04\x00\x00\x00\x00\x00", 3, session)

        self.assertEqual(
            [b"\x03\x00\x00\x04\x00\x00\x00\x00\x00"],
            session.uhid_device.inputs,
        )


class KeyboardReportSerializationTests(unittest.TestCase):
    def setUp(self):
        self._old_serialize = config.classic_serialize_keyboard_reports
        config.classic_serialize_keyboard_reports = True

    def tearDown(self):
        config.classic_serialize_keyboard_reports = self._old_serialize

    def make_host_and_session(self):
        cache_dir = tempfile.mkdtemp(prefix="hid-host-test-")
        config.cache_dir = cache_dir
        config.pairing_keys_file = os.path.join(cache_dir, "pairing_keys.json")
        host = HIDHost()
        session = host._new_session(
            Protocol.CLASSIC,
            "AA:BB:CC:DD:EE:FF",
            FakeConnection(),
        )
        session.uhid_device = FakeUhidDevice()
        return host, session

    def test_classic_keyboard_overlap_is_serialized_into_key_taps(self):
        host, session = self.make_host_and_session()

        host._forward_report_for_session(
            session,
            b"\x01\x00\x00\x04\x00\x00\x00\x00",
        )
        host._forward_report_for_session(
            session,
            b"\x01\x00\x00\x04\x05\x00\x00\x00",
        )

        self.assertEqual(
            [
                b"\x01\x00\x00\x04\x00\x00\x00\x00",
                b"\x01\x00\x00\x00\x00\x00\x00\x00",
                b"\x01\x00\x00\x05\x00\x00\x00\x00",
                b"\x01\x00\x00\x00\x00\x00\x00\x00",
            ],
            session.uhid_device.inputs,
        )

    def test_classic_keyboard_serializer_preserves_modifier_for_tap(self):
        host, session = self.make_host_and_session()

        host._forward_report_for_session(
            session,
            b"\x01\x02\x00\x04\x00\x00\x00\x00",
        )

        self.assertEqual(
            [
                b"\x01\x02\x00\x04\x00\x00\x00\x00",
                b"\x01\x00\x00\x00\x00\x00\x00\x00",
            ],
            session.uhid_device.inputs,
        )

    def test_classic_non_keyboard_report_is_forwarded_unchanged(self):
        host, session = self.make_host_and_session()

        host._forward_report_for_session(session, b"\x03\x01\x02")

        self.assertEqual([b"\x03\x01\x02"], session.uhid_device.inputs)


class DaemonPowerLifecycleTests(unittest.IsolatedAsyncioTestCase):
    async def test_operation_resume_is_deferred_during_power_recovery(self):
        daemon = HIDDaemon()
        daemon._suspended = True
        daemon._suspend_reason = "operation"
        daemon._power_blocked = True

        await daemon.resume(reason="operation")

        self.assertTrue(daemon._suspended)
        self.assertTrue(daemon._resume_after_power)
        self.assertEqual("operation", daemon._resume_after_power_reason)

        await daemon.resume(reason="power")

        self.assertFalse(daemon._suspended)
        self.assertFalse(daemon._resume_after_power)

    async def test_power_resume_does_not_override_manual_suspend(self):
        daemon = HIDDaemon()
        daemon._suspended = True
        daemon._suspend_reason = "manual"
        daemon._power_blocked = True

        await daemon.resume(reason="power")

        self.assertTrue(daemon._suspended)
        self.assertFalse(daemon._resume_after_power)

    async def test_user_resume_after_manual_suspend_waits_for_power_recovery(self):
        daemon = HIDDaemon()
        daemon._suspended = True
        daemon._suspend_reason = "manual"
        daemon._power_blocked = True

        await daemon.resume(reason="user")

        self.assertTrue(daemon._suspended)
        self.assertTrue(daemon._resume_after_power)
        self.assertEqual("user", daemon._resume_after_power_reason)

        await daemon.resume(reason="power")

        self.assertFalse(daemon._suspended)


if __name__ == "__main__":
    unittest.main()
