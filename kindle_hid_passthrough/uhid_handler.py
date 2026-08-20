#!/usr/bin/env python3
"""Virtual HID devices via Linux UHID (/dev/uhid)."""

import logging
import os
import struct
from typing import Optional

__all__ = ['UHIDDevice', 'UHIDError', 'Bus', 'sanitize_digitizer']

logger = logging.getLogger(__name__)

def sanitize_digitizer(descriptor: bytes) -> bytes:
    """Make a Digitizer usable on the Kindle instead of discarding it.

    Three fields are turned into padding rather than removed, so the report
    layout still matches what the device sends and only the events change:
    Tip Pressure, because EV_ABS:ABS_PRESSURE is what KOReader's gyro decoders
    read as a screen rotation (issue #83), and Contact Identifier and Contact
    Count, because the kernel has no CONFIG_HID_MULTITOUCH to parse them and
    drops the whole device when they are present.

    What is left is a single-touch digitizer, which hid-generic handles: it
    gives BTN_TOUCH plus ABS_X/ABS_Y, which is what page turners report on and
    what gesture mapping needs.
    """
    NEUTRALIZE = {(0x0D, 0x30), (0x0D, 0x51), (0x0D, 0x54)}
    out = bytearray(descriptor)
    i = 0
    usage_page = None
    usages = []

    while i < len(descriptor):
        b = descriptor[i]
        size = b & 0x03
        if size == 3:
            size = 4
        item_type = (b >> 2) & 0x03
        tag = (b >> 4) & 0x0F

        if i + 1 + size > len(descriptor):
            break

        if size == 1:
            val = descriptor[i + 1]
        elif size == 2:
            val = int.from_bytes(descriptor[i + 1:i + 3], 'little')
        elif size == 4:
            val = int.from_bytes(descriptor[i + 1:i + 5], 'little')
        else:
            val = 0

        if item_type == 1 and tag == 0:
            usage_page = val
        elif item_type == 2 and tag == 0:
            page = (val >> 16) if size == 4 else usage_page
            usages.append((page, val & 0xFFFF if size == 4 else val))
        elif item_type == 0:
            if tag == 8 and usages and all(u in NEUTRALIZE for u in usages):
                out[i + 1] |= 0x01
            usages = []

        i += 1 + size

    result = bytes(out)
    if result != descriptor:
        logger.info(f"Sanitized digitizer ({len(descriptor)} bytes, "
                    f"pressure and contact fields padded)")
    return result


def descriptor_is_pointer(descriptor: bytes) -> bool:
    """True if the descriptor's first top-level Application collection is a
    Generic Desktop Mouse (0x02) or Pointer (0x01).

    Only the first collection decides: devices lead with their primary
    function, and combo keyboards that append a pointer collection must not
    drive the cursor overlay.
    """
    i = 0
    usage_page = None
    last_usage = None
    depth = 0

    while i < len(descriptor):
        b = descriptor[i]
        size = b & 0x03
        if size == 3:
            size = 4
        item_type = (b >> 2) & 0x03
        tag = (b >> 4) & 0x0F

        if i + 1 + size > len(descriptor):
            break

        if size == 1:
            val = descriptor[i + 1]
        elif size == 2:
            val = int.from_bytes(descriptor[i + 1:i + 3], 'little')
        elif size == 4:
            val = int.from_bytes(descriptor[i + 1:i + 5], 'little')
        else:
            val = 0

        if item_type == 1 and tag == 0:        # Global: Usage Page
            usage_page = val
        elif item_type == 2 and tag == 0:      # Local: Usage
            last_usage = val
        elif item_type == 0 and tag == 10:     # Main: Collection
            if depth == 0 and val == 0x01:
                return usage_page == 0x01 and last_usage in (0x01, 0x02)
            depth += 1
        elif item_type == 0 and tag == 12:     # Main: End Collection
            depth -= 1

        if item_type == 0:                     # any Main item clears locals
            last_usage = None

        i += 1 + size

    return False


# UHID constants from linux/uhid.h
UHID_CREATE2 = 11
UHID_DESTROY = 1
UHID_INPUT2 = 12
# Maximum sizes
HID_MAX_DESCRIPTOR_SIZE = 4096
UHID_DATA_MAX = 4096


class Bus:
    """Bus types for HID devices."""
    BLUETOOTH = 0x05


class UHIDError(Exception):
    """Exception raised for UHID operations."""
    pass


class UHIDDevice:
    """Virtual HID device using Linux UHID.

    Creates a virtual HID device that appears in /dev/input/eventX.
    The kernel parses the HID report descriptor to determine device type
    (keyboard, mouse, gamepad, etc.) automatically.

    Usage:
        # Create device with report descriptor from BLE HID
        device = UHIDDevice(
            name="BLE Remote",
            report_descriptor=report_map,  # bytes from GATT
            bus=Bus.BLUETOOTH
        )

        # Forward HID reports
        device.send_input(hid_report_bytes)

        # Cleanup
        device.destroy()
    """

    def __init__(
        self,
        name: str,
        report_descriptor: bytes,
        vendor: int = 0,
        product: int = 0,
        version: int = 0,
        bus: int = Bus.BLUETOOTH,
        phys: str = "",
        uniq: str = "",
        country: int = 0,
    ):
        """Initialize and create UHID device.

        Args:
            name: Device name (max 128 chars)
            report_descriptor: HID report descriptor bytes (max 4096)
            vendor: Vendor ID
            product: Product ID
            version: Device version
            bus: Bus type (use Bus.BLUETOOTH for BLE devices)
            phys: Physical path (optional)
            uniq: Unique identifier (optional)
            country: HID country code (optional)

        Raises:
            UHIDError: If /dev/uhid is not available or device creation fails
        """
        self.name = name
        self.report_descriptor = report_descriptor
        self.vendor = vendor
        self.product = product
        self.version = version
        self.bus = bus
        self.phys = phys
        self.uniq = uniq
        self.country = country

        self._fd: Optional[int] = None
        self._created = False
        self.input_paths: list = []

        self._open_uhid()
        self._create_device()

    def _open_uhid(self):
        """Open /dev/uhid file descriptor."""
        if not os.path.exists('/dev/uhid'):
            raise UHIDError("/dev/uhid not available - kernel CONFIG_UHID may be disabled")

        try:
            self._fd = os.open('/dev/uhid', os.O_RDWR)
            logger.debug("Opened /dev/uhid")
        except PermissionError:
            raise UHIDError("/dev/uhid permission denied - need root or uinput group")
        except OSError as e:
            raise UHIDError(f"Failed to open /dev/uhid: {e}")

    def _create_device(self):
        """Send UHID_CREATE2 to register the virtual device."""
        if len(self.report_descriptor) > HID_MAX_DESCRIPTOR_SIZE:
            raise UHIDError(f"Report descriptor too large: {len(self.report_descriptor)} > {HID_MAX_DESCRIPTOR_SIZE}")

        if len(self.name) > 128:
            raise UHIDError(f"Device name too long: {len(self.name)} > 128")

        # Pack UHID_CREATE2 event
        # Format: type(L) name(128s) phys(64s) uniq(64s) rd_size(H) bus(H)
        #         vendor(L) product(L) version(L) country(L) rd_data(4096s)
        event = struct.pack(
            '< L 128s 64s 64s H H L L L L 4096s',
            UHID_CREATE2,
            self.name.encode('utf-8')[:128],
            self.phys.encode('utf-8')[:64],
            self.uniq.encode('utf-8')[:64],
            len(self.report_descriptor),
            self.bus,
            self.vendor,
            self.product,
            self.version,
            self.country,
            self.report_descriptor.ljust(HID_MAX_DESCRIPTOR_SIZE, b'\x00'),
        )

        try:
            written = os.write(self._fd, event)
            if written != len(event):
                raise UHIDError(f"Incomplete write: {written} != {len(event)}")
            self._created = True
            logger.info(f"Created UHID device: {self.name} "
                       f"(vendor=0x{self.vendor:04x}, product=0x{self.product:04x}, "
                       f"rd_size={len(self.report_descriptor)})")

        except OSError as e:
            raise UHIDError(f"Failed to create device: {e}")

    def discover_input_paths(self):
        """Find /dev/input/eventX paths for this UHID device.

        Parses /proc/bus/input/devices, matching by uniq (the BD address)
        when set, else by device name. Called externally after an async
        delay to give the kernel time to register the input device after
        UHID_CREATE2.
        """
        self.input_paths = []
        try:
            content = open('/proc/bus/input/devices').read()
        except OSError:
            return

        for block in content.split("\n\n"):
            if not self._block_matches(block):
                continue
            for line in block.splitlines():
                if line.startswith("H: Handlers="):
                    for tok in line.split("=", 1)[1].split():
                        if tok.startswith("event"):
                            self.input_paths.append("/dev/input/" + tok)

    def _block_matches(self, block: str) -> bool:
        """Match a /proc/bus/input/devices block to this device."""
        if not self.uniq:
            return self.name in block
        for line in block.splitlines():
            if line.startswith("U: Uniq="):
                return line.split("=", 1)[1].strip().lower() == self.uniq.lower()
        return False

    def send_input(self, data: bytes):
        """Send HID input report to the kernel.

        Args:
            data: Raw HID report bytes (including report ID if applicable)

        Raises:
            UHIDError: If write fails
        """
        if not self._created:
            raise UHIDError("Device not created")

        if len(data) > UHID_DATA_MAX:
            raise UHIDError(f"Input data too large: {len(data)} > {UHID_DATA_MAX}")

        # Pack UHID_INPUT2 event
        # Format: type(L) size(H) data(4096s)
        event = struct.pack(
            '< L H 4096s',
            UHID_INPUT2,
            len(data),
            data.ljust(UHID_DATA_MAX, b'\x00'),
        )

        try:
            os.write(self._fd, event)
            logger.debug(f"Sent input: {data.hex()}")
        except OSError as e:
            raise UHIDError(f"Failed to send input: {e}")

    def destroy(self):
        """Destroy the virtual device and close the file descriptor."""
        if self._fd is None:
            return

        if self._created:
            try:
                # Send UHID_DESTROY
                event = struct.pack('< L', UHID_DESTROY)
                os.write(self._fd, event)
                logger.info(f"Destroyed UHID device: {self.name}")
            except OSError as e:
                logger.warning(f"Failed to send UHID_DESTROY: {e}")
            self._created = False

        try:
            os.close(self._fd)
        except OSError:
            pass
        self._fd = None

    @property
    def fd(self) -> Optional[int]:
        """Get the file descriptor (for select/poll integration)."""
        return self._fd

    def __enter__(self):
        return self

    def __exit__(self, _exc_type, _exc_val, _exc_tb):
        self.destroy()
        return False

    def __del__(self):
        self.destroy()
