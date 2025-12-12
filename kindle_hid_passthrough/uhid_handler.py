#!/usr/bin/env python3
"""
UHID Handler

Manages virtual HID devices via Linux UHID interface.
Allows BLE/Classic HID devices to appear as native Linux input devices.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

__version__ = "1.0.0"

import os
import struct
import logging
from typing import Optional, Callable, List

__all__ = ['UHIDDevice', 'UHIDError', 'Bus']

logger = logging.getLogger(__name__)

# UHID constants from linux/uhid.h
UHID_CREATE2 = 11
UHID_DESTROY = 1
UHID_INPUT2 = 12
UHID_START = 2
UHID_STOP = 3
UHID_OPEN = 4
UHID_CLOSE = 5
UHID_OUTPUT = 6

# Maximum sizes
HID_MAX_DESCRIPTOR_SIZE = 4096
UHID_DATA_MAX = 4096

# Event struct size for reading
UHID_EVENT_SIZE = 4 + 4380  # type + largest union member


class Bus:
    """Bus types for HID devices."""
    PCI = 0x01
    ISAPNP = 0x02
    USB = 0x03
    HIL = 0x04
    BLUETOOTH = 0x05
    VIRTUAL = 0x06


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
        self._started = False

        # Callbacks for kernel events
        self.on_start: Optional[Callable[[], None]] = None
        self.on_stop: Optional[Callable[[], None]] = None
        self.on_open: Optional[Callable[[], None]] = None
        self.on_close: Optional[Callable[[], None]] = None
        self.on_output: Optional[Callable[[bytes, int], None]] = None

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

    def poll_events(self, timeout: float = 0) -> bool:
        """Poll for kernel events (OUTPUT reports, etc.).

        Args:
            timeout: Timeout in seconds (0 = non-blocking)

        Returns:
            True if an event was processed, False otherwise
        """
        if self._fd is None:
            return False

        import select
        readable, _, _ = select.select([self._fd], [], [], timeout)

        if not readable:
            return False

        try:
            data = os.read(self._fd, UHID_EVENT_SIZE)
            if len(data) < 4:
                return False

            event_type = struct.unpack_from('< L', data)[0]
            self._handle_event(event_type, data)
            return True
        except OSError:
            return False

    def _handle_event(self, event_type: int, data: bytes):
        """Handle kernel event."""
        if event_type == UHID_START:
            self._started = True
            logger.debug("UHID_START received")
            if self.on_start:
                self.on_start()

        elif event_type == UHID_STOP:
            self._started = False
            logger.debug("UHID_STOP received")
            if self.on_stop:
                self.on_stop()

        elif event_type == UHID_OPEN:
            logger.debug("UHID_OPEN received")
            if self.on_open:
                self.on_open()

        elif event_type == UHID_CLOSE:
            logger.debug("UHID_CLOSE received")
            if self.on_close:
                self.on_close()

        elif event_type == UHID_OUTPUT:
            # Parse output report
            # Format: data(4096s) size(H) rtype(B)
            if len(data) >= 4 + UHID_DATA_MAX + 3:
                output_data = data[4:4+UHID_DATA_MAX]
                size, rtype = struct.unpack_from('< H B', data, 4 + UHID_DATA_MAX)
                output_data = output_data[:size]
                logger.debug(f"UHID_OUTPUT received: {output_data.hex()} (type={rtype})")
                if self.on_output:
                    self.on_output(output_data, rtype)

    @property
    def is_created(self) -> bool:
        """Check if device is created."""
        return self._created

    @property
    def is_started(self) -> bool:
        """Check if device is started (kernel acknowledged)."""
        return self._started

    @property
    def fd(self) -> Optional[int]:
        """Get the file descriptor (for select/poll integration)."""
        return self._fd

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.destroy()
        return False

    def __del__(self):
        self.destroy()
