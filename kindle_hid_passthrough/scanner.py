#!/usr/bin/env python3
"""
Bluetooth Scanner

Scans for HID devices across both BLE and Classic protocols simultaneously.
Uses a single Bumble Device instance to perform both scan types.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import asyncio
from dataclasses import dataclass
from typing import List

from bumble.core import AdvertisingData, DeviceClass
from bumble.device import Device
from bumble.gatt import GATT_HUMAN_INTERFACE_DEVICE_SERVICE
from bumble.hci import Address, HCI_Reset_Command
from bumble.transport import open_transport

from config import Protocol, config
from logging_utils import log

__all__ = ['Scanner', 'DiscoveredDevice']


@dataclass
class DiscoveredDevice:
    """A discovered HID device."""
    address: str
    name: str
    protocol: Protocol
    rssi: int = -100

    def __str__(self) -> str:
        proto_tag = "[BLE]" if self.protocol == Protocol.BLE else "[Classic]"
        return f"{proto_tag} {self.name} ({self.address}) RSSI: {self.rssi}"


class Scanner:
    """Scans for HID devices across both BLE and Classic protocols.

    Uses a single Bumble Device instance to perform concurrent scanning.
    Falls back to sequential scanning if concurrent mode fails.
    """

    def __init__(self, transport_spec: str = None):
        """Initialize scanner.

        Args:
            transport_spec: HCI transport (default: from config)
        """
        self.transport_spec = transport_spec or config.transport
        self.transport = None
        self.device = None
        self.on_device_found = None  # Optional callback(DiscoveredDevice)

    async def start(self):
        """Initialize the Bumble device."""
        log.info("Scanner: Opening transport...")

        try:
            self.transport = await asyncio.wait_for(
                open_transport(self.transport_spec),
                timeout=config.transport_timeout
            )
        except asyncio.TimeoutError:
            log.error(f"Transport open timed out after {config.transport_timeout}s")
            raise

        self.device = Device.with_hci(
            config.device_name,
            config.device_address,
            self.transport.source,
            self.transport.sink
        )

        log.info("Sending HCI Reset...")
        try:
            await asyncio.wait_for(
                self.device.host.send_command(HCI_Reset_Command()),
                timeout=config.hci_reset_timeout
            )
            log.success("HCI Reset successful")
            await asyncio.sleep(0.2)
        except asyncio.TimeoutError:
            log.error("HCI Reset timed out")
            raise

        await self.device.power_on()
        log.success(f"Device powered on: {self.device.public_address}")

    async def cleanup(self):
        """Clean up resources."""
        if self.transport:
            try:
                await self.transport.close()
            except Exception:
                pass
            self.transport = None
        self.device = None

    async def scan(
        self,
        duration: float = 10.0,
        concurrent: bool = True,
        stop_event: asyncio.Event = None
    ) -> List[DiscoveredDevice]:
        """Scan for HID devices across both BLE and Classic.

        Args:
            duration: Scan duration in seconds (split between protocols if concurrent)
            concurrent: Try concurrent scanning (falls back to sequential if fails)
            stop_event: If set, scan stops early when this event is triggered

        Returns:
            List of discovered HID devices with protocol tags
        """
        if concurrent:
            try:
                return await self._scan_concurrent(duration, stop_event)
            except Exception as e:
                log.warning(f"Concurrent scan failed ({e}), falling back to sequential")
                return await self._scan_sequential(duration, stop_event)
        else:
            return await self._scan_sequential(duration, stop_event)

    async def _scan_concurrent(self, duration: float, stop_event: asyncio.Event = None) -> List[DiscoveredDevice]:
        """Run BLE and Classic scans concurrently."""
        log.info(f"Scanning BLE + Classic concurrently ({duration}s)...")

        # Run both scans as concurrent tasks
        ble_task = asyncio.create_task(self._scan_ble(duration, stop_event))
        classic_task = asyncio.create_task(self._scan_classic(duration, stop_event))

        results = await asyncio.gather(ble_task, classic_task, return_exceptions=True)

        ble_devices = results[0] if not isinstance(results[0], Exception) else []
        classic_devices = results[1] if not isinstance(results[1], Exception) else []

        if isinstance(results[0], Exception):
            log.warning(f"BLE scan error: {results[0]}")
        if isinstance(results[1], Exception):
            log.warning(f"Classic scan error: {results[1]}")

        return self._merge_results(ble_devices, classic_devices)

    async def _scan_sequential(self, duration: float, stop_event: asyncio.Event = None) -> List[DiscoveredDevice]:
        """Run BLE and Classic scans sequentially."""
        half_duration = duration / 2.0

        log.info(f"Scanning BLE ({half_duration}s)...")
        ble_devices = await self._scan_ble(half_duration, stop_event)

        if stop_event and stop_event.is_set():
            return self._merge_results(ble_devices, [])

        log.info(f"Scanning Classic ({half_duration}s)...")
        classic_devices = await self._scan_classic(half_duration, stop_event)

        return self._merge_results(ble_devices, classic_devices)

    async def _interruptible_sleep(self, duration: float, stop_event: asyncio.Event = None):
        """Sleep for duration, but return early if stop_event is set."""
        if stop_event is None:
            await asyncio.sleep(duration)
        else:
            try:
                await asyncio.wait_for(stop_event.wait(), timeout=duration)
            except asyncio.TimeoutError:
                pass

    async def _scan_ble(self, duration: float, stop_event: asyncio.Event = None) -> List[DiscoveredDevice]:
        """Scan for BLE HID devices."""
        devices_found: List[DiscoveredDevice] = []
        seen_addresses = set()

        def on_advertisement(advertisement):
            addr_str = str(advertisement.address)
            if addr_str in seen_addresses:
                return
            seen_addresses.add(addr_str)

            # Check for HID service in advertising data
            is_hid = False
            if hasattr(advertisement, 'data') and advertisement.data:
                services = advertisement.data.get(
                    AdvertisingData.COMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS
                ) or advertisement.data.get(
                    AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS
                )
                if services:
                    for service_uuid in services:
                        if service_uuid == GATT_HUMAN_INTERFACE_DEVICE_SERVICE:
                            is_hid = True
                            break

            if is_hid:
                name = 'Unknown'
                if hasattr(advertisement, 'data') and advertisement.data:
                    name = advertisement.data.get(AdvertisingData.COMPLETE_LOCAL_NAME) or \
                           advertisement.data.get(AdvertisingData.SHORTENED_LOCAL_NAME) or 'Unknown'
                    if isinstance(name, bytes):
                        name = name.decode('utf-8', errors='replace')

                device = DiscoveredDevice(
                    address=addr_str,
                    name=name,
                    protocol=Protocol.BLE,
                    rssi=advertisement.rssi or -100
                )
                devices_found.append(device)
                log.info(f"  Found: {device}")
                if self.on_device_found:
                    self.on_device_found(device)

        self.device.on('advertisement', on_advertisement)
        try:
            await self.device.start_scanning(filter_duplicates=True)
            await self._interruptible_sleep(duration, stop_event)
            await self.device.stop_scanning()
        finally:
            self.device.remove_listener('advertisement', on_advertisement)

        return devices_found

    async def _scan_classic(self, duration: float, stop_event: asyncio.Event = None) -> List[DiscoveredDevice]:
        """Scan for Classic Bluetooth HID devices."""
        log.info(f"Starting Classic inquiry ({duration}s)...")
        devices_found: List[DiscoveredDevice] = []
        seen_addresses = set()

        def on_inquiry_result(address, class_of_device, eir_data, rssi):
            addr_str = str(address)
            if addr_str in seen_addresses:
                return
            seen_addresses.add(addr_str)

            # Check if HID device (Peripheral device class)
            is_hid = False
            major_class_name = "Unknown"
            try:
                _, major_class, minor_class = DeviceClass.split_class_of_device(class_of_device)
                major_class_name = DeviceClass.major_device_class_name(major_class)
                is_hid = major_class_name == "Peripheral"
            except Exception:
                major_class = (class_of_device >> 8) & 0x1F
                is_hid = (major_class == 0x05)  # Peripheral
                major_class_name = f"0x{major_class:02X}"

            # Log ALL devices found, not just HID
            log.info(f"  Classic: {addr_str} CoD=0x{class_of_device:06X} ({major_class_name}) HID={is_hid}")

            if is_hid:
                name = 'Unknown'
                if eir_data:
                    try:
                        name_data = eir_data.get(0x09) or eir_data.get(0x08)
                        if name_data:
                            if isinstance(name_data, bytes):
                                name = name_data.decode('utf-8', errors='replace')
                            else:
                                name = str(name_data)
                    except Exception:
                        pass

                device = DiscoveredDevice(
                    address=addr_str,
                    name=name,
                    protocol=Protocol.CLASSIC,
                    rssi=rssi or -100
                )
                devices_found.append(device)
                log.info(f"  Found: {device}")
                if self.on_device_found:
                    self.on_device_found(device)

        self.device.on('inquiry_result', on_inquiry_result)
        try:
            await self.device.start_discovery()
            log.debug("Classic inquiry started")
            await self._interruptible_sleep(duration, stop_event)
            await self.device.stop_discovery()
            log.info(f"Classic inquiry complete: {len(seen_addresses)} total, {len(devices_found)} HID")
        finally:
            self.device.remove_listener('inquiry_result', on_inquiry_result)

        # Get names for unknown devices
        for dev in devices_found:
            if dev.name == 'Unknown':
                try:
                    name = await asyncio.wait_for(
                        self.device.request_remote_name(Address(dev.address)),
                        timeout=3.0
                    )
                    if name:
                        dev.name = name
                except Exception:
                    pass

        return devices_found

    def _merge_results(
        self,
        ble_devices: List[DiscoveredDevice],
        classic_devices: List[DiscoveredDevice]
    ) -> List[DiscoveredDevice]:
        """Merge and deduplicate scan results.

        Some devices may advertise on both BLE and Classic. In that case,
        we keep both entries since the user may want to choose the protocol.

        Results are sorted by RSSI (strongest signal first).
        """
        all_devices = ble_devices + classic_devices

        # Sort by RSSI (strongest first)
        all_devices.sort(key=lambda d: d.rssi, reverse=True)

        log.success(f"Found {len(ble_devices)} BLE + {len(classic_devices)} Classic = {len(all_devices)} HID devices")
        return all_devices
