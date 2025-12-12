#!/usr/bin/env python3
"""
Configuration

Configuration for Kindle HID Passthrough.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import configparser
import os
from typing import Optional
from enum import Enum

__all__ = ['config', 'Config', 'Protocol']


class Protocol(Enum):
    """Supported Bluetooth protocols."""
    BLE = "ble"
    CLASSIC = "classic"


class Config:
    """Configuration manager"""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._loaded = False
        return cls._instance

    def __init__(self):
        if not self._loaded:
            self._load()
            self._loaded = True

    def _load(self):
        """Load configuration from config.ini or use defaults"""
        self.base_path = '/mnt/us/kindle_hid_passthrough'

        config_file = os.path.join(self.base_path, 'config.ini')
        self._parser = configparser.ConfigParser()

        if os.path.exists(config_file):
            self._parser.read(config_file)

        # Paths
        self.cache_dir = self._get('paths', 'cache_dir', f'{self.base_path}/cache')
        self.pairing_keys_file = os.path.join(self.cache_dir, 'pairing_keys.json')
        self.devices_config_file = self._get('paths', 'devices_config',
                                             f'{self.base_path}/devices.conf')
        self.log_file = self._get('logging', 'log_file', '/var/log/hid_passthrough.log')

        # Transport
        self.transport = self._get('transport', 'hci_transport', 'file:/dev/stpbt')

        # Timeouts (seconds)
        self.reconnect_delay = self._getint('connection', 'reconnect_delay', 5)
        self.hci_reset_timeout = self._getint('connection', 'hci_reset_timeout', 10)
        self.connect_timeout = self._getint('connection', 'connect_timeout', 30)
        self.transport_timeout = self._getint('connection', 'transport_timeout', 30)

        # Device identity
        self.device_name = self._get('device', 'name', 'Kindle-HID')
        self.device_address = self._get('device', 'address', 'F0:F0:F0:F0:F0:F0')

        # Protocol
        protocol_str = self._get('protocol', 'type', 'ble').lower()
        self.protocol = self._parse_protocol(protocol_str)

    def _parse_protocol(self, protocol_str: str) -> Protocol:
        """Parse protocol string to Protocol enum."""
        if protocol_str in ('classic', 'br/edr', 'bredr'):
            return Protocol.CLASSIC
        return Protocol.BLE

    def _get(self, section: str, key: str, default: str) -> str:
        try:
            return self._parser.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def _getint(self, section: str, key: str, default: int) -> int:
        try:
            return self._parser.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return default

    def get_device_config(self) -> Optional[tuple]:
        """Load first device address and protocol from devices.conf.

        Format:
            ADDRESS                    # Uses default protocol
            ADDRESS ble               # Explicit BLE
            ADDRESS classic           # Explicit Classic Bluetooth

        Returns:
            Tuple of (address, protocol) or None if not configured
        """
        devices = self.get_all_devices()
        return devices[0] if devices else None

    def get_all_devices(self) -> list:
        """Load all device addresses and protocols from devices.conf.

        Format:
            ADDRESS                    # Uses default protocol
            ADDRESS ble               # Explicit BLE
            ADDRESS classic           # Explicit Classic Bluetooth
            # comment                  # Ignored
            * classic                  # Wildcard - accept any device

        Returns:
            List of tuples (address, protocol). Address may be '*' for wildcard.
        """
        if not os.path.exists(self.devices_config_file):
            return []

        devices = []
        with open(self.devices_config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split()
                    address = parts[0]
                    protocol = self._parse_protocol(parts[1]) if len(parts) > 1 else self.protocol
                    devices.append((address, protocol))

        return devices

    def _normalize_address(self, address: str) -> str:
        """Normalize a Bluetooth address for comparison.

        Strips transport suffix (/P for BR/EDR, etc.) and uppercases.
        """
        # Remove any transport suffix like /P or /LE
        addr = address.split('/')[0]
        return addr.upper()

    def is_device_allowed(self, address: str) -> tuple:
        """Check if a device address is in the allowed list.

        Args:
            address: Device address to check

        Returns:
            Tuple of (allowed: bool, protocol: Protocol or None)
        """
        devices = self.get_all_devices()
        if not devices:
            return (False, None)

        addr_norm = self._normalize_address(address)

        for dev_addr, protocol in devices:
            # Wildcard - accept any device
            if dev_addr == '*':
                return (True, protocol)
            # Exact match
            dev_norm = self._normalize_address(dev_addr)
            if addr_norm == dev_norm:
                return (True, protocol)

        return (False, None)


def create_host(protocol: Protocol = None, transport_spec: str = None):
    """Factory function to create the appropriate HID host.

    Args:
        protocol: Protocol to use (default: from config)
        transport_spec: HCI transport specification (default: from config)

    Returns:
        BLEHIDHost or ClassicHIDHost instance
    """
    if protocol is None:
        protocol = config.protocol

    if protocol == Protocol.CLASSIC:
        from classic_host import ClassicHIDHost
        return ClassicHIDHost(transport_spec)
    else:
        from host import BLEHIDHost
        return BLEHIDHost(transport_spec)


# Global singleton instance
config = Config()
