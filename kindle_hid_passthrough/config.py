#!/usr/bin/env python3
"""
Configuration

Configuration for Kindle HID Passthrough.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import configparser
import json
import logging
import os
from enum import Enum
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    pass

__version__ = "3.0.0"

__all__ = ['config', 'Config', 'Protocol', 'get_fallback_hid_descriptor', 'normalize_addr', '__version__']


def normalize_addr(address: str) -> str:
    """Normalize Bluetooth address - strip /P suffix, uppercase."""
    return address.split('/')[0].upper()


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

    def _determine_base_path(self):
        """Determine base path dynamically.

        Priority:
        1. KINDLE_HID_BASE environment variable (set by C wrapper)
        2. Fallback to /mnt/us/kindle_hid_passthrough
        """
        if os.environ.get('KINDLE_HID_BASE'):
            self.base_path = os.environ['KINDLE_HID_BASE']
            return

        # Fallback
        self.base_path = '/mnt/us/kindle_hid_passthrough'

    def _load(self):
        """Load configuration from config.ini or use defaults"""
        self._determine_base_path()

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

        # Bluetooth hardware setup
        self.bt_module_patterns = self._get_list('bluetooth', 'module_patterns', None)
        self.bt_kill_processes = self._get_list('bluetooth', 'kill_processes', None)
        self.bt_settle_time = float(self._get('bluetooth', 'settle_time', '0.5'))

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

    def _get_list(self, section: str, key: str, default):
        """Get a comma-separated list from config, or return default."""
        try:
            raw = self._parser.get(section, key)
            return [s.strip() for s in raw.split(',') if s.strip()]
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def _getint(self, section: str, key: str, default: int) -> int:
        try:
            return self._parser.getint(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError, ValueError):
            return default

    def validate_keystore(self):
        """Validate pairing_keys.json; back up and reset if corrupt."""
        logger = logging.getLogger(__name__)
        keys_file = self.pairing_keys_file
        if not os.path.exists(keys_file):
            return
        try:
            with open(keys_file, 'r') as f:
                json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.warning(f"Corrupt keystore ({e}), backing up and resetting")
            try:
                backup = keys_file + '.bak'
                os.rename(keys_file, backup)
                logger.info(f"Backed up to {backup}")
            except OSError:
                try:
                    os.remove(keys_file)
                except OSError:
                    pass

    def remove_pairing_key(self, address: str) -> bool:
        """Remove a pairing key from pairing_keys.json by normalized address."""
        keys_file = self.pairing_keys_file
        if not os.path.exists(keys_file):
            return False

        try:
            with open(keys_file, 'r') as f:
                data = json.load(f)
        except (json.JSONDecodeError, OSError):
            return False

        addr_norm = normalize_addr(address)
        removed = False
        keys_to_remove = []
        for key in data:
            if normalize_addr(key) == addr_norm:
                keys_to_remove.append(key)

        for key in keys_to_remove:
            del data[key]
            removed = True

        if removed:
            try:
                with open(keys_file, 'w') as f:
                    json.dump(data, f, indent=2)
            except OSError:
                return False

        return removed

    def remove_device(self, address: str) -> dict:
        """Remove a device from devices.conf and its pairing key.

        Returns:
            Dict with 'removed' (bool) and 'keys_removed' (bool) fields.
        """
        address = normalize_addr(address)
        conf_file = self.devices_config_file

        if not os.path.exists(conf_file):
            return {"removed": False, "keys_removed": False}

        removed = False
        lines_to_keep = []
        with open(conf_file, 'r') as f:
            for line in f:
                stripped = line.strip()
                if not stripped or stripped.startswith('#'):
                    lines_to_keep.append(line)
                    continue
                parts = stripped.split()
                line_addr = normalize_addr(parts[0]) if parts[0] != '*' else parts[0]
                if line_addr == address and not removed:
                    removed = True
                    continue
                lines_to_keep.append(line)

        keys_removed = False
        if removed:
            with open(conf_file, 'w') as f:
                f.writelines(lines_to_keep)
            keys_removed = self.remove_pairing_key(address)

        return {"removed": removed, "keys_removed": keys_removed}

    def add_device(self, address: str, protocol, name: str = None):
        """Add a device to devices.conf (appends, avoids duplicates).

        Args:
            address: Bluetooth address
            protocol: Protocol enum (BLE or CLASSIC)
            name: Optional device name
        """
        logger = logging.getLogger(__name__)
        conf_file = self.devices_config_file

        dir_path = os.path.dirname(conf_file)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)

        addr_norm = normalize_addr(address)

        for existing_addr, _, _ in self.get_all_devices():
            if existing_addr == addr_norm:
                logger.info(f"Device {address} already in devices.conf")
                return

        try:
            if not os.path.exists(conf_file):
                with open(conf_file, 'w') as f:
                    f.write("# Device addresses and protocols\n")
                    f.write("# Format: ADDRESS PROTOCOL [NAME]\n")

            with open(conf_file, 'a') as f:
                if name:
                    f.write(f"{addr_norm} {protocol.value} {name}\n")
                else:
                    f.write(f"{addr_norm} {protocol.value}\n")
            logger.info(f"Added: {addr_norm} {protocol.value} ({name or 'unnamed'})")
        except Exception as e:
            logger.error(f"Failed to save device: {e}")

    def get_device_config(self) -> Optional[tuple]:
        """Load first device address, protocol, and name from devices.conf.

        Returns:
            Tuple of (address, protocol, name) or None if not configured
        """
        devices = self.get_all_devices()
        return devices[0] if devices else None

    def get_all_devices(self) -> list:
        """Load all devices from devices.conf.

        Format:
            ADDRESS                    # Uses default protocol
            ADDRESS ble               # Explicit BLE
            ADDRESS classic           # Explicit Classic Bluetooth
            ADDRESS classic DeviceName # With device name
            # comment                  # Ignored
            * classic                  # Wildcard - accept any device

        Returns:
            List of tuples (address, protocol, name). Name may be None.
        """
        if not os.path.exists(self.devices_config_file):
            return []

        devices = []
        with open(self.devices_config_file, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    parts = line.split(None, 2)  # Split into max 3 parts
                    address = parts[0] if parts[0] == '*' else normalize_addr(parts[0])
                    protocol = self._parse_protocol(parts[1]) if len(parts) > 1 else self.protocol
                    name = parts[2] if len(parts) > 2 else None
                    devices.append((address, protocol, name))

        return devices

    def is_device_allowed(self, address: str) -> tuple:
        """Check if a device address is in the allowed list.

        Args:
            address: Device address to check (may have /P suffix from Bumble)

        Returns:
            Tuple of (allowed: bool, protocol: Protocol or None)
        """
        devices = self.get_all_devices()
        if not devices:
            return (False, None)

        addr_norm = normalize_addr(address)

        for dev_addr, protocol, _ in devices:
            if dev_addr == '*':
                return (True, protocol)
            if addr_norm == dev_addr:
                return (True, protocol)

        return (False, None)


def get_configured_protocols() -> set:
    """Get the set of protocols configured in devices.conf.

    Returns:
        Set of Protocol enums (may contain BLE, CLASSIC, or both)
    """
    devices = config.get_all_devices()
    return {d[1] for d in devices}


def get_fallback_hid_descriptor() -> bytes:
    """Return a generic fallback HID report descriptor.

    Used when SDP query or GATT read fails to get the real descriptor.
    Based on Xbox-style controller format with:
    - 4 axes (16-bit): left stick X/Y, right stick X/Y
    - 2 triggers (10-bit): LT, RT
    - D-pad as hat switch
    - 16 buttons
    """
    return bytes([
        0x05, 0x01,        # Usage Page (Generic Desktop)
        0x09, 0x05,        # Usage (Gamepad)
        0xa1, 0x01,        # Collection (Application)
        0x85, 0x01,        #   Report ID (1)

        # 4 axes (16-bit each): LX, LY, RX, RY
        0x05, 0x01,        #   Usage Page (Generic Desktop)
        0x09, 0x30,        #   Usage (X) - Left stick X
        0x09, 0x31,        #   Usage (Y) - Left stick Y
        0x09, 0x32,        #   Usage (Z) - Right stick X
        0x09, 0x35,        #   Usage (Rz) - Right stick Y
        0x16, 0x00, 0x00,  #   Logical Minimum (0)
        0x26, 0xff, 0xff,  #   Logical Maximum (65535)
        0x75, 0x10,        #   Report Size (16)
        0x95, 0x04,        #   Report Count (4)
        0x81, 0x02,        #   Input (Data, Variable, Absolute)

        # 2 triggers (10-bit): LT, RT
        0x05, 0x02,        #   Usage Page (Simulation Controls)
        0x09, 0xc5,        #   Usage (Brake) - LT
        0x09, 0xc4,        #   Usage (Accelerator) - RT
        0x16, 0x00, 0x00,  #   Logical Minimum (0)
        0x26, 0xff, 0x03,  #   Logical Maximum (1023)
        0x75, 0x10,        #   Report Size (16)
        0x95, 0x02,        #   Report Count (2)
        0x81, 0x02,        #   Input (Data, Variable, Absolute)

        # D-pad as hat switch
        0x05, 0x01,        #   Usage Page (Generic Desktop)
        0x09, 0x39,        #   Usage (Hat Switch)
        0x15, 0x01,        #   Logical Minimum (1)
        0x25, 0x08,        #   Logical Maximum (8)
        0x35, 0x00,        #   Physical Minimum (0)
        0x46, 0x3b, 0x01,  #   Physical Maximum (315)
        0x65, 0x14,        #   Unit (Degrees)
        0x75, 0x08,        #   Report Size (8)
        0x95, 0x01,        #   Report Count (1)
        0x81, 0x42,        #   Input (Data, Variable, Null State)

        # 16 buttons
        0x05, 0x09,        #   Usage Page (Button)
        0x19, 0x01,        #   Usage Minimum (1)
        0x29, 0x10,        #   Usage Maximum (16)
        0x15, 0x00,        #   Logical Minimum (0)
        0x25, 0x01,        #   Logical Maximum (1)
        0x75, 0x01,        #   Report Size (1)
        0x95, 0x10,        #   Report Count (16)
        0x81, 0x02,        #   Input (Data, Variable, Absolute)

        0xc0,              # End Collection
    ])


# Global singleton instance
config = Config()
