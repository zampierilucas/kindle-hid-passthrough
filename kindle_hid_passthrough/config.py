#!/usr/bin/env python3
"""Configuration for Kindle HID Passthrough."""

import configparser
import json
import logging
import os
import subprocess
from enum import Enum
from typing import TYPE_CHECKING, Optional

from kindle_detect import detect_kindle

if TYPE_CHECKING:
    pass

__version__ = "3.14.0"
__build_sha__ = None  # stamped by build scripts


def _get_git_sha() -> Optional[str]:
    try:
        return subprocess.check_output(
            ['git', 'rev-parse', '--short', 'HEAD'],
            stderr=subprocess.DEVNULL,
            cwd=os.path.dirname(__file__),
        ).decode().strip()
    except Exception:
        return None


def _get_build_sha() -> Optional[str]:
    sha_file = os.path.join(os.path.dirname(__file__), 'BUILD_SHA')
    try:
        with open(sha_file) as f:
            return f.read().strip()
    except Exception:
        return None


def get_version() -> str:
    sha = __build_sha__ or _get_git_sha() or _get_build_sha()
    if sha:
        return f"{__version__}-{sha}"
    return __version__

__all__ = ['config', 'Config', 'Protocol', 'normalize_addr', 'clean_device_name',
           '__version__', 'get_version']


def normalize_addr(address: str) -> str:
    """Normalize Bluetooth address - strip /P suffix, uppercase."""
    return address.split('/')[0].upper()


def clean_device_name(name) -> str:
    """Decode a device name, dropping padding and unprintable characters.

    Fixed-length name buffers are usually NUL-padded C strings, but some
    devices pad with junk bytes. Dropping only *invalid* UTF-8 is not enough:
    padding that happens to be valid UTF-8 decodes to control, unassigned or
    private-use code points that still render as boxes or U+FFFD downstream.
    So truncate at the first NUL, ignore undecodable bytes, then filter by
    code point category. Accepts str too, since names arriving from bumble,
    the HTTP API or devices.conf are already decoded.
    """
    if name is None:
        return ''
    if isinstance(name, (bytes, bytearray)):
        name = bytes(name).split(b'\x00')[0].decode('utf-8', errors='ignore')
    cleaned = ''.join(
        ch for ch in str(name)
        if ch == ' ' or (ch != '\ufffd' and ch.isprintable())
    )
    return cleaned.strip()


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

        # Transport - auto-detect from Kindle model, fall back to config.ini
        self.transport = self._detect_transport()

        # Timeouts (seconds)
        self.reconnect_delay = self._getint('connection', 'reconnect_delay', 5)
        self.hci_reset_timeout = self._getint('connection', 'hci_reset_timeout', 10)
        self.connect_timeout = self._getint('connection', 'connect_timeout', 30)
        self.transport_timeout = self._getint('connection', 'transport_timeout', 30)

        # Bluetooth hardware setup
        self.bt_module_patterns = self._get_list('bluetooth', 'module_patterns', None)
        self.bt_settle_time = float(self._get('bluetooth', 'settle_time', '0.5'))

        # Device identity
        self.device_name = self._get('device', 'name', 'Kindle-HID')
        self.device_address = self._get('device', 'address', 'F0:F0:F0:F0:F0:F0')

        # Protocol
        protocol_str = self._get('protocol', 'type', 'ble').lower()
        self.protocol = self._parse_protocol(protocol_str)

    def _detect_transport(self) -> str:
        """Auto-detect HCI transport from Kindle hardware.

        Tries known device paths for the detected Kindle model, then
        falls back to probing common paths, and finally the hardcoded default.
        """

        defaults = detect_kindle()
        self._kindle_defaults = defaults

        if defaults:
            if defaults.transport_scheme == 'serial':
                transport = f'serial:{defaults.device_path},{defaults.baud_rate}'
                if defaults.flow_control:
                    transport += f',{defaults.flow_control}'
            else:
                transport = f'file:{defaults.device_path}'
            if os.path.exists(defaults.device_path):
                logging.getLogger(__name__).info(
                    "Auto-detected transport: %s (%s)", transport, defaults.model_name)
            else:
                logging.getLogger(__name__).info(
                    "Detected %s but %s not found yet (module may need loading)",
                    defaults.model_name, defaults.device_path)
            return transport

        # Probe common device paths as a fallback
        for path in ['/dev/stpbt', '/dev/ttymxc2', '/dev/ttyHS0', '/dev/ttyS1']:
            if os.path.exists(path):
                transport = f'file:{path}'
                logging.getLogger(__name__).info(
                    "Probed transport: %s", transport)
                return transport

        # Fall back to config.ini value
        configured = self._get('transport', 'hci_transport', None)
        if configured:
            logging.getLogger(__name__).info(
                "Using configured transport: %s", configured)
            return configured

        return None

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

        # Bumble's JsonKeyStore nests entries under a namespace (e.g. "__DEFAULT__").
        for namespace in data.values():
            if not isinstance(namespace, dict):
                continue
            for key in [k for k in namespace if normalize_addr(k) == addr_norm]:
                del namespace[key]
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
            # Otherwise the block outlives the pairing and the device keeps
            # showing up under the plugin's mapping menu forever.
            import button_mapper
            button_mapper.unregister_device(address)

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
        name = clean_device_name(name) if name else None

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
            import button_mapper
            button_mapper.register_device(addr_norm, name)
        except Exception as e:
            logger.error(f"Failed to save device: {e}")

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
                    name = (clean_device_name(parts[2]) or None) if len(parts) > 2 else None
                    devices.append((address, protocol, name))

        return devices


# Global singleton instance
config = Config()
