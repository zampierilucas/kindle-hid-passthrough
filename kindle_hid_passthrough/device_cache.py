#!/usr/bin/env python3
"""Per-device cache (HID report descriptors, names) for fast reconnection."""

import json
import logging
import os
from typing import Dict, Optional

from config import normalize_addr

logger = logging.getLogger(__name__)


class DeviceCache:
    """Manages caching of device data for fast reconnection"""

    def __init__(self, cache_dir: str):
        """Initialize cache manager

        Args:
            cache_dir: Directory to store cache files
        """
        self.cache_dir = cache_dir
        os.makedirs(cache_dir, exist_ok=True)

    def _get_cache_path(self, address: str) -> str:
        """Get cache file path for device address

        Args:
            address: Device address (e.g., "AA:BB:CC:DD:EE:FF")

        Returns:
            Path to cache file
        """
        safe_addr = normalize_addr(address).replace(':', '_')
        return os.path.join(self.cache_dir, f"{safe_addr}.json")

    def load(self, address: str) -> Optional[Dict]:
        """Load cached data for device

        Args:
            address: Device address

        Returns:
            Cache dictionary if found and valid, None otherwise
        """
        cache_path = self._get_cache_path(address)
        if not os.path.exists(cache_path):
            return None

        try:
            with open(cache_path, 'r') as f:
                cache = json.load(f)

            # Validate cache structure - must have report_map
            if 'report_map' not in cache:
                logger.warning(f"Invalid cache structure for {address}")
                return None

            logger.info(f"Loaded device cache for {address}")
            return cache

        except Exception as e:
            logger.warning(f"Failed to load cache for {address}: {e}")
            return None

    def save(self, address: str, cache_data: Dict) -> bool:
        """Save device data to cache

        Args:
            address: Device address
            cache_data: Dictionary containing cache data

        Returns:
            True if saved successfully, False otherwise
        """
        try:
            cache_path = self._get_cache_path(address)
            with open(cache_path, 'w') as f:
                json.dump(cache_data, f, indent=2)

            logger.info(f"Saved device cache for {address}")
            return True

        except Exception as e:
            logger.warning(f"Failed to save cache for {address}: {e}")
            return False

    def clear(self, address: Optional[str] = None) -> int:
        """Clear cache for specific device or all devices.

        Args:
            address: Device address, or None to clear all

        Returns:
            Number of cache files removed.
        """
        count = 0
        if address:
            cache_path = self._get_cache_path(address)
            try:
                if os.path.exists(cache_path):
                    os.remove(cache_path)
                    count = 1
                    logger.info(f"Cleared cache for {address}")
            except Exception as e:
                logger.warning(f"Failed to clear cache for {address}: {e}")
        else:
            try:
                filenames = os.listdir(self.cache_dir)
            except OSError:
                filenames = []
            for filename in filenames:
                if filename.endswith('.json') and filename != 'pairing_keys.json':
                    try:
                        os.remove(os.path.join(self.cache_dir, filename))
                        count += 1
                    except OSError as e:
                        logger.warning(f"Failed to clear {filename}: {e}")
            logger.info("Cleared all device caches")
        return count

