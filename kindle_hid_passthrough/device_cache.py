#!/usr/bin/env python3
"""
Device Cache Manager

Handles caching of device data (report descriptors, characteristics, etc.)
to speed up reconnection for both BLE and Classic Bluetooth HID devices.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

import json
import logging
import os
from typing import Optional, Dict, List

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
        safe_addr = address.replace(':', '_').replace('/', '_')
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

    def update(self, address: str, updates: Dict) -> bool:
        """Update existing cache with new data

        Args:
            address: Device address
            updates: Dictionary of fields to update

        Returns:
            True if updated successfully, False otherwise
        """
        try:
            # Load existing cache or create new one
            existing_cache = self.load(address)
            if not existing_cache:
                existing_cache = {}

            # Merge updates
            existing_cache.update(updates)

            # Save back
            return self.save(address, existing_cache)

        except Exception as e:
            logger.warning(f"Failed to update cache for {address}: {e}")
            return False

    def clear(self, address: Optional[str] = None) -> None:
        """Clear cache for specific device or all devices

        Args:
            address: Device address, or None to clear all
        """
        if address:
            # Clear specific device
            cache_path = self._get_cache_path(address)
            try:
                if os.path.exists(cache_path):
                    os.remove(cache_path)
                    logger.info(f"Cleared cache for {address}")
            except Exception as e:
                logger.warning(f"Failed to clear cache for {address}: {e}")
        else:
            # Clear all cache files
            try:
                for filename in os.listdir(self.cache_dir):
                    if filename.endswith('.json'):
                        os.remove(os.path.join(self.cache_dir, filename))
                logger.info("Cleared all device caches")
            except Exception as e:
                logger.warning(f"Failed to clear all caches: {e}")

    def list_cached_devices(self) -> List[str]:
        """List all devices with cached data

        Returns:
            List of device addresses (formatted with colons)
        """
        devices = []
        try:
            for filename in os.listdir(self.cache_dir):
                if filename.endswith('.json'):
                    # Convert filename back to address format
                    addr = filename[:-5].replace('_', ':')
                    devices.append(addr)
        except Exception as e:
            logger.warning(f"Failed to list cached devices: {e}")

        return devices


# Backwards compatibility alias
GATTCache = DeviceCache
