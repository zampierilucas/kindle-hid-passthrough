#!/usr/bin/env python3
"""
BLE Pairing Utilities

Handles SMP pairing delegation and key storage management.
Bypasses the broken kernel SMP implementation by using Bumble's
userspace SMP.

Author: Lucas Zampieri <lzampier@redhat.com>
"""

from bumble.pairing import PairingConfig, PairingDelegate
from bumble.keys import JsonKeyStore

from logging_utils import log

__all__ = [
    'AutoAcceptPairingDelegate',
    'create_pairing_config',
    'create_keystore',
]


class AutoAcceptPairingDelegate(PairingDelegate):
    """Pairing delegate that auto-accepts all pairing requests.

    Uses DISPLAY_OUTPUT_AND_YES_NO_INPUT capability to support
    numeric comparison pairing methods.
    """

    def __init__(self):
        super().__init__(
            io_capability=PairingDelegate.DISPLAY_OUTPUT_AND_YES_NO_INPUT
        )

    async def accept(self):
        """Accept incoming pairing request"""
        log.success("Pairing request received - accepting")
        return True

    async def compare_numbers(self, number, digits):
        """Confirm numeric comparison (auto-accept)"""
        log.warning(f"Confirm number: {number:0{digits}}")
        log.warning("Auto-accepting (press Ctrl+C to cancel)")
        return True

    async def get_number(self):
        """Return PIN code (0 for default)"""
        log.warning("Enter PIN (or 0 for default)")
        return 0

    async def display_number(self, number, digits):
        """Display PIN to user"""
        log.info(f"Display PIN: {number:0{digits}}")


def create_pairing_config() -> PairingConfig:
    """Create pairing configuration with secure defaults.

    Returns:
        PairingConfig with:
        - Secure Connections enabled
        - MITM protection enabled
        - Bonding enabled (keys are saved)
        - Auto-accept delegate
    """
    return PairingConfig(
        sc=True,       # Secure Connections
        mitm=True,     # MITM protection
        bonding=True,  # Enable bonding (save keys)
        delegate=AutoAcceptPairingDelegate(),
    )


def create_keystore(path: str) -> JsonKeyStore:
    """Create a JSON-based key store for bonding keys.

    Args:
        path: File path for storing keys (JSON format)

    Returns:
        JsonKeyStore instance that persists pairing keys
    """
    return JsonKeyStore(namespace=None, filename=path)
