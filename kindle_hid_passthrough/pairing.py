#!/usr/bin/env python3
"""Bluetooth pairing utilities — delegate, config, and keystore."""

import secrets

from bumble.core import BT_BR_EDR_TRANSPORT
from bumble.hci import HCI_PIN_Code_Request_Negative_Reply_Command, HCI_PIN_Code_Request_Reply_Command
from bumble.keys import JsonKeyStore
from bumble.pairing import PairingConfig, PairingDelegate
from bumble.utils import AsyncRunner

from logging_utils import errstr, log

__all__ = ['AutoAcceptPairingDelegate', 'create_pairing_config', 'create_keystore',
           'install_legacy_pin_handler', 'current_pin']

# PIN the user must type on a legacy (Bluetooth 2.0) keyboard during pairing,
# or None. Read by the API server so the UIs can show it.
_current_pin = None


def current_pin():
    return _current_pin


def clear_pin():
    global _current_pin
    _current_pin = None


class AutoAcceptPairingDelegate(PairingDelegate):
    """Pairing delegate that auto-accepts all pairing requests."""

    def __init__(self, io_capability=PairingDelegate.DISPLAY_OUTPUT_AND_YES_NO_INPUT):
        super().__init__(io_capability=io_capability)

    async def accept(self):
        log.success("Pairing request received - accepting")
        return True

    async def compare_numbers(self, number, digits):
        log.warning(f"Confirm number: {number:0{digits}}")
        log.warning("Auto-accepting (press Ctrl+C to cancel)")
        return True

    async def get_number(self):
        return 0

    async def display_number(self, number, digits):
        log.info(f"Display PIN: {number:0{digits}}")


def create_pairing_config(conn=None) -> PairingConfig:
    """Create pairing configuration; relaxed for Classic, strict for BLE."""
    transport = getattr(conn, 'transport', None) if conn is not None else None
    if transport == BT_BR_EDR_TRANSPORT:
        log.info("[Pairing] Classic config: sc=False, mitm=False, NoInputNoOutput")
        return PairingConfig(
            sc=False,
            mitm=False,
            bonding=True,
            delegate=AutoAcceptPairingDelegate(
                io_capability=PairingDelegate.NO_OUTPUT_NO_INPUT
            ),
        )

    return PairingConfig(
        sc=True,
        mitm=True,
        bonding=True,
        delegate=AutoAcceptPairingDelegate(),
    )


def create_keystore(path: str) -> JsonKeyStore:
    """Create a JSON-based key store for bonding keys."""
    return JsonKeyStore(namespace=None, filename=path)


def install_legacy_pin_handler(device):
    """Answer Classic legacy PIN requests with a generated PIN.

    Pre-2.1 keyboards (e.g. Apple A1255) pair by having the user type a PIN
    on the keyboard. Bumble only answers a PIN request when the delegate is
    KEYBOARD_ONLY, which would also change SSP pairing for every other device,
    so take over just the PIN request and leave SSP alone.
    """
    host = device.host
    host.remove_listener('pin_code_request', device.on_pin_code_request)

    async def reply(address):
        global _current_pin
        pin = f"{secrets.randbelow(1_000_000):06d}"
        _current_pin = pin
        log.warning(f"[Classic] Legacy PIN pairing: type {pin} on the keyboard, then press Enter")
        try:
            await host.send_command(
                HCI_PIN_Code_Request_Reply_Command(
                    bd_addr=address,
                    pin_code_length=len(pin),
                    pin_code=pin.encode().ljust(16, b'\x00'),
                ),
                check_result=True,
            )
        except Exception as e:
            log.warning(f"[Classic] PIN reply failed: {errstr(e)}")
            clear_pin()
            await host.send_command(
                HCI_PIN_Code_Request_Negative_Reply_Command(bd_addr=address)
            )

    host.on('pin_code_request', lambda address: AsyncRunner.spawn(reply(address)))
