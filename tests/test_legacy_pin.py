import asyncio
import sys
from pathlib import Path

import pytest

pytest.importorskip('bumble')
sys.path.insert(0, str(Path(__file__).parent.parent / 'kindle_hid_passthrough'))

import pairing
from bumble.hci import Address, HCI_PIN_Code_Request_Reply_Command
from pyee import EventEmitter


class FakeHost(EventEmitter):
    def __init__(self):
        super().__init__()
        self.commands = []

    async def send_command(self, command, check_result=False):
        self.commands.append(command)


class FakeDevice:
    def __init__(self):
        self.host = FakeHost()
        self.host.on('pin_code_request', self.on_pin_code_request)
        self.bumble_replies = 0

    def on_pin_code_request(self, address):
        self.bumble_replies += 1


def test_pin_request_answered_with_shown_pin():
    async def run():
        device = FakeDevice()
        pairing.install_legacy_pin_handler(device)
        address = Address('00:11:22:33:44:55')
        device.host.emit('pin_code_request', address)
        await asyncio.sleep(0.05)
        return device, address

    device, address = asyncio.run(run())

    # Bumble's own handler (which sends a negative reply) is replaced.
    assert device.bumble_replies == 0
    [command] = device.host.commands
    assert isinstance(command, HCI_PIN_Code_Request_Reply_Command)
    assert command.bd_addr == address

    pin = pairing.current_pin()
    assert pin is not None and len(pin) == 6 and pin.isdigit()
    assert command.pin_code_length == 6
    assert command.pin_code == pin.encode().ljust(16, b'\x00')

    pairing.clear_pin()
    assert pairing.current_pin() is None
