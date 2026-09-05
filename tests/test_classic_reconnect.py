#!/usr/bin/env python3
"""Replays the PW6 / Keychron K2 reconnect sessions from #203 against the real
Classic setup path. Run: python3 tests/test_classic_reconnect.py

Sessions 1-7 use the milliseconds from the cb0f404 table in #216. That table
records no encryption timestamps, so session 9 is constructed to cover the
other signal a peer can give. A dropped outcome means our side sent nothing
before the peer killed the link, not that the link survived. The peer's side is
replayed, our side is the code under test.
"""

import asyncio
import os
import sys
import types

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'kindle_hid_passthrough'))


def _stub_bumble():
    """Satisfy classic.py's imports without bumble installed."""
    core = types.ModuleType('bumble.core')
    core.BT_BR_EDR_TRANSPORT = 1
    core.BT_HUMAN_INTERFACE_DEVICE_SERVICE = 0x1124
    core.InvalidStateError = type('InvalidStateError', (Exception,), {})
    core.TimeoutError = asyncio.TimeoutError

    hci = types.ModuleType('bumble.hci')
    hci.Address = object
    hci.HCI_Write_Scan_Enable_Command = object
    hci.Role = type('Role', (), {'CENTRAL': 0, 'PERIPHERAL': 1})
    hci.HCI_DIFFERENT_TRANSACTION_COLLISION_ERROR = 0x2A
    hci.HCI_LMP_ERROR_TRANSACTION_COLLISION_OR_LL_PROCEDURE_COLLISION_ERROR = 0x23

    class HCI_Error(Exception):
        def __init__(self, error_code):
            super().__init__(f'error 0x{error_code:02X}')
            self.error_code = error_code

    hci.HCI_Error = HCI_Error

    hid = types.ModuleType('bumble.hid')
    hid.HID_CONTROL_PSM = 0x11
    hid.HID_INTERRUPT_PSM = 0x13
    hid.Message = object
    hid.SetProtocolMessage = object

    l2cap = types.ModuleType('bumble.l2cap')
    l2cap.ClassicChannelSpec = object

    sdp = types.ModuleType('bumble.sdp')
    sdp.Client = object

    sys.modules.setdefault('bumble', types.ModuleType('bumble'))
    for name, mod in (('bumble.core', core), ('bumble.hci', hci),
                      ('bumble.hid', hid), ('bumble.l2cap', l2cap),
                      ('bumble.sdp', sdp)):
        sys.modules[name] = mod


_stub_bumble()

import classic  # noqa: E402
from bumble.hci import HCI_Error, Role  # noqa: E402

COLLISION = 0x2A
ROLE_SWITCH_FAILED = 0x35


class Peer:
    """One observed reconnect from the peer's side. Times in ms from connect."""

    def __init__(self, name, *, switch_error=None, encrypt_error=None,
                 opens_at=None, encrypts_at=None, drops_at=None):
        self.name = name
        self.switch_error = switch_error
        self.encrypt_error = encrypt_error
        self.opens_at = opens_at
        self.encrypts_at = encrypts_at
        self.drops_at = drops_at


class FakeChannel:
    def __init__(self, psm):
        self.psm = psm


class FakeChannels:
    def __init__(self, calls):
        self.ctrl_channel = None
        self.intr_channel = None
        self._calls = calls

    async def connect_control_channel(self):
        self._calls.append('page_ctrl')
        self.ctrl_channel = FakeChannel(0x11)

    async def connect_interrupt_channel(self):
        self._calls.append('page_intr')
        self.intr_channel = FakeChannel(0x13)


class FakeConnection:
    """Bumble Connection surface used by _setup_classic_session."""

    def __init__(self, peer, calls):
        self.peer = peer
        self.calls = calls
        self.role = Role.PERIPHERAL
        self.encryption = 0
        self.authenticated = False
        self.peer_address = 'DC:2C:26:DF:AB:DC'

    @property
    def is_encrypted(self):
        return self.encryption != 0

    async def switch_role(self, role):
        self.calls.append('switch_role')
        if self.peer.switch_error:
            raise HCI_Error(self.peer.switch_error)
        self.role = role

    async def authenticate(self):
        self.calls.append('authenticate')
        self.authenticated = True

    async def encrypt(self, enable=True):
        self.calls.append('encrypt')
        if self.peer.encrypt_error:
            raise HCI_Error(self.peer.encrypt_error)
        self.encryption = 1


class FakeSession:
    def __init__(self, peer, calls):
        self.address = 'dc:2c:26:df:ab:dc'
        self.raw_address = 'DC:2C:26:DF:AB:DC'
        self.connection = FakeConnection(peer, calls)
        self.channels = FakeChannels(calls)
        self.setup_task = None
        self.ready = False


class FakeHost(classic.ClassicMixin):
    def _format_device(self, addr):
        return str(addr)

    def _classic_set_report_protocol(self, session):
        pass

    def _load_cached_descriptor(self, session):
        return True

    def _finalize_classic_hid(self, session):
        session.ready = True

    async def _query_classic_sdp(self, session):
        pass

    async def _teardown_session(self, session):
        pass


class RecordingLog:
    def __init__(self):
        self.lines = []

    def _record(self, level):
        return lambda msg, *a, **k: self.lines.append((level, msg))

    def __getattr__(self, level):
        return self._record(level)


async def replay(peer):
    """Run one session, return its calls, outcome, encryption and log."""
    calls = []
    session = FakeSession(peer, calls)
    host = FakeHost()
    recorder = RecordingLog()
    real_log, classic.log = classic.log, recorder

    loop = asyncio.get_running_loop()
    start = loop.time()

    def at(ms, fn):
        loop.call_later(ms / 1000.0, fn)

    def peer_opens_channels():
        session.channels.ctrl_channel = FakeChannel(0x11)
        session.channels.intr_channel = FakeChannel(0x13)

    def peer_encrypts():
        session.connection.encryption = 1

    def peer_drops_link():
        """The cancel _teardown_session issues from the disconnection event."""
        if session.setup_task and not session.setup_task.done():
            session.setup_task.cancel()

    if peer.opens_at:
        at(peer.opens_at, peer_opens_channels)
    if peer.encrypts_at:
        at(peer.encrypts_at, peer_encrypts)
    if peer.drops_at:
        at(peer.drops_at, peer_drops_link)

    task = asyncio.ensure_future(host._setup_classic_session(session, None))
    session.setup_task = task
    try:
        await task
        outcome = 'ready' if session.ready else 'incomplete'
    except asyncio.CancelledError:
        outcome = 'dropped'
    except Exception:
        outcome = 'failed'
    finally:
        classic.log = real_log

    return {
        'calls': calls,
        'outcome': outcome,
        'encrypted': session.connection.is_encrypted,
        'log': recorder.lines,
        'ms': round((loop.time() - start) * 1000),
    }


SESSIONS = [
    (Peer('1 switch collided, peer silent, dropped',
          switch_error=COLLISION, drops_at=285), 'dropped'),
    (Peer('2 switch collided, peer silent, dropped',
          switch_error=COLLISION, drops_at=333), 'dropped'),
    (Peer('3 peer opened the channels',
          encrypt_error=COLLISION, opens_at=659), 'ready'),
    (Peer('4 peer opened the channels, never encrypted',
          encrypt_error=COLLISION, opens_at=494), 'ready'),
    (Peer('5 ROLE_SWITCH_FAILED, peer silent, dropped',
          switch_error=ROLE_SWITCH_FAILED, drops_at=375), 'dropped'),
    (Peer('6 peer silent, dropped',
          encrypt_error=COLLISION, drops_at=519), 'dropped'),
    (Peer('7 peer opened the channels',
          switch_error=COLLISION, opens_at=283), 'ready'),
    (Peer('8 no peer procedure at all, the #85 shape'), 'ready'),
    (Peer('9 peer encrypts without opening, constructed',
          switch_error=COLLISION, encrypts_at=300), 'ready'),
]

SIGNALLED = {'3', '4', '7', '9'}
QUIET = {'8'}
INITIATED_ON_LINK = ('switch_role', 'authenticate', 'encrypt')


async def main():
    failures = []
    print(f"{'session':<46} {'ms':>6}  {'outcome':<9} {'enc':<5} calls")
    for peer, expected in SESSIONS:
        r = await replay(peer)
        num = peer.name.split()[0]
        print(f"{peer.name:<46} {r['ms']:>6}  {r['outcome']:<9} "
              f"{str(r['encrypted']):<5} {r['calls']}")

        def check(cond, why):
            if not cond:
                failures.append(f"session {num}: {why}")

        check(r['outcome'] == expected,
              f"outcome {r['outcome']}, expected {expected}")

        if num in SIGNALLED:
            sent = [c for c in r['calls'] if c in INITIATED_ON_LINK]
            check(sent == [],
                  f"initiated {sent} at a peer that was already driving")

        if num in QUIET:
            check(r['calls'] == ['switch_role', 'authenticate', 'encrypt',
                                 'page_ctrl', 'page_intr'],
                  f"quiet peer did not get the central path: {r['calls']}")
            check(r['encrypted'], "quiet peer left unencrypted")

        if peer.drops_at:
            check(r['ms'] < peer.drops_at + 150,
                  f"kept going {r['ms']} ms past a link that died at "
                  f"{peer.drops_at} ms")
            check(r['calls'] == [],
                  f"touched a dying link: {r['calls']}")


        if r['outcome'] == 'ready' and not r['encrypted']:
            check(any('not encrypted' in m for _, m in r['log']),
                  "declared HID ready on an unencrypted link without warning")

    print()
    if failures:
        for f in failures:
            print(f"FAIL {f}")
        sys.exit(1)
    print(f"OK {len(SESSIONS)} sessions")


if __name__ == '__main__':
    asyncio.run(main())
