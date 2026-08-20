#!/usr/bin/env python3
"""Tests for the powerd suspend policy (issue #180). Run: python3 tests/test_power_policy.py"""

import asyncio
import os
import sys

sys.path.insert(0, os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    'kindle_hid_passthrough'))

import controller as controller_mod  # noqa: E402
from controller import DaemonController  # noqa: E402


class FakeDaemon:
    def __init__(self):
        self._suspended = False
        self.running = True
        self.calls = []

    async def suspend(self):
        self.calls.append('suspend')
        self._suspended = True

    async def resume(self):
        self.calls.append('resume')
        self._suspended = False


class FakeChip:
    def __init__(self, survives_suspend):
        self.survives_suspend = survives_suspend
        self.calls = []

    def power_off(self):
        self.calls.append('power_off')


def drive(survives_suspend, events):
    """Feed powerd events to a fresh controller; return (daemon, chip)."""
    daemon = FakeDaemon()
    chip = FakeChip(survives_suspend)
    controller_mod.chip = lambda: chip

    async def run():
        ctrl = DaemonController(daemon)
        for event in events:
            if event in ('goingToScreenSaver', 'readyToSuspend'):
                await ctrl._do_system_suspend(event)
            else:
                await ctrl._do_system_resume(event)

    asyncio.run(run())
    return daemon, chip


def test_broadcom_brackets_screen_off():
    daemon, chip = drive(False, ['goingToScreenSaver', 'outOfScreenSaver'])
    assert daemon.calls == ['suspend', 'resume'], daemon.calls
    assert chip.calls == ['power_off'], chip.calls


def test_mtk_keeps_radio_up_across_the_screensaver():
    daemon, chip = drive(True, ['goingToScreenSaver', 'outOfScreenSaver'])
    assert daemon.calls == [], daemon.calls
    assert chip.calls == [], chip.calls


def test_mtk_detaches_for_a_real_suspend_without_powering_off():
    daemon, chip = drive(
        True, ['goingToScreenSaver', 'readyToSuspend', 'wakeupFromSuspend'])
    assert daemon.calls == ['suspend', 'resume'], daemon.calls
    assert chip.calls == [], chip.calls
    assert not daemon._suspended


def test_mtk_resumes_once_when_both_wake_events_arrive():
    daemon, _ = drive(
        True, ['readyToSuspend', 'wakeupFromSuspend', 'outOfScreenSaver'])
    assert daemon.calls == ['suspend', 'resume'], daemon.calls


def test_mtk_resumes_when_only_the_screensaver_wake_arrives():
    daemon, _ = drive(True, ['readyToSuspend', 'outOfScreenSaver'])
    assert daemon.calls == ['suspend', 'resume'], daemon.calls


def main():
    tests = [v for k, v in sorted(globals().items()) if k.startswith('test_')]
    failed = 0
    for t in tests:
        try:
            t()
            print(f"ok   {t.__name__}")
        except AssertionError as e:
            failed += 1
            print(f"FAIL {t.__name__}: {e}")
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return 1 if failed else 0


if __name__ == '__main__':
    sys.exit(main())
