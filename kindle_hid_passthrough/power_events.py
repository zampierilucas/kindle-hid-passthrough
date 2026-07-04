#!/usr/bin/env python3
"""Kindle power event monitor for safe BT/Wi-Fi coexistence."""

import asyncio
import subprocess
from typing import Awaitable, Callable, Optional

from logging_utils import log

PowerEventHandler = Callable[[str], Awaitable[None]]


class KindlePowerEventMonitor:
    """Monitor powerd LIPC events and notify the daemon.

    The MediaTek WMT chip is shared by Bluetooth and Wi-Fi. The HID daemon must
    release its HCI transport before suspend and wait after resume so Kindle's
    stock WMT/Wi-Fi services can restore the chip first.
    """

    EVENTS = (
        "goingToScreenSaver",
        "readyToSuspend",
        "suspending",
        "wakeupFromSuspend",
        "resuming",
        "outOfScreenSaver",
    )

    def __init__(
        self,
        handler: PowerEventHandler,
        *,
        enabled: bool = True,
    ):
        self.handler = handler
        self.enabled = enabled
        self._task: Optional[asyncio.Task] = None
        self._process = None
        self._stopped = asyncio.Event()

    def start(self):
        if not self.enabled:
            log.info("Power event monitor disabled")
            return
        if self._task and not self._task.done():
            log.debug("Power event monitor already running")
            return
        self._stopped = asyncio.Event()
        self._task = asyncio.create_task(self._run(), name="power_event_monitor")

    async def stop(self):
        self._stopped.set()
        if self._process and self._process.returncode is None:
            self._process.terminate()
            try:
                await asyncio.wait_for(self._process.wait(), timeout=2.0)
            except asyncio.TimeoutError:
                self._process.kill()
                await self._process.wait()
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        self._process = None
        self._task = None

    async def _run(self):
        while not self._stopped.is_set():
            try:
                self._process = await asyncio.create_subprocess_exec(
                    "lipc-wait-event",
                    "-m",
                    "-s",
                    "0",
                    "-t",
                    "com.lab126.powerd",
                    "*",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                )
            except FileNotFoundError:
                log.info("lipc-wait-event not available; power monitor inactive")
                return
            except Exception as e:
                log.warning(f"Power monitor failed to start: {e}")
                await asyncio.sleep(30)
                continue

            log.info("Power event monitor started")
            try:
                assert self._process.stdout is not None
                while not self._stopped.is_set():
                    line = await self._process.stdout.readline()
                    if not line:
                        break
                    event = self._parse_event(line.decode(errors="replace"))
                    if not event:
                        continue
                    try:
                        await self.handler(event)
                    except Exception as e:
                        log.warning(f"Power event handler failed for {event}: {e}")
            finally:
                if self._process.returncode is None:
                    self._process.terminate()
                    try:
                        await asyncio.wait_for(self._process.wait(), timeout=2.0)
                    except asyncio.TimeoutError:
                        self._process.kill()
                        await self._process.wait()
                self._process = None

            if not self._stopped.is_set():
                log.warning("Power event monitor exited; restarting in 5s")
                await asyncio.sleep(5)

    def _parse_event(self, line: str) -> Optional[str]:
        for event in self.EVENTS:
            if event in line:
                return event
        return None
