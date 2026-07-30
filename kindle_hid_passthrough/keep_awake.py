#!/usr/bin/env python3
"""Re-arm powerd's screensaver timer on HID input (issue #136).

powerd only counts native input, so pages turned from a Bluetooth device
look like an idle Kindle and the screensaver kicks in mid-read. Same poke
KOReader's AutoSuspend uses, and it leaves the screensaver enabled so the
power button still works.
"""

import subprocess
import threading
import time

POKE = ['lipc-set-prop', '-i', 'com.lab126.powerd', 'touchScreenSaverTimeout', '1']
INTERVAL = 240.0  # under powerd's 10 min t1 timeout

_last_poke = None
_lock = threading.Lock()


def on_activity():
    """Poke powerd, throttled. Safe to call from the report hot path."""
    global _last_poke
    now = time.monotonic()
    with _lock:
        if _last_poke is not None and now - _last_poke < INTERVAL:
            return
        _last_poke = now
    threading.Thread(target=_poke, name='keep_awake', daemon=True).start()


def _poke():
    try:
        subprocess.call(POKE, stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.SubprocessError):
        pass
