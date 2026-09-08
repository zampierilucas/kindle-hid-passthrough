#!/usr/bin/env python3
"""BT chip backends: per-Kindle Bluetooth lifecycle, selected by hardware."""

import os
import signal
import subprocess

from logging_utils import log


def run(cmd, **kwargs):
    """Run a command silently; return True on success."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10, **kwargs)
        return r.returncode == 0
    except Exception:
        return False


def _holders_from_proc(device_path):
    """PIDs holding device_path, read from /proc. Ours is never included."""
    me = os.getpid()
    holders = []
    for entry in os.listdir('/proc'):
        if not entry.isdigit() or int(entry) == me:
            continue
        fd_dir = f'/proc/{entry}/fd'
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f'{fd_dir}/{fd}') == device_path:
                    holders.append(int(entry))
                    break
            except OSError:
                continue
    return holders


def free_device(device_path):
    """Evict whatever userspace process holds device_path.

    fuser does it where there is one. Some Kindles ship without it (#225),
    and there the same answer is in /proc, so read it there instead.
    """
    try:
        r = subprocess.run(['fuser', '-k', device_path],
                           capture_output=True, timeout=5)
        if r.returncode == 0:
            holders = r.stderr.decode(errors='replace').strip()
            log.info(f"Evicted holders of {device_path}: {holders}")
        return True
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        log.info(f"fuser unavailable or timed out ({e}); scanning /proc instead")

    holders = _holders_from_proc(device_path)
    for pid in holders:
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError as e:
            log.warning(f"Could not kill {pid} holding {device_path}: {e}")
    if holders:
        log.info(f"Evicted holders of {device_path}: {holders}")
    return True


class BtChip:
    """Bluetooth lifecycle for one Kindle's chip.

    Defaults are no-ops; subclasses override only the hooks they need.
    """

    # False -> daemon powers BT off before system sleep, re-warms after wake
    survives_suspend = True

    # True -> HCI runs over a real UART that can drop bytes (issue #120)
    uart_hci = False

    def __init__(self, kindle):
        self.kindle = kindle

    def prepare(self) -> bool:
        """Bring the BT device to a state where the transport can open."""
        return True

    def pre_open(self):
        """Run before the HCI transport opens, to wake/verify the chip."""

    def on_transport_open(self):
        """Run right after the transport opens, before the first HCI command."""

    def on_transport_close(self):
        """Run after the transport closes, to drop anything held for it."""

    def on_hci_reset_timeout(self):
        """Run after HCI Reset times out, before the connect attempt is retried."""

    def power_off(self):
        """Turn the radio off (BT-off toggle)."""

    def ensure_powered(self):
        """Re-arm the chip before a (re)connect if it was powered off."""
