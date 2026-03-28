#!/usr/bin/env python3
"""
Bluetooth hardware setup for Kindle.

Ensures the BT kernel module is loaded and Amazon's conflicting
BT processes are stopped before opening the HCI transport.

Auto-detects kernel version and module paths. Override via config.ini:

    [bluetooth]
    module_patterns = wmt_cdev_bt.ko, bt_drv.ko
    kill_processes = bluetoothd, vhci_stpbt_bridge
    settle_time = 0.5

"""

import glob
import os
import subprocess
import time

from logging_utils import log

# Known BT kernel module patterns across Kindle versions
DEFAULT_MODULE_PATTERNS = [
    'wmt_cdev_bt.ko',   # MediaTek (PW4/5, Kindle 10/11, Scribe)
    'bt_drv.ko',         # Older Freescale/NXP Kindles
]

# Known Amazon BT processes that hold /dev/stpbt
DEFAULT_KILL_PROCESSES = [
    'bluetoothd',
    'vhci_stpbt_bridge',
]


def _run(cmd, **kwargs):
    """Run a command silently, return success."""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=10, **kwargs)
        return r.returncode == 0
    except Exception:
        return False


def _find_bt_module(patterns=None):
    """Find the BT kernel module path for the running kernel.

    Returns:
        Module path string, or None if not found.
    """
    patterns = patterns or DEFAULT_MODULE_PATTERNS

    try:
        uname = os.uname().release
    except Exception:
        return None

    base = f'/lib/modules/{uname}/extra'

    for pattern in patterns:
        matches = glob.glob(f'{base}/{pattern}')
        if matches:
            return matches[0]
        # Also check subdirectories
        matches = glob.glob(f'{base}/**/{pattern}', recursive=True)
        if matches:
            return matches[0]

    return None


def _is_module_loaded(module_path):
    """Check if a kernel module is already loaded."""
    mod_name = os.path.basename(module_path).replace('.ko', '')
    try:
        with open('/proc/modules', 'r') as f:
            for line in f:
                if line.split()[0] == mod_name:
                    return True
    except Exception:
        pass
    return False


def _kill_processes(names=None):
    """Kill conflicting BT processes.

    Returns:
        Number of processes killed.
    """
    names = names or DEFAULT_KILL_PROCESSES
    killed = 0
    for name in names:
        if _run(['killall', name]):
            log.info(f"Killed {name}")
            killed += 1
    return killed


def _is_device_free(device_path):
    """Check if the BT device can be opened."""
    try:
        fd = os.open(device_path, os.O_RDWR | os.O_NONBLOCK)
        os.close(fd)
        return True
    except OSError:
        return False


def prepare_bt(transport_spec=None, module_patterns=None,
               kill_processes=None, settle_time=0.5):
    """Prepare Bluetooth hardware for use.

    1. Load BT kernel module if not already loaded
    2. Kill Amazon's conflicting BT processes
    3. Wait for device to settle

    Args:
        transport_spec: Transport string (e.g. 'file:/dev/stpbt') to
                       extract device path. If None, uses /dev/stpbt.
        module_patterns: List of module filename patterns to search for.
        kill_processes: List of process names to kill.
        settle_time: Seconds to wait after killing processes.

    Returns:
        True if BT device is ready.
    """
    # Extract device path from transport spec
    device_path = '/dev/stpbt'
    if transport_spec and transport_spec.startswith('file:'):
        device_path = transport_spec[5:]

    log.info("Preparing Bluetooth hardware...")

    # Step 1: Load kernel module
    module_path = _find_bt_module(module_patterns)
    if module_path:
        if _is_module_loaded(module_path):
            log.info(f"BT module already loaded: {os.path.basename(module_path)}")
        else:
            log.info(f"Loading BT module: {module_path}")
            if _run(['/sbin/insmod', module_path]):
                log.info("BT module loaded")
                time.sleep(0.5)  # wait for /dev node to appear
            else:
                log.warning(f"Failed to load {module_path} (may need root)")
    else:
        log.info("No BT kernel module found (may already be built-in)")

    # Step 2: Check if device is available
    if not os.path.exists(device_path):
        log.warning(f"{device_path} does not exist")
        return False

    if _is_device_free(device_path):
        log.info(f"{device_path} is available")
        return True

    # Step 3: Device is busy - kill conflicting processes
    log.info(f"{device_path} is busy, stopping conflicting processes...")
    killed = _kill_processes(kill_processes)

    if killed > 0 and settle_time > 0:
        time.sleep(settle_time)

    # Step 4: Verify
    if _is_device_free(device_path):
        log.info(f"{device_path} is now available")
        return True

    # Last resort: try again with a longer wait
    log.warning(f"{device_path} still busy, waiting 2s...")
    time.sleep(2.0)

    if _is_device_free(device_path):
        log.info(f"{device_path} is now available")
        return True

    log.warning(f"{device_path} still busy after cleanup")
    return False
