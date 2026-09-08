#!/usr/bin/env python3
"""MediaTek (Kindle 11th gen+) BT via the wmt_cdev_bt kernel module + /dev/stpbt."""

import glob
import os
import signal
import time

from bt_chip import BtChip, run
from config import config
from logging_utils import log

DEFAULT_MODULE_PATTERNS = [
    'wmt_cdev_bt.ko',   # MediaTek (PW4/5, Kindle 10/11, Scribe)
    'bt_drv.ko',         # Older Freescale/NXP Kindles
]

# Stock BT stack: respawn'd upstart jobs, so stop via upstart, never SIGKILL.
_STOCK_BT_JOBS = ('acsbtfd', 'btmanagerd')

# Shared Wi-Fi/CONSYS combo processes — killing one can drop Wi-Fi. Never touch.
_CRITICAL_COMMS = ('wmt_service', 'mtk_wmtd', 'wifid', 'wifim',
                   'stp_main', 'mtk_stp_psm', 'connfem')


def _find_bt_module(patterns=None):
    """Find the BT kernel module path for the running kernel, or None."""
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


def _proc_field(pid, name):
    """Read /proc/<pid>/<name>, or b'' if unavailable."""
    try:
        with open(f'/proc/{pid}/{name}', 'rb') as f:
            return f.read()
    except OSError:
        return b''


def _holder_info(pid):
    """Identity of a process holding a device: comm, cmdline, exe, uid."""
    comm = _proc_field(pid, 'comm').decode(errors='replace').strip()
    cmdline = (_proc_field(pid, 'cmdline')
               .replace(b'\0', b' ').decode(errors='replace').strip())
    try:
        exe = os.readlink(f'/proc/{pid}/exe')
    except OSError:
        exe = ''
    try:
        uid = os.stat(f'/proc/{pid}').st_uid
    except OSError:
        uid = None
    return {'pid': pid, 'comm': comm, 'cmdline': cmdline, 'exe': exe, 'uid': uid}


def _describe(h):
    return (f"pid={h['pid']} comm={h['comm'] or '?'} uid={h['uid']} "
            f"exe={h['exe'] or '?'} cmd='{h['cmdline']}'")


def _find_holders(device_path):
    """Scan /proc for processes holding device_path (excluding self)."""
    my_pid = os.getpid()
    holders = []
    try:
        pids = [e for e in os.listdir('/proc') if e.isdigit()]
    except OSError:
        return holders
    for pid in pids:
        if int(pid) == my_pid:
            continue
        fd_dir = f'/proc/{pid}/fd'
        try:
            fds = os.listdir(fd_dir)
        except OSError:
            continue
        for fd in fds:
            try:
                if os.readlink(f'{fd_dir}/{fd}') == device_path:
                    holders.append(_holder_info(pid))
                    break
            except OSError:
                continue
    return holders


def _graceful_kill(h, settle, device_path):
    """SIGTERM an unknown holder, then SIGKILL only if it clings to the node."""
    for sig in (signal.SIGTERM, signal.SIGKILL):
        if not _find_holders(device_path):
            return
        try:
            os.kill(int(h['pid']), sig)
            log.info(f"Sent {sig.name} to unknown holder {_describe(h)}")
        except OSError as e:
            log.warning(f"Could not signal pid={h['pid']}: {e}")
            return
        time.sleep(settle)


def _evict_holders(device_path, settle):
    """Free device_path: stop stock BT via upstart, spare Wi-Fi, SIGTERM the rest."""
    holders = _find_holders(device_path)
    if not holders:
        return
    for h in holders:
        log.info(f"{device_path} held by {_describe(h)}")

    critical = [h for h in holders if h['comm'] in _CRITICAL_COMMS]
    if critical:
        for h in critical:
            log.error(f"Refusing to evict critical connectivity process {_describe(h)}")
        return

    stock_jobs = {h['comm'] for h in holders if h['comm'] in _STOCK_BT_JOBS}
    if 'acsbtfd' in stock_jobs:
        stock_jobs.add('btmanagerd')
    for job in stock_jobs:
        log.info(f"Stopping stock BT service '{job}' via upstart")
        if not run(['/sbin/initctl', 'stop', job]):
            log.warning(f"'initctl stop {job}' failed")
    if stock_jobs:
        time.sleep(settle)

    for h in holders:
        if h['comm'] not in _STOCK_BT_JOBS and _find_holders(device_path):
            _graceful_kill(h, settle, device_path)


class MtkChip(BtChip):
    def prepare(self):
        device_path = self.kindle.device_path if self.kindle else '/dev/stpbt'
        settle = config.bt_settle_time
        patterns = config.bt_module_patterns
        if patterns is None and self.kindle and self.kindle.kernel_module:
            patterns = [self.kindle.kernel_module]

        module_path = _find_bt_module(patterns)
        if module_path:
            if _is_module_loaded(module_path):
                log.info(f"BT module already loaded: {os.path.basename(module_path)}")
            else:
                log.info(f"Loading BT module: {module_path}")
                if run(['/sbin/insmod', module_path]):
                    log.info("BT module loaded")
                    time.sleep(0.5)
                else:
                    log.warning(f"Failed to load {module_path} (may need root)")
        else:
            log.info("No BT kernel module found (may already be built-in)")

        if not os.path.exists(device_path):
            log.warning(f"{device_path} does not exist")
            return False
        if not _find_holders(device_path):
            log.info(f"{device_path} is available")
            return True

        log.info(f"{device_path} is busy, identifying and evicting holders...")
        _evict_holders(device_path, settle)
        if not _find_holders(device_path):
            log.info(f"{device_path} is now available")
            return True

        log.warning(f"{device_path} still busy, waiting 2s...")
        time.sleep(2.0)
        if not _find_holders(device_path):
            log.info(f"{device_path} is now available")
            return True

        log.warning(f"{device_path} still busy after cleanup")
        return False
