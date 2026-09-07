#!/usr/bin/env python3
"""Bluetooth hardware setup — select and drive the per-Kindle chip backend."""

import glob
import os
import re
import stat

from bt_brcm import BrcmChip
from bt_chip import run
from bt_mtk import MtkChip
from kindle_detect import detect_codename, detect_kindle
from logging_utils import log

VERSION_TXT = '/etc/version.txt'


def _module_search_dirs():
    here = os.path.dirname(os.path.abspath(__file__))
    base = os.environ.get('KINDLE_HID_BASE', '/mnt/us/kindle_hid_passthrough')
    dirs = [
        os.path.join(here, 'modules'),
        os.path.join(base, 'dist', 'kindle_hid_passthrough', 'modules'),
        os.path.join(base, 'modules'),
    ]
    seen = set()
    return [d for d in dirs if not (d in seen or seen.add(d))]


def _find_bundled_kos(pattern, exact_first):
    """Bundled modules matching a glob, deduped by basename, exact build first."""
    found = {}
    for d in _module_search_dirs():
        for ko in glob.glob(os.path.join(d, pattern)):
            found.setdefault(os.path.basename(ko), ko)
    return sorted(found.values(), key=lambda p: os.path.basename(p) != exact_first)

_chip = None


def chip():
    """The BT chip backend for this Kindle (memoized; one chip per device)."""
    global _chip
    if _chip is None:
        _chip = make_chip(detect_kindle())
    return _chip


def make_chip(kindle):
    """Pick the chip backend for a detected Kindle."""
    if kindle and kindle.transport_scheme == 'serial':
        return BrcmChip(kindle)
    return MtkChip(kindle)


def _read_version_line():
    try:
        with open(VERSION_TXT) as f:
            return f.readline().strip()
    except OSError:
        return None


def _read_firmware_build():
    line = _read_version_line()
    if not line:
        return None
    m = re.search(r'-(\d+)\s*$', line)
    return m.group(1) if m else None


def _log_missing_kmod(codename, expected=None, mod='uhid', optional=False):
    kindle = detect_kindle()
    say = log.warning if optional else log.error
    if optional:
        say(f"no bundled {mod}.ko for this Kindle; HID passthrough is unaffected")
    else:
        say(f"no bundled {mod}.ko for this Kindle; we need to build one")
    if expected:
        say(f"  module needed : {expected}")
    say(f"  model         : {kindle.model_name if kindle else 'unknown'}")
    say(f"  codename      : {codename or 'unknown'}")
    say(f"  kernel        : {os.uname().release}")
    say(f"  version.txt   : {_read_version_line() or 'unreadable'}")
    say(f"  searched      : {', '.join(_module_search_dirs())}")
    if optional:
        say("  ^ only needed to inject key events for external tools like "
            "kindle-button-mapper; open an issue with these lines if you want it")
    else:
        say("  ^ open an issue with these lines so we can compile the module")


def _node_ready(path):
    """True when the node exists and the driver behind it opens."""
    try:
        os.close(os.open(path, os.O_RDWR | os.O_NONBLOCK))
        return True
    except OSError:
        return False


def _create_dev_node(sysfs_dev, dev_path):
    """Create a char device node from a sysfs 'major:minor' dev attribute.

    Needed on kernels without devtmpfs (e.g. Oasis 1 / duet), where
    misc_register does not auto-create /dev/uhid.
    """
    try:
        with open(sysfs_dev) as f:
            major, minor = (int(x) for x in f.read().strip().split(':'))
        os.mknod(dev_path, stat.S_IFCHR | 0o600, os.makedev(major, minor))
        return True
    except (OSError, ValueError) as e:
        log.error(f"could not create {dev_path}: {e}")
        return False


def _ensure_hid_core(kernel, build, codename):
    """uhid needs the HID core; the Oasis 1 kernel ships without it.

    When the hid bus isn't registered, load a bundled hid.ko (hid-core +
    hid-input) so uhid's hid_* symbols resolve. No-op on kernels that
    already have HID built in.
    """
    if os.path.exists('/sys/bus/hid'):
        return
    exact = f"hid-{kernel}-{build}-{codename}.ko"
    for ko in _find_bundled_kos(f"hid-{kernel}-*-{codename}.ko", exact_first=exact):
        log.info(f"loading {os.path.basename(ko)} (HID core)")
        if run(['/sbin/insmod', ko]) and os.path.exists('/sys/bus/hid'):
            return


def ensure_uhid():
    """Load bundled uhid.ko on Kindles whose stock kernel lacks CONFIG_UHID."""
    if _node_ready('/dev/uhid'):
        return True
    codename = detect_codename()
    if not codename:
        return False
    build = _read_firmware_build()
    if not build:
        _log_missing_kmod(codename)
        return False
    kernel = os.uname().release
    expected = f"uhid-{kernel}-{build}-{codename}.ko"
    candidates = _find_bundled_kos(f"uhid-{kernel}-*-{codename}.ko", exact_first=expected)
    if not candidates:
        _log_missing_kmod(codename, expected)
        return False
    _ensure_hid_core(kernel, build, codename)
    for ko in candidates:
        log.info(f"loading {os.path.basename(ko)}")
        if not run(['/sbin/insmod', ko]):
            continue
        # duet lacks devtmpfs, so misc_register doesn't create /dev/uhid
        if not _node_ready('/dev/uhid'):
            _create_dev_node('/sys/class/misc/uhid/dev', '/dev/uhid')
        if _node_ready('/dev/uhid'):
            return True
    _log_missing_kmod(codename, expected)
    return False


def ensure_uinput():
    """Best-effort /dev/uinput: stock module, then bundled .ko, else explain."""
    if _node_ready('/dev/uinput'):
        return True
    # Device may ship uinput.ko itself (in /lib/modules) even if not built-in.
    if run(['/sbin/modprobe', 'uinput']) and _node_ready('/dev/uinput'):
        return True
    codename = detect_codename()
    build = _read_firmware_build() if codename else None
    expected = None
    if codename and build:
        kernel = os.uname().release
        expected = f"uinput-{kernel}-{build}-{codename}.ko"
        for ko in _find_bundled_kos(f"uinput-{kernel}-*-{codename}.ko", exact_first=expected):
            log.info(f"loading {os.path.basename(ko)}")
            if not run(['/sbin/insmod', ko]):
                continue
            if not _node_ready('/dev/uinput'):
                _create_dev_node('/sys/class/misc/uinput/dev', '/dev/uinput')
            if _node_ready('/dev/uinput'):
                return True
    _log_missing_kmod(codename, expected, mod='uinput', optional=True)
    return False


def prepare_bt():
    """Load uhid if needed, then prepare the chip. True if BT is ready."""
    ensure_uhid()
    ensure_uinput()
    log.info("Preparing Bluetooth hardware...")
    return chip().prepare()
