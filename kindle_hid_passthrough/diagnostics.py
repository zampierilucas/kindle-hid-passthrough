#!/usr/bin/env python3
"""Read-only diagnostics dump for bug reports.

Gathers everything we routinely ask reporters for (model, firmware, transport,
serial termios, BT proc state, running daemons, kernel BT logs) in one paste.
Safe to run at any time: nothing here writes to the chip or the UART.
"""

import os
import subprocess

from bt_setup import _node_ready
from config import config, get_version
from kindle_detect import (detect_codename, detect_kindle, read_serial,
                           _decode_device_code)

_lines = []


def _out(line=''):
    _lines.append(line)


def _hdr(title):
    _out()
    _out(f"===== {title} =====")


def _kv(key, val):
    _out(f"{key:<22}: {val}")


def _sh(cmd, timeout=8):
    """Run a shell command, return combined output or an error marker."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True,
                           timeout=timeout)
        return (r.stdout + r.stderr).strip()
    except (FileNotFoundError, subprocess.TimeoutExpired) as e:
        return f"<{type(e).__name__}>"


def _read(path):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError as e:
        return f"<{e.__class__.__name__}: {e.errno}>"


_BAUD_CODES = {}


def _baud_map():
    if not _BAUD_CODES:
        import termios
        for name in dir(termios):
            if name.startswith('B') and name[1:].isdigit():
                _BAUD_CODES[getattr(termios, name)] = int(name[1:])
    return _BAUD_CODES


def _termios_flags(path):
    """Read the port's live termios without disturbing it. Serial only."""
    try:
        import termios
    except ImportError:
        return "<no termios module>"
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOCTTY)
        iflag, oflag, cflag, lflag, ispeed, ospeed, _cc = termios.tcgetattr(fd)
        baud = _baud_map().get(ospeed, ospeed)
        crtscts = bool(cflag & termios.CRTSCTS)
        clocal = bool(cflag & termios.CLOCAL)
        return f"baud={baud} crtscts={crtscts} clocal={clocal}"
    except OSError as e:
        return f"<{e.__class__.__name__}: {e}>"
    finally:
        if fd is not None:
            os.close(fd)


def _proc_line(name):
    pids = _sh(['pgrep', '-x', name]).split()
    pids = [p for p in pids if p.isdigit()]
    if not pids:
        return "not running"
    ages = []
    try:
        from bt_brcm import _pid_age
        for p in pids:
            a = _pid_age(int(p))
            ages.append(f"{p}(age {a:.1f}s)" if a is not None else p)
    except Exception:
        ages = pids
    return ', '.join(ages)


def run_diagnostics():
    _out(f"Kindle HID Passthrough diagnostics  v{get_version()}")

    _hdr("Model")
    serial = read_serial()
    code = _decode_device_code(serial) if serial else None
    kindle = detect_kindle()
    _kv("serial (usid)", serial or "<unreadable>")
    _kv("device code", f"0x{code:X}" if code is not None else "<none>")
    _kv("model", kindle.model_name if kindle else "<unrecognized>")
    _kv("codename", detect_codename() or "<none>")
    if kindle:
        _kv("transport scheme", kindle.transport_scheme)
        _kv("device path", kindle.device_path)
        _kv("baud rate", kindle.baud_rate)
        _kv("flow control", kindle.flow_control)

    _hdr("System")
    _kv("kernel", os.uname().release)
    _kv("version.txt", _read('/etc/version.txt').splitlines()[0]
        if os.path.exists('/etc/version.txt') else "<none>")
    _kv("uptime", _read('/proc/uptime').split()[0] + "s")

    _hdr("Transport / config")
    _kv("config transport", config.transport or "<none>")
    _kv("hci_reset_timeout", f"{config.hci_reset_timeout}s")
    _kv("transport_timeout", f"{config.transport_timeout}s")
    try:
        from bt_setup import chip
        _kv("chip backend", type(chip()).__name__)
    except Exception as e:
        _kv("chip backend", f"<{e.__class__.__name__}>")

    _hdr("BT device node")
    dev = kindle.device_path if kindle else None
    if dev:
        _kv("exists", os.path.exists(dev))
        _kv("ls -l", _sh(['ls', '-l', dev]))
        if os.path.exists(dev):
            _kv("holders (fuser)", _sh(['fuser', dev]) or "<none>")
            if kindle and kindle.transport_scheme == 'serial':
                _kv("live termios", _termios_flags(dev))

    _hdr("BT proc interface")
    for p in ('/proc/bluetooth/btenable',
              '/proc/bluetooth/sleep/proto',
              '/proc/bluetooth/sleep/btwake'):
        if os.path.exists(p):
            _kv(p, _read(p))

    _hdr("Processes")
    _kv("bsa_server", _proc_line('bsa_server'))
    _kv("btd", _proc_line('btd'))
    _kv("daemon (main.py)", _sh(['pgrep', '-f', 'main.py --daemon']) or "not running")

    _hdr("UHID")
    _kv("/dev/uhid", _node_ready('/dev/uhid'))
    _kv("/dev/uinput", _node_ready('/dev/uinput'))
    _kv("/sys/bus/hid", os.path.exists('/sys/bus/hid'))
    _kv("modules", _sh(['sh', '-c', 'lsmod | grep -iE "uhid|hidp|^hid|bt" || true']) or "<none>")

    _hdr("lipc BT state")
    _kv("btfd BTstate", _sh(['lipc-get-prop', 'com.lab126.btfd', 'BTstate']))

    _hdr("Kernel BT log (dmesg tail)")
    _out(_sh(['sh', '-c', 'dmesg | grep -iE "bluetooth|hci|btmxc|ttymxc2|bcm|wmt|stpbt|conninfra|mtk" | tail -25 || true'])
         or "<none>")

    _hdr("Daemon log tail")
    logf = '/var/log/hid_passthrough.log'
    _out(_sh(['tail', '-30', logf]) if os.path.exists(logf) else "<no log file>")

    print('\n'.join(_lines))
