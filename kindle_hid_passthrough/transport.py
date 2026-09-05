#!/usr/bin/env python3
"""Bumble transport and device initialization."""

import asyncio
import os

# Not in every cross-compiled python bundle, and only the Broadcom UART path
# needs it.
try:
    import termios
except ImportError:
    termios = None

from bumble.device import Device
from bumble.hci import HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND, LeFeatureMask
from bumble.transport import open_transport

from config import config
from hci_parser import install_resync_parser
from logging_utils import log

__all__ = ['create_bumble_device']


def _tty_fd(transport, device_path):
    """The open tty fd behind this transport, whichever scheme opened it."""
    try:
        fd = transport.sink.transport.serial.fileno()
        if os.isatty(fd):
            return fd
    except (AttributeError, OSError):
        pass
    # file: transports (the probe fallback) hand us no serial object, so find
    # our own fd for the device instead.
    if not device_path:
        return None
    try:
        for entry in os.listdir('/proc/self/fd'):
            try:
                if os.readlink(f'/proc/self/fd/{entry}') != device_path:
                    continue
                fd = int(entry)
                if os.isatty(fd):
                    return fd
            except (OSError, ValueError):
                continue
    except OSError:
        pass
    return None


def _apply_hci_termios(transport, device_path):
    """Ignore breaks on the HCI UART.

    pyserial clears IGNBRK on every open, so a line break arrives as a literal
    0x00 in the HCI stream and desyncs the parser (issue #120).
    """
    if termios is None:
        log.warning("No termios module; leaving HCI UART flags alone "
                    "(issue #120 may resurface)")
        return
    fd = _tty_fd(transport, device_path)
    if fd is None:
        return
    try:
        attrs = termios.tcgetattr(fd)
        attrs[0] |= termios.IGNBRK
        attrs[0] &= ~(termios.BRKINT | termios.PARMRK | termios.INPCK
                      | termios.ISTRIP)
        termios.tcsetattr(fd, termios.TCSANOW, attrs)
    except termios.error as e:
        log.warning(f"Could not set HCI termios flags: {e}")


def _release_leaked_fds(device_path: str) -> int:
    """Close fds in this process pointing at device_path. Returns count."""
    closed = 0
    try:
        for entry in os.listdir('/proc/self/fd'):
            try:
                target = os.readlink(f'/proc/self/fd/{entry}')
            except OSError:
                continue
            if target == device_path:
                try:
                    os.close(int(entry))
                    closed += 1
                except OSError:
                    pass
    except OSError:
        pass
    return closed


async def _open_transport_with_recovery(spec: str):
    try:
        return await asyncio.wait_for(
            open_transport(spec), timeout=config.transport_timeout)
    except OSError as e:
        if e.errno != 16 or not spec.startswith('file:'):
            raise
        device_path = spec[5:]
        n = _release_leaked_fds(device_path)
        if n == 0:
            raise
        log.warning(f"Released {n} leaked fd(s) for {device_path}, retrying")
        return await asyncio.wait_for(
            open_transport(spec), timeout=config.transport_timeout)


async def create_bumble_device(transport_spec=None, configure=None):
    """Open HCI transport, create a Bumble Device, reset, and power on.

    Args:
        transport_spec: HCI transport spec, defaults to config.transport.
        configure: Optional callback receiving the Device before HCI reset
            and power-on. Keystore, pairing config, and SSP/SC flags must
            be set here: power_on() applies them to the controller.

    Returns:
        (transport, device) tuple. The transport is closed before raising
        on any failure past the open, so no stpbt fd is leaked.
    """
    spec = transport_spec or config.transport
    if not spec:
        raise RuntimeError("No HCI transport available")

    # chip hook: wake/verify the chip before we open and reset it
    from bt_setup import chip
    chip().pre_open()

    log.info("Opening transport...")
    try:
        transport = await _open_transport_with_recovery(spec)
    except asyncio.TimeoutError:
        log.error(f"Transport open timed out after {config.transport_timeout}s")
        raise

    # UART HCI drops bytes when the SoC wakes from deep idle, so the parser has
    # to resync rather than trust a corrupt header (issue #120). Keyed off the
    # chip, not the spec: an undetected Kindle falls back to a file: spec for
    # the same UART.
    if chip().uart_hci:
        install_resync_parser(transport)
        _apply_hci_termios(transport, chip().kindle.device_path)

    # chip hook: runs after the transport opens, before the first HCI command
    chip().on_transport_open()

    try:
        device = Device.with_hci(
            config.device_name,
            config.device_address,
            transport.source,
            transport.sink
        )

        if configure:
            configure(device)

        log.info("Sending HCI Reset...")
        try:
            await asyncio.wait_for(
                device.host.reset(),
                timeout=config.hci_reset_timeout
            )
            log.success("HCI Reset successful")
            await asyncio.sleep(0.2)
        except asyncio.TimeoutError:
            log.error("HCI Reset timed out")
            chip().on_hci_reset_timeout()
            raise

        device.address_resolution_offload = (
            device.host.supports_le_features(LeFeatureMask.LL_PRIVACY)
            and device.host.supports_command(HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND)
        )

        await device.power_on()
        log.success(f"Device powered on: {device.public_address}")

        # chip hook: bring-up is done, hand the chip back to its sleep protocol
        chip().on_ready()
    except BaseException:
        try:
            await transport.close()
        except Exception:
            pass
        chip().on_transport_close()
        raise

    return transport, device
