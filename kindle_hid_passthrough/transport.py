#!/usr/bin/env python3
"""Bumble transport and device initialization."""

import asyncio
import os

from bumble.device import Device
from bumble.hci import HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND, LeFeatureMask
from bumble.transport import open_transport

from bt_setup import prepare_bt
from config import config
from logging_utils import log

__all__ = ['create_bumble_device']


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

    prepare_bt(
        transport_spec=spec,
        module_patterns=config.bt_module_patterns,
        settle_time=config.bt_settle_time,
    )

    log.info("Opening transport...")
    try:
        transport = await _open_transport_with_recovery(spec)
    except asyncio.TimeoutError:
        log.error(f"Transport open timed out after {config.transport_timeout}s")
        raise

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
            raise

        device.address_resolution_offload = (
            device.host.supports_le_features(LeFeatureMask.LL_PRIVACY)
            and device.host.supports_command(HCI_LE_ADD_DEVICE_TO_RESOLVING_LIST_COMMAND)
        )

        await device.power_on()
        log.success(f"Device powered on: {device.public_address}")
    except BaseException:
        try:
            await transport.close()
        except Exception:
            pass
        raise

    return transport, device
