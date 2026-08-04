"""Register paired devices with kindle-button-mapper.

Appends a [device.X] block with the device's MAC to the mapper's config, so
its daemon picks the uhid node up by uniq the moment it connects. The mapper
decides from the node's capabilities whether a default layout applies, so
registering a keyboard is harmless.

Append-only on purpose: the config is hand-edited and edited by the mapper's
own app, a parser round-trip would eat comments and formatting.
"""

import logging
import os
import re
import subprocess

logger = logging.getLogger(__name__)

MAPPER_CONFIG = "/mnt/us/kindle-button-mapper/config.ini"


def _bare_addr(value: str) -> str:
    return value.split('/')[0].strip().upper()


def _known_uniqs(text: str) -> set:
    uniqs = set()
    for line in text.splitlines():
        key, sep, value = line.partition('=')
        if sep and key.strip() == 'uniq':
            uniqs.add(_bare_addr(value))
    return uniqs


def _slug(name: str, address: str, text: str) -> str:
    base = re.sub(r'[^a-z0-9]+', '_', (name or '').lower()).strip('_')
    if not base:
        base = 'dev_' + address.replace(':', '')[-4:].lower()
    slug, n = base, 1
    while f'[device.{slug}]' in text:
        n += 1
        slug = f'{base}_{n}'
    return slug


def register_device(address: str, name: str = None, restart: bool = True) -> bool:
    """Add a device block to the mapper config. True if one was added."""
    try:
        with open(MAPPER_CONFIG) as f:
            text = f.read()
    except OSError:
        return False  # mapper not installed

    address = _bare_addr(address)
    if address in _known_uniqs(text):
        return False

    slug = _slug(name, address, text)
    block = f'\n[device.{slug}]\n'
    if name:
        block += f'name = {name}\n'
    block += f'uniq = {address}\n'

    try:
        with open(MAPPER_CONFIG, 'a') as f:
            if not text.endswith('\n'):
                f.write('\n')
            f.write(block)
    except OSError as e:
        logger.warning(f"Could not register {address} with button-mapper: {e}")
        return False

    logger.info(f"Registered {address} as [device.{slug}] with button-mapper")
    if restart:
        _restart_mapper()
    return True


def register_all(devices) -> None:
    """Register every (address, protocol, name) tuple, skipping wildcards."""
    added = False
    for address, _proto, name in devices:
        if address == '*':
            continue
        added |= register_device(address, name, restart=False)
    if added:
        _restart_mapper()


def _restart_mapper() -> None:
    # Restart only: if the user stopped the job, starting it behind their
    # back would be rude, and the next start reads the new block anyway.
    if not os.path.exists('/sbin/initctl'):
        return
    try:
        subprocess.run(['/sbin/initctl', 'restart', 'kindle-button-mapper'],
                       capture_output=True, timeout=15)
    except Exception as e:
        logger.debug(f"button-mapper restart skipped: {e}")
