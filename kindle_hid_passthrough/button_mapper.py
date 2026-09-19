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
import signal

logger = logging.getLogger(__name__)

MAPPER_CONFIG = "/mnt/us/kindle-button-mapper/config.ini"


def _is_audio(protocol) -> bool:
    return str(getattr(protocol, 'value', protocol)) == 'classic_audio'


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


def register_device(address: str, name: str = None, reload: bool = True,
                    audio: bool = False) -> bool:
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
    if audio:
        # An audio device reaches us through the injected Consumer Control
        # descriptor, so its node carries media keys and nothing else --
        # keys KOReader has no binding for. Leaving the node to KOReader by
        # default meant the mapper never saw a press and the button did
        # nothing until the user found the mode setting by hand. Passthrough
        # keeps whatever is unmapped flowing on.
        block += 'grab = true\npassthrough = true\n'

    try:
        with open(MAPPER_CONFIG, 'a') as f:
            if not text.endswith('\n'):
                f.write('\n')
            f.write(block)
    except OSError as e:
        logger.warning(f"Could not register {address} with button-mapper: {e}")
        return False

    logger.info(f"Registered {address} as [device.{slug}] with button-mapper")
    if reload:
        _reload_mapper()
    return True


def unregister_device(address: str) -> bool:
    """Drop the [device.X] blocks whose uniq matches. True if any went."""
    try:
        with open(MAPPER_CONFIG) as f:
            lines = f.readlines()
    except OSError:
        return False

    address = _bare_addr(address)
    kept, dropped = [], False
    # Blocks run to the next [section] at the same level, and a device's
    # [device.X.buttons] children have to go with it.
    drop_prefix = None
    for block_id, block in _blocks(lines):
        if drop_prefix and block_id and (
                block_id == drop_prefix or block_id.startswith(drop_prefix + '.')):
            dropped = True
            continue
        drop_prefix = None
        if block_id and '.' not in block_id and _block_uniq(block) == address:
            drop_prefix = block_id
            dropped = True
            continue
        kept.extend(block)

    if not dropped:
        return False

    try:
        with open(MAPPER_CONFIG, 'w') as f:
            f.writelines(kept)
    except OSError as e:
        logger.warning(f"Could not unregister {address} from button-mapper: {e}")
        return False

    logger.info(f"Unregistered {address} from button-mapper")
    _reload_mapper()
    return True


def _blocks(lines):
    """Yield (device_id_or_None, lines) per [section], preamble first."""
    current_id, buf = None, []
    for line in lines:
        header = re.match(r'\s*\[(.+?)\]\s*$', line)
        if header:
            yield current_id, buf
            section = header.group(1).strip()
            current_id = section[len('device.'):] if section.startswith('device.') else ''
            buf = [line]
        else:
            buf.append(line)
    yield current_id, buf


def _block_uniq(block) -> str:
    for line in block:
        key, sep, value = line.partition('=')
        if sep and key.strip() == 'uniq':
            return _bare_addr(value)
    return ''


def register_all(devices) -> None:
    """Register every (address, protocol, name) tuple, skipping wildcards."""
    added = False
    for address, proto, name in devices:
        if address == '*':
            continue
        added |= register_device(address, name, reload=False,
                                 audio=_is_audio(proto))
    if added:
        _reload_mapper()


def _reload_mapper() -> None:
    """SIGHUP the running daemon so it re-reads the file where it stands.

    Restarting it would tear down the mapper's uinput keyboard, and KOReader
    stops delivering keys from a node that vanishes under it until KOReader is
    itself restarted. Pairing must never be the thing that causes that. If the
    daemon isn't running there is nothing to reload, and starting the job
    behind the user's back would be rude, so that case does nothing.
    """
    pid = _daemon_pid()
    if not pid:
        logger.debug("button-mapper is not running, nothing to reload")
        return
    try:
        os.kill(pid, signal.SIGHUP)
        logger.info(f"Asked button-mapper ({pid}) to re-read its config")
    except OSError as e:
        logger.warning(f"Could not signal button-mapper ({pid}): {e}")


def _daemon_pid(proc: str = '/proc') -> int:
    """The mapper daemon's pid, 0 if it isn't up. Its WAF helper doesn't count."""
    try:
        entries = os.listdir(proc)
    except OSError:
        return 0
    for entry in entries:
        if not entry.isdigit():
            continue
        try:
            with open(os.path.join(proc, entry, 'cmdline'), 'rb') as f:
                argv = f.read().split(b'\0')
        except OSError:
            continue
        if not argv or not argv[0].endswith(b'kindle-button-mapper'):
            continue
        if b'--waf-helper' in argv:
            continue
        return int(entry)
    return 0
