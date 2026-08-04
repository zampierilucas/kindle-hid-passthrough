import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / 'kindle_hid_passthrough'))

import button_mapper


def use_config(monkeypatch, tmp_path, text=None):
    cfg = tmp_path / 'config.ini'
    if text is not None:
        cfg.write_text(text)
    monkeypatch.setattr(button_mapper, 'MAPPER_CONFIG', str(cfg))
    monkeypatch.setattr(button_mapper, '_restart_mapper', lambda: None)
    return cfg


def test_no_mapper_installed(monkeypatch, tmp_path):
    use_config(monkeypatch, tmp_path)
    assert button_mapper.register_device('AA:BB:CC:DD:EE:FF', 'Pad') is False


def test_registers_a_new_device(monkeypatch, tmp_path):
    cfg = use_config(monkeypatch, tmp_path, '[settings]\nkeep_awake = true\n')
    assert button_mapper.register_device('AA:BB:CC:DD:EE:FF', 'My Pad 2') is True
    text = cfg.read_text()
    assert '[device.my_pad_2]' in text
    assert 'uniq = AA:BB:CC:DD:EE:FF' in text
    assert 'name = My Pad 2' in text


def test_existing_uniq_is_not_duplicated(monkeypatch, tmp_path):
    cfg = use_config(
        monkeypatch, tmp_path,
        '[device.pad]\nuniq = aa:bb:cc:dd:ee:ff/P\n',
    )
    assert button_mapper.register_device('AA:BB:CC:DD:EE:FF', 'Pad') is False
    assert cfg.read_text().count('uniq') == 1


def test_slug_collision_gets_a_suffix(monkeypatch, tmp_path):
    cfg = use_config(
        monkeypatch, tmp_path,
        '[device.pad]\nuniq = 11:22:33:44:55:66\n',
    )
    assert button_mapper.register_device('AA:BB:CC:DD:EE:FF', 'Pad') is True
    assert '[device.pad_2]' in cfg.read_text()


def test_nameless_device_uses_mac_tail(monkeypatch, tmp_path):
    cfg = use_config(monkeypatch, tmp_path, '')
    assert button_mapper.register_device('AA:BB:CC:DD:EE:FF') is True
    assert '[device.dev_eeff]' in cfg.read_text()


def test_register_all_skips_wildcard_and_restarts_once(monkeypatch, tmp_path):
    use_config(monkeypatch, tmp_path, '')
    calls = []
    monkeypatch.setattr(button_mapper, '_restart_mapper', lambda: calls.append(1))
    button_mapper.register_all([
        ('*', None, None),
        ('AA:BB:CC:DD:EE:FF', None, 'Pad'),
        ('11:22:33:44:55:66', None, None),
    ])
    assert len(calls) == 1
