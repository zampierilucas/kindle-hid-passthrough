#!/usr/bin/env python3
"""Stamp __version__ into kpm/repo.json and derive kpm/manifest.json from it.

    ./scripts/gen_kpm_manifests.py
"""
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPO = ROOT / 'kpm/repo.json'
MANIFEST = ROOT / 'kpm/manifest.json'
ARTIFACT_URL = ('https://github.com/zampierilucas/kindle-hid-passthrough'
                '/releases/download/v{version}/kindle-hid-passthrough.kpkg')


def version():
    src = (ROOT / 'kindle_hid_passthrough/config.py').read_text()
    return [int(n) for n in re.search(r'^__version__ = "(\d+)\.(\d+)\.(\d+)"$', src, re.M).groups()]


def manifests():
    repo = json.loads(REPO.read_text())
    pkg_id, pkg = next(iter(repo['packages'].items()))
    artifact = pkg['artifacts'][0]
    artifact['version'] = version()
    artifact['url'] = ARTIFACT_URL.format(version='.'.join(str(n) for n in artifact['version']))
    manifest = {'manifest_version': 2, 'id': pkg_id, 'name': pkg['name'], 'author': pkg['author'],
                'description': pkg['description'], 'version': artifact['version'],
                'dependencies': artifact['dependencies'],
                'supported_platforms': artifact['supported_platforms']}
    return manifest, repo


if __name__ == '__main__':
    manifest, repo = manifests()
    MANIFEST.write_text(json.dumps(manifest, indent=2) + '\n')
    REPO.write_text(json.dumps(repo, indent=2) + '\n')
