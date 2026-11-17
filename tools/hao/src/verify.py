"""hao verify: every installed file of the packs against its manifest, read-only.

A manifest is a pack overlay's manifest.json (pipeline/materialize.py's format, the one hao patch applies); only its
"files" (sha256, mode, owner, flags) and "dirs" are read, so a manifest without its files/ folder will do. They come
from overlay folders, manifest files, or ROOT/private/var/db/hao/manifests (where hao install and build-disk keep the
manifests of what they installed). For each file: missing, different content, or different mode/owner/flags.
"""
import json
import os
from pathlib import Path

import livepatch as LP

INSTALLED = 'private/var/db/hao/manifests'


def data_root(root):
    """The Data volume of an unbooted install whose System volume is mounted at ROOT ("macOS" -> "macOS - Data", as
    the Recovery mounts them), or None. Firmlinked paths (Library, private/var, Users ...) live there; on a booted
    system "/" reaches them through the firmlinks."""
    root = Path(root)
    if str(root) == '/':
        return None
    data = root.parent / (root.name + ' - Data')
    return data if data.is_dir() else None


def manifests(sources, root):
    """[(where, manifest)] from overlay folders or manifest files; ROOT's installed manifests when none are given."""
    paths = []
    if not sources:
        data = data_root(root)
        sources = [d for d in ([Path(root) / INSTALLED] + ([data / INSTALLED] if data else [])) if d.is_dir()] or \
            [Path(root) / INSTALLED]
    for s in sources:
        s = Path(s)
        if s.is_file():
            paths.append(s)
        elif (s / 'manifest.json').is_file():
            paths.append(s / 'manifest.json')
        elif s.is_dir():
            paths += sorted(s.glob('*/manifest.json')) + sorted(s.glob('*.json'))
        else:
            raise LP.PatchError('%s: no manifest there' % s)
    out = []
    for p in paths:
        m = json.loads(p.read_text())
        if m.get('format') != 1 or not isinstance(m.get('files'), dict):
            continue
        out.append((str(p), m))
    if not out:
        raise LP.PatchError('no pack manifests found (give overlay folders, or install with hao first)')
    return out


def inside(root, data, path):
    """The file a manifest PATH names under ROOT (or, for a firmlinked path of an unbooted install, under its Data
    volume DATA), or None when PATH is absolute, has empty, . or .. parts, or resolves outside that root."""
    parts = str(path).split('/')
    if not path or str(path).startswith('/') or any(x in ('', '.', '..') for x in parts):
        return None
    target = root / path
    base = root
    if data is not None and not os.path.lexists(target) and os.path.lexists(data / path):
        target, base = data / path, data
    real_base = os.path.realpath(str(base))
    real_parent = os.path.realpath(str(target.parent))
    if real_parent != real_base and not real_parent.startswith(real_base.rstrip('/') + '/'):
        return None
    return target


def verify(root, found, attributes=None, on_file=None):
    """{'ok': n, 'problems': [{path, pack, problem, ...}], 'packs': {pack: files}}; ON_FILE(row) per file."""
    root = Path(root)
    data = data_root(root)
    attributes = attributes or LP.Attributes(root, privileged=True)
    out = {'ok': 0, 'problems': [], 'packs': {}}
    for where, m in found:
        pack = m.get('pack', Path(where).parent.name)
        out['packs'][pack] = len(m['files'])
        for path, meta in sorted(m['files'].items()):
            row = {'path': path, 'pack': pack}
            target = inside(root, data, path)
            if target is None:
                # a manifest path that is absolute, has . or .. parts, or leads out of the root through a symlinked
                # folder: refused, never read or hashed (a manifest must not point hao at other files)
                row['problem'] = 'outside'
                out['problems'].append(row)
                if on_file:
                    on_file(row)
                continue
            if target.is_symlink() or not target.is_file():
                row['problem'] = 'missing'
            else:
                have = LP.sha256_file(target)
                if have != meta['sha256']:
                    row.update(problem='content', want=meta['sha256'], have=have)
                else:
                    try:
                        keys = sum(attributes.differs(target, attributes.wanted(meta)), [])
                    except LP.PatchError as x:
                        keys = ['owner (%s)' % x]
                    if keys:
                        row.update(problem='attributes', keys=keys)
            if 'problem' in row:
                out['problems'].append(row)
            else:
                out['ok'] += 1
            if on_file:
                on_file(row)
    return out
