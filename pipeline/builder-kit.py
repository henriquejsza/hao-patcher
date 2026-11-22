#!/usr/bin/env python3.14
"""Deterministic builder source snapshot, read exclusively from a Git commit."""
import gzip
import io
import json
from pathlib import Path
import subprocess
import tarfile

ROOTS = ('pipeline/', 'packs/', 'patches/', 'tools/hao/', 'tools/acquire/',
         'tools/hao-contract/', 'tools/edit-engine/', 'tools/kernel-foundation/',
         'tools/tahoe-donors/', 'tools/oclp-hardware/', 'tools/oclp-integration/',
         'tools/kc-binder/', 'tools/live-text/', 'tools/shared-cache/',
         'tools/first-boot-seeds/', 'tools/cache-dylib/', 'tools/gg-recovery/', 'cache/metallib/')
ROOTS += ('tools/audiomxd-fix/', 'tools/metal-fixes/')
FILES = ('LICENSE', 'NOTICE.md', 'tools/kernel-fixes/profiles/26B131/kc-recipe.json')


def selected(name):
    parts = Path(name).parts
    if not name.startswith(ROOTS) and name not in FILES:
        return False
    if any(p in ('tests', '__pycache__', '.DS_Store') for p in parts):
        return False
    if name == 'cache/metallib/shader-runtime-helpers/assemble.c':
        return True  # runtime-build records its prebuilt assembler's source hash
    if name.endswith(('.c', '.h', '.cpp', '.m', '.mm', '.swift', '.o', '.S')):
        return False
    return True


def build(top, commit, output, extras=None):
    """Write a normalized gzip/tar; neither ignored nor working-tree bytes enter it."""
    commit = subprocess.check_output(['git', '-C', str(top), 'rev-parse', commit + '^{commit}'], text=True).strip()
    raw = subprocess.check_output(['git', '-C', str(top), 'archive', '--format=tar', commit])
    entries = {}
    with tarfile.open(fileobj=io.BytesIO(raw)) as source:
        for member in source:
            if not selected(member.name) or member.isdir():
                continue
            if not member.isfile():
                raise ValueError('builder kit requires regular source files: ' + member.name)
            entries[member.name] = (source.extractfile(member).read(), 0o755 if member.mode & 0o111 else 0o644)
    for name, data in (extras or {}).items():
        entries[name] = (data, 0o644)
    entries['pipeline/SOURCE_COMMIT'] = ((commit + '\n').encode(), 0o644)
    entries['.hao-source'] = ((json.dumps({'commit': commit, 'dirty': False}, sort_keys=True) + '\n').encode(), 0o644)
    with Path(output).open('wb') as stream, gzip.GzipFile(filename='', fileobj=stream, mode='wb', mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode='w', format=tarfile.USTAR_FORMAT) as archive:
            for name, (data, mode) in sorted(entries.items()):
                info = tarfile.TarInfo(name)
                info.size, info.mode, info.mtime = len(data), mode, 0
                archive.addfile(info, io.BytesIO(data))
    return sorted(entries)


BUNDLE = 'hao-%s.tar'


def sha256_file(path):
    import hashlib
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def write_bundle(output, members):
    """A deterministic tar (POSIX pax, the given order, mtime 0, uid and gid 0, mode 0644, no compression) of
    MEMBERS, [(name, Path)]: plain file names only."""
    with tarfile.open(output, 'w', format=tarfile.PAX_FORMAT) as archive:
        for name, path in members:
            if Path(name).name != name or name.startswith(('.', '-')):
                raise ValueError('bundle member is not a plain file name: ' + name)
            info = tarfile.TarInfo(name)
            info.size, info.mode, info.mtime, info.uid, info.gid, info.uname, info.gname = (
                path.stat().st_size, 0o644, 0, 0, 0, '', '')
            with open(path, 'rb') as f:
                archive.addfile(info, f)


def release_assets(top, release, stage):
    """Add the builder infrastructure assets to an already classified release."""
    import hashlib
    import re
    import tempfile
    name = release['release']
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._-]*', name):
        raise ValueError('release name is not safe for a bootstrap')
    commit = release['hao_patcher']
    if subprocess.check_output(['git', '-C', str(top), 'status', '--porcelain', '--untracked-files=no']).strip():
        raise ValueError('builder kit requires a clean commit')
    if not release.get('candidate'):
        tags = subprocess.check_output(['git', '-C', str(top), 'tag', '--points-at', commit], text=True).splitlines()
        if release['version'] not in tags:
            raise ValueError('final builder cut requires the version tag at the producing commit')
    with tempfile.TemporaryDirectory(prefix='hao-kit-') as temporary:
        folder = Path(stage) if stage else Path(temporary)
        kit = folder / ('hao-kit-' + name + '.tar.gz')
        candidate_key = Path(top)/'tools/hao/data/candidate-keys.pub'
        extra = {}
        if release.get('candidate') and candidate_key.is_file():
            public = candidate_key.read_text().strip()
            if not re.fullmatch(r'ssh-ed25519 [A-Za-z0-9+/=]+(?: [^\n]*)?', public):
                raise ValueError('candidate key must be one Ed25519 public key')
            extra['tools/hao/data/candidate-keys.pub'] = (public+'\n').encode()
        build(top, commit, kit, extra)
        prefix = 'https://github.com/lythka/hao-assets/releases/download/' + name + '/'
        def entry(path, row, role):
            return dict(row=row, file=path.name, url=prefix + path.name,
                        size=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                        commit=commit, repo='hao-patcher', format='file', role=role,
                        reason='Frozen release builder infrastructure')
        kit_row = entry(kit, 'hao_builder_kit', 'builder-kit')
        pins = {}
        for arch in ('arm64', 'x86_64'):
            # Third-party: fetched from its publisher, pinned by size and sha256. A candidate's stage keeps a copy
            # in external/ (never uploaded) so its bootstrap runs without the network.
            row = next(x for x in release['downloads'] if x['row'] == 'python_' + arch)
            if stage and release.get('candidate'):
                import shutil
                folders = [Path(top)/'pipeline/inputs/golden'/release['golden_build'],
                           Path(top)/'pipeline/inputs'/release['donor_build'], Path(top)/'pipeline/inputs/common']
                lock = next(f/row['row'] for f in folders if (f/row['row']).is_file())
                line = next(l for l in lock.read_text().splitlines() if l.strip() and not l.startswith('#'))
                source = Path(top)/line.split(None, 1)[1]
                if hashlib.sha256(source.read_bytes()).hexdigest() != row['sha256']:
                    raise ValueError('Python source hash mismatch')
                (folder/'external').mkdir(exist_ok=True)
                shutil.copyfile(source, folder/'external'/row['name'])
            pins[row['row']] = dict({k: row[k] for k in ('url', 'sha256', 'size')}, file=row['name'])
        for row in release['assets']:
            if not row['url'].startswith(prefix):
                row['upstream_url'] = row['url']
                row['url'] = prefix + row['file']
                if stage:
                    (folder/'external'/row['file']).replace(folder/row['file'])
        if stage and (folder/'external').is_dir() and not any((folder/'external').iterdir()):
            (folder/'external').rmdir()
        metal = next((x for x in release['assets'] if x['row'] == 'metal_llvm'), None)
        release['assets'].append(kit_row)
        if stage:
            # One archive holds every file of ours; the release page lists it, the bootstrap, release.json and
            # SHA256SUMS. Each member keeps its own size and sha256 in release.json and is checked after unpacking.
            members = sorted((x for x in release['assets'] if x['url'].startswith(prefix)), key=lambda x: x['file'])
            bundle = folder / (BUNDLE % name)
            write_bundle(bundle, [(x['file'], folder/x['file']) for x in members])
            release['bundle'] = dict(file=bundle.name, url=prefix + bundle.name, size=bundle.stat().st_size,
                                     sha256=sha256_file(bundle), format='tar', members=[x['file'] for x in members])
            for x in members:
                x['url'], x['bundle'] = release['bundle']['url'], bundle.name
                (folder/x['file']).unlink()
        pins['kit'] = dict({k: kit_row[k] for k in ('url', 'sha256', 'size')}, file=kit_row['file'])
        if metal:
            pins['metal'] = dict({k: metal[k] for k in ('url', 'sha256', 'size')}, file=metal['file'])
        release['bootstrap'] = pins
        template = subprocess.check_output(['git', '-C', str(top), 'show', commit + ':pipeline/bootstrap.sh']).decode()
        key = subprocess.check_output(['git', '-C', str(top), 'show', commit + ':tools/hao/data/release-keys.pub']).decode().strip()
        if '\n' in key:
            raise ValueError('bootstrap expects one owner public key')
        if extra:
            key += '\nhao-release ' + public
        bootstrap = folder / 'hao'
        # an unsigned release: only a version the release commit's own waiver list names, never a candidate
        waivers = json.loads(subprocess.run(
            ['git', '-C', str(top), 'show', commit + ':tools/hao/data/unsigned-releases.json'],
            capture_output=True, text=True).stdout or '{}').get('releases', {})
        unsigned = not release.get('candidate') and isinstance(waivers.get(release['version']), str)
        if unsigned:
            release['unsigned'] = True
        bootstrap.write_text(template.replace('@RELEASE@', name).replace('@KEY@', key)
                             .replace('@CANDIDATE@', 'true' if release.get('candidate') else 'false')
                             .replace('@UNSIGNED@', 'true' if unsigned else 'false'))
        bootstrap.chmod(0o755)
        release['assets'].append(entry(bootstrap, 'hao_bootstrap', 'bootstrap'))
