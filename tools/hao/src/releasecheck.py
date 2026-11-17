"""hao verify-release: a user checks a hao release themselves, with nothing but hao (no git, no ssh-keygen needed).

  hao verify-release              the release beside hao (tools/hao/release.json); on the USB installer, the drive
  hao verify-release PATH         a folder of release files (release.json, SHA256SUMS, their .sig, downloaded files),
                                  or a USB installer (a folder with manifest.json and stick.json, e.g. /Volumes/HAO)
  hao verify-release vX.Y.Z       that release's signed files, downloaded from GitHub into a private folder first

Checks, each PASS, FAIL or SKIP (not made, with the reason; SKIP never hides a FAIL):
  signature   SHA256SUMS.sig and release.json.sig against the release keys hao carries (src/signing.py)
  sums        release.json is the file SHA256SUMS lists (when both are there)
  files       every file here that SHA256SUMS or release.json pins has that sha256 (downloads also in hao's cache)
  tag         the public tag vX.Y.Z of hao-patcher is the commit release.json names ("hao_patcher"), and so is the
              checkout hao runs from (network for the tag; SKIP offline)
  drive       a USB installer: its release.json is signed, its manifest names that release.json, and every file on
              the drive matches the manifest (stick.check_manifest)

Only bytes whose signature held are used for the later checks. Exit 4 on any FAIL.
"""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import urllib.error
import urllib.request

import signing as SIGN

HERE = Path(__file__).resolve().parent
TOP = HERE.parents[2]
HOST = HERE.parent / 'data' / 'host.json'
SUMS_LIMIT = 1 << 20
SIGNED = ('SHA256SUMS', 'release.json')
TAG = re.compile(r'^v\d+\.\d+\.\d+(?:-[A-Za-z0-9.]+)?$')
SUM_LINE = re.compile(r'^([0-9a-f]{64}) [ *]([^/\\\x00-\x1f]+)$')


def layout():
    """Where releases are published (data/host.json "releases"): owner, the source and assets repositories."""
    try:
        r = json.loads(HOST.read_text()).get('releases') or {}
    except (OSError, ValueError):
        r = {}
    return {'owner': r.get('owner', 'lythka'), 'source': r.get('source', 'hao-patcher'),
            'assets': r.get('assets', 'hao-assets')}


def check(name, state, detail, **more):
    return dict(more, name=name, state=state, detail=detail)


def parse_sums(text):
    """{file name: sha256} from `shasum -a 256` lines; any other line makes the file unusable (ValueError)."""
    out = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        m = SUM_LINE.match(line)
        if not m or m.group(2) in out or m.group(2) in ('.', '..'):
            raise ValueError('not a SHA256SUMS line: %s' % _text(line)[:80])
        out[m.group(2)] = m.group(1)
    return out


def _text(s):
    import safety as SAFE
    return SAFE.text(s)


def signed(folder, name, keys):
    """(bytes or None, check or None): FOLDER/NAME verified against FOLDER/NAME.sig; (None, None) when NAME is not
    there at all."""
    path = Path(folder) / name
    if not os.path.lexists(path) and not os.path.lexists(SIGN.signature_of(path)):
        return None, None
    try:
        data = SIGN._read(path, SIGN.RELEASE_LIMIT, name)
        sig = SIGN._read(SIGN.signature_of(path), SIGN.SIG_LIMIT, name + '.sig')
        fp, hashed = SIGN.verify(data, sig.decode('utf-8', errors='replace'), keys)
    except SIGN.SignatureError as x:
        return None, check('signature', 'FAIL', '%s: %s' % (name, x), file=name)
    return data, check('signature', 'PASS', '%s signed by %s (%s)' % (name, fp, hashed), file=name, key=fp)


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(1 << 20), b''):
            h.update(block)
    return h.hexdigest()


def file_checks(folder, sums, release, cache):
    """FILES: each pinned file found here (or a download in CACHE/sha256/) against its sha256."""
    want = {}                                    # name -> (sha256, where it is pinned)
    for name, digest in (sums or {}).items():
        want[name] = (digest, 'SHA256SUMS')
    for row in (release or {}).get('assets') or []:
        if isinstance(row, dict) and isinstance(row.get('file'), str) and isinstance(row.get('sha256'), str):
            want.setdefault(row['file'], (row['sha256'], 'release.json'))
    for row in (release or {}).get('downloads') or []:
        if isinstance(row, dict) and isinstance(row.get('name'), str) and isinstance(row.get('sha256'), str):
            want.setdefault(row['name'], (row['sha256'], 'release.json'))
    out, absent = [], 0
    for name, (digest, source) in sorted(want.items()):
        if name in SIGNED:
            continue
        places = [Path(folder) / name]
        if cache and re.fullmatch('[0-9a-f]{64}', digest):
            places.append(Path(cache) / 'sha256' / digest)
        here = next((p for p in places if p.is_file() and not p.is_symlink()), None)
        if here is None:
            absent += 1
            continue
        have = sha256_file(here)
        out.append(check('files', 'PASS' if have == digest else 'FAIL',
                         '%s %s' % (name, 'matches %s' % source if have == digest else
                                    'differs from %s (sha256 %s, pinned %s)' % (source, have[:16], digest[:16])),
                         file=name))
    if absent:
        out.append(check('files', 'SKIP', '%d pinned files are not here (download them with hao fetch to check them)'
                         % absent, absent=absent))
    return out


def tag_commit(owner, repo, tag, opener):
    """The commit the public tag TAG of OWNER/REPO points to (GitHub's API; an annotated tag is followed)."""
    base = 'https://api.github.com/repos/%s/%s/git/' % (owner, repo)
    ref = json.loads(opener(base + 'ref/tags/' + tag))
    obj = ref.get('object') or {}
    for _ in range(3):
        if obj.get('type') == 'commit':
            return obj.get('sha')
        if obj.get('type') != 'tag':
            return None
        obj = json.loads(opener(base + 'tags/' + obj.get('sha', ''))).get('object') or {}
    return None


def opener_default(url, limit=SUMS_LIMIT, timeout=20):
    req = urllib.request.Request(url, headers={'User-Agent': 'hao-verify-release/1',
                                               'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise OSError('%s is larger than %d bytes' % (url, limit))
    return data


def checkout_commit(top=TOP, run=subprocess.run):
    """The commit of the hao-patcher checkout hao runs from, or None (not a checkout, or no git)."""
    if not (Path(top) / '.git').exists():
        return None
    try:
        r = run(['/usr/bin/git', '-C', str(top), 'rev-parse', 'HEAD'], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None
    return r.stdout.strip() if r.returncode == 0 and re.fullmatch('[0-9a-f]{40}', r.stdout.strip()) else None


def tag_checks(release, tag, opener, offline, here=None):
    version, commit = release.get('version'), release.get('hao_patcher')
    out = []
    if tag and version != tag:
        out.append(check('tag', 'FAIL', 'release.json is %s, not %s' % (version, tag)))
    if not isinstance(version, str) or not TAG.match(version) or not isinstance(commit, str):
        return out + [check('tag', 'FAIL', 'release.json names no version and hao-patcher commit')]
    lay = layout()
    if offline or opener is None:
        out.append(check('tag', 'SKIP', 'public tag %s not looked up (offline)' % version))
    else:
        try:
            public = tag_commit(lay['owner'], lay['source'], version, opener)
        except urllib.error.HTTPError as x:
            public = 'missing' if x.code == 404 else None
            why = 'HTTP %d' % x.code
        except (OSError, ValueError) as x:
            public, why = None, str(getattr(x, 'reason', x))
        if public == 'missing':
            out.append(check('tag', 'FAIL', '%s/%s has no public tag %s' % (lay['owner'], lay['source'], version)))
        elif public is None:
            out.append(check('tag', 'SKIP', 'public tag %s not reached (%s)' % (version, _text(why)[:80])))
        elif public == commit:
            out.append(check('tag', 'PASS', 'public tag %s is %s, the commit release.json names' % (version,
                                                                                                  commit[:12])))
        else:
            out.append(check('tag', 'FAIL', 'public tag %s is %s; release.json names %s' % (version, public[:12],
                                                                                         commit[:12])))
    if here:
        out.append(check('tag', 'PASS' if here == commit else 'FAIL',
                         'this hao is checkout %s%s' % (here[:12], ', as release.json names' if here == commit else
                                                        '; release.json names %s' % commit[:12])))
    return out


def check_folder(folder, keys, cache=None, tag=None, opener=None, offline=False, here=None):
    folder = Path(folder)
    out = []
    sums_bytes, c1 = signed(folder, 'SHA256SUMS', keys)
    rel_bytes, c2 = signed(folder, 'release.json', keys)
    out += [c for c in (c1, c2) if c]
    if c1 is None and c2 is None:
        return [check('signature', 'FAIL', 'no release.json or SHA256SUMS in %s' % folder)]
    sums = release = None
    if sums_bytes is not None:
        try:
            sums = parse_sums(sums_bytes.decode('utf-8', errors='replace'))
        except ValueError as x:
            out.append(check('sums', 'FAIL', 'SHA256SUMS: %s' % x))
    if rel_bytes is not None:
        try:
            release = json.loads(rel_bytes)
            if not isinstance(release, dict):
                raise ValueError('not an object')
        except ValueError as x:
            out.append(check('sums', 'FAIL', 'release.json: %s' % x))
            release = None
    if sums is not None and rel_bytes is not None:
        if 'release.json' in sums:
            same = hashlib.sha256(rel_bytes).hexdigest() == sums['release.json']
            out.append(check('sums', 'PASS' if same else 'FAIL', 'release.json %s SHA256SUMS' % (
                'is the file listed in' if same else 'differs from the one listed in')))
    out += file_checks(folder, sums, release, cache)
    if release is not None:
        out += tag_checks(release, tag, opener, offline, here)
    elif tag:
        out.append(check('tag', 'SKIP', 'no signed release.json here to compare with %s' % tag))
    return out


def check_drive(top, keys, stick=None):
    """A USB installer: release.json signed, the manifest names it, and the drive matches the manifest."""
    top = Path(top)
    out = []
    rel_bytes, c = signed(top, 'release.json', keys)
    if c is None:
        return [check('drive', 'FAIL', 'no release.json on %s: written from a checkout, not from a release' % top)]
    out.append(c)
    try:
        manifest = json.loads(SIGN._read(top / 'manifest.json', 64 << 20, 'manifest.json'))
    except (SIGN.SignatureError, ValueError) as x:
        return out + [check('drive', 'FAIL', 'manifest.json: %s' % x)]
    if rel_bytes is not None:
        same = isinstance(manifest, dict) and manifest.get('release_sha256') == hashlib.sha256(rel_bytes).hexdigest()
        out.append(check('drive', 'PASS' if same else 'FAIL', 'the manifest %s the signed release.json' % (
            'names' if same else 'does not name')))
    if stick is None or not hasattr(stick, 'check_manifest'):
        return out + [check('drive', 'FAIL', 'this hao cannot check a drive against its manifest')]
    problems = stick.check_manifest(top)
    if problems:
        out += [check('drive', 'FAIL', '%s: %s' % (_text(p), _text(why)), file=p) for p, why in problems[:20]]
        if len(problems) > 20:
            out.append(check('drive', 'FAIL', 'and %d more differences' % (len(problems) - 20)))
    else:
        n = len((manifest or {}).get('files') or {})
        out.append(check('drive', 'PASS', 'all %d files on the drive match its manifest' % n))
    return out


def download(tag, opener, beside=None, dest=None):
    """Release TAG's signed files from GitHub into a new private folder: SHA256SUMS(.sig) and release.json(.sig) from the
    source repository's release TAG (release.json(.sig) from BESIDE, the files next to hao, when that release has none);
    then the assets release that release.json names: its SHA256SUMS(.sig) into assets/. A file a release does not have
    is left out, and the checks say so. Nothing downloaded is trusted before its signature holds."""
    lay = layout()
    dest = Path(dest or tempfile.mkdtemp(prefix='hao-verify-'))

    def get(repo, rtag, name, into):
        url = 'https://github.com/%s/%s/releases/download/%s/%s' % (lay['owner'], repo, rtag, name)
        try:
            data = opener(url, SIGN.RELEASE_LIMIT)
        except urllib.error.HTTPError as x:
            if x.code == 404:
                return False
            raise
        into.mkdir(exist_ok=True)
        (into / name).write_bytes(data)
        return True
    for name in ('SHA256SUMS', 'SHA256SUMS.sig', 'release.json', 'release.json.sig'):
        get(lay['source'], tag, name, dest)
    if not (dest / 'release.json').exists() and beside is not None:
        for name in ('release.json', 'release.json.sig'):
            if (Path(beside) / name).is_file():
                (dest / name).write_bytes((Path(beside) / name).read_bytes())
    try:
        name = json.loads((dest / 'release.json').read_bytes()).get('release')
    except (OSError, ValueError, AttributeError):
        name = None
    if isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9._-]+', name):
        for f in ('SHA256SUMS', 'SHA256SUMS.sig'):
            get(lay['assets'], name, f, dest / 'assets')
    return dest


def assets_checks(folder, keys, release_bytes):
    """The assets release's SHA256SUMS: signed, and listing the release.json that was verified."""
    sums_bytes, c = signed(Path(folder), 'SHA256SUMS', keys)
    if c is None:
        return [check('sums', 'SKIP', 'the assets release has no SHA256SUMS')]
    out = [dict(c, detail='assets ' + c['detail'])]
    if sums_bytes is not None and release_bytes is not None:
        try:
            sums = parse_sums(sums_bytes.decode('utf-8', errors='replace'))
        except ValueError as x:
            return out + [check('sums', 'FAIL', 'assets SHA256SUMS: %s' % x)]
        if 'release.json' in sums:
            same = sums['release.json'] == hashlib.sha256(release_bytes).hexdigest()
            out.append(check('sums', 'PASS' if same else 'FAIL', 'release.json %s the assets release\'s SHA256SUMS' %
                             ('is the file listed in' if same else 'differs from the one listed in')))
    return out


def summary(checks):
    n = {s: sum(1 for c in checks if c['state'] == s) for s in ('PASS', 'FAIL', 'SKIP')}
    return n
