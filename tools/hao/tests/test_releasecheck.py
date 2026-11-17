"""hao verify-release (src/releasecheck.py): a good, a tampered and an unsigned release, as a folder, as vX.Y.Z (a fake
GitHub) and as a USB installer; PASS, FAIL and SKIP per check; exit 4 on a mismatch."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import sys
import tempfile
import unittest
import urllib.error

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL / 'src'))
sys.path.insert(0, str(HERE))
import releasecheck as RC  # noqa: E402
import signing as SIGN     # noqa: E402
from test_signing import sshsig_files  # noqa: E402

SECRET = b'\x21' * 32
COMMIT = 'a' * 40


def sign_into(folder, name):
    data = (Path(folder) / name).read_bytes()
    (Path(folder) / (name + '.sig')).write_text(sshsig_files(SECRET, data)[1])


KEYS = SIGN.parse_keys(sshsig_files(SECRET, b'')[0])


def release_folder(d, asset=b'asset bytes', sign=True):
    d = Path(d)
    (d / 'dss.dylib').write_bytes(asset)
    rel = {'release': '27.2.1-26B131.0', 'version': 'v0.0.1', 'hao_patcher': COMMIT,
           'assets': [{'file': 'dss.dylib', 'sha256': hashlib.sha256(b'asset bytes').hexdigest(), 'size': 11}],
           'downloads': [{'name': 'big.dmg', 'sha256': 'b' * 64, 'size': 1}]}
    (d / 'release.json').write_text(json.dumps(rel))
    sums = '%s  release.json\n%s  dss.dylib\n' % (hashlib.sha256((d / 'release.json').read_bytes()).hexdigest(),
                                                   hashlib.sha256(b'asset bytes').hexdigest())
    (d / 'SHA256SUMS').write_text(sums)
    if sign:
        sign_into(d, 'release.json')
        sign_into(d, 'SHA256SUMS')
    return d


def github(tag_commit=COMMIT, files=None):
    """An opener answering GitHub's tag API and release downloads from FILES {url suffix: bytes}."""
    def opener(url, limit=None):
        if '/git/ref/tags/' in url:
            if tag_commit is None:
                raise urllib.error.HTTPError(url, 404, 'Not Found', {}, io.BytesIO())
            return json.dumps({'object': {'type': 'tag', 'sha': 't' * 40}}).encode()
        if '/git/tags/' in url:
            return json.dumps({'object': {'type': 'commit', 'sha': tag_commit}}).encode()
        for suffix, data in (files or {}).items():
            if url.endswith(suffix):
                return data
        raise urllib.error.HTTPError(url, 404, 'Not Found', {}, io.BytesIO())
    return opener


def states(checks):
    return [(k['name'], k['state']) for k in checks]


class Folder(unittest.TestCase):
    def test_a_good_release_passes(self):
        with tempfile.TemporaryDirectory() as d:
            checks = RC.check_folder(release_folder(d), KEYS, opener=github())
            self.assertNotIn('FAIL', [s for _, s in states(checks)], checks)
            self.assertIn(('tag', 'PASS'), states(checks))
            self.assertIn(('sums', 'PASS'), states(checks))
            self.assertIn(('files', 'PASS'), states(checks))
            self.assertIn(('files', 'SKIP'), states(checks))      # big.dmg is not here

    def test_a_tampered_file_fails(self):
        with tempfile.TemporaryDirectory() as d:
            checks = RC.check_folder(release_folder(d, asset=b'asset bytez'), KEYS, opener=github())
            self.assertIn(('files', 'FAIL'), states(checks))

    def test_a_changed_release_json_fails_its_signature(self):
        with tempfile.TemporaryDirectory() as d:
            f = release_folder(d)
            (f / 'release.json').write_text((f / 'release.json').read_text().replace('v0.0.1', 'v0.0.2'))
            checks = RC.check_folder(f, KEYS, opener=github())
            self.assertIn(('signature', 'FAIL'), states(checks))
            self.assertNotIn(('sums', 'PASS'), states(checks))      # an unverified release.json is never compared
            self.assertNotIn(('tag', 'PASS'), states(checks))

    def test_an_unsigned_release_fails(self):
        with tempfile.TemporaryDirectory() as d:
            checks = RC.check_folder(release_folder(d, sign=False), KEYS, opener=github())
            self.assertEqual([s for n, s in states(checks) if n == 'signature'], ['FAIL', 'FAIL'])
            self.assertNotIn(('files', 'PASS'), states(checks))      # unsigned pins are never used

    def test_the_tag(self):
        with tempfile.TemporaryDirectory() as d:
            f = release_folder(d)
            self.assertIn(('tag', 'FAIL'), states(RC.check_folder(f, KEYS, opener=github(tag_commit='c' * 40))))
            self.assertIn(('tag', 'FAIL'), states(RC.check_folder(f, KEYS, opener=github(tag_commit=None))))
            self.assertIn(('tag', 'SKIP'), states(RC.check_folder(f, KEYS, offline=True)))
            self.assertIn(('tag', 'FAIL'), states(RC.check_folder(f, KEYS, offline=True, here='d' * 40)))
            self.assertIn(('tag', 'PASS'), states(RC.check_folder(f, KEYS, offline=True, here=COMMIT)))
            self.assertIn(('tag', 'FAIL'), states(RC.check_folder(f, KEYS, offline=True, tag='v0.0.2')))

    def test_a_signed_sums_file_with_a_bad_line_fails(self):
        with tempfile.TemporaryDirectory() as d:
            f = release_folder(d)
            (f / 'SHA256SUMS').write_text('nonsense\n')
            sign_into(f, 'SHA256SUMS')
            self.assertIn(('sums', 'FAIL'), states(RC.check_folder(f, KEYS, offline=True)))

    def test_downloads_in_the_cache_are_checked(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'rel').mkdir()
            f = release_folder(Path(d) / 'rel')
            (Path(d) / 'cache' / 'sha256').mkdir(parents=True)
            (Path(d) / 'cache' / 'sha256' / ('b' * 64)).write_bytes(b'not it')
            checks = RC.check_folder(f, KEYS, cache=Path(d) / 'cache', offline=True)
            self.assertTrue(any(k['state'] == 'FAIL' and k.get('file') == 'big.dmg' for k in checks))


class Tag(unittest.TestCase):
    def test_download_gets_the_signed_files_and_the_assets_sums(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dest:
            f = release_folder(src)
            files = {'/hao-patcher/releases/download/v0.0.1/' + n: (f / n).read_bytes()
                     for n in ('SHA256SUMS', 'SHA256SUMS.sig', 'release.json', 'release.json.sig')}
            files.update({'/hao-assets/releases/download/27.2.1-26B131.0/' + n: (f / n).read_bytes()
                          for n in ('SHA256SUMS', 'SHA256SUMS.sig')})
            got = RC.download('v0.0.1', github(files=files), dest=dest)
            self.assertTrue((got / 'release.json.sig').is_file())
            self.assertTrue((got / 'assets' / 'SHA256SUMS.sig').is_file())
            checks = RC.check_folder(got, KEYS, tag='v0.0.1', opener=github())
            checks += RC.assets_checks(got / 'assets', KEYS, (got / 'release.json').read_bytes())
            self.assertNotIn('FAIL', [s for _, s in states(checks)], checks)

    def test_release_json_from_beside_hao_when_the_release_has_none(self):
        with tempfile.TemporaryDirectory() as src, tempfile.TemporaryDirectory() as dest:
            f = release_folder(src)
            files = {'/hao-patcher/releases/download/v0.0.1/' + n: (f / n).read_bytes()
                     for n in ('SHA256SUMS', 'SHA256SUMS.sig')}
            got = RC.download('v0.0.1', github(files=files), beside=f, dest=dest)
            self.assertTrue((got / 'release.json').is_file())


class Drive(unittest.TestCase):
    class Stick:
        def __init__(self, problems):
            self.problems = problems

        def check_manifest(self, top):
            return self.problems

    def drive(self, d, sign=True):
        f = release_folder(d, sign=sign)
        (f / 'stick.json').write_text('{}')
        (f / 'manifest.json').write_text(json.dumps({'format': 1, 'files': {}, 'links': {}, 'release_sha256':
                                                    hashlib.sha256((f / 'release.json').read_bytes()).hexdigest()}))
        return f

    def test_a_good_drive_passes(self):
        with tempfile.TemporaryDirectory() as d:
            checks = RC.check_drive(self.drive(d), KEYS, self.Stick([]))
            self.assertEqual([s for _, s in states(checks)], ['PASS', 'PASS', 'PASS'])

    def test_a_changed_drive_fails(self):
        with tempfile.TemporaryDirectory() as d:
            checks = RC.check_drive(self.drive(d), KEYS, self.Stick([('kit/x', 'a different size')]))
            self.assertIn(('drive', 'FAIL'), states(checks))

    def test_a_drive_whose_manifest_names_another_release_fails(self):
        with tempfile.TemporaryDirectory() as d:
            f = self.drive(d)
            (f / 'manifest.json').write_text(json.dumps({'release_sha256': '0' * 64}))
            self.assertIn(('drive', 'FAIL'), states(RC.check_drive(f, KEYS, self.Stick([]))))

    def test_an_unsigned_drive_and_one_without_a_release_fail(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertIn(('signature', 'FAIL'), states(RC.check_drive(self.drive(d, sign=False), KEYS,
                                                                        self.Stick([]))))
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(states(RC.check_drive(Path(d), KEYS, self.Stick([]))), [('drive', 'FAIL')])


class Command(unittest.TestCase):
    def run_cmd(self, target, opener=None, offline=True):
        hao = runpy.run_path(str(TOOL / 'hao'), run_name='hao_module')
        import console as CON
        with tempfile.TemporaryDirectory() as k:
            (Path(k) / 'keys.pub').write_text(sshsig_files(SECRET, b'')[0])
            keys, SIGN.KEYS = SIGN.KEYS, Path(k) / 'keys.pub'
            try:
                c = CON.Console('quiet', out=io.StringIO(), err=io.StringIO(), env={})
                a = argparse.Namespace(target=str(target), cache=None, offline=offline)
                return hao['cmd_verify_release'](a, c, opener=opener)
            except CON.Stopped as x:
                return x.code
            finally:
                SIGN.KEYS = keys

    def test_exit_codes(self):
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_cmd(release_folder(d)), 0)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_cmd(release_folder(d, asset=b'tampered!!!')), 4)
        with tempfile.TemporaryDirectory() as d:
            self.assertEqual(self.run_cmd(release_folder(d, sign=False)), 4)

    def test_keys_from_a_file_in_a_checkout(self):
        with tempfile.TemporaryDirectory() as d, tempfile.TemporaryDirectory() as k:
            (Path(k) / 'test.pub').write_text(sshsig_files(SECRET, b'')[0])
            r = __import__('subprocess').run([sys.executable, '-I', '-B', str(TOOL / 'hao'), 'verify-release',
                                              str(release_folder(d)), '--offline', '--keys', str(Path(k) / 'test.pub')],
                                             capture_output=True, text=True, env=dict(os.environ, HAO_LOGS=k))
            self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
            self.assertIn('PASS', r.stdout + r.stderr)

    def test_without_keys_it_refuses(self):
        with tempfile.TemporaryDirectory() as d:
            r = __import__('subprocess').run([sys.executable, '-I', '-B', str(TOOL / 'hao'), 'verify-release',
                                              str(release_folder(d)), '--offline'], capture_output=True, text=True,
                                             env=dict(os.environ, HAO_LOGS=d))
            self.assertEqual(r.returncode, 4, r.stdout + r.stderr)


if __name__ == '__main__':
    unittest.main()
