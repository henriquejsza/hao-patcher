"""Bootstrap refusals with real SSH signatures and an offline transport fixture."""
import hashlib
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tarfile
import tempfile
import unittest
from unittest import mock

TOP = Path(__file__).resolve().parents[2]


@unittest.skipUnless(shutil.which('ssh-keygen') and shutil.which('plutil'), 'macOS signature tools')
class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.mirror = self.root / 'mirror'
        self.mirror.mkdir()
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        self.key = self.root / 'test-key'
        subprocess.run(['ssh-keygen', '-q', '-t', 'ed25519', '-N', '', '-f', str(self.key)], check=True)
        template = (TOP / 'pipeline/bootstrap.sh').read_text()
        self.script = self.root / 'hao'
        # Only the test copy uses a shim PATH; published bootstraps use system tools.
        template = template.replace('PATH=/usr/bin:/bin:/usr/sbin:/sbin',
                                    'PATH=' + shlex.quote(str(self.bin)) + ':/usr/bin:/bin:/usr/sbin:/sbin')
        self.script.write_text(template.replace('@RELEASE@', 'fixture').replace('@KEY@', self.key.with_suffix('.pub').read_text().strip()).replace('@CANDIDATE@', 'false').replace('@UNSIGNED@', 'false'))
        self.shim('curl', '#!/bin/sh\nfor arg do case "$arg" in https://*) url=$arg;; esac; done\n'
                  + 'for last do :; done\ncp ' + shlex.quote(str(self.mirror)) + '/"${url##*/}" "$last"\n')
        self.shim('uname', '#!/bin/sh\necho arm64\n')
        self.kit = self.archive('kit.tar.gz', {'tools/hao/hao': b'fixture', 'pipeline/SOURCE_COMMIT': b'fixture'})
        self.python = self.archive('python.tar.gz', {'python/bin/python3.12': b'#!/bin/sh\nexit 0\n'})
        self.manifest = {'release': 'fixture', 'bootstrap': {'kit': self.kit, 'python_arm64': self.python}}
        self.sign()

    def shim(self, name, text):
        path = self.bin / name
        path.write_text(text)
        path.chmod(0o755)

    def archive(self, name, files):
        path = self.mirror / name
        with tarfile.open(path, 'w:gz') as archive:
            for name_, data in files.items():
                info = tarfile.TarInfo(name_)
                info.size, info.mode = len(data), 0o755
                archive.addfile(info, io.BytesIO(data))
        return dict(url='https://fixture.invalid/' + name, size=path.stat().st_size,
                    sha256=hashlib.sha256(path.read_bytes()).hexdigest())

    def sign(self):
        release = self.mirror / 'release.json'
        release.write_text(json.dumps(self.manifest))
        (self.mirror / 'SHA256SUMS').write_text(hashlib.sha256(release.read_bytes()).hexdigest() + '  release.json\n')
        for name in ('release.json', 'SHA256SUMS'):
            path = self.mirror / name
            Path(str(path) + '.sig').unlink(missing_ok=True)
            subprocess.run(['ssh-keygen', '-Y', 'sign', '-f', str(self.key), '-n', 'hao-release', str(path)],
                           check=True, capture_output=True)

    def run_bootstrap(self):
        return subprocess.run(['/bin/sh', str(self.script), 'doctor'], cwd=self.root, capture_output=True, text=True)

    def test_success_and_verified_download_resume(self):
        first = self.run_bootstrap()
        self.assertEqual(first.returncode, 0, first.stderr)
        (self.mirror / 'kit.tar.gz').unlink()
        (self.mirror / 'python.tar.gz').unlink()
        second = self.run_bootstrap()
        self.assertEqual(second.returncode, 0, second.stderr)

    def test_bad_signature(self):
        (self.mirror / 'release.json').write_text('{}')
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('bad signature', result.stderr)

    def test_replacement_failure_preserves_store(self):
        self.assertEqual(self.run_bootstrap().returncode, 0)
        sentinel = self.root/'hao-fixture/store/verified-sentinel'
        sentinel.write_text('keep')
        self.shim('mv', '#!/bin/sh\nfor last do :; done\n[ "$last" != runtime ] || exit 1\nexec /bin/mv "$@"\n')
        self.assertNotEqual(self.run_bootstrap().returncode, 0)
        self.assertEqual(sentinel.read_text(), 'keep')

    def test_symlinked_kit_refused(self):
        work = self.root/'hao-fixture'
        work.mkdir()
        outside = self.root/'outside'
        (outside/'store').mkdir(parents=True)
        sentinel = outside/'store/keep'
        sentinel.write_text('keep')
        (work/'kit').symlink_to(outside, target_is_directory=True)
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertEqual(sentinel.read_text(), 'keep')

    def test_bad_hash(self):
        (self.mirror / 'kit.tar.gz').write_bytes(b'damaged')
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('SHA256 mismatch', result.stderr)

    def test_interrupted_download(self):
        self.shim('curl', '#!/bin/sh\nexit 18\n')
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('interrupted', result.stderr)

    def test_wrong_architecture(self):
        self.shim('uname', '#!/bin/sh\necho ppc\n')
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('architecture', result.stderr)

    def test_concurrent_run_refused(self):
        (self.root / 'hao-fixture/.lock').mkdir(parents=True)
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('another hao run', result.stderr)

    def test_checksum_signature_refused(self):
        (self.mirror/'SHA256SUMS.sig').write_text('damaged signature')
        result = self.run_bootstrap()
        self.assertEqual(result.returncode,4,result.stderr)
        self.assertIn('bad signature: SHA256SUMS',result.stderr)

    def test_wrong_python_architecture_refused(self):
        self.manifest['bootstrap']['python_arm64'] = self.archive(
            'python.tar.gz', {'python/bin/python3.12': b'#!/bin/sh\nexit 1\n'})
        self.sign()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode,4,result.stderr)
        self.assertIn('wrong Python architecture',result.stderr)

    def test_candidate_local_mirror_keeps_signature_checks(self):
        self.script.write_text(self.script.read_text().replace("candidate='false'", "candidate='true'"))
        self.shim('curl', '#!/bin/sh\nexit 99\n')
        result = subprocess.run(['/bin/sh',str(self.script),'doctor'],cwd=self.root,capture_output=True,text=True,
                                env=dict(os.environ,HAO_BOOTSTRAP_FILES=str(self.mirror)))
        self.assertEqual(result.returncode,0,result.stderr)
        (self.mirror/'release.json').write_text('{}')
        result = subprocess.run(['/bin/sh',str(self.script),'doctor'],cwd=self.root,capture_output=True,text=True,
                                env=dict(os.environ,HAO_BOOTSTRAP_FILES=str(self.mirror)))
        self.assertEqual(result.returncode,4,result.stderr)
        self.assertIn('bad signature',result.stderr)

    def bundled(self, members=None, listed=None):
        """Sign a release whose kit is a member of one archive, as release-cut makes it."""
        kit = (self.mirror / 'kit.tar.gz').read_bytes()
        members = members if members is not None else {'kit.tar.gz': kit}
        path = self.mirror / 'hao-fixture.tar'
        with tarfile.open(path, 'w') as archive:
            for name, data in members.items():
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        (self.mirror / 'kit.tar.gz').unlink()
        url = 'https://fixture.invalid/hao-fixture.tar'
        self.manifest['bundle'] = dict(file='hao-fixture.tar', url=url, size=path.stat().st_size,
                                       sha256=hashlib.sha256(path.read_bytes()).hexdigest(),
                                       members=list(members))
        self.manifest['bootstrap']['kit'] = dict(url=url, file=listed or 'kit.tar.gz', size=len(kit),
                                                 sha256=hashlib.sha256(kit).hexdigest())
        self.sign()

    def test_kit_from_the_release_archive(self):
        self.bundled()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        work = self.root / 'hao-fixture'
        self.assertEqual((work / 'kit/tools/hao/hao').read_bytes(), b'fixture')
        # the checked archive stays, named by its sha256, and a second run needs no download of it
        self.assertTrue((work / 'downloads' / self.manifest['bundle']['sha256']).is_file())
        (self.mirror / 'hao-fixture.tar').unlink()
        (self.mirror / 'python.tar.gz').unlink()
        self.assertEqual(self.run_bootstrap().returncode, 0)

    def test_hao_is_told_where_the_checked_archive_is(self):
        self.python = self.archive('python.tar.gz', {
            'python/bin/python3.12': b'#!/bin/sh\n[ "$1" = -I ] && [ "$2" = -S ] && exit 0\n'
                                     b'printf %s "$HAO_BUNDLE" > "$PWD/seen"\n'})
        self.manifest['bootstrap']['python_arm64'] = self.python
        self.bundled()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        work = self.root / 'hao-fixture'
        self.assertEqual((work / 'seen').read_text(),
                         str((work / 'downloads' / self.manifest['bundle']['sha256']).resolve()))

    def test_damaged_release_archive_refused(self):
        self.bundled()
        (self.mirror / 'hao-fixture.tar').write_bytes(b'damaged')
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('SHA256 mismatch: bundle', result.stderr)

    def test_changed_member_refused(self):
        # the archive is the pinned one, but the kit in it is not the kit release.json pins
        self.bundled(members={'kit.tar.gz': b'another kit'})
        self.manifest['bootstrap']['kit']['sha256'] = 'a' * 64
        self.sign()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('SHA256 mismatch: kit', result.stderr)

    def test_member_missing_from_the_archive_refused(self):
        self.bundled(members={'other': b'x'})
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('the release archive lacks kit.tar.gz', result.stderr)

    def test_member_name_with_a_path_refused(self):
        self.bundled(listed='../kit.tar.gz')
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('invalid file name', result.stderr)

    def test_candidate_takes_a_download_by_its_file_name_from_external(self):
        # a publisher's URL may spell the name another way (%2B); a candidate's copy is staged in external/
        self.script.write_text(self.script.read_text().replace("candidate='false'", "candidate='true'"))
        self.shim('curl', '#!/bin/sh\nexit 99\n')
        (self.mirror / 'external').mkdir()
        (self.mirror / 'python.tar.gz').rename(self.mirror / 'external' / 'py+1.tar.gz')
        self.manifest['bootstrap']['python_arm64'] = dict(self.python, url='https://fixture.invalid/py%2B1.tar.gz',
                                                          file='py+1.tar.gz')
        self.bundled()
        result = subprocess.run(['/bin/sh', str(self.script), 'doctor'], cwd=self.root, capture_output=True, text=True,
                                env=dict(os.environ, HAO_BOOTSTRAP_FILES=str(self.mirror)))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_unsigned_release_runs_without_signatures_and_says_so(self):
        self.script.write_text(self.script.read_text().replace("unsigned='false'", "unsigned='true'"))
        for name in ('release.json.sig', 'SHA256SUMS.sig'):
            (self.mirror / name).unlink()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('this release is not signed', result.stderr)
        held = {p.name for p in (self.root / 'hao-fixture/kit/tools/hao').iterdir()}
        self.assertEqual(held, {'hao', 'release.json', 'SHA256SUMS'})
        # the checksum list still decides: a release.json it does not list is refused
        (self.mirror / 'release.json').write_text(json.dumps(dict(self.manifest, extra=1)))
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)
        self.assertIn('release.json checksum mismatch', result.stderr)

    def test_signed_release_without_signatures_is_refused(self):
        (self.mirror / 'release.json.sig').unlink()
        result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4, result.stderr)

    def test_candidate_without_staged_release_refuses_before_network(self):
        self.script.write_text(self.script.read_text().replace("candidate='false'", "candidate='true'"))
        self.shim('curl', '#!/bin/sh\necho unexpected-network >&2\nexit 99\n')
        with mock.patch.dict(os.environ, {}, clear=True):
            result = self.run_bootstrap()
        self.assertEqual(result.returncode, 4)
        self.assertIn('candidate requires HAO_BOOTSTRAP_FILES', result.stderr)
        self.assertNotIn('unexpected-network', result.stderr)
