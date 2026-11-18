"""apply.sh on a stand-in Data tree: the keys softwareupdated reads for splats are off, the Install
Tonight queue is empty, and every other key is kept.
python3.14 -I -B -m unittest discover -s patches/golden-gate-update-policy/tests"""
import datetime
import json
import os
import pathlib
import plistlib
import shutil
import stat
import subprocess
import tempfile
import unittest

PATCH = pathlib.Path(__file__).resolve().parents[1]
PJ = json.loads((PATCH / 'patch.json').read_text())
REL = 'Library/Preferences/com.apple.SoftwareUpdate.plist'


@unittest.skipUnless(shutil.which('plutil'), 'needs plutil (macOS)')
class Apply(unittest.TestCase):
    def run_apply(self, data):
        """apply.sh as post.sh runs it (sh -eu, DATA and P), with chown recorded instead of run (not root here)."""
        bin_dir = pathlib.Path(self.tmp) / 'bin'
        bin_dir.mkdir(exist_ok=True)
        log = pathlib.Path(self.tmp) / 'chown.log'
        shim = bin_dir / 'chown'
        shim.write_text('#!/bin/sh\necho "$@" >> "%s"\n' % log)
        shim.chmod(0o755)
        env = dict(os.environ, PATH='%s:/usr/bin:/bin:/usr/sbin:/sbin' % bin_dir, DATA=str(data), P=str(PATCH),
                   SYS='/nonexistent')
        r = subprocess.run(['sh', '-eu', str(PATCH / 'apply.sh')], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr + r.stdout)
        return log.read_text().split('\n') if log.exists() else []

    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.tmp)
        self.data = pathlib.Path(self.tmp) / 'data'
        self.data.mkdir()

    def prefs(self):
        return plistlib.loads((self.data / REL).read_bytes())

    def test_new_file(self):
        chowns = self.run_apply(self.data)
        p = self.prefs()
        self.assertIs(p['SplatEnabled'], False)
        self.assertNotIn('AutomaticallyInstallMacOSUpdates', p)   # macOS updates keep Apple's default
        self.assertNotIn('AutoInstallProductKeys', p)
        self.assertNotIn('FirstInstallTonightDateDictionary', p)
        self.assertEqual(stat.S_IMODE((self.data / REL).stat().st_mode), 0o644)
        self.assertIn('root:wheel %s' % (self.data / REL), chowns)
        self.assertIn('root:wheel %s' % (self.data / 'Library/Preferences'), chowns)

    def test_existing_file_with_a_queued_splat(self):
        f = self.data / REL
        f.parent.mkdir(parents=True)
        when = datetime.datetime(2026, 11, 18, 3, 52, 0)
        f.write_bytes(plistlib.dumps({
            'AutomaticCheckEnabled': False, 'AutomaticDownload': False, 'AutomaticallyInstallMacOSUpdates': True,
            'CriticalUpdateInstall': False, 'ConfigDataInstall': False, 'SplatEnabled': True,
            'AutoInstallProductKeys': ['MSU_UPDATE_26B131_full_27.2.1_rsr'],
            'FirstInstallTonightDateDictionary': {'MSU_UPDATE_26B131_full_27.2.1_rsr': when},
            'LastSuccessfulDate': when}, fmt=plistlib.FMT_BINARY))
        f.chmod(0o600)
        chowns = self.run_apply(self.data)
        p = self.prefs()
        self.assertIs(p['SplatEnabled'], False)
        self.assertNotIn('AutoInstallProductKeys', p)
        self.assertNotIn('FirstInstallTonightDateDictionary', p)
        self.assertIs(p['AutomaticallyInstallMacOSUpdates'], True)    # kept as found
        for k in ('AutomaticCheckEnabled', 'AutomaticDownload', 'CriticalUpdateInstall', 'ConfigDataInstall'):
            self.assertIs(p[k], False, k)                       # kept as found
        self.assertEqual(p['LastSuccessfulDate'], when)
        self.assertEqual(stat.S_IMODE(f.stat().st_mode), 0o644)
        self.assertNotIn('root:wheel %s' % (self.data / 'Library/Preferences'), chowns)   # existing folder untouched

    def test_twice_is_the_same(self):
        self.run_apply(self.data)
        first = (self.data / REL).read_bytes()
        self.run_apply(self.data)
        self.assertEqual(plistlib.loads(first), self.prefs())


class Declaration(unittest.TestCase):
    def test_declares_the_file_it_writes_as_a_seed(self):
        self.assertEqual([f['path'] for f in PJ['files']], [REL])
        self.assertEqual(PJ['files'][0]['content'], 'seed')
        self.assertIn('0644', PJ['files'][0]['origin']['note'])
        self.assertIn('"$DATA/%s"' % REL, (PATCH / 'apply.sh').read_text())

    def test_scope_and_pack(self):
        self.assertEqual(PJ['stage'], 'post')
        self.assertEqual(PJ['pack'], 'base')                  # every image of every Intel Mac, release profiles too
        self.assertEqual(PJ['requires']['os'], ['26B131'])     # the trace is of 26B131's softwareupdated


if __name__ == '__main__':
    unittest.main()
