"""golden-gate-unsupported-daemons: apply.sh on a stand-in Data tree.
python3.14 -I -B -m unittest discover -s patches/golden-gate-unsupported-daemons/tests"""
import os
import pathlib
import plistlib
import shutil
import stat
import subprocess
import tempfile
import unittest

PATCH = pathlib.Path(__file__).resolve().parents[1]
REL = 'private/var/db/com.apple.xpc.launchd/disabled.plist'


def labels():
    rows = [l.split() for l in (PATCH / 'src/disabled-daemons.txt').read_text().splitlines() if l.strip() and not l.startswith('#')]
    return [r[0] for r in rows], rows


@unittest.skipUnless(shutil.which('plutil'), 'needs plutil (macOS)')
class Apply(unittest.TestCase):
    def setUp(self):
        self.tmp = pathlib.Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp)
        self.data = self.tmp / 'data'
        self.data.mkdir()
        (self.tmp / 'bin').mkdir()
        shim = self.tmp / 'bin/chown'
        shim.write_text('#!/bin/sh\necho "$@" >> "%s"\n' % (self.tmp / 'chown.log'))
        shim.chmod(0o755)

    def run_apply(self):
        env = dict(os.environ, PATH='%s:/usr/bin:/bin' % (self.tmp / 'bin'), DATA=str(self.data), P=str(PATCH))
        r = subprocess.run(['sh', '-eu', str(PATCH / 'apply.sh')], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return plistlib.loads((self.data / REL).read_bytes())

    def test_every_label_disabled_new_file(self):
        names, _ = labels()
        self.assertIn('com.apple.modelmanagerd', names)
        self.assertEqual(self.run_apply(), {n: True for n in names})
        self.assertEqual(stat.S_IMODE((self.data / REL).stat().st_mode), 0o644)
        self.assertIn('root:wheel %s' % (self.data / REL), (self.tmp / 'chown.log').read_text())

    def test_keeps_other_entries_and_is_idempotent(self):
        f = self.data / REL
        f.parent.mkdir(parents=True)
        f.write_bytes(plistlib.dumps({'com.apple.ftpd': True, 'com.apple.screensharing': False, 'com.apple.modelmanagerd': False}))
        once = self.run_apply()
        self.assertEqual(once['com.apple.ftpd'], True)
        self.assertEqual(once['com.apple.screensharing'], False)
        self.assertEqual(once['com.apple.modelmanagerd'], True)
        self.assertEqual(self.run_apply(), once)

    def test_every_label_has_a_reason(self):
        _, rows = labels()
        for row in rows:
            self.assertTrue(row[0].startswith('com.apple.'), row)
            self.assertGreaterEqual(len(row), 6, 'a label needs its S18 reason: %s' % row[0])


if __name__ == '__main__':
    unittest.main()
