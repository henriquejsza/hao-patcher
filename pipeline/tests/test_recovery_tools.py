"""pipeline/stages/recovery-tools.py: the install/shasum/cmp/readlink forms the assembly uses in a Recovery."""
import hashlib
import os
import runpy
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

TOOL = Path(__file__).resolve().parents[1] / 'stages' / 'recovery-tools.py'
ASSEMBLE = Path(__file__).resolve().parents[1] / 'stages' / 'golden-assemble.sh'


def run(*argv):
    return subprocess.run([sys.executable, '-I', str(TOOL)] + list(argv), capture_output=True, text=True)


class RecoveryToolsTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_install_directories_and_files(self):
        r = run('install', '-d', '-m', '755', str(self.d / 'a/b'), str(self.d / 'c'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.d / 'a/b').stat().st_mode & 0o777, 0o755)
        src = self.d / 'src'
        src.write_bytes(b'abc')
        os.symlink(src, self.d / 'c/link')                     # an existing link at DEST is replaced, not followed
        me = str(os.getuid())
        r = run('install', '-o', me, '-g', str(os.getgid()), '-m', '644', str(src), str(self.d / 'c/link'))
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertFalse((self.d / 'c/link').is_symlink())
        self.assertEqual((self.d / 'c/link').read_bytes(), b'abc')
        self.assertEqual((self.d / 'c/link').stat().st_mode & 0o777, 0o644)
        r = run('install', '-m', '755', str(src), str(self.d / 'c'))  # into a directory
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.d / 'c/src').stat().st_mode & 0o777, 0o755)

    def test_install_refuses_what_it_does_not_implement(self):
        r = run('install', '-C', 'x', 'y')
        self.assertEqual(r.returncode, 64)
        self.assertIn('-C is not supported', r.stderr)

    def test_shasum_cmp_readlink(self):
        a, b = self.d / 'a', self.d / 'b'
        a.write_bytes(b'x' * 10)
        b.write_bytes(b'x' * 10)
        r = run('shasum', '-a', '256', str(a))
        self.assertEqual(r.stdout, '%s  %s\n' % (hashlib.sha256(b'x' * 10).hexdigest(), a))
        self.assertEqual(run('cmp', '-s', str(a), str(b)).returncode, 0)
        b.write_bytes(b'x' * 9 + b'y')
        self.assertEqual(run('cmp', '-s', str(a), str(b)).returncode, 1)
        self.assertEqual(run('cmp', '-s', str(a), str(self.d / 'none')).returncode, 2)
        os.symlink('target', self.d / 'l')
        self.assertEqual(run('readlink', str(self.d / 'l')).stdout, 'target\n')
        self.assertEqual(run('readlink', str(a)).returncode, 1)
        self.assertEqual(run('shasum', str(a)).returncode, 64)

    def test_assemble_uses_no_tool_a_recovery_lacks_before_the_wrappers(self):
        text = ASSEMBLE.read_text()
        head = text[:text.index('recovery_tools || exit $?')]
        for line in head.splitlines():
            code = line.split('#', 1)[0]
            for tool in ('install ', 'shasum ', 'cmp ', 'readlink '):
                self.assertFalse(code.lstrip().startswith(tool) or (' ' + tool) in code and 'for t in' not in code,
                                 line)


if __name__ == '__main__':
    unittest.main()
