"""pipeline/stages/inputs.sh with fake hdiutil and pkgutil: the KDK, OCLP source and CPython archives are checked
against their rows and extracted afresh each run (nothing left in a cache is used), and an OCLP archive is accepted
only when it is the oclp_source row's bytes, whatever commit it names. The run stops at python_site (no row here)."""
import hashlib
import io
import os
from pathlib import Path
import struct
import subprocess
import sys
import tarfile
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
COMMIT = 'abcdef0123456789abcdef0123456789abcdef01'

FAKE_HDIUTIL = '''#!/bin/sh
echo "hdiutil $*" >> "$FAKE_LOG"
if [ "$1" = attach ]; then
  while [ $# -gt 1 ]; do [ "$1" = -mountpoint ] && m=$2; shift; done
  echo "$1" > "$m/KernelDebugKit.pkg"
fi
'''
FAKE_PKGUTIL = '''#!/bin/sh
echo "pkgutil $*" >> "$FAKE_LOG"
p=$3/KDK.pkg/Payload/System/Library
mkdir -p "$p/Extensions/Real.kext" "$p/CoreServices"
echo real > "$p/Extensions/Real.kext/Info.plist"; echo version > "$p/CoreServices/SystemVersion.plist"
'''


def sha(data):
    return hashlib.sha256(data).hexdigest()


def tar_bytes(files, comment=None, gz=False):
    b = io.BytesIO()
    with tarfile.open(fileobj=b, mode='w:gz' if gz else 'w', format=tarfile.PAX_FORMAT,
                      pax_headers={'comment': comment} if comment else None) as t:
        for name, (data, mode) in files.items():
            i = tarfile.TarInfo(name); i.size, i.mode = len(data), mode
            t.addfile(i, io.BytesIO(data))
    return b.getvalue()


def macho():
    return struct.pack('<IiiIIIII', 0xfeedfacf, 0x01000007, 3, 2, 0, 0, 0, 0)


class InputsStage(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); self.d = Path(self.t.name)
        self.files = self.d / 'files'; self.files.mkdir()
        self.lock, self.common = self.d / 'lock', self.d / 'common'
        self.lock.mkdir(); self.common.mkdir()
        self.row(self.lock, 'kdk', 'Kernel_Debug_Kit_1.0_build_1A1.dmg', b'kdk image')
        self.row(self.common, 'fl', 'fl', b'fl tool')
        constants = b'patcher_support_pkg_version: str = "9.9.9"\n'
        self.oclp = tar_bytes({'opencore_legacy_patcher/constants.py': (constants, 0o644)}, comment=COMMIT)
        self.row(self.common, 'oclp_source', 'oclp-source.tar', self.oclp)
        self.row(self.common, 'psp_9.9.9', 'Universal-Binaries.dmg', b'psp')
        for arch, body in (('arm64', b'#!/bin/sh\necho archive arm64\n'), ('x86_64', macho())):
            self.row(self.common, 'python_' + arch, 'cpython-%s.tar.gz' % arch,
                     tar_bytes({'python/bin/python3.12': (body, 0o755)}, gz=True))
        self.fakes = self.d / 'bin'; self.fakes.mkdir()
        for name, text in (('hdiutil', FAKE_HDIUTIL), ('pkgutil', FAKE_PKGUTIL)):
            (self.fakes / name).write_text(text); (self.fakes / name).chmod(0o755)
        (self.fakes / 'python3').symlink_to(sys.executable)
        self.log = self.d / 'calls.log'

    def tearDown(self):
        self.t.cleanup()

    def row(self, lock, name, file, data):
        p = self.files / file; p.write_bytes(data)
        (lock / name).write_text('%s %s\n' % (sha(data), p))
        return p

    def run_stage(self, share='share', **env):
        e = dict(os.environ, PATH='%s:%s' % (self.fakes, os.environ['PATH']), FAKE_LOG=str(self.log),
                 OCLP_REPO=str(self.d / 'no-repo'), **env)
        share = self.d / share
        r = subprocess.run(['zsh', str(TOP / 'pipeline/stages/inputs.sh'), share, self.d / 'target.json', self.lock,
                            self.common, COMMIT[:9], self.d / 'set.txt', 'golden-first'],
                           capture_output=True, text=True, env=e)
        return r, share

    def test_archives_are_checked_and_extracted_fresh(self):
        r, share = self.run_stage()
        self.assertIn('has no row python_site', r.stderr)       # the planned stop, after the parts under test
        self.assertEqual((share / 'py/bin/python3.12').read_bytes(), b'#!/bin/sh\necho archive arm64\n')
        self.assertEqual((share / 'py-x86_64/bin/python3.12').read_bytes(), macho())
        kdk = share / 'kdk/KDK_1.0_1A1.kdk/System/Library'
        self.assertEqual(sorted(p.name for p in (kdk / 'Extensions').iterdir()), ['Real.kext'])
        self.assertEqual((share / 'oclp/Universal-Binaries.dmg').read_bytes(), b'psp')
        log = self.log.read_text()
        self.assertIn('pkgutil --expand-full', log)
        attached = log.split('hdiutil attach')[1].split()[-1]
        self.assertNotEqual(Path(attached).resolve(), (self.files / 'Kernel_Debug_Kit_1.0_build_1A1.dmg').resolve(),
                            'the KDK is mounted from its checked copy')
        self.assertEqual([p.name for p in self.d.iterdir() if p.name.startswith('.inputs.')], [],
                         'the checked copies are removed')
        # a second run extracts again: nothing kept between runs is read
        self.log.unlink()
        r, share2 = self.run_stage('share2')
        self.assertIn('pkgutil --expand-full', self.log.read_text())
        self.assertEqual((share2 / 'py/bin/python3.12').read_bytes(), b'#!/bin/sh\necho archive arm64\n')

    def test_a_changed_archive_stops_before_it_is_used(self):
        for row, file in (('kdk', 'Kernel_Debug_Kit_1.0_build_1A1.dmg'), ('python_arm64', 'cpython-arm64.tar.gz')):
            with self.subTest(row=row):
                p = self.files / file; good = p.read_bytes()
                p.write_bytes(good + b'x')
                try:
                    r, share = self.run_stage('share-' + row)
                finally:
                    p.write_bytes(good)
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('is not %s (%s)' % (sha(good), row), r.stderr)
                self.assertFalse((share / 'py/bin/python3.12').exists())

    def test_oclp_archive_must_be_the_rows_bytes(self):
        other = tar_bytes({'opencore_legacy_patcher/constants.py': (b'patcher_support_pkg_version: str = "9.9.9"\n'
                                                                      b'evil = 1\n', 0o644)}, comment=COMMIT)
        tar = self.d / 'override' / (COMMIT[:9] + '.tar'); tar.parent.mkdir(); tar.write_bytes(other)
        tar.with_suffix('.commit').write_text(COMMIT + '\n')
        r, share = self.run_stage(OCLP_TAR=str(tar))
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('is not %s (oclp_source)' % sha(self.oclp), r.stderr)
        self.assertEqual(list((share / 'oclp').iterdir()), [], 'nothing of it is extracted')
        self.assertFalse(self.log.exists() and 'pkgutil' in self.log.read_text())
        # the row's own bytes under the override name are accepted
        tar.write_bytes(self.oclp)
        r, share = self.run_stage('share-ok', OCLP_TAR=str(tar))
        self.assertIn('has no row python_site', r.stderr)
        self.assertTrue((share / 'oclp/opencore_legacy_patcher/constants.py').is_file())


if __name__ == '__main__':
    unittest.main()
