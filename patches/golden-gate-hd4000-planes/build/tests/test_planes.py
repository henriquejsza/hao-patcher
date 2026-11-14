"""Host tests for libhd4000-planes.dylib.

python3.14 -I -B -m unittest discover -s patches/golden-gate-hd4000-planes/build/tests

Always: the build is reproducible from build/hd4000_planes.m and yields the bytes of the input row's artifact
(when the row resolves), an x86_64 dylib with the install name the driver's weak load command names.
With HD4000_PLANES_PROBE=PATH (the plane-texture probe, phase D): the probe passes with the
library inserted, and shadows are made for exactly the surfaces whose plane pitches differ. The host GPU does not
have the HD 4000 fault, so this shows the library acts where it should and breaks nothing, not that it fixes it.
"""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

BUILD = Path(__file__).resolve().parents[1]
TOP = BUILD.parents[2]
loader = importlib.machinery.SourceFileLoader('hd4000_make', str(BUILD / 'make'))
spec = importlib.util.spec_from_loader('hd4000_make', loader)
make = importlib.util.module_from_spec(spec)
loader.exec_module(make)


class Build(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dir = Path(tempfile.mkdtemp())
        cls.lib, _ = make.build(cls.dir)

    def test_reproducible(self):
        again, _ = make.build(Path(tempfile.mkdtemp()))
        self.assertEqual(make.sha256(again), make.sha256(self.lib))

    def test_matches_the_row(self):
        row = (TOP / 'pipeline/inputs/25G342/hd4000_planes').read_text().split('\n')
        path = [l for l in row if l and not l.startswith('#')][0].split()[1]
        art = TOP / path / 'libhd4000-planes.dylib'
        if not art.exists():
            self.skipTest(f'{path} not in this store')
        self.assertEqual(make.sha256(self.lib), make.sha256(art))

    def test_install_name_and_arch(self):
        out = subprocess.run(['otool', '-D', str(self.lib)], capture_output=True, text=True, check=True).stdout
        self.assertIn(make.INSTALL_NAME, out)
        self.assertIn('x86_64', subprocess.run(['lipo', '-archs', str(self.lib)], capture_output=True, text=True).stdout)

    def test_hook_points(self):
        # the classes and selectors the constructor looks up by name are spelled as in the HD 4000 driver
        src = (BUILD / 'hd4000_planes.m').read_text()
        for name in ('MTLIGAccelDevice', 'MTLIGAccelCommandBuffer', 'MTLIGAccelTexture',
                     'newTextureWithDescriptor:iosurface:plane:', 'iosurfacePlane'):
            self.assertIn(name, src)

    @unittest.skipUnless(os.environ.get('HD4000_PLANES_PROBE'), 'set HD4000_PLANES_PROBE to the ycbcr-plane-texture probe')
    def test_probe_phase_d(self):
        env = dict(os.environ, DYLD_INSERT_LIBRARIES=str(self.lib), HD4000_PLANES_HOST='1', HD4000_PLANES_LOG='2',
                   YCBCR_PROBE_NO_GETBYTES='1', YCBCR_PROBE_ONLY_D='1')
        env.pop('HD4000_PLANES_PROBE')
        args = ['arch', '-x86_64'] + [a for k in ('DYLD_INSERT_LIBRARIES', 'HD4000_PLANES_HOST', 'HD4000_PLANES_LOG',
                                                  'YCBCR_PROBE_NO_GETBYTES', 'YCBCR_PROBE_ONLY_D') for a in ('-e', f'{k}={env[k]}')]
        r = subprocess.run(args + [os.environ['HD4000_PLANES_PROBE'], '.'], cwd=tempfile.mkdtemp(),
                           capture_output=True, text=True, timeout=600)
        out = r.stdout + r.stderr
        self.assertEqual(r.returncode, 0, out[-2000:])
        self.assertIn('RESULT PASS', out)
        pitches = set(re.findall(r'shadow for surface \d+ plane 1 \((\d+x\d+), pitch (\d+) vs plane 0 (\d+)\)', out))
        self.assertTrue(pitches)
        self.assertTrue(all(p != q for _, p, q in pitches), pitches)     # only where the pitches differ


if __name__ == '__main__':
    unittest.main()
