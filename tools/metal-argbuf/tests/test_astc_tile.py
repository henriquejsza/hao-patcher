"""Host test for libargbuf's ASTC tiles as WeatherMaps uploads them (diag#0055, 2026-11-17): WeatherMaps writes a KTX
ASTC 8x8 tile into its pool texture only when the texture's pixelFormat equals the KTX format. libargbuf's stand-in is
RGBA8, so -pixelFormat must answer the ASTC format to the app (and RGBA8 to the Metal stack). Builds src/device like
make does, links tests/astc_tile_probe.m against it, runs it under Rosetta with and without AGB_ASTC_REPORT_RGBA8.
Run: python3.14 -I -B -m unittest discover -s tools/metal-argbuf/tests
"""
import os
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / 'src' / 'device'
X86 = ['-arch', 'x86_64', '-mmacosx-version-min=11.7']
ALL = 512 * 512


@unittest.skipUnless(platform.system() == 'Darwin', 'needs macOS (x86_64 build, Rosetta)')
class AstcTile(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        t = Path(cls.tmp.name)
        lib, cls.probe = t / 'libargbuf.dylib', t / 'astc_tile_probe'
        subprocess.run(['xcrun', 'clang', *X86, '-fobjc-arc', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter',
                        '-Wno-protocol', '-Wno-mismatched-parameter-types', '-Wl,-no_warn_inits', '-dynamiclib',
                        str(SRC / 'argbuf.m'), str(SRC / 'astc.m'), str(SRC / 'heap.m'), str(SRC / 'argbuf_tramp.s'),
                        '-framework', 'Foundation', '-framework', 'Metal', '-late', '-o', str(lib)], check=True)
        subprocess.run(['xcrun', 'clang', *X86, '-fobjc-arc', str(HERE / 'astc_tile_probe.m'), str(lib),
                        '-framework', 'Foundation', '-framework', 'Metal', '-o', str(cls.probe)], check=True)
        for f in (lib, cls.probe):
            subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def run_probe(self, **env):
        r = subprocess.run([str(self.probe)], capture_output=True, text=True,
                           env={'PATH': os.environ.get('PATH', '/usr/bin:/bin'), **env})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        return {line.split(None, 1)[0]: line.split(None, 1)[1] for line in r.stdout.splitlines() if not line.startswith('device ')}

    def test_weather_tile_uploads(self):
        got = self.run_probe()
        self.assertEqual(got['R'], f'reported 212 uploaded yes texels {ALL}/{ALL}')
        self.assertEqual(got['B'], f'reported 212 uploaded yes texels {ALL}/{ALL}')
        self.assertEqual(got['P'], 'reported 70')

    def test_rgba8_report_drops_tiles(self):
        # the image's behaviour before the fix: the tile reports RGBA8 and WeatherMaps' guard drops it
        got = self.run_probe(AGB_ASTC_REPORT_RGBA8='1')
        self.assertEqual(got['R'], f'reported 70 uploaded no texels 0/{ALL}')
        self.assertEqual(got['B'], f'reported 70 uploaded no texels 0/{ALL}')


if __name__ == '__main__':
    unittest.main()
