"""Host test for libargbuf's render-target storage rule, packed depth/stencil pairing and pass rule (diag#0002, 2026-11-14): multisample textures and depth/stencil
formats asked for as Managed, Shared or Memoryless are made Private (MetalOld's validation aborts otherwise: Weather's
precipitation map asked for a 4x MSAA Stencil8 target that arrived Managed). Builds src/device/argbuf.m and astc.m like
make does, links tests/storage_probe.m against it, runs it under Rosetta.
Run: python3.14 -I -B -m unittest discover -s tools/metal-argbuf/tests
"""
import platform
import subprocess
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
SRC = HERE.parent / 'src' / 'device'
X86 = ['-arch', 'x86_64', '-mmacosx-version-min=11.7']


@unittest.skipUnless(platform.system() == 'Darwin', 'needs macOS (x86_64 build, Rosetta)')
class Storage(unittest.TestCase):
    def test_rule(self):
        with tempfile.TemporaryDirectory() as t:
            lib, probe = Path(t) / 'libargbuf.dylib', Path(t) / 'storage_probe'
            subprocess.run(['xcrun', 'clang', *X86, '-fobjc-arc', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter',
                            '-Wno-protocol', '-Wno-mismatched-parameter-types', '-Wl,-no_warn_inits', '-dynamiclib',
                            str(SRC / 'argbuf.m'), str(SRC / 'astc.m'), str(SRC / 'argbuf_tramp.s'),
                            '-framework', 'Foundation', '-framework', 'Metal', '-late', '-o', str(lib)], check=True)
            subprocess.run(['xcrun', 'clang', *X86, '-fobjc-arc', str(HERE / 'storage_probe.m'), str(lib),
                            '-framework', 'Foundation', '-framework', 'Metal', '-o', str(probe)], check=True)
            for f in (lib, probe):
                subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)
            out = subprocess.run([str(probe)], check=True, capture_output=True, text=True).stdout
        got = dict(line.split() for line in out.splitlines())
        self.assertEqual(got, {
            'weather_msaa_stencil_managed': 'yes', 'msaa_stencil_memoryless': 'yes', 'msaa_color_shared': 'yes',
            'depth32_managed': 'yes', 'depth24s8_shared': 'yes',
            'msaa_stencil_private': 'no', 'color_managed': 'no', 'r8_shared': 'no', 'color_memoryless': 'yes',
            # not a render target: the app may upload into it, so CPU access is never taken away
            'depth32_managed_not_target': 'no', 'stencil8_shared_not_target': 'no',
            # separate Depth32Float + Stencil8 -> Depth32Float_Stencil8 (260); anything else has no packed equivalent (0)
            'packed_weather': '260', 'packed_same': '0', 'packed_depth_only': '0', 'packed_depth16_stencil8': '0',
            # a shared packed texture only when nothing is loaded in or stored out (else refused, left as asked)
            'pass_clear_dontcare': 'yes', 'pass_dontcare_dontcare': 'yes', 'pass_depth_load': 'no',
            'pass_stencil_store': 'no', 'pass_depth_resolve': 'no'})


    def test_weather_cpu_stencil(self):
        # Weather's pattern on the host GPU with the adaptations installed on its classes: the MSAA Stencil8 target goes
        # Private, the CPU mask upload is emulated (staging + per-bit stencil passes), getBytes reads the staging copy, and
        # the overlay pass (separate Depth32Float depth, stencil Load) gets a packed texture filled from the CPU copy
        with tempfile.TemporaryDirectory() as t:
            lib, probe = Path(t) / 'libargbuf.dylib', Path(t) / 'weather_stencil_probe'
            subprocess.run(['xcrun', 'clang', *X86, '-fobjc-arc', '-O1', '-Wall', '-Wextra', '-Wno-unused-parameter',
                            '-Wno-protocol', '-Wno-mismatched-parameter-types', '-Wl,-no_warn_inits', '-dynamiclib',
                            str(SRC / 'argbuf.m'), str(SRC / 'astc.m'), str(SRC / 'argbuf_tramp.s'),
                            '-framework', 'Foundation', '-framework', 'Metal', '-late', '-o', str(lib)], check=True)
            subprocess.run(['xcrun', 'clang', *X86, '-fobjc-arc', str(HERE / 'weather_stencil_probe.m'), str(lib),
                            '-framework', 'Foundation', '-framework', 'Metal', '-o', str(probe)], check=True)
            for f in (lib, probe):
                subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)
            r = subprocess.run([str(probe)], capture_output=True, text=True, env={'AGB_LOG': '1'})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        got = dict(line.split(None, 1) for line in r.stdout.splitlines() if ' ' in line)
        self.assertEqual(got.get('blocks_ok'), '64/64', r.stdout + r.stderr)
        self.assertEqual(got.get('getbytes_ok'), 'yes', r.stdout)
        self.assertEqual(got.get('storage'), str(2), r.stdout)   # MTLStorageModePrivate
        for line in ('texture', 'CPU stencil upload', 'pipeline depth 252 + stencil 253', 'loads a CPU-written stencil'):
            self.assertIn(line, r.stderr, r.stderr)


if __name__ == '__main__':
    unittest.main()
