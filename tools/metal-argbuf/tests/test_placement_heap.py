"""Host test for libargbuf's placement-heap emulation (diag#0019): RealityKit's CoreRE asks for a Private
MTLHeapTypePlacement heap at engine init and MetalOld aborts in -[MTLHeapDescriptorInternal validateWithDevice:].
Builds src/device like make does, links tests/placement_probe.m against it, installs the emulation on the host GPU's
classes and drives it through the Metal API under Rosetta (x86_64): CoreRE's calls, aliasing by byte range,
useHeap(s) on render and compute encoders, and a draw, a dispatch and a blit through placed resources.
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
class PlacementHeap(unittest.TestCase):
    def run_probe(self, env, probe_src='placement_probe.m', args=()):
        with tempfile.TemporaryDirectory() as t:
            lib, probe = Path(t) / 'libargbuf.dylib', Path(t) / Path(probe_src).stem
            subprocess.run(['xcrun', 'clang', *X86, '-fobjc-arc', '-O1', '-Wall', '-Wextra', '-Werror', '-Wno-unused-parameter',
                            '-Wno-protocol', '-Wno-mismatched-parameter-types', '-Wl,-no_warn_inits', '-dynamiclib',
                            str(SRC / 'argbuf.m'), str(SRC / 'astc.m'), str(SRC / 'heap.m'), str(SRC / 'argbuf_tramp.s'),
                            '-framework', 'Foundation', '-framework', 'Metal', '-late', '-o', str(lib)], check=True)
            subprocess.run(['xcrun', 'clang', *X86, '-fobjc-arc', str(HERE / probe_src), str(lib),
                            '-framework', 'Foundation', '-framework', 'Metal', '-o', str(probe)], check=True)
            for f in (lib, probe):
                subprocess.run(['codesign', '-f', '-s', '-', str(f)], check=True, capture_output=True)
            return subprocess.run([str(probe), *args], capture_output=True, text=True, env=env, timeout=120)

    def test_emulation(self):
        r = self.run_probe({'AGB_TRACE_HEAPS': '1'})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        got = dict(line.split(None, 1) for line in r.stdout.splitlines() if ' ' in line)
        self.assertEqual(got, {
            'libargbuf': 'loaded', 'automatic_passthrough': 'yes', 'placement_class': 'AGBPlacementHeap', 'placement_type': '1',
            'placement_size': 'ok', 'placement_storage': '2', 'placement_hazard': '1', 'max_available': 'ok',
            'no_offset_buffer_nil': 'yes', 'texture_made': 'yes', 'texture_storage': '2',
            # aliasing: the same (offset, descriptor) is the same memory; another resource over the range replaces it
            'same_offset_same_texture': 'yes', 'other_offset_other_texture': 'yes', 'used_size': 'ok',
            'outside_nil': 'yes', 'overlap_replaces': 'yes', 'held_within_size': 'yes',
            'buffer_made': 'yes', 'buffer_same': 'yes', 'compute_doubled': 'yes', 'pixels_ok': '4096/4096'}, r.stderr)
        self.assertIn('emulated: size 8388608 storage 2', r.stderr)
        self.assertIn('-> same', r.stderr)

    def test_shared_heap(self):
        # re::HeapPool's Shared automatic heap, with the device answering NO to supportsSharedStorageHeapResources as the
        # HD 4000 does (MetalOld then aborts in validateWithDevice:, "Shared storage mode disallowed")
        r = self.run_probe({}, 'shared_heap_probe.m', ['nosharedheaps'])
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        got = dict(line.split(None, 1) for line in r.stdout.splitlines() if ' ' in line)
        self.assertEqual(got, {
            'device_shared_heaps': 'no', 'libargbuf': 'loaded', 'private_passthrough': 'yes', 'shared_class': 'AGBPlacementHeap',
            'shared_type': '0', 'shared_storage': '0', 'shared_hazard': '2', 'empty_available': 'ok', 'buffer_made': 'yes',
            'used_size': 'ok', 'fills_then_nil': 'yes', 'freed_reused': 'yes', 'texture_made': 'yes',
            'compute_doubled': '1024/1024', 'command_status': '4'}, r.stderr)
        self.assertIn('shared heap', r.stderr)
        self.assertIn('emulated: size 1048576 storage 0', r.stderr)

    def test_shared_heap_left_to_a_device_that_has_them(self):
        r = self.run_probe({}, 'shared_heap_probe.m')
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('device_shared_heaps yes', r.stdout)
        self.assertNotIn('shared_class AGBPlacementHeap', r.stdout)
        self.assertIn('compute_doubled 1024/1024', r.stdout)

    def test_switch_off(self):
        # AGB_KEEP_PLACEMENT_HEAPS leaves placement heaps to the driver (here the host's, which has them)
        r = self.run_probe({'AGB_KEEP_PLACEMENT_HEAPS': '1'})
        self.assertEqual(r.returncode, 0, r.stdout + r.stderr)
        self.assertIn('placement heaps left to MetalOld', r.stderr)
        self.assertNotIn('placement_class AGBPlacementHeap', r.stdout)


if __name__ == '__main__':
    unittest.main()
