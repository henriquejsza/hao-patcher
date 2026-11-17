"""Host tests for src/prespecialization.py and its data (prespecialization-26B131.json).

python3.14 -I -B -m unittest discover -s patches/golden-gate-userspace/tests -k prespecialization

Always: the data's shape (two switch calls become `xor eax, eax; nop`, every descriptor slot is nulled with its chain
delta kept, no site twice), the plan on a sparse fixture cache (UUID and bytes checked, another cache refused) and the
gate on a fixture System (the recorded set passes; one more or one fewer overridden image stops the build).
With USERSPACE_X86_CACHE (the pristine 26B131 x86_64 cache folder): the plan resolves on the real cache.
"""
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]/'src'
sys.path.insert(0, str(ROOT))
spec = importlib.util.spec_from_file_location('prespecialization', ROOT/'prespecialization.py')
P = importlib.util.module_from_spec(spec)
spec.loader.exec_module(P)
DATA = P.load()
MAIN, SIX = 'dyld_shared_cache_x86_64', 'dyld_shared_cache_x86_64.06'


def fixture_cache(folder, data=DATA, uuid=None):
    """Sparse files carrying only the header's UUID and the recipe's `before` bytes."""
    folder.mkdir(parents=True, exist_ok=True)
    for name, entry in data['files'].items():
        with (folder/name).open('wb') as stream:
            stream.truncate(max(e['at'] + 8 for e in entry['edits']) + 0x100)
            if name == MAIN:
                stream.seek(P.UUID_AT)
                stream.write(bytes.fromhex(uuid or data['cache_uuid']))
            for e in entry['edits']:
                stream.seek(e['at'])
                stream.write(bytes.fromhex(e['before']))


class Data(unittest.TestCase):
    def test_the_two_switch_reads_become_xor_eax(self):
        edits = DATA['files'][MAIN]['edits']
        self.assertEqual(sorted(e['id'] for e in edits), ['prespecialization-image-loaded', 'prespecialization-state-setup'])
        for e in edits:
            self.assertEqual(e['before'][:2], 'e8')                # call rel32 (_dyld_shared_cache_some_image_overridden)
            self.assertEqual(e['after'], '31c00f1f00')             # xor eax, eax; nop dword [rax]

    def test_descriptor_slots_are_nulled_with_their_chain_delta_kept(self):
        edits = DATA['files'][SIX]['edits']
        self.assertEqual(len(edits), sum(DATA['descriptor_slots_dropped'].values()))
        self.assertEqual(len(edits), 113)
        for e in edits:
            before, after = bytes.fromhex(e['before']), bytes.fromhex(e['after'])
            self.assertEqual(len(before), 8)
            self.assertEqual(after[:5], bytes(5))
            self.assertEqual(after[5:], before[5:])
            self.assertNotEqual(before[:5], bytes(5))

    def test_no_site_twice_and_the_gate_result_is_recorded(self):
        for entry in DATA['files'].values():
            spans = sorted((e['at'], e['at'] + len(bytes.fromhex(e['before']))) for e in entry['edits'])
            self.assertTrue(all(a[1] <= b[0] for a, b in zip(spans, spans[1:])))
        self.assertEqual(DATA['blocked'], {'apple_entries': 0, 'catalog_keys': 0})
        self.assertEqual(sorted(DATA['overridden']), DATA['overridden'])
        self.assertTrue(set(DATA['descriptor_slots_dropped']) <= set(DATA['overridden']))
        self.assertNotIn('/usr/lib/dyld', DATA['overridden'])

    def test_the_declared_cache_edits_are_the_data(self):
        edits = Path(__file__).resolve().parents[1]/'edits'
        for name, spec_name in ((MAIN, 'cache-main.json'), (SIX, 'cache-06.json')):
            spec = json.loads((edits/spec_name).read_text())
            entry = DATA['files'][name]
            declared = next(e for e in spec['edits'] if e['id'] == 'prespecialization-overrides')
            self.assertEqual(list(declared['resolved']), [entry['sha256']])
            self.assertEqual(declared['resolved'][entry['sha256']],
                             [{k: e[k] for k in ('at', 'before', 'after', 'reason')} for e in entry['edits']])

    def test_the_data_is_part_of_the_cryptex_cache_key(self):
        import cryptex_cache
        files = cryptex_cache.source_files(ROOT)
        self.assertIn('prespecialization-26B131.json', files)
        self.assertIn('prespecialization.py', files)


class Plan(unittest.TestCase):
    def test_plan_on_a_fixture_cache(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)/'dyld'
            fixture_cache(folder)
            plan = P.plan_cache_family(folder)
            self.assertEqual({p.name: len(c) for p, c in plan.items()}, {MAIN: 2, SIX: 113})

    def test_another_cache_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)/'dyld'
            fixture_cache(folder, uuid='00' * 16)
            with self.assertRaisesRegex(ValueError, 'cache UUID'):
                P.plan_cache_family(folder)
            fixture_cache(folder)
            e = DATA['files'][SIX]['edits'][7]
            with (folder/SIX).open('r+b') as stream:
                stream.seek(e['at'])
                stream.write(bytes(8))
            with self.assertRaisesRegex(ValueError, 'bytes differ'):
                P.plan_cache_family(folder)


class Gate(unittest.TestCase):
    IMAGES = DATA['overridden'] + ['/usr/lib/dyld', '/usr/lib/libobjc.A.dylib',
                                   '/System/Library/Frameworks/Foundation.framework/Versions/C/Foundation']

    def system(self, tmp, paths):
        root = Path(tmp)/'System-volume'
        for p in paths:
            f = root/p.lstrip('/')
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_bytes(b'x')
        return root

    def test_the_recorded_set_passes_and_dyld_does_not_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.system(tmp, DATA['overridden'] + ['/usr/lib/dyld'])
            record = P.gate(root, None, paths=self.IMAGES)
            self.assertEqual(record['overridden'], len(DATA['overridden']))
            self.assertEqual(record['descriptor_slots_dropped'], 113)

    @staticmethod
    def swift(path):   # the fixture's Swift-bearing images: everything but the AGX driver and the 10 recorded ones
        return 'AGXMetal' not in path and path not in DATA['overridden']

    def test_one_more_overridden_image_stops_the_build(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self.system(tmp, DATA['overridden'] + ['/usr/lib/libobjc.A.dylib'])
            with self.assertRaisesRegex(SystemExit, r"new: \['/usr/lib/libobjc.A.dylib'\]"):
                P.gate(root, None, paths=self.IMAGES, swift=lambda p: True)

    def test_one_fewer_overridden_image_passes_and_is_recorded(self):
        # e.g. a generic image without the Wi-Fi pack's WiFiPeerToPeer override: its slots are nulled while the cache
        # copy loads, which only takes the ordinary (slower) path
        with tempfile.TemporaryDirectory() as tmp:
            root = self.system(tmp, DATA['overridden'][1:])
            record = P.gate(root, None, paths=self.IMAGES, swift=lambda p: True)
            self.assertEqual(record['gone_null_slots'], [DATA['overridden'][0]])

    def test_an_extra_image_without_swift_metadata_passes_and_is_recorded(self):
        agx = '/System/Library/Extensions/AGXMetalG14X.bundle/Contents/MacOS/AGXMetalG14X'
        with tempfile.TemporaryDirectory() as tmp:
            root = self.system(tmp, DATA['overridden'] + [agx])
            record = P.gate(root, None, paths=self.IMAGES + [agx], swift=self.swift)
            self.assertEqual(record['ignored_without_swift'], [agx])
            self.assertEqual(record['overridden'], len(DATA['overridden']) + 1)
        with tempfile.TemporaryDirectory() as tmp:   # a Swift-bearing extra one still stops it, next to the AGX one
            root = self.system(tmp, DATA['overridden'] + [agx, '/usr/lib/libobjc.A.dylib'])
            with self.assertRaisesRegex(SystemExit, r"new: \['/usr/lib/libobjc.A.dylib'\]"):
                P.gate(root, None, paths=self.IMAGES + [agx], swift=self.swift)


@unittest.skipUnless(os.environ.get('USERSPACE_X86_CACHE'), 'set USERSPACE_X86_CACHE to the 26B131 x86_64 cache folder')
class RealCache(unittest.TestCase):
    def test_plan_resolves_on_the_real_cache(self):
        folder = Path(os.environ['USERSPACE_X86_CACHE'])
        plan = P.plan_cache_family(folder)
        self.assertEqual({p.name: len(c) for p, c in plan.items()}, {MAIN: 2, SIX: 113})
        self.assertTrue(set(DATA['overridden']) <= set(P.image_paths(folder)))

    def test_the_agx_drivers_carry_no_swift_metadata_and_the_wifi_ones_do(self):
        folder = Path(os.environ['USERSPACE_X86_CACHE'])
        swift = P.swift_sections(folder)
        agx = [p for p in P.image_paths(folder) if '/AGXMetal' in p and '.bundle/' in p]
        self.assertGreaterEqual(len(agx), 14)
        self.assertFalse(any(swift(p) for p in agx))
        self.assertTrue(swift('/System/Library/PrivateFrameworks/CoreWiFi.framework/Versions/A/CoreWiFi'))


if __name__ == '__main__':
    unittest.main()
