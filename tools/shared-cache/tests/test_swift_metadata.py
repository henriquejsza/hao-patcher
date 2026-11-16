import copy
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.swift_metadata import (References, FUNCTION_SLOTS, emit_table, materialize,
                                        normalize, recipe_rows, prepare, table_reservations)


class SwiftMetadataTests(unittest.TestCase):
    def setUp(self):
        self.refs = References.__new__(References)
        identity = ('/swift', '__DATA', '__const')
        row = (0x1000, 0x2000, identity, 'uuid', 5)
        self.refs.ranges = [row]
        self.refs.starts = [0x1000]
        self.refs.sections = {identity: row}
        self.family = SimpleNamespace(main=SimpleNamespace(data=bytes(104), mappings=[SimpleNamespace(address=0x1000)]))
        self.recipe = dict(schema=1, records=[dict(name='RootSg', owner='/swift'), dict(name='RootSgSg', owner='/swift')])
        self.header = dict(schema=1, cache_uuid='00000000-0000-0000-0000-000000000000', base=0x6000)
        witness = [0x6300] * 14
        witness[8:11] = [5, 8, 0x200003]
        self.captured = [self.header,
            dict(index=1, metadata=0x8000, full_metadata=[0, 0x9000, 0x202, 0x6200, 0x6100, 0],
                 witness=witness, none_copy_destroy=True),
            dict(index=2, metadata=0x8100, full_metadata=[0, 0x9100, 0x202, 0x6200, 0x8000, 0],
                 witness=witness, none_copy_destroy=True)]
        with patch('dyld_rebuild.swift_metadata.References', return_value=self.refs):
            self.catalog = normalize(self.recipe, self.captured, self.family)
        self.roots = dict(base=0x1000, table=0x1500, swift_pointer=0x1400, dyld_offset=0x1480)

    def generate(self, entries=None, catalog=None):
        with patch('dyld_rebuild.swift_metadata.References', return_value=self.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries', return_value=(entries or {}, self.roots)):
            return materialize(catalog or self.catalog, self.family, 0x3000)

    def test_aslr_is_removed_and_owned_dependencies_relocated(self):
        self.assertEqual(self.catalog['records'][0]['argument']['offset'], 0x100)
        self.assertEqual(self.catalog['records'][1]['argument'], {'owned': 'RootSg'})
        data, fields, entries, _, records, _ = self.generate({(9, 8): [7, 6]})
        self.assertEqual(len(data), 320)
        self.assertEqual(struct.unpack_from('<3Q', data, 112), (5, 8, 0x200003))
        pointers = {r['address']: r['target'] for r in fields}
        self.assertEqual(pointers[0x3008], 0x3030)
        self.assertEqual(pointers[0x30c0], 0x3010)
        self.assertEqual(entries[(0x200, 0x2010)], [0x20b0])
        self.assertEqual(entries[(9, 8)], [7, 6])
        self.assertEqual(len(pointers), 28)
        self.assertEqual(len(records), 2)

    def test_existing_parent_identity_is_used_by_nested_key(self):
        data, fields, entries, _, records, _ = self.generate({(0x200, 0x100): [0x600]})
        self.assertEqual(len(data), 160)
        self.assertEqual(entries[(0x200, 0x600)], [0x2010])
        self.assertTrue(records[0]['existing'])
        self.assertEqual(next(r['target'] for r in fields if r['address'] == 0x3020), 0x1600)

    def test_old_cache_partial_capture_and_heap_reference_fail(self):
        for change in ('uuid', 'missing', 'heap', 'value'):
            captured = copy.deepcopy(self.captured)
            if change == 'uuid': captured[0]['cache_uuid'] = 'another-build'
            if change == 'missing': captured.pop()
            if change == 'heap': captured[1]['full_metadata'][4] = 0xf000
            if change == 'value': captured[1]['none_copy_destroy'] = False
            with self.subTest(change=change), patch('dyld_rebuild.swift_metadata.References', return_value=self.refs), self.assertRaises(Refusal):
                normalize(self.recipe, captured, self.family)

    def test_different_image_uuid_and_dependency_cycle_fail(self):
        changed = copy.deepcopy(self.catalog)
        changed['records'][0]['descriptor']['image_uuid'] = 'different-build'
        with self.assertRaisesRegex(Refusal, 'different Mach-O build'): self.generate(catalog=changed)
        changed = copy.deepcopy(self.catalog)
        changed['records'][0]['argument'] = {'owned': 'RootSgSg'}
        with self.assertRaisesRegex(Refusal, 'cyclic or missing'): self.generate(catalog=changed)

    def test_both_registration_roots_are_emitted(self):
        layout = dict(swift_metadata=dict(address=0x3000, reserve=4096), swift_table=dict(address=0x4000, reserve=4096))
        with patch('dyld_rebuild.swift_metadata.References', return_value=self.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries', return_value=({}, self.roots)), \
             patch('dyld_rebuild.swift_metadata.emit_table', return_value=(b'table', {})):
            recipe = prepare(self.catalog, self.family, layout, '/unused')
        self.assertEqual(recipe['pointer_edits'][0]['target'], 0x4000)
        self.assertEqual(recipe['pointer_edits'][0]['expected'], 0x1500)
        self.assertEqual(struct.unpack('<Q', bytes.fromhex(recipe['byte_edits'][0]['after']))[0], 0x3000)
        self.assertEqual(recipe['total_keys'], 2)

    def test_shipped_recipe_retains_all_412_semantic_names(self):
        recipe = json.loads((ROOT / 'recipes/swift-optionals.json').read_text())
        rows = recipe_rows(recipe)
        self.assertEqual(len(rows), 412)
        self.assertTrue(all(set(r) == {'name', 'owner'} for r in rows))

    def test_no_constructor_requests_is_valid_and_duplicates_still_fail(self):
        self.assertEqual(recipe_rows(dict(schema=1,records=[])), [])
        row=dict(name='Si',owner='/usr/lib/swift/libswiftCore.dylib')
        with self.assertRaisesRegex(Refusal,'duplicate'):
            recipe_rows(dict(schema=1,records=[row,row]))

    @unittest.skipUnless(os.environ.get('CACHE_TOOLCHAIN'), 'source-built dyld toolchain not selected')
    def test_table_reservations_cover_emitted_keys_duplicates_and_separate_families(self):
        original = {(1, 2): [0x100, 0x200], tuple(range(64)): [0x300]}
        metadata = {tuple(1000 + i * 64 + j for j in range(i % 64 + 1)): [0x400 + i]
                    for i in range(257)}
        witnesses = {(20000 + i, 30000 + i): [0x1000 + i] for i in range(129)}
        metatypes = {(40000, 50000 + i): [0x2000 + i] for i in range(33)}
        catalog = dict(records=[dict(key=k) for k in metadata] + [dict(key=(1, 2))] +
                       [dict(key=k, record_kind='metatype') for k in metatypes],
                       witnesses=[dict(key=k, record_kind='protocol-witness') for k in witnesses])
        with tempfile.TemporaryDirectory() as tmp:
            sizes = table_reservations(catalog, original, Path(tmp) / 'sizing')
            for kind, entries in [('metadata', {**original, **metadata}),
                                  ('witness', witnesses), ('metatype', metatypes)]:
                data, _ = emit_table(entries, Path(tmp) / kind)
                with self.subTest(kind=kind):
                    self.assertGreaterEqual(sizes[kind], len(data))
                    self.assertLess(sizes[kind], 2048 * len(entries))
        # Legacy Optional catalogs still reserve two-pointer keys.
        with tempfile.TemporaryDirectory() as tmp:
            sizes = table_reservations(dict(records=[dict(name='SiSg')]), original, Path(tmp))
            data, _ = emit_table({**original, (900, 901): [902]}, Path(tmp) / 'table')
            self.assertGreaterEqual(sizes['metadata'], len(data))
            self.assertEqual(set(sizes), {'metadata'})

    @unittest.skipUnless(os.environ.get('CACHE_TOOLCHAIN'), 'source-built dyld toolchain not selected')
    def test_apple_lookup_roundtrip_retains_duplicate_order_and_long_keys(self):
        entries = {(1, 2): [0x100, 0x200], tuple(range(64)): [0x300], (9,): [0x400]}
        with tempfile.TemporaryDirectory() as tmp:
            data, report = emit_table(entries, Path(tmp) / 'table')
        self.assertEqual(report['keys'], 3)
        self.assertEqual(report['values'], 4)
        self.assertEqual(report['bytes'], len(data))


if __name__ == '__main__':
    unittest.main()
