import copy
from pathlib import Path
import struct
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.lookup_tables import serialize_patch_arrays
from dyld_rebuild.patch_graph import metadata_word, transform
from dyld_rebuild.patches import PatchTableV4


OLD = [('/a', 0x100000000), ('/b', 0x100002000), ('/client', 0x100004000)]
FINAL = [('/a', 0x100010000), OLD[1], OLD[2], ('/a-old', 0x100020000)]


def fixture():
    def packed(fmt, rows):
        return b''.join(struct.pack(fmt, *row) for row in rows)
    return {
        'images': packed('<4I', [(0, 2, 0, 2), (2, 2, 2, 1), (4, 0, 3, 0)]),
        'exports': packed('<2I', [(0x100, 0), (0x180, 3), (0x20, 12)]),
        'clients': packed('<3I', [(0, 0, 1), (2, 1, 1), (0, 2, 1), (2, 3, 1)]),
        'client_exports': packed('<3I', [(0, 0, 1), (0, 1, 1), (2, 2, 1), (2, 3, 1)]),
        'locations': packed('<2I', [(0x200, 0), (0x1000, 16 << 9), (0x2100, 0), (0x1100, 256)]),
        'got_clients': packed('<2I', [(0, 1), (1, 0), (1, 0)]),
        'got_exports': packed('<3I', [(1, 0, 1)]),
        'got_locations': packed('<QII', [(0x8000, 0, 0)]),
        'names': b'_a\0_missing\0_b\0\0',
    }


def changed():
    remaps = {0: dict(target_index=3, implementation=FINAL[3][1] + 0x100,
                      symbol='_a', export_kind=0), 1: None}
    uses = [dict(target_index=1, implementation=OLD[1][1] + 0x20, symbol='_b', export_kind=0,
                 client_index=0, location=FINAL[0][1] + 0x180, addend=16, weak_import=False)]
    return remaps, uses


class PatchGraphTests(unittest.TestCase):
    def test_unchanged_graph_is_byte_identical(self):
        arrays = fixture()
        actual, stats = transform(arrays, OLD, OLD, set(), {}, [])
        self.assertEqual(actual, arrays)
        self.assertEqual(stats['retired_client_locations'], 0)

    def test_reexport_moves_owner_and_replaces_client_imports(self):
        remaps, uses = changed()
        actual, stats = transform(fixture(), OLD, FINAL, {0}, remaps, uses)
        blob, _ = serialize_patch_arrays(actual, 0x100030000, len(FINAL))
        table = PatchTableV4(blob, 0x100030000, FINAL, OLD[0][1])
        self.assertEqual(table.image_uses(0), [])
        target_b = table.image_uses(1)
        self.assertEqual([(r['client_index'], r['location'], r['addend'], r['weak_import']) for r in target_b],
                         [(0, FINAL[0][1] + 0x180, 16, False), (2, OLD[2][1] + 0x1100, 0, True)])
        moved = table.image_uses(3)
        self.assertEqual(len(moved), 1)
        self.assertEqual((moved[0]['implementation'], moved[0]['location'], moved[0]['addend']),
                         (FINAL[3][1] + 0x100, OLD[2][1] + 0x1000, 16))
        self.assertEqual(stats['retired_client_locations'], 2)
        self.assertEqual(stats['missing_locations'], 1)
        self.assertEqual(stats['migrated_locations'], 1)
        self.assertEqual(stats['final_counts']['got_locations'], 0)

    def test_missing_or_unused_resolution_refused(self):
        for kind in ('missing', 'extra'):
            remaps, uses = changed()
            if kind == 'missing':
                remaps.pop(1)
            else:
                remaps[2] = remaps[0]
            with self.subTest(kind=kind), self.assertRaises(Refusal):
                transform(fixture(), OLD, FINAL, {0}, remaps, uses)

    def test_wrong_owner_offset_kind_and_duplicate_location_refused(self):
        for kind in ('client', 'target', 'location', 'kind', 'duplicate', 'negative'):
            remaps, uses = changed()
            if kind == 'client': uses[0]['client_index'] = 2
            if kind == 'target': uses[0]['target_index'] = 4
            if kind == 'location': uses[0]['location'] = FINAL[0][1] - 1
            if kind == 'kind': uses[0]['export_kind'] = 8
            if kind == 'duplicate': uses.append(copy.deepcopy(uses[0]))
            if kind == 'negative': uses[0]['implementation'] = 0
            with self.subTest(kind=kind), self.assertRaises(Refusal):
                transform(fixture(), OLD, FINAL, {0}, remaps, uses)

    def test_graph_contract_and_metadata_overflow_refused(self):
        remaps, uses = changed()
        with self.assertRaisesRegex(Refusal, 'changed headers'):
            transform(fixture(), OLD, FINAL, set(), remaps, uses)
        altered = list(FINAL)
        altered[1] = ('/different', OLD[1][1])
        with self.assertRaisesRegex(Refusal, 'identities'):
            transform(fixture(), OLD, altered, {0}, remaps, uses)
        for addend, weak, high in ((-1, False, 0), (1 << 23, False, 0), (0, 1, 0), (0, False, 3)):
            with self.subTest(addend=addend, weak=weak, high=high), self.assertRaises(Refusal):
                metadata_word(addend=addend, weak_import=weak, high8=high)
        self.assertEqual(PatchTableV4.metadata(metadata_word(addend=42, weak_import=True, high8=254)),
                         dict(addend=42, weak_import=True, high8=254))


if __name__ == '__main__':
    unittest.main()
