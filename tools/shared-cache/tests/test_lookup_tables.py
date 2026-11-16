"""Trie boundaries and v4 raw-array refusal/relocation tests."""
import random
from pathlib import Path
import struct
import sys
import unittest
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from dyld_rebuild.cache_exports import path_trie
from dyld_rebuild.lookup_tables import final_aliases, serialize_patch_arrays, split_patch_arrays, uleb_bytes, write_path_trie


def arrays():
    return {'images': struct.pack('<4I', 0, 1, 0, 1), 'exports': struct.pack('<2I', 32, 0),
            'clients': struct.pack('<3I', 0, 0, 1), 'client_exports': struct.pack('<3I', 0, 0, 1),
            'locations': struct.pack('<2I', 256, 0x13fe), 'names': b'_symbol\0',
            'got_clients': struct.pack('<2I', 0, 1), 'got_exports': struct.pack('<3I', 0, 0, 1),
            'got_locations': struct.pack('<QII', 2**40, 0, 0)}


class LookupTableTests(unittest.TestCase):
    def test_terminal_prefix_and_image_zero(self):
        paths = {'/a': 0, '/a/b': 1, '/ab': 2, '/b/c': 3}
        output = write_path_trie(paths, 4)
        self.assertEqual(path_trie(output, 4), paths)
        self.assertEqual(write_path_trie({}, 1), b'\0\0')

    def test_offset_growth_and_determinism(self):
        entries = [(f'/System/Library/LongFramework{i:04d}.framework/Versions/A/LongFramework{i:04d}', i) for i in range(1500)]
        output = write_path_trie(entries, 1500)
        self.assertGreater(len(output), 16384)
        shuffled = entries.copy()
        random.Random(1378).shuffle(shuffled)
        self.assertEqual(write_path_trie(shuffled, 1500), output)
        self.assertEqual(path_trie(output, 1500), dict(entries))

    def test_trie_refusals(self):
        for entries in ([('/a', 0), ('/a', 0)], [('/a', -1)], [('/a', 1)], [('/a', True)],
                        [('relative', 0)], [('/nul\0path', 0)], [('/caf\u00e9', 0)]):
            with self.subTest(entries=entries), self.assertRaises(ValueError):
                write_path_trie(entries, 1)
        with self.assertRaises(ValueError):
            write_path_trie({'/a': 0}, 1, reserve=1)
        with self.assertRaises(ValueError):
            write_path_trie([('/' + 'a' * i, 0) for i in range(1, 515)], 1)
        for data in (b'\0\1A\0\0', b'\0\1\0\0', b'\1\x80\0'):
            with self.subTest(data=data), self.assertRaises(ValueError):
                path_trie(data, 1)

    def test_uleb_boundaries(self):
        self.assertEqual(uleb_bytes(127), b'\x7f')
        self.assertEqual(uleb_bytes(128), b'\x80\1')
        self.assertEqual(uleb_bytes(16384), b'\x80\x80\1')
        for value in (-1, 2**64, True):
            with self.assertRaises(ValueError):
                uleb_bytes(value)

    def test_preserve_aliases_and_indexes(self):
        before = [('/a', 0x1000)]
        after = before + [('/b', 0x2000)]
        self.assertEqual(final_aliases({'/a': 0, '/alias': 0}, before, after), {'/a': 0, '/alias': 0, '/b': 1})
        for after in ([], [('/b', 0x1000)], before + [('/alias', 0x2000)], before + before):
            with self.subTest(after=after), self.assertRaises(ValueError):
                final_aliases({'/a': 0, '/alias': 0}, before, after)

    def test_patch_roundtrip_and_relocation(self):
        data, stats = serialize_patch_arrays(arrays(), 0x1000, 1)
        moved, moved_stats = serialize_patch_arrays(arrays(), 0x100000, 1)
        self.assertEqual(split_patch_arrays(data, 0x1000, 1), arrays())
        self.assertEqual(data[152:], moved[152:])
        self.assertEqual(stats, moved_stats)
        self.assertEqual(stats['locations']['weak_imports'], 1)
        self.assertEqual(stats['locations']['maximum_addend'], 9)
        for index in range(9):
            old = struct.unpack_from('<Q', data, 8 + index * 16)[0]
            new = struct.unpack_from('<Q', moved, 8 + index * 16)[0]
            self.assertEqual(new - old, 0x100000 - 0x1000)

    def test_patch_refusals(self):
        changes = [('exports', struct.pack('<2I', 32, 0xf0000000)),
                   ('exports', struct.pack('<2I', 32, 99)), ('names', b'no-terminator'),
                   ('clients', struct.pack('<3I', 1, 0, 1)),
                   ('client_exports', struct.pack('<3I', 1, 0, 1)),
                   ('locations', struct.pack('<2I', 256, 1)),
                   ('got_locations', struct.pack('<QII', 1, 0, 1)),
                   ('got_exports', struct.pack('<3I', 0, 1, 1))]
        for name, value in changes:
            data = arrays(); data[name] = value
            with self.subTest(name=name), self.assertRaises(ValueError):
                serialize_patch_arrays(data, 0x1000, 1)
        data = arrays(); data.pop('names')
        with self.assertRaises(ValueError): serialize_patch_arrays(data, 0x1000, 1)
        with self.assertRaises(ValueError): serialize_patch_arrays(arrays(), 0x1000, 2)
        with self.assertRaises(ValueError): serialize_patch_arrays(arrays(), 1, 1)
        with self.assertRaises(ValueError): serialize_patch_arrays(arrays(), 2**64 - 8, 1)
        with self.assertRaises(ValueError): serialize_patch_arrays(arrays(), 0x1000, 1, reserve=152)
        blob, _ = serialize_patch_arrays(arrays(), 0x1000, 1)
        for corrupted in (blob[:-1], blob + b'\0', struct.pack('<I', 3) + blob[4:]):
            with self.assertRaises(ValueError): split_patch_arrays(corrupted, 0x1000, 1)


if __name__ == '__main__':
    unittest.main()
