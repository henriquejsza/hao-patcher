"""Refusal/decoding tests; full real Apple outputs receive integration oracles."""
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest
import os
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from dyld_rebuild.loader_generation import bind_target, load_root_manifest, prepare_adapter, read_set, verify_file, control_source_paths, validate_control_report, sha, classic_targets, disk_image, TREAT_AS_WEAK
from dyld_rebuild.cache_exports import export_trie, CacheDependency
from dyld_rebuild.exports import Image
from dyld_rebuild.lookup_tables import uleb_bytes


def minimal_set():
    data = bytearray(84 + 448 + 3)
    struct.pack_into('<5I', data, 0, 0x73703464, 0x9593b355, len(data), 1, 80)
    struct.pack_into('<I', data, 80, 84)
    struct.pack_into('<IHH', data, 84, 0x6c347964, 3, 0)
    struct.pack_into('<H', data, 84 + 32, 448)
    data[-3:] = b'/x\0'
    return data


class LoaderGenerationTests(unittest.TestCase):
    def test_27_bitfield_regions_after_five_flags(self):
        """26B131's PrebuiltLoader: +0x2c bit 4 is the TLV pre-keyed flag and regionsCount is 11 bits from bit 5."""
        data = minimal_set()
        data += bytes(32)
        struct.pack_into('<I', data, 8, len(data))
        loader = 84
        struct.pack_into('<HH', data, loader + 0x2c, (2 << 5) | 0x10 | 1, len(data) - 32 - loader)
        row = read_set(data, 1, app=False)['loaders'][0]
        self.assertEqual(len(row['regions']), 2)
        self.assertEqual(row['properties'], 0x11)
        with self.assertRaises(ValueError):    # dyld-1378's 12-bit field would read 4 regions past the end
            struct.pack_into('<H', data, loader + 0x2c, (4 << 5) | 1)
            read_set(data, 1, app=False)

    def test_classic_uint64_wrap_vm_bounds_and_target_changes(self):
        image = Image('/main', [CacheDependency('/lib', 0xc)], {})
        # Address advance wraps from 16 to 8; all actual writes remain bounded.
        stream = b'\x11\x40symbol\0\x70\x10\x80' + uleb_bytes(2**64 - 8) + b'\x90\x90\x60\x01\x90\0'
        rows = classic_targets(stream, image, [(0x1000, 32, 0, 8)], 'bind')
        self.assertEqual([(r.symbol, r.ordinal, r.addend) for r in rows], [('symbol', 1, 0), ('symbol', 1, 1)])
        self.assertEqual(classic_targets(stream[:-1], image, [(0x1000, 32, 0, 8)], 'bind'), rows)
        for bad in (b'\x11\x40x\0\x70\x20\x90\0', b'\x11\x40x\0\x71\0\x90\0', b'\xd0', b'\x90\0'):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                classic_targets(bad, image, [(0x1000, 32, 0, 8)], 'bind')
        lazy = b'\x11\x40x\0\x70\0\x90\0\x70\x08\x90\0'
        self.assertEqual(len(classic_targets(lazy, image, [(0, 16, 0, 16)], 'lazy')), 2)

    def test_duplicate_missing_path_strings_are_preserved(self):
        data = minimal_set()
        start = len(data)
        data += b'/missing\0/missing\0'
        struct.pack_into('<I', data, 8, len(data))
        struct.pack_into('<II', data, 32, 2, start)
        self.assertEqual(read_set(data, 1, app=False)['must_be_missing_paths'], ['/missing', '/missing'])
        struct.pack_into('<I', data, 32, 3)
        with self.assertRaises(ValueError): read_set(data, 1, app=False)

    def test_long_export_names_and_resource_refusals(self):
        def trie(name):
            offset = len(name) + 5
            while True:
                root = b'\0\1' + name + b'\0' + uleb_bytes(offset)
                if len(root) == offset: return root + b'\2\0\1\0'
                offset = len(root)
        self.assertIn('S' * 5158, export_trie(trie(b'S' * 5158)))
        self.assertIn('S' * 65535, export_trie(trie(b'S' * 65535)))
        with self.assertRaises(ValueError): export_trie(trie(b'S' * 65536))
        with self.assertRaises(ValueError): export_trie(b'\0\1a\0\0')

    def test_fat_slice_modern_flags_and_main_weak_targets(self):
        name = b'/library\0'
        width = (28 + len(name) + 7) & ~7
        use = bytearray(width)
        struct.pack_into('<7I', use, 0, 0xc, width, 28, 0x1a741800, 0, 0, 9)
        use[28:28 + len(name)] = name
        # Empty LC_DYLD_INFO must not overwrite the main executable filetype.
        info = struct.pack('<12I', 0x80000022, 48, *([0] * 10))
        offset = 32 + width + 48 + 16
        chained = struct.pack('<4I', 0x80000034, 16, offset, 28)
        thin = struct.pack('<8I', 0xfeedfacf, 0x1000007, 3, 2, 3, offset - 32, 0x8000, 0) + use + info + chained
        thin += struct.pack('<7I', 0, 28, 28, 28, 0, 1, 0)
        fat = struct.pack('>7I', 0xcafebabe, 1, 0x1000007, 3, 4096, len(thin), 12) + bytes(4096 - 28) + thin
        image, imports, overrides = disk_image(fat, '/main', main=True)
        self.assertTrue(image.dependencies[0].weak)
        self.assertEqual([r.symbol for r in imports], list(TREAT_AS_WEAK))
        self.assertEqual(overrides, [])
        changed = bytearray(fat)
        struct.pack_into('<I', changed, 4096 + 32 + 24, 16)
        with self.assertRaises(ValueError): disk_image(changed, '/main', main=True)
        changed = bytearray(fat)
        struct.pack_into('<I', changed, 4096 + 4, 0x100000c)
        with self.assertRaises(ValueError): disk_image(changed, '/main', main=True)

    def test_minimal_cached_set(self):
        parsed = read_set(minimal_set(), 1, app=False)
        self.assertEqual(parsed['loaders'][0]['path'], '/x')
        self.assertEqual(parsed['loaders'][0]['binds'], [])

    def test_set_refusals(self):
        for at, fmt, value in ((4, '<I', 0), (8, '<I', 4), (12, '<I', 0), (16, '<I', 0),
                               (80, '<I', 81), (84 + 6, '<H', 0x8000),
                               (84 + 32, '<H', 1), (84 + 42, '<H', 65535),
                               (84 + 52, '<I', 1)):
            data = minimal_set()
            struct.pack_into(fmt, data, at, value)
            with self.subTest(at=at, value=value), self.assertRaises(ValueError):
                read_set(data, 1, app=False)
        with self.assertRaises(ValueError):
            read_set(minimal_set()[:-1], 1, app=False)

    def test_bind_target_arithmetic_and_refs(self):
        self.assertEqual(bind_target(0, 1, 1), {'kind': 'image_offset', 'app': False, 'index': 0, 'offset': 0})
        word = (((1 << 38) - 1) << 24) | (255 << 16)
        self.assertEqual(bind_target(word, 1, 1)['offset'], 2**64 - 1)
        self.assertEqual(bind_target(1 << 62, 1, 1), {'kind': 'absolute', 'value': 0})
        for word in (3 << 62, 1, 0x8001):
            with self.subTest(word=word), self.assertRaises(ValueError):
                bind_target(word, 1, 1)




    def test_full_validator_requires_explicit_pins(self):
        result = subprocess.run([sys.executable, str(ROOT / 'tools/loader-generator/validate-full-programs.py')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        for option in ('--cache-manifest', '--input-pins', '--cached-set-sha256', '--closure-report-sha256'):
            self.assertIn(option, result.stderr)


    @unittest.skipUnless(os.environ.get('CACHE_TOOLCHAIN'), 'requires source-built toolchain')
    def test_cache_path_adapter_uses_runtime_identity_and_refuses_drift(self):
        from dyld_rebuild.loader_generation import prepare_cache_path_adapter
        source=(Path(os.environ['CACHE_TOOLCHAIN'])/'source/dyld/DyldProcessConfig.cpp').read_text()
        adapted=prepare_cache_path_adapter(source)
        self.assertIn('return ::dyldOfflineCacheIndexOfPath(dylibPath, dylibIndex);',adapted)
        self.assertIn('return ::dyldOfflineCachePath(dylibIndex);',adapted)
        self.assertIn('return this->addr->hasImagePath(dylibPath, dylibIndex);',adapted)
        with self.assertRaises(ValueError):prepare_cache_path_adapter('changed')
        with self.assertRaises(ValueError):prepare_cache_path_adapter(source+source)

    @unittest.skipUnless(os.environ.get('CACHE_TOOLCHAIN'), 'requires source-built toolchain')
    def test_adapter_refuses_source_drift(self):
        with self.assertRaises(ValueError):
            prepare_adapter('unexpected source')
        source = (Path(os.environ['CACHE_TOOLCHAIN']) / 'source/dyld/JustInTimeLoader.cpp').read_text()
        adapted = prepare_adapter(source)
        self.assertIn('"__OBJC_RO"', adapted)
        self.assertIn('"__OBJC_RW"', adapted)
        self.assertEqual(adapted.count('Global optimization segments appended'), 1)


if __name__ == '__main__':
    unittest.main()
