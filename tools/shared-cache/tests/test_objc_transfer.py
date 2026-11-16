import hashlib
import json
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from dyld_rebuild.exports import Dependency, Image, Refusal, span
from dyld_rebuild.objc_transfer import CachedReader, DiskReader, Reader, project_ivar_growth, sleb, transfer_entries


class MemoryReader(Reader):
    def __init__(self, data, selector_base=None):
        self.data = data
        self.selector_base = selector_base
    def read(self, address, size):
        return span(self.data, address, size)
    def ptr(self, address):
        return self.number(address)


class TransferTests(unittest.TestCase):
    def test_order_and_loaded_image_identity_preserved(self):
        old = [{'address': 100, 'image_index': 2036}, {'address': 200, 'image_index': 3054},
               {'address': 300, 'image_index': 68}]
        new = transfer_entries(old, [200, 100], [{'address': 900, 'image_index': None}], 'NEW:Old')
        self.assertEqual([(r['address'], r['image_index']) for r in new],
                         [(100, 2036), (200, 3054), (900, 'NEW:Old')])
        # Both duplicate-named Portrait categories stay distinct and conditional.
        def lookup(loaded):
            return next(r['address'] for r in new if r['image_index'] in loaded)
        self.assertEqual(lookup({2036, 3054, 'NEW:Old'}), 100)
        self.assertEqual(lookup({3054, 'NEW:Old'}), 200)
        self.assertEqual(lookup({'NEW:Old'}), 900)
        self.assertEqual(old[-1]['address'], 300)

    def test_replacement_without_base_list_keeps_categories_only(self):
        # 26B131: WiFiAwareDatapathInfo in OCLP's WiFiPeerToPeer has no instance methods; one cache category attaches.
        old = [{'address': 100, 'image_index': 2036}, {'address': 300, 'image_index': 68}]
        new = transfer_entries(old, [100], [], 'NEW:WiFiPeerToPeer')
        self.assertEqual([(r['address'], r['image_index'], r['origin']) for r in new], [(100, 2036, 'preserved_category')])
        with self.assertRaises(Refusal):
            transfer_entries(old, [100], [{'address': 1}, {'address': 2}], 'NEW:x')

    def test_absent_or_duplicate_transfer_refused(self):
        source = [{'address': 10, 'image_index': 1}, {'address': 20, 'image_index': 2}]
        for incoming in ([30], [10, 10]):
            with self.subTest(incoming=incoming), self.assertRaises(Refusal):
                transfer_entries(source, incoming, [], 3)
        with self.assertRaises(Refusal):
            transfer_entries(source + source[:1], [10], [], 3)
        with self.assertRaises(Refusal):
            transfer_entries(source, [], [], 3)

    def test_already_merged_replacement_refused(self):
        with self.assertRaises(Refusal):
            transfer_entries([{'address': 1}, {'address': 2}], [1],
                             [{'address': 3}, {'address': 4}], 0)

    def test_relative_list_signed_delta_and_duplicate_detection(self):
        data = bytearray(256)
        struct.pack_into('<II', data, 128, 8, 2)
        for field, target, image in [(136, 32, 341), (144, 80, 68)]:
            struct.pack_into('<Q', data, field, (((target-field) & ((1<<48)-1)) << 16) | image)
        reader = MemoryReader(data)
        self.assertEqual(reader.lists(129), [{'address': 32, 'image_index': 341}, {'address': 80, 'image_index': 68}])
        struct.pack_into('<Q', data, 144, (((32-144) & ((1<<48)-1)) << 16) | 68)
        with self.assertRaises(Refusal): reader.lists(129)

    def test_relative_list_bad_header_refused(self):
        data = bytearray(32); struct.pack_into('<II', data, 8, 16, 1)
        with self.assertRaises(Refusal): MemoryReader(data).lists(9)

    def test_small_disk_selector_indirect_even_with_extractor_direct_flag(self):
        data = bytearray(256)
        struct.pack_into('<IIiii', data, 16, 0xc000000c, 1, 128-24, 200-28, 220-32)
        struct.pack_into('<Q', data, 128, 160)
        data[160:164] = b'foo\0'; data[200:205] = b'v16@\0'
        row = MemoryReader(data).methods(16)['entries'][0]
        self.assertEqual(row, {'selector': 'foo', 'types': 'v16@', 'imp': '0xdc'})

    def test_cached_direct_selector_uses_selector_base(self):
        data = bytearray(256)
        struct.pack_into('<IIiii', data, 16, 0xc000000f, 1, 32, 200-28, 220-32)
        data[160:164] = b'foo\0'; data[200:205] = b'v16@\0'
        self.assertEqual(MemoryReader(data, 128).methods(16)['entries'][0]['selector'], 'foo')
        struct.pack_into('<I', data, 16, 0x8000000c)
        with self.assertRaises(Refusal): MemoryReader(data, 128).methods(16)

    def test_big_method_and_unsupported_flags(self):
        data = bytearray(256)
        struct.pack_into('<IIQQQ', data, 16, 24, 1, 160, 200, 220)
        data[160:164] = b'foo\0'; data[200:205] = b'v16@\0'
        self.assertEqual(MemoryReader(data).methods(16)['entries'][0]['selector'], 'foo')
        for flags in (0x20000018, 20, 0x40000018):
            struct.pack_into('<I', data, 16, flags)
            with self.subTest(flags=flags), self.assertRaises(Refusal): MemoryReader(data).methods(16)

    def test_v2_pointer_strips_chain_delta(self):
        raw = (3 << 51) | 0x1200
        reader = object.__new__(CachedReader)
        reader.family = SimpleNamespace(read=lambda a, n: struct.pack('<Q', raw)[:n])
        reader.slides = [(0x1000, 0x2000, 0x00ffff0000000000, 0x70000000)]
        self.assertEqual(reader.ptr(0x1100), 0x70001200)
        reader.family.read = lambda a, n: struct.pack('<Q', 3 << 51)[:n]
        self.assertEqual(reader.ptr(0x1100), 0)

    def chain_reader(self):
        reader = object.__new__(DiskReader)
        reader.base = 0x1000
        reader.segments = [(0x1000, 4096, 0, 4096)]
        reader.image = Image('/self', [Dependency('/dep', 0xc)], {})
        reader.binds, reader.rebases = {}, {}
        reader.data = bytearray(4096)
        struct.pack_into('<QQ', reader.data, 0x100, (2 << 51) | 0x200, (1 << 63) | (3 << 24))
        payload = bytearray(128)
        struct.pack_into('<7I', payload, 0, 0, 32, 64, 68, 1, 1, 0)
        struct.pack_into('<II', payload, 32, 1, 8)
        struct.pack_into('<IHHQIHH', payload, 40, 24, 4096, 6, 0, 0, 1, 0x100)
        struct.pack_into('<I', payload, 64, 1)
        payload[68:73] = b'_foo\0'
        return reader, payload

    def test_chained_rebase_and_symbolic_bind(self):
        reader, payload = self.chain_reader(); reader._chained(payload)
        self.assertEqual(reader.ptr(0x1100), 0x1200)
        self.assertEqual(reader.reference(0x1108), {'symbol': '_foo', 'provider': '/dep', 'weak_import': False, 'addend': 3})
        with self.assertRaises(Refusal): reader.ptr(0x1108)

    def test_chained_reserved_bits_and_unknown_format_refused(self):
        for field, fmt, value in [(46, '<H', 3), (64, '<I', 2), (62, '<H', 0x8000)]:
            reader, payload = self.chain_reader(); struct.pack_into(fmt, payload, field, value)
            with self.subTest(field=field), self.assertRaises(Refusal): reader._chained(payload)
        reader, payload = self.chain_reader()
        struct.pack_into('<Q', reader.data, 0x100, 1 << 44)
        with self.assertRaises(Refusal): reader._chained(payload)

    def test_chained_absolute_and_relative_targets_retain_high_byte(self):
        for fmt, expected in [(2, 0xab00000000000200), (6, 0xab00000000001200)]:
            reader, payload = self.chain_reader()
            struct.pack_into('<H', payload, 46, fmt)
            struct.pack_into('<Q', reader.data, 0x100, (2 << 51) | (0xab << 36) | 0x200)
            reader._chained(payload)
            self.assertEqual(reader.ptr(0x1100), expected)

    def test_chained_import_addend_combines_with_pointer_addend(self):
        for fmt in (2, 3):
            reader, payload = self.chain_reader()
            width = 8 if fmt == 2 else 16
            struct.pack_into('<II', payload, 12, 64 + width, 1)
            struct.pack_into('<I', payload, 20, fmt)
            struct.pack_into('<Ii' if fmt == 2 else '<Qq', payload, 64, 1, -17)
            payload[64 + width:69 + width] = b'_foo\0'
            reader._chained(payload)
            self.assertEqual(reader.reference(0x1108)['addend'], -14)

    def test_classic_bind_and_negative_addend(self):
        reader, _ = self.chain_reader()
        # ordinal1, weak symbol, pointer type, addend -1, segment0 offset128, bind, done
        reader._bind_stream(b'\x11\x41_foo\0\x51\x60\x7f\x70\x80\x01\x90\0')
        self.assertEqual(reader.binds[0x1080], {'symbol': '_foo', 'provider': '/dep', 'addend': -1, 'weak_import': True})
        with self.assertRaises(Refusal): reader._bind_stream(b'\xd0')
        self.assertEqual(sleb(b'\x7f', 0), (-1, 1))
        with self.assertRaises(Refusal): sleb(b'\x80', 0)

    def test_superclass_growth_preserves_alignment_without_shrinking(self):
        info = {'data_flags': 0, 'instance_start': 32, 'instance_size': 52,
                'ivars': [{'name': '_label', 'offset': 40, 'alignment': 3}]}
        self.assertEqual(project_ivar_growth(info, 40),
                         {'delta': 8, 'instance_start': 40, 'instance_size': 60, 'ivar_offsets': {'_label': 48}})
        self.assertEqual(project_ivar_growth(info, 33)['delta'], 8)
        self.assertEqual(project_ivar_growth(info, 24)['delta'], 0)
        with self.assertRaises(Refusal): project_ivar_growth(dict(info, data_flags=2), 40)
        # Swift class whose superclass keeps its size: nothing to change.
        self.assertEqual(project_ivar_growth(dict(info, data_flags=2), 32)['delta'], 0)
        with self.assertRaises(Refusal): project_ivar_growth(info, 2**32)

    def test_truncated_method_list_and_string_refused(self):
        data = bytearray(32); struct.pack_into('<II', data, 16, 24, 100)
        with self.assertRaises(Refusal): MemoryReader(data).methods(16)
        with self.assertRaises(Refusal): MemoryReader(b'abc').string(1)




if __name__ == '__main__':
    unittest.main()
