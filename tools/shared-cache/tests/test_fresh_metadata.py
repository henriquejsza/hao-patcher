import importlib.util
from pathlib import Path
import struct
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from dyld_rebuild import codesign
from dyld_rebuild.exports import Refusal
from dyld_rebuild.slides import SlideInfoV2

spec = importlib.util.spec_from_file_location('assemble_cache', ROOT / 'tools/assemble-cache.py')
assembler = importlib.util.module_from_spec(spec)
spec.loader.exec_module(assembler)
BASE = 0x7ff800000000
RECORDS = [dict(path='/fixture', address=BASE, mtime=0, inode=0, uuid='11' * 16, text_size=4096)]


def fixture():
    source = bytearray(8192)
    source[:16] = b'dyld_v1  x86_64\0'
    struct.pack_into('<I', source, 16, 552)
    struct.pack_into('<QQ', source, 40, 8192, 16384)
    struct.pack_into('<Q', source, 560, 4096)
    source += codesign.emit(source, 8192, 'fixture', 4096)
    family = SimpleNamespace(main=SimpleNamespace(
        data=source, mapping_offset=552, mappings=[SimpleNamespace(address=BASE)]))
    mappings = [dict(address=BASE + 0x10000 + i * 8192, size=8192,
                     file_offset=i * 8192, maximum=protection, initial=protection, flags=0)
                for i, protection in enumerate((5, 3, 1))]
    layout = dict(mappings=mappings, prefix_size=8192,
                  swift_metadata=dict(address=mappings[1]['address'], reserve=8192),
                  slide_info=dict(address=mappings[2]['address'], reserve=4096))
    return family, layout


class FreshMetadataTests(unittest.TestCase):
    def test_runtime_code_and_configuration_survive_signing_in_separate_protections(self):
        family,layout=fixture();rx,rw,_=layout['mappings']
        layout['swift_runtime_code']=dict(address=rx['address']+4096,reserve=4096)
        layout['swift_runtime_data']=dict(address=rw['address'],reserve=4096)
        code=b'\x55\x48\x89\xe5\x5d\xc3'
        fields=[dict(address=rw['address']+8*i,target=BASE+0x4000+8*i) for i in range(6)]
        blobs=[(dict(reservation='swift_runtime_code',address=rx['address']+4096),code),
               (dict(reservation='swift_runtime_data',address=rw['address']),bytes(48))]
        data,_=assembler.fresh_metadata(family,layout,RECORDS,blobs,fields)
        codesign.inspect(data)
        self.assertEqual(data[4096:4096+len(code)],code)
        self.assertEqual((rx['initial'],rw['initial']),(5,3))
        table=struct.unpack_from('<I',data,312)[0]
        offset,size=struct.unpack_from('<QQ',data,table+56+24)
        slide=SlideInfoV2(data[offset:offset+size],data,rw['file_offset'],rw['size'])
        decoded=slide.page(0)
        for i,field in enumerate(fields):
            self.assertEqual((decoded[i*8]&0xff0000ffffffffff)+BASE,field['target'])

    def test_packed_pointer_survives_assembly_signing_and_runtime_slide(self):
        family, layout = fixture()
        rw = layout['mappings'][1]
        offsets = (4, 20, 4084, 4100)
        fields = [dict(address=rw['address'] + offset, target=BASE + 0x5000 + index * 8)
                  for index, offset in enumerate(offsets)]
        payload = bytearray(b'\x73' * rw['size'])
        for offset in offsets:
            payload[offset:offset + 8] = bytes(8)
        blob = dict(reservation='swift_metadata', address=rw['address'])
        data, _ = assembler.fresh_metadata(family, layout, RECORDS, [(blob, payload)], fields)
        codesign.inspect(data)
        slide_table = struct.unpack_from('<I', data, 312)[0]
        slide_offset, slide_size = struct.unpack_from('<QQ', data, slide_table + 56 + 24)
        slide = SlideInfoV2(data[slide_offset:slide_offset + slide_size], data,
                            rw['file_offset'], rw['size'])
        decoded = {offset: raw for page in range(2) for offset, raw in slide.page(page).items()}
        self.assertEqual(set(decoded), set(offsets))
        for offset, row in zip(offsets, fields):
            # Kernel-equivalent value decoding, independent of SlideInfoV2.decode.
            for runtime_slide in (0, 4096, 0x19800000):
                actual = (decoded[offset] & 0xff0000ffffffffff) + BASE + runtime_slide
                self.assertEqual(actual, row['target'] + runtime_slide)
        touched = {i for offset in offsets for i in range(offset, offset + 8)}
        self.assertTrue(all(data[rw['file_offset'] + i] == value
                            for i, value in enumerate(payload) if i not in touched))

    def test_pointer_must_still_fit_one_slide_page(self):
        for offset in (2, 4092, 8192):
            family, layout = fixture()
            fields = [dict(address=layout['mappings'][1]['address'] + offset, target=BASE + 4096)]
            with self.subTest(offset=offset), self.assertRaises(Refusal):
                assembler.fresh_metadata(family, layout, RECORDS, [], fields)


if __name__ == '__main__':
    unittest.main()
