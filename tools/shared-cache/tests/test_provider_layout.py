import hashlib
import json
from pathlib import Path
import struct
import runpy
import sys
from types import SimpleNamespace
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.provider_identity import normalize
from dyld_rebuild.provider_layout import (Provider, Segment, classic_rebases, decode_split, file_geometry,
    image_features, pack_fixups, place_uniform, split_constraints, v2_plan)


def fixture():
    segments = [Segment(0, '__TEXT', 32, 0, 4096, 0, 4096, 5, 5),
                Segment(1, '__DATA', 104, 4096, 4096, 4096, 4096, 3, 3),
                Segment(2, '__LINKEDIT', 176, 8192, 4096, 8192, 4096, 1, 1)]
    image = SimpleNamespace(segments=segments, fixup_fields=[4352], base=0,
                            split={'format':'absent','entries':[]}, data=bytes(12288))
    def segment(address, size=1):
        matches = [s for s in segments if s.address <= address and address + size <= s.address+s.size]
        if len(matches)!=1: raise Refusal('fixture unmapped address')
        return matches[0]
    image.segment = segment
    image.file_offset = lambda address, size=1: segment(address,size).file_offset + address-segment(address,size).address
    return image


class LayoutTests(unittest.TestCase):
    def test_header_provider_and_slide_signature_regions_do_not_overlap(self):
        shape = file_geometry(fixture(), 'test')
        self.assertEqual(shape['provider_header_file_offset'],16384)
        self.assertLessEqual(shape['table_end'],4096)
        self.assertEqual(shape['mapping_count'],3)
        self.assertEqual(shape['mappings'][0]['size'],20480)
        slide=shape['mappings'][1]['slide_info']
        self.assertEqual(slide['file_offset'],shape['slide_info_start'])
        self.assertEqual(slide['size'],42)
        last=shape['mappings'][-1]
        self.assertGreaterEqual(shape['signature']['offset'],slide['file_offset']+slide['size'])
        self.assertEqual(last['file_offset']+last['size'],shape['signature']['offset'])
        self.assertEqual(shape['signature']['file_size'],shape['signature']['offset']+shape['signature']['size'])

    def test_macos27_header_moves_tables_by_sixteen_bytes(self):
        old=file_geometry(fixture(),'test')
        new=file_geometry(fixture(),'test',header_size=568)
        self.assertEqual((new['cache_header_size'],new['mapping_offset']),(568,568))
        self.assertEqual(new['slide_mapping_offset'],old['slide_mapping_offset']+16)
        self.assertEqual(new['table_end'],old['table_end']+16)
        self.assertEqual(new['image_tables']['images_offset'],old['image_tables']['images_offset']+16)
        with self.assertRaises(Refusal):file_geometry(fixture(),'test',header_size=560)

    def test_full_rosetta_image_lists_and_pool_fit_before_provider_header(self):
        paths=[f'/{i:04d}/'+'a'*77+('b' if i<1911 else '') for i in range(3615)]
        shape=file_geometry(fixture(),'test',image_paths=paths)
        table=shape['image_tables']
        self.assertEqual(table['count'],3615)
        self.assertEqual(table['string_pool_size'],305571)
        self.assertEqual(shape['prefix_size'],0x84000)
        self.assertLessEqual(table['used_end'],shape['provider_header_file_offset'])
        self.assertEqual(table['images_text_offset']-table['images_offset'],3615*32)
        self.assertEqual(table['string_pool_offset']-table['images_text_offset'],3615*32)
        self.assertEqual(len(table['path_offsets']),3615)
        with self.assertRaises(Refusal):file_geometry(fixture(),'test',prefix=16384,image_paths=paths)

    def test_no_header_collision_or_ninth_mapping(self):
        with self.assertRaises(Refusal):file_geometry(fixture(),'test',prefix=1024)
        image=fixture();image.segments=image.segments*3
        with self.assertRaises(Refusal):file_geometry(image,'test')

    def test_first_fit_preserves_occupied_vm_intervals(self):
        image=fixture();shape=file_geometry(image,'test')
        placed=place_uniform(image,shape,[(0x10000,0x20000,'old mapping')],0x10000,0x100000)
        self.assertEqual(placed['cache_header_address'],0x20000)
        self.assertEqual(placed['provider_header_address'],0x24000)
        self.assertEqual(placed['split_validation']['changed_code_references'],0)
        self.assertEqual(placed['mappings'][0]['file_offset'],0)

    def test_header_prefix_collision_is_not_ignored(self):
        image=fixture();shape=file_geometry(image,'test')
        p=place_uniform(image,shape,[(0x10000,0x11000,'header-only collision')],0x10000,0x100000)
        self.assertEqual(p['cache_header_address'],0x11000)

    def test_shared_region_and_max_slide_bounds_refuse(self):
        image=fixture();shape=file_geometry(image,'test')
        with self.assertRaises(Refusal):place_uniform(image,shape,[],0x10000,0x15000)
        with self.assertRaises(Refusal):place_uniform(image,shape,[],0x10000,0x20000,0x10000)
        with self.assertRaises(Refusal):place_uniform(image,shape,[(1,1,'empty')],0x10000,0x100000)

    def test_uniform_slide_preserves_positive_negative_and_sparse_relative_values(self):
        for start,target in [(0x7ffb06568000,0x7ffb41532000),(0x2000,0x1000),(0x1000,0x7ffff000)]:
            delta=target-start
            for slide in (-0x300000,0x7ff800000000):
                self.assertEqual((target+slide)-(start+slide),delta)
        image=fixture()
        with self.assertRaises(Refusal):split_constraints(image,[0,4096,0])

    def test_v2_chain_page_membership_and_empty_pages(self):
        p=v2_plan([0x1004,0x1080,0x2ff8],0x1000,8192)
        self.assertEqual(p['page_starts'],[1,1022])
        self.assertEqual(p['fields'],3)
        self.assertEqual(v2_plan([],0x1000,8192)['page_starts'],[0x4000,0x4000])

    def test_v2_rejects_bad_fields(self):
        for fields in ([0x1001],[0x1ffc],[0x1000,0x1000],[0x1000,0x1004],[0x3000]):
            with self.subTest(fields=fields),self.assertRaises(Refusal):v2_plan(fields,0x1000,8192)

    def test_classic_rebase_state_repeat_and_target(self):
        image=fixture();data=bytearray(image.data);struct.pack_into('<QQ',data,4096+128,0x100,0x200);image.data=data
        # type pointer, segment1 offset128, two consecutive rebases, DONE
        rows=classic_rebases(b'\x11\x21\x80\x01\x52\0',image)
        self.assertEqual(rows,{4224:0x100,4232:0x200})
        for bad in (b'\x11\x90',b'\x11\x23\0\x51\0',b'\x12\x21\0\x51\0',b'\x11\x21\xff\xff\x03\x51\0'):
            with self.subTest(bad=bad),self.assertRaises(Refusal):classic_rebases(bad,image)


    def test_lossless_compact_fixup_rows(self):
        plan={'pointer_fixups':[{'kind':'rebase','source_address':4096,'source_file_offset':100,
            'file_offset':200,'address':0x7ff800001000,'mapping_index':1,'source_target':8192,'target':0x7ff800002000},
            {'kind':'bind','source_address':4104,'source_file_offset':108,'file_offset':208,'address':0x7ff800001008,
             'mapping_index':1,'binding':{'symbol':'_foo'},'resolution':{'provider':'/lib'},'target':0x7ff800003000,
             'target_policy':'stub'}]}
        pack_fixups(plan);f=plan['pointer_fixups']
        self.assertEqual(dict(zip(f['rebase_columns'],f['rebase_rows'][0]))['target'],0x7ff800002000)
        self.assertEqual(f['bindings'][f['bind_rows'][0][-1]]['binding']['symbol'],'_foo')




if __name__=='__main__':unittest.main()
