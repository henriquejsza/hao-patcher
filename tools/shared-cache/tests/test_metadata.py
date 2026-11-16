import copy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from dyld_rebuild.metadata import validate,slot_file_offset
from dyld_rebuild.exports import Refusal
from dyld_rebuild.run_metadata import allocate_metadata


class MetadataTests(unittest.TestCase):
    def setUp(self):
        fixture=json.loads((Path(__file__).parent/'fixtures/metadata-geometry.json').read_text())
        self.layout,self.plan=fixture['layout'],fixture['plan']
        self.plan['final_image_paths']=[p['path'] for p in self.plan['providers']]+['/fixture/image/'+str(i) for i in range(self.layout['final_images']-len(self.plan['providers']))]
        rows=self.plan['original_mapping_records']
        rows=rows+[m for p in self.plan['providers'] for m in p['placement']['mappings']]
        maps=[SimpleNamespace(address=m['address'],size=m['size']) for m in rows]
        self.images=[(path,0) for path in self.plan['final_image_paths']]
        indexes={path:i for i,(path,_) in enumerate(self.images)}
        for p in self.plan['providers']:
            self.images[indexes[p['path']]]=(p['path'],p['placement']['provider_header_address'])
        self.family=SimpleNamespace(images=self.images,main=SimpleNamespace(mapping_offset=552,data=bytes(1024)),files=[SimpleNamespace(mappings=maps)]+
                                    [SimpleNamespace(mappings=[]) for _ in range(16)])

    def test_reserved_metadata_fits_without_moving_provider_headers(self):
        check=validate(self.layout,self.family,self.plan)
        self.assertEqual(check['provider_headers_unchanged'],10)
        self.assertLessEqual(check['header_used_end'],0x84000)
        self.assertEqual(slot_file_offset(self.layout,'new_protocol',96),0x8c000)
        for name,size in [('selector_names',8894),('class_names',147),('protocol_names',32),('ro',75464),('rw',25160)]:
            self.assertGreater(slot_file_offset(self.layout,name,size),0)

    def test_witness_layout_has_code_and_data_protections_and_preserves_header_space(self):
        plan=copy.deepcopy(self.plan)
        plan['base_layout']=dict(required_main_text_growth=0)
        plan['main_updates']=dict(final_cache_file_count=len(self.family.files))
        for provider in plan['providers']:provider['import_inventory']={}
        baseline=dict(tables={name:dict(size=4096,entries=[]) for name in ('selector','class','protocol')},
                      selector_base=self.layout['selector_base'],legacy_objc_root=self.layout['legacy_objc_root'])
        inventory=dict(selectors=[],classes=[],protocols=[dict(name='NewProtocol')],method_lists=[],categories=[])
        anchor=plan['shared_region']['start']+0x20000000
        layout,_=allocate_metadata(plan,baseline,inventory,dict(incoming=[]),program_pool_size=4096,cached_size=4096,
            patch_size=4096,atlas_size=4096,swift_code_anchor=anchor,
            swift_sizes=dict(swift_metadata=4096,swift_table=4096,swift_witness_table=4096,swift_metatype_table=4096,
                             swift_runtime_code=8192,swift_runtime_data=4096))
        report=validate(layout,self.family,plan)
        code=layout['swift_runtime_code']['address']
        self.assertLess(abs(code-anchor),1<<31)
        self.assertGreaterEqual(slot_file_offset(layout,'swift_runtime_code',8192),report['header_used_end'])
        self.assertLess(code,layout['mappings'][1]['address'])
        self.assertGreaterEqual(layout['swift_runtime_data']['address'],layout['mappings'][1]['address'])
        layout['swift_runtime_code']['address']=layout['mappings'][0]['address']
        with self.assertRaisesRegex(Refusal,'image lists'):validate(layout,self.family,plan)

    def test_mapping_collision_and_slot_overlap_refused(self):
        changed=copy.deepcopy(self.layout)
        changed['mappings'][0]['address']=self.plan['original_mapping_records'][0]['address']
        with self.assertRaises(Refusal):validate(changed,self.family,self.plan)
        changed=copy.deepcopy(self.layout)
        changed['class_names']['address']=changed['selector_names']['address']
        with self.assertRaisesRegex(Refusal,'slots overlap'):validate(changed,self.family,self.plan)

    def test_wrong_graph_protection_relative_range_and_blob_overflow_refused(self):
        for kind in ('graph','protection','relative','header'):
            changed=copy.deepcopy(self.layout)
            if kind=='graph':changed['final_subcaches']=16
            if kind=='protection':changed['mappings'][1]['initial']=5
            if kind=='relative':changed['legacy_objc_root']=0
            if kind=='header':changed['prefix_size']=4096
            with self.subTest(kind=kind),self.assertRaises(Refusal):validate(changed,self.family,self.plan)
        for name,size in [('new_protocol',4097),('missing',10),('rw',0)]:
            with self.subTest(name=name),self.assertRaises(Refusal):slot_file_offset(self.layout,name,size)


if __name__=='__main__':unittest.main()
