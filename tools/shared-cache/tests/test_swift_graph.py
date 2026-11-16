import copy
import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import Mock, patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.swift_graph import discover, is_optional, objc_owners, normalize_graph, optional_records, verification_recipe, record_id
from dyld_rebuild.swift_metadata import materialize, recipe_text
import test_swift_metadata as fixtures


class SwiftGraphTests(unittest.TestCase):
    def setUp(self):
        fixture=fixtures.SwiftMetadataTests(); fixture.setUp()
        self.refs,self.family,self.base,self.roots=fixture.refs,fixture.family,fixture.catalog,fixture.roots
        self.header=dict(schema=2,cache_uuid='00000000-0000-0000-0000-000000000000',base=0x6000,end=0xa000)
        w=[0x6300]*8+[16,16,7]
        self.child=dict(node=0x8000,status='captured',name='Child',owner='/swift',key=[0x6400,0x6100,0x6110],
                        type_arguments=2,canonical=True,descriptor_words=[0xd1,2,4],pattern_flags=0x40000000,
                        full_metadata=[0,0x9000,0x200,0x6400,0x6100,0x6110,8<<32],witness=w)
        self.parent=dict(node=0x8100,status='captured',name='Parent',owner='/swift',key=[0x6500,0x8000],
                         type_arguments=1,canonical=True,descriptor_words=[0xd1,1,3],pattern_flags=0x40000001,
                         full_metadata=[0,0x9100,0x200,0x6500,0x8000,0],witness=w)
        self.recipe=dict(schema=1,kind='generic-values',records=[dict(name='Parent',owner='/swift')])
        self.capture=[self.header,dict(root=1,name='Parent',metadata=0x8100),self.child,self.parent,dict(complete=True)]

    def normalize(self, raw=None):
        with patch('dyld_rebuild.swift_metadata.References',return_value=self.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},self.roots)):
            return normalize_graph(self.recipe,raw or self.capture,self.family,self.base)

    def emit(self,catalog):
        with patch('dyld_rebuild.swift_metadata.References',return_value=self.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},self.roots)):
            return materialize(catalog,self.family,0x3000)

    def test_owned_closure_multiple_keys_and_field_offsets(self):
        catalog,coverage=self.normalize()
        self.assertEqual((coverage['added'],coverage['retained'],coverage['included']),(2,2,1))
        parent=next(r for r in catalog['records'] if r['name']=='Parent')
        self.assertEqual(parent['key'][1],dict(owned=record_id(next(r for r in catalog['records'] if r['name']=='Child'))))
        data,pointers,entries,_,records,_=self.emit(catalog)
        addresses={r['name']:r['address'] for r in records}
        child=addresses['Child']
        self.assertIn((0x400,0x100,0x110),entries)
        self.assertIn((0x500,child-0x1000),entries)
        self.assertEqual(struct.unpack_from('<II',data,child-0x3000+32),(0,8))
        self.assertEqual(next(p['target'] for p in pointers if p['address']==addresses['Parent']+16),child)

    def test_compiler_static_root_is_existing_coverage_without_a_duplicate(self):
        raw=[self.header,dict(root=1,name='Parent',metadata=0x6120),
             dict(node=0x6120,status='compiler_static',canonical=True,static_specialization=True,
                  name='CanonicalParent',descriptor=0x6500),dict(complete=True)]
        catalog,report=self.normalize(raw)
        self.assertEqual(catalog['records'],optional_records(self.base))
        self.assertEqual((report['added'],report['included'],report['compiler_provided']),(0,0,1))
        outcome=report['entries'][0]
        self.assertEqual(outcome['metadata'],self.refs.encode(0x1120))
        self.assertEqual(outcome['canonical_name'],'CanonicalParent')
        shifted=copy.deepcopy(raw)
        shifted[0]['base']+=0x10000;shifted[0]['end']+=0x10000
        shifted[1]['metadata']+=0x10000
        shifted[2]['node']+=0x10000;shifted[2]['descriptor']+=0x10000
        self.assertEqual(self.normalize(shifted),(catalog,report))
        for field,value in (('canonical',False),('static_specialization',False),
                            ('descriptor',0xf000)):
            changed=copy.deepcopy(raw);changed[2][field]=value
            _,rejected=self.normalize(changed)
            self.assertEqual(rejected['compiler_provided'],0)
            self.assertEqual(rejected['entries'][0]['status'],'unsupported')
        raw[1]['metadata']=raw[2]['node']=0xf000
        self.assertEqual(self.normalize(raw)[1]['compiler_provided'],0)

    def test_generated_parent_keeps_compiler_static_dependency_identity(self):
        raw=copy.deepcopy(self.capture)
        raw[2]=dict(node=0x6120,status='compiler_static',canonical=True,static_specialization=True,
                    name='Child',descriptor=0x6400)
        raw[3]['key'][1]=raw[3]['full_metadata'][4]=0x6120
        catalog,report=self.normalize(raw)
        self.assertEqual(report['added'],1)
        parent=next(r for r in catalog['records'] if r['name']=='Parent')
        self.assertEqual(parent['key'][1],self.refs.encode(0x1120))
        self.emit(catalog)

    def test_leaf_kind_survives_parent_failure_and_reused_blocked_node(self):
        raw=copy.deepcopy(self.capture)
        raw[2]=dict(node=0x8000,status='unsupported',reason='metadata kind is not struct or enum',metadata_kind=0x301)
        raw[-1:-1]=[dict(root=2,name='ParentAgain',metadata=0x8100)]
        self.recipe['records'].append(dict(name='ParentAgain',owner='/swift'))
        _,report=self.normalize(raw)
        self.assertEqual(report['included'],0)
        self.assertEqual([r['metadata_kind'] for r in report['entries']],[0x301,0x301])
        self.assertTrue(all(r['reason']=='metadata kind is not struct or enum' for r in report['entries']))

    def test_verification_loads_payload_and_witness_images(self):
        catalog,_=self.normalize()
        recipe=verification_recipe(catalog)
        images={ref['image'] for row in catalog['records'] for ref in row['key']+[p['ref'] for p in row['pointers']] if 'image' in ref}
        self.assertTrue(images <= set(recipe['loads']))
        self.assertEqual(len(recipe['records']),len(catalog['records']))
        self.assertEqual(recipe['loads'],sorted(set(recipe['loads'])))

    def test_same_name_different_key_retains_both_dependency_closures(self):
        first, _ = self.normalize()
        self.base = first
        raw = copy.deepcopy(self.capture)
        raw[2]['key'][1] = raw[2]['full_metadata'][4] = 0x6110
        catalog, report = self.normalize(raw)
        self.assertEqual(report['added'], 2)
        self.assertEqual(len([r for r in catalog['records'] if r['name']=='Child']), 2)
        self.assertEqual(len([r for r in catalog['records'] if r['name']=='Parent']), 2)
        self.assertEqual(catalog['records'][:len(first['records'])], first['records'])
        _, pointers, _, _, records, _ = self.emit(catalog)
        addresses = {r['id']: r['address'] for r in records}
        for row in catalog['records']:
            if row['name'] == 'Parent':
                target = addresses[row['key'][1]['owned']]
                self.assertEqual(next(p['target'] for p in pointers
                                      if p['address']==addresses[row['id']]+16), target)
        recipe = verification_recipe(catalog)
        self.assertEqual(len(recipe['records']), len({r['name'] for r in catalog['records']}))
        repeated, report = self.normalize(raw)
        self.assertEqual(repeated, catalog)

    def test_installed_dependency_is_owned_and_does_not_duplicate_catalog(self):
        self.base, _ = self.normalize()
        emitted = self.emit(self.base)
        addresses = {r['name']: r['address'] for r in emitted[4]}
        raw = copy.deepcopy(self.capture)
        # Child is already in the source cache; Parent is constructed again.
        # Do not make a section reference to Child's generated allocation.
        raw[3]['key'][1] = raw[3]['full_metadata'][4] = addresses['Child'] + 0x5000
        with patch('dyld_rebuild.swift_metadata.References',return_value=self.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=(emitted[2],self.roots)):
            catalog, report = normalize_graph(self.recipe,raw,self.family,self.base)
        self.assertEqual(report['added'],0)
        self.assertEqual(catalog['records'],self.base['records'])

    def test_semantic_loads_survive_cached_payload_owners(self):
        self.recipe['loads'] = ['/SemanticModule']
        catalog, _ = self.normalize()
        self.assertIn('/SemanticModule', verification_recipe(catalog)['loads'])
        self.base = catalog
        self.recipe.pop('loads')
        catalog, _ = self.normalize()
        self.assertIn('/SemanticModule', verification_recipe(catalog)['loads'])

    def test_variant_ids_do_not_include_process_addresses(self):
        catalog, _ = self.normalize()
        raw = copy.deepcopy(self.capture)
        delta = 0x10000
        raw[0]['base'] += delta
        raw[0]['end'] += delta
        raw[1]['metadata'] += delta
        for row in raw[2:-1]:
            row['node'] += delta
            row['key'] = [p+delta for p in row['key']]
            for i in (1,3,4):
                row['full_metadata'][i] += delta
            if row['name'] == 'Child':
                row['full_metadata'][5] += delta
            row['witness'] = [p+delta for p in row['witness'][:8]] + row['witness'][8:]
        shifted, _ = self.normalize(raw)
        self.assertEqual(shifted,catalog)

    def test_replay_matches_image_and_retained_owned_references_without_duplicate_aliases(self):
        first,_=self.normalize()
        alias=copy.deepcopy(first['records'][0]);alias['id']=alias['name']='retained-alias'
        first['records'].append(alias)
        self.base=first
        # RootSg is already present at the image address used by Child's second
        # argument. A larger retained catalog now recognizes it as owned.
        with patch('dyld_rebuild.swift_metadata.References',return_value=self.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({(0x200,0x100):[0x110]},self.roots)):
            repeated,report=normalize_graph(self.recipe,self.capture,self.family,self.base)
            self.assertEqual(repeated,first)
            self.assertEqual(report['added'],0)
            changed=copy.deepcopy(self.capture)
            child=next(row for row in changed if row.get('name')=='Child')
            child['key'][2]=child['full_metadata'][5]=0x6120
            expanded,report=normalize_graph(self.recipe,changed,self.family,self.base)
            self.assertEqual(report['added'],2)
            self.assertEqual(expanded['records'][:len(first['records'])],first['records'])

    def test_noncopyable_metadata_keeps_witness_flags_but_incomplete_is_excluded(self):
        raw = copy.deepcopy(self.capture)
        for row in raw:
            if row.get('status') == 'captured':
                row['witness'][10] |= 0x800000
        catalog, report = self.normalize(raw)
        self.assertEqual(report['added'], 2)
        self.emit(catalog)
        for row in catalog['records'][len(self.base['records']):]:
            witness = next(p['ref']['local'] for p in row['pointers'] if p['offset'] == 8)
            flags = struct.unpack_from('<I', bytes.fromhex(row['data']), witness+80)[0]
            self.assertTrue(flags & 0x800000)
        for row in raw:
            if row.get('status') == 'captured':
                row['witness'][10] |= 0x400000
        _, report = self.normalize(raw)
        self.assertEqual(report['added'], 0)

    def test_anonymous_name_address_does_not_change_metadata_identity(self):
        first, _ = self.normalize()
        raw = copy.deepcopy(self.capture)
        for row in raw:
            if 'node' in row and row.get('status') == 'captured':
                row['name'] = 'Private$7ffe1234Context' + row['name']
        second, _ = self.normalize(raw)
        self.assertEqual([record_id(r) for r in first['records']], [record_id(r) for r in second['records']])
        self.assertEqual([r['key'] for r in first['records']], [r['key'] for r in second['records']])
        self.assertEqual([r['data'] for r in first['records']], [r['data'] for r in second['records']])

    def test_exact_key_recipe_carries_cache_identity_and_distinct_variants(self):
        catalog,_=self.normalize()
        profile=dict(cache_uuid=self.header['cache_uuid'],cache_base=0x1000,catalog=[
            dict(id='Parent#one',name='Parent',metadata=0x4000,key=[0x1500,0x3000]),
            dict(id='Parent#two',name='Parent',metadata=0x5000,key=[0x1500,0x3500])])
        recipe=verification_recipe(catalog,profile)
        text=recipe_text(recipe,True)
        self.assertTrue(text.startswith('@cache\t'+profile['cache_uuid']+'\n'))
        self.assertEqual(recipe['installed_metadata'],[0x3000,0x4000])
        self.assertIn('@metadata\t3000\n',text)
        self.assertIn('Parent\t/swift\t500,2000\n',text)
        self.assertIn('Parent\t/swift\t500,2500\n',text)
        recipe.pop('cache_uuid')
        with self.assertRaisesRegex(Refusal,'exact-key'):
            recipe_text(recipe,True)

    def test_runtime_layout_is_owned_and_typed_metadata_reference_relocated(self):
        raw=copy.deepcopy(self.capture)
        raw[3]['descriptor_words'][0]|=0x100000
        raw[3]['full_metadata'][0]=0x8800
        raw[3]['layout']=struct.pack('<5Q',0,16,12<<56,0x8000,0).hex()
        catalog,report=self.normalize(raw)
        self.assertEqual(report['added'],2)
        parent=next(r for r in catalog['records'] if r['name']=='Parent')
        data,pointers,_,_,records,_=self.emit(catalog)
        addresses={r['name']:r['address'] for r in records}
        layout=next(p['target'] for p in pointers if p['address']==addresses['Parent']-16)
        self.assertEqual(struct.unpack_from('<3Q',data,layout-0x3000),(0,16,12<<56))
        self.assertEqual(next(p['target'] for p in pointers if p['address']==layout+24),addresses['Child'])
        self.assertEqual(parent['key'][1]['owned'],next(r['id'] for r in catalog['records'] if r['name']=='Child'))

    def test_unknown_layout_opcode_does_not_ship_a_partial_closure(self):
        raw=copy.deepcopy(self.capture)
        raw[3]['descriptor_words'][0]|=0x100000
        raw[3]['full_metadata'][0]=0x8800
        raw[3]['layout']=struct.pack('<4Q',0,8,0x7f<<56,0).hex()
        catalog,report=self.normalize(raw)
        self.assertEqual(report['added'],0)
        self.assertIn('layout string opcode 0x7f',report['entries'][0]['reason'])
        self.assertEqual(len(catalog['records']),len(self.base['records']))

    def test_layout_self_metadata_reference_is_local_not_a_dependency_cycle(self):
        raw=copy.deepcopy(self.capture)
        raw[3]['descriptor_words'][0]|=0x100000
        raw[3]['full_metadata'][0]=0x8800
        raw[3]['layout']=struct.pack('<5Q',0,16,12<<56,0x8100,0).hex()
        catalog,report=self.normalize(raw)
        self.assertEqual(report['included'],1)
        parent=next(r for r in catalog['records'] if r['name']=='Parent')
        self.assertEqual(parent['pointers'][2]['ref'],dict(local=16))

    def test_packed_enum_reference_is_relocated_without_touching_neighbor_bytes(self):
        raw=copy.deepcopy(self.capture)
        body=struct.pack('<QQQQIQQ',19<<56,0,8,0,1,16,8)+struct.pack('<QQ',12<<56,0x8000)
        layout=struct.pack('<QQ',0,len(body))+body+bytes(8)
        raw[3]['descriptor_words'][0]|=0x100000
        raw[3]['full_metadata'][0]=0x8800
        raw[3]['layout']=layout.hex()
        catalog,_=self.normalize(raw)
        data,pointers,_,_,records,_=self.emit(catalog)
        addresses={r['name']:r['address'] for r in records}
        start=next(p['target'] for p in pointers if p['address']==addresses['Parent']-16)
        field=next(p for p in pointers if p['address']==start+76)
        self.assertEqual(field['target'],addresses['Child'])
        self.assertEqual(field['address']%8,4)
        expected=bytearray(layout);struct.pack_into('<Q',expected,76,0)
        self.assertEqual(data[start-0x3000:start-0x3000+len(layout)],expected)
        # Move this four-byte-aligned field onto a page boundary. Placement must
        # move the allocation rather than emit an invalid cross-page chain.
        base=0x4000+(4092-(field['address']-0x3000))%4096
        with patch('dyld_rebuild.swift_metadata.References',return_value=self.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},self.roots)):
            moved=materialize(catalog,self.family,base)
        self.assertGreater(len(moved[0]),len(data))
        self.assertTrue(all(p['address']%4096<=4088 for p in moved[1]))

    def test_layout_pointer_shaped_offset_is_preserved_as_data(self):
        raw=copy.deepcopy(self.capture)
        raw[3]['descriptor_words'][0]|=0x100000
        raw[3]['full_metadata'][0]=0x8800
        raw[3]['layout']=struct.pack('<4Q',0,8,(2<<56)|0x6100,0).hex()
        catalog,_=self.normalize(raw)
        parent=next(r for r in catalog['records'] if r['name']=='Parent')
        self.assertTrue(bytes.fromhex(parent['data']).endswith(bytes.fromhex(raw[3]['layout'])))

    def test_optional_conversion_retains_exact_bytes_and_pointer_targets(self):
        with patch('dyld_rebuild.swift_metadata.References',return_value=self.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},self.roots)):
            old=materialize(self.base,self.family,0x3000)
        new=self.emit(dict(schema=2,kind='swift-value-catalog',records=optional_records(self.base)))
        self.assertEqual(new[:2],old[:2])
        self.assertEqual(new[2],old[2])

    def test_missing_or_app_dependency_excludes_whole_root_without_losing_base(self):
        raw=copy.deepcopy(self.capture)
        raw[2]=dict(node=0x8000,status='unsupported',reason='type descriptor is outside shared cache')
        catalog,report=self.normalize(raw)
        self.assertEqual(report['added'],0)
        self.assertEqual(len(catalog['records']),2)
        self.assertEqual(report['entries'][0]['reason'],'type descriptor is outside shared cache')

    def test_rejected_parent_reports_the_unsupported_leaf(self):
        raw=copy.deepcopy(self.capture)
        raw[2]=dict(node=0x8000,status='unsupported',reason='metadata kind is not struct or enum')
        raw[3]=dict(node=0x8100,status='unsupported',reason='unsupported type argument dependency',dependency=0x8000)
        catalog,report=self.normalize(raw)
        self.assertEqual(report['added'],0)
        self.assertEqual(report['entries'][0]['reason'],'metadata kind is not struct or enum')

    def test_interrupted_capture_is_not_partial_success(self):
        with self.assertRaisesRegex(Refusal,'interrupted'):
            self.normalize(self.capture[:-1])

    def test_explicit_completed_prefix_is_distinct_from_interrupted_raw_capture(self):
        raw=copy.deepcopy(self.capture)
        raw[0]['recovered_prefix']=dict(failed_root=2,returncode=134)
        raw[-1]=dict(prefix_complete=True)
        catalog,coverage=self.normalize(raw)
        self.assertTrue(coverage['recovered_prefix'])
        self.assertEqual(coverage['included'],1)

    def test_unused_prefix_does_not_change_payload_or_dependency_closure(self):
        expected, _ = self.normalize()
        raw = copy.deepcopy(self.capture)
        # Neither an unmapped word nor a cache-looking word is a dependency
        # without HasLayoutString. Do not mutate the saved capture while reading.
        raw[2]['full_metadata'][0] = 0xdeadbeef
        raw[3]['full_metadata'][0] = 0x6600
        catalog, coverage = self.normalize(raw)
        self.assertEqual(catalog, expected)
        self.assertEqual(coverage['included'], 1)
        self.assertEqual(raw[2]['full_metadata'][0], 0xdeadbeef)

    def test_layout_bytes_require_the_descriptor_flag(self):
        raw = copy.deepcopy(self.capture)
        raw[2]['layout'] = struct.pack('<3Q', 0, 0, 0).hex()
        _, coverage = self.normalize(raw)
        self.assertEqual(coverage['included'], 0)
        self.assertEqual(coverage['entries'][0]['reason'], 'layout string without descriptor flag')

    def test_prefix_reference_is_relocated_and_witness_data_not_rebased(self):
        raw=copy.deepcopy(self.capture)
        raw[2]['descriptor_words'][0]|=0x100000
        raw[2]['full_metadata'][0]=0x6600
        catalog,_=self.normalize(raw)
        row=next(r for r in catalog['records'] if r['name']=='Child')
        self.assertEqual(next(p['ref']['offset'] for p in row['pointers'] if p['offset']==0),0x600)
        self.assertEqual(struct.unpack('<18Q',bytes.fromhex(row['data']))[-3:],(16,16,7))

    def test_discovery_uses_exact_mangled_names_and_explicit_module_owners(self):
        def snapshot(rows): return [dict(metadata=[dict(address=a,name=n) for a,n in rows])]
        mangled=snapshot([(1,'$sOne'),(2,'Two'),(3,'Three')])
        display=snapshot([(1,'SwiftUI._GraphValue<App.View>'),(2,'App.View'),(3,'AttributeGraph.Attribute<Int>')])
        recipe,excluded=discover(mangled,display,{'SwiftUI':'/SwiftUI','AttributeGraph':'/AG'})
        self.assertEqual(recipe['records'],[dict(name='One',owner='/SwiftUI'),dict(name='Three',owner='/AG')])
        self.assertEqual(excluded[0]['name'],'Two')

    def test_optional_discovery_keeps_app_tuple_container_and_function_wrappers(self):
        types=[('SiSg','Swift.Int?'),('SaySiGSg','[Swift.Int]?'),
               ('Si_SStSg','(Swift.Int, Swift.String)?'),
               ('SiycSg','(() -> Swift.Int)?'),('SiSgyc','() -> Swift.Int?'),
               ('7Example4ViewVSg','Example.View?'),
               ('7SwiftUI11_GraphValueVy7Example4ViewVGSg','SwiftUI._GraphValue<Example.View>?')]
        mangled=[dict(metadata=[dict(address=i,name=n) for i,(n,_) in enumerate(types)])]
        display=[dict(metadata=[dict(address=i,name=n) for i,(_,n) in enumerate(types)])]
        recipe,excluded=discover(mangled,display,{'Swift':'/swift','SwiftUI':['/SwiftUI']},True)
        self.assertEqual({r['name'] for r in recipe['records']},{n for n,_ in types if n!='SiSgyc'})
        self.assertEqual({r['owner'] for r in recipe['records']},{'/swift'})
        self.assertEqual(recipe['loads'],['/SwiftUI','/swift'])
        self.assertEqual(excluded,[])
        self.assertTrue(is_optional('$sSiSgSg'))
        self.assertTrue(is_optional('s8OptionalOySiG'))
        self.assertFalse(is_optional('SaySiSgG'))

    def test_all_observed_keeps_composites_and_unresolved_app_roots(self):
        mangled=[dict(metadata=[dict(address=i,name=n) for i,n in enumerate(('Si_SSt','AppValue','Siyc'))])]
        display=[dict(metadata=[dict(address=i,name=n) for i,n in enumerate(('(Swift.Int, Swift.String)','App.Value','() -> Swift.Int'))])]
        recipe,excluded=discover(mangled,display,{'Swift':['/swift']},all_observed=True)
        self.assertEqual(len(recipe['records']),3)
        self.assertEqual(excluded,[])
        self.assertEqual(recipe['loads'],['/swift'])

    def test_imported_optional_loads_its_class_owner_not_every_c_importer(self):
        mangled=[dict(metadata=[dict(address=1,name='So8NSObjectCSg')])]
        display=[dict(metadata=[dict(address=1,name='__C.NSObject?')])]
        owners={'Swift':['/swift'],'__C':['/unrelated1','/unrelated2']}
        recipe,excluded=discover(mangled,display,owners,True,{'NSObject':['/Foundation']})
        self.assertEqual(recipe['loads'],['/Foundation','/swift'])
        self.assertEqual(excluded,[])

    def test_objc_owner_scan_ignores_symbolic_swift_names_without_decoding_them(self):
        family=Mock(images=[('/Foundation',0x1000)])
        reader=Mock()
        pointers={0x2000:0x3000,0x2008:0x3100,0x3020:0x4000,0x3120:0x4102,
                  0x4018:0x5000,0x4118:0x5100}
        reader.ptr.side_effect=pointers.__getitem__
        reader.string_bytes.side_effect={0x5000:b'NSObject',0x5100:b'\x01\xe8' }.__getitem__
        with patch('dyld_rebuild.objc_emit.FamilyReader',return_value=reader), \
             patch('dyld_rebuild.cache.commands',return_value=[]), \
             patch('dyld_rebuild.objc_transfer.sections',return_value=[('__DATA','__objc_classlist',0x2000,16)]):
            self.assertEqual(objc_owners(family,{'NSObject'}),{'NSObject':['/Foundation']})


if __name__=='__main__': unittest.main()
