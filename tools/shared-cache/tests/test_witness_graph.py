import copy
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.witness_graph import schemas, summarize, merge_catalogs, replay_summary
from dyld_rebuild.swift_graph import normalize_graph, optional_records, record_id, materialize_dependencies
from dyld_rebuild.swift_metadata import materialize
from dyld_rebuild.exports import Refusal
import test_swift_graph as graph_fixtures


def witness(address=0x8200, descriptor=0x6600, base=None):
    return dict(protocol_witness=address, descriptor=descriptor, type=0x6100, protocol=0x6200,
                private_words=1,public_words=2,generic=True,calls=1,canonical=True,
                words=[0x6120,descriptor,base or 0x6300],arguments=[0x6120],
                conditional_requirements=[dict(kind=0,key=True,pack=False,value=False)],
                requirements=[dict(kind=0 if base else 1,flags=0,data=False)])


class WitnessGraphTests(unittest.TestCase):
    def setUp(self):
        self.fixture=graph_fixtures.SwiftGraphTests();self.fixture.setUp()
        self.events=copy.deepcopy(self.fixture.capture)
        self.events[2]['type_arguments']=1
        self.events[2]['key'][2]=self.events[2]['full_metadata'][5]=0x8300
        self.events[-1:-1]=[witness(),witness(0x8300,0x6700,0x8200),
                            dict(witness_graph=True,records=2,internal_implementation=True,calls=2,failed=0)]

    def generate(self, events=None, enabled=True, installed=None, witnesses=None):
        f=self.fixture
        with patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=(installed or {},f.roots)), \
             patch('dyld_rebuild.swift_installed.auxiliary_entries',return_value=witnesses or {}):
            return normalize_graph(f.recipe,events or self.events,f.family,f.base,witness_closures=enabled)

    def test_transitive_witness_and_metadata_closure_retains_base_and_typed_relocations(self):
        catalog,report=self.generate()
        self.assertEqual((report['added_metadata'],report['added_witnesses']),(2,2))
        self.assertEqual(catalog['records'][:2],optional_records(self.fixture.base))
        identities={record_id(r) for r in catalog['records']+catalog['witnesses']}
        for row in catalog['records']+catalog['witnesses']:
            for ref in row['key']+[p['ref'] for p in row['pointers']]:
                if 'owned' in ref:self.assertIn(ref['owned'],identities)
            for p in row['pointers']:
                self.assertEqual(struct.unpack_from('<Q',bytes.fromhex(row['data']),p['offset'])[0],0)
        with self.assertRaisesRegex(Refusal,'unknown Swift catalog'):
            materialize(catalog,self.fixture.family,0x3000)
        self.assertEqual(self.generate(enabled=False)[1]['added'],0)

    def test_incremental_generation_retains_complete_dependency_catalog(self):
        first,_=self.generate()
        self.fixture.base=first
        repeated,report=self.generate()
        self.assertEqual(repeated,first)
        self.assertEqual((report['added'],report['added_metadata'],report['added_witnesses']),(0,0,0))
        self.assertEqual((report['retained_metadata'],report['retained_witnesses']),(4,2))
        # The ordinary capture normalization must not drop the witness section.
        self.assertEqual(self.generate(enabled=False)[0],first)

    def test_witness_replay_reuses_an_image_key_now_recognized_as_owned(self):
        events=copy.deepcopy(self.events)
        for row in events:
            if 'protocol_witness' in row:row['type']=0x6110
        first,_=self.generate(events)
        self.fixture.base=first
        repeated,report=self.generate(events,installed={(0x200,0x100):[0x110]})
        self.assertEqual(repeated,first)
        self.assertEqual((report['added_metadata'],report['added_witnesses']),(0,0))

    def test_retained_witness_alias_does_not_duplicate_its_parent_metadata(self):
        events=copy.deepcopy(self.events)
        for row in events:
            if 'protocol_witness' in row:row['type']=0x6110
        first,_=self.generate(events)
        alias=copy.deepcopy(first['witnesses'][-1])
        alias['id']=alias['name']='retained-witness-alias'
        alias['key'][1]=dict(owned='RootSg')
        first['witnesses'].insert(0,alias)
        self.fixture.base=first
        repeated,report=self.generate(events,installed={(0x200,0x100):[0x110]})
        self.assertEqual(repeated,first)
        self.assertEqual(report['added'],0)

    def test_ordinary_selection_adds_its_closure_without_replacing_direct_keys(self):
        original,_=self.generate()
        events=copy.deepcopy(self.events)
        selected=witness(0x8400,0x6800)
        events[-1:-1]=[selected,dict(conformance_lookup=0x8300,descriptor=0x6700,
                                   type=0x6100,selected=0x8400)]
        catalog,report=self.generate(events)
        self.assertEqual(report['added_witnesses'],3)
        self.assertEqual(catalog['records'],original['records'])
        self.assertEqual(catalog['witnesses'][:2],original['witnesses'])
        outcome=report['ordinary_conformances'][0]
        self.assertEqual(outcome['status'],'included')
        self.assertNotEqual(outcome['source'],outcome['selected']['owned'])
        self.assertEqual(outcome['selected']['owned'],catalog['witnesses'][-1]['id'])
        self.fixture.base=catalog
        repeated,report=self.generate(events)
        self.assertEqual(repeated,catalog)
        self.assertEqual(report['added'],0)

    def test_unsupported_ordinary_dependency_stays_explicit_and_preserves_direct_records(self):
        original,_=self.generate()
        events=copy.deepcopy(self.events)
        selected=witness(0x8400,0x6800)
        selected['type']=0x8500
        events[-1:-1]=[selected,dict(node=0x8500,status='unsupported',
            reason='unsupported class metadata',metadata_kind=0),
            dict(conformance_lookup=0x8300,descriptor=0x6700,type=0x6100,selected=0x8400)]
        catalog,report=self.generate(events)
        self.assertEqual(catalog,original)
        outcome=report['ordinary_conformances'][0]
        self.assertEqual((outcome['status'],outcome['reason'],outcome['metadata_kind']),
                         ('unsupported','unsupported class metadata',0))

    def test_ordinary_selection_follows_transitive_selected_witnesses_only_for_included_sources(self):
        events=copy.deepcopy(self.events)
        events[-1:-1]=[witness(0x8400,0x6800),witness(0x8500,0x6900),
            dict(conformance_lookup=0x8400,descriptor=0x6800,type=0x6100,selected=0x8500),
            dict(conformance_lookup=0x8300,descriptor=0x6700,type=0x6100,selected=0x8400),
            dict(conformance_lookup=0x9999,descriptor=0x6800,type=0x6100,selected=0)]
        catalog,report=self.generate(events)
        self.assertEqual(len(catalog['witnesses']),4)
        self.assertEqual(len(report['ordinary_conformances']),2)

    def test_installed_witness_keys_unlock_installed_parent_identity(self):
        first,_=self.generate()
        allocation=self.allocate(first)
        parent=next(row for row in allocation['records'] if row['name']=='Parent')
        self.fixture.base=first
        events=[self.fixture.header,dict(root=1,name='Parent',metadata=parent['address']+0x5000),dict(complete=True)]
        # No constructor capture is needed for an already installed closure.
        retained,report=self.generate(events,installed=allocation['metadata_entries'],witnesses=allocation['witness_entries'])
        self.assertEqual(retained,first)
        self.assertEqual((report['included'],report['added']),(1,0))
        self.assertEqual(report['retained_witnesses'],2)
        # A metadata map alone cannot prove this witness-dependent identity.
        retained,report=self.generate(events,installed=allocation['metadata_entries'])
        self.assertEqual(retained,first)
        self.assertEqual(report['included'],0)

    def allocate(self,catalog,address=0x3000,existing=None):
        f=self.fixture
        with patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=(existing or {},f.roots)):
            return materialize_dependencies(catalog,f.family,address)

    def test_joint_allocation_relocates_metadata_and_base_witness_edges(self):
        catalog,_=self.generate()
        result=self.allocate(catalog)
        rows={r['id']:r for r in result['records']}
        fields={p['address']:p['target'] for p in result['pointers']}
        self.assertEqual(len(result['metadata_entries']),4)
        self.assertEqual(len(result['witness_entries']),2)
        for source in catalog['records']+catalog['witnesses']:
            row=rows[record_id(source)]
            self.assertEqual(row['address'],0x3000+row['offset']+source['metadata_offset'])
            for p in source['pointers']:
                if 'owned' in p['ref']:
                    self.assertEqual(fields[0x3000+row['offset']+p['offset']],rows[p['ref']['owned']]['address'])
            if row['kind']=='protocol-witness':
                self.assertEqual(fields[row['address']],row['key'][0]+self.fixture.roots['base'])
                self.assertEqual(result['witness_entries'][tuple(row['key'])],[row['address']-self.fixture.roots['base']])
                self.assertEqual(row['address_point'],8)

    def test_equivalent_witness_arguments_share_metadata_but_keep_exact_keys(self):
        for different_conformance in (False,True):
            catalog,_=self.generate()
            child=next(r for r in catalog['records'] if r['name']=='Child')
            original=next(r for r in catalog['witnesses'] if record_id(r)==child['key'][-1]['owned'])
            alternate=copy.deepcopy(original)
            alternate['id']=alternate['name']='alternate-witness'
            alternate['key'][1]=self.fixture.refs.encode(0x1110)
            if different_conformance:
                alternate['key'][0]=self.fixture.refs.encode(0x1680)
                next(p for p in alternate['pointers'] if p['offset']==alternate['metadata_offset'])['ref']=alternate['key'][0]
            variant=copy.deepcopy(child)
            variant['id']='alternate-child'
            child.pop('type_arguments')  # Retained catalogs predate this field.
            variant['key'][-1]=dict(owned='alternate-witness')
            for pointer in variant['pointers']:
                if pointer['ref']==child['key'][-1]:pointer['ref']=variant['key'][-1]
            catalog['records'].append(variant)
            catalog['witnesses'].append(alternate)
            before=copy.deepcopy(catalog)
            result=self.allocate(catalog)
            rows={r['id']:r for r in result['records']}
            left,right=rows[record_id(child)],rows['alternate-child']
            self.assertNotEqual(left['key'],right['key'])
            self.assertEqual(left['address']==right['address'],not different_conformance)
            for row in (left,right):
                self.assertEqual(result['metadata_entries'][tuple(row['key'])],[row['address']-self.fixture.roots['base']])
                witness=next(r for r in result['records'] if r['address']==self.fixture.roots['base']+row['key'][-1])
                normalized=tuple(row['key'][:-1])+tuple(witness['key'][:1])
                self.assertEqual(result['normalized_entries'][normalized],[row['address']-self.fixture.roots['base']])
            self.assertEqual(result['metadata_shapes'][left['key'][0]],(1,2))
            self.assertEqual(len(result['records']),len(catalog['records'])+len(catalog['witnesses']))
            self.assertEqual(catalog,before)
            moved=self.allocate(catalog,address=0x9000)
            self.assertEqual(result['data'],moved['data'])

    def test_new_witness_key_reuses_an_installed_equivalent_metadata_identity(self):
        catalog,_=self.generate()
        child=next(r for r in catalog['records'] if r['name']=='Child')
        original={(0x400,0x100,0x5000):[0x9000]}
        with patch('dyld_rebuild.objc_emit.FamilyReader') as reader:
            reader.return_value.ptr.return_value=0x1700
            result=self.allocate(catalog,existing=copy.deepcopy(original))
        row=next(r for r in result['records'] if r['id']==record_id(child))
        self.assertEqual(row['address'],0xa000)
        self.assertTrue(row['canonical_alias'])
        self.assertNotEqual(tuple(row['key']),next(iter(original)))
        self.assertEqual(result['metadata_entries'][tuple(row['key'])],[0x9000])
        self.assertEqual(result['original'],original)
        reader.return_value.ptr.assert_called_once_with(0x6000)

    def test_associated_conformance_self_reference_is_a_local_relocation(self):
        events=copy.deepcopy(self.events)
        table=next(r for r in events if r.get('protocol_witness')==0x8200)
        table['requirements'].append(dict(kind=8,flags=8,data=False))
        table['public_words']+=1
        table['words'].append(table['protocol_witness'])
        catalog,report=self.generate(events)
        self.assertEqual((report['added_metadata'],report['added_witnesses']),(2,2))
        self_edges=[(r,p) for r in catalog['witnesses'] for p in r['pointers'] if 'local' in p['ref']]
        self.assertEqual(len(self_edges),1)
        row,pointer=self_edges[0]
        self.assertEqual(pointer['ref'],dict(local=row['metadata_offset']))
        self.assertEqual(pointer['offset'],len(bytes.fromhex(row['data']))-8)
        allocated=self.allocate(catalog)
        target=next(r for r in allocated['records'] if r['id']==record_id(row))
        fields={p['address']:p['target'] for p in allocated['pointers']}
        self.assertEqual(fields[0x3000+target['offset']+pointer['offset']],target['address'])
        # Relocating the whole record preserves the same self-reference.
        moved=self.allocate(catalog,address=0x9000)
        target=next(r for r in moved['records'] if r['id']==record_id(row))
        fields={p['address']:p['target'] for p in moved['pointers']}
        self.assertEqual(fields[0x9000+target['offset']+pointer['offset']],target['address'])

    def test_installed_metadata_identity_and_private_witness_prefix_survive_relocation(self):
        catalog,_=self.generate()
        first=self.allocate(catalog)
        base_ids={record_id(r) for r in catalog['records'][:2]}
        installed=[r for r in first['records'] if r['id'] in base_ids]
        existing={tuple(r['key']):[r['address']-self.fixture.roots['base']] for r in installed}
        result=self.allocate(catalog,address=0x9000,existing=existing)
        self.assertEqual(result['original'],{tuple(r['key']):[r['address']-self.fixture.roots['base']] for r in installed})
        self.assertTrue(all(r['existing'] for r in result['records'] if r['id'] in base_ids))
        self.assertEqual(len(result['data']),len(first['data'])-sum(r['size'] for r in installed))
        fields={p['address']:p['target'] for p in result['pointers']}
        for row in result['records']:
            if row['kind']=='protocol-witness':
                self.assertEqual(fields[row['address']-8],0x1120)

    def test_witness_zero_private_prefix_is_valid_but_descriptor_identity_must_match(self):
        catalog,_=self.generate()
        row=catalog['witnesses'][0]
        row['data']=row['data'][16:];row['metadata_offset']=0
        row['pointers']=[dict(p,offset=p['offset']-8) for p in row['pointers'] if p['offset']>=8]
        self.allocate(catalog)
        row['pointers'][0]['ref']=row['key'][1]
        with self.assertRaisesRegex(Refusal,'descriptor differs'):
            self.allocate(catalog)

    def test_equal_keys_in_separate_maps_do_not_alias(self):
        catalog,_=self.generate()
        row=catalog['witnesses'][0]
        value=copy.deepcopy(catalog['records'][0])
        value['id']=value['name']='same-key-metadata';value['key']=copy.deepcopy(row['key'])
        catalog['records'].append(value)
        result=self.allocate(catalog)
        w=next(r for r in result['records'] if r['id']==row['id'])
        v=next(r for r in result['records'] if r['id']=='same-key-metadata')
        self.assertEqual(w['key'],v['key'])
        self.assertNotEqual(w['address'],v['address'])

    def test_native_summary_requires_every_record_and_ordinary_witness_adoption(self):
        layout=dict(records=[dict(kind='metadata'),dict(kind='protocol-witness')])
        events=[dict(record=0,direct=True,ordinary=None),dict(record=1,direct=True,ordinary=True),
                dict(complete=True,metadata_requests=1,metadata_names=1,witness_requests=1,
                     ordinary_requests=1,ordinary_adopted=1,failures=0)]
        self.assertTrue(replay_summary(layout,events)['complete'])
        associated=dict(associated_summary=True,before_metadata_replay=True,requests=4,validated=4)
        ordered=events[:-1]+[associated,events[-1]]
        self.assertTrue(replay_summary(layout,ordered)['complete'])
        self.assertFalse(replay_summary(layout,events[:-1]+[dict(associated,validated=3),events[-1]])['complete'])
        self.assertFalse(replay_summary(layout,events[:-1]+[dict(associated,before_metadata_replay=False),events[-1]])['complete'])
        for broken in (events[1:],events[:-1],events[:1]+events,events[:2]+[dict(events[-1],metadata_names=0)],
                       [events[0],dict(events[1],ordinary=False),events[-1]]):
            self.assertFalse(replay_summary(layout,broken)['complete'])
        self.assertFalse(replay_summary(layout,events[:2]+[dict(events[-1],runtime_policy=True,policy_disabled_fallback=False)])['complete'])
        self.assertTrue(replay_summary(layout,events[:2]+[dict(events[-1],runtime_policy=True,policy_disabled_fallback=True)])['complete'])

    def test_installation_keeps_metadata_root_and_registers_a_separate_witness_table(self):
        from dyld_rebuild.swift_dependency_install import prepare
        catalog,_=self.generate();f=self.fixture
        f.family.main.data=bytearray(512);struct.pack_into('<Q',f.family.main.data,376,0x18000)
        f.family.read=lambda address,size:bytes(size)
        layout={name:dict(address=address,reserve=4096) for name,address in (
            ('swift_metadata',0x3000),('swift_table',0x5000),('swift_witness_table',0x6000),('swift_normalized_table',0x7000))}
        runtime=dict(blobs=[],new_pointer_fields=[],byte_edits=[])
        with patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},f.roots)), \
             patch('dyld_rebuild.swift_dependency_install.swift_roots',return_value=(0x1000,dict(pointer_tables=(0x500,0x600)))), \
             patch('dyld_rebuild.swift_dependency_install.emit_table',return_value=(b'table',{})), \
             patch('dyld_rebuild.swift_dependency_install.runtime_recipe',return_value=runtime):
            result=prepare(catalog,f.family,layout,Path('/unused'),Path('/toolchain'))
        self.assertEqual(result['witness_registration'],0x19038)
        self.assertEqual(result['pointer_edits'][0]['target'],0x5000)
        self.assertEqual(result['byte_edits'][1],dict(address=0x19038,before=bytes(8).hex(),after=struct.pack('<Q',0x5000).hex()))
        self.assertEqual((len(result['records']),len(result['witnesses'])),(4,2))
        self.assertEqual({b['reservation'] for b in result['blobs']},{'swift_metadata','swift_table','swift_witness_table','swift_normalized_table'})
        self.assertEqual(result['normalized_registration'],result['witness_registration']+8)
        self.assertTrue(result['normalized'])

    def test_metadata_only_dependency_catalog_does_not_install_an_unused_runtime(self):
        from dyld_rebuild.swift_metadata import prepare
        catalog,_=self.generate(enabled=False);catalog=dict(catalog,schema=4,kind='swift-dependency-catalog',witnesses=[])
        f=self.fixture
        with patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},f.roots)), \
             patch('dyld_rebuild.swift_metadata.emit_table',return_value=(b'table',{})):
            result=prepare(catalog,f.family,dict(swift_metadata=dict(address=0x3000,reserve=4096),
                           swift_table=dict(address=0x5000,reserve=4096)),Path('/unused'))
        self.assertNotIn('witness_runtime',result)
        self.assertEqual(len(result['records']),len(catalog['records']))

    def test_unknown_private_storage_or_pack_excludes_the_entire_root(self):
        for failure in ('private','pack','canonical','ambiguous'):
            events=copy.deepcopy(self.events);row=events[-4]
            if failure=='private':row['private_words']=2;row['words'].insert(0,0xdeadbeef)
            elif failure=='pack':row['conditional_requirements'][0]['pack']=True
            elif failure=='canonical':row['canonical']=False
            else:
                duplicate=copy.deepcopy(row);duplicate['type']=0x6110;events.insert(-1,duplicate)
            with self.subTest(failure=failure):
                catalog,report=self.generate(events)
                self.assertEqual(report['added'],0)
                self.assertEqual(catalog['records'],optional_records(self.fixture.base))

    def test_associated_type_and_conformance_tags_are_schema_roles(self):
        row=witness();row['private_words']=0;row['arguments']=[];row['conditional_requirements']=[]
        row['requirements']=[dict(kind=k,flags=0,data=False) for k in (7,7,8,8)]
        row['public_words']=5;row['words']=[row['descriptor'],0x6401,0x8000,0x6501,0x8300]
        parsed=schemas([row])[0]
        self.assertFalse(parsed['errors'])
        self.assertEqual([p['kind'] for p in parsed['pointers']],['descriptor','typeref','metadata','typeref','witness'])

    def test_associated_completion_memos_export_the_image_initializer(self):
        for kind in (7,8):
            events=copy.deepcopy(self.events)
            row=events[-4]
            row['requirements']=[dict(kind=kind,flags=kind,data=False)]
            row['words'][-1]=0xdeadbeef0  # Resolved only in the capture process.
            self.assertEqual(self.generate(events)[1]['added'],0)
            row['requirements'][0]['initializer']=0x6401
            catalog,report=self.generate(events)
            self.assertEqual((report['added_metadata'],report['added_witnesses']),(2,2))
            pointer=next(p for p in schemas([row])[0]['pointers'] if p['word']==2)
            self.assertEqual((pointer['kind'],pointer['target']),('typeref',0x6401))
            expected=self.fixture.refs.encode(0x1401)
            self.assertTrue(any(p['ref']==expected for r in catalog['witnesses'] for p in r['pointers']))

    def test_incomplete_recorder_is_not_a_complete_capture(self):
        self.assertTrue(summarize(self.events)['complete'])
        self.assertFalse(summarize(self.events[:-1])['complete'])
        events=copy.deepcopy(self.events);events[-2]['records']=3
        self.assertFalse(summarize(events)['complete'])

    def test_rebase_does_not_change_generated_bytes_or_identities(self):
        expected,_=self.generate()
        events=copy.deepcopy(self.events);delta=0x10000
        events[0]['base']+=delta;events[0]['end']+=delta;events[1]['metadata']+=delta
        for row in events:
            if row.get('status')=='captured':
                row['node']+=delta;row['key']=[p+delta for p in row['key']]
                for i in (1,3,4):row['full_metadata'][i]+=delta
                if row['name']=='Child':row['full_metadata'][5]+=delta
                row['witness']=[p+delta for p in row['witness'][:8]]+row['witness'][8:]
            if 'protocol_witness' in row:
                for k in ('protocol_witness','descriptor','type','protocol'):row[k]+=delta
                for k in ('words','arguments'):row[k]=[p+delta for p in row[k]]
        self.assertEqual(self.generate(events)[0],expected)

    def test_merge_uses_exact_keys_and_payloads_not_printable_private_names(self):
        first,_=self.generate();second=copy.deepcopy(first)
        row=next(r for r in second['records'] if 'id' in r)
        row['name']='Private$1234Context'
        merged,counts=merge_catalogs([first,second])
        self.assertEqual(merged,first)
        self.assertEqual(counts[1],dict(metadata_added=0,witnesses_added=0))
        row['data']='ff'+row['data'][2:]
        with self.assertRaisesRegex(Refusal,'conflicting generated dependency'):
            merge_catalogs([first,second])

    @unittest.skipUnless(os.environ.get('SWIFT_WITNESS_GRAPH_HELPER'),'set SWIFT_WITNESS_GRAPH_HELPER to signed recorder')
    def test_native_unavailable_reference_does_not_abort_other_constructors(self):
        helper=Path(os.environ['SWIFT_WITNESS_GRAPH_HELPER']).resolve()
        first=subprocess.run([str(helper)],input='',text=True,capture_output=True,check=True,timeout=30)
        header=json.loads(first.stdout.splitlines()[0])
        # The cache header is in the reservation but is not a loaded metadata
        # section. Treat it like a file identity whose platform image is absent.
        request=(f'@cache\t{header["cache_uuid"]}\n@reference\t1\t0\n'
                 '@type\t2\tSSSg\nSSSg\t/usr/lib/swift/libswiftCore.dylib\t&2\n')
        result=subprocess.run([str(helper)],input=request,text=True,capture_output=True,check=True,timeout=30)
        rows=[json.loads(line) for line in result.stdout.splitlines()]
        rejected=next(r for r in rows if r.get('constructor')==1)
        self.assertIn('unavailable', rejected['error'])
        self.assertTrue(next(r for r in rows if 'root' in r)['metadata'])
        self.assertTrue(rows[-1]['complete'])

    @unittest.skipUnless(os.environ.get('SWIFT_WITNESS_GRAPH_HELPER'),'set SWIFT_WITNESS_GRAPH_HELPER to signed recorder')
    def test_native_rejected_tuple_reports_upstream_metadata_kind(self):
        helper=Path(os.environ['SWIFT_WITNESS_GRAPH_HELPER']).resolve()
        result=subprocess.run([str(helper)],input='Si_SSt\t/usr/lib/swift/libswiftCore.dylib\n',
                              text=True,capture_output=True,check=True,timeout=60)
        events=[json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(summarize(events)['complete'])
        root=next(row for row in events if 'root' in row)
        node=next(row for row in events if row.get('node')==root['metadata'])
        self.assertEqual(node['metadata_kind'],0x301)
        self.assertEqual(node['status'],'unsupported')

    @unittest.skipUnless(os.environ.get('SWIFT_WITNESS_GRAPH_HELPER'),'set SWIFT_WITNESS_GRAPH_HELPER to signed recorder')
    def test_native_compiler_specializations_are_not_serialized(self):
        helper=Path(os.environ['SWIFT_WITNESS_GRAPH_HELPER']).resolve()
        # Exercise both enum and struct canonical specializations supplied by
        # the host Swift library. This opt-in integration test uses no laptop.
        result=subprocess.run([str(helper)],input='SSSg\t/usr/lib/swift/libswiftCore.dylib\nSDyS2SG\t/usr/lib/swift/libswiftCore.dylib\n',
                              text=True,capture_output=True,check=True,timeout=60)
        events=[json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(summarize(events)['complete'])
        nodes={row['node']:row for row in events if 'node' in row}
        roots=[row for row in events if 'root' in row]
        self.assertEqual(len(roots),2)
        for root in roots:
            row=nodes[root['metadata']]
            self.assertEqual(row['status'],'compiler_static')
            self.assertTrue(row['canonical'] and row['static_specialization'])
            self.assertNotIn('full_metadata',row)

    @unittest.skipUnless(os.environ.get('SWIFT_WITNESS_GRAPH_HELPER'),'set SWIFT_WITNESS_GRAPH_HELPER to signed recorder')
    def test_native_exact_key_retains_compiler_canonical_dependency(self):
        helper=Path(os.environ['SWIFT_WITNESS_GRAPH_HELPER']).resolve()
        first=subprocess.run([str(helper)],input='SSSg\t/usr/lib/swift/libswiftCore.dylib\n',
                             text=True,capture_output=True,check=True,timeout=30)
        events=[json.loads(line) for line in first.stdout.splitlines()]
        header=events[0]
        child=next(row for row in events if row.get('status')=='compiler_static')
        # Optional<Optional<String>> with the exact canonical static child from
        # the first process. Offsets remain bound to this host cache UUID.
        key=','.join(f'{child[field]-header["base"]:x}' for field in ('descriptor','node'))
        request=f'@cache\t{header["cache_uuid"]}\nSSSgSg\t/usr/lib/swift/libswiftCore.dylib\t{key}\n'
        result=subprocess.run([str(helper)],input=request,text=True,capture_output=True,check=True,timeout=30)
        rows=[json.loads(line) for line in result.stdout.splitlines()]
        root=next(row for row in rows if 'root' in row)
        self.assertNotIn('error',root)
        self.assertTrue(root['metadata'])
        reference=(f'@cache\t{header["cache_uuid"]}\n@reference\t1\t{child["node"]-header["base"]:x}\n'
                   f'@generic\t2\t{child["descriptor"]-header["base"]:x}\t1\n'
                   'SSSgSg\t/usr/lib/swift/libswiftCore.dylib\t&2\n'
                   'SSSgSg\t/usr/lib/swift/libswiftCore.dylib\n')
        result=subprocess.run([str(helper)],input=reference,text=True,capture_output=True,check=True,timeout=30)
        rows=[json.loads(line) for line in result.stdout.splitlines()]
        self.assertTrue(all('error' not in r for r in rows if 'constructor' in r))
        roots=[r for r in rows if 'root' in r]
        self.assertEqual(roots[0]['metadata'],roots[1]['metadata'])

    @unittest.skipUnless(os.environ.get('SWIFT_WITNESS_GRAPH_HELPER'),'set SWIFT_WITNESS_GRAPH_HELPER to signed recorder')
    def test_native_reflected_constructor_resolves_conditional_witnesses(self):
        helper=Path(os.environ['SWIFT_WITNESS_GRAPH_HELPER']).resolve()
        name='Shys6UInt32VSgG'
        first=subprocess.run([str(helper)],input=name+'\t/usr/lib/swift/libswiftCore.dylib\n',
                             text=True,capture_output=True,check=True,timeout=60)
        events=[json.loads(line) for line in first.stdout.splitlines()]
        header=events[0]
        root=next(row for row in events if 'root' in row)
        value=next(row for row in events if row.get('node')==root['metadata'])
        descriptor=value['key'][0]-header['base']
        request=(f'@cache\t{header["cache_uuid"]}\n@type\t1\ts6UInt32VSg\n'
                 f'@generic\t2\t{descriptor:x}\t1\n'
                 f'{name}\t/usr/lib/swift/libswiftCore.dylib\t&2\n'
                 f'{name}\t/usr/lib/swift/libswiftCore.dylib\n')
        result=subprocess.run([str(helper)],input=request,text=True,capture_output=True,check=True,timeout=60)
        rows=[json.loads(line) for line in result.stdout.splitlines()]
        constructors=[r for r in rows if 'constructor' in r]
        self.assertTrue(all('error' not in r for r in constructors),constructors)
        roots=[r for r in rows if 'root' in r]
        self.assertEqual(len(roots),2)
        self.assertEqual(roots[0]['metadata'],roots[1]['metadata'])
        self.assertTrue(summarize(rows)['complete'])
        self.assertTrue(any(r.get('protocol_witness') for r in rows))
        failed=subprocess.run([str(helper)],input=request.replace('s6UInt32VSg','Siyc'),
                              text=True,capture_output=True,check=True,timeout=60)
        failures=[json.loads(line) for line in failed.stdout.splitlines()]
        self.assertEqual(next(r for r in failures if r.get('constructor')==2)['error'],
                         'generic protocol requirement did not resolve')

    @unittest.skipUnless(os.environ.get('SWIFT_WITNESS_GRAPH_HELPER'),'set SWIFT_WITNESS_GRAPH_HELPER to signed recorder')
    def test_native_static_recipe_records_both_conditional_and_base_witnesses(self):
        helper=Path(os.environ['SWIFT_WITNESS_GRAPH_HELPER']).resolve()
        # Set<Optional<UInt32>> needs Optional's conditional Hashable/Equatable tables.
        result=subprocess.run([str(helper)],input='Shys6UInt32VSgG\t/usr/lib/swift/libswiftCore.dylib\n',
                              text=True,capture_output=True,check=True,timeout=60)
        events=[json.loads(line) for line in result.stdout.splitlines()]
        report=summarize(events)
        self.assertTrue(report['complete'])
        self.assertTrue(any(r['private_words'] and not r['errors'] for r in report['records']))
        self.assertTrue(any(r.get('derived_base') for r in report['records']))
        self.assertTrue(any(r.get('status')=='captured' and r.get('type_arguments')==1 and len(r.get('key',[]))==3 for r in events))
        selections=[r for r in events if 'conformance_lookup' in r]
        self.assertTrue(selections)
        witnesses={r['protocol_witness'] for r in report['records']}
        self.assertTrue(all(r['selected'] in witnesses for r in selections))
        self.assertEqual({(r['descriptor'],r['type'],r['conformance_lookup']) for r in selections},
                         {(r['descriptor'],r['type'],r['protocol_witness']) for r in report['records']})
