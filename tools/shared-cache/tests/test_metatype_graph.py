import copy
import os
from pathlib import Path
import sys
import struct
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.swift_graph import normalize_graph, materialize_dependencies
from dyld_rebuild.swift_metadata import prepare
from dyld_rebuild.exports import Refusal
import test_swift_graph as fixtures


class MetatypeGraphTests(unittest.TestCase):
    def fixture(self):
        f=fixtures.SwiftGraphTests(); f.setUp()
        events=copy.deepcopy(f.capture)
        events[2]=dict(node=0x8000,status='captured',name='Sim',owner='/swift',
                       abi_family='metatype',metadata_kind=0x304,canonical=True,
                       key=[0x6300,0x6100],full_metadata=[0,0x6200,0x304,0x6100])
        return f,events

    def test_metatype_dependency_exports_and_relocates_with_ordinary_parent(self):
        f,events=self.fixture()
        with patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},f.roots)):
            catalog,report=normalize_graph(f.recipe,events,f.family,f.base,witness_closures=True)
            self.assertEqual(report['added_metadata'],2)
            node=next(r for r in catalog['records'] if r.get('record_kind')=='metatype')
            self.assertTrue(node['key'][0]['executable'])
            self.assertEqual([p['offset'] for p in node['pointers']],[8,24])
            result=materialize_dependencies(catalog,f.family,0x3000)
            metadata=next(r for r in result['records'] if r.get('abi_family')=='metatype')
            parent=next(r for r in result['records'] if r['name']=='Parent')
            fields={r['address']:r['target'] for r in result['pointers']}
            self.assertEqual(fields[parent['address']+16],metadata['address'])
            self.assertEqual(fields[metadata['address']-8],0x1200)
            self.assertEqual(fields[metadata['address']+8],0x1100)
            self.assertIn((0x300,0x100),result['metatype_entries'])
            self.assertNotIn((0x300,0x100),result['metadata_entries'])

    def test_installed_metatypes_resolve_from_secondary_map_and_validate_instance(self):
        from dyld_rebuild.swift_installed import records
        f,events=self.fixture()
        with patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},f.roots)):
            catalog,_=normalize_graph(f.recipe,events,f.family,f.base,witness_closures=True)
            allocated=materialize_dependencies(catalog,f.family,0x3000)
        f.family.read=lambda address,size:allocated['data'][address-0x3000:address-0x3000+size]
        fields={p['address']:p['target'] for p in allocated['pointers']}
        with patch('dyld_rebuild.swift_installed.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_installed.pointer_entries',return_value=(allocated['metadata_entries'],f.roots)), \
             patch('dyld_rebuild.swift_installed.auxiliary_entries',return_value=allocated['metatype_entries']), \
             patch('dyld_rebuild.swift_installed.FamilyReader') as reader:
            reader.return_value.ptr.side_effect=fields.__getitem__
            installed,_=records(catalog,f.family)
            metatype=next(r for r in installed if r.get('abi_family')=='metatype')
            self.assertEqual(metatype['kind'],'metadata')
            fields[metatype['address']+8]+=8
            with self.assertRaisesRegex(Refusal,'instance differs'):
                records(catalog,f.family)

    def test_noncanonical_and_process_local_witnesses_remain_unresolved(self):
        for field,value in [('canonical',False),('full_metadata',[0,0xf000,0x304,0x6100])]:
            f,events=self.fixture();events[2][field]=value
            with self.subTest(field=field), \
                 patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
                 patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},f.roots)):
                _,report=normalize_graph(f.recipe,events,f.family,f.base,witness_closures=True)
                self.assertEqual(report['included'],0)
                self.assertEqual(report['added_metadata'],0)

    def test_installer_registers_the_metatype_map_separately(self):
        from dyld_rebuild.swift_dependency_install import prepare as install
        f,events=self.fixture()
        with patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},f.roots)):
            catalog,_=normalize_graph(f.recipe,events,f.family,f.base,witness_closures=True)
        f.family.main.data=bytearray(512)
        struct.pack_into('<Q',f.family.main.data,376,0x18000)
        f.family.read=lambda address,size:bytes(size)
        layout={name:dict(address=address,reserve=4096) for name,address in (
            ('swift_metadata',0x3000),('swift_table',0x5000),('swift_witness_table',0x6000),('swift_metatype_table',0x7000))}
        with patch('dyld_rebuild.swift_metadata.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},f.roots)), \
             patch('dyld_rebuild.swift_dependency_install.swift_roots',return_value=(0x1000,dict(pointer_tables=(0x500,)))), \
             patch('dyld_rebuild.swift_dependency_install.emit_table',return_value=(b'table',{})), \
             patch('dyld_rebuild.swift_dependency_install.runtime_recipe',return_value=dict(blobs=[],new_pointer_fields=[],byte_edits=[])) as runtime:
            installed=install(catalog,f.family,layout,Path('/unused'),Path('/toolchain'))
        self.assertTrue(runtime.call_args.kwargs['metatypes'])
        self.assertEqual(len(installed['metatypes']),1)
        self.assertEqual(installed['metatype_registration'],installed['witness_registration']+8)
        self.assertFalse(any(r.get('abi_family')=='metatype' for r in installed['records']))
        self.assertEqual(installed['pointer_edits'][0]['target'],layout['swift_table']['address'])

    def test_metatypes_cannot_be_installed_without_the_runtime_consumer(self):
        catalog=dict(kind='swift-dependency-catalog',records=[dict(record_kind='metatype')],witnesses=[])
        with self.assertRaisesRegex(Refusal,'source-built runtime toolchain'):
            prepare(catalog,None,{},'unused')

    @unittest.skipUnless(all(os.environ.get(name) for name in
        ('SWIFT_METATYPE_GRAPH_HELPER','SWIFT_STATIC_MIRROR_TOOLCHAIN','SWIFT_GUM_DEVKIT','SWIFT_LLVM')),
        'set metatype helper, static toolchain, Gum devkit and LLVM for native adoption')
    def test_native_export_relocation_name_resolution_and_value_operations(self):
        from metatype_fixture import run
        with tempfile.TemporaryDirectory() as directory:
            result=run(Path(os.environ['SWIFT_METATYPE_GRAPH_HELPER']).resolve(),
                       Path(os.environ['SWIFT_STATIC_MIRROR_TOOLCHAIN']).resolve(),
                       Path(os.environ['SWIFT_GUM_DEVKIT']).resolve(),
                       Path(os.environ['SWIFT_LLVM']).resolve(),Path(directory)/'fixture')
            self.assertTrue(result['complete'])
            self.assertFalse(result['footer']['installed'])
            self.assertEqual(result['metatypes']['requests'],2)
            self.assertEqual(result['metatypes']['resolved'],2)
            self.assertEqual(result['metatypes']['value_operations'],2)
