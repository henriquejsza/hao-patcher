import json
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.witness_initializers import initializers,normalize,audit_installed


class Reader:
    def __init__(self):self.data=bytearray(8192)
    def read(self,p,n):return self.data[p:p+n]
    def ptr(self,p):return struct.unpack_from('<Q',self.data,p)[0]
    def u32(self,p,n):struct.pack_into('<I',self.data,p,n)
    def pointer(self,p,n):struct.pack_into('<Q',self.data,p,n)
    def relative(self,p,n):struct.pack_into('<i',self.data,p,n-p if n else 0)


class InitializerTests(unittest.TestCase):
    def setUp(self):
        self.r=Reader();r=self.r
        # Protocol at 0x200, one signature requirement, then type, conformance,
        # and method requirements. Conformance at 0x100, static pattern at 0x400.
        r.relative(0x100,0x200);r.relative(0x108,0x400)
        r.u32(0x20c,1);r.u32(0x210,3)
        self.start=0x224
        for i,kind in enumerate((7,8,1)):r.u32(self.start+i*8,kind)
        r.pointer(0x408,0x601);r.pointer(0x410,0x701);r.pointer(0x418,0x800)

    def test_nongeneric_pattern_and_null_default(self):
        self.assertEqual(initializers(self.r,0x100),{1:(7,0x601),2:(8,0x701)})
        self.r.pointer(0x410,0);self.r.relative(self.start+12,0x901)
        self.assertEqual(initializers(self.r,0x100)[2],(8,0x901))

    def test_resilient_overrides_after_conditional_and_pack_descriptors(self):
        r=self.r
        r.u32(0x10c,0x30000|64|(1<<8)|(1<<24));r.relative(0x108,0)
        cursor=0x110+4+12+8
        r.u32(cursor,1);pair=cursor+4
        # Indirect requirement pointer in a resilient conformance.
        r.pointer(0x1000,self.start);r.relative(pair,0x1001);r.relative(pair+4,0xa01)
        r.u32(pair+8,0)  # No fixed pattern words.
        r.relative(self.start+12,0x901)
        self.assertEqual(initializers(r,0x100),{1:(7,0xa01),2:(8,0x901)})

    def catalog(self):
        return dict(schema=4,kind='swift-dependency-catalog',records=[],witnesses=[dict(
            id='witness',name='witness',record_kind='protocol-witness',key=[dict(offset=0x100),dict(offset=0x900)],
            metadata_offset=8,data=bytes(40).hex(),pointers=[
                dict(offset=8,ref=dict(offset=0x100)),
                dict(offset=16,ref=dict(owned='old-type-memo')),
                dict(offset=24,ref=dict(owned='old-conformance-memo')),
                dict(offset=32,ref=dict(offset=0x800))])])

    def run_normalize(self,catalog):
        class Refs:
            def __init__(self,family):pass
            def decode(self,ref):return ref['offset']
            def encode(self,value):return dict(offset=value)
        with patch('dyld_rebuild.objc_emit.FamilyReader',return_value=self.r), \
             patch('dyld_rebuild.swift_metadata.References',Refs):
            return normalize(catalog,object())

    def test_repairs_inherited_memos_and_is_idempotent(self):
        original=self.catalog();fixed,report=self.run_normalize(original)
        self.assertEqual((report['changed_witnesses'],report['changed_slots']),(1,2))
        self.assertEqual(original['witnesses'][0]['pointers'][1]['ref'],dict(owned='old-type-memo'))
        self.assertEqual([p['ref'] for p in fixed['witnesses'][0]['pointers']],
                         [dict(offset=p) for p in (0x100,0x601,0x701,0x800)])
        again,report=self.run_normalize(fixed)
        self.assertEqual(again,fixed);self.assertEqual(report['changed_slots'],0)

    def test_static_non_symbolic_initializer_and_method_are_preserved(self):
        self.r.pointer(0x408,0xb00)
        fixed,report=self.run_normalize(self.catalog())
        self.assertEqual(report['static_initializers'],1)
        self.assertEqual(report['changed_slots'],1)
        self.assertEqual(fixed['witnesses'][0]['pointers'][1]['ref'],dict(owned='old-type-memo'))
        self.assertEqual(fixed['witnesses'][0]['pointers'][-1]['ref'],dict(offset=0x800))

    def test_public_installer_normalizes_before_emitting_witness_tables(self):
        from dyld_rebuild.swift_metadata import prepare
        fixed,report=self.run_normalize(self.catalog())
        with patch('dyld_rebuild.witness_initializers.normalize',return_value=(fixed,report)), \
             patch('dyld_rebuild.swift_dependency_install.prepare',return_value={}) as emit:
            result=prepare(self.catalog(),object(),{},Path('/unused'),Path('/toolchain'))
        self.assertIs(emit.call_args.args[0],fixed)
        self.assertEqual(result['witness_initializers']['changed_slots'],2)

    def test_installed_audit_finds_stale_slots_even_with_clean_catalog_and_aliases(self):
        # The catalog can be correct while a shared table retains an older memo.
        # Inspect actual emitted bytes and count a shared physical slot once.
        rows=[dict(id=name,address=0x1000) for name in ('first','alias')]
        self.r.pointer(0x1000,0x100)
        self.r.pointer(0x1008,0xb00);self.r.pointer(0x1010,0x701)
        with patch('dyld_rebuild.objc_emit.FamilyReader',return_value=self.r):
            report=audit_installed(object(),rows)
            self.assertFalse(report['complete'])
            self.assertEqual((report['witness_records'],report['witness_tables']),(2,1))
            self.assertEqual((report['associated_slots'],report['stale_slots']),(2,1))
            self.assertEqual(report['stale'][0]['records'],['first','alias'])
            self.assertEqual(report['stale'][0]['actual'],0xb00)
            self.r.pointer(0x1008,0x601)
            self.assertTrue(audit_installed(object(),rows)['complete'])
