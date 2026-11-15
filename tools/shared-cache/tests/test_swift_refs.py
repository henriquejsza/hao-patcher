import struct
import sys
from pathlib import Path
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.swift_refs import (optimization_header, read_table, image_index_map,
                                    remap_conformance_indexes, remap_descriptor_indexes)


def conformance_blob(kind='type'):
    size = 1080
    data = bytearray(size+72)
    struct.pack_into('<6I',data,0,4,2,62,3,0xffffffff,4)
    struct.pack_into('<4I',data,1064,size,size+48,0xffffffff,0xffffffff)
    key = 0x100 | (3<<48) if kind=='foreign' else 0x100
    other = 0x200 | (2<<48) if kind=='foreign' else 0x200
    for i,row in enumerate([(key,0x500,(1<<48)|(0x300<<1)|1),
                            (key,0x500,(2<<48)|(0x400<<1)),
                            (other,0x500,(3<<48)|(0x600<<1))]):
        struct.pack_into('<QQQ',data,size+i*24,*row)
    return bytes(data)


def reader(data):
    def read(address,size):
        if not 0<=address<=len(data) or size>len(data)-address: raise Refusal('truncated fixture')
        return data[address:address+size]
    return read


class SwiftReferenceTests(unittest.TestCase):
    def test_identity_and_reordering_keep_keys_conformances_and_hash(self):
        for kind in ('type','metadata','foreign'):
            original=conformance_blob(kind)
            table=read_table(reader(original),0,kind)
            self.assertEqual(remap_conformance_indexes(table,{1:1,2:2,3:3}),original)
            out=remap_conformance_indexes(table,{1:8,2:3,3:4})
            changed=read_table(reader(out),0,kind)
            self.assertEqual(out[:1080],original[:1080])
            self.assertEqual([r[3]>>48 for r in changed.rows],[3,8,4])
            self.assertEqual([(r[3]>>1)&((1<<47)-1) for r in changed.rows],[0x400,0x300,0x600])
            self.assertEqual([(r[1],r[2]) for r in changed.rows],[(r[1],r[2]) for r in table.rows])
            self.assertEqual([r[3]&1 for r in changed.rows],[1,0,0])

    def test_duplicate_alias_hole_key_switch_order_and_offset_refusals(self):
        controls=[]
        b=bytearray(conformance_blob());struct.pack_into('<I',b,1068,1080);controls.append(b)
        b=bytearray(conformance_blob());struct.pack_into('<I',b,1064,1088);controls.append(b)
        b=bytearray(conformance_blob());struct.pack_into('<I',b,1064,1040);controls.append(b)
        b=bytearray(conformance_blob());struct.pack_into('<Q',b,1104,0x999);controls.append(b)
        b=bytearray(conformance_blob());struct.pack_into('<Q',b,1096,(2<<48)|(0x300<<1)|1);struct.pack_into('<Q',b,1120,(1<<48)|(0x400<<1));controls.append(b)
        b=bytearray(conformance_blob());struct.pack_into('<Q',b,1144,(3<<48)|(0x600<<1)|1);controls.append(b)
        b=bytearray(conformance_blob());struct.pack_into('<I',b,4,3);controls.append(b)
        b=bytearray(conformance_blob());struct.pack_into('<I',b,8,61);controls.append(b)
        for b in controls:
            with self.subTest(data=b[:24]),self.assertRaises(Refusal):read_table(reader(bytes(b)),0,'type')
        for size in (0,100,1055,1079,1100,1151):
            with self.assertRaises(Refusal):read_table(reader(conformance_blob()[:size]),0,'type')

    def test_index_mapping_refuses_missing_merged_invalid_or_duplicate_identities(self):
        self.assertEqual(image_index_map(['/a','/b'],['/b','/new','/a']),{0:2,1:0})
        for a,b in [(['/a'],[]),(['/a','/a'],['/a']),(['/a'],['/a','/a']),(['relative'],['relative'])]:
            with self.assertRaises(Refusal):image_index_map(a,b)
        table=read_table(reader(conformance_blob()),0,'type')
        for m in ({1:0},{1:0,2:0,3:1},{1:65536,2:1,3:2},{1:-1,2:1,3:2},{True:0,2:1,3:2}):
            with self.assertRaises(Refusal):remap_conformance_indexes(table,m)

    def test_descriptor_remap_preserves_empty_aux_and_checks_expectations(self):
        data=struct.pack('<4H',5,0xbeef,8,7)
        changed=remap_descriptor_indexes(data,[(0,5),(2,8),(3,7)],{5:9,8:2,7:6})
        self.assertEqual(struct.unpack('<4H',changed),(9,0xbeef,2,6))
        for entries,mapping in [([(0,8)],{8:1}), ([(0,5),(0,5)],{5:1}), ([(4,5)],{5:1}), ([(0,5)],{})]:
            with self.assertRaises(Refusal):remap_descriptor_indexes(data,entries,mapping)
        with self.assertRaises(Refusal):remap_descriptor_indexes(data[:-1],[],{})

    def test_required_roots_versions_and_pointer_table_holes_refuse(self):
        good=struct.pack('<II12Q',3,0,1,2,3,4,5,*([0]*7))
        self.assertEqual(optimization_header(good)['pointer_tables'],(5,))
        for offset,value in ((0,4),(4,1),(8,0),(32,0),(40,0),(56,6)):
            data=bytearray(good);struct.pack_into('<I' if offset<8 else '<Q',data,offset,value)
            with self.assertRaises(Refusal):optimization_header(bytes(data))
        with self.assertRaises(Refusal):optimization_header(good[:-1])

    def test_pointer_keys_and_values_are_decoded_without_objc_index(self):
        data=bytearray(1112)
        struct.pack_into('<6I',data,0,4,1,62,3,0xffffffff,4)
        struct.pack_into('<4I',data,1064,1080,0xffffffff,0xffffffff,0xffffffff)
        struct.pack_into('<IIQ',data,1080,1096,2,0x900)
        struct.pack_into('<QQ',data,1096,0x100,0x200)
        table=read_table(reader(bytes(data)),0,'pointer')
        self.assertEqual(table.pointer_keys,((1080,(0x100,0x200)),))
        with self.assertRaises(Refusal):remap_conformance_indexes(table,{})
        for key,count in ((1088,2),(1097,2),(1096,0),(1096,65)):
            bad=bytearray(data);struct.pack_into('<II',bad,1080,key,count)
            with self.assertRaises(Refusal):read_table(reader(bytes(bad)),0,'pointer')


if __name__=='__main__':unittest.main()
