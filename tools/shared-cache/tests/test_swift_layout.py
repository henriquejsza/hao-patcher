import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.swift_layout import references


def layout(body):
    return struct.pack('<QQ',0,len(body))+body+bytes(8)


class LayoutTests(unittest.TestCase):
    def test_multi_payload_branches_relocate_only_typed_operands(self):
        # Resolved tag function, two branches, pointer-shaped enum size and skip.
        body=struct.pack('<7Q',21<<56,0x6000,2,40,0x8000,0,24)
        body+=struct.pack('<5Q',12<<56,0x7000,0,2<<56|0x9000,0)
        self.assertEqual(references(layout(body)),[(24,True),(80,False)])

    def test_packed_single_payload_inside_generic_multi_payload(self):
        single=struct.pack('<QQQQIQQ',19<<56,0,8,0,1,16,8)
        single+=struct.pack('<3Q',12<<56,0x7000,0)
        body=struct.pack('<6Q',22<<56,1,1,len(single),9,0)+single
        self.assertEqual(references(layout(body)),[(124,False)])

    def test_resolved_single_payload_function_and_metadata_are_distinct(self):
        body=struct.pack('<5Q',18<<56,0x6000,16,8,12<<56)+struct.pack('<Q',0x7000)
        self.assertEqual(references(layout(body)),[(24,True),(56,False)])

    def test_simple_single_payload_has_no_pointer_operands(self):
        body=struct.pack('<7Q',16<<56,0x6000,8,0,0,0,8)
        self.assertEqual(references(layout(body)),[])

    def test_bad_branch_bounds_and_missing_end_are_rejected(self):
        for offset,size in ((8,8),(0,16)):
            body=struct.pack('<7Q',22<<56,1,1,size,8,offset,2<<56)
            with self.subTest(offset=offset,size=size),self.assertRaises(Refusal):
                references(layout(body))

    def test_relative_accessors_are_not_mistaken_for_absolute_pointers(self):
        for tag in (13,15,17,20):
            with self.subTest(tag=tag),self.assertRaisesRegex(Refusal,'unsupported.*opcode'):
                references(layout(struct.pack('<Q',tag<<56)))
