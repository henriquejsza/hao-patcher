"""Conformance key semantics, source scanning, and real Apple writer roundtrips."""
from pathlib import Path
import os
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.swift_conformance import canonical_rows, emit, foreign_identity, collect
from dyld_rebuild.swift_refs import read_table


class ConformanceTests(unittest.TestCase):
    def test_sort_and_preserve_duplicate_values(self):
        rows = [(20, 30, 8 << 48), (10, 30, 2 << 48), (20, 30, 1 << 48), (20, 30, 1 << 48)]
        result, _ = canonical_rows('type', rows, None)
        self.assertEqual(result, sorted(rows))
        self.assertEqual(len(result), 4)

    def test_foreign_byte_identity_canonicalizes_offsets_and_keeps_nuls(self):
        name = b'Name\0Snamespace'
        rows = [(x | (len(name)<<48), 30, raw) for x,raw in [(200, 8<<48),(100,2<<48)]]
        out, names = canonical_rows('foreign', rows, lambda a,n:name)
        self.assertEqual([a for a,_,_ in out], [100 | len(name)<<48]*2)
        self.assertEqual(list(names.values()), [name, name])

    def test_foreign_import_identity(self):
        blob = b'Pretty\0NABI\0Snamespace\0Rrelated\0\0'
        string = lambda a: blob[a:blob.index(b'\0', a)]
        self.assertEqual(foreign_identity(string, lambda a,n:blob[a:a+n], 0, True),
                         (8, b'ABI\0Snamespace\0Rrelated'))
        self.assertEqual(foreign_identity(string, lambda a,n:blob[a:a+n], 0, False), (0,b'Pretty'))

    def test_invalid_rows_refuse(self):
        for rows in ([(True,2,4)], [(-1,2,4)], [(1<<47,2,4)], [(1,1<<47,4)], [(1,2,3)], [(1,2,1<<64)]):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                canonical_rows('type', rows, None)
        for key in ((1<<36), (1<<36) | (2<<48)):
            with self.assertRaises(ValueError):
                canonical_rows('foreign', [(key,2,4)], lambda a,n:b'xx')
        with self.assertRaises(ValueError):
            canonical_rows('foreign', [(100 | 2<<48,2,4)], lambda a,n:b'x')

    def test_scan_direct_indirect_weak_and_objc(self):
        # Cache base 0x1000, owner header 0x1100, owner table 0x1200.
        base = 0x1000
        data = bytearray(0x1000)
        def put(at,fmt,*v): struct.pack_into(fmt,data,at-base,*v)
        def read(at,n):
            self.assertGreaterEqual(at,base); self.assertLessEqual(at+n,base+len(data))
            return bytes(data[at-base:at-base+n])
        put(0x1200,'<IIq',1,24,0x1100-0x1208)
        for i,kind in enumerate((0,1,2,3,1)):
            field,desc=0x1300+4*i,0x1400+16*i
            put(field,'<i',desc-field)
            put(desc,'<i',0x1800-desc)
            target=0x1900 if kind==0 else 0x1a00 if kind==2 else 0x1700 if i<4 else 0x1710
            put(desc+4,'<i',target-(desc+4))
            put(desc+12,'<I',kind<<3)
        put(0x1700,'<Q',0x1900);put(0x1710,'<Q',0)
        class Family:
            images=[('/image',0x1100)]
        f=Family(); f.read=read
        class Reader:
            def __init__(self,f): pass
            def ptr(self,a): return struct.unpack('<Q',read(a,8))[0]
        class Entry:
            name=b'Class'; objects=((0x1b00,0),(0x1c00,0))
        class Table: entries=(Entry(),)
        with patch('dyld_rebuild.swift_conformance.swift_roots',return_value=(base,{})), \
             patch('dyld_rebuild.swift_conformance.FamilyReader',Reader), \
             patch('dyld_rebuild.swift_conformance.objc_header',return_value=(0,0,[4,6,0x200,0,0,0])), \
             patch('dyld_rebuild.swift_conformance.objc_table',return_value=Table()), \
             patch('dyld_rebuild.swift_conformance.commands',return_value=[]), \
             patch('dyld_rebuild.swift_conformance.sections',return_value=[('__TEXT','__swift5_proto',0x1300,20)]), \
             patch('dyld_rebuild.swift_conformance.family_string',return_value=b'Class'):
            rows,stats=collect(f)
        self.assertEqual(len(rows['type']),2)
        self.assertEqual([r[0] for r in rows['metadata']],[0xb00,0xc00,0x900])
        self.assertEqual(stats['weak_types'],1)
        self.assertEqual(stats['descriptors'],5)


@unittest.skipUnless(os.environ.get('CACHE_CONFORMANCE_WRITER'), 'requires compiled Apple host adapter')
class AppleWriterTests(unittest.TestCase):
    def test_empty_single_duplicates_collisions_and_foreign(self):
        binary=Path(os.environ['CACHE_CONFORMANCE_WRITER'])
        for kind in ('type','metadata','foreign'):
            for count in (0,1,2,250):
                with self.subTest(kind=kind,count=count), tempfile.TemporaryDirectory() as tmp:
                    names={100+i*32: (b'X\0S'+str(i).encode() if i else b'') for i in range(count)}
                    rows=[]
                    for i in range(count):
                        key=100+i*32
                        if kind=='foreign': key|=len(names[key])<<48
                        rows.extend([(key,0x1000,0x400),(key,0x1000,(3<<48)|0x200)])
                    blob,stats=emit(binary,Path(tmp),kind,rows,lambda a,n:names[a])
                    table=read_table(lambda a,n:blob[a:a+n],0,kind)
                    self.assertEqual(len(table.rows),count*2)
                    self.assertEqual(stats['keys'],count)
                    self.assertEqual(stats['misses_checked'],count)
                    with tempfile.TemporaryDirectory() as again:
                        repeated, _ = emit(binary,Path(again),kind,list(reversed(rows)),lambda a,n:names[a])
                        self.assertEqual(blob,repeated)
                    if count:
                        self.assertEqual([r[3]&1 for r in table.rows],[1,0]*count)


if __name__ == '__main__': unittest.main()
