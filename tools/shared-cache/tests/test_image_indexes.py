import json
from pathlib import Path
import struct
import tempfile
import copy
import sys
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.loader_generation import sha
from dyld_rebuild.image_indexes import swift_owners,difference,path_at,verify_report,COVERAGE,function_variants
from dyld_rebuild.swift_refs import read_table,remap_conformance_indexes
from test_swift_refs import conformance_blob,reader


class ImageIndexTests(unittest.TestCase):
    def test_swift_index_fault_detected_by_path_even_when_in_range(self):
        old=['/zero','/one','/two','/three']
        new=['/new','/zero','/one','/two','/three']
        for kind in ('type','metadata','foreign'):
            source=read_table(reader(conformance_blob(kind)),0,kind)
            changed=remap_conformance_indexes(source,{i:i+1 for i in range(4)})
            final=read_table(reader(changed),0,kind)
            self.assertEqual(swift_owners(source,old),swift_owners(final,new))
            # One byte in the third record's uint16 index names another valid image.
            bad=bytearray(changed);bad[1144+6]=3
            faulty=read_table(reader(bytes(bad)),0,kind)
            delta=difference(swift_owners(source,old),swift_owners(faulty,new))
            self.assertEqual(delta['missing'][0]['identity'][-1],'/three')
            self.assertEqual(delta['unexpected'][0]['identity'][-1],'/two')
            self.assertEqual(delta['missing'][0]['count'],1)

    def test_duplicate_order_is_not_identity_but_multiplicity_is(self):
        source=read_table(reader(conformance_blob()),0,'type')
        mapped=remap_conformance_indexes(source,{1:3,2:2,3:1})
        final=read_table(reader(mapped),0,'type')
        self.assertEqual(swift_owners(source,['/zero','/one','/two','/three']),
                         swift_owners(final,['/zero','/three','/two','/one']))

    def test_out_of_range_index_refuses(self):
        for index in (-1,2,True):
            with self.assertRaises(Refusal):path_at(['/a','/b'],index)

    def test_function_variant_uint16_owner_and_header_must_agree(self):
        class Family:
            images=[('/a',0x1000),('/b',0x2000)]
            class main:
                data=bytearray(552)
            table=bytearray(struct.pack('<IIQQQIHH',1,1,0x50,0x60,0x2000,0,1,4))
            def read(self,address,size):return self.table[address-0x800:address-0x800+size]
        f=Family();struct.pack_into('<QQ',f.main.data,520,0x800,len(f.table))
        self.assertEqual(next(iter(function_variants(f)))[2],'/b')
        struct.pack_into('<H',f.table,8+28,0)
        with self.assertRaisesRegex(Refusal,'header and image index'):function_variants(f)

    def test_certificate_report_pins_and_coverage_refuse_drift(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'config').mkdir()
            def pin(name,content):
                p=root/name;p.write_text(content)
                return dict(path=str(p),size=p.stat().st_size,sha256=sha(p))
            source=[pin('cache'+str(i),'source'+str(i)) for i in range(7)]
            family=[pin('final','final')];plan=pin('plan.json','{}')
            (root/'config/relayout-inputs.json').write_text(json.dumps(dict(files=source)))
            checks={k:dict(entries=1) for k in COVERAGE};checks['function_variants']=dict(entries=0,version=1)
            report=dict(schema=1,result='PASS',wrong_entries=0,wrong=[],checks=checks,
                        checked_entries=len(COVERAGE)-1,source_files=source,family_files=family,
                        metadata_plan=plan,source_hashes={})
            with patch('dyld_rebuild.image_indexes.ROOT',root),patch('dyld_rebuild.image_indexes.SOURCES',()):
                self.assertEqual(verify_report(report,family,plan)['result'],'PASS')
                variants=[]
                b=copy.deepcopy(report);b['source_files'][1]=b['source_files'][0];variants.append(b)
                b=copy.deepcopy(report);b['family_files'][0]['sha256']='f'*64;variants.append(b)
                b=copy.deepcopy(report);b['source_hashes']={'unexpected':'f'*64};variants.append(b)
                b=copy.deepcopy(report);del b['checks']['swift_type'];variants.append(b)
                b=copy.deepcopy(report);b['checked_entries']+=1;variants.append(b)
                for b in variants:
                    with self.assertRaises(Refusal):verify_report(b,family,plan)
                Path(source[0]['path']).write_text('modified source')
                with self.assertRaisesRegex(Refusal,'input drift'):verify_report(report,family,plan)

    def test_failed_or_incomplete_reports_refuse_before_input_access(self):
        for report in [dict(schema=1,result='REFUSED',wrong_entries=1,wrong=[{}]),
                       dict(schema=1,result='PASS',wrong_entries=0,wrong=[],checks={})]:
            with self.assertRaises(Refusal):verify_report(report,[],{})


if __name__=='__main__':unittest.main()
