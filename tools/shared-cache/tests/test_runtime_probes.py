import json
from pathlib import Path
import struct
import sys
import unittest
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.runtime_probes import generate, reachable_returns, summarize, symbols, table_calls, verify_capture, original_lookup_read
from dyld_rebuild.x86 import Disassembler


class RuntimeProbeTests(unittest.TestCase):
    def test_redirect_recipe_decodes_original_cfg_without_changing_installed_bytes(self):
        data=b'\xe9\x00\x01\x00\x00\x90\xc3'
        read=lambda address,size:data[address-0x1000:address-0x1000+size]
        recipe=dict(profile=dict(metadata_lookup=0x1000),byte_edits=[
            dict(address=0x1000,before='554889e590',after=data[:5].hex())])
        restored=original_lookup_read(read,recipe)
        dis=Disassembler()
        try:
            with self.assertRaisesRegex(ValueError,'no reachable return'):
                reachable_returns(dis,read,0x1000,0x1007)
            self.assertEqual(reachable_returns(dis,restored,0x1000,0x1007),[6])
        finally:dis.close()
        self.assertEqual(restored(0x1002,4),bytes.fromhex('89e59090'))
        self.assertEqual(read(0x1000,7),data)
        recipe['byte_edits'][0]['after']='0000000000'
        with self.assertRaisesRegex(ValueError,'does not match installed'):
            original_lookup_read(read,recipe)

    def setUp(self):
        self.uuid = '00112233-4455-6677-8899-aabbccddeeff'
        a, b = struct.unpack('<QQ', uuid.UUID(self.uuid).bytes)
        self.begin = f'SB\t1\t100000\t{a:x}\t{b:x}\n'
        self.profile = {'cache_uuid': self.uuid, 'objc': {'preoptimized': 1, 'disable': 2}}

    def summary(self, body, end='SE\n', stderr=''):
        return summarize(self.begin + body + end, self.profile, stderr)

    def test_disabled_requests_are_bypasses_not_misses(self):
        s = self.summary('SQ\t2\t7\t1\t4\t1\t1000\t1\n'
                         'SA\t7\t1\t0\t2000\nSR\t3\t7\t1\t4\t1\t0\n')
        self.assertTrue(s['complete'])
        self.assertEqual(s['counts'], {'bypass': 1})

    def test_table_hit_and_miss_with_cross_cpu_record_order(self):
        s = self.summary('SU\t3\t7\t1\t3000\nSA\t7\t1\t0\t2000\n'
                         'SQ\t2\t7\t1\t0\t0\t1000\t1\n'
                         'ST\t2\t7\t1\t4000\t1000\t1\n'
                         'SR\t4\t7\t1\t2\t0\t3000\n'
                         'SQ\t5\t7\t2\t2\t0\t1000\t0\n'
                         'ST\t6\t7\t2\t4000\t1000\t0\n'
                         'SU\t7\t7\t2\t0\nSR\t8\t7\t2\t2\t0\t0\n')
        self.assertTrue(s['complete'])
        self.assertEqual(s['counts'], {'hit': 1, 'miss': 1})

    def test_two_table_fallback_preserves_each_result_and_detects_loss(self):
        body=('SQ\t2\t7\t1\t2\t0\t1000\t0\n'
              'SU\t6\t7\t1\t3000\nST\t5\t7\t1\t5000\t1000\t0\n'
              'ST\t3\t7\t1\t4000\t1000\t0\nSU\t4\t7\t1\t0\n'
              'SR\t7\t7\t1\t2\t0\t3000\n')
        result=self.summary(body)
        self.assertTrue(result['complete'])
        self.assertEqual(result['counts'], {'hit':1})
        self.assertEqual([t['result'] for t in result['requests'][0]['table']], [0,0x3000])
        for invalid in (body.replace('SU\t4\t7\t1\t0\n',''),
                        body.replace('SU\t4\t7\t1\t0','SU\t4\t7\t1\t3000'),
                        body.replace('ST\t5\t7\t1\t5000\t1000','ST\t5\t7\t1\t5000\t1008')):
            self.assertFalse(self.summary(invalid)['complete'])
        miss=body.replace('3000','0')
        self.assertEqual(self.summary(miss)['counts'], {'miss':1})

    def test_incomplete_argument_or_return_is_not_a_miss(self):
        for body in ('SQ\t2\t7\t1\t2\t0\t1000\t1\nSR\t3\t7\t1\t2\t0\t0\n',
                     'SQ\t2\t7\t1\t2\t0\t1000\t0\n'):
            s = self.summary(body)
            self.assertFalse(s['complete'])
            self.assertEqual(s['counts'], {'incomplete': 1})

    def test_identity_drop_and_truncated_capture(self):
        body='SQ\t2\t7\t1\t4\t0\t1000\t0\nSR\t3\t7\t1\t4\t0\t0\n'
        self.assertFalse(self.summary(body, end='')['complete'])
        self.assertFalse(self.summary(body, stderr='dtrace: 5 drops on CPU 1')['complete'])
        self.profile['cache_uuid'] = str(uuid.uuid4())
        self.assertFalse(self.summary(body)['complete'])

    def test_objc_counters_are_reported_separately(self):
        s=self.summary('OS\t4\t1\t0\nOC\tobjc_read_class\t25\n')
        self.assertEqual(s['objc_snapshots'], [dict(wall=4,preoptimized=1,disable=0)])
        self.assertEqual(s['objc_calls'], {'objc_read_class':25})
        self.assertFalse(s['complete'])

    def test_catalog_counts_exact_key_and_result_and_keeps_unobserved_entries(self):
        self.profile['catalog'] = [dict(index=1,name='A?',key=[0x1000,0x2000],metadata=0x3000),
                                   dict(index=2,name='B?',key=[0x1000,0x4000],metadata=0x5000)]
        body = ('SQ\t2\t7\t1\t2\t0\t101000\t1\nSA\t7\t1\t0\t102000\n'
                'ST\t3\t7\t1\t104000\t101000\t1\nSU\t4\t7\t1\t103000\n'
                'SR\t5\t7\t1\t2\t0\t103000\nCG\t1\tcatalog\t8\nGE\n')
        result = self.summary(body)['catalog']
        self.assertTrue(result['complete'])
        self.assertEqual(result['totals']['catalog'],8)
        self.assertEqual(result['totals']['table_hits'],1)
        self.assertEqual(result['unobserved'],1)
        self.assertFalse(self.summary(body,stderr='dtrace: 1 dynamic variable drop')['catalog']['complete'])
        wrong = self.summary(body.replace('103000','103008'))['catalog']
        self.assertEqual(wrong['totals']['mismatch'],1)

    def test_orphaned_rows_make_loss_visible_without_losing_the_report(self):
        result = self.summary('SA\t7\t99\t0\t2000\n')
        self.assertFalse(result['complete'])
        self.assertIn('orphaned', result['errors'][0])

    def test_catalog_counts_two_argument_keys(self):
        self.profile['catalog']=[dict(index=1,name='Pair<A,B>',key=[0x1000,0x2000,0x2500],metadata=0x3000)]
        body=('SQ\t2\t7\t1\t2\t0\t101000\t2\nSA\t7\t1\t0\t102000\nSA\t7\t1\t1\t102500\n'
              'ST\t3\t7\t1\t104000\t101000\t2\nSU\t4\t7\t1\t103000\n'
              'SR\t5\t7\t1\t2\t0\t103000\nGE\n')
        self.assertEqual(self.summary(body)['catalog']['totals']['table_hits'],1)
        self.assertEqual(self.summary(body.replace('102500','102600'))['catalog']['totals']['table_hits'],0)

    def test_catalog_returns_are_matched_offline_without_double_counting_old_aggregates(self):
        self.profile['catalog']=[dict(index=1,name='A?',key=[0x1000,0x2000],metadata=0x3000)]
        request=('SQ\t2\t7\t1\t2\t0\t101000\t1\nSA\t7\t1\t0\t102000\n'
                 'ST\t3\t7\t1\t104000\t101000\t1\nSU\t4\t7\t1\t103000\n'
                 'SR\t5\t7\t1\t2\t0\t103000\n')
        events='N\t6\t7\t1\t101000\t103000\t10\t8\t0\tP\n'
        # Same family, wrong result; same result, wrong family: neither matches.
        wrong='N\t7\t7\t1\t101000\t103008\t10\t8\t0\tP\n'
        wrong+='N\t8\t7\t1\t101008\t103000\t10\t8\t0\tP\n'
        result=self.summary(request+events*2+wrong+'GE\n')['catalog']
        self.assertEqual(result['totals']['catalog'],2)
        self.assertEqual(result['totals']['table_hits'],1)
        old=self.summary(request+events+'CG\t1\tcatalog\t9\nGE\n')['catalog']
        self.assertEqual(old['totals']['catalog'],9)

    def test_graph_verification_counts_retained_entries_and_dependencies(self):
        profile=dict(cache_uuid=self.uuid,cache_base=0x1000,
                     catalog=[dict(name='Parent',metadata=0x3000),dict(name='Child',metadata=0x4000)])
        recipe=dict(records=[dict(name='Parent')])
        raw=[dict(schema=2,cache_uuid=self.uuid,base=0x11000),dict(root=1,name='Parent',metadata=0x13000),
             dict(node=0x14000,name='Child',status='captured'),dict(complete=True)]
        self.assertTrue(verify_capture(profile,recipe,raw)['complete'])
        self.assertFalse(verify_capture(profile,recipe,raw[:-1])['complete'])
        self.assertFalse(verify_capture(profile,recipe,[raw[0],raw[1],raw[-1]])['complete'])

    def test_graph_variants_require_each_address_not_only_the_name(self):
        profile=dict(cache_uuid=self.uuid,cache_base=0x1000,catalog=[
            dict(id='A#one',name='A',metadata=0x3000),dict(id='A#two',name='A',metadata=0x4000)])
        raw=[dict(schema=2,cache_uuid=self.uuid,base=0x11000),
             dict(root=1,name='A',metadata=0x13000),dict(complete=True)]
        result=verify_capture(profile,{},raw)
        self.assertFalse(result['complete'])
        self.assertTrue(result['names_complete'])
        self.assertEqual(result['counts'],dict(catalog=1,unselected_variant=1))
        raw.insert(-1,dict(root=2,name='A',metadata=0x14000))
        self.assertTrue(verify_capture(profile,{},raw)['complete'])

    def test_full_catalog_exercise_requires_each_canonical_result_and_matching_cache(self):
        profile = dict(cache_uuid=self.uuid,cache_base=0x1000,
                       catalog=[dict(name='A?',metadata=0x3000),dict(name='B?',metadata=0x4000)])
        recipe = dict(records=[dict(name='A?'),dict(name='B?')])
        raw = [dict(cache_uuid=self.uuid,base=0x11000),
               dict(index=1,metadata=0x13000,none_copy_destroy=True),
               dict(index=2,metadata=0x14000,none_copy_destroy=True)]
        self.assertTrue(verify_capture(profile,recipe,raw)['complete'])
        self.assertFalse(verify_capture(profile,recipe,raw[:2])['complete'])
        self.assertEqual(verify_capture(profile,recipe,raw[:2])['counts']['unobserved'],1)
        raw[2]['metadata']=0x2000
        self.assertEqual(verify_capture(profile,recipe,raw)['counts']['runtime'],1)
        raw[0]['cache_uuid']='wrong'
        self.assertFalse(verify_capture(profile,recipe,raw)['complete'])

    def test_reachable_returns_do_not_decode_jump_table_as_code(self):
        d=Disassembler()
        try:
            # jz epilogue; indirect jump; embedded ret byte; epilogue ret.
            code=bytes.fromhex('7405ffe0c39090c3')
            read=lambda a,n: code[a-0x1000:a-0x1000+n]
            self.assertEqual(reachable_returns(d,read,0x1000,0x1008), [7])
        finally:
            d.close()

    def test_symbol_reader(self):
        strings=b'\0_symbol\0'
        self.assertEqual(symbols(struct.pack('<IBBHQ',1,15,1,0,0x1234),strings),{'_symbol':0x1234})

    def test_table_calls_resolve_direct_and_slide_decoded_stub_targets(self):
        dis = Disassembler()
        try:
            code = bytearray(0x90 for _ in range(0x100))
            # CALL stub; CALL target; CALL unrelated function; RET.
            for offset, target in ((0, 0x1040), (5, 0x1080), (10, 0x1090)):
                code[offset:offset+5] = b'\xe8' + struct.pack('<i', target - (0x1000+offset+5))
            code[15] = 0xc3
            code[0x40:0x46] = b'\xff\x25' + struct.pack('<i', 0x1060-0x1046)
            code[0x60:0x68] = struct.pack('<Q', 0xffff000000001080)
            read = lambda a,n: bytes(code[a-0x1000:a-0x1000+n])
            slots = []
            def pointer(a):
                slots.append(a)
                return struct.unpack('<Q',read(a,8))[0] & 0xffff
            self.assertEqual(table_calls(dis,read,pointer,0x1000,16,0x1080),
                             [dict(call=0,resume=5),dict(call=5,resume=10)])
            self.assertEqual(slots,[0x1060])
            with self.assertRaisesRegex(ValueError,'cannot locate Swift call'):
                table_calls(dis,read,pointer,0x1000,16,0x10f0)
        finally:
            dis.close()

    def test_generated_probes_use_caller_registers_and_matching_stack(self):
        p = dict(mode=1,gapis=2,override_field=3,cache_base=0,generic_address=0x4000,objc={},
                 table_calls=[dict(call=0x25,resume=0x2a)],functions={})
        for name in ('lookup','callback','objc_map','objc_categories','objc_read_class','objc_attach'):
            p['functions'][name] = dict(module='runtime',symbol=name,address=0x1000,returns=[0x40])
        # An unavailable private dyld symbol must never become a pid probe.
        p['functions']['table'] = dict(module='dyld',symbol='unavailable',returns=[1])
        p['objc'] = {'preoptimized': 4}
        script = generate(p)
        self.assertNotIn('pid$target:dyld:',script)
        self.assertIn('pid$target::-:CACHEADDR_1025_END',script)
        self.assertIn('pid$target::-:CACHEADDR_102a_END',script)
        self.assertIn('(uint64_t)uregs[R_RDI],(uint64_t)uregs[R_RSI],(uint64_t)uregs[R_RDX]',script)
        self.assertIn('cr_t_sp[tid,self->cr_depth]==uregs[R_RSP]',script)
        self.assertIn('if (!self->cr_depth) self->cr_depth=1;',script)
        self.assertIn('cr_t_id[tid,self->cr_depth]==cr_id[tid,self->cr_depth]',script)
        self.assertIn('@cr_table[pid,execname,uregs[R_RAX] ? "hit" : "miss"]=count()',script)
        p.update(generic_address=0x4000,catalog=[dict(index=1,name='Pair',key=[0x5000,0x6000,0x7000],metadata=0x8000)])
        script=generate(p)
        self.assertNotIn('cr_catalog',script)
        self.assertIn('copyin(uregs[R_RDI],4)',script)
        self.assertNotIn('copyin(arg0',script)

    def test_indirect_wrapper_table_call_and_original_body_offsets(self):
        dis=Disassembler()
        try:
            code=bytes.fromhex('ff150a000000c3')+b'\x90'*9+struct.pack('<Q',0x5000)
            read=lambda a,n:code[a-0x2000:a-0x2000+n]
            self.assertEqual(table_calls(dis,read,lambda a:struct.unpack('<Q',read(a,8))[0],
                                        0x2000,7,0x5000),[dict(call=0,resume=6)])
        finally:dis.close()
        p=dict(mode=1,gapis=2,override_field=3,cache_base=0,generic_address=0x4000,
               objc={'preoptimized':4},table_calls=[dict(call=-0xfb5,resume=-0xfb0),dict(call=0x50,resume=0x56)],
               functions={})
        for name in ('lookup','callback','objc_map','objc_categories','objc_read_class','objc_attach'):
            p['functions'][name]=dict(address=0x2000,returns=[0x90])
        script=generate(p)
        for address in (0x2000,0x2090,0x104b,0x1050,0x2050,0x2056):
            self.assertIn(f'CACHEADDR_{address:x}_END',script)
        self.assertNotIn('CACHEADDR_1090_END',script)


if __name__ == '__main__':
    unittest.main()
