import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.fastpaths import generate, summarize


class ConformanceTests(unittest.TestCase):
    def setUp(self):
        self.profile=dict(cache_uuid='test')
        self.helper='\n'.join(map(json.dumps,[
            dict(cache_uuid='test',mode='runtime',override=False),
            dict(type='Int',protocol='Hashable',metadata=0x123,type_descriptor=0x456,
                 protocol_descriptor=0x789,witness=0xabc),
            dict(complete=True,failures=0)]))+'\n'

    def test_descriptor_lookup_with_null_metadata_joins_query(self):
        result=summarize(self.helper+'CQ\t1\t1\t789\t0\t456\nCR\t1\t1\t0\tdef\nCE\n',self.profile)
        self.assertTrue(result['complete'])
        self.assertTrue(result['all_queries_table_hits'])
        self.assertEqual(result['queries'][0]['table_hits'],1)

    def test_metadata_lookup_and_miss(self):
        for kind,value,hits,misses in [(1,'abc',1,0),(2,'0',0,1),(3,'0',0,1),(0,'0',0,0)]:
            r=summarize(self.helper+f'CQ\t1\t1\t789\t123\t0\nCR\t1\t1\t{kind}\t{value}\nCE\n',self.profile)
            self.assertEqual(r['queries'][0]['table_hits'],hits)
            self.assertEqual(r['queries'][0]['table_misses'],misses)

    def test_unobserved_is_not_a_hit(self):
        r=summarize(self.helper+'CQ\t1\t1\t789\t111\t222\nCR\t1\t1\t0\tdef\nCE\n',self.profile)
        self.assertEqual(r['counts']['descriptor_hits'],1)
        self.assertEqual(r['queries'][0]['table_hits'],0)
        self.assertFalse(r['all_queries_table_hits'])

    def test_drops_identity_incomplete_and_duplicate_are_incomplete(self):
        body='CQ\t1\t1\t789\t123\t0\nCR\t1\t1\t0\tdef\nCE\n'
        for text,stderr in [(self.helper+body,'dtrace: 1 drop'),
                            (self.helper+body.replace('CE\n',''),''),
                            (self.helper+body.replace('test','wrong'), 'dtrace: invalid address'),
                            (self.helper+body+'CQ\t1\t1\t789\t123\t0\n',''),
                            (self.helper+'CQ\t1\t1\t789\t123\t0\nCE\n',''),
                            (self.helper.replace('"test"','"wrong"')+body,'')]:
            self.assertFalse(summarize(text,self.profile,stderr)['complete'])

    def test_direct_table_mode_is_not_ordinary_runtime_evidence(self):
        self.assertFalse(summarize(self.helper.replace('runtime','table')+'CE\n',self.profile)['complete'])

    def test_calls_use_cache_bound_addresses_and_stack_matching(self):
        d=generate(dict(calls=[dict(call=0x123,resume=0x128)]))
        self.assertIn('CACHEADDR_123_END',d)
        self.assertIn('CACHEADDR_128_END',d)
        self.assertIn('self->cf_sp == uregs[R_RSP]',d)
        self.assertNotIn(':return',d)


if __name__=='__main__':
    unittest.main()
