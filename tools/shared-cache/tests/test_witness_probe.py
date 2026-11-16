import json
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.witness_probe import summarize,script


class WitnessProbeTests(unittest.TestCase):
    def sample(self,minor=5,mode=3,override=False):
        start=dict(start=True,cache_uuid='test',minor=minor,mode=mode,override=override)
        end=dict(complete=True,requests=8,positive_hits=2,mode=mode,override=override)
        return '\n'.join([json.dumps(start)]+['W\t100\t200']*9+
                         ['L\t2\t300\t400']*2+[json.dumps(end),'WE'])

    def test_clean_negative_capability_with_positive_probe_controls(self):
        r=summarize(self.sample(),'',dict(cache_uuid='test'))
        self.assertTrue(r['complete']);self.assertEqual(r['automatic_table_calls'],0)
        self.assertEqual(r['positive_table_calls'],2)

    def test_override_is_inconclusive_not_a_clean_negative(self):
        self.assertFalse(summarize(self.sample(override=True),'',dict(cache_uuid='test'))['complete'])

    def test_trace_loss_or_absent_controls_cannot_claim_capability(self):
        for text,err in ((self.sample(),'1 dynamic variable drop'),
                         (self.sample().replace('L\t2','L\t0'),''),
                         (self.sample().replace('WE',''),'')):
            with self.subTest(err=err):self.assertFalse(summarize(text,err,dict(cache_uuid='test'))['complete'])

    def test_witness_lookup_is_separate_from_positive_controls(self):
        r=summarize(self.sample()+'\nL\t1\t300\t500','',dict(cache_uuid='test'))
        self.assertTrue(r['complete']);self.assertEqual(r['automatic_table_calls'],1)
        self.assertEqual(r['witness_table_calls'],0)
        r=summarize(self.sample()+'\nL\t1\t300\t100','',dict(cache_uuid='test'))
        self.assertEqual(r['witness_table_calls'],1)

    def test_native_mode_and_wrong_identity(self):
        self.assertTrue(summarize(self.sample(4,2),'',dict(cache_uuid='test'))['complete'])
        self.assertFalse(summarize(self.sample(),' ',dict(cache_uuid='other'))['complete'])

    def test_probe_sites_are_derived_from_profile(self):
        text=script(dict(witness=0x1000,lookup=0x2000))
        self.assertIn('CACHEADDR_1000_END',text);self.assertIn('CACHEADDR_2000_END',text)
