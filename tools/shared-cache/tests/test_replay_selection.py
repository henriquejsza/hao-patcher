import copy
import unittest
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.witness_graph import replay_summary


class ReplaySelectionTests(unittest.TestCase):
    def setUp(self):
        self.layout=dict(records=[dict(kind='metadata',key=[10,20]),
            dict(kind='protocol-witness',key=[30,20]),dict(kind='protocol-witness',key=[40,20])])
        self.events=[dict(record=0,direct=True,ordinary=None),
            dict(record=1,direct=True,ordinary=True,ordinary_valid=True,ordinary_source='catalog',ordinary_record=2),
            dict(record=2,direct=True,ordinary=True,ordinary_valid=True,ordinary_source='catalog',ordinary_record=2),
            dict(complete=True,metadata_requests=1,metadata_names=1,witness_requests=2,
                 ordinary_requests=2,ordinary_adopted=2,ordinary_validated=2,
                 ordinary_fallbacks=0,ordinary_variants=1,failures=0)]

    def test_selected_catalog_variant_must_identify_a_witness_record(self):
        result=replay_summary(self.layout,self.events)
        self.assertTrue(result['complete'])
        self.assertEqual(result['ordinary_coverage']['alternate_records'],[1])
        for index in (0,99,None):
            events=copy.deepcopy(self.events);events[1]['ordinary_record']=index
            self.assertFalse(replay_summary(self.layout,events)['complete'])

    def test_valid_native_fallback_is_uncovered_and_never_counted_as_adoption(self):
        events=copy.deepcopy(self.events)
        events[1].update(ordinary=False,ordinary_source='runtime',ordinary_record=None)
        events[-1].update(ordinary_adopted=1,ordinary_fallbacks=1,ordinary_variants=0)
        result=replay_summary(self.layout,events)
        self.assertTrue(result['complete'])
        self.assertFalse(result['ordinary_coverage']['complete'])
        self.assertEqual(result['ordinary_coverage']['uncovered_records'],[1])
        for change in (dict(ordinary=True),dict(ordinary_valid=False),dict(ordinary_source='catalog'),dict(ordinary_record=2)):
            broken=copy.deepcopy(events);broken[1].update(change)
            self.assertFalse(replay_summary(self.layout,broken)['complete'])
        events[-1]['ordinary_adopted']=2
        self.assertFalse(replay_summary(self.layout,events)['complete'])

    def test_failed_selected_catalog_identity_and_failed_direct_identity_still_fail(self):
        for change in (dict(ordinary=False),dict(ordinary_valid=False),dict(direct=False)):
            events=copy.deepcopy(self.events);events[1].update(change)
            result=replay_summary(self.layout,events)
            self.assertFalse(result['complete'])
            self.assertIn(1,result['failed_records'])

    def test_retained_exact_key_alias_is_not_an_alternate_constructor(self):
        layout=copy.deepcopy(self.layout);layout['records'][2]['key']=layout['records'][1]['key']
        events=copy.deepcopy(self.events);events[-1]['ordinary_variants']=0
        result=replay_summary(layout,events)
        self.assertTrue(result['complete'])
        self.assertEqual(result['ordinary_coverage']['alternate_records'],[])

    def test_selected_lookup_counts_and_installed_mode_must_agree_with_evidence(self):
        for field in ('ordinary_validated','ordinary_fallbacks','ordinary_variants'):
            events=copy.deepcopy(self.events);events[-1][field]+=1
            self.assertFalse(replay_summary(self.layout,events)['complete'])
        events=copy.deepcopy(self.events);events[-1]['installed']=True
        self.assertFalse(replay_summary(self.layout,events)['complete'])
        self.assertTrue(replay_summary(dict(self.layout,installed=True),events)['complete'])
