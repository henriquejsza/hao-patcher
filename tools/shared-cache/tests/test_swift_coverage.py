import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.swift_coverage import report


class CoverageTests(unittest.TestCase):
    def test_compiler_coverage_does_not_claim_generated_or_installed_table_hits(self):
        selection=dict(scope='static roots',entries=[dict(name='Static',processes=['/App'])])
        coverage=dict(entries=[dict(name='Static',status='compiler_static',canonical_name='Canonical',
                                   metadata={'image':'/swift','offset':64},descriptor={'image':'/swift','offset':128})])
        result=report(selection,coverage,dict(records=[]))
        self.assertEqual(result['summary']['compiler_provided'],1)
        self.assertEqual(result['summary']['generated'],0)
        self.assertEqual(result['summary']['installed'],0)
        self.assertEqual(result['summary']['observed'],1)
        self.assertIsNone(result['summary']['utilized'])
        self.assertEqual(result['entries'][0]['ownership'],'source_cache')
        self.assertEqual(result['entries'][0]['compiler_metadata'],coverage['entries'][0]['metadata'])

    def test_generation_installation_and_use_are_separate(self):
        selection=dict(scope='all types',entries=[dict(name=n,processes=['/App'],modules_without_cache_owner=['App'])
            for n in ('ASg','B','C','D')])
        coverage=dict(entries=[dict(name='ASg',status='included',canonical_name='Canonical'),
            dict(name='B',status='unsupported',reason='type name did not resolve'),
            dict(name='C',status='unsupported',reason='type descriptor is outside shared cache')])
        catalog=dict(records=[dict(name='Canonical')])
        result=report(selection,coverage,catalog)
        self.assertEqual(result['summary']['generated'],1)
        self.assertEqual(result['summary']['installed'],0)
        self.assertEqual(result['optionals']['observed'],1)
        self.assertEqual([r['ownership'] for r in result['entries']],
            ['cache_closure','unresolved','outside_shared_cache','unresolved'])
        profile=dict(catalog=[dict(name='Canonical',metadata=4096)])
        runtime=dict(catalog=dict(complete=True,entries=[dict(name='Canonical',lookups=dict(hit=3,miss=0),returns=dict(catalog=7))]))
        result=report(selection,coverage,catalog,profile,runtime)
        self.assertEqual(result['summary']['installed'],1)
        self.assertEqual(result['summary']['utilized'],1)
        self.assertEqual(result['summary']['table_hits'],3)
        self.assertEqual(result['processes']['/App']['observed'],4)
        self.assertTrue(result['entries'][0]['runtime_complete'])

    def test_address_discriminator_is_not_mistaken_for_portable_identity(self):
        selection=dict(scope='all types',entries=[dict(name='3Foo3Bar13$7ff123456789LLVSg',processes=[])])
        result=report(selection,dict(entries=[]),dict(records=[]))
        self.assertTrue(result['entries'][0]['address_bearing_name'])
        self.assertFalse(result['entries'][0]['utilization_checked'])

    def test_shared_type_hits_belong_only_to_the_traced_process(self):
        selection=dict(scope='all types',entries=[dict(name='Shared',processes=['/ControlCenter','/Spotlight'])])
        catalog=dict(records=[dict(name='Shared')])
        runtime=dict(catalog=dict(complete=True,entries=[dict(name='Shared',lookups=dict(hit=3))]))
        result=report(selection,dict(entries=[]),catalog,runtime=runtime,runtime_process='/ControlCenter')
        self.assertEqual(result['summary']['table_hits'],3)
        self.assertEqual(result['processes']['/ControlCenter']['table_hits'],3)
        self.assertTrue(result['processes']['/ControlCenter']['utilization_checked'])
        self.assertIsNone(result['processes']['/Spotlight']['table_hits'])
        self.assertIsNone(result['processes']['/Spotlight']['utilized'])
        self.assertFalse(result['processes']['/Spotlight']['utilization_checked'])
        unidentified=report(selection,dict(entries=[]),catalog,runtime=runtime)
        self.assertEqual(unidentified['summary']['table_hits'],3)
        self.assertTrue(all(r['table_hits'] is None for r in unidentified['processes'].values()))

    def test_variant_utilization_is_aggregated_without_losing_type_denominator(self):
        selection=dict(scope='all types',entries=[dict(name='ASg',processes=[])])
        catalog=dict(records=[dict(id=i,name='ASg') for i in ('one','two')])
        profile=dict(catalog=[dict(id=i,name='ASg',metadata=100+n) for n,i in enumerate(('one','two'))])
        runtime=dict(catalog=dict(complete=True,entries=[dict(id=i,name='ASg',lookups=dict(hit=n+1),returns=dict(catalog=n+3))
            for n,i in enumerate(('one','two'))]))
        result=report(selection,dict(entries=[]),catalog,profile,runtime)
        self.assertEqual(result['summary']['observed'],1)
        self.assertEqual(result['catalog_records'],2)
        self.assertEqual(result['catalog_type_names'],1)
        self.assertEqual(result['entries'][0]['table_hits'],3)
        self.assertEqual(result['entries'][0]['canonical_returns'],7)
        self.assertEqual(result['entries'][0]['variants'],2)
