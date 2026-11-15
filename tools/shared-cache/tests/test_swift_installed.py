import copy
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.swift_installed import records
from dyld_rebuild.swift_graph import verification_recipe
from dyld_rebuild.witness_graph import replay_summary
import test_witness_graph as fixtures


class InstalledSwiftTests(unittest.TestCase):
    def setUp(self):
        f=fixtures.WitnessGraphTests();f.setUp()
        self.catalog,_=f.generate();self.allocation=f.allocate(self.catalog)
        self.fixture=f.fixture
        self.fixture.family.read=lambda address,size: bytes(size)
        keys=list(self.allocation['witness_entries'])
        self.table=SimpleNamespace(pointer_keys=list(enumerate(keys)),
            rows=[(i,0,0,self.allocation['witness_entries'][key][0]) for i,key in enumerate(keys)])
        self.fields={p['address']:p['target'] for p in self.allocation['pointers']}

    def read(self):
        f=self.fixture
        with patch('dyld_rebuild.swift_installed.References',return_value=f.refs), \
             patch('dyld_rebuild.swift_installed.pointer_entries',return_value=(self.allocation['metadata_entries'],f.roots)), \
             patch('dyld_rebuild.swift_installed.swift_roots',return_value=(f.roots['base'],dict(pointer_tables=[0x500,0x10000]))), \
             patch('dyld_rebuild.swift_installed.read_table',return_value=self.table), \
             patch('dyld_rebuild.swift_installed.FamilyReader') as reader:
            reader.return_value.ptr.side_effect=self.fields.__getitem__
            return records(self.catalog,f.family)[0]

    def test_resolves_transitive_metadata_and_witness_keys_from_actual_tables(self):
        result=self.read()
        self.assertEqual({r['id']:r['address'] for r in result},
                         {r['id']:r['address'] for r in self.allocation['records']})
        self.assertTrue(all(r['existing'] for r in result))

    def test_missing_witness_is_reported_instead_of_allocated(self):
        self.table.rows.pop()
        with self.assertRaisesRegex(Refusal,'missing or ambiguous installed Swift protocol-witness'):
            self.read()

    def test_ambiguous_witness_or_mismatched_descriptor_is_rejected(self):
        first=self.table.rows[0]
        self.table.rows.append(first[:3]+(first[3]+8,))
        with self.assertRaisesRegex(Refusal,'ambiguous installed Swift protocol-witness'):self.read()
        self.table.rows.pop()
        self.fields[self.fixture.roots['base']+first[3]]+=8
        with self.assertRaisesRegex(Refusal,'descriptor differs'):self.read()

    def test_installed_summary_cannot_accept_an_isolated_replay(self):
        layout=dict(installed=True,records=[dict(kind='metadata')])
        footer=dict(complete=True,metadata_requests=1,metadata_names=1,witness_requests=0,
                    ordinary_requests=0,ordinary_adopted=0,failures=0)
        events=[dict(record=0,direct=True),footer]
        self.assertFalse(replay_summary(layout,events)['complete'])
        footer['installed']=True
        self.assertTrue(replay_summary(layout,events)['complete'])
        layout['installed']=False
        self.assertFalse(replay_summary(layout,events)['complete'])

    def test_combined_verification_recipe_keeps_metadata_keys_and_excludes_witness_roots(self):
        rows=self.read();base=self.fixture.roots['base']
        # Owner is capture data; these synthetic names have no module context.
        catalog=copy.deepcopy(self.catalog)
        catalog['loads']=['/unresolved-discovery-owner']
        for r in catalog['records']:r['owner']='/fixture'
        profile=dict(cache_uuid='fixture',cache_base=base,catalog=[dict(id=r['id'],name=r['name'],
            key=[base+k for k in r['key']],metadata=r['address']) for r in rows if r['kind']=='metadata'])
        recipe=verification_recipe(catalog,profile)
        self.assertNotIn('/unresolved-discovery-owner',recipe['loads'])
        self.assertEqual(len(recipe['records']),len(catalog['records']))
        self.assertEqual({r['id'] for r in recipe['records']},{r['id'] for r in profile['catalog']})


    def verification_input(self):
        import uuid
        rows=self.read();base=self.fixture.roots['base'];identifier=str(uuid.UUID(int=1))
        self.fixture.family.main=SimpleNamespace(data=bytes(88)+uuid.UUID(identifier).bytes)
        targets=[r for r in rows if r['kind']=='metadata']
        recipe=dict(cache_uuid=identifier,installed_metadata=[r['address']-base for r in targets],
            records=[dict(id=r['id'],name=r['name'],key=r['key']) for r in targets])
        events=[dict(schema=2,cache_uuid=identifier,base=base+0x100000)]
        events += [dict(root=i,name=r['name'],metadata=r['address']+0x100000) for i,r in enumerate(targets,1)]
        events.append(dict(complete=True))
        return rows,recipe,events

    def verify(self,rows,recipe,events):
        from dyld_rebuild.swift_graph import normalize_graph
        with patch('dyld_rebuild.swift_installed.records',return_value=(rows,self.fixture.roots)):
            return normalize_graph(recipe,events,self.fixture.family,self.catalog)

    def test_bench_verification_retains_both_catalog_sections_without_serialization(self):
        rows,recipe,events=self.verification_input()
        catalog,report=self.verify(rows,recipe,events)
        self.assertTrue(report['complete'])
        self.assertEqual((report['added'],report['retained_witnesses']),(0,2))
        self.assertEqual(catalog['records'],self.catalog['records'])
        self.assertEqual(catalog['witnesses'],self.catalog['witnesses'])

    def test_bench_verification_reports_runtime_identity_mismatch(self):
        rows,recipe,events=self.verification_input()
        events[1]['metadata']+=8
        catalog,report=self.verify(rows,recipe,events)
        self.assertFalse(report['complete'])
        self.assertEqual(report['entries'][0]['status'],'unsupported')
        self.assertEqual(catalog['witnesses'],self.catalog['witnesses'])

    def test_bench_verification_rejects_wrong_cache_key_and_missing_roots(self):
        rows,recipe,events=self.verification_input()
        events[0]['cache_uuid']='other'
        with self.assertRaisesRegex(Refusal,'another cache'):self.verify(rows,recipe,events)
        rows,recipe,events=self.verification_input()
        recipe['records'][0]['key']=recipe['records'][0]['key']+[0]
        with self.assertRaisesRegex(Refusal,'key differs'):self.verify(rows,recipe,events)
        rows,recipe,events=self.verification_input()
        with self.assertRaisesRegex(Refusal,'lost or reordered'):self.verify(rows,recipe,events[:1]+events[2:])


if __name__=='__main__':unittest.main()
