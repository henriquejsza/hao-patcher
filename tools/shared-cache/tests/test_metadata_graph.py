"""Portable constructor binding and lossless installation projections."""
from copy import deepcopy
import os
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.metadata_graph import MetadataGraph
from dyld_rebuild.swift_metadata import References, recipe_text
from dyld_rebuild.exports import Refusal


def reference(offset=0):
    return dict(image='/Swift', image_uuid='a'*32, segment='__TEXT', section='__const',
                offset=offset, executable=False)


def references(start=0x2000):
    refs = References.__new__(References)
    key = ('/Swift', '__TEXT', '__const')
    refs.sections = {key: (start, start+0x1000, key, 'a'*32, 5)}
    return refs


def family(cache_uuid=0):
    return SimpleNamespace(main=SimpleNamespace(data=bytes(88)+bytes([cache_uuid])*16,
                                               mappings=[SimpleNamespace(address=0x1000)]))


def graph():
    definitions = [dict(id='8', operation='resolve', name='Si'),
        dict(id='9', operation='opaque', descriptor_reference=reference(32),
             context_reference=reference(64), descriptor=999, context=888,
             arguments=['8'], ordinal=0, key_arguments=2, requirements=[dict(
                 subject_address_reference=reference(96), protocol_reference=reference(128),
                 subject_address=777, protocol=666, subject_length=1)])]
    return MetadataGraph.from_plan(definitions, [dict(name='opaque', owner='/Swift', dependency='9')])


class GraphTests(unittest.TestCase):
    def test_rebinding_moves_every_operand_and_preserves_graph(self):
        portable = graph()
        original = deepcopy(portable.document)
        with patch('dyld_rebuild.swift_metadata.References', return_value=references()):
            first = portable.bind(family())
        with patch('dyld_rebuild.swift_metadata.References', return_value=references(0x6000)):
            second = portable.bind(family(1))
        self.assertIn('1020\t1040\t0\t2\t1\t1060:1:1080', recipe_text(first, True))
        self.assertIn('5020\t5040\t0\t2\t1\t5060:1:5080', recipe_text(second, True))
        self.assertNotEqual(first['cache_uuid'], second['cache_uuid'])
        self.assertEqual(original, portable.document)
        self.assertNotIn('999', json.dumps(original))

    def test_changed_image_requires_analysis_and_old_offsets_are_not_imported(self):
        portable = graph()
        for row in portable.document['constructors'].values():
            if row['operation'] == 'opaque':
                row['descriptor']['image_uuid'] = 'b'*32
        with patch('dyld_rebuild.swift_metadata.References', return_value=references()), self.assertRaisesRegex(Refusal, 'different Mach-O'):
            portable.bind(family())
        with self.assertRaises(KeyError):
            MetadataGraph.from_plan([dict(id='1', operation='generic', descriptor=42, arguments=[])], [])

    def test_constructor_ids_do_not_depend_on_temporary_numbering(self):
        a = MetadataGraph.from_plan([dict(id='2', operation='resolve', name='Si')],
                                   [dict(name='Si', owner='/Swift', dependency='2')])
        b = MetadataGraph.from_plan([dict(id='999', operation='resolve', name='Si')],
                                   [dict(name='Si', owner='/Swift', dependency='999')])
        self.assertEqual(a.document, b.document)

    def test_variants_aliases_and_self_relocations_round_trip(self):
        rows = [dict(id=str(i), name='Alias', key=[reference(i), reference(8)],
                     data='00'*32, metadata_offset=16, pointers=[dict(offset=0, ref=dict(local=16))])
                for i in range(2)]
        witness = dict(rows[0], id='w', record_kind='protocol-witness',
                       key=[reference(32), dict(owned='0')])
        catalog = dict(schema=4, kind='swift-dependency-catalog', source_cache_uuid='source',
                       loads=['/Swift'], records=rows, witnesses=[witness])
        portable = graph()
        portable.import_catalog(catalog)
        self.assertEqual(portable.catalog(), catalog)
        self.assertEqual(portable.document['objects']['w']['key'][1], dict(kind='object', target='0'))
        self.assertEqual(portable.document['objects']['0']['payload']['relocations'][0]['target'],
                         dict(kind='local', offset=16))
        # Payload self-edges never participate in constructor ordering.
        with patch('dyld_rebuild.swift_metadata.References', return_value=references()):
            self.assertEqual(len(portable.bind(family())['records']), 1)

    def test_full_existing_catalog_round_trip(self):
        store = os.environ.get('SHARED_CACHE_STORE')
        path = Path(store or '/nonexistent') / 'artifacts/swift-dependencies-25G332-20261031-6a4c9b536c3d/catalog.json'
        if not store or not path.exists():
            self.skipTest('saved dependency catalog not available')
        catalog = json.loads(path.read_text())
        portable = MetadataGraph()
        portable.import_catalog(catalog)
        self.assertEqual(portable.catalog(), catalog)
        self.assertEqual((len(catalog['records']), len(catalog['witnesses'])), (11537, 177))

    def test_unresolved_requests_are_not_executed_or_counted_as_generated(self):
        portable = graph()
        portable.frontend_evidence(dict(entries=[dict(name='unknown', reason='requires runtime input')]))
        self.assertEqual(portable.document['requests'][-1]['facts'], ['requested', 'unresolved'])
        with patch('dyld_rebuild.swift_metadata.References', return_value=references()):
            self.assertEqual(len(portable.bind(family())['records']), 1)

    def test_multiple_binary_frontends_keep_roots_and_share_constructors(self):
        first = graph()
        combined = MetadataGraph()
        combined.merge_frontend(first, source='binary-a-sha')
        combined.merge_frontend(first, source='binary-b-sha')
        combined.merge_frontend(first, source='binary-a-sha')
        self.assertEqual(len(combined.document['constructors']), 2)
        self.assertEqual(len(combined.document['requests']), 2)
        self.assertNotEqual(*[r['id'] for r in combined.document['requests']])
        self.assertEqual(len({r['constructor'] for r in combined.document['requests']}), 1)

    def test_reusing_graph_does_not_reuse_prior_adoption_or_catalog(self):
        portable = graph()
        portable.document['evidence'].update(capture={'old': True}, isolated_replay={'complete': True})
        portable.document['requests'][0].update(outcome={'status': 'included'}, object='old', facts=['requested', 'generated'])
        portable.document['objects']['old'] = {}
        portable.reset_results()
        self.assertEqual(portable.document['objects'], {})
        self.assertEqual(portable.document['evidence'], {})
        self.assertEqual(portable.document['requests'][0]['facts'], ['requested'])
        self.assertNotIn('object', portable.document['requests'][0])
        self.assertFalse(portable.coverage()['verification']['executed'])


class CaptureGraphTests(unittest.TestCase):
    def test_capture_enriches_graph_and_replay_adds_no_duplicates(self):
        from test_swift_graph import SwiftGraphTests
        fixture = SwiftGraphTests()
        fixture.setUp()
        graph = MetadataGraph.from_plan([], fixture.recipe['records'])
        graph.import_catalog(fixture.base)
        with patch('dyld_rebuild.swift_metadata.References', return_value=fixture.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries', return_value=({}, fixture.roots)):
            report = graph.record_capture(fixture.family, fixture.capture)
            first = graph.catalog()
            self.assertEqual(report['added'], 2)
            self.assertEqual(graph.coverage()['object_facts'], dict(retained=2, generated=2))
            self.assertEqual(graph.coverage()['request_facts'], dict(requested=1, generated=1))
            self.assertIsNone(graph.coverage()['installed'])
            self.assertIsNone(graph.coverage()['observed_native_use'])
            graph.record_capture(fixture.family, fixture.capture)
            self.assertEqual(graph.catalog(), first)
            self.assertEqual(graph.coverage()['generation']['added'], 0)

    def test_unknown_family_and_leaf_kind_remain_explicit(self):
        from dyld_rebuild.swift_abi import export
        with self.assertRaisesRegex(Refusal, 'unsupported Swift ABI export family: class'):
            export('class', {}, 0, None, None, 0)
        from test_swift_graph import SwiftGraphTests
        fixture = SwiftGraphTests()
        fixture.setUp()
        graph = MetadataGraph.from_plan([], fixture.recipe['records'])
        graph.import_catalog(fixture.base)
        fixture.capture[2] = dict(node=0x8000, status='unsupported',
                                  reason='unsupported metadata family', metadata_kind=0x301)
        with patch('dyld_rebuild.swift_metadata.References', return_value=fixture.refs), \
             patch('dyld_rebuild.swift_metadata.pointer_entries', return_value=({}, fixture.roots)):
            graph.record_capture(fixture.family, fixture.capture)
        report = graph.coverage()
        self.assertEqual(report['request_facts'], dict(requested=1, unresolved=1))
        self.assertEqual(report['unresolved'][0]['outcome']['metadata_kind'], 0x301)
