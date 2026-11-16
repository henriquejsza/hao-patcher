from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.metadata_reconcile import reconcile


class ReconciliationTests(unittest.TestCase):
    def test_canonical_aliases_and_unavailable_types_are_not_installed_misses(self):
        requests = dict(requests=[dict(id=str(i), name=name, source=['/App']) for i, name in
            enumerate(['private$1234', 'private$5678', 'old-spelling', 'static', 'foreign', 'tuple'])])
        coverage = dict(generation=dict(entries=[dict(name='old-spelling', canonical_name='canonical')]),
            unresolved=[dict(id=str(i), outcome=row) for i, row in enumerate([
                dict(reason='address-bearing private context needs reflection'),
                dict(reason='address-bearing private context needs reflection'),
                {}, dict(status='compiler_static'), dict(reason='constructor metadata image is unavailable in this process'),
                dict(category='non_nominal_tuple')])])
        report = reconcile(requests, coverage, dict(records=[dict(name='canonical')]))
        states = report['processes']['/App']['states']
        self.assertEqual(states, {'requires-reflection': 2, 'retained-canonical-alias': 1,
                                 'compiler-provided': 1, 'unavailable-image': 1, 'unsupported': 1})
        self.assertEqual(report['processes']['/App']['address_normalized_names'], 5)
        self.assertIsNone(report['installed_misses'])
        self.assertIsNone(report['construction_seconds'])
