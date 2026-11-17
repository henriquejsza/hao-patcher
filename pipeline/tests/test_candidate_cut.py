"""pipeline/candidate-cut's record: each made-on-Mac row's state and create-installer's phase times."""
from pathlib import Path
import json
import runpy
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
C = runpy.run_path(str(TOP / 'pipeline' / 'candidate-cut'))


class Record(unittest.TestCase):
    def test_rows_by_state(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'rows.json'
            self.assertIsNone(C['rows_of'](p))
            p.write_text(json.dumps({'rows': {'a': {'state': 'reused', 'key': 'k'}, 'b': {'state': 'made'},
                                              'c': {'state': 'in-place'}, 'd': {'state': 'reused'}}}))
            got = C['rows_of'](p)
            self.assertEqual(got['by_state'], {'reused': ['a', 'd'], 'made': ['b'], 'in-place': ['c']})
            self.assertEqual(got['detail']['a']['key'], 'k')

    def test_phases_from_the_event_log(self):
        events = [dict(ev='run.start', t=3.0), dict(ev='step.start', t=10.0, step='Download'),
                  dict(ev='command', t=12.0, argv=['py', '-I', '/x/pipeline/place']),
                  dict(ev='command', t=14.0, argv=['py', '-I', '/x/pipeline/make-on-mac']),
                  dict(ev='task.start', t=50.0, text='  stage   inputs'), dict(ev='task.end', t=90.0),
                  dict(ev='run.end', t=95.0)]
        with tempfile.TemporaryDirectory() as d:
            self.assertIsNone(C['phases'](d))
            (Path(d) / 'create-installer-1.json').write_text(json.dumps({'events': events}))
            self.assertEqual(C['phases'](d), [['doctor and questions', 10.0], ['step: Download', 2.0],
                                              ['place', 2.0], ['make-on-mac', 36.0], ['stage inputs', 40.0]])


if __name__ == '__main__':
    unittest.main()
