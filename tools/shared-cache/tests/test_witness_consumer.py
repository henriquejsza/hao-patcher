import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.witness_consumer import summarize, MODES


class WitnessConsumerTests(unittest.TestCase):
    def records(self, path):
        (path / 'produce.jsonl').write_text('{"produced":true}\n')
        for mode in MODES:
            data = dict(complete=True, mode=mode, cache_uuid='same', direct_calls=4,
                        conformance_calls=4, dependencies=1, comparisons=100, hashes=25,
                        map_hits=0 if mode=='native' else 6, fallbacks=3,
                        conformance_adopted=0 if mode=='export' else 4)
            (path / (mode + '.jsonl')).write_text(json.dumps(data)+'\n')

    def test_wrapper_control_is_distinct_from_native_consumer_adoption(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            self.records(path)
            result = summarize(path)
            self.assertTrue(result['consumer_supported'])
            self.assertFalse(result['export_reaches_conformance'])
            self.assertIn('No installed patch', result['scope'])

    def test_partial_run_wrong_cache_and_missing_native_adoption_are_not_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp)
            for key, value in (('complete', False), ('comparisons', 99), ('cache_uuid', 'other'),
                               ('conformance_adopted', 0), ('map_hits', 4), ('fallbacks', 0)):
                self.records(path)
                output = path / 'implementation.jsonl'
                row = json.loads(output.read_text()); row[key] = value
                output.write_text(json.dumps(row))
                with self.subTest(key=key):
                    self.assertFalse(summarize(path)['consumer_supported'])
            output.unlink()
            self.assertFalse(summarize(path)['complete'])

    @unittest.skipUnless(os.environ.get('SWIFT_WITNESS_CONSUMER_BUNDLE'),
                         'set SWIFT_WITNESS_CONSUMER_BUNDLE to a prepared native bundle')
    def test_fresh_process_relocation_and_ordinary_protocol_dispatch(self):
        bundle = Path(os.environ['SWIFT_WITNESS_CONSUMER_BUNDLE']).resolve()
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / 'results'
            subprocess.run([str(bundle/'run.sh'), str(output)], check=True, timeout=150)
            result = summarize(output)
            self.assertTrue(result['consumer_supported'], result)
            self.assertEqual(result['runs']['implementation']['conformance_adopted'], 4)


if __name__ == '__main__':
    unittest.main()
