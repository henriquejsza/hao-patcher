"""A broken native constructor must not contaminate the successful address space."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.metadata_expand import execute
from dyld_rebuild.runtime_capture import capture, interrupted_constructor


class RuntimeCaptureTests(unittest.TestCase):
    def fixture(self, folder, behavior):
        root = Path(folder)
        worker = root/'worker'; worker.mkdir()
        (worker/'swift-capture').write_text('already signed native worker')
        (worker/'names.tsv').write_text('@cache\tuuid\n@type\t1\tSi\n@type\t2\tBad\n@generic\t3\t10\t2\n')
        runner = root/'runner'
        runner.write_text('#!'+sys.executable+'\nimport json, os, pathlib, sys\n'
                         'bundle=pathlib.Path(sys.argv[2])\n'
                         'wire=(bundle/"names.tsv").read_text()\n'+behavior)
        runner.chmod(0o755)
        return root, worker, runner

    def test_fault_restarts_and_only_final_attempt_supplies_addresses(self):
        with tempfile.TemporaryDirectory() as folder:
            root, worker, runner = self.fixture(folder,
                'if "@unavailable\\t2\\t11" not in wire:\n'
                ' print(json.dumps({"constructor_begin":2}),flush=True)\n'
                ' print("first worker diagnostic",file=sys.stderr,flush=True)\n'
                ' os._exit(139)\n'
                'print(json.dumps({"constructor":2,"metadata":0,"error":"native signal 11"}))\n'
                'print(json.dumps({"complete":True}))\n')
            original = (worker/'names.tsv').read_bytes()
            raw = root/'capture.jsonl'
            failures = capture(runner, worker, raw, execute)
            self.assertEqual(failures, [dict(constructor=2, signal=11)])
            self.assertEqual((worker/'names.tsv').read_bytes(), original)
            self.assertNotIn('constructor_begin', raw.read_text())
            self.assertIn('first worker diagnostic', (root/'capture-attempts/0/capture.stderr').read_text())
            retry = (root/'capture-attempts/1/names.tsv').read_text()
            self.assertIn('@unavailable\t2\t11', retry)
            self.assertIn('@generic\t3\t10\t2', retry)
            self.assertEqual(len(json.loads((root/'capture-attempts.json').read_text())), 2)

    def test_transport_and_faults_outside_constructor_are_terminal(self):
        for code, events in [(255, [{'constructor_begin':2}]),
                             (137, [{'constructor_begin':2}]),
                             (139, [{'constructor_begin':2}, {'constructor':2,'metadata':123}])]:
            with self.subTest(code=code, events=events), tempfile.TemporaryDirectory() as folder:
                root, worker, runner = self.fixture(folder,
                    f'for event in {events!r}: print(json.dumps(event),flush=True)\nos._exit({code})\n')
                with self.assertRaises(subprocess.CalledProcessError):
                    capture(runner, worker, root/'capture.jsonl', execute)
                self.assertFalse((root/'capture.jsonl').exists())
                self.assertEqual(len(json.loads((root/'capture-attempts.json').read_text())), 1)

    def test_partial_last_write_keeps_attribution_but_invalid_record_fails(self):
        with tempfile.TemporaryDirectory() as folder:
            p = Path(folder)/'capture.jsonl'
            p.write_text('{"constructor_begin":2}\n{"truncated":')
            self.assertEqual(interrupted_constructor(p), 2)
            p.write_text('{"constructor_begin":2}\ninvalid\n')
            with self.assertRaises(json.JSONDecodeError): interrupted_constructor(p)


if __name__ == '__main__': unittest.main()
