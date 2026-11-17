"""pipeline/make-on-mac: a local download is used only with its row's sha256 (and keeps the release's pins), the first
failed producer or output check stops the run, and the runtime tool comes from the placed archive or an explicit flag."""
import hashlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest
from contextlib import redirect_stdout
from unittest import mock

TOP = Path(__file__).resolve().parents[2]
M = runpy.run_path(str(TOP / 'pipeline/make-on-mac'))


class MakeOnMac(unittest.TestCase):
    def setUp(self):
        self.t = tempfile.TemporaryDirectory(); self.d = Path(self.t.name)
        self.lock = self.d / 'lock'; self.lock.mkdir()
        self.work = self.d / 'work'; self.work.mkdir()
        self.ipsw = self.d / 'x.ipsw'; self.ipsw.write_bytes(b'ipsw bytes')
        self.row('ipsw_27_0', self.ipsw, b'ipsw bytes')
        self.pins = {'members': {'a': {'size': 1, 'sha256': '0' * 64}}}
        self.release = {'downloads': [{'row': 'ipsw_27_0', 'stream': True, 'url': 'https://example.invalid/x.ipsw',
                                       'pins': self.pins}]}

    def tearDown(self):
        self.t.cleanup()

    def row(self, name, p, data):
        (self.lock / name).write_text('%s %s\n' % (hashlib.sha256(data).hexdigest() if data is not None else '-', p))

    def run_(self, release=None):
        return M['Run']([self.lock], self.work, io.StringIO(), False, release)

    def stream(self, release=None):
        with redirect_stdout(io.StringIO()):
            return self.run_(release).stream('ipsw_27_0')

    def test_local_file_with_the_rows_sha256_keeps_the_pins(self):
        src, extra = self.stream(self.release)
        self.assertEqual(src, self.ipsw)
        self.assertEqual(extra[0], '--pins')
        self.assertEqual(json.loads(Path(extra[1]).read_text()), self.pins)
        self.assertEqual(self.stream(), (self.ipsw, []))

    def test_changed_local_file_is_not_used(self):
        self.ipsw.write_bytes(b'other bytes')
        src, extra = self.stream(self.release)
        self.assertEqual(src, 'https://example.invalid/x.ipsw')
        self.assertEqual(extra[0], '--pins')
        with self.assertRaises(M['Failed']):
            self.stream()

    def test_local_file_of_a_row_without_sha256_is_not_used(self):
        self.row('ipsw_27_0', self.ipsw, None)
        with self.assertRaises(M['Failed']):
            self.stream()
        self.assertEqual(self.stream(self.release)[0], 'https://example.invalid/x.ipsw')

    def steps(self, a_bytes, b_fails=False):
        ran = []
        out = {n: self.d / n for n in 'abc'}
        for n in 'abc':
            self.row(n, out[n], n.encode())

        def make(n, data, fail=False):
            def fn():
                ran.append(n)
                if fail:
                    raise M['Failed']('producer %s failed' % n)
                out[n].write_bytes(data)
            return fn
        todo = [(['a'], make('a', a_bytes)), (['b'], make('b', b'b', b_fails)), (['c'], make('c', b'c'))]
        with redirect_stdout(io.StringIO()):
            failed = M['run_steps'](todo, [self.lock], ['a', 'b', 'c'])
        return ran, failed

    def test_every_step_runs_when_each_checks(self):
        self.assertEqual(self.steps(b'a'), (['a', 'b', 'c'], []))

    def test_a_row_that_does_not_check_stops_the_rest(self):
        self.assertEqual(self.steps(b'not a'), (['a'], ['a']))

    def test_a_failed_producer_stops_the_rest(self):
        self.assertEqual(self.steps(b'a', b_fails=True), (['a', 'b'], ['b']))

    def test_runtime_tool(self):
        top = self.d / 'runtime'; (top / 'tools').mkdir(parents=True)
        dev = self.d / 'dev-tool'; dev.write_text('#!/bin/sh\n')
        with mock.patch.dict(os.environ, {'HAO_RUNTIME_ON_MAC': str(dev)}):
            with self.assertRaises(M['Failed']) as e:
                M['find_runtime_tool'](top)
            self.assertIn('--dev-runtime-tool', str(e.exception))
            self.assertEqual(M['find_runtime_tool'](top, dev), dev)
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop('HAO_RUNTIME_ON_MAC', None)
            with self.assertRaises(M['Failed']):
                M['find_runtime_tool'](top)
            with self.assertRaises(M['Failed']):
                M['find_runtime_tool'](top, self.d / 'missing')
            placed = top / 'tools/hao-runtime-on-mac'; placed.write_text('#!/bin/sh\n')
            self.assertEqual(M['find_runtime_tool'](top, dev), placed)


if __name__ == '__main__':
    unittest.main()
