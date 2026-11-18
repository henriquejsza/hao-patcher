"""pipeline/make-on-mac: a local download is used only with its row's sha256 (and keeps the release's pins), the first
failed producer or output check stops the run, and the runtime tool is the archive's or an explicit flag's."""
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
        self.assertNotEqual(src, self.ipsw)
        self.assertEqual(src.read_bytes(), b'ipsw bytes')
        self.assertEqual(extra[0], '--pins')
        self.assertEqual(json.loads(Path(extra[1]).read_text()), self.pins)
        src, extra = self.stream()
        self.assertEqual((src.read_bytes(), extra), (b'ipsw bytes', []))

    def test_pins_are_kept_for_a_download_that_is_not_streamed(self):
        release = {'downloads': [dict(self.release['downloads'][0], stream=False)]}
        src, extra = self.stream(release)
        self.assertEqual(src.read_bytes(), b'ipsw bytes')
        self.assertEqual(json.loads(Path(extra[1]).read_text()), self.pins)
        self.ipsw.write_bytes(b'other bytes')
        with self.assertRaises(M['Failed']):
            self.stream(release)      # never by its URL: only a streamed download is read by range

    def test_the_producer_reads_the_checked_snapshot_not_the_local_path(self):
        r = self.run_(self.release)
        with redirect_stdout(io.StringIO()):
            src, extra = r.stream('ipsw_27_0')
        with open(self.ipsw, 'r+b') as f:      # whoever can write the local file changes it after the check
            f.write(b'evil')
        self.assertEqual(self.ipsw.read_bytes(), b'evil bytes')
        self.assertEqual(src.read_bytes(), b'ipsw bytes')
        st = src.lstat()
        self.assertEqual((st.st_uid, st.st_nlink, st.st_mode & 0o777), (os.geteuid(), 1, 0o400))
        self.assertTrue(src.parent.is_relative_to(self.work))
        r.close()
        self.assertFalse(src.parent.exists())

    def test_a_snapshot_is_copied_where_no_clone_can_be_made(self):
        r = self.run_(self.release)
        g = M['Run'].snapshot.__globals__
        failed = mock.Mock(return_value=mock.Mock(returncode=1))
        with mock.patch.dict(g, subprocess=mock.Mock(run=failed)), redirect_stdout(io.StringIO()):
            src, extra = r.stream('ipsw_27_0')
        self.assertTrue(failed.called)
        self.assertEqual(src.read_bytes(), b'ipsw bytes')
        r.close()

    def test_a_snapshot_is_made_only_in_a_folder_no_one_else_can_write(self):
        self.assertTrue(M['private_base'](self.work))
        os.chmod(self.work, 0o777)
        self.assertFalse(M['private_base'](self.work))
        os.chmod(self.work, 0o1777)
        self.assertTrue(M['private_base'](self.work))
        os.chmod(self.work, 0o700)
        os.chmod(self.d, 0o777)
        try:
            self.assertFalse(M['private_base'](self.work), 'a folder above that others can write')
            r = self.run_(self.release)
            with redirect_stdout(io.StringIO()):
                src, extra = r.stream('ipsw_27_0')
            self.assertFalse(src.is_relative_to(self.d))
            self.assertTrue(src.is_relative_to(os.path.realpath(tempfile.gettempdir())) or
                            src.is_relative_to(tempfile.gettempdir()))
            r.close()
        finally:
            os.chmod(self.d, 0o700)

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
