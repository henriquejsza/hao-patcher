"""pipeline/place: a made-on-Mac file that is a plain copy out of another row is copied once that row checks."""
from pathlib import Path
import runpy
import tempfile
import types
import unittest

TOP = Path(__file__).resolve().parents[2]
P = runpy.run_path(str(TOP / 'pipeline' / 'place'))

COPY = {'path': 'iCBE-real.dylib', 'from_row': 'src', 'path_in_row': 'a/iCBE.dylib'}
MADE = {'path': 'stubs', 'from_row': 'src', 'producer': 'tools/hao-embed'}


class Place(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        self.root = Path(self.d.name)
        self.src, self.dest = self.root / 'src', self.root / 'dest'
        self.dest.mkdir()
        self.checked = []
        g = P['copy_made'].__globals__   # the functions' own globals (run_path returns a copy)
        self.saved = {k: g[k] for k in ('CLASSES', 'find_row', 'lock')}
        g['CLASSES'] = {'row': {'made_on_mac_files': [COPY, MADE]}}
        g['find_row'] = lambda folders, name: (self.root, 'x', self.src)
        g['lock'] = types.SimpleNamespace(path=lambda folder, name: self.checked.append(name))

    def tearDown(self):
        P['copy_made'].__globals__.update(self.saved)
        self.d.cleanup()

    def test_the_copy_waits_while_its_source_row_is_not_in_place(self):
        pending = P['copy_made']([], 'row', self.dest)
        self.assertEqual(pending, [COPY])
        self.assertFalse((self.dest / 'iCBE-real.dylib').exists())

    def test_the_copy_is_made_byte_for_byte_once_the_source_row_checks(self):
        (self.src / 'a').mkdir(parents=True)
        (self.src / 'a/iCBE.dylib').write_bytes(b'repaired')
        self.assertEqual(P['copy_made']([], 'row', self.dest), [])
        self.assertEqual((self.dest / 'iCBE-real.dylib').read_bytes(), b'repaired')
        self.assertEqual(self.checked, ['src'])
        self.assertFalse((self.dest / 'stubs').exists(), 'a producer file is never copied')

    def test_labels_name_the_producer_or_the_source_row(self):
        self.assertEqual(P['made_label'](MADE), 'tools/hao-embed')
        self.assertEqual(P['made_label'](COPY), 'a copy out of row src')


if __name__ == '__main__':
    unittest.main()
