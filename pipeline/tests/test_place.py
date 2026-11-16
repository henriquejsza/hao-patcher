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


class Mode(unittest.TestCase):
    def test_a_mach_o_is_placed_executable_and_data_is_not(self):
        with tempfile.TemporaryDirectory() as d:
            for name, data, mode in (('fat', b'\xca\xfe\xba\xbe' + bytes(8), 0o755), ('lib', b'\xcf\xfa\xed\xfe' + bytes(8), 0o755),
                                     ('dmg', b'koly' + bytes(8), 0o644)):
                src = Path(d) / ('src-' + name); src.write_bytes(data); src.chmod(0o644)
                dest = Path(d) / 'row' / name
                P['clone'](src, dest)
                self.assertEqual(dest.stat().st_mode & 0o777, mode, name)


class Unpack(unittest.TestCase):
    def test_an_archive_class_unpacks_its_payload_folder_as_the_row(self):
        import io, tarfile
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / 'rt.tar.gz'
            with tarfile.open(src, 'w:gz') as t:
                for name, data in (('top/GENERATE.md', b'g'), ('top/payload/bin/hao', b'h')):
                    info = tarfile.TarInfo(name); info.size = len(data); t.addfile(info, io.BytesIO(data))
            dest = Path(d) / 'row' / 'payload'
            P['unpack_archive'](src, dest, {'strip': 1, 'into': 'parent'})
            self.assertEqual((dest / 'bin/hao').read_bytes(), b'h')
            self.assertEqual((dest.parent / 'GENERATE.md').read_bytes(), b'g')
            self.assertFalse((dest.parent / 'top').exists())


if __name__ == '__main__':
    unittest.main()
