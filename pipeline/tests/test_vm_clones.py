"""pipeline/vm/clones.py's ownership check: a clone survives its store being moved within the volume with a symlink at
the old path (a store move, 2026-11-14), and a marker copied somewhere else is still refused. Fixtures only: no VM."""
import json
import os
import runpy
import shutil
import tempfile
import unittest
from pathlib import Path

C = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'vm' / 'clones.py'))


class OwnedTest(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()).resolve()
        self.old = self.tmp / 'old' / 'store'
        root = self.old / 'vm'
        vm = root / 'c1' / 'vm'
        (root / 'c1' / 'share').mkdir(parents=True)
        vm.mkdir()
        self.marker = {'schema': 1, 'name': 'c1', 'root': str(root), 'vm': str(vm), 'share': str(root / 'c1' / 'share'),
                       'base': str(self.tmp / 'base' / 'vm')}
        (vm / C['MARKER']).write_text(json.dumps(self.marker))
        (root / 'registry.json').write_text(json.dumps({'c1': self.marker}))

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def test_owned_in_place(self):
        self.assertEqual(C['owned'](self.old / 'vm' / 'c1' / 'vm'), self.marker)

    def test_owned_after_the_store_moved_with_a_symlink(self):
        new = self.tmp / 'new' / 'store'
        new.parent.mkdir()
        os.rename(self.old, new)
        os.symlink(new, self.old)
        self.assertEqual(C['owned'](self.old / 'vm' / 'c1' / 'vm'), self.marker)   # by the old path
        self.assertEqual(C['owned'](new / 'vm' / 'c1' / 'vm'), self.marker)        # by the new one

    def test_a_copied_clone_is_still_refused(self):
        copy = self.old / 'vm' / 'c2'
        shutil.copytree(self.old / 'vm' / 'c1', copy)
        with self.assertRaises(ValueError) as x:
            C['owned'](copy / 'vm')
        self.assertIn('copied or invalid clone marker', str(x.exception))


if __name__ == '__main__':
    unittest.main()
