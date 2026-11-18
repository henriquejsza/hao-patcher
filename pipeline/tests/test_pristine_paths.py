"""pipeline/stages/pristine.sh: a data-symlinks.tsv path that would leave the Data volume (absolute, or with a
. or .. part) stops the stage before anything is removed or linked. The stage runs in the builder VM, so its loop is run
here on a scratch folder with rm, mkdir and ln as they are. A path whose folders go through a link (one an earlier
line made) stops it too."""
from pathlib import Path
import re
import subprocess
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]


def loop():
    text = (TOP / 'pipeline/stages/pristine.sh').read_text()
    m = re.search(r'n=0; (while IFS=.*?done < \$S/data-symlinks.tsv)', text)
    return m.group(1)


class DataSymlinks(unittest.TestCase):
    def run_loop(self, lines):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            data, outside = d / 'data', d / 'outside'
            data.mkdir(); outside.mkdir(); (outside / 'keep').write_text('k')
            (d / 'data-symlinks.tsv').write_text(''.join('%s\t%s\n' % l for l in lines))
            r = subprocess.run(['sh', '-c', 'S=%s; D=%s; n=0; %s; echo "symlinks=$n"' % (d, data, loop())],
                               capture_output=True, text=True)
            return r, (outside / 'keep').exists(), sorted(p.name for p in data.rglob('*'))

    def test_paths_inside_data_are_linked(self):
        r, kept, made = self.run_loop([('Library/a b', '../../System/x'), ('Users/Shared/y', 'z')])
        self.assertEqual(r.returncode, 0, r.stdout)
        self.assertIn('symlinks=2', r.stdout)
        self.assertIn('a b', made)

    def test_a_path_that_leaves_data_stops_the_stage(self):
        for bad in ('../outside', 'Library/../../outside', '/etc/x', './x', 'a/./b'):
            with self.subTest(path=bad):
                r, kept, made = self.run_loop([('Library/ok', 't'), (bad, 'evil')])
                self.assertNotEqual(r.returncode, 0)
                self.assertIn('SYMLINK-PATH-OUTSIDE', r.stdout)
                self.assertTrue(kept, 'nothing outside Data is removed')
                self.assertNotIn('symlinks=', r.stdout)


    def test_a_path_through_a_link_made_by_an_earlier_line_stops_the_stage(self):
        r, kept, made = self.run_loop([('escape', '../outside'), ('escape/keep', 'evil')])
        self.assertNotEqual(r.returncode, 0)
        self.assertIn('SYMLINK-PATH-OUTSIDE escape/keep (through escape)', r.stdout)
        self.assertTrue(kept, 'nothing outside Data is removed')

    def test_a_path_through_a_link_deeper_down_stops_too(self):
        r, kept, made = self.run_loop([('a/b', '../../outside'), ('a/b/c/keep', 'evil')])
        self.assertNotEqual(r.returncode, 0)
        self.assertTrue(kept)


if __name__ == '__main__':
    unittest.main()
