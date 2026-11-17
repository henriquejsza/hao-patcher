"""tools/tahoe-donors/cache-dylib is a pinned copy: its committed tree is the one cache-dylib.pin names.
python3.14 -I -B -m unittest discover -s tools/tahoe-donors/tests"""
import shutil, subprocess, unittest
from pathlib import Path

UNIT = Path(__file__).resolve().parents[1]
TOP = UNIT.parents[1]


@unittest.skipUnless(shutil.which('git') and (TOP/'.git').exists(), 'needs a git checkout')
class Pin(unittest.TestCase):
    def test_the_committed_copy_is_the_pinned_tree(self):
        tree = (UNIT/'cache-dylib.pin').read_text().split()[-1]
        head = subprocess.run(['git', '-C', str(TOP), 'rev-parse', 'HEAD:tools/tahoe-donors/cache-dylib'],
                              capture_output=True, text=True).stdout.strip()
        self.assertEqual(head, tree)


if __name__ == '__main__':
    unittest.main()
