import runpy
import struct
from pathlib import Path
import unittest

TOOL = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/finalize-no-loaders.py'), run_name='test')


class NoLoaderTests(unittest.TestCase):
    def test_clears_only_the_five_loader_fields(self):
        main = bytearray(range(256)) * 4
        before = bytes(main)
        # 26B131's main: set, program pool, pool size, program trie, trie size
        struct.pack_into('<4QI', main, 328, 0x7ffe86b8ae00, 0x7ffe873af150, 0x5370000, 0x7ffe8c71f150, 0x46180)
        old = TOOL['clear_loader_fields'](main)
        self.assertEqual(old, (0x7ffe86b8ae00, 0x7ffe873af150, 0x5370000, 0x7ffe8c71f150, 0x46180))
        self.assertEqual(bytes(main[328:364]), bytes(36))
        self.assertEqual(main[:328], before[:328])
        self.assertEqual(main[364:], before[364:])   # osVersion and later untouched


if __name__ == '__main__':
    unittest.main()
