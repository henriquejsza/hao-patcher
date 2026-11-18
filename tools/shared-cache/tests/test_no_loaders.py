import runpy
import struct
from pathlib import Path
import unittest

TOOL = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'tools/finalize-no-loaders.py'), run_name='test')


class NoLoaderTests(unittest.TestCase):
    def test_clears_only_the_five_loader_fields(self):
        main = bytearray(range(256)) * 4
        struct.pack_into('<Q', main, 224, 0x7ff800000000)   # sharedRegionStart
        before = bytes(main)
        # 26B131's main: set, program pool, pool size, program trie, trie size
        struct.pack_into('<4QI', main, 328, 0x7ffe86b8ae00, 0x7ffe873af150, 0x5370000, 0x7ffe8c71f150, 0x46180)
        old = TOOL['clear_loader_fields'](main)
        self.assertEqual(old, (0x7ffe86b8ae00, 0x7ffe873af150, 0x5370000, 0x7ffe8c71f150, 0x46180))
        # the dylibs set points at the cache base (dyld adds the slide and calls validHeader without a null check;
        # 0 faulted launchd on 26B131), the program pool and trie are 0
        self.assertEqual(struct.unpack_from('<4QI', main, 328), (0x7ff800000000, 0, 0, 0, 0))
        self.assertNotEqual(bytes(main[328:336]), bytes(8))
        self.assertEqual(main[:328], before[:328])
        self.assertEqual(main[364:], before[364:])   # osVersion and later untouched

    def test_refuses_a_header_without_a_base(self):
        main = bytearray(1024)
        with self.assertRaises(BaseException):
            TOOL['clear_loader_fields'](main)


if __name__ == '__main__':
    unittest.main()
