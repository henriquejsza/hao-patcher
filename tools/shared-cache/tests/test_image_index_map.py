import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.swift_refs import checked_index_map, image_index_map

IO = '/System/Library/PrivateFrameworks/IO80211.framework/Versions/A/IO80211'


class ImageIndexMapTests(unittest.TestCase):
    def test_dropped_replaced_image_gets_no_index(self):
        mapping = image_index_map(['/a', IO, '/b'], ['/a', '/b', '/new'], dropped={IO})
        self.assertEqual(mapping, {0: 0, 2: 1})
        with self.assertRaises(Refusal):       # any later use of IO80211's old index is refused
            checked_index_map(mapping, [1])

    def test_missing_without_dropped_still_refused(self):
        with self.assertRaises(Refusal):
            image_index_map(['/a', IO], ['/a'])
        with self.assertRaises(Refusal):       # a dropped image cannot also be in the final list
            image_index_map(['/a', IO], ['/a', IO], dropped={IO})


if __name__ == '__main__':
    unittest.main()
