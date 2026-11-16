import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.objc_tables import optimization_roots

BASE, LEGACY = 0x7ff800000000, 0x7ff8035043b0
# 26B131 (262FA161) values: global v4 header fields and libobjc's legacy header (selopt offset 0)
FIELDS = [4, 6, 0x218d6a00, 0x43108000, 0x268671b8, 0x276a75d8, 0x27c91720, 0x218f9978, 0x26128e68, 0]
TAIL = bytes.fromhex('14829c020000000035b8d10300000000f0f48204000000000000000000000000'
                     '59fb630000000000d4c4720000000000394c73000000000068998f2100000000')


def legacy(selopt):
    rel = lambda field: BASE + field - LEGACY
    return struct.pack('<II8iq', 16, 6, selopt, rel(FIELDS[2]), 0, 0, rel(FIELDS[3]), 0, rel(FIELDS[5]), rel(FIELDS[6]),
                       rel(FIELDS[7]))


class ObjcHeaderV4Tests(unittest.TestCase):
    def setUp(self):
        self.original = struct.pack('<II8Q', *FIELDS) + TAIL
        self.targets = {k: BASE + 0x50000000 + i * 0x1000 for i, k in enumerate(('ro', 'rw', 'selector', 'class', 'protocol'))}

    def test_v4_roots_move_tail_and_legacy_selopt_stay(self):
        new, new_legacy = optimization_roots(self.original, legacy(0), BASE, LEGACY, self.targets)
        self.assertEqual(len(new), 136)
        self.assertEqual(new[72:], TAIL)
        fields = struct.unpack('<II8Q', new[:72])
        self.assertEqual([BASE + fields[i] for i in (2, 3, 4, 5, 6)], [self.targets[k] for k in ('ro', 'rw', 'selector', 'class', 'protocol')])
        self.assertEqual(fields[7:], tuple(FIELDS[7:]))
        old = struct.unpack('<II8iq', new_legacy)
        self.assertEqual(old[2], 0)
        self.assertEqual(LEGACY + old[3], self.targets['ro'])

    def test_v2_still_requires_matching_legacy_selector(self):
        v2 = struct.pack('<II8Q', 2, 6, *FIELDS[2:])
        with self.assertRaises(Refusal):
            optimization_roots(v2, legacy(0), BASE, LEGACY, self.targets)

    def test_unknown_size_refused(self):
        with self.assertRaises(Refusal):
            optimization_roots(self.original[:100], legacy(0), BASE, LEGACY, self.targets)


if __name__ == '__main__':
    unittest.main()
