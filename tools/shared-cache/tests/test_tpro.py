import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.emit_cache import carry_tpro
from dyld_rebuild.exports import Refusal


class TproTests(unittest.TestCase):
    def source(self, rows):
        data = bytearray(0x2000)
        struct.pack_into('<II', data, 512, 0x1000, len(rows))
        for i, (address, size) in enumerate(rows):
            struct.pack_into('<QQ', data, 0x1000 + 16 * i, address, size)
        return data

    def test_main_records_move_after_cursor_unchanged(self):
        rows = [(0x7ff843104000, 0x4000), (0x7ffe43680000, 0x4000)]   # 26B131 main
        source, data = self.source(rows), bytearray(0x4000)
        self.assertEqual(carry_tpro(source, data, 0x3000, 0x4000), 0x3020)
        self.assertEqual(struct.unpack_from('<II', data, 512), (0x3000, 2))
        self.assertEqual([struct.unpack_from('<QQ', data, 0x3000 + 16 * i) for i in range(2)], rows)

    def test_no_records_leaves_header_alone(self):
        source, data = self.source([]), bytearray(0x4000)
        struct.pack_into('<II', data, 512, 0x1234, 0)
        self.assertEqual(carry_tpro(source, data, 0x3000, 0x4000), 0x3000)
        self.assertEqual(struct.unpack_from('<II', data, 512), (0x1234, 0))

    def test_refuses_overflow(self):
        with self.assertRaises(Refusal):
            carry_tpro(self.source([(1, 2)]), bytearray(0x4000), 0x3ff8, 0x4000)


if __name__ == '__main__':
    unittest.main()
