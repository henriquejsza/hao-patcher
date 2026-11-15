import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.objc_transfer import Reader

SELBASE, LIST = 0x10000, 0x20000


class Memory(Reader):
    def __init__(self, selector_base):
        self.selector_base = selector_base
        self.mem = bytearray(0x30000)

    def read(self, address, size):
        return bytes(self.mem[address:address + size])

    def put(self, address, value):
        self.mem[address:address + len(value)] = value


def fixture(flags, selector_base=SELBASE):
    m = Memory(selector_base)
    m.put(SELBASE + 0x10, b'peerSignalStrength\0')
    m.put(SELBASE + 0x40, b'@16@0:8\0')
    entry = LIST + 8
    # 26B131 small list 0x7ffa20087190: flags 0xe000000f, sel and types both selector-base offsets
    m.put(LIST, struct.pack('<II', flags, 1) + struct.pack('<iii', 0x10, 0x40, 0x1000 - (entry + 8)))
    return m


class MethodTypeOffsetTests(unittest.TestCase):
    def test_types_are_selector_base_offsets_when_flagged(self):
        rows = fixture(0xe000000f).methods(LIST)['entries']
        self.assertEqual(rows, [{'selector': 'peerSignalStrength', 'types': '@16@0:8', 'imp': hex(0x1000)}])

    def test_flag_needs_a_cache_reader(self):
        with self.assertRaises(Refusal):
            fixture(0xe000000f, selector_base=None).methods(LIST)

    def test_unknown_bit_still_refused(self):
        with self.assertRaises(Refusal):
            fixture(0xf000000f).methods(LIST)


if __name__ == '__main__':
    unittest.main()
