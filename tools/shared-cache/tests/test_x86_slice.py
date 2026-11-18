"""run_loaders.has_x86_64: 27's x86_64 cache carries sets for programs the System ships arm64-only; those are retired."""
from pathlib import Path
import struct
import sys
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild.run_loaders import has_x86_64


def fat(*cputypes, wide=False):
    data = struct.pack('>II', 0xcafebabf if wide else 0xcafebabe, len(cputypes))
    for cpu in cputypes:
        data += struct.pack('>IIQQII', cpu, 3, 0, 0, 14, 0) if wide else struct.pack('>IIIII', cpu, 3, 0, 0, 14)
    return data


class Slices(unittest.TestCase):
    def test_fat_and_thin(self):
        self.assertTrue(has_x86_64(fat(0x0100000c, 0x01000007)))          # arm64 + x86_64
        self.assertTrue(has_x86_64(fat(0x01000007, wide=True)))
        self.assertFalse(has_x86_64(fat(0x0100000c)))                       # arm64e only: retired
        self.assertTrue(has_x86_64(struct.pack('<II', 0xfeedfacf, 0x01000007)))
        self.assertFalse(has_x86_64(struct.pack('<II', 0xfeedfacf, 0x0100000c)))
        self.assertFalse(has_x86_64(b'#!/bin/sh\n'))


if __name__ == '__main__':
    unittest.main()
