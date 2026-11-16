import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dyld_rebuild.slides import SlideInfoV2
from dyld_rebuild.exports import Refusal

BASE = 0x7ff800000000
DELTA = 0xffff0000000000


def fixture():
    info = bytearray(struct.pack("<6I2Q2H", 2, 4096, 40, 2, 0, 0, DELTA, BASE, 4, 0x4000))
    data = bytearray(8192)
    struct.pack_into("<Q", data, 16, (8 << 38) | 0x1000)
    struct.pack_into("<Q", data, 24, 0x2000)
    return info, data


def read(info, data):
    return SlideInfoV2(info, data, 0, len(data))


class SlideTests(unittest.TestCase):
    def test_existing_chain_and_retarget_preserve_next_delta(self):
        slide = read(*fixture())
        self.assertEqual(slide.pointer(16)["target"], BASE + 0x1000)
        raw = slide.retarget(16, BASE + 0x1000, BASE + 0x3000)
        self.assertEqual(raw & DELTA, 8 << 38)
        self.assertEqual(slide.decode(raw), BASE + 0x3000)
        self.assertEqual(slide.pointer(24)["next_delta"], 0)

    def test_null_preserves_chain(self):
        slide = read(*fixture())
        raw = slide.retarget(16, BASE + 0x1000, 0)
        self.assertEqual(raw, 8 << 38)
        self.assertEqual(slide.decode(raw), 0)

    def test_pointer_must_be_chain_member(self):
        slide = read(*fixture())
        for offset in (0, 20, 32, 4096, 8192):
            with self.subTest(offset=offset), self.assertRaises(Refusal):
                slide.pointer(offset)

    def test_original_target_and_encoding_refusals(self):
        slide = read(*fixture())
        for old, new, message in [(BASE + 1, BASE + 0x3000, "original"),
                                  (BASE + 0x1000, BASE, "as null"),
                                  (BASE + 0x1000, BASE + (1 << 40), "representable")]:
            with self.subTest(message=message), self.assertRaisesRegex(Refusal, message):
                slide.retarget(16, old, new)

    def test_version_counts_extras_and_mask(self):
        for offset, value, fmt, message in [(0, 3, "I", "version"), (4, 16384, "I", "page size"),
                                            (12, 1, "I", "count"), (16, 40, "I", "extras"),
                                            (24, 0, "Q", "mask"), (24, 0x500, "Q", "mask"),
                                            (40, 0x8000, "H", "page start")]:
            info, data = fixture()
            struct.pack_into("<" + fmt, info, offset, value)
            with self.subTest(offset=offset, value=value), self.assertRaisesRegex(Refusal, message):
                read(info, data)

    def test_overlapping_and_page_crossing_chain(self):
        info, data = fixture()
        struct.pack_into("<Q", data, 16, (4 << 38) | 0x1000)
        with self.assertRaisesRegex(Refusal, "overlapping"):
            read(info, data).pointer(16)
        struct.pack_into("<Q", data, 16, (4096 << 38) | 0x1000)
        with self.assertRaisesRegex(Refusal, "crosses"):
            read(info, data).pointer(16)


if __name__ == "__main__":
    unittest.main()
