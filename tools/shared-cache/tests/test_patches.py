import struct
import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dyld_rebuild.patches import PatchTableV4
from dyld_rebuild.exports import Refusal

BASE = 0x100000000
ADDRESS = BASE + 0x10000
IMAGES = [("/provider", BASE), ("/client", BASE + 0x2000)]


def fixture():
    arrays = [
        struct.pack("<8I", 0, 1, 0, 1, 1, 0, 1, 0),
        struct.pack("<II", 0x100, 8 << 28),
        struct.pack("<III", 1, 0, 1),
        struct.pack("<III", 0, 0, 1),
        struct.pack("<II", 0x20, 0x100 | (42 << 9)),
        b"_thing\0",
        struct.pack("<4I", 0, 1, 1, 0),
        struct.pack("<III", 0, 0, 1),
        struct.pack("<QII", 0x4000, 0, 0),
    ]
    data = bytearray(152)
    struct.pack_into("<II", data, 0, 4, 0)
    offsets = {}
    for i, (name, size, value) in enumerate(zip(PatchTableV4.NAMES, PatchTableV4.SIZES, arrays)):
        offsets[name] = len(data)
        struct.pack_into("<QQ", data, 8 + i * 16, ADDRESS + len(data), len(value) // size)
        data += value
    return data, offsets


def read(data):
    return PatchTableV4(data, ADDRESS, IMAGES, BASE).image_uses(0)


class PatchTests(unittest.TestCase):
    def test_strength_addend_identity_and_shared_got(self):
        rows = read(fixture()[0])
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["symbol"], "_thing")
        self.assertEqual(rows[0]["implementation"], BASE + 0x100)
        self.assertEqual(rows[0]["location"], BASE + 0x2020)
        self.assertEqual(rows[0]["client"], "/client")
        self.assertEqual(rows[0]["addend"], 42)
        self.assertTrue(rows[0]["weak_import"])
        self.assertEqual(rows[0]["export_kind"], 8)
        self.assertEqual(rows[1]["location"], BASE + 0x4000)
        self.assertIsNone(rows[1]["client"])
        self.assertFalse(rows[1]["weak_import"])

    def test_version_and_truncation(self):
        data, _ = fixture()
        for changed in (data[:151], data[:-1]):
            with self.assertRaises(Refusal):
                read(changed)
        for position in (0, 4):
            changed = data.copy()
            struct.pack_into("<I", changed, position, 7)
            with self.assertRaisesRegex(Refusal, "version"):
                read(changed)

    def test_bad_arrays_counts_and_overlaps(self):
        for position, value, expected in [(8, ADDRESS + 16, "header"),
                                           (16, 3, "overlap"),
                                           (8, ADDRESS + 100000, "outside"),
                                           (16, 1, "counts")]:
            data, _ = fixture()
            struct.pack_into("<Q", data, position, value)
            with self.subTest(position=position, value=value), self.assertRaisesRegex(Refusal, expected):
                read(data)

    def test_wrong_export_owner_and_client(self):
        for name, value, expected in [("clients", 2, "client image"),
                                      ("client_exports", 1, "another image"),
                                      ("got_exports", 1, "another image")]:
            data, positions = fixture()
            struct.pack_into("<I", data, positions[name], value)
            with self.subTest(name=name), self.assertRaisesRegex(Refusal, expected):
                read(data)

    def test_out_of_bounds_subarray(self):
        data, positions = fixture()
        struct.pack_into("<I", data, positions["got_exports"] + 8, 2)
        with self.assertRaisesRegex(Refusal, "subarray"):
            read(data)

    def test_unknown_kind_and_unterminated_names(self):
        data, positions = fixture()
        struct.pack_into("<I", data, positions["exports"] + 4, 2 << 28)
        with self.assertRaisesRegex(Refusal, "kind"):
            read(data)
        data, positions = fixture()
        data[positions["names"] + 6] = 1
        with self.assertRaisesRegex(Refusal, "escapes"):
            read(data)

    def test_authenticated_got_padding_and_large_addend(self):
        for word, padding, expected in [(1, 0, "authenticated"), (0, 1, "padding")]:
            data, positions = fixture()
            struct.pack_into("<II", data, positions["got_locations"] + 8, word, padding)
            with self.subTest(word=word, padding=padding), self.assertRaisesRegex(Refusal, expected):
                read(data)
        self.assertEqual(PatchTableV4.metadata(0xfffffffe),
                         {"weak_import": True, "high8": 254, "addend": 0x7fffff})


if __name__ == "__main__":
    unittest.main()
