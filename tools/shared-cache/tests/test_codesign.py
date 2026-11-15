import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dyld_rebuild import codesign
from dyld_rebuild.exports import Refusal


def fixture():
    data = bytearray(8192)
    data[:16] = b"dyld_v1  x86_64\0"
    struct.pack_into("<I", data, 16, 552)
    struct.pack_into("<QQ", data, 40, 8192, 16384)
    struct.pack_into("<Q", data, 560, 4096)
    return data + codesign.emit(data, 8192, "fixture", 4096)


class SignatureTests(unittest.TestCase):
    def test_full_signature_and_required_fields(self):
        value = codesign.inspect(fixture())
        self.assertEqual(value["identifier"], "fixture")
        self.assertEqual(value["pages"], 2)
        self.assertEqual(value["text_size"], 4096)

    def test_content_corruption(self):
        data = fixture()
        data[5000] ^= 1
        with self.assertRaisesRegex(Refusal, "page hash"):
            codesign.inspect(data)

    def test_cms_not_forged(self):
        data = fixture()
        cms = struct.unpack_from(">I", data, 8192 + 32)[0]
        struct.pack_into(">I", data, 8192 + cms, 0xfade0b02)
        with self.assertRaisesRegex(Refusal, "CMS"):
            codesign.inspect(data)

    def test_unknown_version_flags_hash_page_platform(self):
        for offset in (8, 12, 36, 37, 38, 39):
            data = fixture()
            data[8192 + 36 + offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(Refusal):
                codesign.inspect(data)

    def test_unknown_fields_and_padding(self):
        for offset in [8192 + 36 + 44, 8192 + 36 + 48, 8192 + 36 + 56, 8192 + 36 + 80, len(fixture()) - 1]:
            data = fixture()
            data[offset] = 1
            with self.subTest(offset=offset), self.assertRaises(Refusal):
                codesign.inspect(data)

    def test_requirements_hash(self):
        data = fixture()
        hashes = struct.unpack_from(">I", data, 8192 + 36 + 16)[0]
        data[8192 + 36 + hashes - 64] ^= 1
        with self.assertRaisesRegex(Refusal, "requirements hash"):
            codesign.inspect(data)

    def test_exec_segment_limit(self):
        data = fixture()
        struct.pack_into(">Q", data, 8192 + 36 + 72, 8192)
        with self.assertRaisesRegex(Refusal, "exec segment"):
            codesign.inspect(data)

    def test_signature_coverage(self):
        data = fixture()
        struct.pack_into(">I", data, 8192 + 36 + 32, 4096)
        with self.assertRaisesRegex(Refusal, "coverage"):
            codesign.inspect(data)

    def test_child_overlap_and_duplicate_index(self):
        for offset, value in ((8192 + 24, 36), (8192 + 20, 0)):
            data = fixture()
            struct.pack_into(">I", data, offset, value)
            with self.subTest(offset=offset), self.assertRaises(Refusal):
                codesign.inspect(data)

    def test_unaligned_and_huge_code_limits(self):
        for limit in (0, 4097, 2**32):
            with self.subTest(limit=limit), self.assertRaises(Refusal):
                codesign.geometry(limit, "fixture")

    def test_atomic_publication_never_overwrites_empty_directory(self):
        spec = importlib.util.spec_from_file_location("relayout_cli", ROOT / "tools/relayout-cache.py")
        cli = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cli)
        with tempfile.TemporaryDirectory() as tmp:
            source, target = Path(tmp) / "source", Path(tmp) / "target"
            source.mkdir()
            target.mkdir()
            (source / "keep").write_text("source")
            with self.assertRaises(FileExistsError):
                cli.publish(source, target)
            self.assertTrue((source / "keep").exists())
            self.assertEqual(list(target.iterdir()), [])



if __name__ == "__main__":
    unittest.main()
