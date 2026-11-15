"""Synthetic layout/refusal checks; real inputs have a separate Apple oracle."""
import hashlib
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dyld_rebuild.exports import Refusal
from dyld_rebuild.provider_identity import inspect, normalize, signature_pages, verify_normalized, x86_slice

SPEC = importlib.util.spec_from_file_location("normalize_provider_tool", ROOT / "tools/normalize-provider.py")
TOOL = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(TOOL)


def dylib(name="Wrapped/LibSystemShim.dylib", padding=128):
    ident_size = (24 + len(name) + 1 + 7) & ~7
    ident = struct.pack("<6I", 0xd, ident_size, 24, 1, 2, 3)
    ident += name.encode() + bytes(ident_size - 24 - len(name))
    section_offset = 32 + 152 + len(ident) + padding
    size = section_offset + 16
    segment = struct.pack("<II16sQQQQiiII", 0x19, 152, b"__TEXT", 0, size,
                          0, size, 5, 5, 1, 0)
    section = struct.pack("<16s16sQQIIIIIIII", b"__text", b"__TEXT", section_offset,
                          16, section_offset, 0, 0, 0, 0x80000400, 0, 0, 0)
    header = struct.pack("<8I", 0xfeedfacf, 0x1000007, 3, 6, 2, 152 + len(ident), 0x85, 0)
    return header + segment + section + ident + bytes(padding) + b"payload-constant"


def universal(thin, wide=False):
    first = 4096
    second = 8192
    other = b"another-architecture" + bytes(128)
    if wide:
        table = struct.pack(">II", 0xcafebabf, 2)
        table += struct.pack(">IIQQII", 0x1000007, 3, first, len(thin), 12, 0)
        table += struct.pack(">IIQQII", 0x100000c, 0, second, len(other), 12, 0)
    else:
        table = struct.pack(">II", 0xcafebabe, 2)
        table += struct.pack(">IIIII", 0x1000007, 3, first, len(thin), 12)
        table += struct.pack(">IIIII", 0x100000c, 0, second, len(other), 12)
    return table + bytes(first - len(table)) + thin + bytes(second - first - len(thin)) + other


def signed_dylib():
    data = bytearray(dylib(padding=72))
    end = inspect(data)["command_end"]
    size = 96
    data[end:end + 16] = struct.pack("<4I", 0x1d, 16, len(data), size)
    struct.pack_into("<II", data, 16, 3, end - 32 + 16)
    directory = struct.pack(">9I4BI", 0xfade0c02, 76, 0x20000, 0, 44, 0, 0, 1,
                            len(data), 32, 2, 0, 12, 0) + hashlib.sha256(data).digest()
    return bytes(data) + struct.pack(">5I", 0xfade0cc0, size, 1, 0, 20) + directory


class IdentityTests(unittest.TestCase):
    canonical = "/System/Library/PrivateFrameworks/WiFiPeerToPeer.framework/Versions/A/LibSystemShim.dylib"

    def test_header_growth_preserves_all_payload_bytes_and_command_fields(self):
        before = dylib()
        after, plan = normalize(before, "Wrapped/LibSystemShim.dylib", self.canonical)
        first = inspect(before)["first_payload"]
        self.assertEqual(len(before), len(after))
        self.assertEqual(before[first:], after[first:])
        self.assertEqual(plan["command_growth"], 64)
        self.assertEqual(inspect(after)["identity"]["name"], self.canonical)
        # Unchanged segment, section, timestamp, current/compatibility version.
        self.assertEqual(before[32:184], after[32:184])
        self.assertEqual(before[196:208], after[196:208])

    def test_exact_fit_and_one_byte_short(self):
        normalize(dylib(padding=64), "Wrapped/LibSystemShim.dylib", self.canonical)
        for padding in (0, 56, 63):
            with self.subTest(padding=padding), self.assertRaisesRegex(Refusal, "insufficient"):
                normalize(dylib(padding=padding), "Wrapped/LibSystemShim.dylib", self.canonical)

    def test_fat32_and_fat64_preserve_table_other_slices_and_offsets(self):
        for wide in (False, True):
            before = universal(dylib(), wide)
            after, _ = normalize(before, "Wrapped/LibSystemShim.dylib", self.canonical)
            self.assertEqual(x86_slice(before), x86_slice(after))
            self.assertEqual(before[:4096], after[:4096])
            self.assertEqual(before[8192:], after[8192:])

    def test_source_name_drift_and_invalid_target(self):
        for old, new in (("wrong", self.canonical), ("Wrapped/LibSystemShim.dylib", "relative"),
                         ("Wrapped/LibSystemShim.dylib", "/bad\0name")):
            with self.subTest(old=old, new=new), self.assertRaises(Refusal):
                normalize(dylib(), old, new)

    def test_nonzero_header_padding(self):
        data = bytearray(dylib())
        data[inspect(data)["command_end"]] = 1
        with self.assertRaisesRegex(Refusal, "nonzero header padding"):
            inspect(data)

    def test_unknown_command_refused(self):
        data = bytearray(dylib())
        struct.pack_into("<I", data, 184, 0x7777)
        with self.assertRaisesRegex(Refusal, "unsupported load command"):
            inspect(data)

    def test_payload_overlapping_header_refused(self):
        data = bytearray(dylib())
        struct.pack_into("<I", data, 32 + 72 + 48, 32)
        with self.assertRaises(Refusal):
            inspect(data)

    def test_every_prefix_truncation_refused(self):
        data = dylib()
        for count in range(len(data)):
            with self.subTest(count=count), self.assertRaises(Refusal):
                inspect(data[:count])

    def test_bad_fat_alignment_overlap_duplicate_and_extent_refused(self):
        data = universal(dylib())
        for offset, value in ((16, 4097), (36, 4096), (28, 0x1000007), (20, 0xffffffff)):
            changed = bytearray(data)
            struct.pack_into(">I", changed, offset, value)
            if offset == 28:
                struct.pack_into(">I", changed, 32, 3)
            with self.subTest(offset=offset), self.assertRaises(Refusal):
                x86_slice(changed)

    def test_wrong_architecture(self):
        data = bytearray(dylib())
        struct.pack_into("<I", data, 4, 0x100000c)
        with self.assertRaisesRegex(Refusal, "expected x86_64"):
            inspect(data)

    def test_explicit_cache_input_removes_only_signature_command_and_preserves_blob(self):
        source = signed_dylib()
        before = inspect(source)
        self.assertEqual(signature_pages(source)["mismatching_code_slots"], [])
        with self.assertRaisesRegex(Refusal, "insufficient"):
            normalize(source, "Wrapped/LibSystemShim.dylib", self.canonical)
        output, plan = normalize(source, "Wrapped/LibSystemShim.dylib", self.canonical,
                                 remove_signature_command=True)
        self.assertEqual(plan["command_growth"], 48)
        self.assertEqual(plan["removed_commands"][0]["command"], 0x1d)
        self.assertIsNone(inspect(output)["signature"])
        self.assertEqual(source[before["first_payload"]:], output[before["first_payload"]:])
        pages = signature_pages(output, original_signature_range=before["signature"])
        self.assertFalse(pages["referenced_by_load_command"])
        self.assertEqual(pages["mismatching_code_slots"], [0])
        verify_normalized(source, output, "Wrapped/LibSystemShim.dylib", self.canonical,
                          removed_signature=True)

    def test_independent_verifier_refuses_payload_and_command_corruption(self):
        source = signed_dylib()
        output, _ = normalize(source, "Wrapped/LibSystemShim.dylib", self.canonical,
                              remove_signature_command=True)
        for offset in (inspect(output)["first_payload"], 32 + 56, 24):
            changed = bytearray(output)
            changed[offset] ^= 1
            with self.subTest(offset=offset), self.assertRaises(Refusal):
                verify_normalized(source, changed, "Wrapped/LibSystemShim.dylib", self.canonical,
                                  removed_signature=True)

    def test_cache_input_mode_refuses_absent_signature(self):
        with self.assertRaisesRegex(Refusal, "requires one original signature"):
            normalize(dylib(), "Wrapped/LibSystemShim.dylib", self.canonical,
                      remove_signature_command=True)

    def test_fat_cache_input_retains_other_slices_and_signature_blob(self):
        for wide in (False, True):
            source = universal(signed_dylib(), wide)
            output, _ = normalize(source, "Wrapped/LibSystemShim.dylib", self.canonical,
                                  remove_signature_command=True)
            verify_normalized(source, output, "Wrapped/LibSystemShim.dylib", self.canonical,
                              removed_signature=True)
            self.assertEqual(source[:4096], output[:4096])
            self.assertEqual(source[8192:], output[8192:])

    def test_pinned_input_refuses_hash_size_and_path_drift(self):
        with tempfile.TemporaryDirectory() as scratch:
            root = Path(scratch).resolve()
            (root / "inputs").mkdir()
            (root / "inputs/source").write_bytes(b"fixture")
            item = {"path": "inputs/source", "size": 7,
                    "sha256": hashlib.sha256(b"fixture").hexdigest()}
            with patch.object(TOOL, "ROOT", root):
                self.assertEqual(TOOL.pinned(item)[1], b"fixture")
                for changed in ({**item, "size": 6}, {**item, "sha256": "0" * 64},
                                {**item, "path": "../outside"}):
                    with self.subTest(item=changed), self.assertRaises(Refusal):
                        TOOL.pinned(changed)


if __name__ == "__main__":
    unittest.main()
