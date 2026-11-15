"""Refusal and resolution tests; real binaries get a separate Apple-tool oracle."""
import importlib.util
from pathlib import Path
import struct
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dyld_rebuild.exports import Dependency, Export, Image, Refusal, read_image, read_trie, resolve, uleb

spec = importlib.util.spec_from_file_location("audit", ROOT / "tools/audit-providers.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def leaf(terminal, name=b"_x"):
    # One root edge, one terminal. Child offset is a single-byte ULEB.
    return b"\0\1" + name + b"\0" + bytes([len(name) + 4, len(terminal)]) + terminal + b"\0"


def image(exports=None, deps=None):
    return Image("fixture", deps or [], exports or {})


class TrieTests(unittest.TestCase):
    def test_regular_and_weak(self):
        self.assertEqual(read_trie(leaf(b"\0\x42"))["_x"], Export(0, 0x42))
        self.assertEqual(read_trie(leaf(b"\4\x42"))["_x"], Export(4, 0x42))

    def test_explicit_and_renamed_reexport(self):
        self.assertEqual(read_trie(leaf(b"\x08\x02\0"))["_x"], Export(8, ordinal=2))
        self.assertEqual(read_trie(leaf(b"\x08\x02_y\0"))["_x"],
                         Export(8, ordinal=2, imported_name="_y"))

    def test_resolver_metadata_retained(self):
        self.assertEqual(read_trie(leaf(b"\x10\x42\x43"))["_x"], Export(16, 0x42, extra=0x43))

    def test_max_uleb(self):
        self.assertEqual(uleb(b"\xff" * 9 + b"\1", 0), (2**64 - 1, 10))

    def test_malformed_uleb(self):
        for value in [b"\x80", b"\xff" * 10, b"\xff" * 9 + b"\2"]:
            with self.subTest(value=value), self.assertRaises(Refusal):
                uleb(value, 0)

    def test_every_truncation(self):
        data = leaf(b"\0\x42")
        for size in range(1, len(data)):
            with self.subTest(size=size), self.assertRaises(Refusal):
                read_trie(data[:size])

    def test_cycle_and_out_of_range(self):
        for data in [b"\0\1_x\0\0", b"\0\1_x\0\x7f"]:
            with self.subTest(data=data), self.assertRaises(Refusal):
                read_trie(data)

    def test_unknown_flags_and_trailing_terminal(self):
        for terminal in [b"\x40\1", b"\3\1", b"\0\1\0", b"\x38\1\0"]:
            with self.subTest(terminal=terminal), self.assertRaises(Refusal):
                read_trie(leaf(terminal))


class ResolverTests(unittest.TestCase):
    def test_self_shadows_reexport(self):
        images = {"shim": image({"x": Export(0, 10)}, [Dependency("old", 0x8000001f)]),
                  "old": image({"x": Export(0, 20)})}
        self.assertEqual(resolve(images, "shim", "x")["provider"], "shim")

    def test_regular_dependency_not_a_provider(self):
        images = {"shim": image(deps=[Dependency("old", 0xc)]), "old": image({"x": Export(0, 20)})}
        self.assertEqual(resolve(images, "shim", "x")["status"], "missing_symbol")

    def test_ordered_reexports(self):
        images = {"shim": image(deps=[Dependency("first", 0x8000001f), Dependency("second", 0x8000001f)]),
                  "first": image({"x": Export(4, 10)}), "second": image({"x": Export(0, 20)})}
        self.assertEqual(resolve(images, "shim", "x")["provider"], "first")

    def test_missing_earlier_provider_is_not_skipped(self):
        images = {"shim": image(deps=[Dependency("absent", 0x8000001f), Dependency("old", 0x8000001f)]),
                  "old": image({"x": Export(0, 20)})}
        self.assertEqual(resolve(images, "shim", "x")["status"], "missing_input")

    def test_explicit_ordinal_name_and_reexport_chain(self):
        images = {"shim": image({"x": Export(8, ordinal=2, imported_name="y")},
                                [Dependency("absent", 0xc), Dependency("old", 0xc)]),
                  "old": image(deps=[Dependency("leaf", 0x8000001f)]),
                  "leaf": image({"y": Export(0, 99)})}
        self.assertEqual(resolve(images, "shim", "x"),
                         {"status": "resolved", "provider": "leaf", "symbol": "y", "input_offset": "0x63", "flags": 0})

    def test_no_ordinal_guess(self):
        with self.assertRaisesRegex(Refusal, "ordinal"):
            resolve({"shim": image({"x": Export(8, ordinal=0)})}, "shim", "x")

    def test_cycles_refuse(self):
        images = {"a": image(deps=[Dependency("b", 0x8000001f)]),
                  "b": image(deps=[Dependency("a", 0x8000001f)])}
        with self.assertRaisesRegex(Refusal, "cycle"):
            resolve(images, "a", "x")

    def test_special_kinds_never_become_ordinary_binds(self):
        for flag in [1, 2, 16, 32]:
            with self.subTest(flag=flag):
                self.assertEqual(resolve({"a": image({"x": Export(flag, 10)})}, "a", "x")["status"],
                                 "unsupported_kind")


class BoundaryTests(unittest.TestCase):
    def test_wrong_architecture(self):
        header = struct.pack("<8I", 0xfeedfacf, 0x100000c, 0, 6, 0, 0, 0, 0)
        with self.assertRaisesRegex(Refusal, "x86_64"):
            read_image(header)

    def test_fat_slice_bounds(self):
        data = struct.pack(">7I", 0xcafebabe, 1, 0x1000007, 3, 0x1000, 32, 0) + bytes(32)
        with self.assertRaisesRegex(Refusal, "range"):
            read_image(data)

    def test_load_command_size(self):
        header = struct.pack("<8I", 0xfeedfacf, 0x1000007, 3, 6, 1, 8, 0, 0)
        with self.assertRaisesRegex(Refusal, "size"):
            read_image(header + struct.pack("<II", 0xd, 0))

    def test_new_dylib_use_flags_refuse(self):
        command = struct.pack("<7I", 0xc, 32, 28, 0x1a741800, 0, 0, 2) + b"foo\0"
        header = struct.pack("<8I", 0xfeedfacf, 0x1000007, 3, 6, 1, len(command), 0, 0)
        with self.assertRaisesRegex(Refusal, "dylib_use"):
            read_image(header + command)

    def test_input_hash_and_path_refusals(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "input").write_bytes(b"data")
            with self.assertRaisesRegex(Refusal, "hash"):
                audit.verify_input(root, {"path": "input", "size": 4, "sha256": "0" * 64})
            with self.assertRaisesRegex(Refusal, "escapes"):
                audit.verify_input(root, {"path": "../outside", "size": 4, "sha256": "0" * 64})

    def test_got_uses_preserved_and_self_uses_removed(self):
        rows = audit.patch_uses("[PATCHES] /Metal\t(1 symbols)\n0x100: _x\n    0x200: PATCH  Metal\n    0x300: GOT \n    0x400: PATCH  Other\n", "/Metal")
        self.assertEqual([r["location"] for r in rows], ["0x300", "0x400"])

    def test_patch_listing_drift_refuses(self):
        for text in ["[PATCHES] /Metal (2 symbols)\n0x100: _x\n",
                     "[PATCHES] /Metal (1 symbols)\n0x100: _x\n  0x200: UNKNOWN\n"]:
            with self.subTest(text=text), self.assertRaises(Refusal):
                audit.patch_uses(text, "/Metal")


if __name__ == "__main__":
    unittest.main()
