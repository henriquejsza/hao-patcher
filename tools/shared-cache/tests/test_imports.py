"""Import decoding/refusals and final-graph lookup semantics, using small fixtures."""
import struct
import sys
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dyld_rebuild.cache_exports import CacheDependency, FinalGraph, cached_image, export_trie, path_trie
from dyld_rebuild.exports import Dependency, Export, Image, Refusal
from dyld_rebuild.imports import Import, chained_imports, classic_imports, read_imports, resolve_import, sleb


IMAGE = Image("/self", [Dependency("/dep", 0xc)], {})
SEGMENTS = [(0x1000, 256, 0, 256)]


def trie(terminal, name=b"_x"):
    return b"\0\1" + name + b"\0" + bytes([len(name) + 4, len(terminal)]) + terminal + b"\0"


def chain(fmt=1, ordinal=1, weak=False, addend=0, symbol=b"_x\0"):
    if fmt in (1, 2):
        record = struct.pack("<I", (ordinal & 255) | (256 if weak else 0))
        if fmt == 2:
            record += struct.pack("<i", addend)
    else:
        record = struct.pack("<Qq", (ordinal & 65535) | (65536 if weak else 0), addend)
    return struct.pack("<7I", 0, 28, 28, 28 + len(record), 1, fmt, 0) + record + symbol


def graph(images, aliases=None):
    result = object.__new__(FinalGraph)
    result.providers = images
    result.cached = {}
    result.aliases = aliases or {}
    result.resolution_paths = set()
    result.reachable_cache = {}
    class Family:
        images = [("/dep", 0)]
    result.family = Family()
    return result


def complete_image(fixup_command=True, duplicate=False):
    payload = chain()
    total = 520 + len(payload)
    segment = struct.pack("<II16s4Q4I", 0x19, 72, b"__TEXT", 0, total, 0, total, 5, 5, 0, 0)
    identity = struct.pack("<6I", 0xd, 32, 24, 0, 0, 0) + b"/self\0\0\0"
    dependency = struct.pack("<6I", 0xc, 32, 24, 0, 0, 0) + b"/dep\0\0\0\0"
    export = struct.pack("<4I", 0x80000033, 16, 512, 2)
    chained = struct.pack("<4I", 0x80000034 if fixup_command else 0x2a, 16, 520, len(payload))
    body = segment + identity + dependency + export + chained
    if duplicate:
        body += struct.pack("<12I", 0x80000022, 48, *([0] * 10))
    header = struct.pack("<8I", 0xfeedfacf, 0x1000007, 3, 6, 6 if duplicate else 5, len(body), 0, 0)
    return header + body + bytes(512 - len(header + body)) + b"\0\0" + bytes(6) + payload


class ClassicImportTests(unittest.TestCase):
    def decode(self, stream, kind="bind"):
        return classic_imports(stream, IMAGE, SEGMENTS, kind)

    def test_regular_weak_special_addend_and_address(self):
        rows, _ = self.decode(b"\x11\x41_x\0\x60\x7f\x70\x10\x90\0")
        row, = rows
        self.assertEqual((row.symbol, row.provider, row.weak, row.lazy, row.addend, row.address),
                         ("_x", "/dep", True, False, -1, 0x1010))
        rows, _ = self.decode(b"\x3d\x40_x\0\x70\0\x90\0")
        self.assertEqual(rows[0].ordinal, -3)

    def test_repeat_and_skip_opcodes(self):
        prefix = b"\x11\x40_x\0\x70\0"
        rows, _ = self.decode(prefix + b"\xc0\x03\x08\0")
        self.assertEqual([row.address for row in rows], [0x1000, 0x1010, 0x1020])
        rows, _ = self.decode(prefix + b"\xa0\x08\xb1\x90\0")
        self.assertEqual([row.address for row in rows], [0x1000, 0x1010, 0x1020])

    def test_lazy_done_resets_state(self):
        stream = b"\x11\x40_x\0\x70\0\x90\0"
        rows, _ = self.decode(stream + stream, "lazy")
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row.lazy for row in rows))
        with self.assertRaisesRegex(Refusal, "incomplete"):
            self.decode(stream + b"\x90\0", "lazy")

    def test_weak_definition_marker_is_not_a_null_import(self):
        rows, definitions = self.decode(b"\x48_definition\0\x40_x\0\x70\0\x90\0", "weak")
        self.assertEqual(definitions, ["_definition"])
        self.assertEqual(rows[0].ordinal, -3)
        self.assertFalse(rows[0].weak)

    def test_truncated_states_and_unsupported_opcodes(self):
        data = b"\x11\x40_x\0\x70\0\x90\0"
        # Only an unfinished operand is truncated. dyld accepts the declared
        # stream extent after any complete opcode, including the final bind.
        self.assertEqual(self.decode(data[:-1]), self.decode(data))
        for size in (2, 3, 4, 6):
            with self.subTest(size=size), self.assertRaises(Refusal):
                self.decode(data[:size])
        for stream in (b"\xd0", b"\x42_x\0", b"\x11\x40_x\0\x71\0\x90\0",
                       b"\x12\x40_x\0\x70\0\x90\0", b"\0\x11", b"\x80\0"):
            with self.subTest(stream=stream), self.assertRaises(Refusal):
                self.decode(stream)

    def test_binding_outside_file_backed_segment_and_expansion_refused(self):
        with self.assertRaisesRegex(Refusal, "outside"):
            self.decode(b"\x11\x40_x\0\x70\xff\x01\x90\0")
        with self.assertRaisesRegex(Refusal, "repeat limit"):
            self.decode(b"\x11\x40_x\0\x70\0\xc0\xff\xff\xff\x7f\0")

    def test_sleb_boundaries_and_overflow(self):
        self.assertEqual(sleb(b"\x7f", 0), (-1, 1))
        self.assertEqual(sleb(b"\0", 0), (0, 1))
        with self.assertRaises(Refusal):
            sleb(b"\xff" * 11, 0)


class ChainedImportTests(unittest.TestCase):
    def test_all_import_formats_and_signed_ordinals_addends(self):
        for fmt in (1, 2, 3):
            row, = chained_imports(chain(fmt, weak=True, addend=-17 if fmt > 1 else 0), IMAGE)
            self.assertEqual((row.provider, row.weak, row.addend, row.table_index),
                             ("/dep", True, -17 if fmt > 1 else 0, 0))
            row, = chained_imports(chain(fmt, ordinal=-3), IMAGE)
            self.assertEqual(row.ordinal, -3)
            self.assertFalse(row.weak)

    def test_bad_schema_ordinal_reserved_bits_and_symbol_ranges(self):
        source = chain(3)
        mutations = []
        for offset, value in ((0, 1), (20, 4), (24, 1), (12, 0xffffffff), (16, 0xffffffff)):
            changed = bytearray(source)
            struct.pack_into("<I", changed, offset, value)
            mutations.append(changed)
        changed = bytearray(source)
        struct.pack_into("<Q", changed, 28, 1 | (1 << 17))
        mutations.extend((changed, chain(1, ordinal=2), chain(1, symbol=b"unterminated")))
        for data in mutations:
            with self.subTest(data=data), self.assertRaises(Refusal):
                chained_imports(data, IMAGE)

    def test_every_chained_prefix_truncation_refused(self):
        source = chain(3)
        for size in range(len(source)):
            with self.subTest(size=size), self.assertRaises(Refusal):
                chained_imports(source[:size], IMAGE)

    def test_complete_thin_and_universal_reader_use_x86_slice_relative_offsets(self):
        thin = complete_image()
        universal = struct.pack(">7I", 0xcafebabe, 1, 0x1000007, 3, 4096, len(thin), 12)
        universal += bytes(4096 - len(universal)) + thin
        for data, offset in ((thin, 0), (universal, 4096)):
            image, rows, metadata = read_imports(data)
            self.assertEqual(image.install_name, "/self")
            self.assertEqual(rows[0].provider, "/dep")
            self.assertEqual(metadata["slice_offset"], offset)

    def test_missing_or_conflicting_fixup_representation_is_not_zero_import_pass(self):
        for data in (complete_image(fixup_command=False), complete_image(duplicate=True)):
            with self.assertRaisesRegex(Refusal, "missing/conflicting"):
                read_imports(data)


class CacheExportTests(unittest.TestCase):
    def test_empty_terminal_edge_in_legacy_export_trie(self):
        # _x's terminal is reached through an empty edge, as in libgnsdk_manager.
        data = b'\0\1_x\0\x06\0\1\0\x0a\x02\0\x42\0'
        self.assertEqual(export_trie(data), {'_x': Export(0, 0x42)})
        with self.assertRaises(Refusal):
            export_trie(b'\0\1_x\0\x06\0\1\0\x06')  # Empty-edge cycle.

    def test_path_alias_terminals_and_cycle_refusal(self):
        self.assertEqual(path_trie(trie(b"\x01", b"/alias"), 2), {"/alias": 1})
        with self.assertRaises(Refusal):
            path_trie(trie(b"\x02", b"/alias"), 2)
        with self.assertRaises(Refusal):
            path_trie(b"\0\1/a\0\0", 1)

    def test_weak_reexport_and_export_kinds(self):
        self.assertEqual(export_trie(trie(b"\x0c\x01\0"))["_x"], Export(12, ordinal=1))
        self.assertEqual(export_trie(trie(b"\x02\x7f"))["_x"], Export(2, 127))
        self.assertEqual(export_trie(b""), {})
        with self.assertRaises(Refusal):
            export_trie(trie(b"\x0d\x01\0"))

    def test_dylib_use_flags_keep_reexport_weak_and_upward_separate(self):
        dep = CacheDependency("/dep", 0xc, 1 | 2 | 4 | 8)
        self.assertTrue(dep.reexport and dep.weak and dep.upward)
        self.assertFalse(CacheDependency("/dep", 0xc, 8).reexport)

    def test_final_provider_replacement_wins_for_cache_alias(self):
        replacement = Image("/dep", [], {"_x": Export(0, 8)})
        result = graph({"/dep": replacement}, {"/alias": 0, "/dep": 0})
        self.assertEqual(result.resolve("/alias", "_x")["input_offset"], "0x8")

    def test_reexports_precedence_renaming_weak_flags_and_shallow(self):
        images = {"/self": Image("/self", [Dependency("/dep", 0x8000001f)], {"_x": Export(0, 1)}),
                  "/dep": Image("/dep", [], {"_x": Export(0, 2), "_y": Export(4, 3)})}
        result = graph(images)
        self.assertEqual(result.resolve("/self", "_x")["provider"], "/self")
        self.assertEqual(result.resolve("/self", "_y")["provider"], "/dep")
        self.assertEqual(result.resolve("/self", "_y", shallow=True)["status"], "missing_symbol")
        images["/self"].exports["_alias"] = Export(12, ordinal=1, imported_name="_y")
        found = result.resolve("/self", "_alias", shallow=True)
        self.assertEqual(found["provider"], "/dep")
        self.assertTrue(found["weak_definition"])

    def test_ordinary_dependency_not_searched_and_cycles_not_success(self):
        images = {"/self": Image("/self", [Dependency("/dep", 0xc)], {}),
                  "/dep": Image("/dep", [], {"_x": Export(0, 2)})}
        self.assertEqual(graph(images).resolve("/self", "_x")["status"], "missing_symbol")
        images["/self"].dependencies[0] = Dependency("/dep", 0x8000001f)
        images["/dep"].dependencies.append(Dependency("/self", 0x8000001f))
        with self.assertRaisesRegex(Refusal, "cycle"):
            graph(images).resolve("/self", "_absent")

    def test_weak_reexport_absence_does_not_hide_later_available_reexport(self):
        images = {"/self": Image("/self", [CacheDependency("/optional", 0xc, 3),
                                           Dependency("/dep", 0x8000001f)], {}),
                  "/dep": Image("/dep", [], {"_x": Export(0, 2)})}
        self.assertEqual(graph(images).resolve("/self", "_x")["provider"], "/dep")
        images["/self"].exports["_x"] = Export(8, ordinal=1)
        self.assertEqual(graph(images).resolve("/self", "_x")["status"], "missing_symbol")

    def test_cache_linkedit_translation_and_dylib_use_reexport_flags(self):
        payload = trie(b"\0\x20")
        identity = struct.pack("<6I", 0xd, 32, 24, 0, 0, 0) + b"/cached\0"
        dependency = struct.pack("<7I", 0xc, 40, 28, 0x1a741800, 0, 0x10000, 2) + b"/dep\0" + bytes(7)
        linkedit = struct.pack("<II16s4Q4I", 0x19, 72, b"__LINKEDIT", 0x9000, 256, 0x7000, 256, 1, 1, 0, 0)
        export = struct.pack("<4I", 0x80000033, 16, 0x7010, len(payload))
        body = identity + dependency + linkedit + export
        header = struct.pack("<8I", 0xfeedfacf, 0x1000007, 3, 6, 4, len(body), 0, 0)
        class Family:
            def read(self, address, size):
                if 0x1000 <= address < 0x1000 + len(header + body):
                    offset = address - 0x1000
                    return (header + body)[offset:offset + size]
                if address == 0x9010 and size == len(payload):
                    return payload
                raise AssertionError(f"wrong LINKEDIT translation: {address:#x}")
        image = cached_image(Family(), 0x1000)
        self.assertEqual(image.install_name, "/cached")
        self.assertTrue(image.dependencies[0].reexport)
        self.assertEqual(image.exports["_x"], Export(0, 32))

    def test_cache_builder_libcxx_first_follows_explicit_weak_reexport(self):
        main = Image("/self", [Dependency("/usr/lib/libc++.1.dylib", 0xc)], {"_x": Export(4, 7)})
        libcxx = Image("/usr/lib/libc++.1.dylib", [Dependency("/usr/lib/libc++abi.dylib", 0x8000001f)],
                       {"_x": Export(12, ordinal=1)})
        abi = Image("/usr/lib/libc++abi.dylib", [], {"_x": Export(4, 8)})
        result = graph({"/self": main}, {"/usr/lib/libc++.1.dylib": 0, "/usr/lib/libc++abi.dylib": 1})
        result.cached = {libcxx.install_name: libcxx, abi.install_name: abi}
        class Family:
            images = [(libcxx.install_name, 0x1000), (abi.install_name, 0x2000)]
            def read(self, address, size):
                self.assert_address = address
                return struct.pack("<I", 0x8000)
        result.family = Family()
        found = result.resolve_weak_for_cache_build("/self", "_x")
        self.assertEqual(found["provider"], abi.install_name)
        self.assertEqual(found["lookup"], "cache-builder-libc++-first")


class ImportClassificationTests(unittest.TestCase):
    class MissingGraph:
        def __init__(self, status):
            self.status = status
        def resolve(self, path, symbol):
            return {"status": self.status, "path": path, "symbol": symbol}
        def resolve_weak_for_cache_build(self, path, symbol):
            return self.resolve(path, symbol)

    def test_missing_strong_cannot_become_a_badroot_or_lazy_success(self):
        for lazy in (False, True):
            row = Import("_absent", 1, "/dep", False, lazy, 0, 1, "bind")
            self.assertEqual(resolve_import(self.MissingGraph("missing_symbol"), IMAGE, row)["status"],
                             "missing_strong")

    def test_nullable_weak_import_and_required_library_absence_are_distinct(self):
        row = Import("_absent", 1, "/dep", True, False, 0, 1, "bind")
        self.assertEqual(resolve_import(self.MissingGraph("missing_symbol"), IMAGE, row)["status"], "weak_null")
        self.assertEqual(resolve_import(self.MissingGraph("missing_input"), IMAGE, row)["status"], "missing_required_input")
        weak_image = Image("/self", [Dependency("/dep", 0x80000018)], {})
        self.assertEqual(resolve_import(self.MissingGraph("missing_input"), weak_image, row)["status"], "weak_null")

    def test_weak_lookup_is_not_weak_import_null_and_process_scope_is_explicit(self):
        for weak in (False, True):
            row = Import("_absent", -3, "SPECIAL:weak-lookup", weak, False, 0, 1, "chained")
            self.assertEqual(resolve_import(self.MissingGraph("missing_weak_definition"), IMAGE, row)["status"], "missing_strong")
        row = Import("_absent", -1, "SPECIAL:main-executable", True, False, 0, 1, "chained")
        self.assertEqual(resolve_import(self.MissingGraph("missing_symbol"), IMAGE, row)["status"], "unsupported_process_lookup")

    def test_flat_lookup_resolves_through_the_single_definer(self):
        # fold-in 2026-11-14: the Live Text interposers' e5rt imports (ordinal -2) resolve like dyld's flat lookup
        # when one image defines the symbol; none is weak_null/missing_strong, several a refusal (FinalGraph).
        graph = self.MissingGraph("missing_symbol")
        graph.resolve_flat = lambda symbol: {"status": "resolved", "provider": "/Espresso", "symbol": symbol}
        row = Import("_e5rt_x", -2, "SPECIAL:flat-lookup", True, False, 0, 1, "bind")
        self.assertEqual(resolve_import(graph, IMAGE, row)["provider"], "/Espresso")
        graph.resolve_flat = lambda symbol: {"status": "missing_symbol", "symbol": symbol}
        for weak, status in ((True, "weak_null"), (False, "missing_strong")):
            row = Import("_absent", -2, "SPECIAL:flat-lookup", weak, False, 0, 1, "bind")
            self.assertEqual(resolve_import(graph, IMAGE, row)["status"], status)


if __name__ == "__main__":
    unittest.main()
