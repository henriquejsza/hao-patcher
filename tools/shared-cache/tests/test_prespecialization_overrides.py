import hashlib
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from dyld_rebuild import prespecialization_overrides as po
from dyld_rebuild.codesign import emit, inspect
from dyld_rebuild.exports import Refusal
from dyld_rebuild.slides import SlideInfoV2

# The 26B131 bytes after `call _dyld_shared_cache_some_image_overridden` at each site (cache 262FA161).
IMAGE_LOADED_TAIL = bytes.fromhex("84c07414 48833d5be4c93f ff 750c c705 1fe4c93f 04000000 5d c3".replace(" ", ""))
STATE_SETUP_TAIL = bytes.fromhex("84c07415 41c7460804000000 803d".replace(" ", ""))
CONFORMANCE_TAIL = bytes.fromhex("84c0741f 4c01f3 488d3d1f".replace(" ", ""))
LOG_TAIL = bytes.fromhex("0fb6d0 488d357c720000 4c".replace(" ", ""))


def cache_file(size=3 * 4096, identifier="com.apple.dyld.cache.x86_64.development"):
    """A minimal signed file: mapping table at 568 (27's header), signature at EOF."""
    data = bytearray(size)
    data[:16] = b"dyld_v1  x86_64\0"
    struct.pack_into("<II", data, 16, 568, 1)
    struct.pack_into("<QQQII", data, 568, 0x7ff800000000, size, 0, 5, 5)
    signature = emit(data, size, identifier, size)
    struct.pack_into("<QQ", data, 40, size, len(signature))
    return bytes(data + emit(data, size, identifier, size))


class SitePatternTests(unittest.TestCase):
    def test_the_two_switch_off_sites_match_and_the_others_do_not(self):
        self.assertTrue(po.IMAGE_LOADED.match(IMAGE_LOADED_TAIL))
        self.assertTrue(po.STATE_SETUP.match(STATE_SETUP_TAIL))
        for tail in (CONFORMANCE_TAIL, LOG_TAIL):
            self.assertIsNone(po.IMAGE_LOADED.match(tail))
            self.assertIsNone(po.STATE_SETUP.match(tail))
        self.assertTrue(po.CONFORMANCE.match(CONFORMANCE_TAIL))
        for tail in (IMAGE_LOADED_TAIL, STATE_SETUP_TAIL, LOG_TAIL):
            self.assertIsNone(po.CONFORMANCE.match(tail))

    def test_replacement_is_a_five_byte_false(self):
        self.assertEqual(po.NOP_CALL, bytes([0x31, 0xC0, 0x0F, 0x1F, 0x00]))


class CatalogKeyTests(unittest.TestCase):
    def test_static_keys_only(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "names.tsv"
            p.write_text("# comment\nname\tcalls\tmisses\tconfidence\truns\tkey\n"
                         "A<B>\t3\t0\tstatic\tr\t0x7ff81329ae94;0x7ff841266fe0\n"
                         "C<D<E>>\t1\t0\tderived\tr\t-\n")
            self.assertEqual(po.catalog_keys(p), [("A<B>", [0x7ff81329ae94, 0x7ff841266fe0])])


class DescriptorSlotTests(unittest.TestCase):
    def test_null_slot_keeps_the_chain_delta(self):
        base, delta = 0x7ff800000000, 0xffff0000000000
        info = bytearray(struct.pack("<6I2Q1H", 2, 4096, 40, 1, 0, 0, delta, base, 0))
        data = bytearray(4096)
        struct.pack_into("<Q", data, 0, (8 << 38) | 0x1f2eaa78)    # next pointer 8 bytes on
        struct.pack_into("<Q", data, 8, 0x1000)
        slide = SlideInfoV2(info, data, 0, 4096)
        raw = slide.retarget(0, base + 0x1f2eaa78, 0)
        self.assertEqual(raw & ~delta, 0)
        self.assertEqual(slide.decode(raw), 0)
        self.assertEqual(raw & delta, (8 << 38))


class ApplyTests(unittest.TestCase):
    def test_apply_edits_resigns_and_keeps_identifier(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "dyld_shared_cache_x86_64"
            src.write_bytes(cache_file())
            recipe = dict(files=[dict(file="main", path=str(src), sha256=po.sha256(src),
                                      edits=[dict(id="t", at=4096 + 16, before="00" * 5, after=po.NOP_CALL.hex())])])
            rows = po.apply(recipe, Path(d) / "out")
            out = Path(rows[0]["path"]).read_bytes()
            self.assertEqual(out[4096 + 16:4096 + 21], po.NOP_CALL)
            info = inspect(out)
            self.assertEqual(info["identifier"], "com.apple.dyld.cache.x86_64.development")
            self.assertEqual(po.code_directory_identifier(out), info["identifier"])
            self.assertEqual(rows[0]["sha256"], hashlib.sha256(out).hexdigest())

    def test_apply_refuses_a_different_input_or_unexpected_bytes(self):
        with tempfile.TemporaryDirectory() as d:
            src = Path(d) / "dyld_shared_cache_x86_64"
            src.write_bytes(cache_file())
            wrong = dict(files=[dict(file="main", path=str(src), sha256="0" * 64, edits=[])])
            with self.assertRaises(Refusal):
                po.apply(wrong, Path(d) / "a")
            bad = dict(files=[dict(file="main", path=str(src), sha256=po.sha256(src),
                                   edits=[dict(id="t", at=4096, before="ff", after="00")])])
            with self.assertRaises(Refusal):
                po.apply(bad, Path(d) / "b")


@unittest.skipUnless(os.environ.get("PRESPECIALIZATION_CACHE"), "PRESPECIALIZATION_CACHE: a 26B131 x86_64 main cache")
class RealCacheTests(unittest.TestCase):
    def test_26B131_plan(self):
        overridden = ["/usr/lib/system/libsystem_kernel.dylib",
                      "/System/Library/PrivateFrameworks/CoreWiFi.framework/Versions/A/CoreWiFi",
                      "/System/Library/PrivateFrameworks/WiFiPeerToPeer.framework/Versions/A/WiFiPeerToPeer"]
        recipe = po.plan(os.environ["PRESPECIALIZATION_CACHE"], overridden)
        ids = sorted(e["id"] for f in recipe["files"] for e in f["edits"])
        self.assertEqual(ids.count("descriptor-map-overridden"), 113)
        self.assertIn("prespecialization-image-loaded", ids)
        self.assertIn("prespecialization-state-setup", ids)
        self.assertEqual(recipe["apple_entries"], 2762)
        self.assertNotIn("prespecialization-conformance", ids)

    def test_26B131_conformance_gate_refuses_lost_wifisettingskit_conformances(self):
        overridden = ["/System/Library/PrivateFrameworks/CoreWiFi.framework/Versions/A/CoreWiFi"]
        with self.assertRaisesRegex(Refusal, "WiFiSettingsKit.*5 rows"):
            po.plan(os.environ["PRESPECIALIZATION_CACHE"], overridden, conformance=True)

    def test_26B131_conformance_without_swift_overrides(self):
        recipe = po.plan(os.environ["PRESPECIALIZATION_CACHE"], ["/usr/lib/system/libsystem_kernel.dylib"], conformance=True)
        ids = [e["id"] for f in recipe["files"] for e in f["edits"]]
        self.assertIn("prespecialization-conformance", ids)
        self.assertEqual(recipe["conformance_removed"], {k: dict(groups=0, rows=0) for k in ("type", "metadata", "foreign")})


if __name__ == "__main__":
    unittest.main()
