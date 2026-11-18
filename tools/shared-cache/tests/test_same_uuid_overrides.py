"""producer.clear_same_uuid_overrides: a cached loader stops being overridable only when every on-disk copy is the cache
image itself (same x86_64 LC_UUID); a real root keeps it overridable."""
from pathlib import Path
import struct
import sys
import tempfile
import unittest
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild import producer
from test_loader_generation import minimal_set

UUID = bytes(range(16))


def macho(uuid):
    thin = struct.pack('<IiiIIIII', 0xfeedfacf, 0x01000007, 3, 6, 1, 24, 0, 0) + struct.pack('<II', 0x1b, 24) + uuid
    return struct.pack('>IIIIIII', 0xcafebabe, 1, 0x01000007, 3, 28, len(thin), 0) + thin


class Views:
    def __init__(self, root): self.roots = {'system': root / 'sys', 'os': root / 'os', 'app': None}


class SameUuid(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        data = minimal_set()                                   # one cached loader at /x, flags at +0x2c
        data[84 + 8:84 + 24] = UUID
        struct.pack_into('<H', data, 84 + 0x2c, 0b10)          # isOverridable
        self.blob = self.tmp / 'cached.pbl'; self.blob.write_bytes(bytes(data))
        self.views = Views(self.tmp)
        for v in ('sys', 'os'): (self.tmp / v).mkdir()

    def bits(self): return struct.unpack_from('<H', self.blob.read_bytes(), 84 + 0x2c)[0]

    def test_uuid_reader(self):
        f = self.tmp / 'm'; f.write_bytes(macho(UUID))
        self.assertEqual(producer.x86_64_uuid(f), UUID.hex())

    def test_cleared_when_every_copy_is_the_cache_image(self):
        (self.tmp / 'os/x').write_bytes(macho(UUID))
        self.assertEqual(producer.clear_same_uuid_overrides(self.blob, self.views, 1), ['/x'])
        self.assertEqual(self.bits() & 2, 0)

    def test_kept_for_a_real_root_or_no_file(self):
        self.assertEqual(producer.clear_same_uuid_overrides(self.blob, self.views, 1), [])     # nothing on disk
        (self.tmp / 'os/x').write_bytes(macho(UUID)); (self.tmp / 'sys/x').write_bytes(macho(bytes(16)))
        self.assertEqual(producer.clear_same_uuid_overrides(self.blob, self.views, 1), [])     # one copy differs
        self.assertEqual(self.bits() & 2, 2)


if __name__ == '__main__':
    unittest.main()
