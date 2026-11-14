"""pipeline/unpack/cache-images on a synthetic dyld shared cache header: image paths sorted, without the slash."""
import runpy
import struct
import tempfile
import unittest
from pathlib import Path

C = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'unpack' / 'cache-images'))


def cache(paths):
    head = bytearray(b'dyld_v1  x86_64\0'.ljust(512, b'\0'))
    table_at = 512
    names_at = table_at + 32 * len(paths)
    names, rows = b'', b''
    for p in paths:
        rows += struct.pack('<QQQII', 0, 0, 0, names_at + len(names), 0)
        names += p.encode() + b'\0'
    struct.pack_into('<II', head, 448, table_at, len(paths))
    return bytes(head) + rows + names


class CacheImagesTest(unittest.TestCase):
    def test_lists_images(self):
        with tempfile.TemporaryDirectory() as d:
            f, out = Path(d) / 'dyld_shared_cache_x86_64', Path(d) / 'list.txt'
            f.write_bytes(cache(['/usr/lib/libz.1.dylib', '/System/Library/Frameworks/Metal.framework/Versions/A/Metal']))
            C['write'](C['images'](f), out)
            self.assertEqual(out.read_text().splitlines(),
                             ['System/Library/Frameworks/Metal.framework/Versions/A/Metal', 'usr/lib/libz.1.dylib'])
            with self.assertRaises(ValueError):
                C['write']([], out)                                   # never overwrites

    def test_refuses_other_files(self):
        with tempfile.TemporaryDirectory() as d:
            f = Path(d) / 'x'
            f.write_bytes(b'dyld_v1   arm64e\0'.ljust(600, b'\0'))
            with self.assertRaises(ValueError):
                C['images'](f)


if __name__ == '__main__':
    unittest.main()
