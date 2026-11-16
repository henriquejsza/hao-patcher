"""adhoc_sign: a signature with macOS 26 codesign's extra reservation normalizes to macOS 27 codesign's bytes."""
import hashlib
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import unittest

import adhoc_sign


def padded(data, extra):
    """DATA as macOS 26 codesign writes it: EXTRA more bytes reserved, __LINKEDIT and page hashes to match."""
    d = bytearray(data)
    sig, linkedit = adhoc_sign._commands(d)
    off, size = struct.unpack_from('<II', d, sig + 8)
    _, _, fileoff, _ = struct.unpack_from('<QQQQ', d, linkedit + 24)
    filesize = off + size + extra - fileoff
    struct.pack_into('<Q', d, linkedit + 32, (filesize + 0x3fff) & ~0x3fff)
    struct.pack_into('<Q', d, linkedit + 48, filesize)
    struct.pack_into('<I', d, sig + 12, size + extra)
    d += bytes(extra)
    _, _, count = struct.unpack_from('>III', d, off)
    for i in range(count):
        slot, blob = struct.unpack_from('>II', d, off + 12 + i * 8)
        if slot == 0:
            cd = off + blob
            hashes, _, _, pages, limit = struct.unpack_from('>5I', d, cd + 16)
            hsize, _, _, exponent = d[cd + 36:cd + 40]
            for p in range(pages):
                d[cd + hashes + p * hsize:cd + hashes + (p + 1) * hsize] = \
                    hashlib.sha256(d[p << exponent:min((p + 1) << exponent, limit)]).digest()
    return bytes(d)


@unittest.skipUnless(shutil.which('xcrun'), 'needs clang')
class Normalize(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='adhoc-sign-'))
        self.addCleanup(shutil.rmtree, self.work)
        (self.work / 'a.c').write_text('int f(int x) { return x * 3; }\n' * 1 + 'char big[20000] = {1};\n')
        self.binary = self.work / 'a.dylib'
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-dynamiclib', self.work / 'a.c', '-o', self.binary],
                       check=True)

    def test_macos26_reservation_gives_macos27_bytes(self):
        adhoc_sign.sign(self.binary, lambda c: subprocess.run(list(map(str, c)), check=True, capture_output=True))
        reference = self.binary.read_bytes()
        self.assertEqual(adhoc_sign.normalize(reference), reference)
        bigger = padded(reference, 18000)
        self.assertNotEqual(bigger, reference)
        self.assertEqual(adhoc_sign.normalize(bigger), reference)
        self.binary.write_bytes(adhoc_sign.normalize(bigger))
        subprocess.run(['codesign', '-v', self.binary], check=True)

    def test_refuses_unsigned(self):
        subprocess.run(['codesign', '--remove-signature', self.binary], check=True)
        with self.assertRaises(ValueError):
            adhoc_sign.normalize(self.binary.read_bytes())


if __name__ == '__main__':
    unittest.main()
