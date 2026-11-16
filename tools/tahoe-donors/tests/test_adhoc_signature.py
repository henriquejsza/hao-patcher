"""adhoc_signature.pin: one form of a codesign ad-hoc signature, whatever reserve the signer left after it.
python3.14 -I -B -m unittest discover -s tools/tahoe-donors/tests"""
from pathlib import Path
import runpy
import shutil
import struct
import subprocess
import tempfile
import unittest

UNIT = Path(__file__).resolve().parents[1]
A = runpy.run_path(str(UNIT / 'adhoc_signature.py'))


def commands(data):
    at, out = 32, {}
    for _ in range(struct.unpack_from('<I', data, 16)[0]):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x19 and data[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
            out['linkedit'] = at
        elif cmd == 0x1d:
            out['signature'] = at
        at += size
    return out


def reserve(data, extra):
    """DATA as a codesign that reserves EXTRA zero bytes after the blobs would write it (hashes left stale)."""
    data = bytearray(data) + bytes(extra)
    c = commands(data)
    struct.pack_into('<I', data, c['signature'] + 12, struct.unpack_from('<I', data, c['signature'] + 12)[0] + extra)
    filesize = struct.unpack_from('<Q', data, c['linkedit'] + 48)[0] + extra
    struct.pack_into('<Q', data, c['linkedit'] + 48, filesize)
    struct.pack_into('<Q', data, c['linkedit'] + 32, -(-filesize // 0x4000) * 0x4000)
    return bytes(data)


@unittest.skipUnless(shutil.which('xcrun') and shutil.which('codesign'), 'needs Xcode or the Command Line Tools')
class Pin(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.dir = Path(tmp.name)
        source = self.dir / 'a.c'
        source.write_text(''.join('int g%d(void) { return %d; }\n' % (i, i) for i in range(3000)))
        self.dylib = self.dir / 'liba.dylib'
        subprocess.run(['xcrun', 'clang', '-arch', 'x86_64', '-dynamiclib', '-o', self.dylib, source], check=True)
        subprocess.run(['codesign', '-f', '-s', '-', self.dylib], check=True, capture_output=True)
        self.signed = self.dylib.read_bytes()

    def test_pinning_twice_changes_nothing_and_the_signature_verifies(self):
        pinned = A['pin_bytes'](self.signed)
        self.assertEqual(A['pin_bytes'](pinned), pinned)
        self.dylib.write_bytes(pinned)
        subprocess.run(['codesign', '--verify', '--strict', self.dylib], check=True)

    def test_any_reserve_after_the_blobs_gives_the_same_file(self):
        pinned = A['pin_bytes'](self.signed)
        for extra in (16, 18000):
            padded = reserve(self.signed, extra)
            self.assertNotEqual(padded, self.signed)
            self.assertEqual(A['pin_bytes'](padded), pinned)

    def test_anything_but_zeros_after_the_blobs_is_refused(self):
        padded = bytearray(reserve(self.signed, 32))
        padded[-1] = 1
        with self.assertRaisesRegex(ValueError, 'not zeros'):
            A['pin_bytes'](bytes(padded))


if __name__ == '__main__':
    unittest.main()
