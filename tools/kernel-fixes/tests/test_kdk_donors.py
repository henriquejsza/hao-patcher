"""kernel-fixes kdk-donors: the x86_64 slice exactly, a deterministic build.json; with the store, the recorded donors."""
import hashlib
import json
import os
from pathlib import Path
import runpy
import struct
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
K = runpy.run_path(str(ROOT/'kdk_donors.py'))


def thin(cpu, body):
    return struct.pack('<Ii', 0xfeedfacf, cpu) + body


def fat(slices):
    """A universal file: header, then each slice at a 16-byte aligned offset."""
    head = struct.pack('>II', 0xcafebabe, len(slices))
    offset, entries, bodies = 8 + 20 * len(slices), b'', b''
    offset = (offset + 15) // 16 * 16
    for cpu, data in slices:
        entries += struct.pack('>iiIII', cpu, 3, offset + len(bodies), len(data), 4)
        bodies += data + b'\0' * ((-len(data)) % 16)
    out = head + entries
    return out + b'\0' * (offset - len(out)) + bodies


class Slices(unittest.TestCase):
    def test_x86_64_slice_of_a_universal_file(self):
        x86, arm = thin(0x01000007, b'intel' * 7), thin(0x0100000c, b'arm' * 5)
        self.assertEqual(K['x86_64_slice'](fat([(0x0100000c, arm), (0x01000007, x86)])), x86)
        self.assertEqual(K['x86_64_slice'](x86), x86)
        with self.assertRaises(ValueError):
            K['x86_64_slice'](fat([(0x0100000c, arm)]))

    def test_same_kdk_same_folder(self):
        with tempfile.TemporaryDirectory() as d:
            kdk = Path(d)/'kdk'
            for name in K['DONORS']:
                f = kdk/f'System/Library/Extensions/{name}.kext/Contents/MacOS/{name}'
                f.parent.mkdir(parents=True)
                f.write_bytes(fat([(0x01000007, thin(0x01000007, name.encode()))]))
            K['make'](kdk, Path(d)/'a', '25G342'); K['make'](kdk, Path(d)/'b', '25G342')
            for name in list(K['DONORS']) + ['build.json']:
                self.assertEqual((Path(d)/'a'/name).read_bytes(), (Path(d)/'b'/name).read_bytes(), name)
            self.assertNotIn(d, (Path(d)/'a/build.json').read_text())            # no host path


@unittest.skipUnless(os.environ.get('KERNEL_FIXES_KDK'), 'set KERNEL_FIXES_KDK (the 25G342 KDK root)')
class RealKdk(unittest.TestCase):
    RECORDED = {'AppleMobileFileIntegrity': '75cf092ed653c5d52afeec21096b36c077ceec36a276542f74c0b162428556ce',
                'Sandbox': '1ba0231c2dbce4eac3513d31230b57317ea0a0ec8b8a407f95825ab3cad9d283',
                'EndpointSecurity': '30265121599b132b8b5fa68224e55d1289f49ade6133625e1b0cb609b2a4e5c2',
                'IOSurface': '7abec149c0e42695fa2f6e4c1975dccfda57459e0a604bee591840b86dcb8d08'}

    def test_the_recorded_donors(self):
        with tempfile.TemporaryDirectory() as d:
            record = K['make'](os.environ['KERNEL_FIXES_KDK'], Path(d)/'out', '25G342')
            self.assertEqual({n: f['sha256'] for n, f in record['files'].items()}, self.RECORDED)


if __name__ == '__main__':
    unittest.main()
