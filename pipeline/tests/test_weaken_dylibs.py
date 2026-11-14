"""pipeline/stages/weaken-dylibs.py on a minimal Mach-O header (no signing: weaken() only)."""
import runpy
import struct
import tempfile
import unittest
from pathlib import Path

W = runpy.run_path(str(Path(__file__).resolve().parents[1] / 'stages' / 'weaken-dylibs.py'))


def dylib(cmd, name):
    raw = name.encode() + b'\0'
    size = (24 + len(raw) + 7) // 8 * 8
    return struct.pack('<IIIIII', cmd, size, 24, 2, 0x10000, 0x10000) + raw.ljust(size - 24, b'\0')


def macho(cmds):
    body = b''.join(cmds)
    return struct.pack('<IiiIIIII', 0xfeedfacf, 0x01000007, 3, 2, len(cmds), len(body), 0, 0) + body


class WeakenTest(unittest.TestCase):
    def test_only_the_curses_and_edit_libraries_become_weak(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'python3.12'
            p.write_bytes(macho([dylib(0xc, '/usr/lib/libSystem.B.dylib'), dylib(0xc, '/usr/lib/libedit.3.dylib'),
                                 dylib(0xc, '/usr/lib/libncurses.5.4.dylib'), dylib(0xc, '/usr/lib/libpanel.5.4.dylib')]))
            self.assertEqual(W['weaken'](p), ['/usr/lib/libedit.3.dylib', '/usr/lib/libncurses.5.4.dylib',
                                              '/usr/lib/libpanel.5.4.dylib'])
            b, off, cmds = p.read_bytes(), 32, []
            for _ in range(4):
                cmd, size = struct.unpack_from('<II', b, off)
                cmds.append(cmd)
                off += size
            self.assertEqual(cmds, [0xc, 0x80000018, 0x80000018, 0x80000018])
            self.assertEqual(W['weaken'](p), [])          # a second run changes nothing

    def test_refuses_a_fat_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / 'x'
            p.write_bytes(struct.pack('>I', 0xcafebabe) + b'\0' * 28)
            with self.assertRaises(ValueError):
                W['weaken'](p)


if __name__ == '__main__':
    unittest.main()
