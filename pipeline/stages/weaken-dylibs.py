"""weaken-dylibs.py MACHO [NAME...]: make the LC_LOAD_DYLIB commands of a thin 64-bit Mach-O that name any NAME
(default libedit, libncurses, libpanel) LC_LOAD_WEAK_DYLIB, in place, then sign it ad hoc.

Why: the kit's x86_64 CPython (python-build-standalone) links libedit, libncurses and libpanel, which a macOS
Recovery's shared cache does not have: in the stick's Tahoe Recovery python3.12 stopped in dyld ("Library not loaded:
/usr/lib/libpanel.5.4.dylib", QEMU 2026-11-13), as it did in the laptop's NetBoot Recovery (tools/recovery-spikes,
which weakens them the same way). Python's core never needs them, only readline and curses do. Made on whatever Mac
stages the kit, from the pinned download; the row stays the publisher's archive. Python 3.9+."""
import struct
import subprocess
import sys
from pathlib import Path

NAMES = ('libedit', 'libncurses', 'libpanel')
LC_LOAD_DYLIB, LC_LOAD_WEAK_DYLIB = 0xc, 0x80000018


def weaken(path, names=NAMES):
    """The install names changed (already-weak ones are not counted)."""
    b = bytearray(Path(path).read_bytes())
    if struct.unpack_from('<I', b, 0)[0] != 0xfeedfacf:
        raise ValueError('%s: not a thin 64-bit Mach-O' % path)
    ncmds, off, changed = struct.unpack_from('<I', b, 16)[0], 32, []
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', b, off)
        if cmd == LC_LOAD_DYLIB:
            name = bytes(b[off + struct.unpack_from('<I', b, off + 8)[0]:off + size]).split(b'\0')[0].decode()
            if any(n in name for n in names):
                struct.pack_into('<I', b, off, LC_LOAD_WEAK_DYLIB)
                changed.append(name)
        off += size
    if changed:
        Path(path).write_bytes(bytes(b))
    return changed


def main(argv):
    if not argv:
        print(__doc__, file=sys.stderr)
        return 2
    changed = weaken(argv[0], tuple(argv[1:]) or NAMES)
    if changed:
        subprocess.run(['codesign', '-f', '-s', '-', argv[0]], check=True, capture_output=True)
    print('weaken-dylibs: %s: %s' % (argv[0], ', '.join(changed) or 'nothing to change'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
