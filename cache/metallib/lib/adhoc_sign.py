"""Ad-hoc signing whose bytes do not depend on the Mac's codesign.

codesign on macOS 26 reserves about 18 KB more signature space than codesign on macOS 27 (the blobs are the same).
The reserved size sits in LC_CODE_SIGNATURE and __LINKEDIT, which the first code page hashes, so the file and its
CDHash differed between Macs. sign() runs codesign, then trims the reservation to macOS 27's size (the superblob
rounded up to 16 bytes, plus 16), shrinks __LINKEDIT to match and refreshes the code-page hashes. Bytes past the
superblob are left as codesign left them. A file already at that size is unchanged.
"""
import hashlib
import struct
from pathlib import Path

LC_SEGMENT_64, LC_CODE_SIGNATURE = 0x19, 0x1d
SUPERBLOB, CODEDIRECTORY = 0xfade0cc0, 0xfade0c02
HASHES = {1: 'sha1', 2: 'sha256', 3: 'sha256'}


def reserved(length):
    return ((length + 15) & ~15) + 16


def _commands(data):
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('not a thin 64-bit Mach-O')
    count, at, found = struct.unpack_from('<I', data, 16)[0], 32, {}
    for _ in range(count):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == LC_CODE_SIGNATURE:
            found['signature'] = at
        elif cmd == LC_SEGMENT_64 and data[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
            found['linkedit'] = at
        at += size
    if set(found) != {'signature', 'linkedit'}:
        raise ValueError('no embedded signature or no __LINKEDIT')
    return found['signature'], found['linkedit']


def normalize(data):
    """DATA with its embedded ad-hoc signature's reserved space at macOS 27 codesign's size."""
    d = bytearray(data)
    sig, linkedit = _commands(d)
    off, size = struct.unpack_from('<II', d, sig + 8)
    magic, length, count = struct.unpack_from('>III', d, off)
    if magic != SUPERBLOB or off + size != len(d) or length > size:
        raise ValueError('signature is not the last thing in the file')
    want = reserved(length)
    if want == size:
        return bytes(d)
    if want > size:
        raise ValueError('signature reservation smaller than macOS 27 codesign writes')
    _, _, fileoff, _ = struct.unpack_from('<QQQQ', d, linkedit + 24)
    filesize = off + want - fileoff
    struct.pack_into('<Q', d, linkedit + 32, (filesize + 0x3fff) & ~0x3fff)
    struct.pack_into('<Q', d, linkedit + 48, filesize)
    struct.pack_into('<I', d, sig + 12, want)
    del d[off + want:]
    for i in range(count):
        slot, blob = struct.unpack_from('>II', d, off + 12 + i * 8)
        if slot != 0 and not 0x1000 <= slot < 0x1005:
            continue
        cd = off + blob
        if struct.unpack_from('>I', d, cd)[0] != CODEDIRECTORY:
            raise ValueError('bad CodeDirectory')
        hashes, _, special, pages, limit = struct.unpack_from('>5I', d, cd + 16)
        hsize, kind, _, exponent = d[cd + 36:cd + 40]
        if limit != off or kind not in HASHES or not exponent:
            raise ValueError('unsupported CodeDirectory')
        page = 1 << exponent
        for p in range(pages):
            d[cd + hashes + p * hsize:cd + hashes + (p + 1) * hsize] = \
                hashlib.new(HASHES[kind], d[p * page:min((p + 1) * page, limit)]).digest()[:hsize]
    return bytes(d)


def sign(path, run):
    """Ad-hoc sign PATH with codesign (through RUN), then normalize it in place."""
    run(['codesign', '-f', '-s', '-', path])
    path = Path(path)
    path.write_bytes(normalize(path.read_bytes()))
