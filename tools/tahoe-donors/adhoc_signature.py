"""Make an ad-hoc signature independent of the host's codesign.

codesign on macOS 26 reserves about 18 KB of zeros after the signature blobs where codesign on macOS 27 reserves
none; the reserved size goes into LC_CODE_SIGNATURE and __LINKEDIT, which the first page hash covers, so the same
code signed on two hosts gives two files. pin() rewrites a thin Mach-O that codesign has just signed ad hoc to one
form: the signature area is the superblob rounded up to 16 bytes, __LINKEDIT ends with it (vmsize rounded up to
16 KB), and every code page hash is recomputed. For an image cut out of a shared cache (no earlier signature) that
is what macOS 27's codesign writes. The blobs themselves (identifier, flags, requirements, the empty CMS blob) are
codesign's and are kept as they are.
"""
import hashlib
import struct
import sys

LC_SEGMENT_64, LC_CODE_SIGNATURE = 0x19, 0x1d
SUPERBLOB, CODEDIRECTORY = 0xfade0cc0, 0xfade0c02
HASHES = {1: lambda b: hashlib.sha1(b).digest(), 2: lambda b: hashlib.sha256(b).digest()}


def _round(value, unit):
    return -(-value // unit) * unit


def pin_bytes(data):
    """DATA (a thin 64-bit Mach-O with an ad-hoc signature) with the signature reserve removed."""
    data = bytearray(data)
    if data[:4] != b'\xcf\xfa\xed\xfe':
        raise ValueError('expected a thin 64-bit Mach-O')
    ncmds = struct.unpack_from('<I', data, 16)[0]
    at, linkedit, signature = 32, None, None
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == LC_SEGMENT_64 and data[at + 8:at + 24].rstrip(b'\0') == b'__LINKEDIT':
            linkedit = at
        elif cmd == LC_CODE_SIGNATURE:
            signature = at
        at += size
    if linkedit is None or signature is None:
        raise ValueError('no __LINKEDIT or no signature')
    offset, size = struct.unpack_from('<II', data, signature + 8)
    magic, length, count = struct.unpack_from('>III', data, offset)
    if magic != SUPERBLOB or length > size or offset + size != len(data):
        raise ValueError('the signature is not a superblob at the end of the file')
    if any(data[offset + length:]):
        raise ValueError('the bytes after the signature blobs are not zeros')
    fileoff = struct.unpack_from('<Q', data, linkedit + 40)[0]
    size = _round(length, 16)
    del data[offset + size:]
    struct.pack_into('<I', data, signature + 12, size)
    filesize = offset + size - fileoff
    struct.pack_into('<Q', data, linkedit + 32, _round(filesize, 0x4000))   # vmsize
    struct.pack_into('<Q', data, linkedit + 48, filesize)
    for index in range(count):
        kind, blob = struct.unpack_from('>II', data, offset + 12 + 8 * index)
        cd = offset + blob
        if struct.unpack_from('>I', data, cd)[0] != CODEDIRECTORY:
            continue
        hash_offset, _, _, slots, limit = struct.unpack_from('>5I', data, cd + 16)
        hash_size, hash_type, _, page_shift = data[cd + 36], data[cd + 37], data[cd + 38], data[cd + 39]
        if hash_type not in HASHES or limit != offset:
            raise ValueError('unexpected CodeDirectory (hash type %d, code limit %d)' % (hash_type, limit))
        page = 1 << page_shift if page_shift else limit
        if slots != _round(limit, page) // page:
            raise ValueError('CodeDirectory slot count does not cover the code')
        for slot in range(slots):
            digest = HASHES[hash_type](bytes(data[slot * page:min((slot + 1) * page, limit)]))[:hash_size]
            data[cd + hash_offset + slot * hash_size:cd + hash_offset + (slot + 1) * hash_size] = digest
    return bytes(data)


def pin(path):
    with open(path, 'rb') as f:
        data = f.read()
    pinned = pin_bytes(data)
    if pinned != data:
        with open(path, 'r+b') as f:
            f.write(pinned)
            f.truncate()


if __name__ == '__main__':
    for p in sys.argv[1:]:
        pin(p)
