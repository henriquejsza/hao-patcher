"""The pinned cache's dyld-1378 ad-hoc CodeDirectory format, not a trust policy.

Layout oracle: Apple cache_builder/SubCache.cpp getCodeSignatureLayout/codeSign.
Only the observed SHA256/4K/version 0x20400/empty requirements+CMS shape is
supported. Real CMS signatures, alternate hashes and unknown fields are refused.
"""
import hashlib
import struct
from .exports import require, span

PAGE = 4096
ALIGN = 16384
REQUIREMENTS = struct.pack(">III", 0xfade0c01, 12, 0)


def align(value, alignment=ALIGN):
    return (value + alignment - 1) // alignment * alignment


def geometry(limit, identifier):
    require(0 < limit < 2**32 and limit % PAGE == 0, "unsupported signature code limit")
    ident = identifier.encode("ascii") + b"\0"
    require(b"\0" not in ident[:-1] and len(ident) <= 1024, "invalid signing identifier")
    hashes = 88 + len(ident) + 64
    cdsize = hashes + (limit // PAGE) * 32
    return ident, hashes, cdsize, align(36 + cdsize + 20)


def emit(code, limit, identifier, text_size):
    """Recompute all signature bytes. The caller finalizes header fields first."""
    require(len(code) >= limit and 0 < text_size <= limit, "invalid code/exec span")
    ident, hashes, cdsize, sigsize = geometry(limit, identifier)
    result = bytearray(sigsize)
    end = 36 + cdsize
    struct.pack_into(">9I", result, 0, 0xfade0cc0, end + 20, 3,
                     0, 36, 2, end, 0x10000, end + 12)
    struct.pack_into(">9I4B", result, 36, 0xfade0c02, cdsize, 0x20400, 2,
                     hashes, 88, 2, limit // PAGE, limit, 32, 2, 0, 12)
    # scatter/team/spare/codeLimit64/execSegBase and execSegFlags stay zero.
    struct.pack_into(">Q", result, 36 + 72, text_size)
    result[36 + 88:36 + 88 + len(ident)] = ident
    result[36 + hashes - 64:36 + hashes - 32] = hashlib.sha256(REQUIREMENTS).digest()
    result[end:end + 12] = REQUIREMENTS
    struct.pack_into(">II", result, end + 12, 0xfade0b01, 8)
    for index, offset in enumerate(range(0, limit, PAGE)):
        start = 36 + hashes + index * 32
        result[start:start + 32] = hashlib.sha256(code[offset:offset + PAGE]).digest()
    return bytes(result)


def inspect(code, verify_pages=True):
    """Validate structure and hashes independently of the emitting layout code."""
    require(len(code) >= 552, "short cache header")
    offset, size = struct.unpack_from("<QQ", code, 40)
    require(offset > 0 and offset + size == len(code), "signature must end at EOF")
    blob = span(code, offset, size)
    magic, length, count = struct.unpack(">3I", span(blob, 0, 12))
    require(magic == 0xfade0cc0 and count == 3 and 36 <= length <= size, "unknown SuperBlob")
    require(size % ALIGN == 0 and size - length < ALIGN and not any(blob[length:]), "invalid signature padding")
    slots = {}
    ranges = []
    for i in range(count):
        kind, start = struct.unpack_from(">2I", blob, 12 + 8 * i)
        require(kind not in slots and start >= 36, "duplicate/overlapping signature index")
        child_magic, child_size = struct.unpack(">2I", span(blob, start, 8))
        require(child_size >= 8 and start + child_size <= length, "signature child range")
        slots[kind] = (child_magic, blob[start:start + child_size])
        ranges.append((start, start + child_size))
    ranges.sort()
    require(ranges[0][0] == 36 and ranges[-1][1] == length and
            all(a[1] == b[0] for a, b in zip(ranges, ranges[1:])), "signature children overlap or have gaps")
    require(set(slots) == {0, 2, 0x10000}, "unknown signature slots")
    require(slots[2][1] == REQUIREMENTS, "nonempty/unknown requirements")
    require(slots[0x10000][1] == struct.pack(">II", 0xfade0b01, 8), "CMS must be empty")
    cd = slots[0][1]
    require(len(cd) >= 88 and slots[0][0] == 0xfade0c02, "invalid CodeDirectory")
    version, flags, hashes, ident, special, pages, limit = struct.unpack_from(">7I", cd, 8)
    require((version, flags, special) == (0x20400, 2, 2), "unsupported CodeDirectory version/flags")
    require(cd[36:40] == bytes([32, 2, 0, 12]), "unsupported hash/platform/page format")
    require(cd[40:72] == bytes(32) and cd[80:88] == bytes(8), "unsupported CodeDirectory fields")
    require(offset == limit and limit % PAGE == 0 and pages == limit // PAGE, "signature coverage mismatch")
    require(ident == 88 and ident < hashes - 64 and hashes + pages * 32 == len(cd), "invalid hash table geometry")
    identity = cd[ident:hashes - 64]
    require(identity[-1:] == b"\0" and b"\0" not in identity[:-1], "invalid CodeDirectory identifier")
    require(cd[hashes - 64:hashes - 32] == hashlib.sha256(REQUIREMENTS).digest(), "requirements hash mismatch")
    require(cd[hashes - 32:hashes] == bytes(32), "unexpected Info slot hash")
    text_size = struct.unpack_from(">Q", cd, 72)[0]
    mapping = struct.unpack_from("<I", code, 16)[0]
    require(text_size == struct.unpack_from("<Q", code, mapping + 8)[0], "exec segment size mismatch")
    if verify_pages:
        for i in range(pages):
            require(hashlib.sha256(code[i * PAGE:(i + 1) * PAGE]).digest() == cd[hashes + i * 32:hashes + (i + 1) * 32],
                    f"code page hash mismatch: {i:#x}")
    return {"identifier": identity[:-1].decode("ascii"), "code_limit": limit,
            "signature_size": size, "text_size": text_size, "pages": pages,
            "cdhash": hashlib.sha256(cd).hexdigest()[:40]}
