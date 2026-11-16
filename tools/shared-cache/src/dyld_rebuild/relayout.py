"""Scratch-only main TEXT extension with unchanged image/VM identities.

This is a relayout oracle, not a deployable cache transformer. UUIDs, loader sets,
symbols and all existing VM addresses are deliberately preserved. A semantic
replacement requires a new identity policy and regenerated metadata separately.
"""
from dataclasses import dataclass, asdict
import struct
from . import codesign
from .cache import commands
from .exports import require, span

# Observed no-file-offset load commands in the pinned family. Unknowns refuse.
NO_OFFSETS = {0xd, 0x1b, 0x32, 0x2a, 0xc, 0x80000018, 0x80000023,
              0x12, 0xf, 0x5, 0x24, 0x8000001f, 0x14}
# 0x3a: new on 27, not in dyld-1378's loader.h. In 26B131's cache: 90 commands in 31 images, all
# 16-byte (offset, size) pairs inside the image's LINKEDIT, so they move with LINKEDIT like the others.
LINKEDIT_DATA = {0x26, 0x29, 0x80000033, 0x80000034, 0x1d, 0x1e, 0x3a}


@dataclass(frozen=True)
class Patch:
    offset: int
    width: int
    before: int
    after: int
    reason: str


def make_plan(family, growth=0x40000, reserve=16, *, expected_main_images=432):
    main = family.main
    data = main.data
    cutoff = main.mappings[0].size
    require(growth > 0 and growth % codesign.ALIGN == 0, "growth must be positive and 16K aligned")
    require(cutoff + growth + main.mappings[0].address <= main.mappings[1].address, "TEXT extension exceeds VM gap")
    # These require separate implementations if they ever appear in a future input.
    for off, size in [(24, 8), (56, 32), (112, 8), (480, 16), (536, 16)]:
        require(span(data, off, size) == bytes(size), f"unsupported header field at {off:#x}")
    require(0 <= reserve <= 1024, "invalid reserved image capacity")
    imageoff, count = struct.unpack_from("<II", data, 448)
    textoff, textcount = struct.unpack_from("<QQ", data, 136)
    require(count == textcount == len(family.images), "image table counts disagree")
    require(imageoff + count * 32 <= cutoff and textoff + count * 32 <= cutoff, "original image arrays not in TEXT")
    new_images = cutoff
    new_text = cutoff + (count + reserve) * 32
    require(new_text + (count + reserve) * 32 <= cutoff + growth, "extension too small for image arrays")
    signature = codesign.inspect(data)
    # An unchanged-input signing oracle must match the complete original blob.
    rebuilt = codesign.emit(data, signature["code_limit"], signature["identifier"], cutoff)
    require(rebuilt == data[main.signature_offset:], "original signature writer oracle differs")
    new_limit = main.signature_offset + growth
    new_sigsize = codesign.geometry(new_limit, signature["identifier"])[3]
    patches = {}

    def write(offset, width, after, reason):
        before = int.from_bytes(span(data, offset, width), "little")
        require(0 <= after < 1 << (8 * width), "relocated value overflow")
        if before == after:
            return
        patch = Patch(offset, width, before, after, reason)
        if offset in patches:
            require(patches[offset].after == after and patches[offset].width == width, "conflicting patch")
        else:
            patches[offset] = patch

    def shifted(value):
        require(0 <= value <= main.signature_offset, "file offset outside main content")
        return value + growth if value >= cutoff else value

    def file_field(where, width, value, length, owner, reason):
        require(value + length <= owner.signature_offset, "load-command range exceeds signed file")
        if length:
            require(any(m.offset <= value and value + length <= m.offset + m.size for m in owner.mappings),
                    "load-command content crosses mappings")
        if owner is main and value:
            patch_file, patch_offset = family.locate(where, width)
            require(patch_file is main, "cross-subcache file-offset mutation unsupported")
            write(patch_offset, width, shifted(value), reason)

    write(40, 8, new_limit, "header.codeSignatureOffset")
    write(48, 8, new_sigsize, "header.codeSignatureSize")
    write(448, 4, new_images, "header.imagesOffset")
    write(136, 8, new_text, "header.imagesTextOffset")
    for i, mapping in enumerate(main.mappings):
        off = main.mapping_offset + i * 32
        slide = main.slide_offset + i * 56
        if i == 0:
            write(off + 8, 8, cutoff + growth, "mapping.TEXT.size")
            write(slide + 8, 8, cutoff + growth, "slideMapping.TEXT.size")
        else:
            write(off + 16, 8, shifted(mapping.offset), "mapping.fileOffset")
            write(slide + 16, 8, shifted(mapping.offset), "slideMapping.fileOffset")
        slide_info = struct.unpack_from("<Q", data, slide + 24)[0]
        if slide_info:
            write(slide + 24, 8, shifted(slide_info), "slideMapping.slideInfoFileOffset")
    main_images = 0
    section_count = 0
    referenced_ranges = 0
    preserved_relative_sections = []
    for path, address in family.images:
        cmds = commands(family, address)
        header_file, _ = family.locate(address)
        if header_file is main:
            main_images += 1
        linkedit = None
        for location, command, raw in cmds:
            if command != 0x19:
                continue
            require(len(raw) >= 72, "short segment command")
            va, vs, fo, fs = struct.unpack_from("<4Q", raw, 24)
            nsects = struct.unpack_from("<I", raw, 64)[0]
            require(len(raw) == 72 + nsects * 80, "segment section count mismatch")
            name = raw[8:24].split(b"\0", 1)[0]
            if fs:
                owner, actual = family.locate(va, fs)
                require(actual == fo, f"segment file offset disagrees with mapping: {path}")
                file_field(location + 40, 8, fo, fs, owner, "segment.fileoff")
            else:
                owner = header_file
                require(fo == 0 or (vs == 0 and owner.offset(va, 0) == fo), "unknown empty-segment offset convention")
                file_field(location + 40, 8, fo, 0, owner, "emptySegment.fileoff")
            if name == b"__LINKEDIT":
                require(linkedit is None and fs > 0, "invalid LINKEDIT segment")
                linkedit = owner
            for i in range(nsects):
                section = span(raw, 72 + i * 80, 80)
                sva, ssize, soff, _, reloff, nreloc, flags = struct.unpack_from("<QQ5I", section, 32)
                require(va <= sva <= va + vs and ssize <= va + vs - sva, "section outside segment VM range")
                zerofill = flags & 0xff in (1, 0xc, 0x12)
                if not zerofill and ssize:
                    cf, real = family.locate(sva, ssize)
                    if cf is owner and real != soff:
                        # Exactly one observed image retains relative TEXT section offsets.
                        # Its TEXT bytes and offsets do not move in this experiment. Do not
                        # silently normalize these fields or extrapolate to moved sections.
                        require(path == "/usr/lib/system/libcorecrypto.dylib" and name == b"__TEXT"
                                and owner is main and soff == sva - va and fo + fs <= cutoff,
                                f"section offset disagrees with mapping: {path} {section[:16]!r}")
                        preserved_relative_sections.append({"path": path, "section": section[:16].split(b"\0")[0].decode(),
                                                            "recorded": soff, "mapped_file_offset": real})
                    else:
                        require(cf is owner and real == soff, "section owner disagrees with mapping")
                if zerofill:
                    require(soff == 0, "zero-fill section has file bytes")
                else:
                    file_field(location + 72 + i * 80 + 48, 4, soff, ssize, owner, "section.offset")
                # Cached relocation entries are absent in this pinned format.
                require(reloff == nreloc == 0, "section relocations require separate implementation")
                if owner is main:
                    section_count += 1
        require(linkedit is not None, "missing LINKEDIT")
        for location, command, raw in cmds:
            fields = []
            if command in (0x19, *NO_OFFSETS):
                continue
            if command == 2:
                require(len(raw) == 24, "invalid symtab command")
                fields = [(8, 16), (16, 1)]
            elif command == 0xb:
                require(len(raw) == 80, "invalid dysymtab command")
                fields = [(32, 8), (40, 56), (48, 4), (56, 4), (64, 8), (72, 8)]
            elif command in LINKEDIT_DATA:
                require(len(raw) == 16, "invalid linkedit-data command")
                fields = [(8, 1)]
            elif command in (0x22, 0x80000022):
                require(len(raw) == 48, "invalid dyld-info command")
                fields = [(pos, 1) for pos in range(8, 48, 8)]
            else:
                raise ValueError(f"unsupported load command {command:#x} in {path}")
            for pos, unit in fields:
                offset, length = struct.unpack_from("<II", raw, pos)
                require(offset != 0 or length == 0, "nonempty linkedit content at offset zero")
                file_field(location + pos, 4, offset, length * unit, linkedit, f"loadCommand.{command:#x}.{pos}")
                if linkedit is main and length:
                    referenced_ranges += 1
    require(type(expected_main_images) is int and main_images == expected_main_images, "unexpected main-file image count")
    ordered = sorted(patches.values(), key=lambda p: p.offset)
    require(all(a.offset + a.width <= b.offset for a, b in zip(ordered, ordered[1:])), "patches overlap")
    extension = bytearray(growth)
    extension[:count * 32] = span(data, imageoff, count * 32)
    extension[new_text - cutoff:new_text - cutoff + count * 32] = span(data, textoff, count * 32)
    return {"cutoff": cutoff, "growth": growth, "reserve_entries": reserve,
            "signature": signature, "new_signature_offset": new_limit,
            "new_signature_size": new_sigsize, "new_images_offset": new_images,
            "new_image_text_offset": new_text, "main_images": main_images,
            "main_sections": section_count, "main_linkedit_ranges": referenced_ranges,
            "preserved_relative_sections": preserved_relative_sections,
            "patches": [asdict(p) for p in ordered]}, bytes(extension)


def write_main(family, path, plan, extension):
    """Write to a new scratch path. Never touches the source or an existing file."""
    source = family.main.data
    cutoff, growth = plan["cutoff"], plan["growth"]
    with path.open("xb") as output:
        for begin, end in ((0, cutoff), (cutoff, family.main.signature_offset)):
            for offset in range(begin, end, 8 << 20):
                output.write(source[offset:min(end, offset + (8 << 20))])
            if begin == 0:
                output.write(extension)
        for patch in plan["patches"]:
            location = patch["offset"] + (growth if patch["offset"] >= cutoff else 0)
            require(int.from_bytes(source[patch["offset"]:patch["offset"] + patch["width"]], "little") == patch["before"],
                    "source changed after planning")
            output.seek(location)
            output.write(patch["after"].to_bytes(patch["width"], "little"))
        output.truncate(plan["new_signature_offset"])
    # Hash only after all header/load-command modifications are complete.
    import mmap
    with path.open("rb") as stream, mmap.mmap(stream.fileno(), 0, access=mmap.ACCESS_READ) as data:
        signature = codesign.emit(data, plan["new_signature_offset"], plan["signature"]["identifier"], cutoff + growth)
    require(len(signature) == plan["new_signature_size"], "signature geometry changed")
    with path.open("ab") as output:
        output.write(signature)
