"""Semantic and exhaustive byte verification, without consulting a writer plan.

This verifier independently derives the allowed changes from input/output cache
structures. It does not consume the writer's patch list or call make_plan.
"""
import copy
import hashlib
import struct
from .cache import commands
from . import atlas, codesign
from .exports import require


def verify(before, after):
    old, new = before.main, after.main
    cutoff = old.mappings[0].size
    growth = new.mappings[0].size - cutoff
    require(growth > 0 and growth % 16384 == 0, "invalid TEXT growth")
    require(before.images == after.images, "image identities/addresses changed")
    require(new.signature_offset == old.signature_offset + growth, "signature displacement mismatch")
    signatures = codesign.inspect(new.data)
    require(signatures["identifier"] == codesign.inspect(old.data, verify_pages=False)["identifier"], "signing identity changed")
    for i, (a, b) in enumerate(zip(before.files, after.files)):
        require(len(a.mappings) == len(b.mappings), "mapping count changed")
        if i:
            require(hashlib.sha256(a.data).digest() == hashlib.sha256(b.data).digest(), "subcache changed")
        else:
            for index, (ma, mb) in enumerate(zip(a.mappings, b.mappings)):
                require(ma.address == mb.address and ma.maximum == mb.maximum and ma.initial == mb.initial,
                        "mapping VM address/protection changed")
                require(mb.size == ma.size + (growth if index == 0 else 0)
                        and mb.offset == ma.offset + (growth if index else 0), "mapping geometry mismatch")
    # Exact header comparison. New array placement is checked independently below.
    expected_header = bytearray(old.data[:552])
    for offset, width in [(40, 8), (48, 8), (136, 8), (448, 4)]:
        expected_header[offset:offset + width] = new.data[offset:offset + width]
    require(bytes(expected_header) == new.data[:552], "unexpected header change")
    require(old.data[88:104] == new.data[88:104], "scratch identity changed")
    old_img, count = struct.unpack_from("<II", old.data, 448)
    old_text, text_count = struct.unpack_from("<QQ", old.data, 136)
    img = struct.unpack_from("<I", new.data, 448)[0]
    txt = struct.unpack_from("<Q", new.data, 136)[0]
    require(count == text_count, "source image table count mismatch")
    require(cutoff <= img and img + count * 32 <= txt and txt + count * 32 <= cutoff + growth,
            "new image arrays overlap or escape extension")
    extension = bytearray(growth)
    extension[img - cutoff:img - cutoff + count * 32] = old.data[old_img:old_img + count * 32]
    extension[txt - cutoff:txt - cutoff + count * 32] = old.data[old_text:old_text + count * 32]
    require(extension == new.data[cutoff:cutoff + growth], "extension content differs")
    skipped = [(0, 552), (old.mapping_offset, old.mapping_offset + 32 * len(old.mappings)),
               (old.slide_offset, old.slide_offset + 56 * len(old.mappings))]
    for index in range(len(old.mappings)):
        a = list(struct.unpack_from("<6QII", old.data, old.slide_offset + index * 56))
        b = struct.unpack_from("<6QII", new.data, new.slide_offset + index * 56)
        if index == 0:
            a[1] += growth
        else:
            a[2] += growth
        if a[3] >= cutoff:
            a[3] += growth
        require(tuple(a) == b, "slide mapping semantics changed")
    main_images = 0
    checked_commands = 0
    for path, address in before.images:
        old_commands, new_commands = commands(before, address), commands(after, address)
        require(len(old_commands) == len(new_commands), "command count changed")
        owner, header_offset = before.locate(address)
        if owner is not old:
            continue  # entire subcache was byte-compared above
        main_images += 1
        def translate(value):
            return value + growth if value >= cutoff else value
        for (loc, command, raw), (newloc, newcommand, actual) in zip(old_commands, new_commands):
            require(loc == newloc and command == newcommand and len(raw) == len(actual), "command identity changed")
            expected = bytearray(raw)
            offsets = []
            if command == 25:
                va, size, fileoff, filesize = struct.unpack_from("<4Q", raw, 24)
                if filesize:
                    require(before.locate(va, filesize)[0] is old, "unexpected cross-file segment")
                    require(after.locate(va, filesize)[1] == translate(fileoff), "segment no longer maps same VM bytes")
                offsets.append((40, 8))
                sections = struct.unpack_from("<I", raw, 64)[0]
                offsets += [(72 + i * 80 + 48, 4) for i in range(sections)]
                require(all(struct.unpack_from("<II", raw, 72 + i * 80 + 56) == (0, 0) for i in range(sections)),
                        "section relocations unsupported")
            elif command == 2:
                offsets = [(8, 4), (16, 4)]
            elif command == 11:
                offsets = [(p, 4) for p in (32, 40, 48, 56, 64, 72)]
            elif command in (0x22, 0x80000022):
                offsets = [(p, 4) for p in (8, 16, 24, 32, 40)]
            elif command in (0x26, 0x29, 0x80000033, 0x80000034, 0x1d, 0x1e):
                offsets = [(8, 4)]
            elif command not in (0xd, 0x1b, 0x32, 0x2a, 0xc, 0x80000018, 0x80000023, 0x12,
                                 0xf, 0x5, 0x24, 0x8000001f, 0x14):
                raise ValueError(f"unknown verifier load command: {command:#x}")
            for position, width in offsets:
                value = int.from_bytes(raw[position:position + width], "little")
                expected[position:position + width] = translate(value).to_bytes(width, "little")
            require(bytes(expected) == actual, f"load command semantics differ: {path} {command:#x}")
            offset = old.offset(loc, len(raw))
            require(offset is not None and offset + len(raw) <= cutoff, "header outside main TEXT")
            skipped.append((offset, offset + len(raw)))
            checked_commands += 1
    # Exhaust all source bytes outside fields that were semantically verified.
    skipped.sort()
    merged = []
    for start, end in skipped:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(end, merged[-1][1]))
        else:
            merged.append((start, end))
    checked_bytes = 0
    def compare(start, end):
        total = end - start
        while start < end:
            stop = min(end, start + (8 << 20), cutoff if start < cutoff else end)
            target = start + (growth if start >= cutoff else 0)
            require(old.data[start:stop] == new.data[target:target + stop - start],
                    f"unexpected content mutation in source range {start:#x}..{stop:#x}")
            start = stop
        return total
    cursor = 0
    for start, end in merged:
        checked_bytes += compare(cursor, start)
        cursor = end
    checked_bytes += compare(cursor, old.signature_offset)
    # Sidecar verification independently compares all fields, and derives expected
    # segment offsets from the output VM mapping rather than the writer patch list.
    original_atlas = atlas.read(old.path.with_name(old.path.name + ".atlas"), old.data[88:104])
    actual_atlas = atlas.read(new.path.with_name(new.path.name + ".atlas"), new.data[88:104])
    expected_atlas = copy.deepcopy(original_atlas)
    cache = expected_atlas["names"][atlas.BASE]
    file_record = cache["dscs"][0]
    file_record["fsze"] = len(new.data)
    for record, mapping in zip(file_record["maps"], new.mappings):
        record["size"], record["foff"] = mapping.size, mapping.offset
    for image in cache["imgs"]:
        for segment in image["segs"]:
            if segment["fsze"]:
                segment["foff"] = after.locate(segment["padr"], segment["fsze"])[1]
    expected_atlas["uuids"][next(iter(expected_atlas["uuids"]))] = cache
    require(expected_atlas == actual_atlas, "atlas semantics differ")
    old_map = old.path.with_name(old.path.name + ".map").read_text()
    new_map = new.path.with_name(new.path.name + ".map").read_text()
    old_lines, new_lines = old_map.splitlines(), new_map.splitlines()
    require(old_lines[1:] == new_lines[1:], "map image/subcache records changed")
    end_address = new.mappings[0].address + new.mappings[0].size
    require(new_lines[0] == f"mapping  EX {new.mappings[0].size // 1048576:4d}MB 0x{new.mappings[0].address:X} -> 0x{end_address:X}",
            "map TEXT range mismatch")
    return {"result": "PASS_SCRATCH_RELAYOUT", "growth": growth, "main_images": main_images,
            "main_commands_checked": checked_commands, "unchanged_main_content_bytes": checked_bytes,
            "unchanged_subcaches": 6, "image_identities_preserved": len(before.images),
            "extension_bytes_checked": growth, "signature": signatures,
            "sidecars": "atlas semantic equality after mapped-offset updates; map range updated",
            "deployment": "NOT ACCEPTED: identities preserved only for this layout oracle; no target runtime test"}
