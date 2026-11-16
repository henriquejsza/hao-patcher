"""Bounded LC_ID_DYLIB normalization for cache-builder inputs, never installation.

Only load-command bytes, ncmds and sizeofcmds change. File length, slice positions,
section/segment addresses, payloads, UUID and embedded signature bytes remain.
The explicit cache-input mode removes LC_CODE_SIGNATURE, as dyld's cache adjustor
does, while retaining its now-unreferenced blob bytes. No signing is performed.
"""
import hashlib
import struct

from .exports import Refusal, cstring, require, span


def x86_slice(data):
    """Validate universal extents and select exactly one plain x86_64 slice."""
    magic, = struct.unpack(">I", span(data, 0, 4))
    if magic == 0xcffaedfe:
        return 0, len(data), []
    require(magic in (0xcafebabe, 0xcafebabf), "unsupported Mach-O container")
    count, = struct.unpack(">I", span(data, 4, 4))
    require(0 < count <= 64, "unsupported universal slice count")
    width = 20 if magic == 0xcafebabe else 32
    table_end = 8 + count * width
    span(data, 0, table_end)
    entries, selected = [], []
    for i in range(count):
        at = 8 + i * width
        cpu, sub = struct.unpack_from(">II", data, at)
        if width == 20:
            off, size, align = struct.unpack_from(">III", data, at + 8)
        else:
            off, size, align, reserved = struct.unpack_from(">QQII", data, at + 8)
            require(reserved == 0, "nonzero universal reserved field")
        require(align <= 30 and off % (1 << align) == 0,
                "invalid universal slice alignment")
        require(off >= table_end and size >= 32, "universal slice overlaps table or is short")
        span(data, off, size)
        require(not any(off < p + n and p < off + size for p, n in entries),
                "overlapping universal slices")
        entries.append((off, size))
        if (cpu, sub) == (0x1000007, 3):
            selected.append((off, size))
    require(len(selected) == 1, "need exactly one x86_64 subtype 3 slice")
    return *selected[0], entries


def inspect(data):
    """Read only the explicitly supported layout; refuse unknown command semantics."""
    base, length, slices = x86_slice(data)
    image = span(data, base, length)
    magic, cpu, subtype, kind, count, command_size, flags, reserved = struct.unpack(
        "<8I", span(image, 0, 32))
    require((magic, cpu, subtype, kind) == (0xfeedfacf, 0x1000007, 3, 6),
            "expected x86_64 subtype 3 MH_DYLIB")
    require(reserved == 0 and 0 < count <= 4096, "unsupported Mach-O header")
    commands = span(image, 32, command_size)
    end = 32 + command_size
    records, identities, payloads, signatures, text = [], [], [], [], []

    def payload(off, size):
        span(image, off, size)
        if size:
            require(off >= end, "payload overlaps load commands")
            payloads.append(off)

    pos = 0
    for _ in range(count):
        command, size = struct.unpack("<II", span(commands, pos, 8))
        require(size >= 8 and size % 8 == 0, "invalid load-command size")
        raw = span(commands, pos, size)
        record = {"command": command, "offset": 32 + pos, "size": size}
        if command == 0x19:
            span(raw, 0, 72)
            vm, vmsize, off, filesize = struct.unpack_from("<QQQQ", raw, 24)
            span(image, off, filesize)
            nsects, = struct.unpack_from("<I", raw, 64)
            require(size == 72 + 80 * nsects, "invalid segment command size")
            if filesize and off:
                payload(off, filesize)
            if raw[8:24].rstrip(b"\0") == b"__TEXT":
                require(off == 0 and filesize >= end, "unsupported TEXT mapping")
                text.append((off, filesize))
            for section in range(nsects):
                at = 72 + 80 * section
                address, secsize, secoff, align, reloff, nreloc, secflags = struct.unpack_from(
                    "<QQIIIII", raw, at + 32)
                if secsize:
                    require(vm <= address and address + secsize <= vm + vmsize,
                            "section outside segment VM range")
                if secflags & 0xff not in (1, 0xc, 0x12):
                    if secsize:
                        require(off <= secoff and secoff + secsize <= off + filesize,
                                "section outside segment file range")
                        payload(secoff, secsize)
                payload(reloff, nreloc * 8)
        elif command in (0xc, 0xd, 0x80000018, 0x8000001f, 0x80000023, 0x20):
            span(raw, 0, 24)
            nameoff, timestamp = struct.unpack_from("<II", raw, 8)
            require(timestamp != 0x1a741800, "dylib_use_command unsupported")
            require(nameoff == 24, "unsupported dylib name offset")
            name, name_end = cstring(raw, nameoff)
            require(name and not any(raw[name_end:]), "nonzero dylib padding")
            record["name"] = name
            if command == 0xd:
                identities.append(record)
        elif command in (0x1d, 0x26, 0x29, 0x80000033, 0x80000034):
            require(size == 16, "invalid linkedit command size")
            off, datasize = struct.unpack_from("<II", raw, 8)
            payload(off, datasize)
            if command == 0x1d:
                signatures.append((off, datasize))
        elif command == 2:
            require(size == 24, "invalid symtab command size")
            symoff, nsyms, stroff, strsize = struct.unpack_from("<4I", raw, 8)
            payload(symoff, nsyms * 16)
            payload(stroff, strsize)
        elif command == 0xb:
            require(size == 80, "invalid dysymtab command size")
            values = struct.unpack_from("<18I", raw, 8)
            for index, width in ((6, 8), (8, 56), (10, 4), (12, 4), (14, 8), (16, 8)):
                payload(values[index], values[index + 1] * width)
        elif command == 0x1b:
            require(size == 24, "invalid UUID command size")
        elif command == 0x32:
            require(size >= 24, "invalid build-version size")
            require(size == 24 + 8 * struct.unpack_from("<I", raw, 20)[0],
                    "invalid build tools count")
        elif command == 0x2a:
            require(size == 16, "invalid source-version size")
        else:
            raise Refusal(f"unsupported load command: {command:#x}")
        records.append(record)
        pos += size
    require(pos == len(commands), "load-command count/size mismatch")
    require(len(identities) == 1 and len(text) == 1 and payloads,
            "need one identity, one TEXT mapping and bounded payloads")
    first = min(payloads)
    require(first <= text[0][1], "header padding outside TEXT")
    require(not any(image[end:first]), "nonzero header padding")
    require(len(signatures) <= 1, "multiple signatures unsupported")
    return {"slice_offset": base, "slice_size": length, "slices": slices,
            "commands": records, "identity": identities[0], "command_end": end,
            "first_payload": first, "signature": signatures[0] if signatures else None}


def normalize(data, expected_name, canonical_name, *, remove_signature_command=False):
    """Replace the ID using verified header padding without changing file layout."""
    before = inspect(data)
    identity = before["identity"]
    require(identity["name"] == expected_name, "source install name drift")
    require(canonical_name.startswith("/") and "\0" not in canonical_name,
            "canonical install name must be absolute without NUL")
    encoded = canonical_name.encode("utf-8") + b"\0"
    size = (24 + len(encoded) + 7) & ~7
    id_growth = size - identity["size"]
    require(id_growth >= 0, "shrinking command not supported")
    removed = [record for record in before["commands"] if record["command"] == 0x1d]
    if remove_signature_command:
        require(len(removed) == 1, "cache-input mode requires one original signature command")
    else:
        removed = []
    growth = id_growth - sum(record["size"] for record in removed)
    require(growth >= 0, "shrinking command region not supported")
    require(before["command_end"] + growth <= before["first_payload"],
            "insufficient verified header padding; payload relayout refused")
    base, end = before["slice_offset"], before["command_end"]
    commands = bytearray()
    for record in before["commands"]:
        raw = span(data, base + record["offset"], record["size"])
        if record in removed:
            continue
        if record["command"] == 0xd:
            raw = bytearray(raw[:24])
            struct.pack_into("<I", raw, 4, size)
            raw += encoded + bytes(size - 24 - len(encoded))
        commands += raw
    result = bytearray(data)
    result[base + 32:base + end + growth] = commands
    struct.pack_into("<I", result, base + 16, len(before["commands"]) - len(removed))
    struct.pack_into("<I", result, base + 20, end - 32 + growth)
    after = inspect(result)
    require(after["identity"]["name"] == canonical_name, "output identity mismatch")
    require(len(result) == len(data), "output length changed")
    require(result[:base] == data[:base] and result[base + end + growth:] == data[base + end + growth:],
            "bytes outside covered header changed")
    return bytes(result), {"before": before, "after": after, "command_growth": growth,
                           "id_command_growth": id_growth,
                           "removed_commands": removed,
                           "signature_status": "retained blob bytes; original covered header changed; NOT valid trust evidence"}


def signature_pages(data, *, original_signature_range=None):
    """Independently compare SHA-256 code slots; no CMS or trust verification."""
    layout = inspect(data)
    signature_range = original_signature_range or layout["signature"]
    require(signature_range is not None, "no embedded signature")
    base = layout["slice_offset"]
    off, size = signature_range
    signature = span(data, base + off, size)
    magic, length, count = struct.unpack(">III", span(signature, 0, 12))
    require(magic == 0xfade0cc0 and length <= len(signature) and count <= 32,
            "unsupported signature superblob")
    directory, cms = [], []
    for index in range(count):
        slot, start = struct.unpack(">II", span(signature, 12 + index * 8, 8))
        blobmagic, blobsize = struct.unpack(">II", span(signature, start, 8))
        blob = span(signature[:length], start, blobsize)
        if slot == 0:
            require(blobmagic == 0xfade0c02, "invalid CodeDirectory")
            directory.append(blob)
        if slot == 0x10000:
            cms.append({"size": blobsize, "sha256": hashlib.sha256(blob).hexdigest()})
    require(len(directory) == 1, "need one primary CodeDirectory")
    cd = directory[0]
    version, flags, hash_offset, ident, specials, count, limit = struct.unpack(
        ">7I", span(cd, 8, 28))
    hashsize, hashtype, platform, page = struct.unpack("4B", span(cd, 36, 4))
    require(version >= 0x20000 and hashsize == 32 and hashtype == 2 and page <= 16,
            "unsupported CodeDirectory hash format")
    require(limit <= off and count == (limit + (1 << page) - 1) >> page,
            "invalid code slot coverage")
    hashes = span(cd, hash_offset, count * hashsize)
    mismatches = []
    for index in range(count):
        start = index << page
        content = span(data, base + start, min(1 << page, limit - start))
        if hashlib.sha256(content).digest() != hashes[index * 32:(index + 1) * 32]:
            mismatches.append(index)
    return {"referenced_by_load_command": layout["signature"] is not None,
            "version": hex(version), "flags": flags, "code_slots": count,
            "code_limit": limit, "page_size": 1 << page, "mismatching_code_slots": mismatches,
            "cms": cms, "cms_or_trust_verified": False,
            "signature_sha256": hashlib.sha256(signature).hexdigest()}


def verify_normalized(source, candidate, expected_name, canonical_name, *, removed_signature):
    """Derive allowed byte differences independently; do not consume writer plan."""
    old, new = inspect(source), inspect(candidate)
    require(len(source) == len(candidate), "candidate length changed")
    require((old["slice_offset"], old["slice_size"], old["slices"]) ==
            (new["slice_offset"], new["slice_size"], new["slices"]), "slice layout changed")
    require(old["identity"]["name"] == expected_name and
            new["identity"]["name"] == canonical_name, "identity mismatch")
    base = old["slice_offset"]
    require(source[:base] == candidate[:base] and
            source[base + old["slice_size"]:] == candidate[base + old["slice_size"]:],
            "other slices or container bytes changed")
    require(source[base:base + 16] == candidate[base:base + 16] and
            source[base + 24:base + 32] == candidate[base + 24:base + 32],
            "unrelated Mach-O header fields changed")
    require(old["first_payload"] == new["first_payload"], "payload start changed")
    require(source[base + old["first_payload"]:base + old["slice_size"]] ==
            candidate[base + new["first_payload"]:base + new["slice_size"]],
            "payload bytes changed")
    old_commands = [item for item in old["commands"]
                    if not (removed_signature and item["command"] == 0x1d)]
    require(len(old_commands) == len(new["commands"]), "unexpected removed/added commands")
    if removed_signature:
        require(old["signature"] is not None and new["signature"] is None,
                "unexpected signature command state")
    else:
        require(new["signature"] == old["signature"], "unexpected signature command state")
    for before, after in zip(old_commands, new["commands"]):
        require(before["command"] == after["command"], "command order changed")
        raw_before = span(source, base + before["offset"], before["size"])
        raw_after = span(candidate, base + after["offset"], after["size"])
        if before["command"] == 0xd:
            require(raw_before[:4] == raw_after[:4] and raw_before[8:24] == raw_after[8:24],
                    "dylib identity fields changed")
        else:
            require(raw_before == raw_after, "unrelated load command changed")
    return {"unrelated_header_and_commands_unchanged": True, "all_payload_bytes_unchanged": True,
            "container_and_other_slices_unchanged": True, "commands_compared": len(old_commands)}
