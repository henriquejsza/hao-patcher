"""Read x86_64 classic bind imports and chained import tables without execution.

Rows preserve weak-import, special ordinal, lazy/eager, addend and bind type.
Chained tables are audited in full, including any entry without a pointer use.
Unknown schemas/opcodes are refusals, never empty successful inventories.
"""
from __future__ import annotations
from dataclasses import dataclass
import struct
from .exports import Refusal, cstring, read_image, require, span, uleb
from .provider_identity import x86_slice


@dataclass(frozen=True)
class Import:
    symbol: str
    ordinal: int
    provider: str
    weak: bool
    lazy: bool
    addend: int
    bind_type: int
    source: str
    address: int | None = None
    table_index: int | None = None


def sleb(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = span(data, offset, 1)[0]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            if byte & 64:
                value -= 1 << (shift + 7)
            require(-(1 << 63) <= value < (1 << 63), "SLEB128 overflow")
            return value, offset
    raise Refusal("SLEB128 overflow")


def provider(image, ordinal):
    if ordinal in (0, -1, -2, -3):
        return {0: image.install_name, -1: "SPECIAL:main-executable",
                -2: "SPECIAL:flat-lookup", -3: "SPECIAL:weak-lookup"}[ordinal]
    require(1 <= ordinal <= len(image.dependencies), f"invalid import library ordinal {ordinal}")
    return image.dependencies[ordinal - 1].path


def chained_imports(payload, image):
    version, starts, imports, symbols, count, fmt, symfmt = struct.unpack(
        "<7I", span(payload, 0, 28))
    require(version == 0 and fmt in (1, 2, 3) and symfmt == 0,
            "unsupported chained import header/schema")
    require(count <= 1_000_000, "chained import count limit")
    width = {1: 4, 2: 8, 3: 16}[fmt]
    require(imports >= 28 and imports + count * width <= symbols <= len(payload),
            "invalid chained imports/symbols extents")
    span(payload, imports, count * width)
    result = []
    for index in range(count):
        offset = imports + index * width
        if fmt in (1, 2):
            word, = struct.unpack("<I", span(payload, offset, 4))
            ordinal, weak, nameoff = word & 255, bool(word & 256), word >> 9
            if ordinal > 240:
                ordinal -= 256
            addend = struct.unpack_from("<i", payload, offset + 4)[0] if fmt == 2 else 0
        else:
            word, addend = struct.unpack("<Qq", span(payload, offset, 16))
            ordinal, weak, nameoff = word & 65535, bool(word & 65536), word >> 32
            require((word >> 17) & 0x7fff == 0, "nonzero chained import reserved bits")
            if ordinal > 65520:
                ordinal -= 65536
        name, _ = cstring(payload, symbols + nameoff)
        require(bool(name), "empty import name")
        result.append(Import(name, ordinal, provider(image, ordinal), weak, False,
                             addend, 1, "chained", table_index=index))
    return result


def classic_imports(data, image, segments, stream_kind):
    """Decode regular/lazy/weak bind opcodes, preserving each bind location."""
    require(stream_kind in ("bind", "lazy", "weak"), "unknown classic bind stream")
    pos, rows, definitions = 0, [], []
    ordinal, symbol, addend, kind, segment, delta, weak = None, None, 0, 1, None, None, False
    if stream_kind == "weak":
        ordinal = -3

    def bind():
        nonlocal delta
        require(ordinal is not None and symbol and segment is not None and delta is not None,
                "incomplete classic bind state")
        require(kind in (1, 2, 3), "unsupported classic bind type")
        vm, vmsize, off, filesize = segments[segment]
        require(0 <= delta and delta + (8 if kind == 1 else 4) <= min(vmsize, filesize),
                "classic bind outside file-backed segment")
        rows.append(Import(symbol, ordinal, provider(image, ordinal), weak,
                           stream_kind == "lazy", addend, kind, stream_kind, vm + delta))
        require(len(rows) <= 2_000_000, "classic bind expansion limit")
        delta = (delta + 8) & ((1 << 64)-1)

    while pos < len(data):
        byte = data[pos]
        pos += 1
        op, imm = byte & 240, byte & 15
        if op == 0:
            require(imm == 0, "invalid DONE opcode")
            if stream_kind != "lazy":
                require(not any(data[pos:]), "nonzero data after bind DONE")
                return rows, definitions
            ordinal, symbol, addend, kind, segment, delta, weak = None, None, 0, 1, None, None, False
        elif op == 0x10:
            ordinal = imm
        elif op == 0x20:
            ordinal, pos = uleb(data, pos)
        elif op == 0x30:
            ordinal = imm - 16 if imm else 0
        elif op == 0x40:
            require(not imm & ~9, "unknown bind symbol flags")
            symbol, pos = cstring(data, pos)
            require(bool(symbol), "empty bind symbol")
            weak = bool(imm & 1)
            if imm & 8:
                require(stream_kind == "weak", "nonweak-definition marker outside weak stream")
                definitions.append(symbol)
        elif op == 0x50:
            kind = imm
        elif op == 0x60:
            addend, pos = sleb(data, pos)
        elif op == 0x70:
            require(imm < len(segments), "bad classic bind segment ordinal")
            segment = imm
            delta, pos = uleb(data, pos)
        elif op == 0x80:
            skip, pos = uleb(data, pos)
            require(delta is not None, "address advance without segment")
            delta = (delta + skip) & ((1 << 64)-1)
        elif op == 0x90:
            require(imm == 0, "invalid DO_BIND immediate")
            bind()
        elif op == 0xa0:
            require(imm == 0, "invalid DO_BIND_ADD_ADDR_ULEB immediate")
            bind()
            skip, pos = uleb(data, pos)
            delta = (delta + skip) & ((1 << 64)-1)
        elif op == 0xb0:
            bind()
            delta = (delta + imm * 8) & ((1 << 64)-1)
        elif op == 0xc0:
            require(imm == 0, "invalid DO_BIND_ULEB_TIMES_SKIPPING_ULEB immediate")
            count, pos = uleb(data, pos)
            skip, pos = uleb(data, pos)
            require(count <= 2_000_000, "classic bind repeat limit")
            for _ in range(count):
                bind()
                delta = (delta + skip) & ((1 << 64)-1)
        else:
            raise Refusal(f"unsupported classic bind opcode {op:#x}")
    # A complete opcode at the declared byte extent also terminates the stream.
    return rows, definitions


def read_imports(data, *, canonical_install_name=None, bundle_path=None):
    base, size, _ = x86_slice(data)
    data = span(data, base, size)
    image = read_image(data,bundle_path=bundle_path)
    if canonical_install_name is not None:
        image.install_name = canonical_install_name
    count, cmdsize = struct.unpack("<II", span(data, 16, 8))
    body = span(data, 32, cmdsize)
    pos, segments, streams, chained, classic_commands = 0, [], [], [], 0
    for _ in range(count):
        cmd, length = struct.unpack("<II", span(body, pos, 8))
        require(length >= 8 and length % 8 == 0, "invalid import load command")
        row = span(body, pos, length)
        if cmd == 0x19:
            segments.append(struct.unpack("<4Q", span(row, 24, 32)))
        elif cmd in (0x22, 0x80000022):
            classic_commands += 1
            require(length == 48, "invalid dyld-info command")
            for at, kind in ((16, "bind"), (24, "weak"), (32, "lazy")):
                off, size_ = struct.unpack_from("<II", row, at)
                if size_:
                    streams.append((kind, span(data, off, size_)))
        elif cmd == 0x80000034:
            require(length == 16, "invalid chained fixups command")
            chained.append(span(data, *struct.unpack_from("<II", row, 8)))
        pos += length
    require(pos == len(body), "import command count/size mismatch")
    require(len(chained) + classic_commands == 1,
            "missing/conflicting import format; relocations require another reader")
    rows, definitions = [], []
    for kind, stream in streams:
        parsed, defs = classic_imports(stream, image, segments, kind)
        rows += parsed
        definitions += defs
    for payload in chained:
        rows += chained_imports(payload, image)
    return image, rows, {"format": "chained" if chained else "classic", "nonweak_definitions": definitions,
                         "import_records": len(rows), "slice_offset": base, "slice_size": len(data)}


def resolve_import(graph, image, row):
    """Classify an import without a root-override sentinel or runtime fallback."""
    if row.ordinal == -3:
        result = graph.resolve_weak_for_cache_build(image.install_name, row.symbol)
    elif row.ordinal == -2:
        result = graph.resolve_flat(row.symbol)
    elif row.ordinal == -1:
        return {"status": "unsupported_process_lookup", "ordinal": row.ordinal, "symbol": row.symbol}
    else:
        result = graph.resolve(row.provider, row.symbol)
    if result["status"] in ("missing_input", "missing_symbol", "missing_weak_definition"):
        dependency_is_weak = row.ordinal > 0 and image.dependencies[row.ordinal - 1].command == 0x80000018
        if result["status"] == "missing_weak_definition":
            # The buildingCache -3 branch diagnoses an absent coalesced
            # definition; its name does not imply a nullable weak import.
            status = "missing_strong"
        elif result["status"] == "missing_input" and not dependency_is_weak:
            status = "missing_required_input"
        else:
            status = "weak_null" if row.weak else "missing_strong"
        result = dict(result, status=status, reason=result["status"])
    return result
