"""Bounded Mach-O export reader and static-link provider lookup.

Resolution follows dyld-1378 Loader::hasExportedSymbol(staticLink): self first,
explicit terminal reexports by dependency ordinal/name, then LC_REEXPORT_DYLIB
dependencies in load-command order. Ordinary dependencies are not reexports.
This reader does not execute resolvers or prove ABI compatibility.
"""
from dataclasses import dataclass
import struct


class Refusal(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise Refusal(message)


def span(data, offset, size):
    require(0 <= offset <= len(data) and 0 <= size <= len(data) - offset,
            f"range outside input: {offset:#x}+{size:#x}")
    return data[offset:offset + size]


def uleb(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        require(offset < len(data), "truncated ULEB128")
        byte = data[offset]
        offset += 1
        require(shift != 63 or byte <= 1, "ULEB128 overflow")
        value |= (byte & 127) << shift
        if not byte & 128:
            return value, offset
    raise Refusal("ULEB128 overflow")


def cstring(data, offset):
    require(0 <= offset < len(data), "string outside input")
    end = data.find(b"\0", offset)
    require(end != -1, "unterminated string")
    try:
        return data[offset:end].decode("utf-8"), end + 1
    except UnicodeDecodeError as exc:
        raise Refusal("non-UTF8 name") from exc


@dataclass(frozen=True)
class Export:
    flags: int
    value: int = 0
    ordinal: int = 0
    imported_name: str = ""
    extra: int = 0


def read_trie(data):
    if not data:
        return {}
    exports = {}
    pending = [(0, "", frozenset())]
    visits = 0
    while pending:
        offset, name, ancestors = pending.pop()
        require(offset not in ancestors, "export trie cycle")
        require(len(ancestors) < 512 and len(name) <= 4096, "export trie depth/name limit")
        visits += 1
        require(visits <= 1_000_000, "export trie expansion limit")
        ancestors = ancestors | {offset}
        size, start = uleb(data, offset)
        terminal = span(data, start, size)
        if size:
            require(name and name not in exports, "empty or duplicate export name")
            flags, pos = uleb(terminal, 0)
            require(not flags & ~0x3f and flags & 3 != 3, "unsupported export flags")
            if flags & 8:
                require(flags == 8, "unsupported reexport flags")
                ordinal, pos = uleb(terminal, pos)
                imported, pos = cstring(terminal, pos)
                exports[name] = Export(flags, ordinal=ordinal, imported_name=imported)
            else:
                value, pos = uleb(terminal, pos)
                extra = 0
                require(flags & 0x30 != 0x30, "resolver and function variant combined")
                if flags & 0x30:
                    extra, pos = uleb(terminal, pos)
                exports[name] = Export(flags, value=value, extra=extra)
            require(pos == len(terminal), "unparsed export terminal bytes")
        offset = start + size
        require(offset < len(data), "missing export child count")
        count = data[offset]
        offset += 1
        labels = []
        for _ in range(count):
            label, offset = cstring(data, offset)
            require(all(not label.startswith(old) for old in labels),
                    "shadowed or duplicate trie edge")
            # A final empty edge is a fallback used by extracted legacy tries.
            # Earlier siblings must not shadow this edge; cycles remain refused.
            labels.append(label)
            child, offset = uleb(data, offset)
            require(child < len(data), "export child outside trie")
            pending.append((child, name + label, ancestors))
    return exports


@dataclass(frozen=True)
class Dependency:
    path: str
    command: int

    @property
    def reexport(self):
        return self.command == 0x8000001f


@dataclass
class Image:
    install_name: str
    dependencies: list
    exports: dict


def read_image(data, *, bundle_path=None):
    """Read a thin or universal MH_DYLIB with exactly one plain x86_64 slice."""
    require(len(data) >= 32, "short Mach-O")
    magic = struct.unpack_from(">I", data)[0]
    if magic in (0xcafebabe, 0xcafebabf):
        count = struct.unpack_from(">I", data, 4)[0]
        size = 20 if magic == 0xcafebabe else 32
        span(data, 8, count * size)
        choices = []
        for i in range(count):
            offset = 8 + i * size
            cpu, sub = struct.unpack_from(">II", data, offset)
            fmt = ">II" if size == 20 else ">QQ"
            start, length = struct.unpack_from(fmt, data, offset + 8)
            span(data, start, length)
            if (cpu, sub) == (0x1000007, 3):
                choices.append((start, length))
        require(len(choices) == 1, "need exactly one x86_64 subtype 3 slice")
        data = span(data, *choices[0])
    span(data, 0, 32)
    magic, cpu, sub, kind, count, size = struct.unpack_from("<6I", data)
    require((magic,cpu,sub)==(0xfeedfacf,0x1000007,3) and
            (kind==6 or kind==8 and isinstance(bundle_path,str) and bundle_path.startswith('/')),
            "expected x86_64 subtype 3 MH_DYLIB or explicitly identified MH_BUNDLE")
    commands = span(data, 32, size)
    dependencies, names, tries, segments = [], [], [], []
    offset = 0
    for _ in range(count):
        cmd, length = struct.unpack("<II", span(commands, offset, 8))
        require(length >= 8 and length % 8 == 0, "invalid load-command size")
        command = span(commands, offset, length)
        if cmd in (0xc, 0xd, 0x80000018, 0x8000001f, 0x80000023, 0x20):
            span(command, 0, 24)
            require(struct.unpack_from("<I", command, 12)[0] != 0x1a741800,
                    "dylib_use_command flags unsupported")
            name_offset = struct.unpack_from("<I", command, 8)[0]
            require(name_offset >= 24, "dylib name overlaps command header")
            name, _ = cstring(command, name_offset)
            require(bool(name), "empty dylib name")
            if cmd == 0xd:
                names.append(name)
            else:
                dependencies.append(Dependency(name, cmd))
        elif cmd == 0x80000033:
            require(length == 16, "invalid exports command size")
            tries.append(struct.unpack_from("<II", command, 8))
        elif cmd in (0x22, 0x80000022):
            require(length == 48, "invalid dyld-info command size")
            off, length_ = struct.unpack_from("<II", command, 40)
            if length_:
                tries.append((off, length_))
        elif cmd == 0x19:
            span(command, 0, 72)
            vm, vmsize, fileoff, filesize = struct.unpack_from("<QQQQ", command, 24)
            span(data, fileoff, filesize)
            segments.append((vm, vmsize, fileoff, filesize))
        elif cmd == 0x12:
            # LC_SUB_FRAMEWORK (umbrella name): link-time only, copied unchanged. Apple's 26B131 cache keeps it in
            # 67 images, libsystem_kernel/platform/pthread ("System") among them.
            require(length >= 12 and struct.unpack_from("<I", command, 8)[0] >= 12, "invalid sub-framework command")
        elif cmd in (0x10, 0x13, 0x14, 0x15, 0x3a):
            raise Refusal("legacy/lazy dylib resolution semantics unsupported")
        offset += length
    require(offset == len(commands), "load-command count/size mismatch")
    require(len(names) == (0 if kind==8 else 1), "unexpected LC_ID_DYLIB count")
    require(tries and len(set(tries)) == 1, "missing or conflicting export tries")
    bases = [vm for vm, _, off, size in segments if off == 0 and size >= 32]
    require(len(bases) == 1, "ambiguous image load address")
    exports = read_trie(span(data, *tries[0]))
    for name, exp in exports.items():
        if exp.flags & 8:
            require(1 <= exp.ordinal <= len(dependencies), f"bad reexport ordinal: {name}")
        elif exp.flags & 3 != 2:
            require(any(vm <= bases[0] + exp.value < vm + size
                        for vm, size, _, _ in segments), f"unmapped export: {name}")
    return Image(bundle_path if kind==8 else names[0], dependencies, exports)


def resolve(images, path, symbol, ancestors=frozenset()):
    """Return final provider/offset or explicit missing-input/symbol status.

    Offsets are in the input image, NOT final cache offsets. Unsupported symbol
    kinds are retained as blockers, never coerced into regular image binds.
    """
    require(len(ancestors) < 512, "reexport depth limit")
    key = (path, symbol)
    if key in ancestors:
        raise Refusal(f"reexport cycle: {path}: {symbol}")
    if path not in images:
        return {"status": "missing_input", "path": path, "symbol": symbol}
    image = images[path]
    exp = image.exports.get(symbol)
    ancestors = ancestors | {key}
    if exp:
        if exp.flags & 8:
            require(1 <= exp.ordinal <= len(image.dependencies), "bad reexport ordinal")
            dep = image.dependencies[exp.ordinal - 1]
            return resolve(images, dep.path, exp.imported_name or symbol, ancestors)
        if exp.flags & 0x33:
            return {"status": "unsupported_kind", "path": path, "symbol": symbol,
                    "flags": exp.flags}
        return {"status": "resolved", "provider": path, "symbol": symbol,
                "input_offset": hex(exp.value), "flags": exp.flags}
    for dep in image.dependencies:
        if dep.reexport:
            result = resolve(images, dep.path, symbol, ancestors)
            if result["status"] != "missing_symbol":
                return result
    return {"status": "missing_symbol", "path": path, "symbol": symbol}
