"""Read cached export tries and path aliases; resolve a final provider graph.

This is a static symbol-presence audit. Export offsets are source image offsets,
not a final relocation plan. Resolver/TLV exports are identified without execution.
"""
from __future__ import annotations
import struct
from dataclasses import dataclass
from .cache import commands
from .exports import Export, Image, Refusal, cstring, require, span, uleb


@dataclass(frozen=True)
class CacheDependency:
    path: str
    command: int
    use_flags: int | None = None

    @property
    def reexport(self):
        return bool(self.use_flags & 2) if self.use_flags is not None else self.command == 0x8000001f

    @property
    def upward(self):
        return bool(self.use_flags & 4) if self.use_flags is not None else self.command == 0x80000023

    @property
    def weak(self):
        return bool(self.use_flags & 1) if self.use_flags is not None else self.command == 0x80000018


def path_trie(data, image_count):
    pending, result, visits = [(0, "", frozenset())], {}, 0
    while pending:
        offset, name, ancestors = pending.pop()
        require(offset not in ancestors and len(ancestors) < 512, "cache path trie cycle/depth")
        ancestors = ancestors | {offset}
        visits += 1
        require(visits <= 1_000_000 and len(name) <= 4096, "cache path trie expansion limit")
        terminal_size, start = uleb(data, offset)
        terminal = span(data, start, terminal_size)
        if terminal_size:
            index, end = uleb(terminal, 0)
            require(end == len(terminal) and index < image_count and name.startswith("/") and name not in result,
                    "invalid cache path trie terminal")
            result[name] = index
        offset = start + terminal_size
        count = span(data, offset, 1)[0]
        offset += 1
        initials = set()
        for _ in range(count):
            label, offset = cstring(data, offset)
            child, offset = uleb(data, offset)
            require(label and label[0] not in initials and child < len(data), "ambiguous/bad cache trie edge")
            initials.add(label[0])
            pending.append((child, name + label, ancestors))
    return result


def export_trie(data):
    """Decode cached exports, including weak reexports present in the input."""
    if not data:
        return {}
    pending, result, visits = [(0, "", frozenset())], {}, 0
    while pending:
        offset, name, ancestors = pending.pop()
        require(offset not in ancestors and len(ancestors) < 512, "cached export trie cycle/depth")
        ancestors = ancestors | {offset}
        visits += 1
        # Parser resource bound, not a dyld format/runtime limit. The pinned
        # factory cache contains valid Swift export names longer than 4096.
        require(visits <= 1_000_000 and len(name) <= 65535, "cached export trie expansion limit")
        size, start = uleb(data, offset)
        terminal = span(data, start, size)
        if size:
            require(name and name not in result, "empty/duplicate cached export")
            flags, pos = uleb(terminal, 0)
            require(not flags & ~0x3f and flags & 3 != 3, "unknown cached export flags")
            if flags & 8:
                require(not flags & ~12, f"unsupported cached reexport flags {flags:#x}")
                ordinal, pos = uleb(terminal, pos)
                imported, pos = cstring(terminal, pos)
                result[name] = Export(flags, ordinal=ordinal, imported_name=imported)
            else:
                value, pos = uleb(terminal, pos)
                require(flags & 0x30 != 0x30, "combined resolver/function-variant flags")
                extra = 0
                if flags & 0x30:
                    extra, pos = uleb(terminal, pos)
                result[name] = Export(flags, value=value, extra=extra)
            require(pos == len(terminal), "unparsed cached export terminal")
        offset = start + size
        count = span(data, offset, 1)[0]
        offset += 1
        labels = []
        for _ in range(count):
            label, offset = cstring(data, offset)
            child, offset = uleb(data, offset)
            require(all(not label.startswith(old) for old in labels) and child < len(data), "bad cached export edge")
            # Legacy disk tries can put a terminal behind a final empty edge.
            # The same decoder serves cached and disk images.
            labels.append(label)
            pending.append((child, name + label, ancestors))
    return result


def trie_flags(data, symbol):
    """The export flags of SYMBOL in an export trie, or None: one walk, no full decode."""
    offset, rest = 0, symbol
    for _ in range(len(symbol) + 1):
        if not data:
            return None
        size, start = uleb(data, offset)
        if not rest:
            return uleb(span(data, start, size), 0)[0] if size else None
        offset = start + size
        count = span(data, offset, 1)[0]
        offset += 1
        for _ in range(count):
            label, offset = cstring(data, offset)
            child, offset = uleb(data, offset)
            if label and rest.startswith(label):
                rest, offset = rest[len(label):], child
                require(child < len(data), "bad cached export edge")
                break
        else:
            return None
    raise Refusal("cached export trie walk did not end")


def cached_trie_range(family, address):
    """(address, size) of a cached image's export trie, located as cached_image does."""
    tries, linkedit = [], []
    for _, command, raw in commands(family, address):
        if command == 0x19 and raw[8:24].rstrip(b"\0") == b"__LINKEDIT":
            linkedit.append(struct.unpack_from("<QQQQ", raw, 24))
        elif command == 0x80000033:
            tries.append(struct.unpack_from("<II", raw, 8))
        elif command in (0x22, 0x80000022):
            off, length = struct.unpack_from("<II", raw, 40)
            if length:
                tries.append((off, length))
    require(len(linkedit) == 1 and tries and len(set(tries)) == 1, "ambiguous cached export trie")
    off, length = tries[0]
    vm, _, fileoff, filesize = linkedit[0]
    require(fileoff <= off and off + length <= fileoff + filesize, "cached export trie outside LINKEDIT")
    return vm + off - fileoff, length


def cached_image(family, address):
    names, deps, tries, linkedit = [], [], [], []
    for _, command, raw in commands(family, address):
        if command in (0xc, 0xd, 0x80000018, 0x8000001f, 0x80000023, 0x20):
            span(raw, 0, 24)
            nameoff, timestamp = struct.unpack_from("<II", raw, 8)
            use_flags = None
            if timestamp == 0x1a741800:
                require(command in (0xc, 0x80000018) and nameoff == 28,
                        "unsupported cached dylib-use header")
                use_flags, = struct.unpack("<I", span(raw, 24, 4))
                require(not use_flags & ~15, "unknown cached dylib-use flags")
            else:
                require(nameoff >= 24, "cached dylib name overlaps header")
            name, _ = cstring(raw, nameoff)
            if command == 0xd:
                names.append(name)
            else:
                deps.append(CacheDependency(name, command, use_flags))
        elif command == 0x19 and raw[8:24].rstrip(b"\0") == b"__LINKEDIT":
            linkedit.append(struct.unpack_from("<QQQQ", raw, 24))
        elif command == 0x80000033:
            require(len(raw) == 16, "invalid cached exports command")
            tries.append(struct.unpack_from("<II", raw, 8))
        elif command in (0x22, 0x80000022):
            require(len(raw) == 48, "invalid cached dyld-info command")
            off, length = struct.unpack_from("<II", raw, 40)
            if length:
                tries.append((off, length))
    require(len(names) == 1 and len(linkedit) == 1, "ambiguous cached identity/LINKEDIT")
    require(tries and len(set(tries)) == 1, "missing/conflicting cached export tries")
    off, length = tries[0]
    vm, vmsize, fileoff, filesize = linkedit[0]
    require(fileoff <= off and off + length <= fileoff + filesize, "cached export trie outside LINKEDIT")
    exports = export_trie(family.read(vm + off - fileoff, length))
    for symbol, entry in exports.items():
        if entry.flags & 8:
            require(1 <= entry.ordinal <= len(deps), f"invalid cached reexport ordinal: {symbol}")
    return Image(names[0], deps, exports)


class FinalGraph:
    def __init__(self, family, providers):
        self.family, self.providers = family, providers
        address, size = struct.unpack_from("<QQ", family.main.data, 0x108)
        self.trie_bytes = family.read(address, size)
        self.aliases = path_trie(self.trie_bytes, len(family.images))
        self.cached = {}
        self.resolution_paths = set()
        self.reachable_cache = {}
        for index, (path, _) in enumerate(family.images):
            require(self.aliases.get(path) == index, "cache image/path trie disagreement")

    def canonical(self, path):
        if path in self.providers:
            return path
        if path in self.aliases:
            return self.family.images[self.aliases[path]][0]
        return None

    def image(self, path):
        canonical = self.canonical(path)
        if canonical is None:
            return None, None
        if canonical in self.providers:
            return canonical, self.providers[canonical]
        if canonical not in self.cached:
            index = self.aliases[canonical]
            self.cached[canonical] = cached_image(self.family, self.family.images[index][1])
        return canonical, self.cached[canonical]

    def resolve(self, path, symbol, ancestors=frozenset(), *, shallow=False):
        canonical, image = self.image(path)
        if image is None:
            return {"status": "missing_input", "path": path, "symbol": symbol}
        self.resolution_paths.add(canonical)
        key = canonical, symbol
        require(key not in ancestors and len(ancestors) < 512, "export resolution cycle/depth")
        ancestors = ancestors | {key}
        entry = image.exports.get(symbol)
        if entry is not None:
            if entry.flags & 8:
                require(1 <= entry.ordinal <= len(image.dependencies), "reexport ordinal out of range")
                imported = entry.imported_name or symbol
                dependency = image.dependencies[entry.ordinal - 1]
                found = self.resolve(dependency.path,
                                     imported, ancestors, shallow=shallow and imported == symbol)
                if found["status"] == "missing_input" and getattr(dependency, "weak", dependency.command == 0x80000018):
                    found = {"status": "missing_symbol", "path": canonical, "symbol": symbol,
                             "missing_weak_reexport": dependency.path}
                return dict(found, reexport_chain=[{"path": canonical, "symbol": symbol,
                                                     "flags": entry.flags, "ordinal": entry.ordinal}] +
                                                    found.get("reexport_chain", []))
            return {"status": "resolved", "provider": canonical, "symbol": symbol,
                    "input_offset": hex(entry.value), "flags": entry.flags,
                    "extra_offset": hex(entry.extra) if entry.flags & 0x30 else None,
                    "kind": {0: "regular", 1: "thread_local", 2: "absolute"}[entry.flags & 3],
                    "weak_definition": bool(entry.flags & 4),
                    "resolver": bool(entry.flags & 16), "function_variant": bool(entry.flags & 32)}
        for dep in image.dependencies:
            if dep.reexport and not shallow:
                found = self.resolve(dep.path, symbol, ancestors)
                if found["status"] == "missing_input" and getattr(dep, "weak", dep.command == 0x80000018):
                    continue
                if found["status"] != "missing_symbol":
                    return found
        return {"status": "missing_symbol", "path": canonical, "symbol": symbol}

    def resolve_flat(self, symbol):
        """A flat-namespace lookup (ordinal -2) for a cache build: the one image that defines SYMBOL itself (not by
        reexport), among the providers and the cache images they do not replace. dyld's runtime lookup goes through
        the loaded images in load order; a static answer exists only when there is a single definer, so 0 is
        missing_symbol and more than one is a refusal (fold-in, pm/metal 2026-11-14: the e5rt calls of the Live Text
        interposers, all defined by Espresso)."""
        if not hasattr(self, "trie_ranges"):
            self.trie_ranges = {}
        definers = [path for path, image in self.providers.items()
                    if (entry := image.exports.get(symbol)) is not None and not entry.flags & 8]
        for index, (path, header) in enumerate(self.family.images):
            if path in self.providers:
                continue
            if index not in self.trie_ranges:
                self.trie_ranges[index] = cached_trie_range(self.family, header)
            address, size = self.trie_ranges[index]
            flags = trie_flags(self.family.read(address, size), symbol)
            if flags is not None and not flags & 8:
                definers.append(path)
        require(len(definers) <= 1, f"flat lookup has several definers: {symbol} {sorted(definers)}")
        if not definers:
            return {"status": "missing_symbol", "path": "SPECIAL:flat-lookup", "symbol": symbol}
        return dict(self.resolve(definers[0], symbol), lookup="flat-single-definer")

    def reachable(self, root):
        if root in self.reachable_cache:
            return self.reachable_cache[root]
        pending, visited = [(root, False)], set()
        while pending:
            requested, weak = pending.pop()
            path, image = self.image(requested)
            if image is None and weak:
                continue
            require(image is not None, f"missing dependency while deriving weak lookup scope: {requested}")
            if path in visited:
                continue
            visited.add(path)
            pending.extend((dep.path, getattr(dep, "weak", dep.command == 0x80000018))
                           for dep in image.dependencies)
        self.reachable_cache[root] = visited
        return visited

    def resolve_weak_for_cache_build(self, importer, symbol):
        """Bounded cache-builder weak coalescing; never substitute a weak null.

        Mirrors Loader.cpp's buildingCache path. Refuses order-sensitive competing
        libc++ choices instead of inventing a loaded-image order.
        """
        reachable = self.reachable(importer)
        libcxx = []
        for path in sorted(reachable):
            if path.startswith("/usr/lib/libc++.") and path not in self.providers:
                index = self.aliases[path]
                flags, = struct.unpack("<I", self.family.read(self.family.images[index][1] + 24, 4))
                if flags & 0x8000:  # MH_WEAK_DEFINES
                    result = self.resolve(path, symbol, shallow=True)
                    if result["status"] == "resolved":
                        libcxx.append(result)
        require(len(libcxx) <= 1, "order-sensitive competing libc++ weak lookup candidates")
        if libcxx:
            return dict(libcxx[0], lookup="cache-builder-libc++-first")
        result = self.resolve(importer, symbol, shallow=True)
        if result["status"] == "resolved":
            return dict(result, lookup="cache-builder-self")
        _, image = self.image(importer)
        for dep in image.dependencies:
            upward = getattr(dep, "upward", dep.command == 0x80000023)
            if not upward:
                result = self.resolve(dep.path, symbol)
                if result["status"] == "resolved":
                    return dict(result, lookup="cache-builder-direct-dependent")
        return {"status": "missing_weak_definition", "symbol": symbol}
