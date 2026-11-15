"""Read-only target-cache transport for upstream Swift type resolution."""
import argparse
from collections import Counter
import ctypes as C
import json
from pathlib import Path
import uuid

from .cache_exports import FinalGraph
from .exports import Refusal
from .loader_generation import LoaderFamily, disk_image
from .objc_emit import FamilyReader
from .swift_metadata import References, provenance, write_json


class Layout(C.Structure):
    _fields_ = [('pointer_size', C.c_uint8), ('objc_interop', C.c_uint8),
                ('objc_low_bits', C.c_uint8), ('least_pointer', C.c_uint64),
                ('pointer_mask', C.c_uint64)]


class Bridge:
    """The ABI transports bytes and addresses only, never Swift layouts."""
    READ = C.CFUNCTYPE(C.c_int, C.c_uint64, C.c_uint64, C.c_void_p)
    POINTER = C.CFUNCTYPE(C.c_uint64, C.c_uint64, C.c_uint64)
    SYMBOL = C.CFUNCTYPE(C.c_uint64, C.c_void_p, C.c_size_t)

    def __init__(self, library, reader, pointer, symbol, layout):
        self.errors = Counter()
        def read(address, size, dest):
            try:
                data = reader(address, size)
                if len(data) != size:
                    raise ValueError('short transport read')
                C.memmove(dest, bytes(data), size)
                return 1
            except (ValueError, Refusal, KeyError) as error:
                self.errors['read: '+str(error)] += 1
                return 0
        def resolve_pointer(address, value):
            try:
                return pointer(address, value)
            except (ValueError, Refusal, KeyError) as error:
                self.errors['pointer: '+str(error)] += 1
                return 0
        def find_symbol(name, size):
            try:
                return symbol(C.string_at(name, size).decode())
            except (ValueError, Refusal, KeyError, UnicodeDecodeError) as error:
                self.errors['symbol: '+str(error)] += 1
                return 0
        self.callbacks = self.READ(read), self.POINTER(resolve_pointer), self.SYMBOL(find_symbol)
        self.lib = C.CDLL(str(library))
        signatures = {
            'swift_view_create': ([self.READ, self.POINTER, self.SYMBOL, Layout], C.c_void_p),
            'swift_view_add_image': ([C.c_void_p, C.c_uint64], C.c_int),
            'swift_view_resolve': ([C.c_void_p, C.c_void_p, C.c_size_t], C.c_void_p),
            'swift_view_opaque': ([C.c_void_p, C.c_uint64], C.c_void_p),
            'swift_view_free_result': ([C.c_void_p], None),
            'swift_view_destroy': ([C.c_void_p], None),
        }
        for name, (args, result) in signatures.items():
            fn = getattr(self.lib, name)
            fn.argtypes, fn.restype = args, result
        self.handle = self.lib.swift_view_create(*self.callbacks, layout)
        if not self.handle:
            raise ValueError('Swift MemoryReader does not support this pointer size')

    def add(self, address):
        return bool(self.lib.swift_view_add_image(self.handle, address))

    def resolve(self, name):
        encoded = name.encode()
        result = self.lib.swift_view_resolve(self.handle, encoded, len(encoded))
        if not result:
            raise ValueError('Swift MemoryReader returned no result')
        try:
            return json.loads(C.string_at(result))
        finally:
            self.lib.swift_view_free_result(result)

    def close(self):
        if self.handle:
            self.lib.swift_view_destroy(self.handle)
            self.handle = None

    def opaque(self, address):
        result = self.lib.swift_view_opaque(self.handle, address)
        try:
            return json.loads(C.string_at(result))
        finally:
            self.lib.swift_view_free_result(result)

    def inventory(self, architecture='x86_64'):
        """Inventory the added images through upstream Swift, including cache images."""
        function = self.lib.swift_view_inventory
        function.argtypes, function.restype = [C.c_void_p, C.c_char_p], C.c_void_p
        result = function(self.handle, architecture.encode())
        try:
            return json.loads(C.string_at(result))
        finally:
            self.lib.swift_view_free_result(result)


class CacheView:
    def __init__(self, family, dependencies):
        self.family = family
        self.reader = FamilyReader(family)
        self.symbols = {}
        self.export_errors = {}
        self.missing_symbols = Counter()
        self.ambiguous_symbols = Counter()
        self.missing_images = []
        self.images = []
        graph = FinalGraph(family, {})
        addresses = dict(family.images)
        pending, visited = list(dependencies), set()
        while pending:
            requested = pending.pop()
            path = graph.canonical(requested)
            if path is None:
                self.missing_images.append(requested)
                continue
            if path in visited:
                continue
            visited.add(path)
            address = addresses[path]
            try:
                _, image = graph.image(path)
            except (ValueError, Refusal) as error:
                self.export_errors[path] = str(error)
                continue
            self.images.append((path, address))
            pending.extend(d.path for d in image.dependencies)
            for name, entry in image.exports.items():
                # Reexports point to definitions elsewhere in this same family.
                # Resolver/TLV exports require execution and cannot supply a static address.
                if entry.flags & (8 | 16 | 32) or entry.flags & 3 == 1:
                    continue
                value = entry.value if entry.flags & 3 == 2 else address + entry.value
                self.symbols.setdefault(name, set()).add(value)

    def symbol(self, name):
        values = self.symbols.get(name) or self.symbols.get('_'+name, set())
        if len(values) == 1:
            return next(iter(values))
        if values:
            self.ambiguous_symbols[name] += 1
        else:
            self.missing_symbols[name] += 1
        return 0


def resolve_opaque(family, view, bridge, requests):
    references, constructors = References(family), []
    base = family.main.mappings[0].address
    for request in requests:
        row = dict(request)
        address = view.symbol(request['symbol'])
        if not address:
            row['error'] = 'opaque descriptor symbol missing or ambiguous'
        else:
            row.update(bridge.opaque(address))
            if 'error' not in row:
                row['descriptor_reference'] = references.encode(address)
                row['descriptor'] = address-base
                row['context_reference'] = references.encode(row['context'])
                row['context'] -= base
                for requirement in row['requirements']:
                    for key in ('subject_address', 'protocol'):
                        if key in requirement:
                            try:
                                requirement[key+'_reference'] = references.encode(requirement[key])
                                requirement[key] -= base
                            except ValueError as error:
                                row['error'] = key+': '+str(error)
        constructors.append(row)
    return constructors


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cache', 'requests', 'toolchain', 'output'):
        parser.add_argument(name, type=Path)
    parser.add_argument('--binary', required=True, type=Path, help='Mach-O whose linked dependency scope to use')
    parser.add_argument('--opaque-requests', type=Path, help='compiler-decoded opaque constructor inputs')
    args = parser.parse_args(argv)
    args.output.mkdir(parents=True, exist_ok=False)
    library = args.toolchain.resolve() / 'build/libSwiftMemoryView.dylib'
    family = LoaderFamily(args.cache)
    bridge = None
    try:
        root, _, _ = disk_image(args.binary.read_bytes(), '/input')
        view = CacheView(family, [d.path for d in root.dependencies])
        # The existing loader/slide backend accepts x86_64. These are its Darwin
        # ABI properties, not host properties or a particular Mac/OS build.
        bridge = Bridge(library, view.reader.read, lambda address, value: view.reader.ptr(address),
                        view.symbol, Layout(8, 1, 1, 0x100000000, (1 << 64)-1))
        images = [dict(path=p, address=a, added=bridge.add(a)) for p, a in view.images]
        if args.opaque_requests:
            constructors = resolve_opaque(family, view, bridge, json.loads(args.opaque_requests.read_text()))
            write_json(args.output/'opaque-requests.json', dict(cache_uuid=str(uuid.UUID(bytes=bytes(family.main.data[88:104]))),
                                                              requests=constructors))
        counts = Counter()
        with args.requests.open() as requests, (args.output/'resolutions.jsonl').open('w') as output:
            for line in requests:
                name = json.loads(line)
                row = bridge.resolve(name)
                counts['requested'] += 1
                counts['decoded' if 'mangled' in row else 'errors'] += 1
                counts['changed'] += int('mangled' in row and row['mangled'] != name)
                output.write(json.dumps(row, sort_keys=True)+'\n')
        report = dict(counts, images=images, transport_errors=dict(bridge.errors),
                      export_errors=view.export_errors, missing_symbols=dict(view.missing_symbols),
                      ambiguous_symbols=dict(view.ambiguous_symbols),
                      missing_images=sorted(set(view.missing_images)),
                      scope='Offline upstream Swift resolution against the supplied cache. '
                            'Missing app images and unsupported layouts remain unresolved; no target code runs.')
        write_json(args.output/'summary.json', report)
        write_json(args.output/'build.json', provenance(
            [args.requests, args.binary, library, args.toolchain/'build.json', Path(__file__),
             Path(__file__).with_name('cache_exports.py'), Path(__file__).with_name('objc_emit.py'),
             Path(__file__).with_name('slides.py'), Path(__file__).with_name('loader_generation.py')]
            + [f.path for f in family.files] + ([args.opaque_requests] if args.opaque_requests else []), operation='swift-cache-memory-view',
            cache_uuid=str(uuid.UUID(bytes=bytes(family.main.data[88:104])))))
        print(json.dumps(dict(counts, images=len(images), added_images=sum(i['added'] for i in images)), indent=2))
    finally:
        if bridge is not None:
            bridge.close()
        family.close()
