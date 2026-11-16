"""Deterministic lookup serialization; patch graph semantics belong to the caller.

All original aliases and raw patch payloads can be reconstructed unchanged.
Relocating the v4 header changes nine array addresses, never client offsets.
"""
from __future__ import annotations
from dataclasses import dataclass, field
import hashlib
import struct
from .cache_exports import path_trie
from .exports import require
from .patches import PatchTableV4

PATCH_ORDER = ('images', 'exports', 'clients', 'client_exports', 'locations',
               'got_clients', 'got_exports', 'got_locations', 'names')
FORMATS = dict(zip(PatchTableV4.NAMES, ('<4I', '<2I', '<3I', '<3I', '<2I', None, '<2I', '<3I', '<QII')))


def uleb_bytes(value):
    require(type(value) is int and 0 <= value < 2**64, 'ULEB value outside uint64')
    result = bytearray()
    while True:
        byte = value & 127
        value >>= 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


@dataclass
class _Node:
    value: int | None = None
    children: dict = field(default_factory=dict)
    edges: list = field(default_factory=list)
    offset: int = 0


def write_path_trie(entries, image_count, *, reserve=None):
    """Write a compressed, byte-sorted ASCII dyld path trie with fixed-point offsets."""
    require(type(image_count) is int and 0 < image_count < 2**32, 'invalid path image count')
    pairs = list(entries.items() if hasattr(entries, 'items') else entries)
    root, names = _Node(), set()
    for name, index in pairs:
        require(isinstance(name, str) and name.startswith('/') and '\0' not in name, 'invalid dylib path')
        require(name.isascii(), 'non-ASCII path requires a byte-oriented UTF-8 reader')
        require(len(name) <= 4096 and name not in names, 'duplicate/oversized path')
        require(type(index) is int and 0 <= index < image_count, 'path image index outside array')
        names.add(name)
        node = root
        for byte in name.encode('ascii'):
            node = node.children.setdefault(byte, _Node())
        node.value = index
    nodes = []

    def compress(node, depth=0):
        require(depth < 512, 'path trie exceeds checked reader depth')
        nodes.append(node)
        for byte, child in sorted(node.children.items()):
            label = bytearray([byte])
            while child.value is None and len(child.children) == 1:
                byte, child = next(iter(child.children.items()))
                label.append(byte)
            node.edges.append((bytes(label), child))
            compress(child, depth + 1)
        require(len(node.edges) <= 255, 'trie node has too many edges')

    compress(root)

    def encode(node):
        terminal = b'' if node.value is None else uleb_bytes(node.value)
        body = bytearray(uleb_bytes(len(terminal)) + terminal + bytes([len(node.edges)]))
        for label, child in node.edges:
            body += label + b'\0' + uleb_bytes(child.offset)
        return bytes(body)

    for _ in range(128):
        cursor, changed = 0, False
        for node in nodes:
            if node.offset != cursor:
                node.offset, changed = cursor, True
            cursor += len(encode(node))
        require(cursor < 2**32, 'path trie exceeds uint32 extent')
        if not changed:
            result = b''.join(encode(node) for node in nodes)
            require(reserve is None or len(result) <= reserve, 'path trie exceeds reserved bytes')
            require(path_trie(result, image_count) == dict(pairs), 'independent path reader differs')
            return result
    raise ValueError('path trie offset calculation did not converge')


def final_aliases(original, original_images, final_images):
    require(len(final_images) >= len(original_images), 'final image inventory dropped original identities')
    require([p for p, _ in final_images[:len(original_images)]] == [p for p, _ in original_images], 'original image indexes changed')
    result = dict(original)
    for index, (path, _) in enumerate(original_images):
        require(result.get(path) == index, 'original path trie/image inventory differs')
    for index in range(len(original_images), len(final_images)):
        path, _ = final_images[index]
        require(path not in result, 'added image path collides with existing alias')
        result[path] = index
    require(len({p for p, _ in final_images}) == len(final_images), 'duplicate final image identity')
    return result


def split_patch_arrays(data, base, image_count):
    """Return complete raw arrays after the existing checked schema reader validates extents."""
    require(type(base) is int and 0 <= base < 2**64 and base % 8 == 0, 'invalid patch table base')
    table = PatchTableV4(data, base, [(f'/image/{i}', 0) for i in range(image_count)], 0)
    result = {}
    cursor = 152
    for name in PATCH_ORDER:
        offset, count, width = table.arrays[name]
        require(offset == cursor, 'noncanonical patch-array packing/padding')
        result[name] = bytes(data[offset:offset + count * width])
        cursor += count * width
    require(cursor == len(data), 'undeclared/trailing patch bytes')
    return result


def validate_patch_arrays(arrays, image_count):
    require(set(arrays) == set(PatchTableV4.NAMES), 'patch array inventory differs from v4 schema')
    require(type(image_count) is int and 0 < image_count < 2**32, 'invalid patch image count')
    counts = {}
    for name, width in zip(PatchTableV4.NAMES, PatchTableV4.SIZES):
        require(isinstance(arrays[name], bytes) and len(arrays[name]) % width == 0, 'patch array byte extent/type')
        counts[name] = len(arrays[name]) // width
    require(counts['images'] == counts['got_clients'] == image_count, 'patch image counts differ')
    names = arrays['names']
    exports = list(struct.iter_unpack('<II', arrays['exports']))
    for offset, flags in exports:
        nameoff = flags & 0xfffffff
        require(flags >> 28 in (0, 1, 8), 'unknown patch export kind')
        require(nameoff < len(names) and names.find(b'\0', nameoff) > nameoff, 'invalid patch export name')
    clients = list(struct.iter_unpack('<III', arrays['clients']))
    client_exports = list(struct.iter_unpack('<III', arrays['client_exports']))
    got_exports = list(struct.iter_unpack('<III', arrays['got_exports']))
    image_rows = list(struct.iter_unpack('<IIII', arrays['images']))
    got_rows = list(struct.iter_unpack('<II', arrays['got_clients']))
    cursors = dict.fromkeys(('clients', 'exports', 'client_exports', 'locations', 'got_exports', 'got_locations'), 0)

    def extent(name, start, count):
        require(start == cursors[name] and count <= counts[name] - start, f'nonpartitioned/out-of-range {name}')
        cursors[name] += count

    for image, (client_start, client_count, export_start, export_count) in enumerate(image_rows):
        extent('clients', client_start, client_count)
        extent('exports', export_start, export_count)
        seen_clients = set()
        for client, start, count in clients[client_start:client_start + client_count]:
            require(client < image_count and client not in seen_clients, 'invalid/duplicate patch client')
            seen_clients.add(client)
            extent('client_exports', start, count)
            implementations = set()
            for export, location_start, location_count in client_exports[start:start + count]:
                require(export_start <= export < export_start + export_count, 'patch export owner differs')
                require(exports[export][0] not in implementations, 'ambiguous implementation within client')
                implementations.add(exports[export][0])
                extent('locations', location_start, location_count)
        start, count = got_rows[image]
        extent('got_exports', start, count)
        previous = -1
        for export, location_start, location_count in got_exports[start:start + count]:
            require(export_start <= export < export_start + export_count, 'GOT export owner differs')
            require(exports[export][0] > previous, 'GOT export implementations not strictly ordered')
            previous = exports[export][0]
            extent('got_locations', location_start, location_count)
    require(all(cursors[name] == counts[name] for name in cursors), 'orphan patch records')
    stats = {'counts': counts, 'arrays': {name: hashlib.sha256(data).hexdigest() for name, data in arrays.items()}}
    for name, fmt in (('locations', '<II'), ('got_locations', '<QII')):
        digest = hashlib.sha256()
        weak = maximum_addend = high8_count = 0
        for record in struct.iter_unpack(fmt, arrays[name]):
            offset, word = record[:2]
            require(not word & 1, 'authenticated patch location unsupported for x86_64')
            require(name != 'got_locations' or record[2] == 0, 'nonzero GOT padding')
            high8, addend, is_weak = ((word >> 1) & 127) << 1, word >> 9, bool(word & 256)
            digest.update(struct.pack('<8Q', offset, high8, addend, is_weak, 0, 0, 0, 0))
            weak += is_weak
            high8_count += high8 != 0
            maximum_addend = max(maximum_addend, addend)
        stats[name] = {'decoded_sha256': digest.hexdigest(), 'weak_imports': weak, 'nonzero_high8': high8_count, 'maximum_addend': maximum_addend}
    digest = hashlib.sha256()
    for image, (_, _, start, count) in enumerate(image_rows):
        for implementation, flags in exports[start:start + count]:
            start = flags & 0xfffffff
            end = names.index(b'\0', start)
            name = names[start:end]
            digest.update(struct.pack('<4Q', image, implementation, flags >> 28, len(name)) + name)
    stats['exports_decoded_sha256'] = digest.hexdigest()
    return stats


def serialize_patch_arrays(arrays, base, image_count, *, reserve=None):
    require(type(base) is int and 0 <= base < 2**64 and base % 8 == 0, 'invalid patch table base')
    stats = validate_patch_arrays(arrays, image_count)
    size = 152 + sum(len(arrays[name]) for name in PATCH_ORDER)
    require(base + size <= 2**64 and (reserve is None or size <= reserve), 'patch table exceeds address/reservation')
    addresses, cursor = {}, 152
    for name in PATCH_ORDER:
        require(base + cursor < 2**64, 'patch array address overflow')
        addresses[name] = base + cursor
        cursor += len(arrays[name])
    header = [4, 0]
    for name in PatchTableV4.NAMES:
        header.extend((addresses[name], stats['counts'][name]))
    result = struct.pack('<II18Q', *header) + b''.join(arrays[name] for name in PATCH_ORDER)
    require(split_patch_arrays(result, base, image_count) == arrays, 'checked patch reader differs after serialization')
    return result, stats
