"""Rebuild v4 patch ownership from retained uses and the final provider graph.

Locations are packed blocks, so millions of unchanged entries need not become
Python objects. Replaced clients are retired; shared GOT locations remain live
unless an explicit missing-export record removes them. This module emits table
bytes only. Pointer retargeting and fixed-slot slide edits are separate gates.
"""
from collections import defaultdict
import struct
from .exports import require
from .lookup_tables import validate_patch_arrays


def metadata_word(*, addend, weak_import, high8=0):
    require(type(addend) is int and 0 <= addend < 1 << 23, 'patch addend cannot be represented')
    require(type(weak_import) is bool, 'patch weak-import flag must be boolean')
    require(type(high8) is int and 0 <= high8 <= 254 and high8 % 2 == 0,
            'patch high-byte cannot be represented')
    return (addend << 9) | (int(weak_import) << 8) | high8


def transform(arrays, old_images, final_images, replaced, remaps, new_uses):
    """Return raw v4 arrays, with changed exports resolved by the caller.

    remaps maps an old export index to None (explicitly absent) or a dict with
    target_index, implementation, symbol, export_kind. It must cover exactly
    the surviving uses of replaced targets. new_uses adds client_index/location,
    addend/weak_import/high8 to the same export description.
    """
    before = validate_patch_arrays(arrays, len(old_images))
    require(len(final_images) >= len(old_images) and
            [p for p, _ in old_images] == [p for p, _ in final_images[:len(old_images)]],
            'final graph changed original image identities/indexes')
    require(len({p for p, _ in final_images}) == len(final_images), 'duplicate final image identity')
    replaced = set(replaced)
    require(all(type(i) is int and 0 <= i < len(old_images) for i in replaced), 'invalid replaced index')
    require({i for i, (_, mh) in enumerate(old_images) if mh != final_images[i][1]} == replaced,
            'replaced set differs from changed headers')
    rows = {name: list(struct.iter_unpack(fmt, arrays[name])) for name, fmt in (
        ('images', '<4I'), ('exports', '<2I'), ('clients', '<3I'),
        ('client_exports', '<3I'), ('got_clients', '<2I'), ('got_exports', '<3I'))}
    output = {name: bytearray() for name in arrays}
    output['names'] += arrays['names']
    incoming = defaultdict(list)
    used_remaps = set()
    stats = dict(retired_client_locations=0, migrated_locations=0,
                 missing_locations=0, new_locations=0, coalesced_exports=0)
    new_name_offsets = {}

    def block(name, start, count, width):
        return memoryview(arrays[name])[start * width:(start + count) * width]

    def exported(description):
        target = description['target_index']
        require(type(target) is int and 0 <= target < len(final_images), 'patch target outside final graph')
        implementation = description['implementation']
        offset = implementation - final_images[target][1]
        require(type(implementation) is int and 0 <= offset < 2**32,
                'export implementation offset cannot be represented')
        symbol, kind = description['symbol'], description['export_kind']
        require(isinstance(symbol, str) and symbol and '\0' not in symbol and symbol.isascii(),
                'invalid patch export symbol')
        require(kind in (0, 1, 8), 'unknown patch export kind')
        # Keep the old name pool intact. New names are shared by identical bytes.
        if symbol not in new_name_offsets:
            new_name_offsets[symbol] = len(output['names'])
            output['names'] += symbol.encode('ascii') + b'\0'
        name_offset = new_name_offsets[symbol]
        require(name_offset < 2**28, 'patch name offset cannot be represented')
        return target, offset, (kind << 28) | name_offset

    def migrate(export_index, client, payload, count):
        require(export_index in remaps, 'changed export has no explicit resolution')
        used_remaps.add(export_index)
        resolution = remaps[export_index]
        if resolution is None:
            stats['missing_locations'] += count
            return
        target, offset, flags = exported(resolution)
        incoming[target].append((client, offset, flags, payload))
        stats['migrated_locations'] += count

    # Move surviving old references to the actual defining provider, including
    # reexports. Never infer clients of a globally uniqued GOT slot.
    for target in sorted(replaced):
        client_start, client_count, _, _ = rows['images'][target]
        for client, start, count in rows['clients'][client_start:client_start + client_count]:
            for export, loc_start, loc_count in rows['client_exports'][start:start + count]:
                if client in replaced:
                    stats['retired_client_locations'] += loc_count
                else:
                    migrate(export, client, block('locations', loc_start, loc_count, 8), loc_count)
        start, count = rows['got_clients'][target]
        for export, loc_start, loc_count in rows['got_exports'][start:start + count]:
            migrate(export, None, block('got_locations', loc_start, loc_count, 16), loc_count)
    require(used_remaps == set(remaps), 'unused or missing changed-export resolution')

    seen_new_locations = set()
    for use in new_uses:
        client = use['client_index']
        require(type(client) is int and (client in replaced or len(old_images) <= client < len(final_images)),
                'new patch location is not owned by a final provider')
        require(use['location'] not in seen_new_locations, 'duplicate new patch location')
        seen_new_locations.add(use['location'])
        offset = use['location'] - final_images[client][1]
        require(0 <= offset < 2**32, 'client location offset cannot be represented')
        word = metadata_word(addend=use['addend'], weak_import=use['weak_import'], high8=use.get('high8', 0))
        target, implementation, flags = exported(use)
        incoming[target].append((client, implementation, flags, struct.pack('<II', offset, word)))
        stats['new_locations'] += 1

    def add(groups, exports, client, implementation, flags, payload):
        require(payload, 'empty patch-use block')
        if implementation in exports:
            require(exports[implementation] >> 28 == flags >> 28, 'coalesced export kind differs')
            if exports[implementation] != flags:
                stats['coalesced_exports'] += 1
        else:
            exports[implementation] = flags
        groups.setdefault(client, {}).setdefault(implementation, []).append(payload)

    def locations(spans, width):
        if len(spans) == 1:
            return spans[0]
        # Multiple old exports may collapse to one replacement implementation.
        # Deduplicate exact records but refuse conflicting uses of one slot.
        result, addresses = bytearray(), {}
        for span in spans:
            for at in range(0, len(span), width):
                record = bytes(span[at:at + width])
                address = struct.unpack_from('<Q' if width == 16 else '<I', record)[0]
                if address in addresses:
                    require(addresses[address] == record, 'conflicting patch metadata at one location')
                else:
                    addresses[address] = record
                    result += record
        if width == 16:
            result = bytearray(b''.join(addresses[address] for address in sorted(addresses)))
        return result

    for target in range(len(final_images)):
        groups, exports = {}, {}
        if target < len(old_images) and target not in replaced:
            client_start, client_count, _, _ = rows['images'][target]
            for client, start, count in rows['clients'][client_start:client_start + client_count]:
                for export, loc_start, loc_count in rows['client_exports'][start:start + count]:
                    if client in replaced:
                        stats['retired_client_locations'] += loc_count
                        continue
                    implementation, flags = rows['exports'][export]
                    add(groups, exports, client, implementation, flags,
                        block('locations', loc_start, loc_count, 8))
            start, count = rows['got_clients'][target]
            for export, loc_start, loc_count in rows['got_exports'][start:start + count]:
                implementation, flags = rows['exports'][export]
                add(groups, exports, None, implementation, flags,
                    block('got_locations', loc_start, loc_count, 16))
        for client, implementation, flags, payload in incoming.get(target, []):
            add(groups, exports, client, implementation, flags, payload)
        export_start = len(output['exports']) // 8
        export_indexes = {}
        for implementation in sorted(exports):
            export_indexes[implementation] = len(output['exports']) // 8
            output['exports'] += struct.pack('<II', implementation, exports[implementation])
        client_start = len(output['clients']) // 12
        for client in sorted(c for c in groups if c is not None):
            start = len(output['client_exports']) // 12
            for implementation, spans in sorted(groups[client].items()):
                payload = locations(spans, 8)
                output['client_exports'] += struct.pack('<3I', export_indexes[implementation],
                                                       len(output['locations']) // 8, len(payload) // 8)
                output['locations'] += payload
            output['clients'] += struct.pack('<3I', client, start, len(groups[client]))
        output['images'] += struct.pack('<4I', client_start, len(output['clients']) // 12 - client_start,
                                        export_start, len(exports))
        got_start = len(output['got_exports']) // 12
        for implementation, spans in sorted(groups.get(None, {}).items()):
            payload = locations(spans, 16)
            output['got_exports'] += struct.pack('<3I', export_indexes[implementation],
                                                len(output['got_locations']) // 16, len(payload) // 16)
            output['got_locations'] += payload
        output['got_clients'] += struct.pack('<2I', got_start, len(output['got_exports']) // 12 - got_start)
    output['names'] += bytes((-len(output['names'])) % 4)
    result = {name: bytes(data) for name, data in output.items()}
    after = validate_patch_arrays(result, len(final_images))
    stats.update(original_counts=before['counts'], final_counts=after['counts'],
                 explicit_changed_exports=len(remaps), new_unique_locations=len(seen_new_locations))
    return result, stats
