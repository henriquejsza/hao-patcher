"""Bounded Swift-v3 table decoding and identity-index-only rewrite planning.

These routines do not establish complete Swift metadata closure. Address/key
changes require a separately proved hash-table regeneration path. Index remaps
preserve key bytes and hash data, and restore Apple's duplicate-value ordering.
"""
from dataclasses import dataclass
import struct
from .exports import require, span


@dataclass(frozen=True)
class SwiftHashHeader:
    capacity: int
    occupied: int
    shift: int
    mask: int
    sentinel: int
    rounded_tab_size: int
    byte_size: int


@dataclass(frozen=True)
class SwiftTable:
    kind: str
    address: int
    header: SwiftHashHeader
    data: bytes
    # (offset in table, first key word, second key word, value/flags)
    rows: tuple
    # Each group is the sequence of table-relative value offsets for one key.
    groups: tuple
    pointer_keys: tuple = ()


# LibPrespecializedData major/minor read on 26 (1.4) and 27 (26B131: 1.5); layouts in
# swift_metadata.pointer_entries.
PRESPECIALIZATION_ABIS = ((1, 4), (1, 5))


def optimization_header(data):
    require(len(data) == 104, 'unsupported Swift optimization header size')
    version, reserved, *offsets = struct.unpack('<II12Q', data)
    require(version == 3 and reserved == 0, 'unsupported Swift optimization header')
    require(all(offsets[i] for i in range(4)), 'required Swift table/data offset absent')
    pointers = offsets[4:]
    require(pointers[0] != 0, 'required prespecialization hash table absent')
    seen_zero = False
    for offset in pointers:
        if offset == 0:
            seen_zero = True
        else:
            require(not seen_zero, 'noncontiguous prespecialization hash offsets')
    require(len(set(o for o in offsets if o)) == len([o for o in offsets if o]), 'aliased Swift roots')
    return dict(version=version, type=offsets[0], metadata=offsets[1], foreign=offsets[2],
                prespecialization=offsets[3], pointer_tables=tuple(o for o in pointers if o))


def hash_header(data):
    require(len(data) >= 1056, 'truncated Swift hash header')
    capacity, occupied, shift, mask, sentinel, rounded = struct.unpack_from('<6I', data)
    require(0 < capacity <= 1 << 22 and capacity & (capacity - 1) == 0, 'invalid Swift hash capacity')
    # 27 (26B131): the second pointer-keyed table (prespecialization data +48) is empty: capacity 1, occupied 0.
    require(0 <= occupied <= capacity, 'invalid Swift hash occupied count')
    require(shift == 64 - (capacity.bit_length() - 1), 'invalid Swift hash shift')
    require(mask < 1 << 22 and (mask + 1) & mask == 0, 'invalid Swift hash mask')
    require(rounded == max(mask + 1, 4) and sentinel == 0xffffffff, 'unsupported Swift hash shape')
    return SwiftHashHeader(capacity, occupied, shift, mask, sentinel, rounded, 1056 + rounded + 5 * capacity)


def read_table(read, address, kind):
    """Decode every bucket and duplicate chain, refusing holes/aliases/overlap."""
    require(kind in ('type', 'metadata', 'foreign', 'pointer'), 'unknown Swift table kind')
    head = hash_header(read(address, 1056))
    prefix = read(address, head.byte_size)
    offsets = struct.unpack_from(f'<{head.capacity}I', prefix, 1056 + head.rounded_tab_size + head.capacity)
    starts = [o for o in offsets if o != head.sentinel]
    require(len(starts) == head.occupied and len(set(starts)) == len(starts), 'Swift bucket count/alias mismatch')
    stride = 16 if kind == 'pointer' else 24
    require(all(o >= head.byte_size and (o - head.byte_size) % stride == 0 for o in starts),
            'Swift value offset misaligned/in header')
    # Builder values form one dense array. Locate its end from the final bucket;
    # then validate every bucket, chain and array element against that boundary.
    end = max(starts) if starts else head.byte_size
    for _ in range(1_000_000 if starts else 0):
        raw = struct.unpack_from('<Q', read(address + end, stride), stride - 8)[0]
        end += stride
        if not (raw >> 63 if kind == 'pointer' else raw & 1):
            break
    else:
        require(not starts, 'unterminated Swift duplicate chain')
    require((end - head.byte_size) // stride <= 1_000_000, 'Swift value count exceeds bound')
    data = read(address, end)
    rows = {}
    groups = []
    pointer_keys = {}
    maximum_end = end
    for start in sorted(starts):
        group = []
        pos = start
        key = None
        while True:
            require(pos < end and pos not in rows, 'Swift duplicate-chain overlap/overflow')
            if kind == 'pointer':
                keyoff, count, raw = struct.unpack('<IIQ', span(data, pos, 16))
                require(0 < count <= 64 and keyoff % 8 == 0 and keyoff >= end,
                        'invalid Swift pointer key array')
                require(keyoff + count * 8 < 1 << 32, 'Swift key offset overflow')
                keys = struct.unpack(f'<{count}Q', read(address + keyoff, count * 8))
                pointer_keys[pos] = keys
                maximum_end = max(maximum_end, keyoff + count * 8)
                row = (pos, keyoff, count, raw)
                this_key = keys
                duplicate = raw >> 63
            else:
                a, b, raw = struct.unpack('<QQQ', span(data, pos, 24))
                row = (pos, a, b, raw)
                this_key = (a, b)
                duplicate = raw & 1
            if key is None:
                key = this_key
            require(key == this_key, 'Swift duplicate chain changes key')
            rows[pos] = row
            group.append(pos)
            if not duplicate:
                break
            pos += stride
        groups.append(tuple(group))
    require(sorted(rows) == list(range(head.byte_size, end, stride)), 'Swift value array has holes')
    ordered = tuple(rows[p] for p in sorted(rows))
    if kind != 'pointer':
        previous = None
        for _, a, b, raw in ordered:
            compare = ((a & ((1 << 48)-1), a >> 48, b, raw & ~1) if kind == 'foreign'
                       else (a, b, raw & ~1))
            require(previous is None or previous <= compare, 'Swift value order differs from source comparator')
            previous = compare
    return SwiftTable(kind, address, head, bytes(read(address, maximum_end)), ordered,
                      tuple(groups), tuple((p, pointer_keys[p]) for p in sorted(pointer_keys)))


def image_index_map(original, final, dropped=()):
    """Original ObjC index -> final index. `dropped`: replaced images with no final ObjC header (26B131: OCLP's IO80211
    shim); they get no entry, so any later use of their old index is refused by checked_index_map or the list edits."""
    require(len(original) < 65536 and len(final) < 65536, 'ObjC image-index capacity exceeded')
    require(all(isinstance(p, str) and p.startswith('/') for p in (*original, *final)), 'invalid ObjC image identity')
    require(len(set(original)) == len(original) and len(set(final)) == len(final), 'duplicate ObjC image identity')
    indexes = {path: i for i, path in enumerate(final)}
    dropped = set(dropped)
    require(not dropped & indexes.keys(), 'dropped ObjC image still in final identity list')
    require(set(original) - dropped <= indexes.keys(), 'original ObjC image missing from final identity list: '
            + repr(sorted(set(original) - dropped - indexes.keys())[:8]))
    return {i: indexes[path] for i, path in enumerate(original) if path not in dropped}


def checked_index_map(mapping, used):
    require(all(type(a) is int and type(b) is int and 0 <= a < 65536 and 0 <= b < 65536
                for a, b in mapping.items()), 'invalid ObjC index mapping')
    require(len(set(mapping.values())) == len(mapping), 'ObjC index mapping merges identities')
    require(set(used) <= mapping.keys(), 'ObjC index mapping incomplete')


def remap_conformance_indexes(table, mapping):
    """Return a new table blob; keys/addresses and hash prefix remain untouched.

    This API accepts no address map. A changed address/key cannot be represented
    by this transform. Its caller must separately establish key identity validity.
    """
    require(table.kind in ('type', 'metadata', 'foreign'), 'pointer tables have no ObjC value index')
    checked_index_map(mapping, (row[3] >> 48 for row in table.rows))
    result = bytearray(table.data)
    values = {row[0]: row for row in table.rows}
    for group in table.groups:
        rewritten = []
        for offset in group:
            _, a, b, raw = values[offset]
            new_raw = (mapping[raw >> 48] << 48) | (raw & ((1 << 48)-2))
            rewritten.append((a, b, new_raw))
        rewritten.sort(key=lambda row: row[2])
        for i, (offset, (a, b, raw)) in enumerate(zip(group, rewritten)):
            struct.pack_into('<QQQ', result, offset, a, b, raw | (i+1 < len(group)))
    require(result[:table.header.byte_size] == table.data[:table.header.byte_size], 'Swift hash prefix changed')
    return bytes(result)


def remap_descriptor_indexes(auxiliary, entries, mapping):
    """Rewrite only occupied descriptor-map uint16 fields.

    entries contains (slot, expected original index); empty-slot auxiliary bytes
    remain unchanged. Pointer descriptors and their implicit string keys are not
    modified by this routine.
    """
    entries = tuple(entries)
    require(all(type(slot) is int and type(index) is int and 0 <= index < 65536
                for slot, index in entries), 'invalid descriptor index record')
    require(len(auxiliary) % 2 == 0, 'unaligned descriptor auxiliary array')
    require(len({slot for slot, _ in entries}) == len(entries), 'duplicate descriptor slot')
    checked_index_map(mapping, (index for _, index in entries))
    result = bytearray(auxiliary)
    for slot, expected in entries:
        require(type(slot) is int and 0 <= slot < len(auxiliary) // 2, 'descriptor auxiliary slot outside array')
        require(struct.unpack_from('<H', auxiliary, slot * 2)[0] == expected, 'descriptor auxiliary original differs')
        struct.pack_into('<H', result, slot * 2, mapping[expected])
    return bytes(result)
