"""Checked byte edits and combined v2 membership changes for scratch assembly."""
from collections import defaultdict
import struct
from .exports import require
from .slides import MASK64


def merge_pointer_edits(edits):
    result = {}
    for edit in edits:
        address = edit['address']
        core = {k: edit[k] for k in ('address', 'expected', 'target', 'member_before', 'member_after')}
        require(type(address) is int and address % 4 == 0 and address % 4096 <= 4088,
                'unaligned/cross-page pointer edit')
        require(type(core['expected']) is int and type(core['target']) is int and
                0 <= core['expected'] <= MASK64 and 0 <= core['target'] <= MASK64,
                'pointer edit value outside uint64')
        require(type(core['member_before']) is type(core['member_after']) is bool, 'invalid membership flag')
        require(address not in result or result[address] == core, 'conflicting decoded pointer edits')
        result[address] = core
    return [result[k] for k in sorted(result)]


def edit_page(slide, page_index, edits):
    """Combine target changes, new slots and fixed literals on one existing page."""
    begin = page_index * 4096
    original_members = slide.page(page_index)
    original = bytes(slide.data[slide.mapping_offset + begin:slide.mapping_offset + begin + 4096])
    members = {offset: slide.decode(raw) for offset, raw in original_members.items()}
    require(len(original) == 4096, 'truncated pointer-edit page')
    fixed, touched = {}, set()
    for edit in edits:
        offset = edit['offset']
        require(begin <= offset <= begin + 4088 and offset % 4 == 0, 'pointer edit outside selected page')
        require(offset not in touched, 'duplicate page pointer edit')
        touched.add(offset)
        require((offset in members) == edit['member_before'], 'pointer membership differs before edit')
        expected = members[offset] if offset in members else struct.unpack_from('<Q', original, offset - begin)[0]
        require(expected == edit['expected'], 'decoded pointer value differs before edit')
        if edit['member_after']:
            members[offset] = edit['target']
        else:
            members.pop(offset, None)
            fixed[offset] = edit['target']
    order = sorted(members)
    require(all(a + 8 <= b for a, b in zip(order, order[1:])), 'new slide members overlap')
    require(not any(a < f + 8 and f < a + 8 for a in order for f in fixed), 'fixed literal overlaps slide member')
    edited = bytearray(original)
    for index, offset in enumerate(order):
        target = members[offset]
        require(0 <= target <= MASK64, 'pointer target overflow')
        value = (target - slide.value_add) & MASK64 if target else 0
        require((not target or value) and not value & slide.delta_mask, 'new target not representable in v2')
        delta = order[index + 1] - offset if index + 1 < len(order) else 0
        bits = delta << slide.delta_shift
        require(not bits & ~slide.delta_mask, 'new slide delta not representable')
        struct.pack_into('<Q', edited, offset - begin, value | bits)
    for offset, value in fixed.items():
        struct.pack_into('<Q', edited, offset - begin, value)
    start = (order[0] - begin) // 4 if order else 0x4000
    writes = []
    for offset in sorted(set(original_members) | set(members) | set(fixed)):
        at = offset - begin
        before, after = original[at:at + 8], bytes(edited[at:at + 8])
        if before != after:
            writes.append((offset, before, after))
    return {'page': page_index, 'original': original, 'edited': bytes(edited),
            'old_start': slide.starts[page_index], 'new_start': start, 'writes': writes,
            'members': members, 'fixed': fixed}


def pointer_pages(slides, edits):
    by_mapping = defaultdict(list)
    for edit in merge_pointer_edits(edits):
        matches = [(file, mapping, slide) for file, mapping, slide in slides
                   if mapping.address <= edit['address'] and edit['address'] + 8 <= mapping.address + mapping.size]
        require(len(matches) == 1, 'pointer edit does not have one existing slide mapping')
        file, mapping, slide = matches[0]
        by_mapping[mapping.address].append(dict(edit, offset=edit['address'] - mapping.address))
    plans = []
    for file, mapping, slide in slides:
        pages = defaultdict(list)
        for edit in by_mapping.get(mapping.address, []):
            pages[edit['offset'] // 4096].append(edit)
        for page, changes in sorted(pages.items()):
            plans.append((file, mapping, slide, edit_page(slide, page, changes)))
    return plans


def checked_byte_edits(edits):
    """Coalesce identical edits; refuse partial overlap and inconsistent extents."""
    unique = {}
    for address, before, after in edits:
        require(type(address) is int and address >= 0 and isinstance(before, bytes) and isinstance(after, bytes)
                and len(before) == len(after) > 0, 'invalid byte edit')
        key = address, len(before)
        require(key not in unique or unique[key] == (before, after), 'conflicting byte edits')
        unique[key] = before, after
    result = [(a, *unique[(a, n)]) for a, n in sorted(unique)]
    require(all(a + len(old) <= b for (a, old, _), (b, _, _) in zip(result, result[1:])),
            'overlapping byte edits')
    return result
