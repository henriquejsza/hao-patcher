"""Plan existing v2 chain members becoming fixed, unslid scalar words.

No missing-symbol policy, binary writes, new slot allocation or cache publication.
The caller must provide each current decoded target and desired literal explicitly.
"""
from __future__ import annotations
from dataclasses import dataclass
import struct
from .exports import require
from .slides import MASK64, SlideInfoV2


@dataclass(frozen=True)
class FixedSlot:
    mapping_offset: int
    expected_target: int
    literal: int


@dataclass(frozen=True)
class FixedPagePlan:
    page_index: int
    original_start: int
    edited_start: int
    original_page: bytes
    edited_page: bytes
    fixed_slots: tuple[FixedSlot, ...]
    changed_predecessors: tuple[int, ...]
    original_member_count: int
    surviving_member_count: int


def plan_fixed_slots(slide: SlideInfoV2, page_index: int,
                     changes: list[FixedSlot] | tuple[FixedSlot, ...]) -> FixedPagePlan:
    """Return a page/start-entry edit plan without modifying the supplied mapping.

    Offsets are relative to the slide mapping. All requested slots must be existing
    members on one page. Removing them repairs predecessor deltas and page start;
    the resulting literals are never members of that page's chain.
    """
    require(type(page_index) is int and 0 <= page_index < len(slide.starts), 'fixed page outside mapping')
    changes = tuple(changes)
    require(bool(changes), 'no fixed slots requested')
    require(all(isinstance(c, FixedSlot) for c in changes), 'invalid fixed slot record')
    require(all(type(c.mapping_offset) is type(c.expected_target) is type(c.literal) is int for c in changes),
            'fixed slot values must be integers')
    require(len({c.mapping_offset for c in changes}) == len(changes), 'duplicate fixed slot')
    require(all(0 <= c.expected_target <= MASK64 and 0 <= c.literal <= MASK64 for c in changes),
            'fixed slot target/literal overflow')
    begin = page_index * 4096
    require(all(begin <= c.mapping_offset <= begin + 4088 for c in changes), 'fixed slot outside selected page')
    changes = tuple(sorted(changes, key=lambda c: c.mapping_offset))
    members = slide.page(page_index)
    for change in changes:
        require(change.mapping_offset in members, 'fixed slot is not a chain member')
        require(slide.decode(members[change.mapping_offset]) == change.expected_target,
                'fixed slot original target differs')
    file_offset = slide.mapping_offset + begin
    original = bytes(slide.data[file_offset:file_offset + 4096])
    require(len(original) == 4096, 'truncated fixed page')
    # A cached reader page must not conceal a mutation of caller-owned memory.
    require(all(struct.unpack_from('<Q', original, offset - begin)[0] == raw
                for offset, raw in members.items()), 'source changed after slide page read')
    removed = {c.mapping_offset for c in changes}
    survivors = sorted(set(members) - removed)
    edited = bytearray(original)
    predecessors = []
    for i, offset in enumerate(survivors):
        delta = survivors[i + 1] - offset if i + 1 < len(survivors) else 0
        bits = delta << slide.delta_shift
        require(bits & ~slide.delta_mask == 0, 'new slide delta is not representable')
        raw = (members[offset] & slide.value_mask) | bits
        if raw != members[offset]:
            predecessors.append(offset)
        struct.pack_into('<Q', edited, offset - begin, raw)
    for change in changes:
        struct.pack_into('<Q', edited, change.mapping_offset - begin, change.literal)
    new_start = (survivors[0] - begin) // 4 if survivors else 0x4000
    return FixedPagePlan(page_index, slide.starts[page_index], new_start, original,
                         bytes(edited), changes, tuple(predecessors), len(members), len(survivors))
