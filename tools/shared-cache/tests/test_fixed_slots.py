import struct
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
import unittest
from dyld_rebuild.exports import Refusal
from dyld_rebuild.fixed_slots import FixedSlot, plan_fixed_slots
from dyld_rebuild.slides import SlideInfoV2

MASK = 0x00FFFF0000000000
ADD = 0x7FF800000000
SHIFT = (MASK & -MASK).bit_length() - 3


def fixture(positions=(0, 8, 16), pages=1):
    data = bytearray(4096 * pages)
    for i, pos in enumerate(positions):
        delta = positions[i + 1] - pos if i + 1 < len(positions) else 0
        struct.pack_into('<Q', data, pos, (delta << SHIFT) | (0x100 + pos))
    info = struct.pack('<6I2Q', 2, 4096, 40, pages, 0, 0, MASK, ADD)
    info += struct.pack('<H', positions[0] // 4 if positions else 0x4000)
    info += struct.pack('<H', 0x4000) * (pages - 1)
    return SlideInfoV2(info, data, 0, len(data)), data


class FixedSlotsTests(unittest.TestCase):
    def check(self, positions, removed):
        slide, data = fixture(positions)
        before = bytes(data)
        changes = [FixedSlot(p, ADD + 0x100 + p, 0x12340000 + p) for p in removed]
        plan = plan_fixed_slots(slide, 0, changes)
        self.assertEqual(bytes(data), before)
        kept = sorted(set(positions) - set(removed))
        info = struct.pack('<6I2QH', 2, 4096, 40, 1, 0, 0, MASK, ADD, plan.edited_start)
        decoded = SlideInfoV2(info, plan.edited_page, 0, 4096)
        self.assertEqual(sorted(decoded.page(0)), kept)
        for p in kept:
            self.assertEqual(decoded.pointer(p)['target'], ADD + 0x100 + p)
        for p in removed:
            self.assertEqual(struct.unpack_from('<Q', plan.edited_page, p)[0], 0x12340000 + p)
        allowed = {p + b for p in set(removed) | set(plan.changed_predecessors) for b in range(8)}
        self.assertTrue({i for i, pair in enumerate(zip(before, plan.edited_page)) if pair[0] != pair[1]} <= allowed)
        return plan

    def test_interior_adjacent_sparse_first_last_only_all(self):
        for positions, removed in [((0,8,16,24,4088),(8,16)), ((8,24,4088),(24,)),
                                    ((0,8,16),(0,)), ((0,8,16),(16,)), ((4088,),(4088,)),
                                    ((0,8,16),(0,8,16))]:
            with self.subTest(positions=positions, removed=removed):
                self.check(positions, removed)

    def test_explicit_literals_and_order_independence(self):
        slide, _ = fixture()
        changes = [FixedSlot(0, ADD+0x100, 0), FixedSlot(16, ADD+0x110, (1<<64)-1)]
        a = plan_fixed_slots(slide, 0, changes)
        b = plan_fixed_slots(slide, 0, tuple(reversed(changes)))
        self.assertEqual(a, b)
        self.assertEqual(struct.unpack_from('<Q', a.edited_page, 0)[0], 0)
        self.assertEqual(struct.unpack_from('<Q', a.edited_page, 16)[0], (1<<64)-1)

    def test_refuses_wrong_target_nonmember_duplicate_empty_and_cross_page(self):
        slide, _ = fixture(pages=2)
        good = FixedSlot(0, ADD+0x100, 7)
        cases = [[], [good,good], [FixedSlot(0,ADD,7)], [FixedSlot(4,ADD+0x104,7)],
                 [FixedSlot(4096,ADD+0x1100,7)], [FixedSlot(-1,0,7)],
                 [FixedSlot(0,-1,7)], [FixedSlot(0,ADD+0x100,1<<64)],
                 [FixedSlot(0,ADD+0x100,-1)], [FixedSlot(True,ADD+0x100,7)]]
        for changes in cases:
            with self.subTest(changes=changes), self.assertRaises(Refusal):
                plan_fixed_slots(slide,0,changes)
        for page in (-1,2,True):
            with self.assertRaises(Refusal): plan_fixed_slots(slide,page,[good])

    def test_refuses_source_mutated_after_reader_cached_page(self):
        slide, data = fixture()
        slide.page(0)
        data[8] ^= 1
        with self.assertRaises(Refusal):
            plan_fixed_slots(slide,0,[FixedSlot(0,ADD+0x100,7)])

    def test_refuses_unrepresentable_join(self):
        mask = 0xC000000000000000
        shift = 60
        data = bytearray(4096)
        for pos in (0,8,16):
            struct.pack_into('<Q',data,pos,((8 if pos<16 else 0)<<shift) | (0x100+pos))
        info=struct.pack('<6I2QH',2,4096,40,1,0,0,mask,ADD,0)
        slide=SlideInfoV2(info,data,0,4096)
        with self.assertRaisesRegex(Refusal,'not representable'):
            plan_fixed_slots(slide,0,[FixedSlot(8,ADD+0x108,7)])


if __name__ == '__main__': unittest.main()
