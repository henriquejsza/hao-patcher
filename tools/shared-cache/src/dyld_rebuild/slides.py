"""Bounded v2 slide-chain reader/encoder for existing x86_64 pointer slots.

The pinned family uses 4K pages, one chain per page, and no extras array. This
module refuses other shapes. It cannot create chains or relocate pointer slots.
"""
import struct
from .exports import require, span

MASK64 = (1 << 64) - 1


class SlideInfoV2:
    def __init__(self, info, data, mapping_offset, mapping_size):
        version, page_size, starts, count, extras, nextras, mask, add = struct.unpack("<6I2Q", span(info, 0, 40))
        require(version == 2 and page_size == 4096, "unsupported slide version/page size")
        require(mapping_size > 0 and mapping_size % page_size == 0 and count == mapping_size // page_size,
                "slide page count does not cover mapping")
        require(starts == 40 and extras == nextras == 0 and len(info) == 40 + 2 * count,
                "unsupported slide starts/extras layout")
        require(mask > 0 and mask <= MASK64, "invalid slide delta mask")
        low = (mask & -mask).bit_length() - 1
        contiguous = mask >> low
        require(low >= 2 and contiguous & (contiguous + 1) == 0, "noncontiguous slide delta mask")
        require(0 <= mapping_offset <= len(data) and mapping_size <= len(data) - mapping_offset,
                "slide mapping outside file")
        self.starts = struct.unpack_from(f"<{count}H", info, 40)
        require(all(s == 0x4000 or s < 1024 for s in self.starts), "unsupported extra/invalid page start")
        self.data, self.mapping_offset, self.mapping_size = data, mapping_offset, mapping_size
        self.delta_mask, self.value_mask, self.value_add = mask, MASK64 ^ mask, add
        self.delta_shift = low - 2
        self.pages = {}

    def decode(self, raw):
        require(0 <= raw <= MASK64, "slide word overflow")
        value = raw & self.value_mask
        return ((value + self.value_add) & MASK64) if value else 0

    def page(self, index):
        require(0 <= index < len(self.starts), "slide page outside mapping")
        if index in self.pages:
            return self.pages[index]
        start = self.starts[index]
        result = {}
        if start != 0x4000:
            offset = start * 4
            while True:
                require(offset <= 4096 - 8, "slide chain crosses page boundary")
                raw = struct.unpack_from("<Q", self.data, self.mapping_offset + index * 4096 + offset)[0]
                delta = (raw & self.delta_mask) >> self.delta_shift
                require(delta == 0 or delta >= 8, "overlapping slide-chain words")
                result[index * 4096 + offset] = raw
                if not delta:
                    break
                offset += delta
        self.pages[index] = result
        return result

    def pointer(self, offset):
        require(0 <= offset <= self.mapping_size - 8, "pointer outside slide mapping")
        entries = self.page(offset // 4096)
        require(offset in entries, "pointer is not a slide-chain member")
        raw = entries[offset]
        return {"raw": raw, "target": self.decode(raw),
                "next_delta": (raw & self.delta_mask) >> self.delta_shift}

    def retarget(self, offset, expected, target):
        """Return a new encoded word; no mutation, new slot or chain allocation."""
        pointer = self.pointer(offset)
        require(pointer["target"] == expected, "original slide pointer target differs")
        require(0 <= target <= MASK64, "new pointer target overflow")
        value = (target - self.value_add) & MASK64 if target else 0
        require(target == 0 or value != 0, "non-null target encodes as null")
        require(not value & self.delta_mask, "new target is not representable in slide encoding")
        raw = (pointer["raw"] & self.delta_mask) | value
        require(self.decode(raw) == target, "slide target round-trip failed")
        return raw


def family_slides(family):
    result = []
    for file in family.files:
        for i, mapping in enumerate(file.mappings):
            _, _, _, offset, size, _, _, _ = struct.unpack_from("<6QII", file.data, file.slide_offset + i * 56)
            if size:
                info = span(file.data, offset, size)
                result.append((file, mapping, SlideInfoV2(info, file.data, mapping.offset, mapping.size)))
    return result


def pointer_at(slides, address):
    choices = [(file, mapping, slide) for file, mapping, slide in slides
               if mapping.address <= address and address + 8 <= mapping.address + mapping.size]
    require(len(choices) == 1, "pointer does not have exactly one slide mapping")
    file, mapping, slide = choices[0]
    return file, mapping, slide, slide.pointer(address - mapping.address)
