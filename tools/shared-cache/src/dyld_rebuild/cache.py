"""Bounds-checked reader for a modern x86_64 cache family (dyld-1378 / macOS 26 and macOS 27 headers)."""
from dataclasses import dataclass
import mmap
from pathlib import Path
import struct
from .exports import require, span, cstring


@dataclass(frozen=True)
class Mapping:
    address: int
    size: int
    offset: int
    maximum: int
    initial: int


class CacheFile:
    def __init__(self, path):
        self.path = Path(path)
        self.stream = self.path.open("rb")
        self.data = mmap.mmap(self.stream.fileno(), 0, access=mmap.ACCESS_READ)
        try:
            require(len(self.data) >= 552 and self.data[:16] == b"dyld_v1  x86_64\0", "unknown cache architecture")
            self.mapping_offset, count = struct.unpack_from("<II", self.data, 16)
            # 552: dyld-1378 (macOS 26); 568: macOS 27 (26B131) adds 16 bytes after prewarmingDataSize
            require(self.mapping_offset in (552, 568) and 1 <= count <= 8, "unknown cache header/mapping schema")
            self.mappings = [Mapping(*struct.unpack("<QQQII", span(self.data, self.mapping_offset + i * 32, 32))) for i in range(count)]
            self.signature_offset, self.signature_size = struct.unpack_from("<QQ", self.data, 40)
            require(self.signature_offset + self.signature_size == len(self.data), "signature is not at EOF")
            self.slide_offset, slides = struct.unpack_from("<II", self.data, 312)
            require(slides == count, "mapping table counts disagree")
            for i, mapping in enumerate(self.mappings):
                require(mapping.size > 0 and mapping.size % 4096 == mapping.offset % 4096 == 0, "mapping alignment")
                require(mapping.initial & ~mapping.maximum == 0, "mapping protection mismatch")
                require(mapping.offset + mapping.size <= self.signature_offset, "mapping exceeds signed region")
                entry = struct.unpack("<6QII", span(self.data, self.slide_offset + 56 * i, 56))
                require(entry[:3] + entry[6:] == (mapping.address, mapping.size, mapping.offset, mapping.maximum, mapping.initial),
                        "mapping/slide tables disagree")
                if entry[4]:
                    require(entry[3] > 0 and entry[3] + entry[4] <= self.signature_offset, "slide info outside signed region")
                else:
                    require(entry[3] == 0, "slide offset without size")
            require(self.mappings[0].offset == 0, "TEXT must start at file offset zero")
            require(self.mappings[-1].maximum == 1, "last mapping must be read-only")
            for a, b in zip(self.mappings, self.mappings[1:]):
                require(a.offset + a.size == b.offset and a.address + a.size <= b.address, "overlapping/discontiguous mappings")
            require(self.mappings[-1].offset + self.mappings[-1].size == self.signature_offset,
                    "unmapped data before signature unsupported")
        except BaseException:
            self.close()
            raise

    def close(self):
        self.data.close()
        self.stream.close()

    def offset(self, address, size=1):
        for mapping in self.mappings:
            if mapping.address <= address and address + size <= mapping.address + mapping.size:
                return mapping.offset + address - mapping.address
        return None


class CacheFamily:
    def __init__(self, path):
        self.files = []
        try:
            self.main = CacheFile(path)
            self.files.append(self.main)
            data = self.main.data
            suboff, count = struct.unpack_from("<II", data, 392)
            # 25G241/25G332: 6 subcaches, 3,608 images; 26B131: 6 subcaches, 3,945 images. The shape comes from the
            # header; callers that need a fixed family (graph_contract) pin it themselves.
            require(1 <= count <= 64, "unsupported subcache count")
            for i in range(count):
                entry = span(data, suboff + i * 56, 56)
                suffix, _ = cstring(entry, 24)
                require(suffix == f".{i + 1:02d}", "unexpected subcache suffix/order")
                file = CacheFile(str(path) + suffix)
                self.files.append(file)
                require(entry[:16] == file.data[88:104], "subcache UUID mismatch")
                require(struct.unpack_from("<Q", entry, 16)[0] == file.mappings[0].address - self.main.mappings[0].address,
                        "subcache VM offset mismatch")
            intervals = sorted((m.address, m.address + m.size) for f in self.files for m in f.mappings)
            require(all(a[1] <= b[0] for a, b in zip(intervals, intervals[1:])), "cache VM mappings overlap")
            imgoff, count = struct.unpack_from("<II", data, 448)
            require(0 < count < 65536, "unsupported image count")
            self.images = []
            for i in range(count):
                address, _, _, pathoff, pad = struct.unpack("<QQQII", span(data, imgoff + i * 32, 32))
                path, _ = cstring(span(data, pathoff, min(4096, len(data) - pathoff)), 0)
                # The last word is 0 on 552-byte (26) headers; 568-byte (27) headers use it (1 or 2 on 26B131).
                require(path.startswith("/") and (pad == 0 or self.main.mapping_offset == 568), "invalid image identity")
                self.images.append((path, address))
            require(len({p for p, _ in self.images}) == count, "duplicate image path")
        except BaseException:
            self.close()
            raise

    def locate(self, address, size=1):
        for file in self.files:
            offset = file.offset(address, size)
            if offset is not None:
                return file, offset
        raise ValueError(f"unmapped cache address: {address:#x}+{size:#x}")

    def read(self, address, size):
        file, offset = self.locate(address, size)
        return span(file.data, offset, size)

    def close(self):
        for file in self.files:
            file.close()
        self.files = []


def commands(family, address):
    header = family.read(address, 32)
    magic, cpu, subtype, kind, count, size = struct.unpack_from("<6I", header)
    require((magic, cpu, subtype) == (0xfeedfacf, 0x1000007, 3) and kind in (6, 7, 8), "unexpected cached Mach-O")
    body = family.read(address + 32, size)
    result = []
    pos = 0
    for _ in range(count):
        cmd, size = struct.unpack("<II", span(body, pos, 8))
        require(size >= 8 and size % 8 == 0, "invalid load command length")
        result.append((address + 32 + pos, cmd, span(body, pos, size)))
        pos += size
    require(pos == len(body), "load command count/length mismatch")
    return result


def interpose_sections(family):
    """[(image path, segment, section)] of every interpose section (S_INTERPOSING, or __DATA*,__interpose) left in a
    cache family. dyld ignores them in cache images, so a family that has one silently drops its hooks."""
    found = []
    for path, header in family.images:
        for _, cmd, raw in commands(family, header):
            if cmd != 0x19:
                continue
            segment = raw[8:24].rstrip(b"\0").decode("ascii", "replace")
            nsects, = struct.unpack_from("<I", raw, 64)
            for i in range(nsects):
                row = span(raw, 72 + 80 * i, 80)
                name = row[:16].rstrip(b"\0").decode("ascii", "replace")
                flags, = struct.unpack_from("<I", row, 64)
                if flags & 255 == 0x0d or (name == "__interpose" and segment.startswith("__DATA")):
                    found.append((path, segment, name))
    return found
