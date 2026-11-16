"""Read the pinned x86_64 v4 patch table, including shared GOT import strength.

Layout reference: pinned dyld-1378 common/CachePatching.h. This is a reader;
missing exports remain unresolved and no null/sentinel policy is implemented.
"""
import struct
from .exports import require, span, cstring


class PatchTableV4:
    SIZES = (16, 8, 12, 12, 8, 1, 8, 12, 16)
    NAMES = ("images", "exports", "clients", "client_exports", "locations",
             "names", "got_clients", "got_exports", "got_locations")

    def __init__(self, data, address, images, cache_base):
        header = struct.unpack("<II18Q", span(data, 0, 152))
        require(header[:2] == (4, 0), "unsupported patch table/location version")
        self.data, self.address = data, address
        self.images, self.cache_base = images, cache_base
        self.arrays = {}
        ranges = []
        for i, (name, size) in enumerate(zip(self.NAMES, self.SIZES)):
            start, count = header[2 + 2 * i:4 + 2 * i]
            offset = start - address
            require(offset >= 152, "patch array overlaps header")
            require(offset <= len(data) and count * size <= len(data) - offset,
                    "patch array outside table")
            self.arrays[name] = (offset, count, size)
            if count:
                ranges.append((offset, offset + count * size))
        ranges.sort()
        require(all(a[1] <= b[0] for a, b in zip(ranges, ranges[1:])), "patch arrays overlap")
        require(self.arrays["images"][1] == self.arrays["got_clients"][1] == len(images),
                "patch image counts disagree")

    def record(self, name, index, fmt):
        offset, count, size = self.arrays[name]
        require(0 <= index < count and struct.calcsize(fmt) == size, "patch record index/size")
        return struct.unpack_from(fmt, self.data, offset + index * size)

    def indices(self, name, start, count):
        require(0 <= start <= self.arrays[name][1] and 0 <= count <= self.arrays[name][1] - start,
                "patch subarray outside array")
        return range(start, start + count)

    def export(self, index, image_index, export_range):
        require(index in export_range, "patch export belongs to another image")
        offset, flags = self.record("exports", index, "<II")
        require(flags >> 28 in (0, 1, 8), "unknown patch kind")
        start, size, _ = self.arrays["names"]
        name_offset = flags & 0xfffffff
        require(name_offset < size, "patch name outside strings")
        # Limit the string search to the declared names array.
        name, end = cstring(self.data, start + name_offset)
        require(end <= start + size and name, "patch name escapes strings")
        path, address = self.images[image_index]
        return {"target": path, "symbol": name, "implementation": address + offset,
                "export_index": index, "export_kind": flags >> 28}

    @staticmethod
    def metadata(word):
        require(not word & 1, "authenticated patch unsupported on x86_64")
        return {"weak_import": bool(word & 0x100), "addend": word >> 9,
                "high8": ((word >> 1) & 0x7f) << 1}

    def image_uses(self, image_index):
        client_start, client_count, export_start, export_count = self.record("images", image_index, "<4I")
        export_range = self.indices("exports", export_start, export_count)
        rows = []
        for client_idx in self.indices("clients", client_start, client_count):
            client, start, count = self.record("clients", client_idx, "<3I")
            require(client < len(self.images), "patch client image out of range")
            for ref in self.indices("client_exports", start, count):
                export, loc_start, loc_count = self.record("client_exports", ref, "<3I")
                info = self.export(export, image_index, export_range)
                for loc in self.indices("locations", loc_start, loc_count):
                    offset, word = self.record("locations", loc, "<II")
                    rows.append({**info, **self.metadata(word), "kind": "PATCH",
                                 "location": self.images[client][1] + offset,
                                 "client_index": client, "client": self.images[client][0]})
        start, count = self.record("got_clients", image_index, "<II")
        for ref in self.indices("got_exports", start, count):
            export, loc_start, loc_count = self.record("got_exports", ref, "<3I")
            info = self.export(export, image_index, export_range)
            for loc in self.indices("got_locations", loc_start, loc_count):
                offset, word, padding = self.record("got_locations", loc, "<QII")
                require(padding == 0, "nonzero GOT patch padding")
                rows.append({**info, **self.metadata(word), "kind": "GOT",
                             "location": self.cache_base + offset,
                             "client_index": None, "client": None})
        require(len({(r["kind"], r["location"]) for r in rows}) == len(rows), "duplicate patch location")
        return rows
