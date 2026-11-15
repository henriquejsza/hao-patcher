"""Explicit-schema reader for emitted scratch families; not a runtime certificate.

The original CacheFamily intentionally stays strict about the pinned input.
Candidate counts must be supplied by the caller's versioned build contract.
"""
from pathlib import Path
import struct
from .cache import CacheFile, CacheFamily
from .exports import cstring, require, span


class CandidateFamily(CacheFamily):
    def __init__(self, path, *, image_count, subcache_count):
        require(type(image_count) is int and 0 < image_count < 65536, 'invalid candidate image contract')
        require(type(subcache_count) is int and 0 <= subcache_count < 128, 'invalid candidate subcache contract')
        self.files = []
        try:
            path = Path(path)
            self.main = CacheFile(path)
            self.files.append(self.main)
            data = self.main.data
            offset, count = struct.unpack_from('<II',data,392)
            require(count == subcache_count, 'candidate subcache count differs from contract')
            for i in range(count):
                entry = span(data,offset+i*56,56)
                suffix,end = cstring(entry,24)
                require(suffix == f'.{i+1:02d}' and not any(entry[end:]), 'candidate suffix/order/padding differs')
                file = CacheFile(str(path)+suffix)
                self.files.append(file)
                require(entry[:16] == file.data[88:104], 'candidate subcache UUID differs')
                require(struct.unpack_from('<Q',entry,16)[0] == file.mappings[0].address-self.main.mappings[0].address,
                        'candidate subcache VM offset differs')
            intervals = sorted((m.address,m.address+m.size) for f in self.files for m in f.mappings)
            require(all(a[1] <= b[0] for a,b in zip(intervals,intervals[1:])), 'candidate VM mappings overlap')
            self.images = []
            offset,count = struct.unpack_from('<II',data,448)
            require(count == image_count, 'candidate image count differs from contract')
            for i in range(count):
                address,_,_,pathoff,pad = struct.unpack('<3Q2I',span(data,offset+32*i,32))
                path,_ = cstring(span(data,pathoff,min(4096,len(data)-pathoff)),0)
                # The last word is padding (0) in 26's 552-byte header. 27's 568-byte header uses it: 26B131 has 1
                # in 3,941 rows and 2 for libxpc, libsystem_sandbox, libSystem and libsystem_secinit (meaning unread).
                require(path.startswith('/') and (pad == 0 or self.main.mapping_offset == 568),'invalid candidate image identity')
                require(struct.unpack_from('<I',self.read(address,4))[0] == 0xfeedfacf,'candidate image header missing')
                self.images.append((path,address))
            require(len({p for p,_ in self.images}) == count,'duplicate candidate image path')
        except BaseException:
            self.close()
            raise
