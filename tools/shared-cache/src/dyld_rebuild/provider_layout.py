"""Checked producer plan for uniformly relocated provider subcache inputs.

Never maps/executes providers and never edits an input. Existing cache VM maps
are occupied intervals. Each new file has its own cache header prefix, provider
Mach-O sections, newly allocated v2 slide metadata and ad-hoc signature extent.
The result is a writer input, not a cache emitter or target acceptance proof.
"""
from collections import Counter
from dataclasses import asdict, dataclass
import hashlib
import json
import struct
from .codesign import geometry
from .exports import Refusal, require, span, uleb
from .imports import read_imports
from .objc_transfer import DiskReader
from .provider_identity import x86_slice

PAGE = 4096
PREFIX = 16384
DELTA_MASK = 0x00ffff0000000000


def align(value, boundary=PAGE):
    require(value >= 0 and boundary > 0 and boundary & (boundary - 1) == 0, 'invalid alignment')
    return (value + boundary - 1) & ~(boundary - 1)


def sha(data):
    return hashlib.sha256(data).hexdigest()


@dataclass(frozen=True)
class Segment:
    index: int
    name: str
    command_offset: int
    address: int
    size: int
    file_offset: int
    file_size: int
    maximum: int
    initial: int


class Provider:
    def __init__(self, key, data, canonical):
        self.key, self.canonical = key, canonical
        start, length, _ = x86_slice(data)
        self.container_offset = start
        self.data = span(data, start, length)
        bundle_path=canonical if struct.unpack_from("<I",self.data,12)[0]==8 else None
        self.reader = DiskReader(self.data,bundle_path=bundle_path)
        require(self.reader.image.install_name == canonical, 'provider identity is not canonical')
        self.image, imports, self.import_info = read_imports(self.data,bundle_path=bundle_path)
        self.import_count = len(imports)
        self.import_rows = imports
        self.sections, self.segments, self.commands, self.linkedit = [], [], [], []
        count, size = struct.unpack_from('<II', self.data, 16)
        pos = 32
        split = []
        self.classic_rebase_streams = []
        for _ in range(count):
            cmd, length = struct.unpack_from('<II', self.data, pos)
            raw = span(self.data, pos, length)
            self.commands.append({'command': cmd, 'offset': pos, 'size': length})
            if cmd == 0x19:
                index = len(self.segments)
                vm, vs, off, fs = struct.unpack_from('<4Q', raw, 24)
                maximum, initial, nsects = struct.unpack_from('<3I', raw, 56)
                name = raw[8:24].rstrip(b'\0').decode('ascii')
                require(vm % PAGE == off % PAGE == 0 and vs > 0 and fs <= vs,
                        'provider segment start is not page aligned or file extent exceeds VM extent')
                require(initial & ~maximum == 0 and initial in (1,3,5) and maximum in (1,3,5,7), 'unsupported/WX segment protection')
                self.segments.append(Segment(index, name, pos, vm, vs, off, fs, maximum, initial))
                require(length == 72 + 80 * nsects, 'section count/command size mismatch')
                for i in range(nsects):
                    at = pos + 72 + i * 80
                    row = span(self.data, at, 80)
                    sva, ssize, soff, alignment, reloff, nreloc, flags = struct.unpack_from('<QQ5I', row, 32)
                    require(vm <= sva <= vm + vs and ssize <= vm + vs - sva, 'section outside segment')
                    require(alignment <= 31 and sva % (1 << alignment) == 0, 'invalid section alignment')
                    require(reloff == nreloc == 0, 'section relocations require a relocation-specific plan')
                    zerofill = flags & 255 in (1, 12, 18)
                    if not zerofill and ssize:
                        require(off <= soff and soff + ssize <= off + fs, 'section file range outside segment')
                    self.sections.append({'index': len(self.sections) + 1, 'segment': index,
                        'name': row[:16].split(b'\0')[0].decode('ascii'), 'address': sva, 'size': ssize,
                        'offset': soff, 'flags': flags, 'alignment': alignment, 'command_offset': at})
            elif cmd in (0x22, 0x80000022):
                off, n = struct.unpack_from('<II', raw, 8)
                if n:
                    self.classic_rebase_streams.append(span(self.data, off, n))
                for i, kind in enumerate(('rebase', 'bind', 'weak_bind', 'lazy_bind', 'exports')):
                    off, n = struct.unpack_from('<II', raw, 8 + 8 * i)
                    if n: self.linkedit.append({'kind': kind, 'offset': off, 'size': n})
            elif cmd in (0x1d, 0x1e, 0x26, 0x29, 0x80000033, 0x80000034):
                off, n = struct.unpack_from('<II', raw, 8)
                span(self.data, off, n)
                self.linkedit.append({'kind': hex(cmd), 'offset': off, 'size': n})
                if cmd == 0x1e: split.append(span(self.data, off, n))
            elif cmd == 2:
                off, count_, strings, n = struct.unpack_from('<4I', raw, 8)
                span(self.data, off, count_ * 16); span(self.data, strings, n)
                self.linkedit += [{'kind': 'nlist_64', 'offset': off, 'size': count_ * 16},
                                  {'kind': 'strings', 'offset': strings, 'size': n}]
            elif cmd == 0xb:
                fields = struct.unpack_from('<18I', raw, 8)
                for at, width, kind in ((6, 8, 'toc'), (8, 56, 'modules'), (10, 4, 'external_refs'),
                                        (12, 4, 'indirect_symbols'), (14, 8, 'external_relocations'),
                                        (16, 8, 'local_relocations')):
                    off, n = fields[at:at+2]
                    if n:
                        span(self.data, off, n * width)
                        self.linkedit.append({'kind': kind, 'offset': off, 'size': n * width})
                        require(at not in (14, 16), 'classic relocation table requires a separate checked plan')
            pos += length
        require(pos == 32 + size and len(split) <= 1, 'provider command/split count mismatch')
        text = [s for s in self.segments if s.name == '__TEXT']
        require(len(text) == 1 and text[0].index == 0 and text[0].file_offset == 0, 'need first TEXT segment')
        require(self.segments[-1].name == '__LINKEDIT' and self.segments[-1].initial == 1,
                'provider last segment must be read-only LINKEDIT')
        require(all(a.address + a.size <= b.address for a, b in zip(self.segments, self.segments[1:])),
                'overlapping or unordered provider segments')
        self.base = text[0].address
        self.split = decode_split(split[0], self) if split else {'format': 'absent', 'entries': []}
        self.rebases = dict(self.reader.rebases)
        for stream in self.classic_rebase_streams:
            for field, target in classic_rebases(stream, self).items():
                require(field not in self.rebases, 'duplicate rebase field')
                self.rebases[field] = target
        # Classic weak coalescing may supersede a local weak-definition rebase.
        for field in self.rebases.keys() & self.reader.weak_bind_fields:
            binding = self.reader.binds[field]
            exp = self.image.exports.get(binding['symbol'])
            require(exp is not None and exp.flags in (0,4) and
                    self.rebases[field] == self.base + exp.value + binding['addend'],
                    'weak coalescing rebase lacks exact local definition')
            del self.rebases[field]
        lazy_fields = {r.address for r in self.import_rows if r.lazy}
        for field in self.rebases.keys() & self.reader.binds.keys() & lazy_fields:
            require(any(s.initial & 4 and s.address <= self.rebases[field] < s.address+s.size
                        for s in self.segments), 'lazy bind rebase is not an executable stub')
            del self.rebases[field]
        require(not (self.rebases.keys() & self.reader.binds.keys()), 'field is both bind and rebase')
        for field, target in self.rebases.items():
            self.segment(field, 8)
            require(target == 0 or any(s.address <= (target & ~7) < s.address + s.size for s in self.segments),
                    f'rebase target outside provider: {key} {field:#x}->{target:#x}')
        self.interpose = interpose_tuples(self)
        # dyld ignores __interpose in a cache image (dyld-1378 DyldRuntimeState.cpp:1310): the tuples become cache
        # patches (run_prepare/run_patch) and their own pointer fields are not emitted (emit zeroes the section).
        tuple_fields = {f for t in self.interpose for f in (t['field'], t['field'] + 8)}
        self.fixup_fields = sorted((self.rebases.keys() | self.reader.binds.keys()) - tuple_fields)
        require(all(f % 4 == 0 for f in self.fixup_fields), 'v2 chain field not four-byte aligned')
        require(all(a + 8 <= b for a, b in zip(self.fixup_fields, self.fixup_fields[1:])), 'overlapping pointer fixups')
        # On-disk selectors/ObjC coalescing need the dedicated metadata writer even
        # though uniform sliding preserves local relative differences.

    def segment(self, address, size=1):
        found = [s for s in self.segments if s.address <= address and address + size <= s.address + s.size]
        require(len(found) == 1, f'provider address has no unique segment: {address:#x}+{size:#x}')
        return found[0]

    def file_offset(self, address, size=1):
        seg = self.segment(address, size)
        require(address + size <= seg.address + seg.file_size, 'provider address has no file bytes')
        return seg.file_offset + address - seg.address


S_INTERPOSING = 0x0d


def is_interpose(section, segment_name):
    return section['flags'] & 255 == S_INTERPOSING or (section['name'] == '__interpose' and
                                                        segment_name.startswith('__DATA'))


def interpose_tuples(image):
    """[{field, replacement (source address), original binding}] of every __interpose section: 16-byte entries, a
    local rebase to the replacement then a bind to the original. Anything else is a refusal."""
    rows = []
    for section in image.sections:
        if not is_interpose(section, image.segments[section['segment']].name):
            continue
        require(section['size'] % 16 == 0 and section['size'], 'interpose section is not whole 16-byte tuples')
        for field in range(section['address'], section['address'] + section['size'], 16):
            replacement = image.rebases.get(field)
            binding = image.reader.binds.get(field + 8)
            require(replacement and field not in image.reader.binds and binding is not None and
                    field + 8 not in image.rebases, f'interpose tuple is not rebase + bind: {image.key} {field:#x}')
            require(image.segment(replacement).initial & 4, 'interpose replacement is not code')
            require(binding['addend'] == 0, 'interpose original with an addend')
            rows.append(dict(field=field, replacement=replacement, original=dict(binding)))
    require(len({r['original']['symbol'] for r in rows}) == len(rows), 'one original interposed twice in one image')
    return rows


def classic_rebases(data, image):
    pos, segment, offset, kind = 0, None, None, None
    result = {}
    def rebase():
        nonlocal offset
        require(kind == 1 and segment is not None and offset is not None, 'unsupported/incomplete classic rebase state')
        seg = image.segments[segment]
        require(0 <= offset and offset + 8 <= seg.file_size, 'classic rebase outside file-backed segment')
        field = seg.address + offset
        require(field not in result, 'duplicate classic rebase')
        result[field] = struct.unpack_from('<Q', image.data, seg.file_offset + offset)[0]
        offset += 8
    while pos < len(data):
        byte = data[pos]; pos += 1
        op, imm = byte & 240, byte & 15
        if op == 0:
            require(imm == 0 and not any(data[pos:]), 'malformed rebase DONE')
            return result
        if op == 0x10: kind = imm
        elif op == 0x20:
            require(imm < len(image.segments), 'invalid rebase segment')
            segment = imm; offset, pos = uleb(data, pos)
        elif op in (0x30, 0x40):
            require(offset is not None, 'rebase address advance without segment')
            if op == 0x30: delta, pos = uleb(data, pos)
            else: delta = imm * 8
            offset += delta
        elif op in (0x50, 0x60):
            if op == 0x50: count = imm
            else: count, pos = uleb(data, pos)
            require(count <= 2_000_000, 'rebase expansion limit')
            for _ in range(count): rebase()
        elif op == 0x70:
            rebase(); delta, pos = uleb(data, pos); offset += delta
        elif op == 0x80:
            count, pos = uleb(data, pos); skip, pos = uleb(data, pos)
            require(count <= 2_000_000, 'rebase expansion limit')
            for _ in range(count): rebase(); offset += skip
        else: raise Refusal(f'unsupported rebase opcode {op:#x}')
    raise Refusal('classic rebase stream lacks DONE')


def decode_split(data, image):
    require(data, 'empty split-segment payload')
    entries = []
    if data[0] != 127:
        pos = 0
        while pos < len(data) and data[pos]:
            kind = data[pos]; pos += 1
            require(kind in (1, 2), 'non-x86 split v1 instruction kind')
            offset = 0
            while True:
                delta, pos = uleb(data, pos)
                if not delta: break
                offset += delta
                width = 4 if kind == 1 else 8
                field = image.base + offset
                require(image.segment(field, width).index == 0, 'v1 reference outside TEXT')
                image.file_offset(field, width)
                entries.append({'kind': kind, 'field': field, 'width': width})
        require(pos < len(data) and data[pos] == 0 and not any(data[pos:]), 'unterminated split v1/trailing data')
        return {'format': 'v1', 'entries': entries}
    pos = 1
    groups, pos = uleb(data, pos)
    require(groups <= 100000, 'split v2 group limit')
    sections = [{'address': image.base, 'size': image.segments[0].size, 'segment': 0}] + image.sections
    for _ in range(groups):
        source, pos = uleb(data, pos); target, pos = uleb(data, pos); count, pos = uleb(data, pos)
        require(source < len(sections) and target < len(sections) and count <= 1000000, 'split v2 section/count invalid')
        target_offset = 0
        for _ in range(count):
            delta, pos = uleb(data, pos); target_offset += delta
            kinds, pos = uleb(data, pos)
            require(kinds <= 100000, 'split v2 kind count limit')
            for _ in range(kinds):
                kind, pos = uleb(data, pos); references, pos = uleb(data, pos)
                require(kind in (1, 2, 3, 4, 12) and references <= 1000000, 'unsupported x86 split v2 kind/count')
                source_offset = 0
                for _ in range(references):
                    delta, pos = uleb(data, pos); source_offset += delta
                    width = 8 if kind in (2, 4) else 4
                    require(source_offset + width <= sections[source]['size'], 'split v2 source reference outside section')
                    target_address = sections[target]['address'] + target_offset
                    target_segment = image.segments[sections[target]['segment']]
                    # Unwind sentinel in pinned libhelloblur is __text end+1,
                    # inside TEXT padding. Preserve its declared segment slide.
                    require(target_segment.address <= target_address <= target_segment.address + target_segment.size,
                            'split v2 target outside declared segment')
                    field = sections[source]['address'] + source_offset
                    image.file_offset(field, width)
                    entries.append({'kind': kind, 'field': field, 'width': width,
                        'source_segment': sections[source]['segment'], 'target_segment': sections[target]['segment'],
                        'target': target_address})
    require(not any(data[pos:]), 'split v2 trailing nonzero bytes')
    return {'format': 'v2', 'entries': entries}


def split_constraints(image, slides):
    require(len(slides) == len(image.segments), 'segment slide count mismatch')
    entries = image.split['entries']
    if image.split['format'] == 'absent':
        require(len(set(slides)) == 1, 'absent split metadata requires uniform segment slide in this plan')
        return {'format': 'absent', 'references_checked': 0, 'changed_code_references': 0}
    changed = 0
    for entry in entries:
        if image.split['format'] == 'v1':
            delta = slides[1] - slides[0]
        else:
            delta = slides[entry['target_segment']] - slides[entry['source_segment']]
        old = int.from_bytes(image.data[image.file_offset(entry['field'], entry['width']):][:entry['width']],
                             'little', signed=entry['width'] == 4 and entry['kind'] in (1, 3))
        if image.split['format'] == 'v1' and entry['kind'] == 1 or image.split['format'] == 'v2' and entry['kind'] == 3:
            require(-(1 << 31) <= old + delta < (1 << 31), 'signed 32-bit split displacement overflow')
        if image.split['format'] == 'v2' and entry['kind'] == 12:
            new = entry['target'] + slides[entry['target_segment']] - (image.base + slides[0])
            require(0 <= new < 2**32, 'image-relative 32-bit offset overflow')
        changed += bool(delta)
    return {'format': image.split['format'], 'references_checked': len(entries),
            'changed_code_references': changed, 'kinds': dict(Counter(str(e['kind']) for e in entries)),
            'decoded_entries_sha256': sha(json.dumps(entries, sort_keys=True, separators=(',', ':')).encode())}


def v2_plan(fields, mapping_address, mapping_size):
    require(mapping_address % PAGE == mapping_size % PAGE == 0 and mapping_size > 0, 'invalid v2 mapping geometry')
    pages = {}
    for field in fields:
        require(mapping_address <= field and field + 8 <= mapping_address + mapping_size and field % 4 == 0,
                'v2 pointer outside mapping or unaligned')
        offset = field - mapping_address
        require(offset % PAGE <= PAGE - 8, 'v2 pointer straddles page')
        pages.setdefault(offset // PAGE, []).append(offset % PAGE)
    starts = [0x4000] * (mapping_size // PAGE)
    for page, offsets in pages.items():
        offsets.sort()
        require(len(offsets) == len(set(offsets)) and all(a + 8 <= b for a, b in zip(offsets, offsets[1:])),
                'duplicate/overlapping v2 chain fields')
        starts[page] = offsets[0] // 4
        for a, b in zip(offsets, offsets[1:]):
            require((b - a) << 38 & ~DELTA_MASK == 0, 'v2 next delta exceeds mask')
    return {'version': 2, 'page_size': PAGE, 'page_count': len(starts), 'page_starts': starts,
            'delta_mask': DELTA_MASK, 'fields': len(fields), 'extras_count': 0,
            'size': 40 + 2 * len(starts)}


def file_geometry(image, identifier, prefix=None, image_paths=('/fixture',), header_size=552):
    require(header_size in (552, 568), 'unknown cache header size')
    count = len(image.segments)
    require(1 < count <= 8, 'new cache mapping count exceeds observed dyld8 limit')
    table_end = header_size + count * (32 + 56)
    require(table_end <= 4096, 'cache mapping tables exceed first page')
    require(image_paths and len(image_paths) == len(set(image_paths)) and
            all(p.startswith('/') and '\0' not in p for p in image_paths), 'invalid canonical image paths')
    image_count = len(image_paths)
    images_offset = table_end
    image_text_offset = images_offset + image_count * 32
    string_pool_offset = image_text_offset + image_count * 32
    path_offsets = []
    pool_end = string_pool_offset
    for path in image_paths:
        path_offsets.append(pool_end)
        pool_end += len(path.encode('utf-8')) + 1
    if prefix is None:
        prefix = align(pool_end, 16384)
    require(prefix >= 4096 and prefix % PAGE == 0, 'cache header prefix must contain a first page')
    require(pool_end <= prefix and table_end <= prefix, 'complete cache image arrays/string pool collide with provider TEXT')
    mappings, segments, offset = [], [], 0
    slide_bytes = 0
    for segment in image.segments:
        header = prefix if segment.index == 0 else 0
        mapping_size = header + align(segment.size)
        fields = [f for f in image.fixup_fields if segment.address <= f < segment.address + segment.size]
        # Geometry is computed before selecting a global slide.
        slide = v2_plan(fields, segment.address - header, mapping_size) if fields else None
        if slide: slide_bytes += align(slide['size'], 8)
        mappings.append({'source_segment': segment.index, 'relative_address': segment.address - image.base - header,
            'size': mapping_size, 'file_offset': offset, 'maximum': segment.initial if segment.maximum == 7 else segment.maximum,
            'initial': 1 if segment.name == '__DATA_CONST' else segment.initial,
            'flags': 4 if segment.name == '__DATA_CONST' else 32 if segment.maximum == 1 and segment.name != '__LINKEDIT' else 0,
            'slide_info': slide})
        segments.append({'source': asdict(segment), 'new_file_offset': offset + header})
        offset += mapping_size
    slide_offset = offset
    cursor = slide_offset
    for mapping in mappings:
        if mapping['slide_info'] is not None:
            mapping['slide_info']['file_offset'] = cursor
            mapping['slide_info']['value_add'] = 0x7ff800000000
            cursor += align(mapping['slide_info']['size'], 8)
    require(cursor == slide_offset + slide_bytes, 'v2 slide allocation arithmetic differs')
    require(mappings[-1]['slide_info'] is None, 'LINKEDIT pointer chains need iterative geometry')
    require(mappings[-1]['maximum'] == 1, 'slide metadata needs a final read-only mapping')
    code_limit = align(offset + slide_bytes, 16384)
    tail = code_limit - offset
    mappings[-1]['size'] += tail
    signature_size = geometry(code_limit, identifier)[3]
    return {'prefix_size': prefix, 'cache_header_size': header_size, 'mapping_offset': header_size,
            'mapping_count': count, 'slide_mapping_offset': header_size + count * 32,
            'table_end': table_end, 'provider_header_file_offset': prefix,
            'image_tables': {'count': image_count, 'images_offset': images_offset,
                'images_text_offset': image_text_offset, 'subcache_array_offset': string_pool_offset,
                'subcache_array_count': 0, 'tpro_mappings_offset': string_pool_offset, 'tpro_mappings_count': 0,
                'string_pool_offset': string_pool_offset, 'string_pool_size': pool_end-string_pool_offset,
                'path_offsets': path_offsets, 'used_end': pool_end},
            'mappings': mappings, 'segments': segments, 'slide_info_start': slide_offset,
            'slide_info_bytes': slide_bytes, 'last_mapping_metadata_and_padding': tail,
            'signature': {'offset': code_limit, 'size': signature_size, 'identifier': identifier,
                          'file_size': code_limit + signature_size,
                          'exec_segment_base': 0, 'exec_segment_limit': mappings[0]['size']}}


def place_uniform(image, geometry_, occupied, low, high, max_slide=0):
    require(low % PAGE == high % PAGE == 0 and low < high, 'invalid placement interval')
    require(all(lo < hi for lo, hi, _ in occupied), 'invalid occupied interval')
    anchor = align(low + geometry_['prefix_size'])
    mappings = geometry_['mappings']
    attempts = 0
    while True:
        attempts += 1
        require(attempts <= 100000, 'placement search expansion limit')
        starts = [(anchor + m['relative_address'], anchor + m['relative_address'] + m['size']) for m in mappings]
        require(all(lo >= low and hi + max_slide <= high for lo, hi in starts), 'uniform image placement exceeds shared region')
        collision = None
        for (lo, hi), mapping in zip(starts, mappings):
            hits = [(a, b, name) for a, b, name in occupied if lo < b and a < hi]
            if hits:
                a, b, name = min(hits)
                collision = b - mapping['relative_address']
                break
        if collision is None:
            break
        require(collision > anchor, 'placement search failed to advance')
        anchor = align(collision)
    slide = anchor - image.base
    require(-(1 << 63) <= slide < (1 << 63), 'uniform slide exceeds signed 64-bit range')
    placed = []
    for mapping, (lo, hi) in zip(mappings, starts):
        placed.append(dict(mapping, address=lo))
    require(all(a['address'] + a['size'] <= b['address'] for a, b in zip(placed, placed[1:])),
            'new cache VM mappings overlap')
    return {'uniform_slide': slide, 'provider_header_address': anchor,
            'cache_header_address': anchor - geometry_['prefix_size'], 'attempts': attempts,
            'mappings': placed, 'split_validation': split_constraints(image, [slide] * len(image.segments))}


def image_features(image, slide):
    source_flags = struct.unpack_from('<I', image.data, 24)[0]
    initializers, tlvs, nonlazy = [], [], []
    for section in image.sections:
        kind = section['flags'] & 255
        if kind in (17, 18, 19, 20, 21):
            tlvs.append(section)
        if section['name'] in ('__objc_nlclslist', '__objc_nlcatlist'):
            nonlazy.append(section)
        if kind == 22:
            require(section['size'] % 4 == 0, 'initializer offset table is unaligned')
            for offset in range(0, section['size'], 4):
                field = section['address'] + offset
                value = struct.unpack_from('<I', image.data, image.file_offset(field, 4))[0]
                target = image.base + value
                require(image.segment(target).initial & 4, 'initializer offset does not target code')
                initializers.append({'kind': 'image_relative_uint32', 'source_field': field,
                    'new_field': field + slide, 'offset': value, 'source_target': target, 'target': target + slide})
        elif kind in (9, 10):
            require(section['size'] % 8 == 0, 'initializer pointer table is unaligned')
            for field in range(section['address'], section['address'] + section['size'], 8):
                require(field in image.rebases or field in image.reader.binds,
                        'initializer pointer absent from fixup inventory')
                initializers.append({'kind': 'pointer_init' if kind == 9 else 'pointer_term',
                                     'source_field': field, 'new_field': field + slide})
    require(bool(source_flags & 0x800000) == bool(tlvs), 'Mach-O TLV flag and section presence differ')
    return {'source_macho_flags': source_flags, 'cached_macho_flags': source_flags | 0x80000000,
            'has_tlv_descriptors': bool(source_flags & 0x800000), 'tlv_sections': tlvs,
            'nonlazy_objc_sections': nonlazy, 'initializers': initializers,
            'requirements': ['Preserve all existing Mach-O feature flags and set MH_DYLIB_IN_CACHE.',
                'Preserve image-relative initializer offsets; include initializer ordering in regenerated loader records.',
                'If TLV inputs are introduced, perform checked cache TLV key/thunk optimization; current ten inputs have none.']}


def pack_fixups(plan):
    """Lossless compact writer schema; column names travel with numeric rows."""
    rebases, binds, catalog, keys = [], [], [], {}
    for row in plan.pop('pointer_fixups'):
        common = [row['source_file_offset'], row['file_offset'], row['address'], row['mapping_index']]
        if row['kind'] == 'rebase':
            rebases.append(common + [row['source_target'], row['target']])
        else:
            value = {k: v for k, v in row.items() if k in ('binding', 'resolution', 'target', 'target_policy', 'interpose')}
            key = json.dumps(value, sort_keys=True, separators=(',', ':'))
            if key not in keys:
                keys[key] = len(catalog); catalog.append(value)
            binds.append(common + [keys[key]])
    plan['pointer_fixups'] = {
        'rebase_columns': ['source_file_offset', 'file_offset', 'address', 'mapping_index', 'source_target', 'target'],
        'rebase_rows': rebases,
        'bind_columns': ['source_file_offset', 'file_offset', 'address', 'mapping_index', 'binding_index'],
        'bind_rows': binds, 'bindings': catalog,
        'source_address_formula': 'address - placement.uniform_slide'}


def provider_plan(image, geometry_, placement, suffix):
    slide = placement['uniform_slide']
    segments = []
    for segment in geometry_['segments']:
        original = segment['source']
        segments.append(dict(segment, new_address=original['address'] + slide,
                             sections=[dict(section, new_address=section['address'] + slide,
                                 new_offset=segment['new_file_offset'] + section['address'] - original['address']
                                 if section['flags'] & 255 not in (1, 12, 18) else 0)
                                 for section in image.sections if section['segment'] == original['index']]))
    fixes = []
    for field in image.fixup_fields:
        segment = image.segment(field, 8)
        mapping = geometry_['mappings'][segment.index]
        row = {'source_address': field, 'source_file_offset': image.file_offset(field, 8),
               'address': field + slide, 'file_offset': geometry_['segments'][segment.index]['new_file_offset'] + field - segment.address,
               'mapping_index': segment.index}
        if field in image.rebases:
            target = image.rebases[field]
            final = target + slide if target else 0
            require(not ((final - 0x7ff800000000) & ((1 << 64) - 1)) & DELTA_MASK if final else True,
                    'rebase target not representable with pinned v2 value_add/mask')
            row.update({'kind': 'rebase', 'source_target': target, 'target': final})
        else:
            row.update({'kind': 'bind', 'binding': image.reader.binds[field],
                        'target_status': 'OPEN: resolve through final provider graph before signature emission'})
        fixes.append(row)
    return {'key': image.key, 'path': image.canonical, 'new_subcache_suffix': suffix,
            'input_sha256': sha(image.data), 'slice_offset': image.container_offset,
            'input_size': len(image.data), 'original_vm_span': image.segments[-1].address + image.segments[-1].size - image.base,
            'relocation_policy': 'uniform VM slide for every segment; file offsets rewritten independently',
            'independent_relayout_metadata': image.split['format'],
            'split_reference_counts': dict(Counter(str(e['kind']) for e in image.split['entries'])),
            'features': image_features(image, slide), 'import_inventory': image.import_info, 'linkedit_payloads': image.linkedit,
            'interpose': [dict(t, new_field=t['field'] + slide, replacement_target=t['replacement'] + slide)
                          for t in image.interpose],
            'geometry': geometry_, 'placement': placement, 'segments': segments, 'pointer_fixups': fixes,
            'slide_value_add': 0x7ff800000000,
            'writer_requirements': ['Rewrite Mach-O segment/section VM addresses, cache-file offsets, defined nlist values and LINKEDIT commands.',
                'Remove standalone signature/split/chained commands using checked builder rules; do not carry stale standalone signature trust.',
                'Apply every rebase/bind, then ObjC/Swift metadata transformations and affected lookup tables.',
                'Build v2 chain words for recorded fields and any fields introduced by metadata transformations; recompute geometry if field set changes.',
                'Allocate v2 blocks in final LINKEDIT mapping and regenerate whole-file signatures after final cache UUIDs/header bytes.',
                'Preserve all old VM mappings and bytes, including classes physically co-located with replaced images.']}
