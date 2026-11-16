"""Read-only ObjC category-transfer planner; never emits or mutates cache bytes.

Addresses in source entries are pinned cache VAs. Destination addresses are
input-image VAs and MUST be relocated by a final writer. Image indexes in list
lists are ObjC header-info indexes, not cache image/PBL indexes.
"""
import struct
from .cache import commands
from .exports import Refusal, cstring, read_image, require, resolve, span, uleb

KINDS = (('instanceMethods', 16, False, 32), ('classMethods', 24, True, 32),
         ('protocols', 32, False, 40), ('instanceProperties', 40, False, 64),
         ('classProperties', 48, True, 64))


def sections(command_rows):
    result = []
    for _, cmd, data in command_rows:
        if cmd != 0x19:
            continue
        count = struct.unpack_from('<I', data, 64)[0]
        require(len(data) == 72 + count * 80, 'section command size mismatch')
        for i in range(count):
            row = span(data, 72 + i * 80, 80)
            name = row[:16].split(b'\0')[0].decode('ascii')
            seg = row[16:32].split(b'\0')[0].decode('ascii')
            address, size = struct.unpack_from('<QQ', row, 32)
            result.append((seg, name, address, size))
    return result


class Reader:
    selector_base = None
    def number(self, address, fmt='<Q'):
        return struct.unpack(fmt, self.read(address, struct.calcsize(fmt)))[0]

    def string(self, address):
        require(address != 0, 'null string')
        value = bytearray()
        for i in range(65536):
            byte = self.read(address + i, 1)
            if byte == b'\0':
                try:
                    return value.decode('utf-8')
                except UnicodeDecodeError as exc:
                    raise Refusal('non-UTF8 ObjC string') from exc
            value += byte
        raise Refusal('ObjC string exceeds limit')

    def lists(self, value):
        if not value:
            return []
        if not value & 1:
            return [{'address': value, 'image_index': None}]
        address = value & ~1
        size, count = struct.unpack('<II', self.read(address, 8))
        require(size == 8 and 0 < count <= 65535, 'invalid relative list-list header')
        result = []
        for i in range(count):
            field = address + 8 + 8 * i
            raw = self.number(field)
            delta = raw >> 16
            if delta & (1 << 47):
                delta -= 1 << 48
            target = field + delta
            self.read(target, 8)
            result.append({'address': target, 'image_index': raw & 65535})
        require(len({r['address'] for r in result}) == len(result), 'duplicate relative list attachment')
        return result

    def methods(self, address):
        flags, count = struct.unpack('<II', self.read(address, 8))
        small = bool(flags & 0x80000000)
        stride = flags & 0xfffc
        require(count <= 100000 and stride == (12 if small else 24), 'unsupported method list layout')
        # 0x20000000 methodListUsesTypeOffsets (dyld-1378 ObjCVisitor.h): types are u32 offsets from the selector base
        # (the method-types buffer follows the selectors). 26B131's cache sets it on its small lists.
        type_offsets = bool(flags & 0x20000000)
        require(flags & ~0xe000ffff == 0, f'unknown method-list flags {flags:#x} at {address:#x}')
        require(not flags & 0x40000000 or small, 'direct selector flag on big method list')
        require(not type_offsets or (small and self.selector_base is not None), 'type offsets outside a cache small list')
        self.read(address + 8, stride * count)
        rows = []
        for i in range(count):
            entry = address + 8 + i * stride
            if small:
                sel, types, imp = struct.unpack('<iii', self.read(entry, 12))
                if self.selector_base is not None:
                    require(flags & 0x40000000, 'cached relative selectors lack direct flag')
                    sel = self.selector_base + (sel & 0xffffffff)
                else:
                    # Shipping runtime chooses directness by shared-cache range;
                    # extracted WiFiOld retains 0x40000000 but uses selrefs.
                    sel = self.ptr(entry + sel)
                types = self.selector_base + (types & 0xffffffff) if type_offsets else entry + 4 + types
                imp = entry + 8 + imp
            else:
                sel, types, imp = [self.ptr(entry + j) for j in (0, 8, 16)]
            rows.append({'selector': self.string(sel), 'types': self.string(types), 'imp': hex(imp)})
        return {'address': hex(address), 'flags': hex(flags), 'entries': rows}

    def properties(self, address):
        stride, count = struct.unpack('<II', self.read(address, 8))
        require(stride == 16 and count <= 100000, 'unsupported property list')
        self.read(address + 8, count * stride)
        return {'address': hex(address), 'entries': [
            {'name': self.string(self.ptr(address + 8 + i * 16)),
             'attributes': self.string(self.ptr(address + 16 + i * 16))} for i in range(count)]}

    def protocols(self, address):
        count = self.number(address)
        require(count <= 100000, 'protocol count exceeds limit')
        self.read(address + 8, count * 8)
        entries = []
        for i in range(count):
            field = address + 8 + i * 8
            ref = self.reference(field)
            if 'symbol' in ref:
                require(ref['symbol'].startswith('_OBJC_PROTOCOL_$_') and ref['addend'] == 0,
                        'non-protocol symbol in protocol list')
                entries.append({'name': ref['symbol'][len('_OBJC_PROTOCOL_$_'):], 'binding': ref})
            else:
                entries.append({'name': self.string(self.ptr(self.ptr(field) + 8))})
        return {'address': hex(address), 'entries': entries}

    def contents(self, kind, address):
        return (self.methods if kind.endswith('Methods') else
                self.protocols if kind == 'protocols' else self.properties)(address)

    def class_info(self, address):
        ro_bits = self.ptr(address + 32)
        ro = ro_bits & ~7
        flags, start, size, reserved = struct.unpack('<IIII', self.read(ro, 16))
        require(reserved == 0, 'class_ro reserved is nonzero')
        result = {'address': hex(address), 'isa': self.reference(address),
                  'superclass': self.reference(address + 8),
                  'ro_address': hex(ro), 'ro_flags': hex(flags), 'data_flags': ro_bits & 7,
                  'instance_start': start, 'instance_size': size,
                  'name': self.string(self.ptr(ro + 24)),
                  'cache_words': [hex(self.number(address + j)) for j in (16, 24)],
                  'base_lists': {}}
        for kind, _, meta, offset in KINDS:
            if meta:
                continue
            result['base_lists'][kind] = [dict(entry, content=self.contents(kind, entry['address']))
                                          for entry in self.lists(self.ptr(ro + offset))]
        ivars = self.ptr(ro + 48)
        result['ivars'] = []
        result['ivar_offset_storage'] = {}
        if ivars:
            stride, count = struct.unpack('<II', self.read(ivars, 8))
            require(stride == 32 and count <= 100000, 'unsupported ivar list')
            for i in range(count):
                field = ivars + 8 + stride * i
                alignment, length = struct.unpack('<II', self.read(field + 24, 8))
                ivar_name = self.string(self.ptr(field + 8))
                result['ivar_offset_storage'][ivar_name] = hex(self.ptr(field))
                result['ivars'].append({'name': ivar_name,
                    'types': self.string(self.ptr(field + 16)),
                    'offset': self.number(self.ptr(field), '<I'), 'size': length, 'alignment': alignment})
        return result

    def reference(self, address):
        return {'address': hex(self.ptr(address))}


class CachedReader(Reader):
    def __init__(self, family):
        self.family = family
        self.slides = []
        for file in family.files:
            for i, mapping in enumerate(file.mappings):
                off, size = struct.unpack_from('<QQ', file.data, file.slide_offset + i * 56 + 24)
                if not size:
                    continue
                header = span(file.data, off, 40)
                require(struct.unpack_from('<I', header)[0] == 2, 'only slide v2 supported')
                mask, add = struct.unpack_from('<QQ', header, 24)
                self.slides.append((mapping.address, mapping.address + mapping.size, mask, add))
        base = family.main.mappings[0].address
        from .objc_tables import objc_header
        self.opts = objc_header(family)[0]
        self.selector_base = base + self.number(self.opts + 48)
        hinfo = base + self.number(self.opts + 8)
        count, stride = struct.unpack('<II', self.read(hinfo, 8))
        require(0 < count < 65536 and stride in (16, 24), 'unsupported ObjC header-info array')
        images = {a: p for p, a in family.images}
        self.objc_images = {}
        for i in range(count):
            field = hinfo + 8 + i * stride
            mh = field + self.number(field, '<q')
            require(mh in images, 'ObjC header index does not identify a cache image')
            self.objc_images[i] = images[mh]

    def read(self, address, size):
        return self.family.read(address, size)

    def ptr(self, address):
        raw = self.number(address)
        for lo, hi, mask, add in self.slides:
            if lo <= address < hi:
                raw &= ~mask
                return raw + add if raw else 0
        return raw


def sleb(data, offset):
    value = 0
    for shift in range(0, 70, 7):
        byte = span(data, offset, 1)[0]
        offset += 1
        value |= (byte & 127) << shift
        if not byte & 128:
            if byte & 64:
                value -= 1 << (shift + 7)
            require(-(1 << 63) <= value < (1 << 63), 'SLEB128 overflow')
            return value, offset
    raise Refusal('SLEB128 overflow')


class DiskReader(Reader):
    def __init__(self, data, *, bundle_path=None):
        self.data = data
        self.image = read_image(data,bundle_path=bundle_path)
        require(data[:4] == b'\xcf\xfa\xed\xfe', 'planner requires pinned thin x86_64 image')
        count, size = struct.unpack_from('<II', data, 16)
        body = span(data, 32, size)
        rows, self.segments = [], []
        position = 0
        self.binds, self.rebases = {}, {}
        streams, chained, weak_streams = [], [], []
        for _ in range(count):
            cmd, length = struct.unpack_from('<II', body, position)
            row = span(body, position, length)
            rows.append((32 + position, cmd, row))
            if cmd == 0x19:
                self.segments.append(struct.unpack_from('<QQQQ', row, 24))
            if cmd in (0x22, 0x80000022):
                start, length_ = struct.unpack_from('<II', row, 24)
                if length_: weak_streams.append(span(data, start, length_))
                for off in (16, 32):
                    start, length_ = struct.unpack_from('<II', row, off)
                    if length_:
                        streams.append(span(data, start, length_))
            if cmd == 0x80000034:
                chained.append(span(data, *struct.unpack_from('<II', row, 8)))
            position += length
        self.sections = sections(rows)
        bases = [a for a, _, f, n in self.segments if f == 0 and n >= 32]
        require(len(bases) == 1, 'ambiguous disk image base')
        self.base = bases[0]
        require(len(chained) <= 1 and not (chained and (streams or weak_streams)), 'conflicting fixup formats')
        for stream in streams:
            self._bind_stream(stream)
        for payload in chained:
            self._chained(payload)
        self.weak_bind_fields = set()
        for stream in weak_streams:
            self._weak_bind_stream(stream)

    def _weak_bind_stream(self, stream):
        from .imports import classic_imports
        rows, definitions = classic_imports(stream,self.image,self.segments,'weak')
        for row in rows:
            require(row.bind_type == 1 and row.ordinal == -3, 'unsupported weak coalescing bind')
            previous = self.binds.get(row.address)
            if previous is not None:
                require(previous['symbol'] == row.symbol and previous['addend'] == row.addend,
                        'weak coalescing disagrees with original binding')
            binding = dict(symbol=row.symbol,provider=row.provider,addend=row.addend,weak_import=row.weak)
            require(row.address not in self.weak_bind_fields or previous == binding,
                    'conflicting duplicate weak coalescing field')
            self.binds[row.address] = binding
            self.weak_bind_fields.add(row.address)

    def read(self, address, size):
        for vm, _, off, length in self.segments:
            if vm <= address and address + size <= vm + length:
                return span(self.data, off + address - vm, size)
        raise Refusal(f'unmapped disk image address: {address:#x}+{size:#x}')

    def ptr(self, address):
        if address in self.binds:
            binding = self.binds[address]
            export = self.image.exports.get(binding['symbol'])
            require(binding['provider'] == self.image.install_name and export is not None and export.flags == 0,
                    f'bound pointer requires symbolic handling: {address:#x}: {binding}')
            return self.base + export.value + binding['addend']
        return self.rebases.get(address, self.number(address))

    def reference(self, address):
        if address in self.binds:
            result = dict(self.binds[address])
            if result['provider'] == self.image.install_name:
                exp = self.image.exports.get(result['symbol'])
                if exp and exp.flags == 0:
                    result['address'] = hex(self.base + exp.value + result['addend'])
            return result
        value = self.ptr(address)
        return {'address': hex(value)}

    def bind_provider(self, ordinal):
        if ordinal in (0, -1, -2, -3):
            return {0: self.image.install_name, -1: 'SPECIAL:main-executable',
                    -2: 'SPECIAL:flat-lookup', -3: 'SPECIAL:weak-lookup'}[ordinal]
        require(1 <= ordinal <= len(self.image.dependencies), 'invalid bind ordinal')
        return self.image.dependencies[ordinal - 1].path

    def _chained(self, data):
        from .imports import chained_imports
        version, starts, imports, symbols, count, fmt, symfmt = struct.unpack('<7I', span(data, 0, 28))
        imported = [dict(symbol=row.symbol, provider=row.provider, weak_import=row.weak, addend=row.addend)
                    for row in chained_imports(data, self.image)]
        segcount = struct.unpack('<I', span(data, starts, 4))[0]
        require(segcount == len(self.segments), 'chained segment count mismatch')
        offsets = struct.unpack('<' + 'I' * segcount, span(data, starts + 4, 4 * segcount))
        for index, offset in enumerate(offsets):
            if not offset:
                continue
            row = starts + offset
            size, page_size, pointer_format, segment_offset, max_valid, pages = struct.unpack(
                '<IHHQIH', span(data, row, 22))
            require(pointer_format in (2, 6) and page_size in (4096, 16384) and max_valid == 0,
                    'unsupported chained pointer/page schema')
            span(data, row, size)
            require(size >= 22 + 2 * pages, 'truncated chained page starts')
            vm, vmsize, _, _ = self.segments[index]
            require(self.base + segment_offset == vm and pages * page_size <= vmsize,
                    'chained segment extent mismatch')
            for page in range(pages):
                start = struct.unpack('<H', span(data, row + 22 + page * 2, 2))[0]
                if start == 65535:
                    continue
                require(start < page_size and not start & 0x8000, 'multi-start/outside-page chain unsupported')
                field = vm + page * page_size + start
                limit = vm + (page + 1) * page_size
                while True:
                    require(field + 8 <= limit and field not in self.binds and field not in self.rebases,
                            'chained pointer outside page or duplicate')
                    word = self.number(field)
                    if word >> 63:
                        require(not ((word >> 32) & 0x7ffff), 'nonzero chained bind reserved bits')
                        ordinal = word & 0xffffff
                        require(ordinal < len(imported), 'chained bind import ordinal out of range')
                        self.binds[field] = dict(imported[ordinal], addend=imported[ordinal]['addend'] + ((word >> 24) & 255))
                    else:
                        require(not ((word >> 44) & 127), 'nonzero chained rebase reserved bits')
                        target = word & ((1 << 36) - 1)
                        high = (word >> 36) & 255
                        # PTR_64 stores an unslid VM address; PTR_64_OFFSET stores
                        # an image-relative target. Both retain the high byte.
                        self.rebases[field] = (target + (self.base if pointer_format == 6 else 0)) | (high << 56)
                    delta = ((word >> 51) & 4095) * 4
                    if not delta:
                        break
                    require(delta >= 8, 'overlapping chained pointer')
                    field += delta

    def _bind_stream(self, data):
        pos, ordinal, symbol, addend, bindtype, location, weak = 0, None, None, 0, 1, None, False
        def bind():
            nonlocal location
            require(bindtype == 1 and location is not None and symbol and ordinal is not None,
                    'incomplete/unsupported binding state')
            self.read(location, 8)
            binding = {'symbol': symbol, 'provider': self.bind_provider(ordinal),
                       'addend': addend, 'weak_import': weak}
            require(location not in self.binds or self.binds[location] == binding, 'conflicting duplicate bind location')
            self.binds[location] = binding
            location = (location + 8) & ((1 << 64)-1)
        while pos < len(data):
            byte = data[pos]; pos += 1
            op, imm = byte & 240, byte & 15
            if op == 0:
                ordinal, symbol, addend, bindtype, location, weak = None, None, 0, 1, None, False
            elif op == 0x10: ordinal = imm
            elif op == 0x20: ordinal, pos = uleb(data, pos)
            elif op == 0x30: ordinal = imm - 16 if imm else 0
            elif op == 0x40:
                require(not imm & ~1, 'unknown bind symbol flags')
                symbol, pos = cstring(data, pos)
                weak = bool(imm & 1)
            elif op == 0x50: bindtype = imm
            elif op == 0x60: addend, pos = sleb(data, pos)
            elif op == 0x70:
                require(imm < len(self.segments), 'bad bind segment ordinal')
                delta, pos = uleb(data, pos); location = self.segments[imm][0] + delta
            elif op == 0x80:
                delta, pos = uleb(data, pos)
                require(location is not None, 'bind address advance before segment'); location = (location + delta) & ((1 << 64)-1)
            elif op == 0x90: bind()
            elif op == 0xa0:
                bind(); delta, pos = uleb(data, pos); location = (location + delta) & ((1 << 64)-1)
            elif op == 0xb0: bind(); location = (location + imm * 8) & ((1 << 64)-1)
            elif op == 0xc0:
                count, pos = uleb(data, pos); skip, pos = uleb(data, pos)
                require(count <= 1000000, 'bind repeat limit')
                for _ in range(count): bind(); location = (location + skip) & ((1 << 64)-1)
            else: raise Refusal(f'unsupported bind opcode {op:#x}')


def transfer_entries(source, incoming, destination, destination_index, label=''):
    """Retain exact source precedence and conditional image identity.

    Incoming entries must each occur once. Replace precisely the source owner's
    base entry with the replacement base; never concatenate it per category.
    """
    require(len(incoming) == len(set(incoming)), 'duplicate incoming category list')
    addresses = [entry['address'] for entry in source]
    require(len(addresses) == len(set(addresses)), 'duplicate source attached list')
    require(all(addresses.count(a) == 1 for a in incoming), 'incoming list absent or duplicated')
    base = [entry for entry in source if entry['address'] not in incoming]
    require(len(base) == 1, 'source base is not exactly one list')
    # 0 base lists: the replacement class has none of this kind (26B131: OCLP's WiFiPeerToPeer WiFiAwareDatapathInfo has
    # no instance methods; a category from another cache image attaches to it). The result is then the categories only.
    require(len(destination) <= 1, 'replacement must provide at most one base list' + (': ' + label if label else ''))
    result = []
    for entry in source:
        if entry['address'] in incoming:
            result.append(dict(entry, origin='preserved_category'))
        elif destination:
            result.append(dict(destination[0], image_index=destination_index, origin='replacement_base'))
    require(sum(r['origin'] == 'preserved_category' for r in result) == len(incoming), 'lost incoming list')
    return result


def project_ivar_growth(info, final_superclass_size):
    """Mirror pinned dyld's superclass-growth adjustment for ordinary ObjC.

    No shrinking: existing child layout can contain padding after a smaller
    superclass. Swift elision requires a separate checked transformation.
    """
    require(0 <= final_superclass_size < 2**32, 'superclass size overflow')
    delta = max(0, final_superclass_size - info['instance_start'])
    # A Swift class (data flags 1/2) is left as it is when its superclass does not grow; growing one needs its own plan.
    require(not (info['data_flags'] & 3 and delta), 'Swift ivar elision requires a separate plan'
            + (f": {info.get('name', '?')} grows by {delta}" if delta else ''))
    alignments = [8 if x['alignment'] == 0xffffffff else 1 << x['alignment']
                  for x in info['ivars'] if x['alignment'] == 0xffffffff or x['alignment'] <= 31]
    require(len(alignments) == len(info['ivars']), 'invalid ivar alignment')
    alignment = max([1] + alignments)
    delta = (delta + alignment - 1) & ~(alignment - 1)
    require(info['instance_size'] + delta < 2**32, 'grown instance size overflow')
    return {'delta': delta, 'instance_start': info['instance_start'] + delta,
            'instance_size': info['instance_size'] + delta,
            'ivar_offsets': {x['name']: x['offset'] + delta for x in info['ivars']}}


def inspect(family, providers, provider_readers, targets):
    source = CachedReader(family)
    inventory = []
    image_sections = {}
    target_classes = {}
    for path, mh in family.images:
        rows = commands(family, mh)
        secs = sections(rows)
        image_sections[path] = secs
        if path in targets:
            for _, name, address, size in secs:
                if name == '__objc_classlist':
                    require(size % 8 == 0, 'unaligned classlist')
                    for field in range(address, address + size, 8):
                        cls = source.ptr(field)
                        target_classes[cls] = path
                        target_classes[source.ptr(cls)] = path
    def owner(address):
        # ObjC class data is physically co-located across images. Classlist
        # ownership, not segment containment, defines the semantic provider.
        return target_classes.get(address)
    scanned = 0
    for path, secs in image_sections.items():
        if path in targets:
            continue
        for _, name, address, size in secs:
            if name not in ('__objc_catlist', '__objc_nlcatlist'):
                continue
            require(size % 8 == 0, 'unaligned category list')
            for field in range(address, address + size, 8):
                scanned += 1
                cat = source.ptr(field); cls = source.ptr(cat + 8)
                target = owner(cls)
                if not target or path in targets:
                    continue
                info = source.class_info(cls)
                category = {'target_image': target, 'image': path, 'category_address': hex(cat),
                    'category_pointer_field': hex(field), 'category': source.string(source.ptr(cat)),
                    'class': info['name'], 'class_address': hex(cls), 'lists': []}
                for kind, offset, meta, ro_off in KINDS:
                    attached = source.ptr(cat + offset)
                    if not attached:
                        continue
                    target_cls = source.ptr(cls) if meta else cls
                    ro = source.ptr(target_cls + 32) & ~7
                    entries = source.lists(source.ptr(ro + ro_off))
                    require(sum(e['address'] == attached for e in entries) == 1, 'incoming category not attached exactly once')
                    for entry in entries:
                        require(entry['image_index'] in source.objc_images, 'missing ObjC image index')
                    cat_entry = next(e for e in entries if e['address'] == attached)
                    require(source.objc_images[cat_entry['image_index']] == path, 'category owner index mismatch')
                    category['lists'].append({'kind': kind, 'address': attached, 'source_entries': entries,
                                               'content': source.contents(kind, attached)})
                inventory.append(category)
    groups = {}
    for row in inventory:
        groups.setdefault((row['target_image'], row['class']), []).append(row)
    plans = []
    supplemental_categories = []
    for provider, reader in provider_readers.items():
        for _, section, address, size in reader.sections:
            if section not in ('__objc_catlist', '__objc_nlcatlist'):
                continue
            require(size % 8 == 0, 'unaligned replacement category section')
            for field in range(address, address + size, 8):
                cat = reader.ptr(field)
                ref = reader.reference(cat + 8)
                for (target, name) in groups:
                    if ref.get('symbol') != '_OBJC_CLASS_$_' + name:
                        continue
                    supplemental_categories.append({'image': provider, 'class': name,
                        'category': reader.string(reader.ptr(cat)), 'category_address': hex(cat),
                        'class_reference': ref, 'lists': [
                            {'kind': kind, 'address': reader.ptr(cat + offset),
                             'content': reader.contents(kind, reader.ptr(cat + offset))}
                            for kind, offset, _, _ in KINDS if reader.ptr(cat + offset)]})
    for (target, name), cats in groups.items():
        resolution = resolve(providers, target, '_OBJC_CLASS_$_' + name)
        require(resolution['status'] == 'resolved', f'missing replacement class: {name}')
        dest_reader = provider_readers[resolution['provider']]
        cls = dest_reader.base + int(resolution['input_offset'], 16)
        dest = dest_reader.class_info(cls)
        require(dest['name'] == name, 'replacement class export/name mismatch')
        original = source.class_info(int(cats[0]['class_address'], 16))
        old_meta = source.class_info(int(original['isa']['address'], 16))
        new_meta = dest_reader.class_info(int(dest['isa']['address'], 16))
        supplements = [c for c in supplemental_categories if c['class'] == name]
        plan = {'class': name, 'new_provider_categories': supplements, 'source_image': target, 'destination_provider': resolution['provider'],
                'destination_identity': 'new ObjC header-info index for ' + resolution['provider'],
                'source': original, 'source_metaclass': old_meta, 'replacement': dest,
                'replacement_metaclass': new_meta, 'transfers': []}
        for kind, _, is_meta, _ in KINDS:
            lists = [item for cat in cats for item in cat['lists'] if item['kind'] == kind]
            if not lists:
                continue
            source_entries = lists[0]['source_entries']
            require(all(item['source_entries'] == source_entries for item in lists), 'inconsistent attached list views')
            dest_info = new_meta if is_meta else dest
            dest_kind = 'instanceMethods' if kind == 'classMethods' else 'instanceProperties' if kind == 'classProperties' else kind
            dest_entries = [{k: v for k, v in e.items() if k != 'content'}
                            for e in dest_info['base_lists'][dest_kind]]
            entries = transfer_entries(source_entries, [item['address'] for item in lists],
                                       dest_entries, 'NEW:' + resolution['provider'],
                                       label=f"{name} {kind} (source {target}, replacement {resolution['provider']}, {len(dest_entries)} base lists)")
            extras = []
            for supplement in supplements:
                for extra in supplement['lists']:
                    if extra['kind'] != kind:
                        continue
                    if kind.endswith('Methods'):
                        selectors = {e['selector'] for e in extra['content']['entries']}
                        incoming_selectors = {e['selector'] for item in lists for e in item['content']['entries']}
                        require(not selectors & incoming_selectors, 'new provider category conflicts with preserved category precedence')
                    extras.append({'address': extra['address'], 'image_index': 'NEW:' + supplement['image'],
                                   'origin': 'new_provider_category', 'image': supplement['image']})
            base_positions = [i for i, e in enumerate(entries) if e['origin'] == 'replacement_base']
            require(len(base_positions) == 1 or not extras, 'new category without replacement base anchor')
            if extras:
                entries[base_positions[0]:base_positions[0]] = extras
            for entry in entries:
                if entry['origin'] == 'preserved_category':
                    entry['image'] = source.objc_images[entry['image_index']]
                elif entry['origin'] == 'replacement_base':
                    entry['image'] = resolution['provider']
            plan['transfers'].append({'kind': kind, 'entries_in_lookup_order': entries,
                'incoming_lists': [{'address': hex(item['address']), 'content': item['content']} for item in lists]})
        old_ivars = {x['name']: x for x in original['ivars']}
        new_ivars = {x['name']: x for x in dest['ivars']}
        plan['layout_comparison'] = {'source_size': original['instance_size'], 'replacement_size': dest['instance_size'],
            'removed_ivars': sorted(old_ivars.keys() - new_ivars.keys()),
            'added_ivars': sorted(new_ivars.keys() - old_ivars.keys()),
            'changed_ivars': [{'source': old_ivars[n], 'replacement': new_ivars[n]}
                              for n in sorted(old_ivars.keys() & new_ivars.keys()) if old_ivars[n] != new_ivars[n]]}
        superclass = source.class_info(int(original['superclass']['address'], 16))
        dest_super = dest['superclass']
        require(dest_super.get('symbol') == '_OBJC_CLASS_$_' + superclass['name'],
                'replacement superclass identity differs from source')
        super_size = superclass['instance_size']
        super_size_basis = 'unchanged cached superclass'
        if dest_super['provider'] in provider_readers:
            super_reader = provider_readers[dest_super['provider']]
            require('address' in dest_super, 'internal superclass missing resolved address')
            replacement_super = super_reader.class_info(int(dest_super['address'], 16))
            require(replacement_super['instance_start'] == superclass['instance_start'] and
                    replacement_super['instance_size'] == superclass['instance_size'],
                    'changed replacement superclass needs recursive whole-graph layout plan')
            super_size_basis = 'replacement superclass layout matches source; whole-graph recursion still required'
        plan['superclass_layout'] = {'source_name': superclass['name'],
            'source_address': superclass['address'], 'source_instance_size': superclass['instance_size'],
            'source_ivars': superclass['ivars'], 'source_ivar_offset_storage': superclass['ivar_offset_storage'],
            'replacement_reference': dest_super, 'size_basis': super_size_basis,
            'projected_replacement_layout': project_ivar_growth(dest, super_size)}
        plans.append(plan)
    references = []
    for path, secs in image_sections.items():
        if path in targets:
            continue
        for _, name, address, size in secs:
            if name in ('__objc_classrefs', '__objc_superrefs', '__objc_classlist', '__objc_nlclslist'):
                require(size % 8 == 0, 'unaligned ObjC references')
                for field in range(address, address + size, 8):
                    value = source.ptr(field)
                    if value in target_classes:
                        references.append({'image': path, 'kind': name, 'field': hex(field), 'target': hex(value)})
                    if name in ('__objc_classlist', '__objc_nlclslist'):
                        for candidate, role in ((value, 'class'), (source.ptr(value), 'metaclass')):
                            for delta, relation in ((0, 'isa'), (8, 'superclass')):
                                dest = source.ptr(candidate + delta)
                                if dest in target_classes:
                                    references.append({'image': path, 'kind': role + '.' + relation,
                                                       'field': hex(candidate + delta), 'target': hex(dest)})
    requested = {'_MTLCommandBuffer': ['_privateData', '_privateDataOffset', '_requiresBindingLogState'],
                 '_MTLCommandQueue': ['_privateDataTable'], '_MTL4CommandBuffer': ['_labelTraceID']}
    ivar_audit = []
    for provider, reader in provider_readers.items():
        if '/Metal.framework/' not in provider:
            continue
        classes = {}
        for _, section, address, size in reader.sections:
            if section == '__objc_classlist':
                for field in range(address, address + size, 8):
                    cls = reader.ptr(field)
                    ro = reader.ptr(cls + 32) & ~7
                    classes[reader.string(reader.ptr(ro + 24))] = cls
        for name, fields in requested.items():
            found = reader.class_info(classes[name]) if name in classes else None
            ivar_audit.append({'provider': provider, 'class': name, 'classlist_count': len(classes),
                'class_metadata': found, 'requested_fields': {field: next(
                    (v for v in found['ivars'] if v['name'] == field), None) if found else None for field in fields}})
    for ref in references:
        cls = int(ref['target'], 16)
        ro = source.ptr(cls + 32) & ~7
        name = source.string(source.ptr(ro + 24))
        flags, start, size = struct.unpack('<III', source.read(ro, 12))
        symbol = ('_OBJC_METACLASS_$_' if flags & 1 else '_OBJC_CLASS_$_') + name
        ref.update({'class': name, 'source_image': target_classes[cls], 'metaclass': bool(flags & 1),
                    'source_instance_start': start, 'source_instance_size': size,
                    'replacement_export': resolve(providers, target_classes[cls], symbol)})
        resolution = ref['replacement_export']
        if resolution['status'] == 'resolved':
            reader = provider_readers[resolution['provider']]
            dest = reader.base + int(resolution['input_offset'], 16)
            dest_ro = reader.ptr(dest + 32) & ~7
            require(reader.string(reader.ptr(dest_ro + 24)) == name, 'external replacement class name mismatch')
            ref['replacement_metadata'] = {'address': hex(dest),
                'instance_start': reader.number(dest_ro + 4, '<I'),
                'instance_size': reader.number(dest_ro + 8, '<I')}
        if ref['kind'] in ('class.superclass', 'metaclass.superclass'):
            child = int(ref['field'], 16) - 8
            child_ro = source.ptr(child + 32) & ~7
            ref['subclass'] = {'address': hex(child), 'name': source.string(source.ptr(child_ro + 24)),
                'instance_start': source.number(child_ro + 4, '<I'),
                'instance_size': source.number(child_ro + 8, '<I')}
    return {'schema': 1, 'ivar_audit': ivar_audit, 'new_provider_categories': supplemental_categories,
            'status': 'checked symbolic transfer plan; writer and runtime acceptance not checked here',
            'categories_scanned': scanned, 'incoming': inventory, 'class_plans': plans,
            'external_class_references': references, 'target_class_and_metaclass_count': len(target_classes),
            'source_objc_header_count': len(source.objc_images),
            'reference_scan_scope': 'External classrefs/superrefs and isa/superclass fields in classlist/nlclslist; export patch tables, Swift and PBL references require separate integration.',
            'required_writer_gates': [
                'Relocate replacement classes, metaclasses, class_ro, ivars, methods, properties and protocols; bind their imports.',
                'Retarget each category.cls to the resolved replacement class; preserve category pointers and external list implementations.',
                'Emit one tagged relative list-list per affected class/kind, in entries_in_lookup_order; remap every image index through the final ObjC header-info table.',
                'Set coherent image/category preoptimized flags and retain attached-list recognition; prove no duplicate runtime attachment.',
                'Retarget external class/superclass/isa/classrefs/superrefs and class export/patch uses; regenerate class/protocol lookup tables.',
                'Unique replacement selectors against final selector table; rebuild/sort method lists and encode direct selector-base offsets correctly.',
                'Audit Swift ObjC class references/conformance/prespecialization and regenerate affected prebuilt loader ObjC fixups.',
                'Rebuild any affected IMP caches and slide chains; preserve all required pre-rendered caches.',
                'Prove source category implementation compatibility with replacement instance layout and methods before publishing a cache.']}
