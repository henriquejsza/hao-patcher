"""Scratch cache emitter: checked image relocation, new v2 chains and signatures.

These primitives emit real bytes but do not certify a finished cache graph.
The CLI records remaining integration gates and never installs its output.
"""
import hashlib
import struct
from . import codesign
from .exports import require, span
from .provider_layout import Provider, is_interpose
from .relayout import NO_OFFSETS
from .slides import SlideInfoV2, MASK64

INTERPOSE_APPLIED = b'__ipose_applied'   # an __interpose section after its tuples became cache patches
REMOVED_COMMANDS = {0x1d, 0x1e, 0x2b, 0x80000034}


def image_records(family, providers):
    """Final image identities; both x86_64 image arrays are required in every file."""
    data = family.main.data
    imageoff, count = struct.unpack_from('<II', data, 448)
    textoff, textcount = struct.unpack_from('<QQ', data, 136)
    require(count == textcount == len(family.images), 'image counts differ')
    records = []
    for i, (path, address) in enumerate(family.images):
        addr, mtime, inode, _, pad = struct.unpack_from('<3Q2I', data, imageoff + 32*i)
        uuid, textaddr, size, _ = struct.unpack_from('<16sQ2I', data, textoff + 32*i)
        # The last word is 0 on 552-byte (26) headers; 27 (568) uses it (1, or 2 for four libSystem members on 26B131;
        # meaning OPEN). Kept as read for every original row.
        require(addr == textaddr == address and (pad == 0 or family.main.mapping_offset == 568), 'image/text identity differs')
        records.append(dict(path=path, address=address, mtime=mtime, inode=inode,
                            uuid=uuid.hex(), text_size=size, image_word=pad))
    for provider in providers:
        index = provider['image_record']['image_index']
        raw = provider['_source']
        image = Provider(provider['key'], raw, provider['path'])
        uuids = [span(image.data, c['offset'] + 8, 16) for c in image.commands if c['command'] == 0x1b]
        require(len(uuids) == 1, 'provider needs exactly one Mach-O UUID')
        # A replacement keeps the original row's word; an addition takes 1 on 27 (3,941 of 3,945 rows), 0 on 26.
        entry = dict(path=provider['path'], address=provider['placement']['provider_header_address'],
                     mtime=0, inode=0, uuid=uuids[0].hex(), text_size=image.segments[0].size,
                     image_word=1 if family.main.mapping_offset == 568 else 0)
        if index < count:
            require(records[index]['path'] == entry['path'], 'replacement identity differs')
            entry['image_word'] = records[index]['image_word']
            records[index] = entry
        else:
            require(index == len(records), 'addition indexes must be contiguous')
            records.append(entry)
    require(len({r['path'] for r in records}) == len(records), 'duplicate image identity')
    return records


def write_image_lists(data, records, images_offset, text_offset, strings_offset, limit, *, compact_paths=False):
    require(0 < images_offset < text_offset < strings_offset <= limit <= len(data), 'invalid image-list geometry')
    count = len(records)
    require(images_offset + count*32 <= text_offset and text_offset + count*32 <= strings_offset,
            'overlapping image arrays')
    cursor = strings_offset
    offsets = {}
    if compact_paths:
        names={row['path'].encode('utf-8') for row in records}
        require(all(name.startswith(b'/') and b'\0' not in name for name in names),'invalid image path')
        for name in sorted(names,key=lambda value:(-len(value),value)):
            if name in offsets:continue
            require(cursor+len(name)+1<=limit,'x86_64 compact image paths exceed reserved prefix')
            data[cursor:cursor+len(name)+1]=name+b'\0'
            for position,byte in enumerate(name):
                if byte==47 and name[position:] in names:
                    offsets.setdefault(name[position:],cursor+position)
            cursor+=len(name)+1
    for i, row in enumerate(records):
        name = row['path'].encode('utf-8') + b'\0'
        require(name.startswith(b'/') and b'\0' not in name[:-1], 'invalid image path')
        path_offset=offsets[name[:-1]] if compact_paths else cursor
        require(path_offset + len(name) <= limit, 'x86_64 image lists exceed reserved prefix')
        struct.pack_into('<3Q2I', data, images_offset + 32*i,
                         row['address'], row['mtime'], row['inode'], path_offset, row.get('image_word', 0))
        struct.pack_into('<16sQ2I', data, text_offset + 32*i,
                         bytes.fromhex(row['uuid']), row['address'], row['text_size'], path_offset)
        if not compact_paths:
            data[cursor:cursor+len(name)] = name
            cursor += len(name)
    struct.pack_into('<II', data, 448, images_offset, count)
    struct.pack_into('<QQ', data, 136, text_offset, count)
    return cursor


def relocate_macho(data, source, provider):
    """Copy source commands, remove consumed fixups, rewrite addresses/file offsets."""
    image = Provider(provider['key'], source, provider['path'])
    require(hashlib.sha256(image.data).hexdigest() == provider['input_sha256'] and
            len(image.data) == provider['input_size'], 'provider input drift')
    slide = provider['placement']['uniform_slide']
    segments = provider['segments']
    require(len(segments) == len(image.segments), 'provider segment count differs')
    for segment, old in zip(segments, image.segments):
        require(segment['source'] == vars(old), 'source segment plan differs')
        require(segment['new_address'] == old.address + slide, 'nonuniform image relocation')
        begin = segment['new_file_offset']
        span(data, begin, old.size)
        data[begin:begin+old.file_size] = span(image.data, old.file_offset, old.file_size)

    def translate(offset, length):
        if offset == length == 0:
            return 0
        matches = [s for s in segments if s['source']['file_offset'] <= offset and
                   offset + length <= s['source']['file_offset'] + s['source']['file_size']]
        # A zero-sized range can sit exactly on a boundary; prefer the following segment.
        if not length and len(matches) == 2:
            matches = [s for s in matches if s['source']['file_offset'] == offset]
        require(len(matches) == 1, 'LINKEDIT range has no unique source segment')
        segment = matches[0]
        require(segment['source']['name'] == '__LINKEDIT', 'load-command payload outside LINKEDIT')
        return segment['new_file_offset'] + offset - segment['source']['file_offset']

    commands, removed, symbols_changed, interposed = [], [], 0, []
    repaired_sections = []
    for command in image.commands:
        cmd, at, size = command['command'], command['offset'], command['size']
        raw = bytearray(span(image.data, at, size))
        if cmd in REMOVED_COMMANDS:
            removed.append(cmd)
            continue
        if cmd == 0x19:
            segment = next(s for s in segments if s['source']['command_offset'] == at)
            struct.pack_into('<Q', raw, 24, segment['new_address'])
            struct.pack_into('<Q', raw, 40, segment['new_file_offset'])
            for section in segment['sections']:
                rel = section['command_offset'] - at
                require(section['new_address'] == section['address'] + slide, 'nonuniform section relocation')
                struct.pack_into('<Q', raw, rel+32, section['new_address'])
                struct.pack_into('<I', raw, rel+48, section['new_offset'])
                if is_interpose(section, segment['source']['name']):
                    # Applied as cache patches (run_patch): the tuples are zeroed and carry no fixups, and the
                    # section is no longer an interpose section by name or type.
                    data[section['new_offset']:section['new_offset']+section['size']] = bytes(section['size'])
                    raw[rel:rel+16] = INTERPOSE_APPLIED.ljust(16, b'\0')
                    struct.pack_into('<I', raw, rel+64, section['flags'] & ~255)
                    interposed.append(dict(section=section['name'], address=section['new_address'], size=section['size']))
        elif cmd == 2:
            symoff, nsyms, strings, strsize = struct.unpack_from('<4I', raw, 8)
            newoff = translate(symoff, nsyms*16)
            struct.pack_into('<I', raw, 8, newoff)
            struct.pack_into('<I', raw, 16, translate(strings, strsize))
            for i in range(nsyms):
                strx, kind, section, desc, value = struct.unpack_from('<IBBHQ', image.data, symoff+16*i)
                if not kind & 0xe0 and kind & 0x0e == 0x0e:
                    final_section=symbol_section(image.sections,section,value)
                    if final_section!=section:
                        data[newoff+16*i+5]=final_section
                        repaired_sections.append(dict(symbol_index=i,before=section,after=final_section,value=value))
                    struct.pack_into('<Q', data, newoff+16*i+8, value+slide)
                    symbols_changed += 1
        elif cmd == 0xb:
            for pos, unit in ((32,8), (40,56), (48,4), (56,4), (64,8), (72,8)):
                off, count = struct.unpack_from('<II', raw, pos)
                require(pos not in (32,40,48,64,72) or count == 0, 'unsupported legacy symbol/relocation payload')
                struct.pack_into('<I', raw, pos, translate(off, count*unit))
        elif cmd in (0x22, 0x80000022):
            # Runtime cache rebasing/binding uses cache slides and loader metadata.
            raw[8:40] = bytes(32)
            off, length = struct.unpack_from('<II', raw, 40)
            struct.pack_into('<I', raw, 40, translate(off, length))
        elif cmd in (0x26, 0x29, 0x80000033):
            off, length = struct.unpack_from('<II', raw, 8)
            struct.pack_into('<I', raw, 8, translate(off, length))
        else:
            require(cmd in NO_OFFSETS, f'unsupported provider command {cmd:#x}')
        commands.append(raw)
    payload = b''.join(commands)
    base = provider['geometry']['provider_header_file_offset']
    old_size = struct.unpack_from('<I', image.data, 20)[0]
    require(len(payload) <= old_size, 'load commands grew beyond source allocation')
    data[base+32:base+32+old_size] = payload + bytes(old_size-len(payload))
    struct.pack_into('<II', data, base+16, len(commands), len(payload))
    flags = struct.unpack_from('<I', image.data, 24)[0]
    struct.pack_into('<I', data, base+24, flags | 0x80000000)
    require(sum(i['size'] for i in interposed) == 16 * len(provider.get('interpose', [])),
            'applied interpose sections differ from the plan')
    return {'removed_commands': removed, 'relocated_symbols': symbols_changed, 'applied_interpose_sections': interposed,
            'commands': len(commands), 'command_bytes': len(payload),
            'repaired_symbol_sections': repaired_sections}



def symbol_section(sections, section, value):
    """Preserve valid ordinals; repair extractor-stale ordinals by unique address."""
    require(1 <= section <= len(sections), 'N_SECT symbol section out of range')
    owner=sections[section-1]
    if owner['address'] <= value <= owner['address']+owner['size']:
        return section
    matches=[i+1 for i,row in enumerate(sections) if row['address'] <= value < row['address']+row['size']]
    require(len(matches)==1 and matches[0]<256,'section symbol lacks unique mapped section')
    return matches[0]

def pointer_records(provider):
    packed = provider['pointer_fixups']
    require(packed['rebase_columns'] == ['source_file_offset','file_offset','address','mapping_index','source_target','target'] and
            packed['bind_columns'] == ['source_file_offset','file_offset','address','mapping_index','binding_index'],
            'unknown pointer schema')
    result = []
    for kind in ('rebase', 'bind'):
        columns = packed[kind+'_columns']
        for row in packed[kind+'_rows']:
            require(len(row) == len(columns), 'truncated pointer row')
            value = dict(zip(columns, row))
            if kind == 'bind':
                index = value['binding_index']
                require(0 <= index < len(packed['bindings']), 'binding index outside catalog')
                binding = packed['bindings'][index]
                require(binding['resolution']['status'] == 'resolved', 'unresolved provider bind')
                value['target'] = binding['target']
            else:
                target = value['source_target']
                require(value['target'] == (target+provider['placement']['uniform_slide'] if target else 0),
                        'rebase target differs from uniform slide')
            result.append(value)
    return result


def emit_slide_chains(data, provider):
    """Encode every recorded pointer and verify the exact field set with a separate reader."""
    fields = pointer_records(provider)
    require(len({f['address'] for f in fields}) == len(fields), 'duplicate pointer field')
    mappings = provider['placement']['mappings']
    require(all(0 <= f['mapping_index'] < len(mappings) for f in fields), 'invalid pointer mapping index')
    verified = 0
    for index, mapping in enumerate(mappings):
        selected = sorted((f for f in fields if f['mapping_index'] == index), key=lambda f: f['address'])
        info = mapping['slide_info']
        require(bool(selected) == bool(info), 'pointer/slide mapping mismatch')
        if not info:
            continue
        require(info['version'] == 2 and info['page_size'] == 4096 and info['delta_mask'] == 0x00ffff0000000000,
                'unknown v2 encoding')
        require(info['page_count']*4096 == mapping['size'] and info['size'] == 40+2*info['page_count'],
                'slide-info geometry differs')
        starts = [0x4000]*info['page_count']
        pages = {}
        for field in selected:
            rel = field['address']-mapping['address']
            require(0 <= rel <= mapping['size']-8 and rel%4 == 0 and rel%4096 <= 4088,
                    'invalid pointer location')
            require(field['file_offset'] == mapping['file_offset']+rel, 'pointer file/VM location differs')
            pages.setdefault(rel//4096, []).append((rel%4096, field))
        for page, rows in pages.items():
            starts[page] = rows[0][0]//4
            for i, (offset, field) in enumerate(rows):
                delta = rows[i+1][0]-offset if i+1 < len(rows) else 0
                require(delta == 0 or delta >= 8, 'overlapping pointers')
                target = field['target']
                require(0 <= target <= MASK64, 'pointer target overflow')
                value = (target-info['value_add']) & MASK64 if target else 0
                require((target == 0 or value != 0) and not value & info['delta_mask'],
                        'pointer target cannot be represented')
                encoded_delta = delta << 38
                require(not encoded_delta & ~info['delta_mask'], 'slide delta overflow')
                struct.pack_into('<Q', data, field['file_offset'], value | encoded_delta)
        require(starts == info['page_starts'], 'slide starts differ from producer')
        block = struct.pack('<6I2Q',2,4096,40,len(starts),0,0,info['delta_mask'],info['value_add'])
        block += struct.pack(f'<{len(starts)}H', *starts)
        off = info['file_offset']
        require(provider['geometry']['slide_info_start'] <= off and off+len(block) <= provider['geometry']['signature']['offset'],
                'slide block outside allocation')
        data[off:off+len(block)] = block
        reader = SlideInfoV2(block, data, mapping['file_offset'], mapping['size'])
        decoded = {mapping['address']+rel:reader.decode(raw)
                   for page in range(len(starts)) for rel, raw in reader.page(page).items()}
        require(decoded == {f['address']:f['target'] for f in selected}, 'emitted pointer-chain round trip differs')
        verified += len(decoded)
    require(verified == len(fields), 'not every pointer was emitted')
    return verified


def sign_with_uuid(data, identifier, text_size):
    """Apple SubCache::codeSign UUID algorithm: zero-UUID CodeDirectory hash."""
    limit, expected_size = struct.unpack_from('<QQ', data, 40)
    require(len(data) == limit+expected_size and not any(data[88:104]), 'signing requires unset UUID and exact extent')
    preliminary = codesign.emit(data, limit, identifier, text_size)
    cdsize = struct.unpack_from('>I', preliminary, 40)[0]
    uuid = bytearray(hashlib.sha256(preliminary[36:36+cdsize]).digest()[:16])
    uuid[6] = (uuid[6] & 15) | 0x30
    uuid[8] = (uuid[8] & 63) | 0x80
    data[88:104] = uuid
    signature = codesign.emit(data, limit, identifier, text_size)
    require(len(signature) == expected_size, 'signature size differs from allocation')
    data[limit:] = signature
    result = codesign.inspect(data)
    result['uuid'] = bytes(uuid).hex()
    return result


def emit_provider(source, provider, template_header, records):
    geometry = provider['geometry']
    sig = geometry['signature']
    data = bytearray(sig['file_size'])
    data[:16] = b'dyld_v1  x86_64\0'
    # Only scalar platform/OS/cache-kind properties come from the pinned header.
    for offset, length in ((104,8),(216,8),(364,12),(456,4)):
        data[offset:offset+length] = span(template_header, offset, length)
    header = geometry['mapping_offset']
    require(header == len(template_header) == struct.unpack_from('<I', template_header, 16)[0] and header in (552, 568),
            'provider header size differs from the source cache')
    # 27 (568): cputype 0x01000007, cpusubtype 3, 8 zero bytes after prewarmingDataSize, as in every 26B131 file.
    data[552:header] = template_header[552:header]
    struct.pack_into('<II',data,16,header,geometry['mapping_count'])
    struct.pack_into('<QQ',data,40,sig['offset'],sig['size'])
    struct.pack_into('<Q',data,224,provider['placement']['cache_header_address'])
    struct.pack_into('<II',data,312,geometry['slide_mapping_offset'],geometry['mapping_count'])
    for i, mapping in enumerate(provider['placement']['mappings']):
        struct.pack_into('<3Q2I',data,header+32*i,mapping['address'],mapping['size'],mapping['file_offset'],mapping['maximum'],mapping['initial'])
        info = mapping['slide_info']
        flags = mapping['flags']
        struct.pack_into('<6Q2I',data,geometry['slide_mapping_offset']+56*i,
                         mapping['address'],mapping['size'],mapping['file_offset'],
                         info['file_offset'] if info else 0,info['size'] if info else 0,
                         flags,mapping['maximum'],mapping['initial'])
    tables = geometry['image_tables']
    require(tables['count'] == len(records), 'producer image count differs')
    list_start, text_start, strings_start = (tables[k] for k in ('images_offset','images_text_offset','string_pool_offset'))
    lists_end = write_image_lists(data,records,list_start,text_start,strings_start,geometry['prefix_size'])
    require(lists_end == tables['used_end'], 'producer image pool size differs')
    require([struct.unpack_from('<I',data,list_start+i*32+24)[0] for i in range(len(records))] == tables['path_offsets'],
            'producer path offsets differ')
    struct.pack_into('<II',data,392,tables['subcache_array_offset'],0)
    struct.pack_into('<II',data,512,tables['tpro_mappings_offset'],0)
    transformations = relocate_macho(data,source,provider)
    pointers = emit_slide_chains(data,provider)
    signature = sign_with_uuid(data,sig['identifier'],sig['exec_segment_limit'])
    return bytes(data), {'key':provider['key'],'image_header':provider['placement']['provider_header_address'],
                         'signature':signature,'pointer_count':pointers,'image_list_end':lists_end,
                         'macho':transformations,'sha256':hashlib.sha256(data).hexdigest(),'size':len(data)}


def update_original_subcache(data, records, original_count):
    """Use verified padding before the first Mach-O; no mapped image bytes move."""
    images_offset, count = struct.unpack_from('<II',data,448)
    text_offset, text_count = struct.unpack_from('<QQ',data,136)
    require(count == text_count == original_count, 'original subcache image count differs')
    require(struct.unpack_from('<I',data,516)[0] == 0, 'subcache has unhandled TPRO records')
    base, text_size = struct.unpack_from('<QQ',data,struct.unpack_from('<I',data,16)[0])
    old_addresses = [struct.unpack_from('<Q',data,images_offset+32*i)[0] for i in range(count)]
    headers = [address-base for address in old_addresses if base <= address < base+text_size]
    require(headers, 'original subcache has no image headers')
    limit = min(headers)
    # Original list strings are the sole bytes after the old arrays in this prefix.
    old_end = max(data.find(b'\0',struct.unpack_from('<I',data,images_offset+32*i+24)[0])+1 for i in range(count))
    require(0 < old_end <= limit and not any(data[old_end:limit]), 'prefix padding is not empty')
    text_offset = images_offset+len(records)*32
    strings_offset = text_offset+len(records)*32
    end = write_image_lists(data,records,images_offset,text_offset,strings_offset,limit,compact_paths=True)
    struct.pack_into('<II',data,392,strings_offset,0)
    struct.pack_into('<II',data,512,strings_offset,0)
    data[88:104] = bytes(16)
    identifier = codesign.inspect(data,verify_pages=False)['identifier']
    signature = sign_with_uuid(data,identifier,text_size)
    return {'image_list_end':end,'preserved_from':limit,'signature':signature}


def carry_tpro(source, data, cursor, limit):
    """Copy the source main's TPRO records (header +512: offset, count; 16-byte address/size rows) to cursor.

    27 (26B131): main lists 2 TPRO regions (main RW2 and .06 RW2, 16 KB each) inside the prefix that update_main
    rewrites; subcaches and 26 mains list none. Rows are kept unchanged and +512 is repointed. Returns the new cursor.
    """
    offset, count = struct.unpack_from('<II', source, 512)
    if not count:
        return cursor
    rows = bytes(span(source, offset, 16 * count))
    require(cursor % 8 == 0 and cursor + len(rows) <= limit, 'TPRO records exceed main extension')
    data[cursor:cursor + len(rows)] = rows
    struct.pack_into('<II', data, 512, cursor, count)
    return cursor + len(rows)


def update_main(data, source_family, plan, records, subcaches):
    """Connect the staged family. Metadata tables are separately gated by the CLI."""
    updates, base = plan['main_updates'], plan['base_layout']
    imageoff, textoff = base['images_file_offset'],base['image_text_file_offset']
    require(struct.unpack_from('<II',data,448) == (imageoff,len(source_family.images)), 'main relayout image table differs')
    require(struct.unpack_from('<QQ',data,136) == (textoff,len(source_family.images)), 'main relayout text table differs')
    suboff, size = updates['subcache_array_offset'],updates['subcache_array_size']
    require(len(subcaches) == updates['final_subcache_count'] and len(records) == updates['final_image_count'],
            'final graph count differs from placement plan')
    require(size == len(subcaches)*56 and suboff+size <= updates['extension_end'], 'main subcache table overflows allocation')
    cursor = suboff+size
    cursor = carry_tpro(source_family.main.data, data, cursor, updates['extension_end'])
    old_imageoff = struct.unpack_from('<I',source_family.main.data,448)[0]
    for i,row in enumerate(records):
        if i < len(source_family.images):
            require(row['path'] == source_family.images[i][0], 'changed canonical image path')
            pathoff = struct.unpack_from('<I',source_family.main.data,old_imageoff+32*i+24)[0]
        else:
            name = row['path'].encode()+b'\0'
            require(cursor+len(name) <= updates['extension_end'], 'new paths exceed main extension')
            pathoff = cursor
            data[cursor:cursor+len(name)] = name
            cursor += len(name)
        struct.pack_into('<3Q2I',data,imageoff+32*i,row['address'],row['mtime'],row['inode'],pathoff,row.get('image_word',0))
        struct.pack_into('<16sQ2I',data,textoff+32*i,bytes.fromhex(row['uuid']),row['address'],row['text_size'],pathoff)
    cache_base = source_family.main.mappings[0].address
    for i,row in enumerate(subcaches):
        suffix = row['suffix'].encode()+b'\0'
        require(row['suffix'] == f'.{i+1:02d}' and len(suffix)<=32, 'subcache order differs')
        struct.pack_into('<16sQ32s',data,suboff+i*56,bytes.fromhex(row['uuid']),row['address']-cache_base,suffix)
    struct.pack_into('<II',data,392,suboff,len(subcaches))
    struct.pack_into('<I',data,452,len(records))
    struct.pack_into('<Q',data,144,len(records))
    data[88:104] = bytes(16)
    identifier = codesign.inspect(data,verify_pages=False)['identifier']
    signature = sign_with_uuid(data,identifier,source_family.main.mappings[0].size+base['required_main_text_growth'])
    return {'extension_used_end':cursor,'signature':signature}
