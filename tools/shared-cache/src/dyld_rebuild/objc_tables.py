"""Checked ObjC lookup-table inputs and header-info emission.

Perfect hashes and object table bytes are emitted by pinned Apple C++ writers.
This module independently decodes their complete results. It never changes
class/protocol objects or chooses canonical object identity implicitly.
"""
from dataclasses import dataclass
import struct
from .exports import require, span


# dyld's ObjC optimization header (main cache header +464: offset, size). 26 (dyld-1378): v2, 72 bytes. 27 (26B131): v4,
# 136 bytes; its first 72 bytes keep v2's fields except +0x38 (v2: selector buffer size; v4: class-name string base),
# then two arrays of four cumulative name-region offsets (from +0x30 and +0x38) and +0x80 (16-byte msgSend record).
# FACT on 262FA161 (research docs/cache27-objc-header.md; dyld 27 reads +0x08..+0x28 and +0x80). Only the root fields
# 2-6 are ever rewritten; the rest is carried unchanged.
OBJC_HEADER_FORMS = {72: (2, 6), 136: (4, 6)}


def objc_header(family):
    """(address, size, fields): the first ten '<II8Q' values of the global ObjC optimization header, checked."""
    base = family.main.mappings[0].address
    offset, size = struct.unpack_from('<QQ', family.main.data, 464)
    require(size in OBJC_HEADER_FORMS, 'unsupported ObjC optimization header extent')
    fields = struct.unpack('<II8Q', family.read(base + offset, 72))
    require(fields[:2] == OBJC_HEADER_FORMS[size], 'unsupported ObjC optimization header version/flags')
    return base + offset, size, fields


@dataclass(frozen=True)
class NameEntry:
    name: bytes
    address: int
    # (unslid object address, ObjC header-info index), in runtime lookup order.
    objects: tuple = ()


@dataclass(frozen=True)
class ObjCTable:
    kind: str
    address: int
    data: bytes
    capacity: int
    entries: tuple
    # Original duplicate-array order, followed by single-implementation keys.
    object_order: tuple


def family_string(family, address):
    file, offset = family.locate(address)
    mapping = next(m for m in file.mappings if m.address <= address < m.address + m.size)
    maximum = min((1 << 20), mapping.address + mapping.size - address)
    end = file.data.find(b'\0',offset,offset+maximum)
    require(offset <= end < offset+maximum, 'ObjC name missing terminator within bound')
    return bytes(file.data[offset:end])


def read_table(read, string, address, kind, cache_base):
    require(kind in ('selector', 'class', 'protocol'), 'unknown ObjC table kind')
    header = read(address, 1056)
    version, capacity, occupied, shift, mask = struct.unpack_from('<5I', header)
    require(version == 0 and header[20:24] == b'\0'*4, 'unsupported ObjC hash version/padding')
    require(0 < capacity <= 1 << 22 and capacity & (capacity-1) == 0, 'invalid ObjC capacity')
    require(0 < occupied <= capacity, 'invalid ObjC occupied count')
    require(shift == 64-(capacity.bit_length()-1), 'invalid ObjC hash shift')
    require(mask < 1 << 22 and (mask+1) & mask == 0, 'invalid ObjC hash mask')
    checks_at = 1056 + mask + 1
    offsets_at = checks_at + capacity
    prefix_size = offsets_at + 4*capacity
    prefix = read(address, prefix_size)
    offsets = struct.unpack_from(f'<{capacity}i', prefix, offsets_at)
    require(sum(bool(o) for o in offsets) == occupied, 'ObjC bucket count differs')
    duplicates = ()
    values = ()
    data = prefix
    if kind != 'selector':
        values = struct.unpack(f'<{capacity}Q', read(address+prefix_size, capacity*8))
        count = struct.unpack('<I', read(address+prefix_size+capacity*8, 4))[0]
        require(count <= 1 << 22, 'ObjC duplicate count exceeds bound')
        data = read(address, prefix_size+capacity*8+4+count*8)
        duplicates = struct.unpack_from(f'<{count}Q', data, prefix_size+capacity*8+4)
        require(all(not (v & 1) for v in duplicates), 'nested ObjC duplicate descriptor')
    entries, groups, names, ranges = [], [], set(), []
    for bucket, offset in enumerate(offsets):
        if not offset:
            require(prefix[checks_at+bucket] == 0, 'empty ObjC bucket has check byte')
            require(not values or values[bucket] == 0, 'empty ObjC bucket has object')
            continue
        target = address + offset
        name = string(target)
        require(name and b'\0' not in name and len(name) < (1 << 20), 'invalid ObjC key')
        require(name not in names, 'duplicate ObjC key')
        names.add(name)
        require(prefix[checks_at+bucket] == ((name[0]&7)<<5)|(len(name)&31), 'ObjC key check byte differs')
        objects = ()
        group_order = (1, bucket)
        if kind != 'selector':
            raw = values[bucket]
            require(raw != 0, 'occupied ObjC bucket lacks object')
            if raw & 1:
                start, count = (raw>>1)&((1<<47)-1), raw>>48
                require(count >= 2 and start+count <= len(duplicates), 'invalid ObjC duplicate range')
                ranges.append((start,start+count))
                raws = duplicates[start:start+count]
                group_order = (0,start)
            else:
                raws = (raw,)
            objects = tuple((cache_base+((v>>1)&((1<<47)-1)), v>>48) for v in raws)
            require(all(a != cache_base for a,_ in objects), 'null ObjC object offset')
        entry = NameEntry(name,target,objects)
        entries.append(entry);groups.append((group_order,name))
    position = 0
    for start,end in sorted(ranges):
        require(start == position, 'ObjC duplicate array has overlap/hole')
        position = end
    require(position == len(duplicates), 'ObjC duplicate array has unused records')
    return ObjCTable(kind,address,bytes(data),capacity,tuple(entries),tuple(n for _,n in sorted(groups)))


def validate_entries(entries, kind, cache_base, table_address):
    entries = tuple(entries)
    require(entries and len(entries) <= 1 << 22, 'invalid ObjC entry count')
    require(len({e.name for e in entries}) == len(entries), 'duplicate ObjC input key')
    require(len({e.address for e in entries}) == len(entries), 'aliased ObjC input names')
    for e in entries:
        require(type(e.name) is bytes and 0 < len(e.name) < (1 << 20) and b'\0' not in e.name, 'invalid ObjC input name')
        require(type(e.address) is int and -(1<<31) <= e.address-table_address < 1<<31
                and e.address != table_address, 'ObjC key outside relative range')
        if kind == 'selector':
            require(not e.objects, 'selector has object values')
        else:
            require(0 < len(e.objects) < 65536, 'ObjC object multiplicity overflow')
            for address,index in e.objects:
                require(type(address) is int and 0 < address-cache_base < 1<<47, 'ObjC object offset overflow')
                require(type(index) is int and 0 <= index < 65536, 'ObjC owner index overflow')
    return entries


def writer_fixture(entries, kind, cache_base, table_address, reserve, object_order=None):
    """Explicit complete logical input to the unmodified Apple writer templates."""
    require(kind in ('selector','class','protocol'), 'unknown ObjC writer kind')
    entries = validate_entries(entries,kind,cache_base,table_address)
    ordered = sorted(entries,key=lambda e:e.address)
    strings_base = ordered[0].address
    require(ordered[-1].address-strings_base < 1<<32, 'ObjC string-buffer offset overflow')
    require(type(reserve) is int and 1056 <= reserve <= 1<<29, 'invalid ObjC table reservation')
    byname = {e.name:e for e in entries}
    object_order = tuple(object_order) if object_order is not None else tuple(e.name for e in ordered)
    require(len(object_order) == len(entries) and set(object_order) == set(byname), 'ObjC object order differs from keys')
    names_index = {e.name:i for i,e in enumerate(ordered)}
    result = bytearray(struct.pack('<4sIIIQQQQ',b'OTW1',('selector','class','protocol').index(kind)+1,
                                   len(ordered),sum(len(e.objects) for e in entries),strings_base,table_address,cache_base,reserve))
    for e in ordered:
        result += struct.pack('<II',e.address-strings_base,len(e.name))+e.name+b'\0'
    for name in object_order:
        for address,index in byname[name].objects:
            result += struct.pack('<IQH',names_index[name],address,index)
    return bytes(result)


def rewrite_objects(table, original_order, final_order, replaced, additions):
    """Replace explicit image memberships while preserving other lookup order.

    additions contains (name bytes, canonical-name address, object address,
    final image path). Class/protocol canonical identity is supplied by the
    metadata transformer; this function never chooses a replacement object.
    """
    require(table.kind in ('class','protocol'), 'object rewrite requires object table')
    require(len(set(original_order)) == len(original_order) and len(set(final_order)) == len(final_order), 'duplicate image identity')
    # A replaced image may lose its ObjC header in the final family (26B131: OCLP's IO80211 is a shim; its classes now
    # come from IO80211OCLP/IO80211Old, which arrive as additions). Its objects are dropped here, never re-indexed.
    kept = set(original_order) - set(replaced)
    require(kept <= set(final_order) and set(replaced) <= set(original_order), 'missing original image identity: '
            + repr(sorted(kept - set(final_order))[:8]) + ' not final; ' + repr(sorted(set(replaced) - set(original_order))[:8]) + ' not original')
    indexes = {p:i for i,p in enumerate(final_order)}
    result = {}
    for e in table.entries:
        require(all(i < len(original_order) for _,i in e.objects), 'original ObjC owner out of range')
        objects = tuple((a,indexes[original_order[i]]) for a,i in e.objects if original_order[i] not in replaced)
        if objects: result[e.name] = NameEntry(e.name,e.address,objects)
    new_order = [n for n in table.object_order if n in result]
    source_names = {e.name:e.address for e in table.entries}
    for name,name_address,address,path in additions:
        require(path in indexes, 'added ObjC owner lacks header-info identity')
        require(name not in source_names or source_names[name] == name_address, 'existing ObjC canonical name moved')
        if name not in result:
            result[name] = NameEntry(name,name_address,())
            new_order.append(name)
        require(result[name].address == name_address, 'added ObjC canonical name differs')
        obj=(address,indexes[path])
        require(obj not in result[name].objects, 'duplicate added ObjC object/owner')
        e=result[name];result[name]=NameEntry(e.name,e.address,e.objects+(obj,))
    return tuple(result[n] for n in new_order),tuple(new_order)


def decode_header_info(read, ro_address, rw_address, *, bootstrap_only=False):
    count,stride = struct.unpack('<II',read(ro_address,8))
    require(0 < count < 65536 and stride == 24,'unsupported ObjC RO header-info shape')
    require(struct.unpack('<II',read(rw_address,8)) == (count,8),'ObjC RW header-info shape differs')
    require(not any(read(rw_address+8,8*count)), 'ObjC RW initial state is not zero')
    rows=[]
    for i in range(count):
        field=ro_address+8+i*24
        offsets=struct.unpack('<3q',read(field,24))
        require((offsets[2]==0) if bootstrap_only else (offsets[2]!=0),
                'ObjC header PBL bootstrap/final mode differs')
        targets=tuple(0 if j==2 and bootstrap_only else field+8*j+v for j,v in enumerate(offsets))
        require(all(targets[:2]) and (bootstrap_only or targets[2]),'null ObjC header-info target')
        rows.append(targets)
    require(all(a[0]<b[0] for a,b in zip(rows,rows[1:])), 'ObjC headers are not strictly MH sorted')
    return tuple(rows)


def emit_header_info(rows, ro_address, rw_address, imageinfo_address, *, bootstrap_only=False):
    """Emit MH-sorted rows; explicit bootstrap has zero raw PBL fields only.

    Bootstrap blobs are generator inputs, never valid final cache metadata.
    Default mode requires every final cached PBL address to be positive.
    """
    rows=tuple(rows)
    require(0 < len(rows) < 65536,'invalid ObjC header-info count')
    require(all(a[0]<b[0] for a,b in zip(rows,rows[1:])), 'ObjC header input order differs')
    require(all(type(a) is int and a > 0 and a%8 == 0 for a in (ro_address,rw_address,imageinfo_address)), 'ObjC header allocation alignment')
    ro=bytearray(struct.pack('<II',len(rows),24));infos=bytearray()
    for i,(mh,info,pbl) in enumerate(rows):
        require(type(mh) is int and type(pbl) is int and mh>0, 'ObjC header missing MH/PBL')
        require((pbl==0) if bootstrap_only else (pbl>0), 'ObjC header PBL bootstrap/final mode differs')
        require(type(info) is bytes and len(info)==8, 'unsupported ObjC imageinfo size')
        version,flags=struct.unpack('<II',info)
        require(version == 0 and flags & 8, 'ObjC imageinfo not explicitly optimized')
        field=ro_address+8+24*i
        offsets=(mh-field,imageinfo_address+8*i-(field+8),0 if bootstrap_only else pbl-(field+16))
        require(bootstrap_only or offsets[2]!=0,'final PBL pointer aliases its offset field')
        require(all(-(1<<63)<=x<1<<63 for x in offsets),'ObjC header relative offset overflow')
        ro+=struct.pack('<3q',*offsets);infos+=info
    rw=struct.pack('<II',len(rows),8)+b'\0'*(len(rows)*8)
    return dict(ro=bytes(ro),rw=rw,imageinfo=bytes(infos))


def checked_loader_addresses(document, loaders, base, byte_count, digest):
    """Bind an address map to independently decoded serialized loader offsets."""
    require(type(document) is dict and type(base) is int and base>0 and base%8==0,'invalid loader address map')
    expected={row['path']:base+row['offset'] for row in loaders}
    require(len(expected)==len(loaders),'duplicate serialized loader path')
    if 'loaders' in document:
        require(set(document)=={'base','alignment','size','sha256','loaders'},'unknown loader address document shape')
        require(document['base']==base and document['alignment']==8 and document['size']==byte_count and document['sha256']==digest,
                'loader address document does not bind serialized blob')
        records=document['loaders'];require(type(records) is list and len(records)==len(loaders),'loader address record count differs')
        for row,wanted in zip(records,loaders):
            require(set(row)=={'index','path','offset','address'} and row['index']==wanted['index'] and
                    row['path']==wanted['path'] and row['offset']==wanted['offset'] and row['address']==base+wanted['offset'],
                    'loader address record differs from serialized offset/order')
        actual={row['path']:row['address'] for row in records}
    else:
        actual=document
    require(actual==expected,'PBL address map differs from actual serialized offsets')
    return actual


RO_LIST_FIELDS=(32,40,64)  # class_ro_t baseMethods, baseProtocols, baseProperties


def _identifier(data):
    name=data.split(b'\0')[0]
    return bool(name) and len(name)<len(data) and (name[:1].isalpha() or name[:1] in b'_$') and \
        all(c<128 and (chr(c).isalnum() or c in b'_$.') for c in name)


def template_class_objects(family, slides):
    """Class objects reached only through slide pointers, not classlists.

    Swift classes whose metadata is completed at runtime (for example generic or
    resilient superclasses) keep a class template outside every classlist, yet
    Apple's builder still preattaches tagged relative list-lists to their RO.
    A candidate needs a tagged slide pointer at an RO list field to a list-list
    header, an identifier name at RO+24, and a slide pointer to that RO at a
    class object's data field (+32). Returns {class object: RO}.
    """
    def words():
        for _,mapping,slide in slides:
            for page in range(len(slide.starts)):
                for offset,raw in slide.page(page).items():
                    yield mapping.address+offset,slide.decode(raw)
    ros=set()
    for field,value in words():
        if not value&1:continue
        try:stride,count=struct.unpack('<II',family.read(value&~1,8))
        except Exception:continue
        if stride!=8 or not 0<count<65536:continue
        for offset in RO_LIST_FIELDS:
            ro=field-offset
            try:ok=_identifier(family.read(_slid(slides,ro+24),128))
            except Exception:continue
            if ok:ros.add(ro)
    found={};seen=set()
    for field,value in words():
        ro=value&~7
        if ro in ros and ro not in seen:
            seen.add(ro);found[field-32]=ro
    return found


def _slid(slides,address):
    for _,mapping,slide in slides:
        if mapping.address<=address<mapping.address+mapping.size:
            return slide.pointer(address-mapping.address)['target']
    raise ValueError('not a slide pointer')


def relative_list_index_edits(family, pointer, mapping, extra_objects=(), include_entries=False):
    """Enumerate every original class/metaclass conditional list owner index.

    Ownership comes from all classlists plus extra_objects: class templates that
    are reached only through slide pointers (template_class_objects). Physical
    ObjC segment containment is deliberately irrelevant. Return checked scalar
    edits only, retaining the signed48 relative target and list order. New
    reconstructed lists are separate.
    """
    from .cache import commands
    from .objc_transfer import sections
    from .swift_refs import checked_index_map
    checked_index_map(mapping,())
    objects=set();lists={};edits=[];entry_count=0
    for path,mh in family.images:
        for _,name,address,size in sections(commands(family,mh)):
            if name not in ('__objc_classlist','__objc_nlclslist'):continue
            require(size%8==0,'classlist size is not pointer aligned')
            for field in range(address,address+size,8):
                cls=pointer(field);require(cls,'null classlist object')
                objects.add(cls);meta=pointer(cls);require(meta,'null metaclass');objects.add(meta)
    listed=len(objects)
    for cls in extra_objects:
        require(pointer(cls+32)&~7,'template class without RO')
        objects.add(cls)
    for cls in sorted(objects):
        ro=pointer(cls+32)&~7
        require(ro,'null class_ro')
        for offset in (32,40,64):
            value=pointer(ro+offset)
            if not value&1:continue
            address=value&~1
            if address in lists:continue
            stride,count=struct.unpack('<II',family.read(address,8))
            require(stride==8 and 0<count<65536,'unsupported original relative list-list')
            entries=[]
            for i in range(count):
                field=address+8+8*i;raw=struct.unpack('<Q',family.read(field,8))[0];index=raw&65535
                require(index in mapping,'relative list owner index missing')
                delta=raw>>16
                if delta&(1<<47):delta-=1<<48
                target=field+delta;family.read(target,8)
                new=(raw&~65535)|mapping[index]
                entries.append(dict(field=field,index=index,new_index=mapping[index],target=target))
                if new!=raw:edits.append(dict(address=field,expected=struct.pack('<Q',raw).hex(),replacement=struct.pack('<Q',new).hex()))
                entry_count+=1
            lists[address]=entries
    result=dict(class_and_metaclass_objects=len(objects),template_objects=len(objects)-listed,
                lists=len(lists),entries=entry_count,changed_entries=len(edits),edits=edits)
    if include_entries:
        result['all_entries']=[e for entries in lists.values() for e in entries]
    return result


def optimization_roots(original, legacy, cache_base, legacy_address, addresses):
    """Checked root-field rewrite; selector base/extent and all flags survive."""
    require(len(original) in OBJC_HEADER_FORMS and len(legacy)==48,'unsupported ObjC root sizes')
    fields=list(struct.unpack('<II8Q',original[:72]));old=list(struct.unpack('<II8iq',legacy))
    require(tuple(fields[:2])==OBJC_HEADER_FORMS[len(original)] and old[:2]==[16,6],'unsupported ObjC root version/flags')
    # 27: libobjc's legacy selopt offset is 0 (selectors come from dyld's header only); it stays 0.
    legacy_selector=old[2]!=0 or len(original)==72
    require(old[4:6]==[0,0] and old[7]==0,'nonempty legacy compatibility fields')
    for index,legacy_index,kind in [(2,3,'ro'),(3,6,'rw'),(4,2,'selector'),(5,8,'class'),(6,9,'protocol')]:
        if kind=='selector' and not legacy_selector:
            target=addresses[kind]
            require(type(target) is int and target>cache_base,'invalid ObjC root target')
            fields[index]=target-cache_base
            continue
        require(legacy_address+old[legacy_index]==cache_base+fields[index],'legacy/global ObjC roots differ')
        target=addresses[kind]
        require(type(target) is int and target>cache_base and target-cache_base<1<<64,'invalid ObjC root target')
        delta=target-legacy_address
        require(-(1<<31)<=delta<1<<31 and delta!=0,'ObjC legacy root relative overflow')
        fields[index]=target-cache_base;old[legacy_index]=delta
    require(legacy_address+old[10]==cache_base+fields[7],'legacy selector base differs')
    return struct.pack('<II8Q',*fields)+original[72:],struct.pack('<II8iq',*old)


def check_scalar_edits(family, edits):
    """Require expected source bytes and no overlapping tracked slide word."""
    from .slides import family_slides
    slides=family_slides(family);pages={};seen=set()
    for edit in edits:
        address=edit['address'];before=bytes.fromhex(edit['expected']);after=bytes.fromhex(edit['replacement'])
        require(len(before)==len(after)==8 and address not in seen,'invalid scalar edit width/duplicate')
        seen.add(address);require(family.read(address,8)==before,'scalar original bytes differ')
        for file,mapping,slide in slides:
            if address+8<=mapping.address or address>=mapping.address+mapping.size:continue
            require(mapping.address<=address and address+8<=mapping.address+mapping.size,'scalar edit crosses slide mapping')
            for page in range((address-mapping.address)//4096,(address+7-mapping.address)//4096+1):
                key=(mapping.address,page)
                if key not in pages:pages[key]=slide.page(page)
                for offset in pages[key]:
                    slot=mapping.address+offset
                    require(slot+8<=address or slot>=address+8,'scalar edit overlaps slide word')
    return dict(edits=len(edits),slide_pages_checked=len(pages),overlapping_slide_words=0)
