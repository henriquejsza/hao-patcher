"""Export the observed x86_64 Swift v1.4 ABI families.

The runtime worker supplies completed objects and upstream-described witness
slots. Each family owns its extents and field meanings in one place. The graph
owns closure, canonical keys and identities; the installer owns registration.
Unknown layouts fail explicitly. No pointer-shaped-word inference is permitted.
"""
import struct

from .exports import require
from .swift_layout import references as layout_references


def schemas(captured):
    """Classify every witness slot from its descriptor, never pointer appearance."""
    records = []
    for row in captured:
        if 'protocol_witness' not in row:
            continue
        pointers, errors = [], []
        prefix, public = row['private_words'], row['public_words']
        words = row['words']
        if len(words)!=prefix+public or public!=len(row['requirements'])+1 or words[prefix]!=row['descriptor']:
            errors.append('witness extent or descriptor differs')
            records.append(dict(row, errors=errors, pointers=pointers));continue
        pointers.append(dict(word=prefix, kind='descriptor', target=row['descriptor']))
        keys=[r for r in row['conditional_requirements'] if r['key']]
        if len(keys)!=len(row['arguments']) or len(keys)>prefix:
            errors.append('conditional key count differs')
        else:
            for i, (req, argument) in enumerate(zip(keys,row['arguments'])):
                slot=prefix-1-i
                if req['kind']!=0 or req['pack'] or req['value']:
                    errors.append('conditional key requires unsupported pack/value schema')
                elif words[slot]!=argument:
                    errors.append('conditional witness differs from constructor key')
                else:
                    pointers.append(dict(word=slot,kind='witness',target=argument))
            if any(words[:prefix-len(keys)]):
                errors.append('nonzero private storage lacks a typed schema')
        for i,req in enumerate(row['requirements'],prefix+1):
            pointer=words[i]
            if not pointer:continue  # Swift VFE permits null unused requirement slots.
            kind=req['kind']
            if kind in (7,8) and req.get('initializer',0)&1:
                # Keep the image's type expression instead of a completion
                # memo from another process. Swift resolves it in this process.
                pointer=req['initializer']
            if kind in (0,7,8):
                # The upstream associated-type ABI tags mangled names; otherwise
                # these are metadata/witness pointers, not accessor functions.
                role='typeref' if pointer&1 else 'metadata' if kind==7 else 'witness'
            elif 1<=kind<=6:
                role='data' if req['data'] else 'function'
            else:
                errors.append('unknown protocol requirement kind');continue
            pointers.append(dict(word=i,kind=role,target=pointer))
        records.append(dict(row,pointers=pointers,errors=sorted(set(errors))))
    return records



def generic_value(row, address, reference, refs, slide):
    key, m, w = row['key'], list(row['full_metadata']), row['witness']
    require(2 <= len(key) <= 64 and m[2] in (0x200,0x201,0x202) and m[3] == key[0]
            and m[4:3+len(key)] == key[1:], 'generic metadata key differs')
    flags, fields, offsets = row['descriptor_words']
    require(flags & 128 and flags & 31 in (17,18), 'not generic value metadata')
    count = len(key)-1
    end = 2+count
    if flags & 31 == 17 and offsets:
        require(offsets >= end, 'field offsets overlap generic arguments')
        end = offsets+(fields+1)//2
    if flags & 31 == 18 and fields >> 24:
        require(fields >> 24 == end, 'enum payload offset differs')
        end += 1
    if row['pattern_flags'] & 2:
        require(m[-1] == 0, 'nonzero metadata trailing flags')
        end += 1
    require(len(m) == end+2, 'metadata extent differs from descriptor')
    require(len(w) in (11,14) and w[8] <= w[9] and w[9] > 0 and not w[10] & 0x400000
            and len(w) == (14 if w[10] & 0x200000 else 11), 'unsupported value witness layout')

    normalized_key = [reference(p) for p in key]
    pointers = [dict(offset=8,ref=dict(local=len(m)*8))]
    layout = bytes.fromhex(row.get('layout',''))
    if not flags & 0x100000:
        require(not layout, 'layout string without descriptor flag')
        # Captures from older collectors may include the preceding word
        # even though the ABI does not describe it as a layout pointer.
        m[0] = 0
    if m[0]:
        if layout:
            layout_offset=(len(m)+len(w))*8
            pointers.append(dict(offset=0,ref=dict(local=layout_offset)))
            for slot, executable in layout_references(layout):
                target=struct.unpack_from('<Q',layout,slot)[0]
                ref = reference(target,executable,owner=address,address_point=16)
                pointers.append(dict(offset=layout_offset+slot,ref=ref))
        else:
            pointers.append(dict(offset=0,ref=refs.encode(m[0]-slide)))
    else:
        require(not layout, 'layout string without metadata prefix')
    pointers += [dict(offset=24+8*i,ref=ref) for i,ref in enumerate(normalized_key)]
    pointers += [dict(offset=(len(m)+i)*8,ref=reference(p,True))
                 for i,p in enumerate(w) if i<8 or i>10]
    words = list(m)+list(w)
    data = bytearray(struct.pack(f'<{len(words)}Q', *words))
    data.extend(layout + b'\0'*(-len(layout)%8))
    for p in pointers:
        struct.pack_into('<Q', data, p['offset'], 0)
    return dict(name=row['name'], owner=row['owner'], key=normalized_key,
                metadata_offset=16, data=data.hex(), pointers=pointers,
                **({'type_arguments':row['type_arguments']} if 'type_arguments' in row else {}))


def protocol_witness(row, address, reference, refs, slide):
    require(row.get('canonical') is True, 'noncanonical protocol witness')
    require(not row['errors'], '; '.join(row['errors']))
    key=[reference(row['descriptor']),reference(row['type'])]
    data=bytearray(struct.pack(f"<{len(row['words'])}Q",*row['words']))
    pointers=[]
    for pointer in row['pointers']:
        target,kind=pointer['target'],pointer['kind']
        if kind in ('witness','metadata'):
            ref=reference(target,owner=address,address_point=row['private_words']*8)
        else:
            ref=refs.encode(target-slide,executable=kind=='function')
        pointers.append(dict(offset=pointer['word']*8,ref=ref))
        struct.pack_into('<Q',data,pointer['word']*8,0)
    return dict(record_kind='protocol-witness',key=key,
                metadata_offset=row['private_words']*8,data=data.hex(),pointers=pointers)


def metatype(row, address, reference, refs, slide):
    """Upstream MetatypeMetadata: immutable value witnesses and instance type."""
    words, key = row['full_metadata'], row['key']
    require(row.get('canonical') is True and row.get('metadata_kind') == 0x304,
            'incomplete or noncanonical metatype')
    require(len(words) == 4 and len(key) == 2 and words[0] == 0 and
            words[2] == 0x304 and words[3] == key[1], 'metatype ABI extent or instance key differs')
    constructor = reference(key[0], True)
    instance = reference(key[1])
    pointers = [dict(offset=8, ref=refs.encode(words[1]-slide)), dict(offset=24, ref=instance)]
    return dict(name=row['name'], owner=row['owner'], record_kind='metatype',
                key=[constructor, instance], metadata_offset=16,
                data=struct.pack('<4Q', 0, 0, words[2], 0).hex(), pointers=pointers)


EXPORTERS = {'generic-value': generic_value, 'protocol-witness': protocol_witness, 'metatype': metatype}


def export(family, row, address, reference, refs, slide):
    require(family in EXPORTERS, 'unsupported Swift ABI export family: ' + family)
    return EXPORTERS[family](row, address, reference, refs, slide)
