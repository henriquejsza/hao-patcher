"""Checked reservations for the next scratch metadata subcache."""
import hashlib
import json
import struct
from pathlib import Path
from .exports import require

SLOTS = {'selector_names','class_names','protocol_names','selector','class','protocol',
         'ro','rw','imageinfo','new_protocol','provider_rw','category_lists','path_trie',
         'patch_table','cached_pbl','program_pbl','program_trie','atlas','slide_info'}
SWIFT_SLOTS = {'swift_metadata', 'swift_table'}
METATYPE_SLOTS = {'swift_metatype_table'}
NORMALIZED_SLOTS = {'swift_normalized_table'}
WITNESS_SLOTS = {'swift_witness_table','swift_runtime_code','swift_runtime_data'}


def validate(layout, family, provider_plan):
    require(layout.get('schema') == 1, 'unknown metadata allocation schema')
    require(layout['final_images'] == len(family.images) and layout['final_subcaches'] == len(family.files),
            'metadata final graph counts differ')
    require(layout['subcache_suffix'] == f'.{len(family.files):02d}', 'metadata subcache suffix differs')
    rows = layout['mappings']
    require(len(rows) == 3, 'metadata needs header, writable and read-only mappings')
    require([(m['maximum'],m['initial'],m['flags']) for m in rows] == [(5,5,0),(3,3,0),(1,1,0)],
            'unknown metadata mapping protections')
    require(rows[0]['file_offset'] == 0 and rows[0]['size'] == layout['prefix_size'], 'metadata header extent differs')
    occupied = [(m.address,m.address+m.size) for file in family.files for m in file.mappings]
    occupied += [(r['address'],r['address']+r['size']) for r in provider_plan['preserved_nonfile_reservations']]
    region = provider_plan['shared_region']
    for i,mapping in enumerate(rows):
        address,size,offset = (mapping[k] for k in ('address','size','file_offset'))
        require(all(type(v) is int and v >= 0 and v%4096 == 0 for v in (address,size,offset)) and size > 0,
                'metadata mapping alignment/extent')
        if i:
            prior=rows[i-1]
            require(offset == prior['file_offset']+prior['size'] and address >= prior['address']+prior['size'],
                    'metadata mappings overlap or file offsets have gaps')
        require(region['start'] <= address and address+size+region['max_slide'] <= region['start']+region['size'],
                'metadata mapping exceeds slid shared region')
        require(not any(address < end and start < address+size for start,end in occupied),
                'metadata overlaps an existing mapping or reservation')
    current=dict(family.images)
    require(all(current.get(p['path']) == p['placement']['provider_header_address'] for p in provider_plan['providers']),
            'provider headers moved after allocation planning')
    slots={k:v for k,v in layout.items() if isinstance(v,dict) and set(v)=={'address','reserve'}}
    contracts=[SLOTS,SLOTS | SWIFT_SLOTS]
    contracts += [SLOTS | SWIFT_SLOTS | WITNESS_SLOTS | m | n
                  for m in (set(),METATYPE_SLOTS) for n in (set(),NORMALIZED_SLOTS)]
    require(set(slots) in contracts, 'metadata slot contract missing or unexpected')
    intervals=[]
    for name,row in slots.items():
        address,size=row['address'],row['reserve']
        require(type(address) is int and type(size) is int and size>0 and address%8 == 0,'invalid metadata slot')
        intervals.append((address,address+size,name))
        owners=[m for m in rows if m['address'] <= address and address+size <= m['address']+m['size']]
        require(len(owners)==1,'metadata slot outside data mappings')
        writable=name in {'rw','new_protocol','provider_rw','swift_metadata','swift_runtime_data'}
        require(owners[0]['initial'] == (5 if name=='swift_runtime_code' else 3 if writable else 1),'metadata slot protection differs')
    intervals.sort()
    require(all(a[1] <= b[0] for a,b in zip(intervals,intervals[1:])),'metadata slots overlap')
    # 27: main's TPRO regions (header +512) are left to dyld (inferred: read-only after startup); no slot goes there.
    offset,count=struct.unpack_from('<II',family.main.data,512)
    tpro=[struct.unpack_from('<QQ',family.main.data,offset+16*i) for i in range(count)]
    require(not any(s < a+n and a < e for s,e,_ in intervals for a,n in tpro),'metadata slot overlaps a TPRO region')
    for name in ('selector','class','protocol','ro','rw'):
        require(-(1<<31) <= slots[name]['address']-layout['legacy_objc_root'] < 1<<31,
                'ObjC legacy root relative offset overflows')
    selector=slots['selector_names']
    require(-(1<<31) <= selector['address']-layout['selector_base'] and
            selector['address']+selector['reserve']-layout['selector_base'] <= 1<<31,
            'new selector pool exceeds signed relative range')
    count=len(family.images)
    pool_size=sum(len(path.encode())+1 for path,_ in family.images)
    header_end=family.main.mapping_offset+len(rows)*(32+56)+count*64+pool_size
    require(header_end <= layout['prefix_size'],'metadata full x86 image lists exceed prefix')
    if 'swift_runtime_code' in slots:
        require(rows[0]['address']+header_end<=slots['swift_runtime_code']['address'],
                'witness runtime overlaps metadata image lists')
    return {'classification':'allocation geometry checked; metadata content and target acceptance not checked here',
            'header_used_end':header_end,'slot_count':len(slots),'mapping_count':len(rows),
            'signed_content_bytes':rows[-1]['file_offset']+rows[-1]['size'],
            'provider_headers_unchanged':len(provider_plan['providers'])}


def load(path, family, provider_plan_path):
    plan_bytes=Path(provider_plan_path).read_bytes()
    layout=json.loads(Path(path).read_text())
    require(layout['provider_plan_sha256'] == hashlib.sha256(plan_bytes).hexdigest(),'metadata provider plan digest differs')
    validate(layout,family,json.loads(plan_bytes))
    return layout


def slot_file_offset(layout, name, size, *, alignment=8):
    require(name in SLOTS | SWIFT_SLOTS | WITNESS_SLOTS | METATYPE_SLOTS | NORMALIZED_SLOTS and type(size) is int and size>0,'unknown slot or empty metadata blob')
    require(alignment>0 and alignment&(alignment-1)==0,'invalid blob alignment')
    slot=layout[name]
    require(size<=slot['reserve'] and slot['address']%alignment==0,'blob exceeds reservation or alignment')
    matches=[m for m in layout['mappings'] if m['address'] <= slot['address'] and
             slot['address']+size <= m['address']+m['size']]
    require(len(matches)==1,'metadata blob outside mapping')
    mapping=matches[0]
    return mapping['file_offset']+slot['address']-mapping['address']
