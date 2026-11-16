"""Restore image-defined associated witnesses, including inherited catalog rows.

A resolved associated witness is a process-local memo. Its generic metadata may
not yet have a MetadataCacheEntry in the consuming process. Read the original
symbolic initializer from the cache's conformance descriptors, never that memo.
Layouts follow Swift ABI Metadata.h / MetadataValues.h / GenericContext.h.
"""
import argparse
from collections import Counter
from functools import lru_cache
import json
from pathlib import Path
import struct

from .exports import require


def initializers(reader, descriptor):
    def u32(address):return struct.unpack('<I',reader.read(address,4))[0]
    def relative(address, indirect=False):
        offset=struct.unpack('<i',reader.read(address,4))[0]
        if not offset:return 0
        target=address+(offset & ~1 if indirect else offset)
        return reader.ptr(target) if indirect and offset&1 else target
    protocol=relative(descriptor,True)
    require(protocol!=0,'witness has no protocol descriptor')
    flags=u32(descriptor+12)
    start=protocol+24+12*u32(protocol+12)
    count=u32(protocol+16)
    pattern=relative(descriptor+8)
    # Retroactive context (4), conditional requirements (12 each), then pack
    # shape descriptors (8 each) precede resilient witness pairs (8 each).
    cursor=descriptor+16+4*bool(flags&64)+12*((flags>>8)&255)+8*(flags>>24)
    overrides={}
    if flags&0x10000:
        number=u32(cursor);cursor+=4
        for index in range(number):
            address=cursor+index*8
            overrides[relative(address,True)]=relative(address+4)
        cursor+=number*8
    pattern_words=struct.unpack('<H',reader.read(cursor,2))[0] if flags&0x20000 else count+1
    result={}
    for index in range(count):
        requirement=start+index*8
        kind=u32(requirement)&15
        if kind not in (7,8):continue
        value=reader.ptr(pattern+8*(index+1)) if pattern and index+1<pattern_words else 0
        value=overrides.get(requirement,value)
        if not value:value=relative(requirement+4)
        result[index+1]=(kind,value)
    return result


def normalize(catalog, family):
    from .objc_emit import FamilyReader
    from .swift_metadata import References
    from .swift_graph import record_id
    rows=catalog.get('witnesses',[])
    if not rows:return catalog,dict(witnesses=0,associated_slots=0,changed_slots=0,changed_witnesses=0,changes=[])
    reader,refs=FamilyReader(family),References(family)
    slots=lru_cache(maxsize=None)(lambda address:initializers(reader,address))
    fixed=[];changes=[];counts=Counter()
    for row in rows:
        pointers={p['offset']:p['ref'] for p in row['pointers']}
        changed=False;data=bytearray.fromhex(row['data'])
        for word,(kind,value) in slots(refs.decode(row['key'][0])).items():
            counts['associated_slots']+=1
            if not value&1:
                counts['static_initializers']+=1
                continue
            counts['symbolic_initializers']+=1
            offset=row['metadata_offset']+word*8
            require(offset+8<=len(data),'associated witness slot exceeds catalog record')
            initializer=refs.encode(value)
            if pointers.get(offset)!=initializer:
                changes.append(dict(record=record_id(row),kind=kind,offset=offset,
                                    previous=pointers.get(offset),initializer=initializer))
                pointers[offset]=initializer;struct.pack_into('<Q',data,offset,0);changed=True
        fixed.append(dict(row,data=data.hex(),pointers=[dict(offset=o,ref=r) for o,r in sorted(pointers.items())])
                     if changed else row)
    report=dict(witnesses=len(rows),**counts,changed_slots=len(changes),
                changed_witnesses=len({r['record'] for r in changes}),changes=changes)
    return dict(catalog,witnesses=fixed),report


def audit_installed(family, witnesses):
    """Compare emitted slots with image initializers, counting aliases once."""
    from .objc_emit import FamilyReader
    reader=FamilyReader(family)
    slots=lru_cache(maxsize=None)(lambda address:initializers(reader,address))
    tables={}
    for row in witnesses:tables.setdefault(row['address'],[]).append(row['id'])
    counts=Counter();stale=[]
    for address,identities in tables.items():
        for word,(kind,expected) in slots(reader.ptr(address)).items():
            counts['associated_slots']+=1
            counts['associated_type_slots' if kind==7 else 'associated_conformance_slots']+=1
            if not expected&1:continue
            counts['symbolic_initializers']+=1
            actual=reader.ptr(address+word*8)
            if actual!=expected:
                stale.append(dict(records=identities,address=address,slot=word,kind=kind,
                                  actual=actual,expected=expected))
    return dict(witness_records=len(witnesses),witness_tables=len(tables),**counts,
                stale_slots=len(stale),affected_tables=len({r['address'] for r in stale}),
                complete=not stale,stale=stale)


def main(argv):
    from .loader_generation import LoaderFamily
    from .swift_metadata import write_json,provenance
    parser=argparse.ArgumentParser(description=__doc__)
    for name in ('cache','catalog','output'):parser.add_argument(name,type=Path)
    parser.add_argument('--installed',action='store_true',
                        help='Audit the built cache read-only; exit 1 if stale slots remain')
    args=parser.parse_args(argv)
    family=LoaderFamily(args.cache)
    try:
        catalog=json.loads(args.catalog.read_text())
        if args.installed:
            from .swift_installed import records
            installed,_=records(catalog,family)
            report=audit_installed(family,[r for r in installed if r['kind']=='protocol-witness'])
        else:catalog,report=normalize(catalog,family)
        args.output.mkdir(parents=True,exist_ok=False)
        if not args.installed:write_json(args.output/'catalog.json',catalog)
        write_json(args.output/'initializers.json',report)
        write_json(args.output/'build.json',provenance([args.catalog,Path(__file__),*[f.path for f in family.files]],
            operation='audit-installed-witness-initializers' if args.installed else 'normalize-witness-initializers',
            native_acceptance='OPEN'))
        print(json.dumps({k:v for k,v in report.items() if k not in ('changes','stale')}))
    finally:family.close()
    return int(args.installed and not report['complete'])
