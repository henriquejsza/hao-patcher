"""Compare indexed metadata by image path, independently of index remapping writers.

The inventory is format-specific and refuses unsupported roots. It covers retained
ObjC list-lists, global class/protocol owners, Swift conformance/descriptor owners,
and cached-loader references. Replacement objects use the explicit emission plan.
"""
from collections import Counter
from pathlib import Path
import json
import struct

from .exports import require
from .objc_transfer import CachedReader
from .objc_tables import (family_string, read_table as objc_table,
                          relative_list_index_edits, template_class_objects)
from .slides import family_slides
from .swift_refs import PRESPECIALIZATION_ABIS, optimization_header, read_table as swift_table, image_index_map
from .loader_generation import read_set, sha


ROOT = Path(__file__).resolve().parents[2]
SOURCES = ('src/dyld_rebuild/image_indexes.py', 'tools/check-image-indexes.py',
           'src/dyld_rebuild/objc_tables.py', 'src/dyld_rebuild/objc_transfer.py',
           'src/dyld_rebuild/swift_refs.py', 'src/dyld_rebuild/loader_generation.py',
           'src/dyld_rebuild/slides.py', 'src/dyld_rebuild/cache.py',
           'src/dyld_rebuild/candidate.py')
COVERAGE = ('objc_list_lists', 'swift_type', 'swift_metadata', 'swift_foreign',
            'swift_descriptors', 'objc_class', 'objc_protocol', 'cached_loader_refs', 'function_variants')


def path_at(order, index):
    require(type(index) is int and 0 <= index < len(order), 'image index outside identity table')
    return order[index]


def swift_owners(table, order):
    """Logical identity ignores duplicate-row ordering, retaining multiplicity."""
    return Counter((a, b, (raw >> 1) & ((1 << 47)-1), path_at(order, raw >> 48))
                   for _, a, b, raw in table.rows)


def difference(expected, actual):
    return dict(missing=[dict(identity=list(k), count=n) for k,n in sorted((expected-actual).items())],
                unexpected=[dict(identity=list(k), count=n) for k,n in sorted((actual-expected).items())])


def pins(family):
    return [dict(path=str(f.path.resolve()), size=f.path.stat().st_size, sha256=sha(f.path)) for f in family.files]


def objc_roots(family):
    from .objc_tables import objc_header
    base=family.main.mappings[0].address
    _,_,fields=objc_header(family)
    return {kind:objc_table(family.read,lambda a:family_string(family,a),base+fields[i],kind,base)
            for kind,i in [('class',5),('protocol',6)]}


def swift_roots(family):
    base=family.main.mappings[0].address
    offset,size=struct.unpack_from('<QQ',family.main.data,376)
    require(size==104,'unsupported Swift header extent')
    return base,optimization_header(family.read(base+offset,size))


def descriptors(family, reader, base, roots, order):
    """Descriptor-map slots with their owners. The u16 aux value is an ObjC header-info index (MH order), as in the
    conformance tables, so `order` must be the ObjC image order. FACT on 262FA161 (26B131): all 365,361 occupied
    slots' aux values name the address owner in header-info order; none match the dyld image table."""
    data=base+roots['prespecialization']
    require(struct.unpack('<II',family.read(data,8)) in PRESPECIALIZATION_ABIS,'unsupported prespecialization data')
    descriptor=reader.ptr(data+40)
    require(descriptor!=0,'required descriptor map missing')
    count=struct.unpack('<Q',family.read(descriptor,8))[0]
    require(0<count<=1_000_000,'descriptor map count invalid')
    auxiliary=descriptor+8+count*8
    values=Counter()
    for slot in range(count):
        target=reader.ptr(descriptor+8+slot*8)
        if target:
            index=struct.unpack('<H',family.read(auxiliary+slot*2,2))[0]
            values[(slot,target,path_at(order,index))]+=1
    return values


def function_variants(family):
    address,size=struct.unpack_from('<QQ',family.main.data,520)
    require(address and size>=8,'required function-variant inventory missing')
    version,count=struct.unpack('<II',family.read(address,8))
    require(version==1 and size==8+count*32,'unsupported function-variant inventory')
    order=[p for p,_ in family.images]
    rows=Counter()
    for i in range(count):
        fixup,table,mh,flags,index,words=struct.unpack('<QQQIHH',family.read(address+8+i*32,32))
        owner=path_at(order,index)
        require(family.images[index][1]==mh,'function variant header and image index disagree')
        rows[(fixup,table,owner,flags,words)]+=1
    return rows


def cached_refs(family):
    address=struct.unpack_from('<Q',family.main.data,328)[0]
    require(address!=0,'required cached loader set missing')
    size=struct.unpack('<I',family.read(address+8,4))[0]
    require(80<=size<=1<<28,'cached loader set extent invalid')
    parsed=read_set(family.read(address,size),len(family.images),app=False)
    order=[r['path'] for r in parsed['loaders']]
    require(order==[p for p,_ in family.images],'cached loader identity order differs')
    refs={}
    for row in parsed['loaders']:
        def resolve(ref):
            if ref==0x7fff:return '<missing>'
            require(not ref&0x8000,'cached loader contains app reference')
            return path_at(order,ref)
        deps=tuple((resolve(ref),kind) for ref,kind in zip(row['dependencies'],row['dependency_attributes']))
        twin='<no-twin>' if row['twin_index']==0xffff else resolve(row['twin_index'])
        binds=[]
        for binding in row['binds']+row['override_binds']:
            if 'index' not in binding:continue
            require(not binding['app'],'cached bind names app loader')
            binds.append(path_at(order,binding['index']))
        refs[row['path']]=(deps,twin,tuple(binds))
    return refs


def audit(source, family, metadata_plan):
    before=CachedReader(source);after=CachedReader(family)
    old=[before.objc_images[i] for i in range(len(before.objc_images))]
    new=[after.objc_images[i] for i in range(len(after.objc_images))]
    mapping=image_index_map(old,new)
    checks={};wrong=[]
    templates=template_class_objects(source,family_slides(source))
    lists=relative_list_index_edits(source,before.ptr,mapping,templates,include_entries=True)
    for entry in lists['all_entries']:
        original=struct.unpack('<Q',source.read(entry['field'],8))[0]
        actual=struct.unpack('<Q',family.read(entry['field'],8))[0]
        index=actual&65535
        if index>=len(new) or old[entry['index']]!=new[index] or original>>16!=actual>>16:
            wrong.append(dict(table='objc_list_lists',address=hex(entry['field']),
                              expected=old[entry['index']],actual=new[index] if index<len(new) else None,
                              offset_preserved=original>>16==actual>>16))
    checks['objc_list_lists']=dict(entries=lists['entries'],lists=lists['lists'],
                                   template_objects=lists['template_objects'])
    oldbase,oldroots=swift_roots(source);newbase,newroots=swift_roots(family)
    require(oldbase==newbase,'cache base changed')
    for kind in ('type','metadata','foreign'):
        original=swift_table(source.read,oldbase+oldroots[kind],kind)
        actual=swift_table(family.read,newbase+newroots[kind],kind)
        delta=difference(swift_owners(original,old),swift_owners(actual,new))
        if delta['missing'] or delta['unexpected']:wrong.append(dict(table='swift_'+kind,**delta))
        checks['swift_'+kind]=dict(entries=len(original.rows))
    expected=descriptors(source,before,oldbase,oldroots,old)
    actual=descriptors(family,after,newbase,newroots,new)
    delta=difference(expected,actual)
    if delta['missing'] or delta['unexpected']:wrong.append(dict(table='swift_descriptors',**delta))
    checks['swift_descriptors']=dict(entries=sum(expected.values()))
    oldtables=objc_roots(source);newtables=objc_roots(family)
    replaced=set(metadata_plan['replaced_images'])
    require(replaced=={p for p,a in source.images if dict(family.images).get(p)!=a},
            'replacement identity plan differs from image addresses')
    for kind,plural in [('class','classes'),('protocol','protocols')]:
        expected=Counter((e.name.hex(),a,path_at(old,i)) for e in oldtables[kind].entries
                         for a,i in e.objects if path_at(old,i) not in replaced)
        for r in metadata_plan[plural]:expected[(r['name'].encode().hex(),r['address'],r['image'])]+=1
        actual=Counter((e.name.hex(),a,path_at(new,i)) for e in newtables[kind].entries for a,i in e.objects)
        delta=difference(expected,actual)
        if delta['missing'] or delta['unexpected']:wrong.append(dict(table='objc_'+kind,**delta))
        checks['objc_'+kind]=dict(entries=sum(expected.values()),replacement_objects=len(metadata_plan[plural]))
    original_variants=function_variants(source);actual_variants=function_variants(family)
    delta=difference(original_variants,actual_variants)
    if delta['missing'] or delta['unexpected']:wrong.append(dict(table='function_variants',**delta))
    checks['function_variants']=dict(entries=sum(original_variants.values()),version=1)
    original=cached_refs(source);actual=cached_refs(family)
    # Regenerated bindings may legitimately change provider for replaced images.
    # Dependencies/twins must preserve identities for every retained image. Full
    # bind targets are independently checked by RC's program/provider oracles.
    for path,record in original.items():
        if path in replaced:continue
        if path not in actual or record[:2]!=actual[path][:2]:
            wrong.append(dict(table='cached_loader_refs',image=path,
                              expected=record[:2],actual=actual.get(path,())[:2]))
    checks['cached_loader_refs']=dict(entries=len(actual),retained_compared=len(original)-len(replaced),
                                     binding_indexes_range_checked=sum(len(r[2]) for r in actual.values()))
    return dict(schema=1,result='PASS' if not wrong else 'REFUSED',checks=checks,
                wrong_entries=len(wrong),checked_entries=sum(r['entries'] for r in checks.values()),wrong=wrong,source_objc_images=len(old),candidate_objc_images=len(new))


def verify_report(report, family_pins, metadata_plan_pin, *, source_manifest=None, source_manifest_sha256=None):
    require(report['schema']==1 and report['result']=='PASS' and report['wrong_entries']==0 and not report['wrong'],
            'image-index invariant failed')
    require(set(report['checks'])==set(COVERAGE) and all(r['entries']>0 for k,r in report['checks'].items() if k!='function_variants')
            and report['checks']['function_variants']['entries']>=0
            and report['checks']['function_variants']['version']==1
            and report['checked_entries']==sum(r['entries'] for r in report['checks'].values()),
            'image-index invariant coverage incomplete')
    canonical=lambda rows:[(Path(r['path']).resolve(),r['size'],r['sha256']) for r in rows]
    require(canonical(report['family_files'])==canonical(family_pins),'image-index invariant covers another family')
    require((source_manifest is None)==(source_manifest_sha256 is None),'current source requires manifest and SHA256')
    if source_manifest is not None:
        from .run_prepare import open_source_family
        source,_=open_source_family(source_manifest,source_manifest_sha256)
        try:expected_rows=pins(source)
        finally:source.close()
        expected={Path(r['path']).name:r for r in expected_rows}
        expected_count=len(expected)
    else:
        expected_rows=json.loads((ROOT/'config/relayout-inputs.json').read_text())['files']
        expected={Path(r['path']).name:r for r in expected_rows};expected_count=7
    require(len(report['source_files'])==expected_count and len({Path(r['path']).name for r in report['source_files']})==expected_count,
            'image-index invariant source inventory differs')
    require(all(Path(r['path']).name in expected and r['sha256']==expected[Path(r['path']).name]['sha256']
                and r['size']==expected[Path(r['path']).name]['size'] for r in report['source_files'])
            ,'image-index invariant source differs')
    require(report['metadata_plan']['sha256']==metadata_plan_pin['sha256'],'image-index metadata plan differs')
    require(report['source_hashes']=={p:sha(ROOT/p) for p in SOURCES},'image-index checker source drift')
    for r in report['source_files']+[report['metadata_plan']]:
        require(sha(Path(r['path']))==r['sha256'],'image-index evidence input drift')
    return {k:report[k] for k in ('result','checks','wrong_entries','checked_entries')}
