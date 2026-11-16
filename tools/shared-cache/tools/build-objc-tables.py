#!/usr/bin/env python3
"""Emit checked ObjC table blobs in fresh scratch; never modify a cache family.

The tables subcommand consumes explicit provider identity/canonicalization data.
The headers subcommand requires final cached-loader addresses. The explicitly
incomplete bootstrap subcommand emits zero PBL fields for the offline generator.
"""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import struct
import subprocess
import sys
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'src'))
from dyld_rebuild.cache import CacheFamily,commands
from dyld_rebuild.candidate import CandidateFamily
from dyld_rebuild.exports import Refusal,require
from dyld_rebuild.objc_transfer import CachedReader,sections
from dyld_rebuild.objc_tables import (NameEntry,read_table,family_string,writer_fixture,
                                     rewrite_objects,decode_header_info,emit_header_info,relative_list_index_edits,template_class_objects,optimization_roots,check_scalar_edits,checked_loader_addresses)


def sha(path):
    h=hashlib.sha256()
    with Path(path).open('rb') as f:
        for b in iter(lambda:f.read(8*1024*1024),b''):h.update(b)
    return h.hexdigest()


def number(value):
    require(type(value) in (str,int),'invalid address type')
    return int(value,0) if type(value) is str else value


def fresh(path):
    path=Path(path).resolve()
    require(not path.exists(),'output must be fresh work directory')
    path.mkdir(parents=True)
    return path


def source_family(args=None):
    path=getattr(args,'source_manifest',None);expected=getattr(args,'source_manifest_sha256',None)
    require((path is None)==(expected is None),'explicit source requires manifest and SHA256')
    if path is not None:
        from dyld_rebuild.run_prepare import open_source_family
        return open_source_family(path,expected)
    pins=json.loads((ROOT/'config/relayout-inputs.json').read_text())
    for p in pins['files']:
        path=ROOT/p['path']
        require(path.stat().st_size==p['size'] and sha(path)==p['sha256'],'source cache pin differs: '+p['path'])
    return CacheFamily(ROOT/pins['main']),pins


def read_original(c):
    base=c.main.mappings[0].address
    from dyld_rebuild.objc_tables import objc_header
    opts,_,fields=objc_header(c)
    tables={kind:read_table(c.read,lambda a:family_string(c,a),base+fields[index],kind,base)
            for kind,index in [('selector',4),('class',5),('protocol',6)]}
    rows=decode_header_info(c.read,base+fields[2],base+fields[3])
    paths={a:p for p,a in c.images}
    order=[paths[r[0]] for r in rows]
    return base,opts,fields,tables,rows,order


def writer(out):
    spec=importlib.util.spec_from_file_location('objc_writer_build',ROOT/'tools/objc-table-writers/build.py')
    m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)
    return m.build(out/'writer')


def emit_table(binary,out,name,entries,kind,base,address,reserve,order=None):
    fixture=writer_fixture(entries,kind,base,address,reserve,order)
    input_path=out/(name+'.input');output_path=out/(name+'.bin')
    input_path.write_bytes(fixture)
    command=[str(binary),str(input_path),str(output_path)]
    p=subprocess.run(command,capture_output=True,text=True)
    require(p.returncode==0,'Apple writer refused: '+p.stderr)
    data=output_path.read_bytes();keymap={e.address:e.name for e in entries}
    def read(a,n):
        require(address<=a and a+n<=address+len(data),'emitted table read outside blob')
        return data[a-address:a-address+n]
    parsed=read_table(read,keymap.__getitem__,address,kind,base)
    expected={e.name:(e.address,e.objects) for e in entries}
    actual={e.name:(e.address,e.objects) for e in parsed.entries}
    require(expected==actual,'independent ObjC table roundtrip differs')
    return dict(file=output_path.name,address=hex(address),bytes=len(data),sha256=sha(output_path),
                input_sha256=sha(input_path),source_lookup=json.loads(p.stdout),
                independent_roundtrip=True,command=command),data


def candidate_order(path,subcache_count,image_count):
    c=CandidateFamily(path,image_count=image_count,subcache_count=subcache_count)
    identities=[]
    try:
        for image,mh in c.images:
            info=[(a,n) for seg,name,a,n in sections(commands(c,mh)) if seg.startswith('__DATA') and name=='__objc_imageinfo']
            require(len(info)<=1,'multiple imageinfo sections')
            if info:
                require(info[0][1]==8,'unsupported final imageinfo size')
                identities.append((mh,image,info[0][0]))
        identities.sort()
        require(0<len(identities)<65536 and all(a[0]<b[0] for a,b in zip(identities,identities[1:])),'final ObjC identity shape differs')
        pins=[dict(path=str(f.path),size=f.path.stat().st_size,sha256=sha(f.path)) for f in c.files]
        return identities,pins,dict(c.images)
    finally:c.close()


def names(args):
    out=fresh(args.output_dir);allocation=json.loads(args.allocation.read_text());missing=json.loads(args.missing_names.read_text())
    require(allocation['schema']==1,'unknown names allocation schema')
    result={'schema':1,'pools':{}}
    for kind,key in [('selectors','selector_names'),('classes','class_names'),('protocols','protocol_names')]:
        values=missing[kind];require(len(values)==len(set(values)),'duplicate missing canonical name')
        base=number(allocation[key]['address']);reserve=number(allocation[key]['reserve']);data=bytearray();mapping={}
        for name in values:
            require(type(name) is str and name and '\0' not in name,'invalid missing canonical name')
            mapping[name]=base+len(data);data+=name.encode('utf-8')+b'\0'
        require(len(data)<=reserve,'canonical names exceed allocation')
        if kind=='selectors':
            relative_base=number(allocation['selector_base'])
            require(all(-(1<<31)<=a-relative_base<1<<31 for a in mapping.values()),'canonical selector relative overflow')
        path=out/(kind+'.bin');path.write_bytes(data);result[kind]=mapping
        result['pools'][kind]=dict(address=hex(base),bytes=len(data),reserve=reserve,path=str(path),sha256=sha(path))
    result['allocation_sha256']=sha(args.allocation);result['missing_names_sha256']=sha(args.missing_names)
    (out/'names.json').write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),mode='names',bytes=sum(r['bytes'] for r in result['pools'].values()))))


def oracle(args):
    out=fresh(args.output_dir);c,pins=source_family(args)
    try:
        base,opts,fields,tables,headerrows,order=read_original(c)
        binary,build=writer(out);results={}
        for kind,t in tables.items():
            record,data=emit_table(binary,out,kind+'-original',t.entries,kind,base,t.address,len(t.data),t.object_order)
            require(data==t.data,'original complete ObjC writer oracle differs: '+kind)
            record['complete_original_match']=True;results[kind]=record
        original_infos=[bytes(c.read(info,8)) for _,info,_ in headerrows]
        info_start=headerrows[0][1]
        require(all(info==info_start+8*i for i,(_,info,_) in enumerate(headerrows)),'original imageinfo not contiguous')
        header=emit_header_info([(mh,info,pbl) for (mh,_,pbl),info in zip(headerrows,original_infos)],
                                base+fields[2],base+fields[3],info_start)
        for name,address in [('ro',base+fields[2]),('rw',base+fields[3]),('imageinfo',info_start)]:
            require(header[name]==c.read(address,len(header[name])),'original header-info roundtrip differs')
        report=dict(schema=1,mode='original_complete_oracle',tables=results,header_info_count=len(headerrows),
                    header_roundtrip_bytes={k:len(v) for k,v in header.items()},source_pins=pins,writer_build=build)
    finally:c.close()
    finish(out,report)


def tables(args):
    out=fresh(args.output_dir);recipe=json.loads(args.metadata_plan.read_text());allocation=json.loads(args.allocation.read_text())
    require(recipe['schema']==allocation['schema']==1,'unknown ObjC input schema')
    identities,cpins,final_images=candidate_order(args.candidate,args.subcache_count,allocation['final_images']);final_order=[p for _,p,_ in identities]
    c,pins=source_family(args)
    try:
        base,opts,fields,original,headerrows,order=read_original(c)
        replacement=set(recipe['replaced_images'])
        # Replaced images with no ObjC header in the final family (26B131: OCLP's IO80211 shim).
        dropped=(replacement&set(order))-set(final_order)
        expected={path for path,mh in c.images if final_images.get(path)!=mh}
        require(replacement==expected and replacement<=final_images.keys(),'ObjC replacement image set differs from actual MH replacements')
        binary,build=writer(out);results={}
        for kind,table in original.items():
            if kind=='selector':
                byname={e.name:e for e in table.entries}
                for r in recipe['selectors']:
                    name=r['name'].encode('utf-8');address=number(r['address'])
                    require(name not in byname or byname[name].address==address,'existing selector identity changed')
                    require(-(1<<31)<=address-(base+fields[7])<1<<31,'selector outside relative method range')
                    byname[name]=NameEntry(name,address)
                entries=tuple(byname.values());object_order=None
            else:
                additions=[(r['name'].encode('utf-8'),number(r['name_address']),number(r['address']),r['image'])
                           for r in recipe[kind+'es' if kind=='class' else 'protocols']]
                # Replaced images without ObjC (26B131: libsystem_kernel/platform/pthread) own no table objects.
                entries,object_order=rewrite_objects(table,order,final_order,replacement&set(order),additions)
            a=allocation[kind]
            record,data=emit_table(binary,out,kind,entries,kind,base,number(a['address']),number(a['reserve']),object_order)
            record['original_bytes']=len(table.data);record['names']=len(entries);record['values']=sum(len(e.objects) for e in entries)
            results[kind]=record
        from dyld_rebuild.swift_refs import image_index_map
        source_reader=CachedReader(c)
        from dyld_rebuild.slides import family_slides
        # Swift class templates are outside classlists but carry preattached list-lists.
        templates=template_class_objects(c,family_slides(c))
        list_edits=relative_list_index_edits(c,source_reader.ptr,image_index_map(order,final_order,dropped),templates)
        list_edits['scalar_validation']=check_scalar_edits(c,list_edits['edits'])
        (out/'relative-list-index-edits.json').write_text(json.dumps(list_edits,indent=2)+'\n')
        (out/'objc-order.json').write_text(json.dumps(final_order,indent=2)+'\n')
        report=dict(schema=1,mode='lookup_blobs',tables=results,final_objc_count=len(final_order),
                    relative_lists={k:v for k,v in list_edits.items() if k!='edits'},
                    relative_list_edits_sha256=sha(out/'relative-list-index-edits.json'),
                    objc_order_sha256=sha(out/'objc-order.json'),candidate_pins=cpins,source_pins=pins,writer_build=build,
                    metadata_plan=dict(path=str(args.metadata_plan),sha256=sha(args.metadata_plan)),
                    allocation=dict(path=str(args.allocation),sha256=sha(args.allocation)),
                    preserved_selector_base=hex(base+fields[7]),preserved_selector_buffer_size=fields[8],
                    limitations=['Standalone lookup blobs; final header-info/PBL roots and whole cache publication are separate.'])
    finally:c.close()
    finish(out,report)


def descriptor_index_bytes(c,reader,descriptor,mapping,*,legacy_contract=True):
    """Read actual descriptor occupancy and transform only retained owner indexes."""
    from dyld_rebuild.swift_refs import remap_descriptor_indexes
    count=reader.number(descriptor)
    require(0 < count <= 1<<24,'prespecialized descriptor count exceeds checked bound')
    if legacy_contract:require(count==291294,'prespecialized descriptor count differs')
    aux_address=descriptor+8+8*count;aux=bytes(c.read(aux_address,count*2))
    entries=[(i,struct.unpack_from('<H',aux,i*2)[0]) for i in range(count) if reader.ptr(descriptor+8+i*8)]
    if legacy_contract:require(len(entries)==218471,'prespecialized occupied count differs')
    else:require(entries,'required prespecialized descriptor table is empty')
    new_aux=remap_descriptor_indexes(aux,entries,mapping)
    return aux_address,aux,new_aux,dict(descriptors=count,occupied=len(entries))


def headers(args):
    out=fresh(args.output_dir);recipe=json.loads(args.metadata_plan.read_text());allocation=json.loads(args.allocation.read_text())
    bootstrap_only=args.mode=='bootstrap'
    require(recipe['schema']==allocation['schema']==1,'unknown ObjC input schema')
    identities,cpins,final_images=candidate_order(args.candidate,args.subcache_count,allocation['final_images']);c,pins=source_family(args)
    try:
        base,opts,fields,original,headerrows,order=read_original(c)
        require(set(recipe['replaced_images'])=={path for path,mh in c.images if final_images.get(path)!=mh},
                'header replacement image set differs from actual MH replacements')
        final_order=[p for _,p,_ in identities]
        dropped=(set(recipe['replaced_images'])&set(order))-set(final_order)
        infos={p:bytes(c.read(row[1],8)) for p,row in zip(order,headerrows)}
        updates={r['image']:bytes.fromhex(r['bytes_hex']) for r in recipe['imageinfo']}
        require(len(updates)==len(recipe['imageinfo']),'duplicate explicit imageinfo')
        infos.update(updates)
        final_order=[p for _,p,_ in identities]
        if bootstrap_only:
            pbl={p:0 for p in final_order};loader_proof={'bootstrap_only':True,'final_publication_allowed':False}
        else:
            from dyld_rebuild.loader_generation import read_set
            pbl_document=json.loads(args.pbl_addresses.read_text())
            cached_bytes=args.cached_pbl.read_bytes();cached=read_set(cached_bytes,allocation['final_images'],app=False)
            candidate=CandidateFamily(args.candidate,image_count=allocation['final_images'],subcache_count=args.subcache_count)
            try:require([r['path'] for r in cached['loaders']]==[p for p,_ in candidate.images],'cached PBL identity order differs')
            finally:candidate.close()
            pbl_base=number(allocation['cached_pbl']['address'])
            require(len(cached_bytes)<=number(allocation['cached_pbl']['reserve']),'cached PBL reservation exceeded')
            pbl=checked_loader_addresses(pbl_document,cached['loaders'],pbl_base,len(cached_bytes),sha(args.cached_pbl))
            loader_proof=dict(bootstrap_only=False,pbl_addresses_sha256=sha(args.pbl_addresses),cached_pbl_sha256=sha(args.cached_pbl))
        require(set(final_order)<=infos.keys() and set(final_order)<=pbl.keys(),'missing final imageinfo/PBL identity')
        rows=[(mh,infos[p],number(pbl[p])) for mh,p,_ in identities]
        addresses={k:number(allocation[k]['address']) for k in ('ro','rw','imageinfo')}
        blobs=emit_header_info(rows,addresses['ro'],addresses['rw'],addresses['imageinfo'],bootstrap_only=bootstrap_only)
        outputs={}
        for kind,data in blobs.items():
            require(len(data)<=number(allocation[kind]['reserve']),'header allocation too small')
            path=out/(kind+'.bin');path.write_bytes(data)
            outputs[kind]=dict(file=path.name,address=hex(addresses[kind]),bytes=len(data),sha256=sha(path))
        def read(a,n):
            for k,d in blobs.items():
                start=addresses[k]
                if start<=a and a+n<=start+len(d):return d[a-start:a-start+n]
            raise Refusal('header roundtrip outside blobs')
        require(decode_header_info(read,addresses['ro'],addresses['rw'],bootstrap_only=bootstrap_only)==tuple((mh,addresses['imageinfo']+8*i,pbladdr)
                for i,(mh,info,pbladdr) in enumerate(rows)),'final header roundtrip differs')
        # Preserve every Swift key/descriptor/protocol address. Only owner indexes
        # change, under the separately proved pinned-input Swift preservation plan.
        from dyld_rebuild.swift_refs import (PRESPECIALIZATION_ABIS,optimization_header,read_table as read_swift,image_index_map,
                                             remap_conformance_indexes,remap_descriptor_indexes)
        mapping=image_index_map(order,final_order,dropped);reader=CachedReader(c)
        swift=optimization_header(c.read(base+struct.unpack_from('<Q',c.main.data,376)[0],104))
        swift_outputs={}
        for kind in ('type','metadata','foreign'):
            table=read_swift(c.read,base+swift[kind],kind);data=remap_conformance_indexes(table,mapping)
            path=out/('swift-'+kind+'.bin');path.write_bytes(data)
            swift_outputs[kind]=dict(file=path.name,address=hex(table.address),bytes=len(data),sha256=sha(path),
                                    expected_sha256=hashlib.sha256(table.data).hexdigest())
        data_root=base+swift['prespecialization']
        require(struct.unpack('<II',c.read(data_root,8)) in PRESPECIALIZATION_ABIS,'prespecialized data version differs')
        descriptor=reader.ptr(data_root+40)
        aux_address,aux,new_aux,descriptor_counts=descriptor_index_bytes(c,reader,descriptor,mapping,legacy_contract=getattr(args,'source_manifest',None) is None)
        path=out/'swift-descriptor-indexes.bin';path.write_bytes(new_aux)
        swift_outputs['descriptor_indexes']=dict(file=path.name,address=hex(aux_address),bytes=len(new_aux),sha256=sha(path),
                                                expected_sha256=hashlib.sha256(aux).hexdigest())
        libobjc=dict(c.images)['/usr/lib/libobjc.A.dylib']
        legacy_roots=[a for seg,name,a,n in sections(commands(c,libobjc)) if seg=='__TEXT' and name=='__objc_opt_ro']
        require(len(legacy_roots)==1,'legacy ObjC root absent/ambiguous');legacy_address=legacy_roots[0]
        root_addresses={k:number(allocation[k]['address']) for k in ('ro','rw','selector','class','protocol')}
        original_root=bytes(c.read(opts,struct.unpack_from('<Q',c.main.data,472)[0]));legacy_root=bytes(c.read(legacy_address,48))
        new_root,new_legacy=optimization_roots(original_root,legacy_root,base,legacy_address,root_addresses)
        root_edits=[dict(address=hex(a),expected=before.hex(),replacement=after.hex()) for a,before,after in
                    ((opts,original_root,new_root),(legacy_address,legacy_root,new_legacy))]
        (out/'root-edits.json').write_text(json.dumps(root_edits,indent=2)+'\n')
        report=dict(schema=1,mode='bootstrap_only_header_blobs' if bootstrap_only else 'header_blobs',loader_proof=loader_proof,outputs=outputs,swift_outputs=swift_outputs,root_edits_sha256=sha(out/'root-edits.json'),identities=[dict(image=p,mh=hex(mh),index=i,imageinfo_section=hex(info),
                    pbl=hex(number(pbl[p])),imageinfo_bytes=infos[p].hex()) for i,(mh,p,info) in enumerate(identities)],
                    candidate_pins=cpins,source_pins=pins,
                    metadata_plan_sha256=sha(args.metadata_plan),allocation_sha256=sha(args.allocation),swift_descriptor_counts=descriptor_counts)
    finally:c.close()
    finish(out,report)


def finish(out,report):
    report['sources']={p:sha(ROOT/p) for p in ('src/dyld_rebuild/objc_tables.py','tools/build-objc-tables.py',
                                            'tools/objc-table-writers/writer.cpp','tools/objc-table-writers/build.py')}
    (out/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(dict(output=str(out),mode=report['mode'])))


def main():
    ap=argparse.ArgumentParser(description=__doc__);sub=ap.add_subparsers(dest='mode',required=True)
    p=sub.add_parser('names');p.add_argument('--output-dir',type=Path,required=True)
    p.add_argument('--allocation',type=Path,required=True);p.add_argument('--missing-names',type=Path,required=True)
    for mode in ('oracle','tables','headers','bootstrap'):
        p=sub.add_parser(mode);p.add_argument('--output-dir',type=Path,required=True)
        p.add_argument('--source-manifest',type=Path);p.add_argument('--source-manifest-sha256')
        if mode!='oracle':
            p.add_argument('--subcache-count',type=int,required=True);p.add_argument('--candidate',type=Path,required=True);p.add_argument('--metadata-plan',type=Path,required=True)
            p.add_argument('--allocation',type=Path,required=True)
        if mode=='headers':
            p.add_argument('--pbl-addresses',type=Path,required=True);p.add_argument('--cached-pbl',type=Path,required=True)
    args=ap.parse_args()
    try:(headers if args.mode=='bootstrap' else globals()[args.mode])(args)
    except (Refusal,ValueError,KeyError) as e:print('REFUSED: '+str(e),file=sys.stderr);return 2
    return 0
if __name__=='__main__':sys.exit(main())
