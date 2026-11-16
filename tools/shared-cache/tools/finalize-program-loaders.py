#!/usr/bin/env python3
"""Install every validated required program set into a fresh pinned cache copy."""
import argparse
import json
import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1];sys.path.insert(0,str(ROOT/'src'))
from dyld_rebuild.cache import CacheFamily
from dyld_rebuild.candidate import CandidateFamily
from dyld_rebuild.codesign import inspect
from dyld_rebuild.emit_cache import sign_with_uuid
from dyld_rebuild.exports import require
from dyld_rebuild.loader_generation import cache_manifest,read_set,sha
from dyld_rebuild.cache_exports import path_trie
from dyld_rebuild.graph_contract import checked_manifest
from dyld_rebuild.program_pool import build_pool,original_inventory,validate_retirement,main_identity,MIRRORING


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--cache-manifest',type=Path,required=True)
    ap.add_argument('--program-report',type=Path,required=True)
    ap.add_argument('--program-report-sha256')
    ap.add_argument('--source-manifest',type=Path)
    ap.add_argument('--source-manifest-sha256')
    ap.add_argument('--output',type=Path,required=True)
    args=ap.parse_args();output=args.output.resolve()
    main_path,count,images,pins=cache_manifest(args.cache_manifest)
    source=CandidateFamily(main_path,image_count=images,subcache_count=count-1)
    handles=[];maps={}
    try:
        manifest=json.loads(args.cache_manifest.read_text())
        allocation=json.loads(Path(manifest['components']['allocation']['path']).read_text())
        report=json.loads(args.program_report.read_text())
        retired_paths={r['path'] for r in report['retired_programs']}
        programs=[]
        for row in report['programs']:
            path=(args.program_report.parent/row['file']).resolve()
            require(path.is_relative_to(args.program_report.parent.resolve()),'program blob escaped report directory')
            programs.append(dict(row,data=path.read_bytes()))
        entries=report['program_trie_entries']
        pool,trie,rows,indexed=build_pool(programs,report['required_program_paths'],sorted(retired_paths),entries,images,
            reserve=allocation['program_pbl']['reserve'],trie_reserve=allocation['program_trie']['reserve'])
        slots=[('program_pbl',pool),('program_trie',trie)]
        metadata=source.files[-1]
        for name,value in slots:
            slot=allocation[name];require(slot['address']%8==0,'program allocation not aligned8')
            file,offset=source.locate(slot['address'],len(value))
            require(file is metadata and any(m.initial==1 and m.address<=slot['address'] and
                slot['address']+len(value)<=m.address+m.size for m in file.mappings),'program slot must be metadata RO')
            require(source.read(slot['address'],len(value))==bytes(len(value)),'program reservation not empty')
        output.mkdir()
        for file in source.files:
            dest=output/file.path.name
            copied=subprocess.run(['/bin/cp','-c',str(file.path),str(dest)],capture_output=True)
            if copied.returncode:shutil.copyfile(file.path,dest)
        for file in (source.main,metadata):
            stream=(output/file.path.name).open('r+b');handles.append(stream);maps[file.path.name]=mmap.mmap(stream.fileno(),0)
        data=maps[metadata.path.name]
        for name,value in slots:
            _,offset=source.locate(allocation[name]['address'],len(value));data[offset:offset+len(value)]=value
        identifier=inspect(data,verify_pages=False)['identifier'];data[88:104]=bytes(16)
        metadata_signature=sign_with_uuid(data,identifier,metadata.mappings[0].size)
        main=maps[source.main.path.name];suboff,subcount=struct.unpack_from('<II',main,392)
        require(subcount==count-1,'final subcache vector differs')
        main[suboff+(subcount-1)*56:suboff+(subcount-1)*56+16]=data[88:104]
        # dyld_cache_header source: uint64 poolAddr,poolSize,trieAddr; uint32 trieSize,osVersion.
        old_osversion=bytes(main[364:368]);struct.pack_into('<3QI',main,336,
            allocation['program_pbl']['address'],len(pool),allocation['program_trie']['address'],len(trie))
        require(bytes(main[364:368])==old_osversion,'program trie update changed OS version')
        identifier=inspect(main,verify_pages=False)['identifier'];main[88:104]=bytes(16)
        main_signature=sign_with_uuid(main,identifier,source.main.mappings[0].size)
        for mapping in maps.values():mapping.flush()
        candidate=CandidateFamily(output/main_path.name,image_count=images,subcache_count=count-1)
        try:
            pool_addr,pool_size,trie_addr,trie_size=struct.unpack_from('<3QI',candidate.main.data,336)
            require((pool_addr,pool_size,trie_addr,trie_size)==(allocation['program_pbl']['address'],len(pool),
                allocation['program_trie']['address'],len(trie)),'program header readback differs')
            require(candidate.read(pool_addr,pool_size)==pool and candidate.read(trie_addr,trie_size)==trie,'actual pool/trie bytes differ')
            cached_address=struct.unpack_from('<Q',source.main.data,328)[0]
            cached_size=manifest['cached_loaders']['bytes']
            require(struct.unpack_from('<Q',candidate.main.data,328)[0]==cached_address and
                candidate.read(cached_address,cached_size)==source.read(cached_address,cached_size),'cached loader set changed')
            decoded=path_trie(candidate.read(trie_addr,trie_size),pool_size)
            require(decoded==indexed,'actual program trie differs')
            for row in rows:
                actual=candidate.read(pool_addr+row['offset'],row['size'])
                require(main_identity(actual)['path']==row['path'] and len(read_set(actual,images,app=True)['loaders'])==row['loader_count'],
                        'actual program loader readback differs')
        finally:candidate.close()
        result=dict(manifest)
        result.update(stage='program-loaders-integrated',
            original_files=[dict(file=f.path.name,size=(output/f.path.name).stat().st_size,sha256=sha(output/f.path.name)) for f in source.files],outputs=[],
            program_pool=dict(address=allocation['program_pbl']['address'],size=len(pool),sets=len(rows),rows=rows),
            program_trie=dict(address=allocation['program_trie']['address'],size=len(trie),entries=indexed))
        (output/'build-report.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    finally:
        for mapping in maps.values():mapping.close()
        for stream in handles:stream.close()
        source.close()

if __name__=='__main__':main()
