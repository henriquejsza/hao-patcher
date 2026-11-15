#!/usr/bin/env python3
"""Emit replacement subcache bytes into fresh scratch, with explicit unfinished gates."""
import argparse
import hashlib
import importlib.util
import json
import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from dyld_rebuild.cache import CacheFamily, CacheFile
from dyld_rebuild.emit_cache import emit_provider, image_records, update_original_subcache, update_main
from dyld_rebuild.exports import require, span
from dyld_rebuild.relayout import make_plan, write_main


def sha(path):
    value = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(8<<20), b''):
            value.update(block)
    return value.hexdigest()


def read_plan(path, expected, *, source_manifest=None, source_sha256=None):
    require(len(expected) == 64 and sha(path) == expected, 'producer plan digest differs')
    plan = json.loads(path.read_text())
    require(plan['schema'] == 1 and 0 < len(plan['providers']) < 120, 'unknown provider plan')
    explicit = source_manifest is not None
    require(explicit == (source_sha256 is not None), 'explicit source manifest requires SHA256')
    if explicit:
        from dyld_rebuild.run_prepare import checked_source_manifest
        source_contract = checked_source_manifest(source_manifest,source_sha256)
        require(plan.get('source_manifest') == {'path':str(source_manifest.resolve()),'sha256':source_sha256}, 'plan source manifest binding differs')
    for name, row in plan['inputs'].items():
        source = (ROOT/name).resolve()
        require((explicit or source.is_relative_to(ROOT/'inputs') or source.is_relative_to(ROOT/'work')) and source.stat().st_size == row['size'] and
                sha(source) == row['sha256'], 'pinned input drift: '+name)
    for provider in plan['providers']:
        source = (ROOT/provider['input_path']).resolve()
        require(explicit or source.is_relative_to(ROOT/'inputs') or source.is_relative_to(ROOT/'work'), 'provider path outside inputs/scratch')
        raw = span(source.read_bytes(), provider['slice_offset'], provider['input_size'])
        require(hashlib.sha256(raw).hexdigest() == provider['input_sha256'], 'provider slice digest differs')
        provider['_source'] = raw
    if explicit: plan['_plan_path'] = str(path.resolve())
    return plan


def verify_family(stage, main_name, records, plan):
    files, ranges = [], []
    try:
        for i in range(plan['main_updates']['final_cache_file_count']):
            file = CacheFile(stage/(main_name+(f'.{i:02d}' if i else '')))
            files.append(file)
            ranges += [(m.address,m.address+m.size) for m in file.mappings]
            data = file.data
            io, count = struct.unpack_from('<II',data,448)
            to, tc = struct.unpack_from('<QQ',data,136)
            require(count == tc == len(records),'emitted image-list count differs')
            for j, expected in enumerate(records):
                address, mtime, inode, pathoff, pad = struct.unpack_from('<3Q2I',data,io+32*j)
                uuid, textaddr, textsize, textpath = struct.unpack_from('<16sQ2I',data,to+32*j)
                end = data.find(b'\0',pathoff)
                require(end>pathoff and data[pathoff:end].decode()==expected['path'],'emitted image path differs')
                require(address == textaddr == expected['address'] and pad == expected.get('image_word', 0) and pathoff==textpath and
                        uuid.hex()==expected['uuid'] and textsize==expected['text_size'] and
                        mtime==expected['mtime'] and inode==expected['inode'],'emitted image/text records differ')
        suboff,count=struct.unpack_from('<II',files[0].data,392)
        require(count==len(files)-1,'emitted subcache count differs')
        base=files[0].mappings[0].address
        for i,file in enumerate(files[1:]):
            uuid,offset,suffix=struct.unpack_from('<16sQ32s',files[0].data,suboff+i*56)
            require(uuid==file.data[88:104] and offset==file.mappings[0].address-base and
                    suffix.split(b'\0')[0].decode()==f'.{i+1:02d}','emitted subcache identity differs')
        for reservation in plan['preserved_nonfile_reservations']:
            ranges.append((reservation['address'],reservation['address']+reservation['size']))
        ranges.sort()
        require(all(a[1]<=b[0] for a,b in zip(ranges,ranges[1:])),'emitted mappings/reservations overlap')
        return {'files':len(files),'image_records_checked':len(files)*len(records),
                'image_text_records_checked':len(files)*len(records),'mapping_and_reservation_overlap':False}
    finally:
        for file in files: file.close()


def assemble_family(stage, family, plan, records, reports):
    subcaches, originals = [], []
    for i,source in enumerate(family.files[1:],1):
        dest=stage/source.path.name
        cloned=subprocess.run(['/bin/cp','-c',str(source.path),str(dest)],capture_output=True)
        if cloned.returncode: shutil.copyfile(source.path,dest)
        with dest.open('r+b') as stream, mmap.mmap(stream.fileno(),0) as data:
            report=update_original_subcache(data,records,len(family.images))
            start=report['preserved_from']; end=source.signature_offset
            for offset in range(start,end,8<<20):
                require(data[offset:min(end,offset+(8<<20))]==source.data[offset:min(end,offset+(8<<20))],
                        'existing mapped payload changed during image-list assembly')
            report['sha256']=hashlib.sha256(data).hexdigest()
            report['size']=len(data)
            data.flush()
        report.update(file=source.path.name,payload_bytes_preserved=end-start)
        originals.append(report)
        subcaches.append(dict(suffix=f'.{i:02d}',uuid=report['signature']['uuid'],address=source.mappings[0].address))
        print(json.dumps({'assembled':source.path.name,'payload_bytes_preserved':end-start}),flush=True)
    for provider,report in zip(plan['providers'],reports):
        subcaches.append(dict(suffix=provider['new_subcache_suffix'],uuid=report['signature']['uuid'],
                             address=provider['placement']['cache_header_address']))
    options = {}
    if 'source_manifest' in plan:
        options['expected_main_images'] = sum(family.locate(address,32)[0] is family.main for _,address in family.images)
    relayout, extension=make_plan(family,growth=plan['base_layout']['required_main_text_growth'],reserve=plan['base_layout']['reserved_image_capacity']-len(family.images),**options)
    main=stage/family.main.path.name
    write_main(family,main,relayout,extension)
    with main.open('r+b') as stream,mmap.mmap(stream.fileno(),0) as data:
        report=update_main(data,family,plan,records,subcaches)
        report.update(file=main.name,size=len(data),sha256=hashlib.sha256(data).hexdigest())
        data.flush()
    originals.insert(0,report)
    print(json.dumps({'assembled':main.name,'subcaches':len(subcaches),'images':len(records)}),flush=True)
    verified=verify_family(stage,main.name,records,plan)
    return originals,verified


def build_providers(plan, output, plan_digest, stage_kind='providers', *, source_manifest=None, source_sha256=None):
    require(not output.exists() and not output.is_symlink(), 'output already exists')
    require(output.parent.is_dir(), 'output parent does not exist')
    if source_manifest is not None:
        from dyld_rebuild.run_prepare import checked_source_manifest
        pins = checked_source_manifest(source_manifest,source_sha256)
    else:
        require(source_sha256 is None, 'source SHA256 requires source manifest')
        pins = json.loads((ROOT/'config/relayout-inputs.json').read_text())
    require(all(row['path'] in plan['inputs'] and plan['inputs'][row['path']] == row for row in pins['files']),
            'original cache family and both sidecars must be pinned')
    if source_manifest is not None:
        from dyld_rebuild.run_prepare import open_source_family
        family,_ = open_source_family(source_manifest,source_sha256)
    else: family = CacheFamily(ROOT/pins['main'])
    try:
        records = image_records(family,plan['providers'])
        with tempfile.TemporaryDirectory(prefix='.provider-emission-',dir=output.parent) as tmp:
            stage = Path(tmp)/'providers'
            stage.mkdir()
            reports = []
            for provider in plan['providers']:
                data, report = emit_provider(provider['_source'],provider,family.main.data[:family.main.mapping_offset],records)
                name = family.main.path.name + provider['new_subcache_suffix']
                dest = stage/name
                with dest.open('xb') as stream:
                    stream.write(data)
                check = CacheFile(dest)
                try:
                    require(len(check.mappings) == len(provider['placement']['mappings']), 'independent cache reader mapping mismatch')
                finally:
                    check.close()
                reports.append(dict(report,file=name))
                print(json.dumps({'emitted':name,'size':len(data),'pointers':report['pointer_count']}),flush=True)
            original_reports, family_checks = [], None
            if stage_kind=='family':
                original_reports,family_checks=assemble_family(stage,family,plan,records,reports)
            result = {'schema':1,'classification':'FACT: emitted scratch components; metadata integration incomplete',
                      'stage':stage_kind,'producer_plan_sha256':plan_digest,'images':len(records),
                      'outputs':reports,'complete_candidate':False,
                      'original_files':original_reports,'family_checks':family_checks,
                      'remaining_gates':[
                          'Regenerate the path trie and v4 patch tables for the final graph.',
                          'Retarget existing external references and encode the eight audited fixed missing-use literals.',
                          'Emit provider ObjC category/class transformations and global ObjC lookup/header tables.',
                          'Apply the verified Swift identity-index transformation while preserving required caches.',
                          'Generate final cached-dylib and all required program loader sets from the final filesystem.',
                          'Update atlas/map sidecars and regenerate affected identities/signatures after metadata integration.',
                          'Pass complete offline checks and separately authorized target dyld/kernel/cryptex/SSV acceptance.'
                      ],
                      'runtime_acceptance':'OPEN: no cache execution, shared-region operation or target test'}
            if source_manifest is not None:
                result['source_manifest'] = dict(path=str(source_manifest.resolve()),sha256=source_sha256)
                result['producer_plan'] = dict(path=str(plan['_plan_path']),sha256=plan_digest)
            (stage/'build-report.json').write_text(json.dumps(result,indent=2)+'\n')
            (stage/'image-records.json').write_text(json.dumps(records,indent=2)+'\n')
            spec = importlib.util.spec_from_file_location('relayout_cli', ROOT/'tools/relayout-cache.py')
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            module.publish(stage,output)
        return result
    finally:
        family.close()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--stage',choices=['providers','family'],required=True)
    parser.add_argument('--plan',type=Path,required=True)
    parser.add_argument('--plan-sha256',required=True)
    parser.add_argument('--output',type=Path,required=True)
    parser.add_argument('--source-manifest',type=Path)
    parser.add_argument('--source-manifest-sha256')
    args = parser.parse_args()
    try:
        plan = read_plan(args.plan,args.plan_sha256,source_manifest=args.source_manifest,source_sha256=args.source_manifest_sha256)
        plan['_plan_path'] = str(args.plan.resolve())
        result = build_providers(plan,args.output,args.plan_sha256,args.stage,source_manifest=args.source_manifest,source_sha256=args.source_manifest_sha256)
        print(json.dumps({'stage':result['stage'],'files':len(result['outputs'])+len(result['original_files']),
                          'complete_candidate':False,'output':str(args.output)}))
    except (ValueError,OSError,KeyError) as error:
        parser.exit(1,f'REFUSED: {error}\n')


if __name__ == '__main__':
    main()
