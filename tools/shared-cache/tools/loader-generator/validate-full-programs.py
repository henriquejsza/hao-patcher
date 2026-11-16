#!/usr/bin/env python3
"""Independently resolve all app-loader binds from explicit pinned offline inputs."""
import sys,json,struct,hashlib,collections,copy,argparse
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2];sys.path.insert(0,str(ROOT/'src'))
from dyld_rebuild.loader_generation import LoaderFamily,read_set,disk_image,sha,cache_manifest,verify_file
from dyld_rebuild.cache_exports import FinalGraph,CacheDependency
from dyld_rebuild.exports import Image,require
ap=argparse.ArgumentParser(description=__doc__)
ap.add_argument('--program-directory',type=Path,required=True)
ap.add_argument('--input-pins',type=Path,required=True)
ap.add_argument('--cache-manifest',type=Path,required=True)
ap.add_argument('--cached-set',type=Path,required=True)
ap.add_argument('--cached-set-sha256',required=True)
ap.add_argument('--closure-report',type=Path,required=True)
ap.add_argument('--closure-report-sha256',required=True)
ap.add_argument('--output-report',type=Path,required=True)
args=ap.parse_args();OUT=args.program_directory.resolve()
require(OUT.is_relative_to(ROOT/'work') and args.output_report.resolve().is_relative_to(ROOT/'work') and not args.output_report.exists(),'reports must be fresh under work/')
require(sha(args.cached_set)==args.cached_set_sha256 and sha(args.closure_report)==args.closure_report_sha256,'cached set/closure pin drift')
pins=json.loads(args.input_pins.read_text());main,file_count,image_count,cache_pins=cache_manifest(args.cache_manifest)
require(cache_pins==pins['cache_inputs'],'input cache pin inventory differs')
for record in pins['root_inputs'].values():verify_file(record['physical_path'],record)
family=LoaderFamily(main,file_count,image_count);basegraph=FinalGraph(family,{})
cached_bytes=args.cached_set.read_bytes();cached_address=struct.unpack_from('<Q',family.main.data,328)[0]
require(family.read(cached_address,len(cached_bytes))==cached_bytes,'cached set differs from integrated family')
cached=read_set(cached_bytes,image_count,app=False)['loaders'];disks={};edges={};closure=json.loads(args.closure_report.read_text())
for edge in closure['edges']:edges[(edge['main'],edge['loader'],edge['dependency'])]=edge
# Every absent path comes from a read-only final source lookup, and only weak
# imports may carry a missing dependent reference.
missing={(r['main'],r['loader'],r['dependency']) for r in closure['unresolved'] if r.get('weak')}

def disk(path):
 if path not in disks:disks[path]=disk_image(Path(pins['root_inputs'][path]['physical_path']).read_bytes(),path)
 return disks[path]

def check_one(number,mainpath):
 data=(OUT/f'program-{number:04d}.pbl').read_bytes();parsed=read_set(data,image_count,app=True);apps=parsed['loaders'];rows={r['index']|0x8000:r for r in apps};rows.update({r['index']:r for r in cached});providers={};checked_deps=0
 require(apps[0]['path']==mainpath,'main path differs')
 for app in apps:
  image,imports,overrides=disk(app['path']);require(len(app['dependencies'])==len(image.dependencies),'dependent count differs');deps=[]
  for dep,ref,attrs in zip(image.dependencies,app['dependencies'],app['dependency_attributes']):
   weak=dep.weak and not dep.reexport
   expect=(1 if weak else 0)|(2 if dep.reexport else 0)|(4 if dep.upward else 0)|((dep.use_flags or 0)&8 if not dep.reexport else 0)
   require(attrs==expect,f'dep attrs differ {dep.path}: {attrs}/{expect}')
   key=(mainpath,app['path'],dep.path)
   if ref==0x7fff:
    require(weak and key in missing,f'unproven missing dep {dep.path}');deps.append(dep);continue
   target=rows[ref]['path'];edge=edges.get(key);require(edge is not None,f'missing independent closure edge {key}');expected=basegraph.canonical(edge['selected']) if edge['source']=='cache' else edge['selected'];require(target==expected,f'dependent target differs {dep.path}: {target}/{expected}')
   deps.append(CacheDependency(target,dep.command,dep.use_flags));checked_deps+=1
  providers[app['path']]=Image(app['path'],deps,image.exports)
 graph=copy.copy(basegraph);graph.providers=providers;graph.resolution_paths=set()
 loaded=[0x8000];seen=set();added={0x8000}
 def add(ref):
  if ref!=0x7fff and ref not in added:added.add(ref);loaded.append(ref)
 def visit(ref):
  if ref==0x7fff or ref in seen:return
  seen.add(ref);row=rows[ref]
  if not ref&0x8000:add(ref)
  for dep in row['dependencies']:
   if not ref&0x8000 or dep&0x8000:add(dep)
  for dep in row['dependencies']:visit(dep)
 visit(0x8000)
 normal=set()
 def mark(ref):
  if ref==0x7fff or ref in normal:return
  normal.add(ref)
  for dep,attr in zip(rows[ref]['dependencies'],rows[ref]['dependency_attributes']):
   if not attr&8:mark(dep)
 mark(0x8000);scope=[[ref for ref in loaded if ref in normal],[ref for ref in loaded if ref not in normal]];special_cache={}
 def resolve(app,row,override=False):
  if row.ordinal>0:
   ref=app['dependencies'][row.ordinal-1]
   if ref==0x7fff:return {'status':'missing_symbol'}
   return graph.resolve(rows[ref]['path'],row.symbol)
  if row.ordinal in (0,-1):return graph.resolve(app['path'] if row.ordinal==0 else mainpath,row.symbol)
  require(row.ordinal in (-2,-3),'unknown process ordinal');key=(row.ordinal,row.symbol, bool(override))
  if key in special_cache:return special_cache[key]
  best={'status':'missing_symbol'}
  for group in scope:
   for ref in group:
    loader=rows[ref]
    if row.ordinal==-3 and not loader['flags']&0x800:continue
    candidate=graph.resolve(loader['path'],row.symbol,shallow=True)
    if candidate['status']!='resolved':continue
    if row.ordinal==-2:best=candidate;break
    if override and not ref&0x8000 and not candidate['weak_definition']:continue
    if best['status']!='resolved' or best['weak_definition'] and not candidate['weak_definition']:best=candidate
   if best['status']=='resolved':break
  special_cache[key]=best;return best
 checked=0;counts=collections.Counter();hasher=hashlib.sha256()
 for app in apps:
  image,imports,overrides=disk(app['path']);require(len(imports)==len(app['binds']),'bind count differs');require(len(overrides)==len(app['override_binds']),'override count differs')
  for row,binding,override in [(r,b,False) for r,b in zip(imports,app['binds'])]+[(r,b,True) for r,b in zip(overrides,app['override_binds'])]:
   resolution=resolve(app,row,override)
   if resolution['status']!='resolved':
    require((row.weak or override) and binding=={'kind':'absolute','value':0},f'nonnullable unresolved {row.symbol} {row.ordinal} {binding}')
   elif resolution['kind']=='absolute':require(binding=={'kind':'absolute','value':int(resolution['input_offset'],16)+row.addend},f'absolute differs {row.symbol}')
   else:
    require(binding['kind'] in ('image_offset','function_variant'),f'unexpected absolute {row.symbol} {binding}')
    target=apps[binding['index']] if binding['app'] else cached[binding['index']];require(target['path']==resolution['provider'],f'provider differs {row.symbol} ord{row.ordinal}: {target["path"]}/{resolution["provider"]}')
    if binding['kind']=='function_variant':
     require(resolution['flags']&0x20 and row.addend==0 and binding['variant']==int(resolution['extra_offset'],16),'variant differs')
     # Check exact table address from target image load commands independently.
     from dyld_rebuild.cache import commands
     require(not binding['app'],'disk function variant table needs reader');address=family.images[binding['index']][1];cmds=commands(family,address);tables=[struct.unpack_from('<II',raw,8) for _,cmd,raw in cmds if cmd==0x37];links=[struct.unpack_from('<4Q',raw,24) for _,cmd,raw in cmds if cmd==0x19 and raw[8:24].rstrip(b'\0')==b'__LINKEDIT'];require(len(tables)==len(links)==1,'ambiguous variant tables');off,size=tables[0];vm,_,fileoff,filesize=links[0];require(fileoff<=off and off+size<=fileoff+filesize and binding['table_offset']==vm+off-fileoff-address,'variant table differs')
    else:require(binding['offset']==(int(resolution['input_offset'],16)+row.addend)&((1<<64)-1),f'offset differs {row.symbol}: {binding}/{resolution}')
   checked+=1;counts[(row.ordinal,row.source)]+=1;hasher.update(json.dumps([app['path'],row.symbol,row.ordinal,binding,resolution],sort_keys=True).encode()+b'\n')
  require(app.get('validation',{}).get('check_cdhash') and not app['validation']['check_inode_mtime'],'file validation policy differs')
 return {'path':mainpath,'file':f'program-{number:04d}.pbl','size':len(data),'sha256':hashlib.sha256(data).hexdigest(),'cdhash':apps[0]['validation']['cdhash'],'check_cdhash':True,'loader_count':len(apps),'validation_status':'passed','bind_count':checked,'dependency_count':checked_deps,'binding_checks_sha256':hasher.hexdigest(),'objc_maps':parsed['objc_maps'],'swift_maps':parsed['swift_maps'],'must_be_missing_count':parsed['must_be_missing_count']}
rows=[];failures=[]
for number,program in enumerate(pins['programs']):
 try:rows.append(check_one(number,program))
 except Exception as e:failures.append({'index':number,'path':program,'error':str(e)})
 if number%200==0:print(number,'passed',len(rows),'failed',len(failures),failures[-1:] if failures else '',flush=True)
args.output_report.write_text(json.dumps({'programs':rows,'failures':failures,'cache_inputs':pins['cache_inputs'],'source_sha256':sha(Path(__file__)),'input_pins_sha256':sha(args.input_pins),'closure_sha256':sha(args.closure_report)},indent=2)+'\n');print('FINAL',len(rows),len(failures),flush=True);family.close();raise SystemExit(1 if failures else 0)
