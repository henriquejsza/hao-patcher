"""Fresh offline loader controls, filesystem closure and complete program reports.

No captured program report or binary is reused. The pinned Apple host serializer
is a toolchain input; every target byte and filesystem decision belongs to the run.
"""
from collections import Counter, deque
import json
import os
from pathlib import Path
import posixpath
import re
import stat
import struct
import subprocess

from .cache import commands
from .cache_exports import FinalGraph
from .exports import require, span, cstring
from .graph_contract import program_inventory_checks
from .loader_generation import (ROOT, SYNTHETIC_NAMES, LoaderFamily, cache_manifest,
    check_target_schema, executable, load_root_manifest, read_set, run_generation, sha, verify_file)
from .program_pool import MIRRORING, original_inventory
from .provider_identity import x86_slice
from .run_inputs import pin, PROVIDERS
from .run_rpaths import expand_path, rpath_stack, dependency_candidates


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')
    return pin(path)


def open_family(manifest):
    main, count, images, pins = cache_manifest(manifest)
    return LoaderFamily(main, count, images), pins


def derive_control_contract(pristine_manifest, target_dyld, output):
    out = Path(output).resolve(); require(not out.exists(), 'control output must be fresh')
    source, pins = open_family(pristine_manifest)
    try:
        objc = [address for path,address in source.images if path == '/usr/lib/libobjc.A.dylib']
        require(len(objc) == 1, 'source libobjc identity missing/ambiguous')
        synthetic = []
        for _, kind, raw in commands(source, objc[0]):
            if kind != 0x19: continue
            name = raw[8:24].rstrip(b'\0').decode('ascii')
            if name in SYNTHETIC_NAMES:
                address,size = struct.unpack_from('<QQ', raw, 24)
                maximum,initial = struct.unpack_from('<II', raw, 56)
                synthetic.append(dict(name=name,address=address,size=size,maximum=maximum,initial=initial))
        require({r['name'] for r in synthetic} == set(SYNTHETIC_NAMES) and len(synthetic) == 2,
                'source libobjc synthetic regions differ')
        address = struct.unpack_from('<Q',source.main.data,328)[0]
        require(address != 0, 'factory cached PBL absent')
        length = struct.unpack_from('<I',source.read(address,20),8)[0]
        require(length >= 80, 'short factory cached PBL')
        blob = source.read(address,length); parsed = read_set(blob,len(source.images),app=False)
        require([r['path'] for r in parsed['loaders']] == [p for p,_ in source.images],
                'factory cached PBL path order differs')
        programs,keys = original_inventory(source)
        import hashlib
        contract = dict(schema=2, original_image_count=len(source.images), original_file_count=len(source.files),
            original_cached_set_size=length, original_cached_set_sha256=hashlib.sha256(blob).hexdigest(),
            original_cache_inputs=pins, source_manifest=dict(path=str(Path(pristine_manifest).resolve()),sha256=sha(pristine_manifest)),
            libobjc_synthetic_segments=synthetic,target_dyld=pin(target_dyld),target_schema=check_target_schema(target_dyld),
            deriver=pin(Path(__file__)))
    finally: source.close()
    out.mkdir(parents=True)
    inventory = write_json(out/'original-program-inventory.json',dict(schema=1,programs=programs,keys=keys,cache_inputs=pins))
    contract['original_program_inventory'] = inventory
    return write_json(out/'control-contract.json',contract)


class FilesystemViews:
    """Resolve target absolute links/firmlinks without touching host fallback paths."""
    def __init__(self, *, system, os_root, app=None, data=None, program_files=None, privileged_inputs=None, privileged_inputs_sha256=None, build=None):
        self.program_files = Path(program_files).resolve() if program_files else None
        self.roots = {key:Path(value).resolve(strict=True) if value is not None else None
                      for key,value in dict(system=system,os=os_root,app=app,data=data).items()}
        require(all(root is None or root.is_dir() for root in self.roots.values()), 'filesystem view is not a directory')
        table = self.roots['system']/'usr/share/firmlinks'
        require(table.is_file(), 'current System firmlink table missing: '+str(table))
        self.firmlink_pin = pin(table); self.firmlinks=[]
        for line in table.read_text().splitlines():
            if not line or line.startswith('#'): continue
            parts = line.split('\t'); require(len(parts)==2, 'malformed current firmlink table')
            prefix,target = parts
            prefix='/'+prefix.lstrip('/'); target=target.lstrip('/')
            require('..' not in Path(prefix).parts and '..' not in Path(target).parts and target,
                    'unsafe firmlink mapping')
            self.firmlinks.append((prefix,target))
        require(len({p for p,_ in self.firmlinks})==len(self.firmlinks),'duplicate firmlink prefix')
        self.firmlinks.sort(key=lambda r:-len(r[0]))
        require((privileged_inputs is None)==(privileged_inputs_sha256 is None),'privileged inputs require path and independent hash')
        self.privileged_inputs=None
        if privileged_inputs is not None:
            from .run_privileged_inputs import PrivilegedInputs
            self.privileged_inputs=PrivilegedInputs(privileged_inputs,privileged_inputs_sha256,self.roots['system'],build)

    @classmethod
    def from_program_report(cls,report_path,report_sha256,*,build,original_programs):
        """Revalidate the complete view proof from an independently pinned current report."""
        report_path=Path(report_path)
        report_pin=pin(report_path)
        require(report_pin['sha256']==report_sha256,'source-view program report pin differs')
        raw=report_path.read_bytes()
        import hashlib
        require(hashlib.sha256(raw).hexdigest()==report_sha256,'source-view program report changed while reading')
        report=json.loads(raw);value=report.get('source_views')
        require(report.get('schema')==1 and isinstance(value,dict),'current source-view proof missing')
        require(set(value) in ({'roots','firmlinks'},{'roots','firmlinks','privileged_inputs'}),
                'unknown or partial current source-view proof')
        roots=value['roots']
        require(isinstance(roots,dict) and set(roots)=={'system','os','app','data'},'source-view root coverage differs')
        require(isinstance(build,str) and build,'source-view current source build missing')
        # The independent full-program validator pins the exact closure. A stripped
        # or forged source_views section cannot become a new roots-only proof.
        validation_pin=report.get('fresh_validation')
        require(isinstance(validation_pin,dict) and pin(validation_pin['path'])['sha256']==validation_pin['sha256'],
                'source-view independent validation pin differs')
        validation=json.loads(Path(validation_pin['path']).read_text())
        expected_inputs=report.get('cache_inputs')
        require(isinstance(expected_inputs,list) and expected_inputs
                and type(validation.get('failures')) is list and not validation['failures']
                and validation.get('cache_inputs')==expected_inputs,
                'source-view independent validation did not pass exact family')
        closure_hash=validation.get('closure_sha256')
        matches=[path for path,digest in report.get('evidence_pins',{}).items() if digest==closure_hash]
        require(isinstance(closure_hash,str) and len(matches)==1,'source-view pinned closure missing or ambiguous')
        closure_path=Path(matches[0]);closure_pin=pin(closure_path)
        require(closure_pin['sha256']==closure_hash,'source-view closure evidence changed')
        closure=json.loads(closure_path.read_text())
        require(closure.get('views')==value and closure.get('cache_inputs')==report.get('cache_inputs')
                and closure.get('program_count')==len(report['programs']),'source-view report differs from validated closure')
        options={}
        if 'privileged_inputs' in value:
            proof=value['privileged_inputs'];record=proof.get('manifest') if isinstance(proof,dict) else None
            require(isinstance(record,dict) and set(record)=={'path','size','sha256'},'privileged source-view manifest proof missing')
            verify_file(record['path'],record)
            options=dict(privileged_inputs=record['path'],privileged_inputs_sha256=record['sha256'],build=build)
        views=cls(system=roots['system'],os_root=roots['os'],app=roots['app'],data=roots['data'],**options)
        views.verify_privileged_programs(original_programs)
        require(views.provenance()==value,'current source view/firmlink proof differs')
        from .run_privileged_inputs import ALLOWED
        for logical in sorted(ALLOWED.intersection(original_programs)):
            lookup=views.resolve(logical)
            require(lookup==closure.get('lookups',{}).get(logical),'current source physical input differs from validated closure')
            require(lookup['found'] is not None,'required source-view program missing')
            try:
                with Path(lookup['found']['path']).open('rb') as stream:stream.read(1)
            except PermissionError as error:
                raise ValueError('required execute-only source input lacks verified privileged proof: '+logical) from error
        require(pin(report_path)==report_pin and pin(closure_path)==closure_pin
                and pin(validation_pin['path'])['sha256']==validation_pin['sha256'],'source-view proof changed during rehydration')
        return views

    def verify_privileged_programs(self,original):
        if self.privileged_inputs is not None:self.privileged_inputs.verify_factory(original)

    def candidates(self, logical):
        for prefix,view in [('/System/Cryptexes/OS','os'),('/System/Cryptexes/App','app'),
                ('/System/Volumes/Preboot/Cryptexes/OS','os'),('/System/Volumes/Preboot/Cryptexes/App','app'),
                ('/System/Volumes/Data','data')]:
            if logical==prefix or logical.startswith(prefix+'/'):
                return [(view,logical[len(prefix):].lstrip('/'),prefix,0)]
        for prefix,target in self.firmlinks:
            if logical==prefix or logical.startswith(prefix+'/'):
                return [('data',target+logical[len(prefix):],prefix,len(target.split('/'))) ]
        return [(view,logical.lstrip('/'),'',0) for view in ('system','os','app')]

    def resolve(self, logical):
        require(logical.startswith('/') and '\t' not in logical and '\n' not in logical, 'unsafe target path')
        logical=posixpath.normpath(logical); visited=set(); history=[]; attempts=[]
        for _ in range(40):
            require(logical not in visited,'target symlink cycle: '+logical); visited.add(logical); redirect=None
            missing_views=[]
            for view,relative,logical_base,strip_components in self.candidates(logical):
                base=self.roots[view]
                if base is None:
                    missing_views.append(view); attempts.append(dict(view=view,path=logical,status='view-not-supplied')); continue
                physical=base; parts=relative.split('/')
                try:
                    for index,part in enumerate(parts):
                        if part in ('','.'): continue
                        require(part!='..','unresolved target parent component')
                        physical=physical/part; info=physical.lstat()
                        if stat.S_ISLNK(info.st_mode):
                            require(index>=strip_components,'symlink inside firmlink target prefix needs explicit view proof')
                            link=os.readlink(physical); virtual=logical_base+'/'+('/'.join(parts[strip_components:index+1]))
                            remainder='/'.join(parts[index+1:])
                            redirect=posixpath.normpath(posixpath.join(link if link.startswith('/') else posixpath.join(posixpath.dirname(virtual),link),remainder))
                            history.append(dict(view=view,logical=virtual,link=link,redirect=redirect));break
                    if redirect is not None: break
                    if physical.is_file():
                        require(physical.resolve().is_relative_to(base),'source escaped explicit view')
                        found=dict(view=view,path=str(physical))
                        if self.privileged_inputs is not None and logical in self.privileged_inputs.files:
                            require(self.privileged_inputs.factory_verified,'privileged input current factory identity not verified')
                            found=self.privileged_inputs.select(logical,view,physical)
                        return dict(found=found,symlinks=history,attempts=attempts,error=None)
                    attempts.append(dict(view=view,path=str(physical),status='not-file'))
                except (FileNotFoundError,NotADirectoryError):
                    attempts.append(dict(view=view,path=str(physical),status='absent'))
                except PermissionError as exc:
                    raise ValueError('permission denied in explicit view: '+str(physical)) from exc
            if redirect is None:
                require(not missing_views,'required filesystem view(s) '+','.join(missing_views)+' missing for '+logical)
                return dict(found=None,symlinks=history,attempts=attempts,error='unresolved_in_explicit_views')
            logical=redirect
        raise ValueError('target symlink depth exceeded')

    def provenance(self):
        value=dict(roots={k:str(v) if v is not None else None for k,v in self.roots.items()},firmlinks=self.firmlink_pin)
        if self.privileged_inputs is not None:value['privileged_inputs']=self.privileged_inputs.provenance()
        return value


def dependencies(data):
    start,length,_=x86_slice(data); image=span(data,start,length)
    magic,cpu,sub,kind,count,size=struct.unpack_from('<6I',span(image,0,32))
    require((magic,cpu,sub)==(0xfeedfacf,0x1000007,3) and kind in (2,6,8),'unsupported target disk Mach-O')
    body=span(image,32,size); pos=0; deps=[]; rpaths=[]
    for _ in range(count):
        command,width=struct.unpack('<II',span(body,pos,8));require(width>=8 and width%8==0,'bad load command')
        raw=span(body,pos,width)
        if command in (0xc,0x80000018,0x8000001f,0x80000023,0x20):
            off,timestamp=struct.unpack_from('<II',span(raw,0,24),8)
            flags=struct.unpack_from('<I',span(raw,0,28),24)[0] if timestamp==0x1a741800 else None
            require(flags is None or off==28 and not flags&~15,'unknown dylib-use flags')
            weak=bool(flags&1) if flags is not None else command==0x80000018
            reexport=bool(flags&2) if flags is not None else command==0x8000001f
            deps.append((cstring(raw,off)[0],weak and not reexport))
        elif command==0x8000001c:rpaths.append(cstring(raw,struct.unpack_from('<I',span(raw,0,12),8)[0])[0])
        pos+=width
    require(pos==size,'load-command extent differs')
    return deps,rpaths


def retirement_records(original, original_keys, views):
    """Programs in Apple's cache that are not on the input System (a patch removed them, e.g. hide-iphone-mirroring):
    no loader, and their trie keys are dropped."""
    rows=[]
    for path in sorted(original):
        lookup=views.resolve(path)
        if lookup['found'] is None:
            rows.append(dict(path=path,original_pool_offset=original[path]['offset'],retired_keys=original[path]['keys'],
                             source_absence=lookup))
    return rows


def collect_program_inputs(source_manifest, candidate_manifest, views, output):
    out=Path(output).resolve();require(not out.exists(),'program intake output must be fresh')
    original,original_pins=open_family(source_manifest)
    try: required,keys=original_inventory(original)
    finally:original.close()
    views.verify_privileged_programs(required)
    retired=retirement_records(required,keys,views)
    if retired:print('programs not on this System, retired: '+', '.join(r['path'] for r in retired),flush=True)
    programs=sorted(set(required)-{r['path'] for r in retired})
    require(programs,'current source has no retained programs')
    candidate,candidate_pins=open_family(candidate_manifest)
    files={};lookups={};metadata={};edges={};unresolved=[]
    try:
        graph=FinalGraph(candidate,{})
        def ensure(path):
            if path in files:return True
            lookup=views.resolve(path);lookups[path]=lookup
            if lookup['found'] is None:return False
            physical=Path(lookup['found']['path'])
            try:
                record=pin(physical)
            except PermissionError:
                # Mode-4511 tools need explicit readable build inputs. The matching
                # installer unpack or an export of the same System supplies them.
                # Never substitute programs from the host OS.
                if views.program_files is None:
                    raise
                physical=views.program_files/path.lstrip('/')
                record=pin(physical)
            dependencies(physical.read_bytes())
            files[path]=dict(record,virtual_path=path,physical_path=str(physical))
            return True
        missing=[path for path in programs if not ensure(path)]
        require(not missing,'required current program input missing; no sets dropped: '+repr(missing))
        for main in programs:
            require(graph.canonical(main) is None,'required program unexpectedly became a cached dylib')
            queue=deque([(main,())]);seen=set()
            while queue:
                loader,inherited=queue.popleft()
                if loader not in metadata:metadata[loader]=dependencies(Path(files[loader]['physical_path']).read_bytes())
                deps,rpaths=metadata[loader]
                stack=rpath_stack(rpaths,loader,inherited);key=(loader,stack)
                if key in seen:continue
                seen.add(key);require(len(seen)<10000,'current program closure runaway')
                for dep,weak in deps:
                    candidates=[];selected=None
                    for path in dependency_candidates(dep,loader,main,stack):
                        candidates.append(path)
                        if graph.canonical(path):selected=(path,'cache');break
                        if ensure(path):selected=(path,'disk');break
                    if selected is None:
                        require(weak,'required current dependency missing: '+repr((main,loader,dep,candidates)))
                        unresolved.append(dict(main=main,loader=loader,dependency=dep,weak=True,candidates=candidates,
                                               reason='unresolved_in_explicit_views'))
                        continue
                    path,source=selected;edge=dict(main=main,loader=loader,dependency=dep,selected=path,source=source,weak=weak)
                    identity=(main,loader,dep)
                    require(identity not in edges or edges[identity]==edge,'context-dependent closure target is ambiguous')
                    edges[identity]=edge
                    if source=='disk':queue.append((path,stack))
        for row in files.values():verify_file(row['physical_path'],row)
        require(pin(Path(views.firmlink_pin['path']))==views.firmlink_pin,'firmlink source changed')
    finally:candidate.close()
    out.mkdir(parents=True)
    root=dict(schema=1,coverage='explicit-inputs',files=list(files.values()),programs=programs,
              original_required_path_count=len(required),retired_programs=retired)
    closure=dict(schema=1,classification='FACT: fresh complete explicit-view recursive closure; no host fallback',
                 program_count=len(programs),edges=list(edges.values()),unresolved=unresolved,
                 views=views.provenance(),lookups=lookups,cache_inputs=candidate_pins)
    inventory=dict(schema=1,required_program_paths=sorted(required),original_programs=required,original_keys=keys,
                   retired_programs=retired,original_cache_inputs=original_pins)
    return dict(root=write_json(out/'root-manifest.json',root),closure=write_json(out/'closure-report.json',closure),
                inventory=write_json(out/'inventory.json',inventory))


def generate_cached(cache_manifest_path, root_manifest, output, *, target_dyld, control_contract,
                    control_contract_sha256, control_report=None, workspace_root=None):
    return run_generation(cache_manifest_path,root_manifest,output,mode='cached',target_dyld=target_dyld,
                          control_report=control_report,control_contract=control_contract,
                          control_contract_sha256=control_contract_sha256,workspace_root=workspace_root)


def select_control_program(files, programs, family, original):
    """Choose a retained executable within the cache-only control oracle's scope."""
    cached={path for path,_ in family.images}; rejected=[]
    order=sorted(programs,key=lambda path:(path!='/usr/bin/true',path))
    for path in order:
        if path not in original:
            rejected.append(dict(path=path,reason='not a current factory program'));continue
        data=Path(files[path]['physical_path']).read_bytes()
        verify_file(files[path]['physical_path'],files[path])
        try:
            deps,_=dependencies(data);_,imports=executable(data,path)
            require(all(dep in cached for dep,_ in deps),'dependency requires a disk/rpath/absent-path oracle')
            require(all(row.ordinal>0 and row.provider in cached for row in imports),
                    'import requires process-special or disk lookup oracle')
        except ValueError as error:
            rejected.append(dict(path=path,reason=str(error)));continue
        return path,rejected
    raise ValueError('no retained factory executable supported by independent cache-only control: '+json.dumps(rejected))


def factory_control(pristine_manifest, root_manifest, output, *, target_dyld, control_contract,
                    control_contract_sha256, workspace_root=None):
    require(sha(control_contract)==control_contract_sha256,'factory control contract changed')
    files,programs=load_root_manifest(root_manifest)
    family,_=open_family(pristine_manifest)
    try:
        original,_=original_inventory(family)
        chosen,rejected=select_control_program(files,programs,family,original)
    finally:family.close()
    root=json.loads(Path(root_manifest).read_text())
    root['programs']=[chosen]
    root['control_selection']=dict(reason='retained current factory executable with cache-only dependencies and ordinary imports',
                                   chosen=chosen,rejected=rejected,source_root=pin(root_manifest))
    # Sibling provenance stays in the same temporary run workspace; output itself
    # remains fresh for the serializer. The complete file inventory is unchanged.
    control_root=Path(output).with_name(Path(output).name+'-root.json')
    require(not control_root.exists(),'factory control root must be fresh')
    write_json(control_root,root)
    report=run_generation(pristine_manifest,control_root,output,mode='program-control',target_dyld=target_dyld,
                          control_contract=control_contract,control_contract_sha256=control_contract_sha256,
                          workspace_root=workspace_root)
    require(report['cached_set']['original_cached_bytes_equal'],'factory-byte control failed')
    require(len(report['programs'])==1 and report['programs'][0]['path']==chosen,
            'factory executable control missing or changed')
    return report


def disk_and_absence_checks(directory, programs, image_count, root_inputs, views):
    expected={};sets={};occurrences=Counter()
    for row in programs:
        blob=(directory/row['file']).read_bytes()
        require(len(blob)==row['size'] and sha(directory/row['file'])==row['sha256'],'validated program bytes changed')
        parsed=read_set(blob,image_count,app=True);sets[row['path']]=parsed
        occurrences.update(parsed['must_be_missing_paths'])
        for loader in parsed['loaders']:
            validation=loader['validation']
            require(validation['check_cdhash'] and not validation['check_inode_mtime'],'disk loader lacks stable CDHash validation')
            old=expected.setdefault(loader['path'],validation['cdhash'])
            require(old==validation['cdhash'],'inconsistent disk loader CDHash')
    signed=[]
    for path,digest in sorted(expected.items()):
        record=root_inputs[path];verify_file(record['physical_path'],record)
        process=subprocess.run(['/usr/bin/codesign','-dvvv','--arch','x86_64',record['physical_path']],capture_output=True,text=True)
        match=re.search(r'^CDHash=([0-9a-f]{40})$',process.stderr,re.M)
        require(process.returncode==0 and match is not None and match[1]==digest,'Apple CodeDirectory comparison failed: '+path)
        signed.append(dict(path=path,expected_cdhash=digest,codesign_cdhash=match[1],exit=process.returncode,
                           passed=True,output=process.stdout+process.stderr))
    absent=[]
    for path,count in sorted(occurrences.items()):
        lookup=views.resolve(path)
        require(lookup['found'] is None and lookup['error']=='unresolved_in_explicit_views','serialized missing path exists: '+path)
        absent.append(dict(path=path,occurrences=count,found=None,source_lookup_error=lookup['error'],
                           attempts=lookup['attempts'],symlinks=lookup['symlinks']))
    codesign=dict(unique_disk_loaders=len(signed),passed=len(signed),rows=signed)
    write_json(directory/'codesign-all-disk-loaders.json',codesign)
    write_json(directory/'missing-paths-source-check.json',absent)
    return sets,codesign,absent


def generate_programs(cache_manifest_path, root_manifest, closure_report, inventory_report,
                      cached_regeneration, views, output, *, baked_paths, provider_profile=None, build=None):
    """Emit every current program through Apple serializers and independently verify it."""
    from .provider_profile import check_inventory
    check_inventory(baked_paths,provider_profile,build)
    out=Path(output).resolve()
    require(not out.exists() and out.is_relative_to(ROOT/'work'),
            'program workspace must be fresh under repository work (independent validator boundary)')
    root_inputs,programs=load_root_manifest(root_manifest)
    inventory=json.loads(Path(inventory_report).read_text());closure=json.loads(Path(closure_report).read_text())
    required=inventory['required_program_paths'];retired=inventory['retired_programs']
    require(len(required)==len(set(required)) and set(programs)==set(required)-{r['path'] for r in retired},
            'current required program coverage differs')
    main,count,images,pins=cache_manifest(cache_manifest_path)
    require(closure['cache_inputs']==pins,'closure was collected against another cache family')
    regeneration_path=Path(cached_regeneration).resolve();regeneration=json.loads(regeneration_path.read_text())
    require(regeneration['mode']=='cached' and regeneration['cache_inputs']==pins,'cached regeneration family differs')
    require(regeneration['root_inputs']==root_inputs,'cached and program filesystem inputs differ')
    control_pin=regeneration.get('control_contract')
    require(control_pin and sha(control_pin['path'])==control_pin['sha256'],'current factory contract missing/changed')
    control=json.loads(Path(control_pin['path']).read_text())
    original_pin=control['original_program_inventory']
    require(sha(original_pin['path'])==original_pin['sha256'],'factory program inventory changed')
    original=json.loads(Path(original_pin['path']).read_text())
    require(inventory['original_cache_inputs']==control['original_cache_inputs']==original['cache_inputs'] and
            inventory['original_programs']==original['programs'] and inventory['original_keys']==original['keys'] and
            set(required)==set(original['programs']),'program inventory is not the current factory inventory')
    require(closure['views']==views.provenance(),'program closure filesystem views differ')
    for virtual,record in root_inputs.items():
        lookup=views.resolve(virtual)
        require(lookup['found'] is not None and Path(lookup['found']['path']).resolve()==Path(record['physical_path']).resolve(),
                'program input is not from the current explicit filesystem: '+virtual)
    require(retired==retirement_records(original['programs'],original['keys'],views),'program retirement changed')
    cached=regeneration_path.parent/regeneration['cached_set']['file']
    require(sha(cached)==regeneration['cached_set']['sha256'],'cached regeneration bytes changed')
    helper=regeneration_path.parent/'helper/generator'
    require(sha(helper)==regeneration['helper_build']['generator_sha256'],'host serializer changed')
    family=LoaderFamily(main,count,images)
    try:
        address=struct.unpack_from('<Q',family.main.data,328)[0]
        require(family.read(address,cached.stat().st_size)==cached.read_bytes(),
                'cached PBL is not a fixed point of the current integrated family')
    finally:family.close()
    out.mkdir(parents=True)
    input_pins=dict(schema=1,cache_inputs=pins,root_inputs=root_inputs,programs=programs)
    write_json(out/'input-pins.json',input_pins)
    (out/'root.tsv').write_text(''.join(f"{virtual}\t{row['physical_path']}\n" for virtual,row in sorted(root_inputs.items())))
    (out/'batch.tsv').write_text(''.join(f"{program}\t{out/f'program-{index:04d}.pbl'}\t{out/f'program-{index:04d}.txt'}\n"
                                       for index,program in enumerate(programs)))
    command=[str(helper),str(main),root_inputs[programs[0]]['physical_path'],programs[0],str(out/'batch-output'),
             'program-batch',str(images),str(count),str(out/'root.tsv'),str(cached),str(out/'batch.tsv')]
    process=subprocess.run(command,capture_output=True,text=True)
    (out/'batch-generation.txt').write_text(process.stdout+process.stderr)
    require(process.returncode==0 and f'batch programs={len(programs)} failures=0' in process.stdout,
            'current program serializer batch did not complete without failures')
    validator=ROOT/'tools/loader-generator/validate-full-programs.py'
    import sys
    validation_path=out/'full-bind-validation.json'
    command=[sys.executable,str(validator),'--program-directory',str(out),'--input-pins',str(out/'input-pins.json'),
             '--cache-manifest',str(cache_manifest_path),'--cached-set',str(cached),'--cached-set-sha256',sha(cached),
             '--closure-report',str(closure_report),'--closure-report-sha256',sha(closure_report),
             '--output-report',str(validation_path)]
    process=subprocess.run(command,capture_output=True,text=True)
    (out/'validation.txt').write_text(process.stdout+process.stderr)
    require(process.returncode==0,'fresh independent full-program validation failed')
    validation=json.loads(validation_path.read_text());rows=validation['programs']
    require(not validation['failures'] and validation['cache_inputs']==pins and
            validation['input_pins_sha256']==sha(out/'input-pins.json') and
            validation['closure_sha256']==sha(closure_report) and validation['source_sha256']==sha(validator),
            'full-program validation provenance differs')
    require(len(rows)==len(programs) and {r['path'] for r in rows}==set(programs),
            'independent validation omitted/duplicated a required program')
    sets,signed,absent=disk_and_absence_checks(out,rows,images,root_inputs,views)
    checks=program_inventory_checks(rows,sets,signed,absent,baked_paths)
    entries={key:path for key,path in inventory['original_keys'].items()
             if not key.startswith('/cdhash/') and path in programs}
    for row in sorted(rows,key=lambda r:r['path'].encode('utf-8')):
        if row['check_cdhash']:entries['/cdhash/'+row['cdhash']]=row['path']
    require(all(entries.get(path)==path for path in programs),'canonical program trie key missing')
    evidence=[Path(root_manifest),Path(closure_report),Path(inventory_report),regeneration_path,validator,
              out/'input-pins.json',out/'batch-generation.txt',validation_path,
              out/'codesign-all-disk-loaders.json',out/'missing-paths-source-check.json',Path(__file__)]
    report=dict(schema=1,classification='FACT: fresh current-run complete program generation and independent binding/CodeDirectory/absence checks; native OPEN',
                cache_inputs=pins,required_program_paths=required,retired_programs=retired,programs=rows,
                program_trie_entries=entries,checks=checks,
                original_program_inventory=dict(path=str(Path(inventory_report).resolve()),sha256=sha(inventory_report)),
                fresh_validation=dict(path=str(validation_path),sha256=sha(validation_path)),
                evidence_pins={str(p.resolve()):sha(p) for p in evidence},
                source_views=views.provenance(),complete_candidate=False)
    for record in root_inputs.values():verify_file(record['physical_path'],record)
    require(cache_manifest(cache_manifest_path)[3]==pins,'cache changed during program generation')
    require(pin(Path(views.firmlink_pin['path']))==views.firmlink_pin,'firmlink source changed during program generation')
    write_json(out/'result.json',report)
    return report
