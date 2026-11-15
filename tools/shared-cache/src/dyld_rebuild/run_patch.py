"""Fresh lookup/patch graphs from the complete current cache and provider graph.

No historical patch audit, missing-use inventory or candidate hash is consumed.
Missing exports require an independent current-target root-marker proof callback;
absence of that proof refuses the stage and retains the current use evidence.
"""
import hashlib
import importlib.util
import inspect
import json
from pathlib import Path
import struct

from .cache_exports import FinalGraph, path_trie
from .candidate import CandidateFamily
from .exports import require
from .loader_generation import cache_manifest
from .lookup_tables import final_aliases,split_patch_arrays,serialize_patch_arrays,write_path_trie
from .metadata import load as load_layout
from .patch_graph import transform
from .patches import PatchTableV4
from .provider_layout import Provider
from .run_assembly import ROOT,_document,_fresh,_record,_run
from .run_inputs import pin
from .run_prepare import _json,_verified,open_source_family
from .slides import family_slides,pointer_at

MARKER = 0xBAD4007


def missing_use_policy(row):
    """What a use of an export the replacement lacks holds. 'marker': a non-weak GOT gets dyld's missing-export
    marker (as before); 'weak-null': a weak import is null, dyld's value for a missing weak import; 'retained': an
    ObjC class/metaclass pointer (PATCH) keeps the original class bytes, like the ObjC recipe's retained external
    class references (r83) and like Apple's images with the image overridden on disk. Anything else: None (refused).
    FACT (fold-in 26B131): 61 uses of Apple 27 Metal's tensor API absent from OCLP's Metal wrapper; the 32 class
    pointers are isa/superclass fields of the Apple-silicon AGX drivers."""
    if row['addend'] or row['high8']:
        return None
    if row['kind']=='GOT':
        return 'weak-null' if row['weak_import'] else 'marker'
    if row['kind']=='PATCH' and not row['weak_import'] and row['symbol'].startswith(('_OBJC_CLASS_$_','_OBJC_METACLASS_$_')):
        return 'retained'
    return None


def missing_policy(rows, target_dyld, output, proof):
    """Require complete current-use evidence and a current target semantic proof."""
    # Evidence first, so a refusal below leaves the rows it refused on disk.
    _json(output/'current-missing-uses.json',dict(schema=1,classification='FACT: current absent exports and retained source pointer uses; native caller behavior OPEN',
          target_dyld=target_dyld,missing=rows,caller_settling='OPEN: normal-mode execution of each retained caller'))
    identities=set()
    for row in rows:
        identity=(row['target'],row['symbol'],row['location'])
        require(identity not in identities,'duplicate current missing reference')
        identities.add(identity)
        require(row['policy'] is not None and row['policy']==missing_use_policy(row),
                'missing export has unreviewed reference semantics: '+row['symbol']+' '+row['kind'])
        require(row['source_pointer']['target']==row['candidate_pointer']['target']==row['expected_target']
                and row['resolution']['status']=='missing_symbol', 'missing export lacks complete current source/absence proof')
    if not rows:
        return dict(schema=1,required=False,missing_count=0)
    # This is dyld's existing missing-export marker, not an implementation of the absent API.
    counts={p:sum(r['policy']==p for r in rows) for p in ('marker','weak-null','retained')}
    return dict(missing_count=len(rows), literal=MARKER, policies=counts, native_caller_behavior='OPEN')



def lookup_controls(original,candidate,layout,output,original_pins,candidate_pins,allocation_pin):
    """Retain every original alias and require raw full-table serialization equality."""
    address,size=struct.unpack_from('<QQ',original.main.data,264)
    old=path_trie(original.read(address,size),len(original.images))
    aliases=final_aliases(old,original.images,candidate.images)
    trie=write_path_trie(aliases,len(candidate.images),reserve=layout['path_trie']['reserve'])
    patch_address,patch_size=struct.unpack_from('<QQ',original.main.data,152)
    raw=original.read(patch_address,patch_size)
    arrays=split_patch_arrays(raw,patch_address,len(original.images))
    repeated,stats=serialize_patch_arrays(arrays,patch_address,len(original.images))
    require(repeated==raw,'current original patch serialization differs')
    relocated,_=serialize_patch_arrays(arrays,layout['patch_table']['address'],len(original.images),reserve=layout['patch_table']['reserve'])
    require(relocated[152:]==raw[152:],'current raw patch relocation changed payload')
    output.mkdir()
    for name,data in [('path-trie.bin',trie),('patch-original.bin',repeated),('patch-relocated-control.bin',relocated)]:
        (output/name).write_bytes(data)
    (output/'aliases.tsv').write_text(''.join(f'{name}\t{index}\n' for name,index in sorted(aliases.items())))
    _json(output/'final-images.json',candidate.images)
    result=dict(schema=1,classification='FACT: current complete aliases and raw patch serialization controls; final semantic graph separate',
        original_inputs=original_pins,candidate_inputs=candidate_pins,allocation_sha256=allocation_pin['sha256'],
        final_identity_input=next(p for p in candidate_pins if p['path']==str(candidate.main.path)),
        path_trie=dict(address=layout['path_trie']['address'],reserve=layout['path_trie']['reserve'],size=len(trie),
            sha256=hashlib.sha256(trie).hexdigest(),original_aliases=len(old),added_paths=len(candidate.images)-len(original.images),
            aliases=len(aliases),images=len(candidate.images)),
        patch_table=dict(original_address=patch_address,relocated_address=layout['patch_table']['address'],size=len(repeated),
            reserve=layout['patch_table']['reserve'],original_byte_equal=True,relocated_payload_equal=True,
            original_sha256=hashlib.sha256(raw).hexdigest(),relocated_sha256=hashlib.sha256(relocated).hexdigest(),stats=stats))
    _json(output/'result.json',result)
    return arrays,raw,patch_address


def interpose_edits(hooks,table,replaced,final_slides,edits):
    """Apply each provider __interpose tuple to the cache: every patch-table use (GOT and PATCH) of the original holds
    the replacement, written into its existing slide-chain member. That is what dyld does at launch for an on-disk
    interposer and skips for a cache image (dyld-1378 DyldRuntimeState.cpp:1310). The table keeps listing the uses
    under the original. Returns one report row per tuple."""
    edited={e['location'] for e in edits};report=[]
    for hook in hooks:
        index=hook['original_image_index']
        if hook['original_in_provider']:
            # A provider's export: Apple uses of a replaced image were migrated and retargeted above (the source
            # patch table names the old export), a new image has none; provider binds are set in run_prepare.
            require(index in replaced or index>=len(table.images),'provider original with unmigrated cache uses')
            report.append(dict(hook,cache_uses=hook.get('migrated_cache_uses',[])))
            continue
        require(index not in replaced,'interposed original lives in a replaced image')
        uses=[r for r in table.image_uses(index) if r['symbol']==hook['symbol']]
        require(all(r['implementation']==hook['original'] for r in uses),'interposed original address differs from patch table')
        applied=[]
        for row in uses:
            if row['client_index'] in replaced:
                continue                        # a replaced client's uses are retired with it
            require(row['location'] not in edited,'interposed use already edited')
            expected=(row['implementation']+row['addend'])|(row['high8']<<56)
            _,mapping,slide,actual=pointer_at(final_slides,row['location'])
            require(actual['target']==expected,'interposed use does not hold the original')
            value=(hook['replacement']+row['addend'])|(row['high8']<<56)
            slide.retarget(row['location']-mapping.address,expected,value)
            edits.append(dict(**row,expected_target=expected,target_value=value,encoding='existing_v2_member',
                              final_export=None,interposed_by=hook['interposer']))
            edited.add(row['location']);applied.append(dict(kind=row['kind'],location=row['location'],client=row['client']))
        report.append(dict(hook,cache_uses=applied))
    return report


def patch_graph(original,candidate,plan,layout,arrays,raw,patch_address,output,*,original_pins,candidate_pins,
                plan_pin,allocation_pin,closure_pin,target_dyld,marker_proof=None):
    """Transform every surviving use of all actual replaced source images."""
    module_path=ROOT/'tools/build-patch-graph.py'
    spec=importlib.util.spec_from_file_location('current_patch_primitives',module_path)
    module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    providers={}
    for row in plan['providers']:
        provider=Provider(row['key'],Path(row['input_path']).read_bytes(),row['path'])
        require(len(provider.data)==row['input_size'] and hashlib.sha256(provider.data).hexdigest()==row['input_sha256'],'current provider slice drift')
        providers[row['path']]=provider.image
    graph=FinalGraph(original,providers)
    indexes={path:i for i,(path,_) in enumerate(candidate.images)}
    replaced={r['image_record']['image_index'] for r in plan['providers'] if 'original_header' in r['image_record']}
    old_slides,final_slides=family_slides(original),family_slides(candidate)
    kinds,object_counts=module.patchable_objects(candidate,final_slides)
    control,control_stats=transform(arrays,original.images,original.images,set(),{},[])
    require(control==arrays,'complete original semantic patch graph reconstruction differs')
    table=PatchTableV4(raw,patch_address,original.images,original.main.mappings[0].address)
    source_rows=[]
    for target in sorted(replaced):
        require(target<len(original.images),'replaced target not in source image inventory')
        source_rows.extend(row for row in table.image_uses(target) if row['client_index'] not in replaced)
    require(len({(r['target'],r['kind'],r['location']) for r in source_rows})==len(source_rows),'duplicate current external reference')
    def resolution(path,symbol):
        found=graph.resolve(path,symbol)
        if found['status']=='missing_symbol':return None,found
        require(found['status']=='resolved' and found['kind']=='regular' and not found['function_variant'],
                'current export requires unreviewed runtime semantics')
        index=indexes[found['provider']]
        implementation=candidate.images[index][1]+int(found['input_offset'],16)
        candidate.read(implementation,1)
        return dict(target_index=index,implementation=implementation,symbol=found['symbol'],export_kind=kinds.get(implementation,0)),found
    remaps,edits,missing={},[],[]
    hooks={(h['original_provider'],h['symbol']):h for h in plan.get('interpositions',[])}
    for row in source_rows:
        found,resolved=resolution(row['target'],row['symbol'])
        export=row['export_index']
        require(export not in remaps or remaps[export]==found,'inconsistent current export resolution')
        remaps[export]=found
        expected=(row['implementation']+row['addend'])|(row['high8']<<56)
        _,_,_,old_pointer=pointer_at(old_slides,row['location'])
        _,mapping,slide,actual=pointer_at(final_slides,row['location'])
        require(old_pointer['target']==actual['target']==expected,'current original/candidate pointer disagrees with source patch graph')
        if found is None:
            policy=missing_use_policy(row)
            missing.append(dict(**row,expected_target=expected,source_pointer=old_pointer,candidate_pointer=actual,
                                resolution=resolved,policy=policy))
            if policy=='retained':
                continue                    # keeps the original class bytes' address: no edit
            if policy=='weak-null':
                value,encoding=0,'existing_v2_member'
                slide.retarget(row['location']-mapping.address,expected,0)
            else:
                value,encoding=MARKER,'fixed_unslid_literal'
        else:
            value=(found['implementation']+row['addend'])|(row['high8']<<56)
            hook=hooks.get((resolved['provider'],resolved['symbol']))
            if hook is not None:            # a use of a replaced image's export that a provider interposes
                require(found['implementation']==hook['original'],'interposed provider original differs')
                value=(hook['replacement']+row['addend'])|(row['high8']<<56)
                hook.setdefault('migrated_cache_uses',[]).append(dict(kind=row['kind'],location=row['location'],client=row['client']))
            slide.retarget(row['location']-mapping.address,expected,value)
            encoding='existing_v2_member'
        edits.append(dict(**row,expected_target=expected,target_value=value,encoding=encoding,final_export=found))
    interposed=interpose_edits(plan.get('interpositions',[]),table,replaced,final_slides,edits)
    output.mkdir()
    _json(output/'current-reference-audit.json',dict(schema=1,source_patch_sha256=hashlib.sha256(raw).hexdigest(),
          replaced_indexes=sorted(replaced),references=source_rows,source_pins=original_pins,provider_plan=plan_pin,
          classification='FACT: complete retained external-use inventory from current PatchTableV4; source API oracle separate'))
    policy=missing_policy(missing,target_dyld,output,marker_proof)
    new_uses=[];own_calls_through=0
    hooks={(h['original_provider'],h['symbol']):h for h in plan.get('interpositions',[])}
    for provider in plan['providers']:
        packed=provider['pointer_fixups']
        require(packed['bind_columns']==['source_file_offset','file_offset','address','mapping_index','binding_index'],'unknown provider bind columns')
        for _,_,location,_,binding_index in packed['bind_rows']:
            binding=packed['bindings'][binding_index];record=binding['binding'];resolved=binding['resolution']
            found,_=resolution(resolved['provider'],resolved['symbol'])
            require(found is not None,'provider binding disagrees with current final graph')
            hook=hooks.get((resolved['provider'],resolved['symbol']))
            if binding.get('interpose')=='own-call-through':
                # Holds the original; not listed: every patch-table use of an interposed original holds the
                # replacement (what dyld's launch-time interposing of cache images writes). OPEN: a root of the
                # original's image would not reach this slot.
                require(hook is not None and hook['interposer']==provider['path'] and
                        found['implementation']+record['addend']==binding['target'],'interposer call-through slot differs')
                own_calls_through+=1
                continue
            expected=hook['replacement'] if binding.get('interpose')=='retargeted' else found['implementation']+record['addend']
            require((hook is not None)==(binding.get('interpose')=='retargeted') and expected==binding['target'],
                    'provider binding disagrees with current final graph')
            require(pointer_at(final_slides,location)[3]['target']==binding['target'],'current emitted provider pointer disagrees with plan')
            new_uses.append(dict(**found,client_index=provider['image_record']['image_index'],location=location,
                                 addend=record['addend'],weak_import=record['weak_import'],high8=0))
    require(len(new_uses)+own_calls_through==plan['resolved_pointer_bind_uses'],'current provider binding coverage differs')
    final_arrays,stats=transform(arrays,original.images,candidate.images,replaced,remaps,new_uses)
    blob,decoded=serialize_patch_arrays(final_arrays,layout['patch_table']['address'],len(candidate.images),reserve=layout['patch_table']['reserve'])
    (output/'patch-table.bin').write_bytes(blob)
    _json(output/'pointer-edits.json',edits);_json(output/'new-uses.json',new_uses)
    result=dict(schema=1,classification='FACT: current final semantic patch graph; independent source reader and pointer application separate',
        original_inputs=original_pins,candidate_inputs=candidate_pins,provider_plan_sha256=plan_pin['sha256'],
        allocation_sha256=allocation_pin['sha256'],provider_import_closure=closure_pin,original_graph_byte_equal=True,
        control=control_stats,stats=stats,patchable_objects=object_counts,pointer_edits=len(edits),fixed_literals=len(missing),
        missing_policy=policy,retired_marker=None,interpositions=interposed,interposer_own_calls_through=own_calls_through,
        patch_table=dict(address=layout['patch_table']['address'],size=len(blob),sha256=hashlib.sha256(blob).hexdigest(),decoded=decoded),
        source_hashes={str(module_path):pin(module_path)['sha256'],str(Path(__file__)):pin(Path(__file__))['sha256']})
    return _json(output/'result.json',result)


def prepare_patch(preparation_report,metadata_report,structural_manifest,output,*,preparation_sha256,metadata_sha256,
                  structural_sha256,marker_proof=None):
    """Emit fresh controls/final graphs and require complete Apple reader oracles."""
    prep_path,prep=_document(preparation_report,preparation_sha256,'dyld-cache-build/producer-preparation')
    metadata_path,metadata=_document(metadata_report,metadata_sha256,'dyld-cache-build/metadata-preparation')
    structural,_=_document(structural_manifest,structural_sha256)
    require(metadata['preparation']==pin(prep_path) and metadata['structural']==pin(structural),'patch preparation lineage differs')
    for row in prep['artifacts'].values():_verified(row)
    for row in metadata['outputs'].values():_verified(row)
    for row in prep['intake_pins'].values():_verified(row)
    source=prep['intake_pins']['capture-manifest.json'];plan_pin=prep['artifacts']['provider-plan.json']
    plan=json.loads(Path(plan_pin['path']).read_text());allocation_pin=metadata['outputs']['metadata-layout.json']
    _,_,_,source_pins=cache_manifest(source['path'])
    main,files,images,candidate_pins=cache_manifest(structural)
    require((images,files)==(plan['main_updates']['final_image_count'],plan['main_updates']['final_cache_file_count']), 'patch structural geometry differs')
    provenance=json.loads(Path(prep['intake_pins']['run-provenance.json']['path']).read_text())
    _verified(provenance['target_dyld'])
    original,_=open_source_family(source['path'],source['sha256']);candidate=None
    out=_fresh(output);lookup=out/'lookup';patch=out/'patch'
    try:
        candidate=CandidateFamily(main,image_count=images,subcache_count=files-1)
        layout=load_layout(allocation_pin['path'],candidate,plan_pin['path'])
        arrays,raw,address=lookup_controls(original,candidate,layout,lookup,source_pins,candidate_pins,allocation_pin)
        patch_pin=patch_graph(original,candidate,plan,layout,arrays,raw,address,patch,original_pins=source_pins,
            candidate_pins=candidate_pins,plan_pin=plan_pin,allocation_pin=allocation_pin,
            closure_pin=prep['artifacts']['import-closure.json'],target_dyld=provenance['target_dyld'],marker_proof=marker_proof)
    finally:
        if candidate is not None:candidate.close()
        original.close()
    return _record(out,'dyld-cache-build/patch-stage',{},
        dict(lookup_report=pin(lookup/'result.json'),patch_report=patch_pin))
