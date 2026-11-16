"""Versioned graph geometry, derived from independently inventoried identities.

This does not certify provider semantics. Callers must pin/read the original
cache, plan and ObjC order before deriving this contract.
"""
from .exports import require


def from_plan(plan, *, original_paths, original_file_count=7,
              final_objc_order=None, plan_pin=None, manifest_pin=None):
    original = list(original_paths)
    require(plan.get('schema') == 1, 'unknown provider plan schema')
    require(original and len(set(original)) == len(original), 'duplicate/empty original image inventory')
    require(type(original_file_count) is int and original_file_count > 1, 'invalid original file count')
    providers = plan['providers']
    paths = [p['path'] for p in providers]
    keys = [p['key'] for p in providers]
    require(providers and len(set(paths)) == len(paths) and len(set(keys)) == len(keys),
            'duplicate/empty provider identities')
    require(all(isinstance(p, str) and p.startswith('/') for p in original + paths), 'invalid canonical path')
    indexes = {p:i for i,p in enumerate(original)}
    additions = [p for p in paths if p not in indexes]
    expected = original + additions
    require(plan['final_image_paths'] == expected, 'final image identity/order differs')
    final_indexes = {p:i for i,p in enumerate(expected)}
    for p in providers:
        record = p['image_record']
        require(record['key'] == p['key'] and record['path'] == p['path'] and
                record['image_index'] == final_indexes[p['path']], 'provider image record differs')
    for kind, wanted in [('additions', additions), ('replacements', [p for p in paths if p in indexes])]:
        records = plan['path_trie'][kind]
        require([p['path'] for p in records] == wanted, 'provider '+kind+' inventory differs')
        require(all(p == next(q['image_record'] for q in providers if q['path'] == p['path'])
                    for p in records), 'provider '+kind+' records differ')
    structural = original_file_count + len(providers)
    updates = plan['main_updates']
    require(updates['final_image_count'] == len(expected) and
            updates['final_cache_file_count'] == structural and
            updates['final_subcache_count'] == structural-1, 'provider plan geometry differs')
    require(plan['base_layout']['reserved_image_capacity'] >= len(expected), 'image array capacity exceeded')
    require(structural < 128, 'metadata expansion exceeds 128 subcache source limit')
    header_count = None
    if final_objc_order is not None:
        require(len(final_objc_order) == len(set(final_objc_order)) and
                set(final_objc_order) <= set(expected), 'ObjC order identity inventory differs')
        header_count = len(final_objc_order)
    pins = {}
    for name, pin in [('plan', plan_pin), ('manifest', manifest_pin)]:
        if pin is not None:
            require(set(pin) == {'path','sha256'} and isinstance(pin['path'], str) and
                    len(pin['sha256']) == 64 and all(c in '0123456789abcdef' for c in pin['sha256']),
                    'invalid graph '+name+' pin')
            pins[name] = dict(pin)
    return dict(schema=1, original_images=len(original), original_files=original_file_count,
                providers=len(providers), additions=len(additions), replacements=len(paths)-len(additions),
                images=len(expected), structural_files=structural, structural_subcaches=structural-1,
                final_files=structural+1, final_subcaches=structural, header_info_count=header_count, pins=pins)


def validate_shape(contract, *, images, files, stage='final'):
    require(contract.get('schema') == 1 and stage in ('structural','final'), 'unknown graph contract/stage')
    require(contract['images'] == contract['original_images'] + contract['additions'] and
            contract['providers'] == contract['additions'] + contract['replacements'] and
            contract['structural_files'] == contract['original_files'] + contract['providers'] and
            contract['structural_subcaches'] == contract['structural_files']-1 and
            contract['final_files'] == contract['structural_files']+1 and
            contract['final_subcaches'] == contract['final_files']-1, 'inconsistent graph contract')
    require(images == contract['images'] and files == contract[stage+'_files'], 'cache graph shape differs')
    return contract


def objc_inventory(family):
    """Independently inventory HeaderInfo members from actual image sections."""
    from .cache import commands
    from .objc_transfer import sections
    rows=[]
    for path,mh in family.images:
        info=[(address,size) for segment,name,address,size in sections(commands(family,mh))
              if segment.startswith('__DATA') and name=='__objc_imageinfo']
        require(len(info)<=1,'multiple ObjC imageinfo sections')
        if info:
            require(info[0][1]==8,'unknown ObjC imageinfo extent')
            rows.append(dict(path=path,mh=mh,imageinfo_section=info[0][0]))
    rows.sort(key=lambda row:row['mh'])
    require(0<len(rows)<65536 and len({r['mh'] for r in rows})==len(rows),'invalid HeaderInfo image inventory')
    return rows


def checked_manifest(manifest, *, root, images, files, stage='final', family=None, plan_path=None):
    """Derive geometry from pinned plan and the independently read Apple image list.

    A family, when supplied, additionally binds ordered image identities and ObjC
    section inventory. Legacy manifests resolve their plan through provider_objc;
    new manifests carry its direct path/hash pin. No numeric candidate fallback.
    """
    import json
    from pathlib import Path
    from .cache import CacheFamily
    from .loader_generation import cache_manifest,sha
    root=Path(root).resolve()
    if not isinstance(manifest,dict):manifest=json.loads(Path(manifest).read_text())
    def pinned(pin):
        path=(root/pin['path']).resolve()
        require(sha(path)==pin['sha256'],'graph input pin differs')
        return path,json.loads(path.read_text())
    expected=manifest['producer_plan_sha256']
    if plan_path is not None:
        pin=dict(path=str(Path(plan_path).resolve()),sha256=expected)
    elif 'producer_plan' in manifest:
        pin=manifest['producer_plan']
        require(pin['sha256']==expected,'producer plan pins disagree')
    else:
        _,recipe=pinned(manifest['components']['provider_objc'])
        pin=dict(path=recipe['inputs']['provider_layout_path'],sha256=recipe['inputs']['provider_layout_sha256'])
        require(pin['sha256']==expected,'provider recipe/plan pin differs')
    path,plan=pinned(pin)
    source_pin=plan.get('source_manifest')
    if source_pin is not None:
        from .run_prepare import open_source_family
        source_path=(root/source_pin['path']).resolve()
        source,source_pins=open_source_family(source_path,source_pin['sha256'])
        count=source_pins['cache_files'];original_images=source_pins['images']
        require(manifest.get('source_manifest',source_pin)==source_pin,'source manifest binding differs')
    else:
        main,count,original_images,_=cache_manifest(root/'config/relayout-inputs.json')
        require(count==7 and original_images==3608,'original Apple graph changed')
        source=CacheFamily(main)
    try:
        original=[p for p,_ in source.images]
        require(len(original)==original_images and len(source.files)==count,'original Apple inventory changed')
        inventory=objc_inventory(family) if family is not None else None
        contract=from_plan(plan,original_paths=original,original_file_count=count,
                           final_objc_order=[r['path'] for r in inventory] if inventory is not None else None,
                           plan_pin=dict(path=str(path),sha256=expected))
    finally:source.close()
    validate_shape(contract,images=images,files=files,stage=stage)
    if family is not None:
        require([p for p,_ in family.images]==plan['final_image_paths'] and len(family.files)==files,
                'actual cache identity inventory differs from plan')
    declared=manifest.get('graph_contract')
    if declared is not None:
        validate_shape(declared,images=images,files=files,stage=stage)
        for key,value in contract.items():
            if key=='header_info_count' and value is None:continue
            require(declared.get(key)==value,'declared graph contract differs: '+key)
        if inventory is None:
            value=declared.get('header_info_count')
            require(type(value) is int and 0<value<=images,'declared HeaderInfo count invalid')
            contract['header_info_count']=value
    return contract


def program_inventory_checks(programs, loader_sets, codesign, missing, baked_paths):
    """Count independently validated actual sets; require complete disk/absence proof."""
    from collections import Counter
    require(len({r['path'] for r in programs})==len(programs) and
            set(loader_sets)=={r['path'] for r in programs},'program coverage inventory differs')
    signed={r['path']:r for r in codesign['rows']}
    require(len(signed)==len(codesign['rows'])==codesign['unique_disk_loaders']==codesign['passed'] and
            all(r['passed'] is True and r['exit']==0 and r['expected_cdhash']==r['codesign_cdhash'] for r in signed.values()),
            'disk CodeDirectory proof incomplete')
    absent={r['path']:r for r in missing}
    require(len(absent)==len(missing) and all(r['found'] is None and r['source_lookup_error']=='unresolved_in_explicit_views'
            and type(r['occurrences']) is int and r['occurrences']>0 for r in missing),'missing-path source proof incomplete')
    disks=set();occurrences=Counter();bindings=0;instances=0
    for row in programs:
        parsed=loader_sets[row['path']];loaders=parsed['loaders']
        require(row['validation_status']=='passed' and loaders and loaders[0]['path']==row['path'] and
                row['loader_count']==len(loaders),'validated loader inventory differs')
        count=sum(len(r['binds'])+len(r['override_binds']) for r in loaders)
        require(row['bind_count']==count and row['dependency_count']==sum(sum(x!=0x7fff for x in r['dependencies']) for r in loaders),
                'independent binding/dependency coverage differs')
        require(row['must_be_missing_count']==parsed['must_be_missing_count']==len(parsed['must_be_missing_paths']),
                'missing-path coverage differs')
        for loader in loaders:
            path=loader['path'];proof=signed.get(path);validation=loader.get('validation',{})
            require(proof is not None and validation.get('check_cdhash') and not validation.get('check_inode_mtime') and
                    validation['cdhash']==proof['expected_cdhash'],'actual disk loader lacks CodeDirectory proof')
            disks.add(path)
        occurrences.update(parsed['must_be_missing_paths']);bindings+=count;instances+=len(loaders)
    require(not disks.intersection(baked_paths),'baked provider remains a disk loader')
    require(all(path in absent and count<=absent[path]['occurrences'] for path,count in occurrences.items()),
            'actual missing-path occurrence lacks source proof')
    return dict(serialized_programs=len(programs),serialized_disk_loader_instances=instances,
                unique_disk_loaders_cdhash_checked=len(disks),independent_bindings=bindings,
                unique_missing_paths_source_checked=len(occurrences),missing_path_search_attempts=sum(occurrences.values()),
                baked_canonical_paths_excluded=list(baked_paths))
