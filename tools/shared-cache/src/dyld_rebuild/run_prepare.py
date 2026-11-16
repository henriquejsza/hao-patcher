"""Current-run producer preparation; no imported target inputs or reports.

This emits checked producer inputs, not a finished cache or certificate. Each
source identity comes from the explicit intake. Required downstream gates are
recorded as OPEN and cannot be silently replaced with historical evidence.
"""
from dataclasses import asdict
import hashlib
import json
from pathlib import Path
import struct

from .candidate import CandidateFamily
from .cache_exports import FinalGraph, path_trie
from .codesign import inspect as signature_info
from .exports import require
from .imports import resolve_import
from .provider_identity import normalize, verify_normalized
from .provider_layout import Provider, file_geometry, place_uniform, provider_plan, pack_fixups, align
from .run_inputs import PROVIDERS, pin


def producer_plan(family, pins, provider_inputs, prepared_inputs, provider_manifest, normalization, verified):
    """Plan every provider from the current cache graph and parsed source bytes."""
    main = family.main
    region_start, region_size, max_slide = struct.unpack_from('<3Q', main.data, 224)
    require(region_start == 0x7ff800000000, 'provider v2 emitter requires matching current shared-region value_add')
    require(len(family.files)+len(provider_inputs) < 128, 'metadata addition exceeds supported cache-file count')
    region_end = region_start + region_size
    original_maps = [{'file': f.path.name, 'index': i, 'address': m.address, 'size': m.size,
                      'file_offset': m.offset, 'maximum': m.maximum, 'initial': m.initial}
                     for f in family.files for i, m in enumerate(f.mappings)]
    occupied = [(m['address'], m['address'] + m['size'], m['file']) for m in original_maps]
    reservations = []
    for offset, name in ((416, 'Rosetta read-only reservation'), (432, 'Rosetta read-write reservation')):
        address, size = struct.unpack_from('<QQ', main.data, offset)
        if size:
            reservations.append({'name': name, 'address': address, 'size': size})
            occupied.append((address, address + size, name))
    dynamic, size = struct.unpack_from('<QQ', main.data, 496)
    if size:
        reservations.append({'name': 'dynamic configuration', 'address': region_start + dynamic, 'size': size})
        occupied.append((region_start + dynamic, region_start + dynamic + size, 'dynamic configuration'))
    original_text_end = main.mappings[0].address + main.mappings[0].size
    scratch_end = original_text_end + 0x40000
    occupied.append((original_text_end, scratch_end, 'existing scratch main TEXT extension'))
    metadata_reservations = []
    trie_address, trie_size = struct.unpack_from('<QQ', main.data, 264)
    aliases = path_trie(family.read(trie_address, trie_size), len(family.images))
    indexes = {path: index for index, (path, _) in enumerate(family.images)}
    require(all(aliases.get(path) == index for path, index in indexes.items()), 'image array and path trie disagree')
    identifier = signature_info(main.data, verify_pages=True)['identifier']
    final_paths = [path for path, _ in family.images]
    # Serialized intake dictionaries are key-sorted. Image indexes and emitted
    # additions follow parsed provider order, so geometry must use that order.
    final_paths += [image.canonical for image in provider_inputs.values() if image.canonical not in indexes]
    require(len(final_paths) == len(set(final_paths)), 'duplicate final canonical image identity')
    plans = []
    additions, replacements = [], []
    old_count = len(family.images)
    for number, (key, image) in enumerate(provider_inputs.items(), len(family.files)):
        canonical = image.canonical
        if canonical in indexes:
            require(aliases.get(canonical) == indexes[canonical], 'canonical replacement path trie identity mismatch')
            record = {'key': key, 'path': canonical, 'image_index': indexes[canonical],
                      'original_header': family.images[indexes[canonical]][1]}
            replacements.append(record)
        else:
            require(canonical not in aliases, 'provider addition shadows a cache alias')
            record = {'key': key, 'path': canonical, 'image_index': old_count + len(additions)}
            additions.append(record)
        shape = file_geometry(image, identifier, image_paths=final_paths, header_size=family.main.mapping_offset)
        placement = place_uniform(image, shape, occupied, scratch_end, region_end, max_slide)
        plan = provider_plan(image, shape, placement, f'.{number:02d}')
        plan['image_record'] = record
        plan['input_path'] = prepared_inputs[key]['path']
        plans.append(plan)
        occupied += [(m['address'], m['address'] + m['size'], key) for m in placement['mappings']]
    graph = FinalGraph(family, {p.canonical: p.image for p in provider_inputs.values()})
    destination_headers = {p['path']: p['placement']['provider_header_address'] for p in plans}
    final_bind_counts = {}
    interposed = interpositions(graph, plans, provider_inputs, destination_headers, family, aliases)
    for plan in plans:
        image = provider_inputs[plan['key']]
        for fixup in plan['pointer_fixups']:
            if fixup['kind'] != 'bind':
                continue
            binding = fixup['binding']
            imported = [r for r in image.import_rows if r.symbol == binding['symbol'] and
                        r.provider == binding['provider'] and r.weak == binding.get('weak_import', False)]
            require(imported, 'pointer bind has no matching complete import-table row')
            ordinals = {r.ordinal for r in imported}
            require(len(ordinals) == 1, 'ambiguous pointer binding import ordinal')
            resolution = resolve_import(graph, image.image, imported[0])
            require(resolution['status'] == 'resolved' and resolution['kind'] == 'regular' and
                    not resolution['function_variant'],
                    'binding needs richer runtime export semantics: ' + str(resolution))
            provider = resolution['provider']
            header = destination_headers.get(provider)
            if header is None:
                header = family.images[aliases[provider]][1]
            target = header + int(resolution['input_offset'], 16) + binding['addend']
            hook = interposed.get((provider, resolution['symbol']))
            if hook is not None and hook['interposer'] == plan['path']:
                # The interposer's own call through: dyld never interposes an image's own binds, so it keeps the
                # original (else the hook calls itself). Not a patch-table use (run_patch): those must all hold the
                # replacement.
                fixup['interpose'] = 'own-call-through'
                hook['own_calls_through'] += 1
            elif hook is not None:
                require(binding['addend'] == 0, 'interposed bind with an addend')
                target = hook['replacement']
                fixup['interpose'] = 'retargeted'
                hook['provider_uses'] += 1
            require(0 <= target < 2**64 and not ((target - region_start) & ((1 << 64) - 1)) & 0x00ffff0000000000,
                    'bound target does not fit v2 slide value encoding')
            fixup.update({'resolution': resolution, 'target': target,
                          'target_policy': ('cache-build skipResolver: first export-trie stub value plus addend; resolver offset retained'
                                            if resolution['resolver'] else 'final provider export address plus pointer addend')})
            fixup.pop('target_status', None)
            final_bind_counts[provider] = final_bind_counts.get(provider, 0) + 1
        pack_fixups(plan)
    require(len(replacements)+len(additions)==len(plans), 'provider graph inventory differs')
    final_count = old_count + len(additions)
    require(final_count == len(final_paths), 'derived image count differs')
    capacity = old_count + max(16,len(additions))
    images_file_offset = main.mappings[0].size
    text_file_offset = images_file_offset + capacity * 32
    arrays_end = text_file_offset + capacity * 32
    subcache_table_offset = align(arrays_end, 8)
    subcache_table_size = (len(family.files)-1 + len(plans)) * 56
    require(subcache_table_offset + subcache_table_size <= main.mappings[0].size + 0x40000,
            'expanded main subcache table collides with scratch extension end')
    result = {'schema': 1, 'status': 'representable provider input/placement plan; cache writer and target acceptance not checked here',
        'provider_inputs': {'path': str(provider_manifest), 'sha256': pin(provider_manifest)['sha256']},
        'metadata_reserved_for_later': metadata_reservations,
        'inputs': verified, 'normalization': normalization,
        'original_mapping_records': original_maps, 'preserved_nonfile_reservations': reservations,
        'shared_region': {'start': region_start, 'size': region_size, 'max_slide': max_slide},
        'base_layout': {'required_main_text_growth': 0x40000, 'images_file_offset': images_file_offset,
                       'image_text_file_offset': text_file_offset, 'reserved_image_capacity': capacity},
        'path_trie': {'source_names': len(aliases), 'additions': additions, 'replacements': replacements,
                      'requirement': 'preserve all existing aliases and the independently inventoried provider identities'},
        'main_updates': {'final_image_count': final_count, 'final_subcache_count': len(family.files)-1 + len(plans),
            'final_cache_file_count': len(family.files) + len(plans), 'subcache_array_offset': subcache_table_offset,
            'subcache_array_size': subcache_table_size, 'image_arrays_end': arrays_end,
            'extension_end': main.mappings[0].size + 0x40000,
            'mapping_count': len(main.mappings), 'slide_mapping_count': len(main.mappings)},
        'final_image_paths': final_paths,
        'cache_header_size': main.mapping_offset,
        'providers': plans, 'resolved_pointer_bind_uses': sum(final_bind_counts.values()),
        'interpositions': sorted(interposed.values(), key=lambda h: (h['interposer'], h['symbol'])),
        'binding_providers': final_bind_counts,
        'new_cache_file_bytes': sum(p['geometry']['signature']['file_size'] for p in plans),
        'new_mapping_count': sum(p['geometry']['mapping_count'] for p in plans),
        'finalization_gates': ['Generate coherent new UUIDs and subcache UUID entries; update atlas/map and every affected file signature.',
            'Regenerate dylib path/address tries, image-text UUID records, patch tables, ObjC/Swift tables and required prebuilt loaders.',
            'Recompute slide fields/blocks if metadata transformations add pointers; apply final provider graph bindings before signatures.',
            'Preserve required caches, original VM maps, Rosetta reservations and dynamic configuration region.',
            'Target dyld/kernel/cryptex/SSV acceptance under existing security configuration requires separate authorization.']}
    return result




def interpositions(graph, plans, provider_inputs, destination_headers, family, aliases):
    """{(original image, symbol): hook} for every __interpose tuple of a provider (dyld ignores them in a cache
    image, so they become cache patches). The original resolves like the tuple's own bind (flat lookups to the single
    definer). The original may be in an Apple image or in a provider (libLiveTextLibrary hooks Metal, itself a
    provider replacing Apple's Metal at the same index)."""
    hooks = {}
    final_index = {p['path']: p['image_record']['image_index'] for p in plans}
    for plan in plans:
        image = provider_inputs[plan['key']]
        for row in plan['interpose']:
            binding = row['original']           # chained imports have no address: match like the bind loop does
            imported = [r for r in image.import_rows if r.symbol == binding['symbol'] and
                        r.provider == binding['provider'] and r.weak == binding.get('weak_import', False)]
            require(imported and len({r.ordinal for r in imported}) == 1, 'interpose original has no unique import')
            resolution = resolve_import(graph, image.image, imported[0])
            require(resolution['status'] == 'resolved' and resolution['kind'] == 'regular' and
                    not resolution['resolver'] and not resolution['function_variant'],
                    'interpose original does not resolve to a plain export: ' + str(resolution))
            provider = resolution['provider']
            require(provider != plan['path'], 'an image interposing its own export')
            in_provider = provider in destination_headers
            header = destination_headers[provider] if in_provider else family.images[aliases[provider]][1]
            key = (provider, resolution['symbol'])
            require(key not in hooks, 'one original interposed by two tuples: ' + str(key))
            hooks[key] = dict(interposer=plan['path'], interposer_key=plan['key'], symbol=resolution['symbol'],
                              original_provider=provider, original_in_provider=in_provider,
                              original_image_index=final_index[provider] if in_provider else aliases[provider],
                              original=header + int(resolution['input_offset'], 16),
                              replacement=row['replacement_target'], tuple_field=row['new_field'],
                              import_ordinal=imported[0].ordinal, own_calls_through=0, provider_uses=0)
    return hooks


def _json(path, value):
    with path.open('x') as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write('\n')
    return pin(path)


def _verified(record):
    actual = pin(record['path'])
    require(all(actual[k] == record[k] for k in ('path', 'size', 'sha256')), 'current-run input pin drift: '+record['path'])
    return actual


def import_closure(family, providers):
    """Resolve every import; unresolved/weak-null results never pass preparation."""
    graph = FinalGraph(family, {p.canonical:p.image for p in providers.values()})
    rows = []
    for key, provider in providers.items():
        for imported in provider.import_rows:
            resolution = resolve_import(graph, provider.image, imported)
            require(resolution['status'] == 'resolved', 'provider import unresolved: '+key+' '+imported.symbol)
            rows.append(dict(key=key, image=provider.canonical, **{'import':asdict(imported)}, resolution=resolution))
    return dict(schema=1, classification='complete current-run provider import resolution; ABI acceptance not checked here',
                imports=rows, import_count=len(rows), provider_count=len(providers))


def canonical_protocol_objects(entries, source):
    """Use current Apple canonical flags; never choose a duplicate by ordering."""
    protocol_objects = {}
    for entry in entries:
        candidates = {address for address, _ in entry['objects']
                      if source.number(address+68,'<I') & (1 << 29)}
        require(len(candidates) == 1, 'Apple canonical protocol flag missing/ambiguous: '+entry['name'])
        address = next(iter(candidates))
        require(source.string(source.ptr(address+8)) == entry['name'], 'Apple canonical protocol name differs')
        protocol_objects[entry['name']] = address
    return protocol_objects


def source_metadata(family, output):
    from .loader_generation import VERSION as LOADER_SET_VERSION
    """Decode current Apple canonical tables, Swift roots and loader baselines."""
    from .objc_tables import read_table, family_string
    from .objc_transfer import CachedReader
    from .swift_refs import optimization_header, read_table as swift_table
    from .loader_generation import read_set, required_programs
    from .slides import family_slides
    base = family.main.mappings[0].address
    from .objc_tables import objc_header
    header_address, _, fields = objc_header(family)
    offset = header_address - base
    source = CachedReader(family)
    from .cache import commands
    from .objc_transfer import sections
    libobjc=dict(family.images).get('/usr/lib/libobjc.A.dylib')
    require(libobjc is not None,'required current libobjc image missing')
    roots=[address for segment,name,address,size in sections(commands(family,libobjc))
           if segment=='__TEXT' and name=='__objc_opt_ro']
    require(len(roots)==1,'legacy current ObjC root missing/ambiguous')
    objc = dict(schema=1, objc_root=base+offset, legacy_objc_root=roots[0], selector_base=base+fields[7],
                objc_order=[source.objc_images[i] for i in range(len(source.objc_images))], tables={})
    for kind, index in [('selector',4), ('class',5), ('protocol',6)]:
        table = read_table(family.read, lambda address:family_string(family,address), base+fields[index], kind, base)
        entries = [dict(name=e.name.decode('utf-8','surrogateescape'), address=e.address, objects=e.objects) for e in table.entries]
        objc['tables'][kind] = dict(address=table.address, size=len(table.data), sha256=hashlib.sha256(table.data).hexdigest(),
                                    entries=entries, object_order=[n.decode('utf-8','surrogateescape') for n in table.object_order])
        _json(output/(kind+'-canonical.json'), {e['name']:e['address'] for e in entries})
    protocol_objects = canonical_protocol_objects(objc['tables']['protocol']['entries'],source)
    _json(output/'protocol-objects.json', protocol_objects)
    # Preserve all Apple protocol identities and ordering, without inventing a
    # canonical object winner from duplicate implementations.
    _json(output/'objc-baseline.json', objc)
    offset, size = struct.unpack_from('<QQ', family.main.data, 376)
    header = optimization_header(family.read(base+offset,size))
    swift = dict(schema=1, header=header, tables=[])
    for kind, off in [(k,header[k]) for k in ('type','metadata','foreign')] + [('pointer',o) for o in header['pointer_tables']]:
        table = swift_table(family.read,base+off,kind)
        swift['tables'].append(dict(kind=kind,address=table.address,header=asdict(table.header),
                                    sha256=hashlib.sha256(table.data).hexdigest(), rows=table.rows,
                                    groups=table.groups, pointer_keys=table.pointer_keys))
    _json(output/'swift-baseline.json', swift)
    cached_address = struct.unpack_from('<Q',family.main.data,328)[0]
    cached_length = struct.unpack('<I',family.read(cached_address+8,4))[0]
    require(80 <= cached_length <= 1 << 29, 'cached loader extent exceeds bound')
    cached_bytes = family.read(cached_address,cached_length)
    # Decoded only in the layout the serializer writes (dyld-1378). 27's sets (26B131 versionHash 0x9593b355) are
    # recorded undecoded: the no-prebuilt-loaders route needs only their extent, the loader route refuses later.
    version = struct.unpack('<I',family.read(cached_address+4,4))[0]
    decodable = version == LOADER_SET_VERSION
    cached = read_set(cached_bytes,len(family.images),app=False) if decodable else None
    if cached is not None:
        require([r['path'] for r in cached['loaders']] == [p for p,_ in family.images], 'cached loader identities differ from image array')
    _json(output/'cached-loader-baseline.json',dict(schema=1,address=cached_address,length=cached_length,version_hash=version,
          sha256=hashlib.sha256(cached_bytes).hexdigest(),decoded=cached))
    entries, paths = required_programs(family)
    pool, pool_size = struct.unpack_from('<QQ',family.main.data,336)
    programs = output/'program-baselines'; programs.mkdir()
    records = []
    for number, relative in enumerate(sorted(set(entries.values()))):
        require(type(relative) is int and 0 <= relative <= pool_size-20, 'program set starts outside source pool')
        length = struct.unpack('<I',family.read(pool+relative+8,4))[0]
        require(80 <= length <= pool_size-relative, 'program set extent outside source pool')
        raw = family.read(pool+relative,length)
        decoded = read_set(raw,len(family.images),app=True) if decodable else None
        record = _json(programs/(f'{number:04d}.json'),dict(schema=1,address=pool+relative,
                       sha256=hashlib.sha256(raw).hexdigest(),decoded=decoded))
        records.append(dict(pool_offset=relative, **record))
    _json(output/'program-inventory.json',dict(schema=1,entries=entries,required_paths=paths,sets=records,
          complete_final_filesystem=False,classification='source Apple program inventory; final filesystem closure not checked here'))
    signatures = [dict(path=str(f.path),signature=signature_info(f.data,verify_pages=True)) for f in family.files]
    slides = []
    for file, mapping, slide in family_slides(family):
        members = 0
        for i in range(len(slide.starts)):
            members += len(slide.page(i)); slide.pages.clear()
        slides.append(dict(file=str(file.path),address=mapping.address,size=mapping.size,chain_members=members))
    _json(output/'source-audit.json',dict(schema=1,signatures=signatures,slides=slides,
          classification='complete source signature pages and supported slide chains decoded; final-output gates not checked here'))


def prepare_producer(intake_directory, output, *, intake_pins, build=None):
    """Prepare current-run plans/baselines from externally bound intake pins.

    Returns pinned artifacts and backend_ready=False. Callers must refuse cache
    success until every required downstream gate has actually completed.
    """
    intake = Path(intake_directory).resolve(strict=True)
    out = Path(output).resolve()
    names = {'capture-manifest.json','provider-inputs.json','run-provenance.json'}
    require(set(intake_pins) == names, 'complete current-run intake pins required')
    docs = {}
    for name in sorted(names):
        require(Path(intake_pins[name]['path']) == intake/name, 'intake pin path differs')
        _verified(intake_pins[name]); docs[name] = json.loads((intake/name).read_text())
        require(docs[name].get('schema') == 1 and docs[name].get('build') == build, 'intake build/schema differs')
    capture, pins, provenance = [docs[n] for n in ('capture-manifest.json','provider-inputs.json','run-provenance.json')]
    require(provenance.get('kind') == 'dyld-cache-build/run-inputs', 'not current-run intake provenance')
    from .provider_profile import documents, authenticated
    selected = documents(pins,provenance,build)
    _, _, additions = authenticated(pins.get('provider_profile'),build)
    pristine, patched = [Path(provenance[k]).resolve(strict=True) for k in ('pristine_os','patched_system')]
    require(not out.exists() and not any(out.is_relative_to(p) for p in (pristine,patched,intake)), 'preparation output must be fresh and outside sources/intake')
    verified = {}
    for row in capture['files'] + [pins['inputs'][key] for key in selected] + [provenance['target_dyld']] + list(provenance['build_evidence'].values()):
        verified[row['path']] = _verified(row)
    require(all(Path(r['path']).is_relative_to(pristine) for r in capture['files']), 'cache source outside supplied pristine OS')
    # A provider read from a built file (features `sources`, run_inputs) is outside the System view by design; it must
    # be recorded as such in the run provenance with the same path and hash as its pinned input.
    origins = provenance.get('provider_sources', {})
    for k in selected:
        path, origin = Path(pins['inputs'][k]['path']), origins.get(k, {})
        if origin.get('origin') == 'file':
            require(origin['path'] == pins['inputs'][k]['path'] and origin['sha256'] == pins['inputs'][k]['sha256'],
                    'file provider source differs from its pinned input: ' + k)
        else:
            require(path.is_relative_to(patched), 'provider source outside supplied patched System')
    require(Path(provenance['target_dyld']['path']).is_relative_to(patched), 'target dyld outside supplied patched System')
    require(capture['main'] == pins['inputs']['cache_main']['path'] == capture['files'][0]['path'], 'cache/provider source identity differs')
    out.mkdir(parents=True); inputs = out/'producer-inputs'; inputs.mkdir()
    providers, prepared, normalizations = {}, {}, {}
    for key, canonical in selected.items():
        record = pins['inputs'][key]; raw = Path(record['path']).read_bytes()
        require(hashlib.sha256(raw).hexdigest() == record['sha256'], 'provider changed after verification')
        if record['normalization']:
            old = record['normalization']['source_install_name']
            from .graphics_identity import normalize_graphics
            normalized, transformation = normalize_graphics(raw,record['sha256'],old,canonical)
            verification = {}
            path = inputs/key
            with path.open('xb') as stream: stream.write(normalized)
            prepared[key] = pin(path); raw = normalized
            normalizations[key] = dict(**prepared[key],transformation=transformation,verification=verification)
        else: prepared[key] = _verified(record)
        providers[key] = Provider(key,raw,canonical)
    family = CandidateFamily(capture['main'],image_count=capture['images'],subcache_count=capture['cache_files']-1)
    try:
        _json(out/'import-closure.json',import_closure(family,providers))
        plan = producer_plan(family,pins,providers,prepared,intake/'provider-inputs.json',normalizations,verified)
        plan['source_manifest'] = dict(path=str(intake/'capture-manifest.json'),sha256=intake_pins['capture-manifest.json']['sha256'])
        _json(out/'provider-plan.json',plan)
        baseline = out/'source-metadata'; baseline.mkdir()
        source_metadata(family,baseline)
        from .objc_transfer import inspect as transfer
        readers = {p.canonical:p.reader for p in providers.values()}
        targets = {r['path'] for r in plan['path_trie']['replacements']}
        _json(out/'objc-transfer.json',transfer(family,{p.canonical:p.image for p in providers.values()},readers,targets))
    finally: family.close()
    for row in verified.values(): _verified(row)
    for row in intake_pins.values(): _verified(row)
    artifacts = {str(p.relative_to(out)):pin(p) for p in sorted(out.rglob('*')) if p.is_file()}
    report = dict(schema=1,kind='dyld-cache-build/producer-preparation',build=build,
                  classification='current-run preparation only; cache build and acceptance not checked here',
                  intake_pins=intake_pins,
                  source_modules={p.name:pin(p) for p in Path(__file__).parent.glob('*.py')},
                  artifacts=artifacts)
    report_pin = _json(out/'preparation.json',report)
    return dict(report=report_pin,artifacts=artifacts)


def checked_source_manifest(path, expected_sha256):
    """Verify an explicit source family contract without any legacy defaults."""
    path = Path(path).resolve(strict=True)
    record = pin(path)
    require(expected_sha256 is not None and record['sha256'] == expected_sha256, 'explicit source manifest pin differs')
    value = json.loads(path.read_text())
    require(value.get('schema') == 1 and 'images' in value and 'cache_files' in value and 'build' in value,
            'explicit source manifest lacks current-run build/count contract')
    from .loader_generation import cache_manifest
    main, files, images, records = cache_manifest(path)
    require(files == value['cache_files'] and images == value['images'], 'source family count contract differs')
    for row in records: _verified(row)
    require(pin(path) == record, 'explicit source manifest changed while reading')
    return value


def open_source_family(path, expected_sha256):
    value = checked_source_manifest(path,expected_sha256)
    return CandidateFamily(value['main'],image_count=value['images'],subcache_count=value['cache_files']-1),value
