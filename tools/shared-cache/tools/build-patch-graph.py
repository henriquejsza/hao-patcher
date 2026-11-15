#!/usr/bin/env python3
"""Emit the final semantic patch graph and checked, unapplied pointer edits."""
import argparse
from bisect import bisect_right
import hashlib
import json
from pathlib import Path
import struct
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from dyld_rebuild.cache import CacheFamily, commands
from dyld_rebuild.cache_exports import FinalGraph
from dyld_rebuild.candidate import CandidateFamily
from dyld_rebuild.exports import require
from dyld_rebuild.loader_generation import cache_manifest, sha
from dyld_rebuild.lookup_tables import split_patch_arrays, serialize_patch_arrays
from dyld_rebuild.metadata import load as load_layout
from dyld_rebuild.patch_graph import transform
from dyld_rebuild.patches import PatchTableV4
from dyld_rebuild.provider_layout import Provider
from dyld_rebuild.slides import family_slides, pointer_at


WIFI_CANDIDATE_SHA256 = 'fc6384ac5dece27fcc369d36ee47509dbadb9164458c87a987f3449e64ec186a'
WIFI_PATH = '/System/Library/PrivateFrameworks/WiFiPeerToPeer.framework/Versions/A/WiFiPeerToPeer'
WIFI_SYMBOL = '_OBJC_CLASS_$_WiFiAwareDatapathInfo'
WIFI_SLOT = 0x7ffb4007ed90


def check_missing_policy(audited_missing, edits, plan, candidate_sha):
    key = lambda row: (row['target'], row['symbol'], row['location'])
    expected = {key(row) for row in audited_missing}
    require(len(expected) == len(audited_missing) == 8, 'historical missing-export policy differs')
    retired = None
    if candidate_sha is not None:
        require(candidate_sha == WIFI_CANDIDATE_SHA256, 'unknown WiFi candidate pin')
        providers = [row for row in plan['providers'] if row['path'] == WIFI_PATH]
        require(len(providers) == 1 and providers[0]['input_sha256'] == candidate_sha,
                'WiFi provider differs from reviewed candidate')
        identity = (WIFI_PATH, WIFI_SYMBOL, WIFI_SLOT)
        require(identity in expected, 'reviewed WiFi marker absent from historical policy')
        rows = [row for row in edits if key(row) == identity]
        require(len(rows) == 1, 'reviewed WiFi reference missing/duplicated')
        row = rows[0]; resolved = row['final_export']
        require(resolved is not None and resolved['symbol'] == WIFI_SYMBOL and
                resolved['target_index'] == providers[0]['image_record']['image_index'] and
                resolved['export_kind'] == 8 and row['target_value'] == resolved['implementation'] and
                row['encoding'] == 'existing_v2_member', 'WiFi marker does not resolve to slid provider class')
        retired = dict(identity=list(identity), provider_sha256=candidate_sha, final_export=resolved)
        expected.remove(identity)
    actual = [key(row) for row in edits if row['final_export'] is None]
    require(len(actual) == len(expected) and set(actual) == expected, 'missing-export policy set changed')
    return retired


def patchable_objects(family, slides):
    """Apply Apple's class/metaclass and __const_cfobj2 membership rules."""
    maps = sorted((m.address, m.address + m.size, f, m) for f in family.files for m in f.mappings)
    starts = [m[0] for m in maps]
    slide_maps = {m.address: s for _, m, s in slides}

    def pointer(address):
        index = bisect_right(starts, address) - 1
        require(index >= 0 and address + 8 <= maps[index][1], 'unmapped ObjC class pointer')
        lo, _, file, mapping = maps[index]
        require(lo in slide_maps, 'class pointer has no slide mapping')
        return slide_maps[lo].pointer(address - lo)['target']

    kinds, classes, singletons = {}, set(), set()
    for path, mh in family.images:
        saw_singletons = False
        for _, cmd, raw in commands(family, mh):
            if cmd != 0x19:
                continue
            for at in range(72, len(raw), 80):
                name = raw[at:at + 16].split(b'\0')[0]
                address, size = struct.unpack_from('<QQ', raw, at + 32)
                if name == b'__objc_classlist':
                    require(size % 8 == 0, 'misaligned class list')
                    for field in range(address, address + size, 8):
                        cls = pointer(field)
                        require(cls != 0, 'null class-list entry')
                        meta = pointer(cls)
                        require(meta != 0, 'null class isa')
                        classes.update((cls, meta))
                elif name == b'__const_cfobj2' and not saw_singletons:
                    saw_singletons = True
                    reserved2, = struct.unpack_from('<I', raw, at + 72)
                    if size % 16 == 0 and reserved2 == 16:
                        singletons.update(range(address, address + size, 16))
    kinds.update((a, 1) for a in singletons)
    kinds.update((a, 8) for a in classes)
    return kinds, {'class_and_metaclass_objects': len(classes), 'cfobj2_objects': len(singletons)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', type=Path, required=True)
    parser.add_argument('--family-manifest', type=Path, required=True)
    parser.add_argument('--allocation', type=Path, default=ROOT / 'config/metadata-layout.json')
    parser.add_argument('--wifi-candidate-sha256',help='Explicit reviewed candidate permitting only the WiFi class marker retirement')
    parser.add_argument('--extra-audit', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    output = args.output.resolve()
    require(not output.exists(), 'output must be fresh under work/')
    original_main, _, _, original_pins = cache_manifest(ROOT / 'config/relayout-inputs.json')
    candidate_main, count, image_count, candidate_pins = cache_manifest(args.family_manifest)
    plan = json.loads(args.plan.read_text())
    report = json.loads(args.family_manifest.read_text())
    require(report['producer_plan_sha256'] == sha(args.plan), 'family/placement plan differs')
    original = CacheFamily(original_main)
    candidate = CandidateFamily(candidate_main, image_count=image_count, subcache_count=count - 1)
    try:
        layout = load_layout(args.allocation, candidate, args.plan)
        require(image_count == len(plan['final_image_paths']) and 0 < len(plan['providers']) < 120 and
                count == 7 + len(plan['providers']), 'unknown structural family')
        providers = {}
        for row in plan['providers']:
            path = (ROOT / row['input_path']).resolve()
            require(path.is_relative_to(ROOT / 'inputs') or path.is_relative_to(ROOT / 'work'), 'provider path escapes input/scratch')
            raw = path.read_bytes()
            provider = Provider(row['key'], raw, row['path'])
            require(len(provider.data) == row['input_size'] and
                    hashlib.sha256(provider.data).hexdigest() == row['input_sha256'], 'provider input drift')
            providers[row['path']] = provider.image
        graph = FinalGraph(original, providers)
        indexes = {path: i for i, (path, _) in enumerate(candidate.images)}
        replaced = {row['image_record']['image_index'] for row in plan['providers'] if 'original_header' in row['image_record']}
        original_slides, final_slides = family_slides(original), family_slides(candidate)
        kinds, object_counts = patchable_objects(candidate, final_slides)
        address, size = struct.unpack_from('<QQ', original.main.data, 152)
        raw = original.read(address, size)
        arrays = split_patch_arrays(raw, address, len(original.images))
        # Exercise the semantic reconstruction on the complete original graph.
        control, control_stats = transform(arrays, original.images, original.images, set(), {}, [])
        require(control == arrays, 'full original patch graph reconstruction differs')
        table = PatchTableV4(raw, address, original.images, original.main.mappings[0].address)
        audit_path = ROOT / 'evidence/2026-10-25-cache-patches/patches.json'
        audit = json.loads(audit_path.read_text())
        require(hashlib.sha256(raw).hexdigest() == audit['patch_table']['sha256'], 'original patch audit drift')
        audit_rows = list(audit['references'])
        if len(plan['providers']) >= 13:
            require(args.extra_audit is not None, 'expanded graph requires independent extra-provider audit')
            extra = json.loads(args.extra_audit.read_text())
            require(extra['schema'] == 1 and extra['extended_provider_config_sha256'] ==
                    plan['provider_inputs']['sha256'], 'extra-provider audit/config drift')
            require(not extra['missing_cached_exports'] and not extra['unresolved_strong_or_unsupported'],
                    'expanded graph introduces an unreviewed compatibility policy')
            audit_rows += extra['external_cached_uses']
        else:
            require(args.extra_audit is None, 'extra audit supplied for original provider scope')
        audit_rows = [r for r in audit_rows if r['client_index'] not in replaced]
        audited = {(r['target'], r['kind'], r['location']): r for r in audit_rows}
        require(len(audited) == len(audit_rows), 'duplicate audited external reference')
        remaps, edits, seen = {}, [], set()

        def resolution(path, symbol):
            found = graph.resolve(path, symbol)
            if found['status'] == 'missing_symbol':
                return None
            require(found['status'] == 'resolved' and found['kind'] == 'regular' and
                    not found['function_variant'], 'export requires unimplemented resolution semantics')
            index = indexes[found['provider']]
            implementation = candidate.images[index][1] + int(found['input_offset'], 16)
            candidate.read(implementation, 1)
            return dict(target_index=index, implementation=implementation, symbol=found['symbol'],
                        export_kind=kinds.get(implementation, 0))

        for target in sorted(replaced):
            for row in table.image_uses(target):
                if row['client_index'] in replaced:
                    continue
                key = row['target'], row['kind'], row['location']
                require(key in audited and all(audited[key][k] == v for k, v in row.items()),
                        'selected final reference differs from independent original audit')
                seen.add(key)
                found = resolution(row['target'], row['symbol'])
                export = row['export_index']
                require(export not in remaps or remaps[export] == found, 'inconsistent changed-export resolution')
                remaps[export] = found
                expected = (row['implementation'] + row['addend']) | (row['high8'] << 56)
                _, _, _, old_pointer = pointer_at(original_slides, row['location'])
                _, mapping, slide, actual = pointer_at(final_slides, row['location'])
                require(old_pointer['target'] == actual['target'] == expected, 'external pointer no longer matches source graph')
                if found is None:
                    require(row['kind'] == 'GOT' and not row['weak_import'] and row['addend'] == row['high8'] == 0,
                            'missing export outside verified strong fixed-slot policy')
                    target_value, encoding = 0xBAD4007, 'fixed_unslid_literal'
                else:
                    target_value = (found['implementation'] + row['addend']) | (row['high8'] << 56)
                    slide.retarget(row['location'] - mapping.address, expected, target_value)
                    encoding = 'existing_v2_member'
                edits.append({**row, 'expected_target': expected, 'target_value': target_value,
                              'encoding': encoding, 'final_export': found})
        require(seen == set(audited), 'original external-reference coverage differs')
        missing = [e for e in edits if e['final_export'] is None]
        retired_marker = check_missing_policy(audit['missing'], edits, plan, args.wifi_candidate_sha256)
        new_uses = []
        for provider in plan['providers']:
            packed = provider['pointer_fixups']
            require(packed['bind_columns'] == ['source_file_offset', 'file_offset', 'address', 'mapping_index', 'binding_index'],
                    'unknown provider binding columns')
            for _, _, location, _, binding_index in packed['bind_rows']:
                binding = packed['bindings'][binding_index]
                record, resolved = binding['binding'], binding['resolution']
                found = resolution(resolved['provider'], resolved['symbol'])
                require(found is not None and found['implementation'] + record['addend'] == binding['target'],
                        'provider binding no longer agrees with final graph')
                _, _, _, pointer = pointer_at(final_slides, location)
                require(pointer['target'] == binding['target'], 'emitted provider pointer differs from plan')
                new_uses.append({**found, 'client_index': provider['image_record']['image_index'],
                                 'location': location, 'addend': record['addend'],
                                 'weak_import': record['weak_import'], 'high8': 0})
        require(len(new_uses) == plan['resolved_pointer_bind_uses'], 'provider binding coverage differs')
        final_arrays, stats = transform(arrays, original.images, candidate.images, replaced, remaps, new_uses)
        blob, decoded = serialize_patch_arrays(final_arrays, layout['patch_table']['address'], image_count,
                                               reserve=layout['patch_table']['reserve'])
        output.mkdir()
        (output / 'patch-table.bin').write_bytes(blob)
        (output / 'pointer-edits.json').write_text(json.dumps(edits, indent=2) + '\n')
        (output / 'new-uses.json').write_text(json.dumps(new_uses, indent=2) + '\n')
        result = {'schema': 1, 'classification': 'final semantic table emitted; pointer edits remain unapplied',
                  'original_inputs': original_pins, 'candidate_inputs': candidate_pins,
                  'provider_plan_sha256': sha(args.plan), 'allocation_sha256': sha(args.allocation),
                  'extra_audit': None if args.extra_audit is None else {'path': str(args.extra_audit), 'sha256': sha(args.extra_audit)},
                  'original_graph_byte_equal': True, 'control': control_stats, 'stats': stats,
                  'retired_marker': retired_marker,
                  'patchable_objects': object_counts, 'pointer_edits': len(edits), 'fixed_literals': len(missing),
                  'patch_table': {'address': layout['patch_table']['address'], 'size': len(blob),
                                  'sha256': hashlib.sha256(blob).hexdigest(), 'decoded': decoded},
                  'source_hashes': {str(p.relative_to(ROOT)): sha(p) for p in
                                    (Path(__file__).resolve(), ROOT / 'src/dyld_rebuild/patch_graph.py',
                                     ROOT / 'src/dyld_rebuild/lookup_tables.py')},
                  'open': ['Apply pointer edits together with fixed-slot chain removal and ObjC edits.',
                           'Integrate the final table and run the independent Apple reader oracle.',
                           'Regenerate required loader metadata and prove target acceptance.']}
        (output / 'result.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({k: result[k] for k in ('classification', 'stats', 'patchable_objects', 'pointer_edits', 'fixed_literals')}))
    finally:
        original.close()
        candidate.close()


if __name__ == '__main__':
    main()
