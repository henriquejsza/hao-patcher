"""Recover replayable generic-value requests from a matching runtime trace.

Anonymous-context names do not round-trip through Swift's name resolver. Recorded
keys can bypass that resolver when every component has a stable cache identity.
Process-local pointers remain evidence only; they never enter a replay recipe.
"""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct
import uuid

from .exports import Refusal, require
from .swift_metadata import References, provenance, write_json


def recover(family, profile, runtime):
    identity = str(uuid.UUID(bytes=bytes(family.main.data[88:104])))
    require(profile['cache_uuid'] == identity, 'profile and supplied cache differ')
    identities = runtime.get('identities', [])
    require(runtime.get('complete') and not runtime.get('errors') and identities,
            'runtime trace is incomplete')
    require({r['cache_uuid'] for r in identities} == {identity} and
            len({r['slide'] for r in identities}) == 1, 'runtime trace has mixed cache identities or slides')
    slide = identities[0]['slide']
    base = family.main.mappings[0].address
    require(profile['cache_base'] == base, 'profile cache base differs')
    refs = References(family)
    installed = {r['metadata']: r.get('id', r['name']) for r in profile.get('catalog', [])
                 if r.get('metadata') is not None}
    requests = {}
    for row in runtime.get('requests', []):
        if row['outcome'] != 'miss':
            continue
        key = tuple(p-slide for p in [row['descriptor'], *row['arguments']])
        requests[key] = requests.get(key, 0)+1
    records, evidence, loads = [], [], set()
    for key, occurrences in sorted(requests.items()):
        components, blocked = [], []
        descriptor = None
        params = count = kind = None
        try:
            descriptor = refs.encode(key[0])
            flags = struct.unpack('<I', family.read(key[0], 4))[0]
            kind = flags & 31
            if kind in (17, 18) and flags & 128:
                params, _, count, _ = struct.unpack('<4H', family.read(key[0]+36, 8))
        except Refusal:
            pass
        for index, address in enumerate(key):
            role = 'descriptor' if index == 0 else ('protocol_witness' if params is not None and index > params
                                                    else 'type_metadata' if params is not None else 'argument')
            try:
                ref = refs.encode(address) if index == 0 or address not in installed else dict(catalog=installed[address])
                components.append(dict(index=index, role=role, reference=ref))
            except Refusal:
                components.append(dict(index=index, role=role, process_address=address+slide))
                blocked.append(index)
        if blocked:
            state = 'needs_live_dependencies'
        elif kind == 16:
            state = 'needs_class_metadata_support'
        elif descriptor is None or kind not in (17, 18) or count is None:
            state = 'unsupported_descriptor'
        elif count != len(key)-1 or params > count or not count:
            state = 'unsupported_key_layout'
        else:
            state = 'exact_key_replay'
        fingerprint = hashlib.sha256(json.dumps(components, sort_keys=True).encode()).hexdigest()
        entry = dict(id='request_'+fingerprint, category=state, occurrences=occurrences,
                     descriptor_kind=kind, components=components, blocked_components=blocked)
        if state == 'exact_key_replay':
            records.append(dict(id=entry['id'], name=entry['id'], owner=descriptor['image'],
                                key=[p-base for p in key]))
            for component in components:
                if 'image' in component['reference']:
                    loads.add(component['reference']['image'])
        evidence.append(entry)
    recipe = dict(schema=1, kind='generic-values', cache_uuid=identity, loads=sorted(loads),
                  installed_metadata=sorted(p-base for p in installed), records=records)
    summary = dict(cache_uuid=identity, missed_requests=sum(requests.values()), distinct_missed_keys=len(requests),
                   categories=dict(Counter(e['category'] for e in evidence)),
                   blocked_roles=dict(Counter(e['components'][i]['role'] for e in evidence
                                              for i in e['blocked_components'])),
                   scope='Exact-key capture recipe, not generated metadata or native acceptance.', entries=evidence)
    return recipe, summary


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('cache', type=Path)
    ap.add_argument('profile', type=Path)
    ap.add_argument('runtime', type=Path)
    ap.add_argument('output', type=Path)
    a = ap.parse_args(argv)
    from .loader_generation import LoaderFamily
    family = LoaderFamily(a.cache)
    try:
        recipe, summary = recover(family, json.loads(a.profile.read_text()), json.loads(a.runtime.read_text()))
        a.output.mkdir(parents=True, exist_ok=False)
        write_json(a.output/'recipe.json', recipe)
        write_json(a.output/'dependencies.json', summary)
        write_json(a.output/'build.json', provenance([a.profile, a.runtime]+[f.path for f in family.files],
                   operation='swift-dependencies', cache_uuid=summary['cache_uuid']))
    finally:
        family.close()
    print(json.dumps({k:v for k,v in summary.items() if k != 'entries'}, indent=2))
