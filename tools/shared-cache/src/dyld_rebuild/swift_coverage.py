"""Join observed type requests, generation outcomes and measured catalog use."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

from .swift_metadata import provenance, write_json


def category(row):
    if row is None:
        return 'not_captured'
    if row['status']=='included':
        return 'generated'
    if row['status']=='compiler_static':
        return 'compiler_provided'
    reason=row.get('reason','')
    if 'terminated (' in reason:
        return 'runtime_resolution_failure'
    if 'type name did not resolve' in reason:
        return 'unresolved_name'
    if 'descriptor is outside shared cache' in reason:
        return 'outside_shared_cache'
    if 'metadata kind' in reason:
        return 'unsupported_metadata_kind'
    if 'witness dependency is outside' in reason:
        return 'process_local_witness'
    if 'layout string' in reason:
        return 'process_local_layout'
    return 'unsupported_layout'


def report(selection, coverage, catalog, profile=None, runtime=None, runtime_process=None):
    outcomes={r['name']:r for r in coverage['entries']}
    generated={r['name'] for r in catalog['records']}
    installed={r['name']:r for r in (profile or {}).get('catalog',[]) if r.get('metadata') is not None}
    used=defaultdict(list)
    for row in (runtime or {}).get('catalog',{}).get('entries',[]):
        used[row['name']].append(row)
    variants=Counter(r['name'] for r in catalog['records'])
    installed_variants=Counter(r['name'] for r in (profile or {}).get('catalog',[]) if r.get('metadata') is not None)
    entries=[]
    for row in selection['entries']:
        name=row['name']; outcome=outcomes.get(name)
        canonical=(outcome or {}).get('canonical_name',name)
        state=category(outcome)
        if canonical in generated and state!='compiler_provided':
            state='generated'
        use=used[canonical]
        entry=dict(row,category=state,canonical_name=canonical,
                   compiler_provided=state=='compiler_provided',
                   generated=canonical in generated,installed=canonical in installed,
                   installation_checked=profile is not None,
                   utilization_checked=runtime is not None,
                   runtime_complete=(runtime or {}).get('catalog',{}).get('complete',False),
                   variants=variants[canonical], installed_variants=installed_variants[canonical],
                   table_hits=sum(r.get('lookups',{}).get('hit',0) for r in use),
                   table_misses=sum(r.get('lookups',{}).get('miss',0) for r in use),
                   canonical_returns=sum(r.get('returns',{}).get('catalog',0) for r in use))
        if outcome and 'reason' in outcome:
            entry['reason']=outcome['reason']
        if outcome and 'metadata_kind' in outcome:
            entry['metadata_kind']=outcome['metadata_kind']
        if state=='compiler_provided':
            entry['compiler_metadata']=outcome['metadata']
            entry['compiler_descriptor']=outcome['descriptor']
        entry['address_bearing_name']=bool(re.search(r'\$[0-9a-fA-F]{8,}LL',name))
        # A missing module name is a resolution lead, not proof that its
        # descriptor is outside the cache. Keep that evidence separate.
        entry['ownership']='outside_shared_cache' if state=='outside_shared_cache' else (
            'source_cache' if entry['compiler_provided'] else
            'cache_closure' if entry['generated'] else 'unresolved')
        entries.append(entry)
    def counts(rows, measured=runtime is not None):
        return dict(observed=len(rows),categories=dict(sorted(Counter(r['category'] for r in rows).items())),
                    generated=sum(r['generated'] for r in rows),installed=sum(r['installed'] for r in rows),
                    compiler_provided=sum(r['compiler_provided'] for r in rows),
                    utilization_checked=measured,
                    utilized=sum(bool(r['table_hits'] or r['canonical_returns']) for r in rows) if measured else None,
                    table_hits=sum(r['table_hits'] for r in rows) if measured else None,
                    table_misses=sum(r['table_misses'] for r in rows) if measured else None)
    processes={}
    for row in entries:
        for process in row['processes']:
            processes.setdefault(process,[]).append(row)
    from .swift_graph import is_optional
    return dict(scope=selection['scope'],summary=counts(entries),
                runtime_scope=dict(process=runtime_process, measured=runtime is not None,
                    description='Type-level use in the supplied trace; per-process use requires its executable path.'),
                optionals=counts([r for r in entries if is_optional(r['name'])]),
                processes={p:counts(rows, runtime is not None and p == runtime_process)
                           for p,rows in sorted(processes.items())},
                catalog_records=len(catalog['records']),catalog_type_names=len(generated),entries=entries)


def main(argv):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('selection',type=Path)
    ap.add_argument('coverage',type=Path)
    ap.add_argument('catalog',type=Path)
    ap.add_argument('output',type=Path)
    ap.add_argument('--profile',type=Path,help='runtime profile generated from the installed candidate')
    ap.add_argument('--runtime',type=Path,help='summarize-runtime output from that candidate')
    ap.add_argument('--runtime-process',help='exact inventory executable path targeted by this single-process trace')
    a=ap.parse_args(argv)
    paths=[a.selection,a.coverage,a.catalog]+[p for p in (a.profile,a.runtime) if p]
    read=lambda p: json.loads(p.read_text()) if p else None
    result=report(read(a.selection),read(a.coverage),read(a.catalog),read(a.profile),read(a.runtime),a.runtime_process)
    a.output.mkdir(parents=True)
    from .swift_graph import verification_recipe
    (a.output/'catalog.json').write_bytes(a.catalog.read_bytes())
    write_json(a.output/'verification-recipe.json',verification_recipe(read(a.catalog)))
    write_json(a.output/'coverage.json',result)
    write_json(a.output/'build.json',provenance(paths,operation='swift-coverage',runtime_process=a.runtime_process))
    print(json.dumps({k:v for k,v in result.items() if k not in ('entries','processes')},indent=2))
