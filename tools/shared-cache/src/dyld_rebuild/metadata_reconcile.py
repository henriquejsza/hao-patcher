"""Reconcile saved request outcomes with a newer catalog without native construction."""
import argparse
from collections import Counter, defaultdict
import json
from pathlib import Path
import re

from .swift_metadata import provenance, write_json


def reconcile(requests, coverage, catalog, selected=()):
    names = {row['name'] for row in catalog['records']}
    entries = {row['name']: row for row in coverage['generation']['entries']}
    unresolved = {row['id']: row['outcome'] for row in coverage['unresolved']}
    processes = defaultdict(dict)
    for request in requests['requests']:
        name = request['name']
        entry = entries.get(name, {})
        outcome = unresolved.get(request['id'], entry)
        canonical = entry.get('canonical_name', name)
        reason = outcome.get('reason', outcome.get('category', outcome.get('status', 'unclassified')))
        if canonical in names or name in names:
            state = 'retained-name' if name in names else 'retained-canonical-alias'
        elif outcome.get('status') in ('compiler_static', 'compiler_provided'):
            state = 'compiler-provided'
        elif 'unavailable' in reason or reason == 'owner could not be loaded':
            state = 'unavailable-image'
        elif reason == 'address-bearing private context needs reflection':
            state = 'requires-reflection'
        else:
            state = 'unsupported' if reason != 'unclassified' else 'unclassified'
        sources = request.get('source', [])
        if isinstance(sources, str):
            sources = [sources]
        for source in sources:
            if not source.startswith('/') or selected and source not in selected:
                continue
            processes[source][name] = dict(name=name, canonical_name=canonical, state=state, reason=reason)
    report = {}
    for process, rows in sorted(processes.items()):
        values = list(rows.values())
        report[process] = dict(names=len(rows), states=dict(Counter(r['state'] for r in values)),
            unresolved_reasons=dict(Counter(r['reason'] for r in values
                                           if not r['state'].startswith('retained'))),
            address_normalized_names=len({re.sub(r'\$[0-9a-fA-F]+', '$ADDRESS', name) for name in rows}),
            requests=sorted(values, key=lambda row: row['name']))
    return dict(classification='checked', catalog_records=len(catalog['records']), processes=report,
        installed_misses=None, absent_lookup_keys=None, construction_seconds=None,
        scope='Exact names and saved canonical aliases, not installed pointer-key lookups. '
              'Address normalization only measures count inflation; it does not establish type identity. '
              'Native misses and latency require matching-cache probes. Historical outcomes remain historical.')


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--expansion', type=Path, required=True)
    parser.add_argument('--catalog', type=Path, required=True)
    parser.add_argument('--process', action='append', default=[])
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    requests, coverage = (args.expansion/name for name in ('requests.json', 'coverage.json'))
    report = reconcile(json.loads(requests.read_text()), json.loads(coverage.read_text()),
                       json.loads(args.catalog.read_text()), set(args.process))
    args.output.mkdir(parents=True, exist_ok=False)
    write_json(args.output/'reconciliation.json', report)
    write_json(args.output/'build.json', provenance(
        [requests, coverage, args.expansion/'build.json', args.catalog, Path(__file__)],
        operation='metadata-reconciliation', processes=args.process, installed=False))
    print(json.dumps({p: {k: v for k, v in row.items() if k != 'requests'}
                      for p, row in report['processes'].items()}, indent=2))
