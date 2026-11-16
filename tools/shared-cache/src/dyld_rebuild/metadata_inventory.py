"""Batch saved Swift inventories and reflection graphs into native requests."""
from collections import Counter
import hashlib
import json
import re
import subprocess
import tempfile

from .metadata_graph import MetadataGraph
from .swift_graph import framework_owners


def inputs(inventories, reflections):
    return sorted([dict(kind=kind, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
                   for kind, paths in (('swift-inventory', inventories), ('swift-reflection', reflections))
                   for path in paths], key=lambda row: (row['kind'], row['sha256']))


def names(document):
    if isinstance(document, list):
        return {row['name'].removeprefix('$s'): []
                for block in document for row in block.get('metadata', []) if row.get('name')}
    # netboot/swift_inventory.py's cumulative type-processes.json.
    return {name.removeprefix('$s'): processes for name, processes in document.items()}


def type_constraints(names, toolchain):
    """Use upstream type trees to distinguish names from concrete requests."""
    result = {}
    def walk(node):
        yield node
        for child in node.get('children', []):
            yield from walk(child)
    with tempfile.TemporaryFile() as output:
        subprocess.run([str(toolchain/'build/swift-type-graph-json')],
                       input=''.join(json.dumps(name)+'\n' for name in names).encode(),
                       stdout=output, check=True)
        output.seek(0)
        for line in output:
            row = json.loads(line)
            if 'tree' not in row:
                result[row['input']] = dict(reason='upstream type unavailable', details=row.get('error'))
                continue
            kinds = sorted({node['kind'] for node in walk(row['tree'])
                            if node['kind'].startswith(('Dependent', 'Opaque', 'Pack'))})
            if kinds:
                result[row['input']] = dict(reason='requires generic, opaque or pack context', details=kinds)
    return result


def plan(family, inventories, reflections, catalog, toolchain):
    observed, sources = {}, []
    for path in inventories:
        rows = names(json.loads(path.read_text()))
        for name, processes in rows.items():
            observed.setdefault(name, set()).update(processes)
        sources.append(dict(path=str(path), names=len(rows),
                            sha256=hashlib.sha256(path.read_bytes()).hexdigest()))
    graph = MetadataGraph()
    owners = framework_owners(family)
    # As in swift-discover --all-observed, Swift is the resolver's load image,
    # not an assertion about the requested type's descriptor owner. Export derives
    # actual owners from the constructed graph's file-backed pointer identities.
    resolver = owners['Swift'][0]
    graph.document['loads'] = sorted(set(catalog.get('loads', [])) | set(owners['Swift']))
    states = Counter()
    constraints = type_constraints([name for name in sorted(observed)
                                    if not re.search(r'\$[0-9a-fA-F]+', name)], toolchain)
    for name, processes in sorted(observed.items()):
        if re.search(r'\$[0-9a-fA-F]+', name):
            states['requires_live_reflection'] += 1
            graph.request(name, source=sorted(processes),
                          unresolved=dict(reason='address-bearing private context needs reflection'))
        elif name in constraints:
            states['requires_type_context'] += 1
            graph.request(name, source=sorted(processes), unresolved=constraints[name])
        else:
            states['native_name_candidate'] += 1
            graph.request(name, resolver, graph.constructor('resolve', name=name), source=sorted(processes))
    graph.document['evidence']['frontend'] = dict(
        sources=sources, names=len(observed), states=dict(states),
        scope='Observed names, not cache misses. Native construction determines exact supported keys. '
              'Private names need saved reflection dependencies; no application UI is launched.')
    reports = []
    if reflections:
        from .swift_generation import plan as reflection_plan
        for path in reflections:
            document, report = reflection_plan(family, json.loads(path.read_text()), catalog)
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            graph.merge_frontend(MetadataGraph(document), source=digest)
            reports.append(dict(path=str(path), sha256=digest, report=report))
    graph.document['evidence']['frontends'] = reports
    return graph
