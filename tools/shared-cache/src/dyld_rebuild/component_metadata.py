"""Feed discovered disk and cache components into the existing metadata graph."""
from collections import Counter
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace
import uuid

from .exports import require
from .loader_generation import LoaderFamily
from .metadata_graph import MetadataGraph, identity
from .swift_cache_view import Bridge, CacheView, Layout, resolve_opaque
from .swift_graph import framework_owners
from .swift_metadata import ROOT, provenance, write_json


def component_inputs(document):
    rows = []
    for component in document['components']:
        fields = ('path', 'image_uuid') if component['kind'] == 'cache-image' else ('sha256',)
        rows.append(dict(kind=component['kind']+'-input', architecture='x86_64',
                         **{key:component[key] for key in fields}))
    return sorted(rows, key=lambda r:json.dumps(r, sort_keys=True))


def component_identity(component):
    return identity('component', {key:component.get(key) for key in ('path', 'image_uuid', 'sha256')})


def reuse_frontends(expansion, document, cache_uuid):
    """Reuse component requests, with their library-resolution context intact."""
    files = [expansion/name for name in ('requests.json', 'components.json', 'build.json')]
    graph = MetadataGraph(json.loads(files[0].read_text()))
    previous = json.loads(files[1].read_text())
    build = json.loads(files[2].read_text())
    require(graph.document.get('inputs') == component_inputs(previous),
            'saved component requests and manifest have different inputs')
    # Keep the saved frontend's resolution scope, including unresolved outcomes.
    # Adding another frontend does not change the identity of its constructors.
    # Changed cache binaries do require renewed resolution instead of reuse.
    old_cached = {row['path']: row['image_uuid'] for row in previous['components']
                  if row['kind'] == 'cache-image'}
    changed = any(row['path'] in old_cached and old_cached[row['path']] != row['image_uuid']
                  for row in document['components'] if row['kind'] == 'cache-image')
    if build['cache_uuid'] != cache_uuid or changed:
        return MetadataGraph(), {}, files, 'cache binaries changed'
    known = {component_identity(row): row for row in previous['components']
             if isinstance(row.get('analysis'), dict) and
             row['analysis'].get('state') in ('analyzed', 'reused')}
    reused = {component_identity(row): known[component_identity(row)] for row in document['components']
              if component_identity(row) in known}
    graph.reset_results()
    graph.document['requests'] = [row for row in graph.document['requests']
        if isinstance(row.get('source'), dict) and row['source'].get('input') in reused]
    constructors = graph.document['constructors']
    used = set()
    def include(key):
        if key in used:
            return
        used.add(key)
        for child in constructors[key].get('arguments', []):
            include(child)
    for row in graph.document['requests']:
        if 'constructor' in row:
            include(row['constructor'])
    graph.document['constructors'] = {key: row for key, row in constructors.items() if key in used}
    paths = {row['path'] for row in reused.values()}
    graph.document['evidence']['frontends'] = [row for row in graph.document['evidence'].get('frontends', [])
                                              if row['component'] in paths]
    # Earlier graphs carry one combined load set. Retain that context for the
    # selected requests; do not infer which imports are safe to omit.
    if not reused:
        graph.document['loads'] = []
    return graph, reused, files, None


def analyze(cache, document, catalog, toolchain, output, reuse=None):
    frontend = ROOT.parent/'swift-analysis/lib'
    sys.path.insert(0, str(frontend))
    from analysis import command, read_jsonl
    from static_mirror import scan, apply_resolutions, opaque_inputs, summary
    from generation_graph import plan, sources
    output.mkdir(parents=True, exist_ok=False)
    family = LoaderFamily(cache)
    bridge = None
    graph = MetadataGraph()
    try:
        reuse_files, reused, reuse_reason = [], {}, None
        if reuse is not None:
            graph, reused, reuse_files, reuse_reason = reuse_frontends(
                reuse, document, str(uuid.UUID(bytes=bytes(family.main.data[88:104]))))
        cached = [c['path'] for c in document['components'] if c['kind'] == 'cache-image']
        view = CacheView(family, cached)
        library = toolchain/'build/libSwiftMemoryView.dylib'
        def make_bridge():
            return Bridge(library, view.reader.read, lambda address, value:view.reader.ptr(address),
                          view.symbol, Layout(8, 1, 1, 0x100000000, (1 << 64)-1))
        bridge = make_bridge()
        additions = {p:bridge.add(a) for p, a in view.images}
        owners = framework_owners(family)
        trees, resolutions = {}, {}
        reports = graph.document['evidence'].get('frontends', [])
        def type_trees(names, path):
            missing = sorted(set(names)-set(trees))
            command([str(toolchain/'build/swift-type-graph-json')], path,
                    stdin=''.join(json.dumps(n)+'\n' for n in missing))
            trees.update({r['input']:r for r in read_jsonl(path)})
        for index, component in enumerate(document['components']):
            source = component_identity(component)
            component['analysis_id'] = source
            if source in reused:
                component['analysis'] = dict(deepcopy(reused[source]['analysis']),
                    state='reused', expansion=str(reuse.resolve()))
                continue
            if not component['swift_reflection']:
                component['analysis'] = dict(state='analyzed', reflection_sections=False, sources=0)
                continue
            work = output/str(index)
            work.mkdir()
            if component['kind'] == 'cache-image':
                inventory = make_bridge()
                try:
                    require(inventory.add(dict(view.images)[component['path']]),
                            'upstream reader could not add cache image: '+component['path'])
                    data = inventory.inventory()
                    diagnostics = dict(inventory.errors)
                finally:
                    inventory.close()
                write_json(work/'inventory.json', data)
            else:
                scan(SimpleNamespace(output=work/'semantic', toolchain=toolchain,
                                     binary=[Path(component['binary'])], arch='x86_64'))
                data = json.loads((work/'semantic/types.json').read_text())
                diagnostics = {}
            rows = sources(data)
            names = sorted({r['name'] for r in rows if r['name']})
            type_trees(names, work/'input-type-trees.jsonl')
            opaque = resolve_opaque(family, view, bridge, opaque_inputs(trees[n] for n in names))
            for name in names:
                if name not in resolutions:
                    resolutions[name] = bridge.resolve(name)
            resolution_report = apply_resolutions(data, {n:resolutions[n] for n in names})
            write_json(work/'types.json', data)
            write_json(work/'opaque-requests.json', opaque)
            rows = sources(data)
            names = sorted({r['name'] for r in rows if r['name']} | {r['name'] for r in opaque} |
                           {a for r in opaque for a in r['arguments'] if a})
            type_trees(names, work/'type-trees.jsonl')
            planned, report = plan(rows, trees, owners, catalog, opaque)
            graph.merge_frontend(MetadataGraph(planned), source=source)
            write_json(work/'plan.json', report)
            component['analysis'] = dict(state='analyzed', directory=str(work), **summary(data),
                                        transport_errors=diagnostics)
            reports.append(dict(component=component['path'], report=report, resolution=resolution_report))
            print(json.dumps(dict(component=component['path'], sources=len(rows),
                                  constructors=len(planned['constructors']))), flush=True)
        graph.document['evidence']['frontends'] = reports
        graph.document['inputs'] = component_inputs(document)
        write_json(output/'reader.json', dict(images=additions, transport_errors=dict(bridge.errors),
            missing_images=view.missing_images, missing_symbols=dict(view.missing_symbols),
            ambiguous_symbols=dict(view.ambiguous_symbols), export_errors=view.export_errors,
            reused_components=len(reused), analyzed_components=len(document['components'])-len(reused),
            reuse_context_change=reuse_reason))
        write_json(output/'build.json', provenance([Path(c['binary']) for c in document['components'] if 'binary' in c]+
            [f.path for f in family.files]+[toolchain/'build.json', library, toolchain/'build/swift-type-graph-json',
             Path(__file__), Path(__file__).with_name('component_graph.py'), Path(__file__).with_name('swift_cache_view.py')]+
            [frontend/n for n in ('static_mirror.py','generation_graph.py','analysis.py')]+reuse_files,
            operation='component-metadata-analysis', component_inputs=graph.document['inputs']))
        return graph
    finally:
        if bridge is not None:
            bridge.close()
        family.close()


def generation_results(document, graph):
    results = {}
    for row in graph.document['requests']:
        source = row.get('source')
        if not isinstance(source, dict):
            continue
        count = results.setdefault(source['input'], Counter())
        count['requests'] += 1
        count.update(row['facts'][1:])
    for component in document['components']:
        count = results.get(component_identity(component), Counter())
        component['generation'] = dict(state='evaluated', **count)
        component['installed'] = False
    return document


def attribute_results(discovery, expansion, coverage):
    """Attribute existing results by exact component identity, never app name."""
    known={component_identity(row):row for row in expansion['components']}
    rows=[]
    for component in discovery['components']:
        identity=component_identity(component)
        source=known.get(identity)
        row={key:component[key] for key in ('path','kind','image_uuid','sha256') if key in component}
        row['id']=identity
        row['matched']=source is not None
        if source is None:
            row.update(analysis=dict(state='not-analyzed'),generation=dict(state='pending'))
        else:
            row.update(analysis=deepcopy(source['analysis']),generation=deepcopy(source['generation']))
        rows.append(row)
    facts=Counter()
    for row in rows:
        facts.update({key:value for key,value in row['generation'].items() if key!='state'})
    return dict(schema=1,kind='application-component-generation',roots=discovery['roots'],components=rows,
        summary=dict(discovered=len(rows),matched=sum(row['matched'] for row in rows),
                     not_analyzed=sum(not row['matched'] for row in rows),request_facts=dict(facts)),
        expansion_verification=deepcopy(coverage.get('verification')),
        installed=None,observed_application_use=None,
        scope='Per-component results from the referenced expansion; connections remain in the referenced '
              'discovery manifest. Request counts overlap between apps and are not unique cache additions. '
              'Expansion verification does not establish installed or application use.')
