"""Construct, export and prepare verification of a portable Swift dependency graph."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

from .exports import require
from .loader_generation import LoaderFamily
from .metadata_graph import MetadataGraph
from .swift_graph import framework_owners
from .swift_metadata import ROOT, provenance, write_json
from . import witness_graph


def analyze(cache, binaries, catalog, toolchain, output):
    """Static evidence enters the same graph consumed by the runtime worker."""
    frontend = ROOT.parent / 'swift-analysis/lib'
    sys.path.insert(0, str(frontend))
    from static_mirror import scan, resolve_cache
    from generation_graph import plan, sources
    from analysis import command, read_jsonl
    graph = MetadataGraph()
    family = LoaderFamily(cache)
    try:
        owners = framework_owners(family)
    finally:
        family.close()
    reports = []
    for index, binary in enumerate(binaries):
        work = output / str(index)
        work.mkdir(parents=True)
        scan(SimpleNamespace(output=work/'semantic', toolchain=toolchain, binary=[binary], arch='x86_64'))
        resolve_cache(SimpleNamespace(output=work/'resolved', semantic=work/'semantic',
                                      toolchain=toolchain, binary=binary, cache=cache))
        semantic = work/'resolved'
        rows = sources(json.loads((semantic/'types.json').read_text()))
        opaque = json.loads((semantic/'cache-view/opaque-requests.json').read_text())['requests']
        names = sorted({r['name'] for r in rows if r['name']} | {r['name'] for r in opaque} |
                       {a for r in opaque for a in r['arguments'] if a})
        command([str(toolchain/'build/swift-type-graph-json')], work/'type-trees.jsonl',
                stdin=''.join(json.dumps(n)+'\n' for n in names))
        trees = {r['input']: r for r in read_jsonl(work/'type-trees.jsonl')}
        document, report = plan(rows, trees, owners, catalog, opaque)
        graph.merge_frontend(MetadataGraph(document), source=hashlib.sha256(binary.read_bytes()).hexdigest())
        reports.append(dict(binary=str(binary), report=report))
    graph.document['evidence']['frontends'] = reports
    graph.document['inputs'] = binary_inputs(binaries, graph.architecture)
    return graph


def execute(runner, phase, bundle, output, *, check=True):
    """The adapter owns transport; no implicit host execution, SSH, or reboot."""
    with output.open('wb') as stream, output.with_suffix('.stderr').open('wb') as errors:
        return subprocess.run([str(runner), phase, str(bundle.resolve())],
                              stdout=stream, stderr=errors, check=check)


def binary_inputs(binaries, architecture='x86_64'):
    return sorted([dict(kind='binary-input', architecture=architecture,
                        sha256=hashlib.sha256(p.read_bytes()).hexdigest()) for p in binaries],
                  key=lambda row: row['sha256'])


def reused_graph(path, binaries, inputs=None):
    graph = MetadataGraph(json.loads(path.read_text()))
    require(graph.document.get('inputs') == (inputs if inputs is not None else binary_inputs(binaries, graph.architecture)),
            'request graph binary inputs differ or are missing; renew analysis')
    return graph


def expand(args):
    started = time.monotonic()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    catalog = json.loads(args.catalog.read_text())
    from .witness_initializers import normalize
    family=LoaderFamily(args.cache)
    try:
        catalog,initializers=normalize(catalog,family)
    finally:family.close()
    write_json(output/'witness-initializers.json',initializers)
    components, component_files = None, []
    if args.dependencies or args.cache_image:
        from .component_graph import discover
        from .component_metadata import component_inputs
        family = LoaderFamily(args.cache)
        try:
            runtime = json.loads(args.runtime_connections.read_text()) if args.runtime_connections else None
            components, component_files = discover(family, args.binary, args.root, runtime,
                                                  args.cache_image, args.dependencies, args.root_map)
        finally:
            family.close()
        write_json(output/'components.json', components)
    inputs = component_inputs(components) if components is not None else binary_inputs(args.binary)
    if args.inventory or args.reflection_graph:
        from .metadata_inventory import inputs as observation_inputs
        inputs += observation_inputs(args.inventory, args.reflection_graph)
    if args.request_graph:
        graph = reused_graph(args.request_graph, args.binary, inputs)
        if components is not None:
            for component in components['components']:
                component['analysis'] = dict(state='reused', request_graph=str(args.request_graph))
    elif args.inventory or args.reflection_graph:
        from .metadata_inventory import plan as inventory_plan
        family = LoaderFamily(args.cache)
        try:
            graph = inventory_plan(family, args.inventory, args.reflection_graph, catalog, args.toolchain)
        finally:
            family.close()
    elif components is not None:
        from .component_metadata import analyze as analyze_components
        graph = analyze_components(args.cache, components, catalog, args.toolchain, output/'analysis',
                                   reuse=args.reuse_expansion)
    else:
        graph = analyze(args.cache, args.binary, catalog, args.toolchain, output/'analysis')
    # Requests may originate from an earlier graph, but the explicit catalog is
    # the retained baseline for this expansion. Past outcomes are not new facts.
    graph.reset_results()
    graph.document['inputs'] = inputs
    graph.import_catalog(catalog)
    write_json(output/'requests.json', graph.document)
    family = LoaderFamily(args.cache)
    try:
        bound = graph.bind(family)
        cache_inputs = [f.path for f in family.files]
        # The isolated verifier remaps this symbolic allocation into its own
        # arena. Place it past the cache so source and owned pointers are distinct.
        address = (max(m.address+m.size for f in family.files for m in f.mappings)+4095) & ~4095
    finally:
        family.close()
    capture_start = time.monotonic()
    if args.saved_capture:
        raw = output/'capture.jsonl'
        raw.write_bytes(args.saved_capture.read_bytes())
        execution = dict(adapter='saved-capture', native_run=False, source=str(args.saved_capture.resolve()))
    else:
        from .runtime_capture import capture as capture_runtime
        witness_graph.prepare(args.cache, output/'requests.json', args.catalog, args.toolchain,
                              args.devkit, output/'worker', args.llvm)
        raw = output/'capture.jsonl'
        failures = capture_runtime(args.runner, output/'worker', raw, execute)
        execution = dict(adapter='external-runner', native_run=True, runner=str(args.runner),
                         constructor_failures=failures)
    capture_seconds = time.monotonic()-capture_start
    with raw.open() as stream:
        events = list(map(json.loads, stream))
    witness_summary = witness_graph.summarize(events)
    require(witness_summary['complete'], 'witness constructor capture was interrupted')
    family = LoaderFamily(args.cache)
    try:
        graph.record_capture(family, events)
    finally:
        family.close()
    graph.document['evidence']['execution'] = {k: v for k, v in execution.items()
                                              if k in ('adapter', 'native_run', 'constructor_failures')}
    result = graph.catalog()
    write_json(output/'catalog.json', result)
    write_json(output/'graph.json', graph.document)
    if components is not None:
        from .component_metadata import generation_results
        write_json(output/'components.json', generation_results(components, graph))
    os.environ['CACHE_TOOLCHAIN'] = str(args.dyld_toolchain.resolve())
    witness_graph.materialize(args.cache, output/'catalog.json', output/'allocation', address)
    witness_graph.replay_prepare(output/'allocation', output/'catalog.json', args.toolchain,
                                 args.devkit, output/'verification', args.llvm)
    coverage = graph.coverage()
    if args.runner:
        replay = output/'verification.jsonl'
        execution_result=execute(args.runner, 'verify', output/'verification', replay, check=False)
        layout = json.loads((output/'allocation/allocation.json').read_text())
        with replay.open() as stream:
            verified = witness_graph.replay_summary(layout, list(map(json.loads, stream)))
        verified['returncode']=execution_result.returncode
        verified['complete']=verified['complete'] and execution_result.returncode==0
        graph.document['evidence']['isolated_replay'] = dict(executed=True, installed=False, result=verified)
        coverage = graph.coverage()
        write_json(output/'graph.json', graph.document)
        write_json(output/'coverage.json', coverage)
        require(verified['complete'], 'isolated native verification failed; see coverage.json')
    write_json(output/'coverage.json', coverage)
    inputs = [args.catalog, args.toolchain/'build.json', args.devkit, raw, *args.binary,
              output/'allocation/build.json', output/'verification/build.json', *cache_inputs,
              *[Path(__file__).with_name(name) for name in
                ('metadata_expand.py', 'metadata_graph.py', 'swift_abi.py', 'swift_graph.py',
                 'witness_graph.py', 'runtime_capture.py', 'witness_initializers.py')]]
    inputs += [ROOT.parent/'swift-analysis/lib'/name for name in
               ('analysis.py', 'static_mirror.py', 'generation_graph.py')]
    inputs.append(output/'requests.json')
    inputs += component_files
    if args.inventory or args.reflection_graph:
        inputs += args.inventory + args.reflection_graph + [Path(__file__).with_name('metadata_inventory.py')]
    if args.runtime_connections:
        inputs.append(args.runtime_connections)
    if components is not None:
        inputs += [output/'components.json', Path(__file__).with_name('component_graph.py'),
                   Path(__file__).with_name('component_metadata.py')]
    inputs += sorted((output/'analysis').rglob('build.json'))
    if (output/'worker/build.json').exists():
        inputs.append(output/'worker/build.json')
    if args.request_graph:
        inputs.append(args.request_graph)
    if args.runner:
        inputs.append(args.runner)
    if args.saved_capture:
        inputs.append(args.saved_capture)
    else:
        inputs += sorted((output/'capture-attempts').glob('*/capture.*'))
        inputs += sorted((output/'capture-attempts').glob('*/names.tsv'))
        inputs.append(output/'capture-attempts.json')
    write_json(output/'build.json', provenance(inputs, operation='metadata-expand',
               architecture=graph.architecture, cache_uuid=bound['cache_uuid'], execution=execution,
               measurements=dict(total_seconds=time.monotonic()-started, capture_seconds=capture_seconds,
                                 catalog_bytes=(output/'catalog.json').stat().st_size,
                                 payload_bytes=(output/'allocation/payload.bin').stat().st_size)))
    print(json.dumps(dict(output=str(output), requests=coverage['constructor_requests'],
                         metadata=len(result['records']), witnesses=len(result['witnesses']),
                         added=coverage['generation']['added'], verification=coverage['verification']), indent=2))
    return output


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('cache', 'catalog', 'toolchain', 'dyld-toolchain', 'devkit', 'llvm', 'output'):
        parser.add_argument('--'+name, type=Path, required=True)
    parser.add_argument('--binary', type=Path, action='append', default=[],
                        help='target binary; repeat for multiple static frontends')
    parser.add_argument('--inventory', type=Path, action='append', default=[],
                        help='batch saved swift-inspect JSON or type-processes.json; repeatable, skips binary discovery')
    parser.add_argument('--reflection-graph', type=Path, action='append', default=[],
                        help='batch saved swift-live-capture graph.json dependencies; repeatable')
    parser.add_argument('--dependencies', action='store_true',
                        help='discover and analyze linked libraries, bundled helpers and declared services')
    parser.add_argument('--cache-image', action='append', default=[],
                        help='also inventory this shared-cache image; repeat to select multiple libraries')
    parser.add_argument('--root', type=Path, action='append', default=[],
                        help='target filesystem root; repeat for System and cryptex views')
    from .component_graph import root_mapping
    parser.add_argument('--root-map', type=root_mapping, action='append', default=[],
                        help='map /TARGET/PREFIX=HOST_DIRECTORY; repeat for cryptex aliases')
    parser.add_argument('--runtime-connections', type=Path,
                        help='observed process launches, image loads and client-to-service connections')
    requests = parser.add_mutually_exclusive_group()
    requests.add_argument('--request-graph', type=Path,
                        help='reuse explicit portable requests instead of running static analysis')
    requests.add_argument('--reuse-expansion', type=Path,
                        help='reuse unchanged component frontends and analyze additional or changed components')
    parser.add_argument('--runner', type=Path, help='adapter invoked as RUNNER capture|verify BUNDLE; with --saved-capture, verify only')
    parser.add_argument('--saved-capture', type=Path, help='reuse matching-runtime construction evidence; add --runner for native verification')
    args = parser.parse_args(argv)
    if not (args.binary or args.cache_image or args.inventory or args.reflection_graph):
        parser.error('provide a binary, cache image, inventory, or reflection graph')
    if not args.runner and not args.saved_capture:
        parser.error('provide --runner or --saved-capture')
    if (args.root or args.root_map or args.runtime_connections) and not args.dependencies:
        parser.error('--root, --root-map and --runtime-connections require --dependencies')
    if args.reuse_expansion and not (args.dependencies or args.cache_image):
        parser.error('--reuse-expansion requires component discovery')
    for field in ('cache', 'catalog', 'toolchain', 'dyld_toolchain', 'devkit', 'llvm', 'runner'):
        value = getattr(args, field)
        if value is not None:
            setattr(args, field, value.resolve())
    args.binary = [p.absolute() for p in args.binary]
    expand(args)
    return 0
