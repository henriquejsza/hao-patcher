"""Discover app components with explicit library, bundle, service and runtime edges."""
import argparse
from collections import defaultdict, deque
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import plistlib
import posixpath
import re
import struct
import subprocess
from xml.parsers.expat import ExpatError

from .cache import commands
from .cache_exports import FinalGraph
from .exports import Refusal, cstring, require, span
from .loader_generation import LoaderFamily
from .objc_transfer import sections
from .provider_identity import x86_slice
from .run_loaders import dependencies
from .run_rpaths import rpath_stack, dependency_candidates
from .swift_metadata import pin, provenance, write_json

BUNDLES = {'.app', '.xpc', '.appex', '.framework', '.bundle', '.plugin'}


class Roots:
    """Overlay target roots; absolute symlinks resolve inside those roots."""
    def __init__(self, roots, mappings=()):
        self.mounts = [(posixpath.normpath(prefix), Path(path).absolute(), Path(path).resolve())
                       for prefix, path in [*mappings, *(('/', p) for p in roots)]]
        self.roots = list(dict.fromkeys(resolved for _, _, resolved in self.mounts))
        self.lookups = {}

    def logical(self, path):
        path = Path(path).absolute()
        for prefix, original, resolved in sorted(self.mounts, key=lambda m:-len(m[1].parts)):
            for root in (original, resolved):
                if path.is_relative_to(root):
                    return posixpath.normpath(prefix.rstrip('/') + '/' + path.relative_to(root).as_posix())
        return str(path)

    def find(self, logical):
        if logical not in self.lookups:
            self.lookups[logical] = self._find(logical)
        return self.lookups[logical]

    def _find(self, logical):
        logical = posixpath.normpath(logical)
        seen = set()
        while logical not in seen:
            seen.add(logical)
            redirect = None
            candidates = [(prefix, root) for prefix, _, root in self.mounts
                          if prefix == '/' or logical == prefix or logical.startswith(prefix+'/')]
            longest = max((len(prefix) for prefix, _ in candidates), default=0)
            for prefix, root in candidates:
                if len(prefix) != longest:
                    continue
                physical = root
                parts = PurePosixPath(logical[len(prefix):].lstrip('/')).parts
                for index, part in enumerate(parts):
                    physical = physical / part
                    if physical.is_symlink():
                        target = os.readlink(physical)
                        directory = prefix.rstrip('/') + '/' + '/'.join(parts[:index])
                        redirect = posixpath.normpath(posixpath.join(
                            target if target.startswith('/') else posixpath.join(directory, target),
                            *parts[index+1:]))
                        break
                    if not physical.exists():
                        break
                if redirect is not None:
                    break
                if physical.exists() and physical.is_relative_to(root):
                    return physical
            if redirect is None:
                return None
            logical = redirect
        raise ValueError('target symlink cycle: ' + logical)


def root_mapping(value):
    prefix, separator, path = value.partition('=')
    if not separator or not prefix.startswith('/') or not path:
        raise argparse.ArgumentTypeError('expected /TARGET/PREFIX=HOST_DIRECTORY')
    return prefix, Path(path)


def disk_commands(data):
    start, size, _ = x86_slice(data)
    image = span(data, start, size)
    count, extent = struct.unpack_from('<II', image, 16)
    body = span(image, 32, extent)
    offset, result = 0, []
    for _ in range(count):
        kind, width = struct.unpack('<II', span(body, offset, 8))
        require(width >= 8, 'short Mach-O command')
        result.append((32+offset, kind, span(body, offset, width)))
        offset += width
    require(offset == extent, 'Mach-O command extent differs')
    return result


def image_info(rows):
    uuids = [bytes(raw[8:24]).hex() for _, kind, raw in rows if kind == 0x1b]
    return dict(image_uuid=uuids[0] if len(uuids) == 1 else None,
                swift_reflection=any(name.startswith('__swift5_') and size
                                     for _, name, _, size in sections(rows)))


def plist(path):
    try:
        return plistlib.loads(path.read_bytes())
    except ExpatError:
        # Some target plists use Apple's accepted unquoted XML attributes.
        return plistlib.loads(subprocess.check_output(['plutil', '-convert', 'xml1', '-o', '-', str(path)]))


def bundle_executable(path, info, roots):
    name = info.get('CFBundleExecutable')
    if not isinstance(name, str) or not name:
        return None
    for candidate in (path/'Contents/MacOS'/name, path/name, path/'Versions/Current'/name):
        physical = roots.find(roots.logical(candidate))
        if physical is not None and physical.is_file():
            return physical
    return None


def service_index(roots):
    result, inputs, unresolved = {}, [], []
    for root in roots.roots:
        for directory in ('System/Library/LaunchAgents', 'System/Library/LaunchDaemons',
                          'Library/LaunchAgents', 'Library/LaunchDaemons'):
            for path in sorted((root/directory).glob('*.plist')):
                logical = roots.logical(path)
                physical = roots.find(logical)
                if physical is None:
                    unresolved.append(dict(path=logical, reason='service declaration target absent from supplied roots'))
                    continue
                info = plist(physical)
                inputs.append(physical)
                executable = info.get('Program') or next(iter(info.get('ProgramArguments', [])), None)
                if not executable or not executable.startswith('/'):
                    continue
                names = set(info.get('MachServices', {}))
                if info.get('Label'):
                    names.add(info['Label'])
                for name in names:
                    result.setdefault(name, []).append(dict(executable=executable,
                        declaration=roots.logical(path), label=info.get('Label')))
    return result, inputs, unresolved


def discover(family, binaries, root_paths=(), runtime=None, cache_images=(), recursive=True, root_maps=()):
    roots = Roots(root_paths, root_maps)
    cache = FinalGraph(family, {})
    addresses = dict(family.images)
    services, inputs, unresolved = service_index(roots)
    components, edges, edge_keys = {}, [], set()
    pending, visited, bundles, parsed = deque(), set(), set(), {}
    explicit = {roots.logical(p): (roots.find(roots.logical(p))
        if any(Path(p).absolute().is_relative_to(root) for _, original, resolved in roots.mounts
               for root in (original, resolved)) else Path(p)) for p in binaries}
    for path in explicit:
        pending.append((path, path, ()))
    for path in cache_images:
        pending.append((path, path, ()))
    runtime_events = runtime.get('events', []) if runtime else []
    runtime_by_source = defaultdict(list)
    for event in runtime_events:
        source = event.get('source')
        if source:
            runtime_by_source[cache.canonical(source) or source].append(event)

    # A closed cache-only library graph cannot consume the caller's LC_RPATHs.
    # Preserve the full caller context if any reachable link leaves that graph.
    # Missing absolute links do not consume rpaths and remain unresolved below.
    contextual, parents = set(), defaultdict(set)
    if recursive:
        for cached_path in addresses:
            try:
                _, cached_image = cache.image(cached_path)
            except (ValueError, Refusal):
                continue  # Discovery records the actual parse error if reached.
            for dependency in cached_image.dependencies:
                target = cache.canonical(dependency.path)
                if target and dependency.path.startswith('/'):
                    parents[target].add(cached_path)
                elif (not dependency.path.startswith('/') or explicit.get(dependency.path) is not None
                      or roots.find(dependency.path) is not None):
                    contextual.add(cached_path)
        todo = list(contextual)
        while todo:
            for parent in parents[todo.pop()] - contextual:
                contextual.add(parent)
                todo.append(parent)

    def edge(source, target, relation, **evidence):
        row = dict(source=source, target=target, relation=relation, **evidence)
        key = json.dumps(row, sort_keys=True)
        if key not in edge_keys:
            edges.append(row)
            edge_keys.add(key)

    def helpers(source):
        logical = PurePosixPath(source)
        parents = [p for p in logical.parents if p.suffix in BUNDLES]
        if not parents:
            return
        # The outer app includes its framework/XPC descendants. Do not scan /System.
        owner = parents[-1]
        if str(owner) in bundles:
            return
        bundles.add(str(owner))
        physical = roots.find(str(owner))
        if physical is None or not physical.is_dir():
            return
        for info_path in sorted(physical.rglob('Info.plist')):
            bundle = info_path.parent.parent if info_path.parent.name == 'Contents' else info_path.parent
            if bundle.suffix not in BUNDLES or bundle == physical:
                continue
            resolved_info = roots.find(roots.logical(info_path))
            if resolved_info is None:
                unresolved.append(dict(source=source, path=roots.logical(info_path),
                                       reason='bundle declaration target absent from supplied roots'))
                continue
            info = plist(resolved_info)
            inputs.append(resolved_info)
            executable = bundle_executable(bundle, info, roots)
            if executable is None:
                unresolved.append(dict(source=source, relation='bundled-component',
                    path=roots.logical(bundle), reason='bundle has no readable declared executable'))
                continue
            child = roots.logical(executable)
            if bundle.suffix == '.xpc' and info.get('CFBundleIdentifier'):
                services.setdefault(info['CFBundleIdentifier'], []).append(dict(
                    executable=child, declaration=roots.logical(info_path)))
            edge(source, child, 'bundled-component', declaration=roots.logical(info_path),
                 bundle_identifier=info.get('CFBundleIdentifier'), observed=False)
            pending.append((child, child, ()))

    while pending:
        requested, main, inherited = pending.popleft()
        canonical = cache.canonical(requested)
        path = canonical or requested
        closed_cache = canonical and path not in contextual
        context = (path, None, ()) if closed_cache else (path, main, inherited)
        if context in visited:
            continue
        visited.add(context)
        try:
            if path in parsed:
                component, deps, rpaths, strings = parsed[path]
            else:
                if canonical:
                    rows = commands(family, addresses[path])
                    _, image = cache.image(path)
                    deps = [(d.path, d.weak) for d in image.dependencies]
                    rpaths = [cstring(raw, struct.unpack_from('<I', raw, 8)[0])[0]
                              for _, kind, raw in rows if kind == 0x8000001c]
                    component = dict(path=path, kind='cache-image', **image_info(rows))
                    # C string literals only establish candidates, never observed XPC use.
                    strings = set()
                    for _, name, address, size in sections(rows):
                        if name == '__cstring' and size:
                            strings.update(family.read(address, size).split(b'\0'))
                else:
                    physical = explicit.get(path) or roots.find(path)
                    if physical is None or not physical.is_file():
                        unresolved.append(dict(path=path, reason='component absent from supplied roots and cache'))
                        continue
                    data = physical.read_bytes()
                    deps, rpaths = dependencies(data)
                    component = dict(path=path, kind='disk-image', binary=str(physical),
                        sha256=hashlib.sha256(data).hexdigest(), **image_info(disk_commands(data)))
                    inputs.append(physical)
                    strings = set(re.findall(rb'[ -~]{6,}', data))
                parsed[path] = component, deps, rpaths, strings
            if path not in components:
                components[path] = dict(component, analysis='pending', generation='pending')
                if not recursive:
                    continue
                helpers(path)
                for name, declarations in services.items():
                    if name.encode() not in strings:
                        continue
                    for declaration in declarations:
                        target = declaration['executable']
                        edge(path, target, 'service-name-reference', service=name,
                             declaration=declaration['declaration'], observed=False)
                        pending.append((target, target, ()))
                # Events must identify the client executable, not just parent PID.
                for event in runtime_by_source[path]:
                    relation = event.get('kind')
                    require(relation in ('process-launch', 'xpc-connection', 'image-load'),
                            'unknown runtime dependency event')
                    targets = [dict(executable=event['target'])] if event.get('target') else services.get(event.get('service'), [])
                    if not targets:
                        unresolved.append(dict(source=path, event=event, reason='runtime service executable unresolved'))
                    for target in targets:
                        destination = target['executable']
                        edge(path, destination, relation, observed=event.get('observed', True), evidence=event)
                        pending.append((destination, destination if relation != 'image-load' else main, ()))
            stack = rpath_stack(rpaths, path, inherited)
            if closed_cache:
                stack = ()
            for dependency, weak in deps:
                candidates = []
                try:
                    for candidate in dependency_candidates(dependency, path, main, stack):
                        candidates.append(candidate)
                        target = cache.canonical(candidate)
                        disk = None if target else explicit.get(candidate) or roots.find(candidate)
                        if target or disk is not None and disk.is_file():
                            target = target or candidate
                            edge(path, target, 'linked-library', load_path=dependency, weak=weak, observed=False)
                            pending.append((target, main, stack))
                            break
                    else:
                        unresolved.append(dict(source=path, relation='linked-library',
                            load_path=dependency, weak=weak, candidates=candidates, reason='dependency not found'))
                except (ValueError, Refusal) as error:
                    unresolved.append(dict(source=path, relation='linked-library',
                        load_path=dependency, reason=str(error)))
        except (ValueError, Refusal, OSError) as error:
            unresolved.append(dict(path=path, reason=str(error)))
    document = dict(schema=1, kind='application-components', roots=sorted(set(explicit) | set(cache_images)),
        filesystem_roots=[str(p) for p in roots.roots], components=[components[p] for p in sorted(components)],
        filesystem_mappings=[dict(target=prefix, root=str(path)) for prefix, _, path in roots.mounts],
        edges=sorted(edges, key=lambda e:json.dumps(e, sort_keys=True)),
        unresolved=[json.loads(value) for value in sorted({json.dumps(e, sort_keys=True) for e in unresolved})],
        runtime_events_supplied=len(runtime_events), recursive=recursive,
        scope='Static linked libraries and eligible helpers/services, plus supplied observed connections. '
              'A string reference or bundle membership does not prove service activation. '
              'Unobserved dynamic connections remain open.')
    return document, sorted(set(inputs))


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--binary', type=Path, action='append', default=[])
    parser.add_argument('--manifest', type=Path, help='attribute results to an existing discovery manifest')
    parser.add_argument('--generation', type=Path, help='metadata-expand artifact supplying component results')
    parser.add_argument('--root', type=Path, action='append', default=[])
    parser.add_argument('--root-map', type=root_mapping, action='append', default=[],
                        help='map /TARGET/PREFIX=HOST_DIRECTORY; repeat for cryptex aliases')
    parser.add_argument('--runtime-connections', type=Path)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args(argv)
    if args.manifest:
        if not args.generation or args.binary or args.cache or args.root or args.root_map or args.runtime_connections:
            parser.error('--manifest requires --generation and accepts no discovery inputs')
        from .component_metadata import attribute_results
        inputs=[args.manifest,args.generation/'components.json',args.generation/'coverage.json',args.generation/'build.json']
        discovery,expansion,coverage,_=[json.loads(path.read_text()) for path in inputs]
        result=attribute_results(discovery,expansion,coverage)
        result.update(discovery=pin(args.manifest),expansion=[pin(path) for path in inputs[1:]])
        args.output.mkdir(parents=True,exist_ok=False)
        write_json(args.output/'component-results.json',result)
        write_json(args.output/'build.json',provenance(inputs+[Path(__file__),Path(__file__).with_name('component_metadata.py')],
                                                      operation='application-component-generation'))
        print(json.dumps(result['summary'],indent=2))
        return 0
    if not args.cache or not args.binary or args.generation:
        parser.error('discovery requires --cache and --binary; --generation requires --manifest')
    args.output.mkdir(parents=True, exist_ok=False)
    runtime = json.loads(args.runtime_connections.read_text()) if args.runtime_connections else None
    family = LoaderFamily(args.cache)
    try:
        result, inputs = discover(family, args.binary, args.root, runtime, root_maps=args.root_map)
        write_json(args.output/'components.json', result)
        write_json(args.output/'build.json', provenance(inputs+[Path(__file__)]+[f.path for f in family.files]+
            ([args.runtime_connections] if args.runtime_connections else []), operation='application-components'))
    finally:
        family.close()
    print(json.dumps(dict(components=len(result['components']), edges=len(result['edges']),
                         unresolved=len(result['unresolved'])), indent=2))
