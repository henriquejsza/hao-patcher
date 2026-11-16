"""Read-only, build-specific intake for a cache producer run.

This writes input records, never cache bytes or source/global manifests. Intake
is not certification: all producer and independent semantic gates still run.
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import struct

from .exports import require, span, cstring
from .provider_identity import x86_slice

BASE = 'dyld_shared_cache_x86_64'
PROVIDERS = {}  # Provider choices are data under features/.



def rooted(root, virtual):
    root = Path(root).resolve(strict=True)
    require(virtual.startswith('/') and '..' not in Path(virtual).parts, 'invalid virtual input path')
    path = (root/virtual.lstrip('/')).resolve(strict=True)
    require(path.is_relative_to(root) and path.is_file(), 'input escapes supplied root or is not a file: '+virtual)
    return path


def pin(path):
    path = Path(path).resolve(strict=True)
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        before = os.fstat(stream.fileno())
        for data in iter(lambda: stream.read(8 << 20), b''):
            digest.update(data)
        after = os.fstat(stream.fileno())
        path_after = path.stat()
    identity = lambda st: (st.st_dev, st.st_ino, st.st_size, st.st_mtime_ns, st.st_ctime_ns)
    require(identity(before) == identity(after) == identity(path_after), 'source changed while hashing: '+str(path))
    return dict(path=str(path), size=after.st_size, sha256=digest.hexdigest())


def build_record(root, build):
    path = rooted(root, '/System/Library/CoreServices/SystemVersion.plist')
    record = pin(path)
    value = plistlib.loads(path.read_bytes())
    require(value.get('ProductBuildVersion') == build, 'source build differs: '+str(root))
    require(pin(path) == record, 'build evidence changed while reading')
    return dict(**record, product_build=value['ProductBuildVersion'], product_version=value.get('ProductVersion'))


def macho_record(path, canonical, *, dyld=False, compiler_input=None):
    record = pin(path); data = path.read_bytes()
    require(hashlib.sha256(data).hexdigest() == record['sha256'], 'Mach-O changed after pin')
    offset, size, _ = x86_slice(data); image = span(data, offset, size)
    magic, cpu, subtype, kind, count, command_size, flags, reserved = struct.unpack('<8I', span(image, 0, 32))
    require((magic, cpu, subtype) == (0xfeedfacf, 0x1000007, 3), 'not plain x86_64 subtype3')
    require(kind in ((7,) if dyld else (6, 8)) and reserved == 0, 'wrong Mach-O input type')
    commands = span(image, 32, command_size); position = 0; names = []
    for _ in range(count):
        command, length = struct.unpack('<II', span(commands, position, 8))
        require(length >= 8 and length % 8 == 0, 'invalid Mach-O command size')
        raw = span(commands, position, length)
        if command == 0x0d:
            name_offset = struct.unpack_from('<I', span(raw, 0, 24), 8)[0]
            require(24 <= name_offset < length, 'invalid install-name offset')
            names.append(cstring(raw, name_offset)[0])
        position += length
    require(position == command_size, 'Mach-O command extent differs')
    require(len(names) == (1 if kind == 6 else 0), 'missing/duplicate/unexpected install name')
    install_name = names[0] if names else canonical
    normalization = None
    if not dyld and install_name != canonical:
        normalization = dict(source_install_name=install_name, canonical_install_name=canonical)
    return dict(**record, canonical_path=canonical, slice_offset=offset, slice_size=size,
                slice_sha256=hashlib.sha256(image).hexdigest(), filetype=kind,
                install_name=install_name, normalization=normalization)


def cache_records(root):
    path = rooted(root, '/System/Library/dyld/'+BASE)
    main_pin = pin(path)
    with path.open('rb') as stream:
        header = stream.read(552)
        require(len(header) == 552 and header[:16] == b'dyld_v1  x86_64\0', 'unsupported Apple cache architecture/header')
        suboffset, count = struct.unpack_from('<II', header, 392)
        image_offset, images = struct.unpack_from('<II', header, 448)
        require(0 < count < 128 and 0 < images < 65536, 'invalid source cache inventory counts')
        require(552 <= suboffset and suboffset+count*56 <= main_pin['size'], 'subcache table outside file')
        require(552 <= image_offset and image_offset+images*32 <= main_pin['size'], 'image table outside file')
        stream.seek(suboffset); table = stream.read(count*56)
    rows = [main_pin]; suffixes = []
    for index in range(count):
        entry = span(table, index*56, 56); suffix = cstring(entry, 24)[0]
        require(re.fullmatch(r'\.[0-9]{2}', suffix) is not None and suffix == f'.{index+1:02d}',
                'unsupported/noncontiguous source subcache suffix')
        child = rooted(root, '/System/Library/dyld/'+BASE+suffix); row = pin(child)
        with child.open('rb') as stream:
            child_header = stream.read(104)
        require(len(child_header) == 104 and child_header[:16] == header[:16]
                and child_header[88:104] == bytes(entry[:16]), 'source subcache UUID/architecture mismatch')
        rows.append(row); suffixes.append(suffix)
    expected = {BASE, BASE+'.atlas', BASE+'.map'} | {BASE+s for s in suffixes}
    observed = {p.name for p in path.parent.glob(BASE+'*')}
    require(observed == expected, 'source cache has missing or unexpected family files')
    rows += [pin(rooted(root, '/System/Library/dyld/'+BASE+suffix)) for suffix in ('.atlas', '.map')]
    require(pin(path) == main_pin, 'source cache changed during intake')
    return dict(main=str(path), files=rows, images=images, cache_files=count+1,
                main_uuid=header[88:104].hex(), architecture='x86_64')


def pristine_build_record(root, build, cache, identity=None, identity_sha256=None):
    require((identity is None) == (identity_sha256 is None), 'pristine identity requires an external SHA256')
    if identity is None:
        return build_record(root, build)
    require(re.fullmatch(r'[0-9a-f]{64}', identity_sha256) is not None, 'invalid pristine identity SHA256')
    identity = Path(identity).resolve(strict=True); record = pin(identity)
    require(record['sha256'] == identity_sha256, 'pristine identity pin differs')
    value = json.loads(identity.read_text())
    require(value.get('schema') == 1 and value.get('build') == build, 'pristine identity build/schema differs')
    rows = value.get('files', [])
    require(len(rows) == len(cache['files']) and len({r['path'] for r in rows}) == len(rows),
            'pristine identity inventory incomplete/duplicate')
    expected = {r['path']:(r['size'],r['sha256']) for r in cache['files']}
    actual = {str(Path(r['path']).resolve()):(r['size'],r['sha256']) for r in rows}
    require(actual == expected, 'pristine identity family pins differ')
    require(pin(identity) == record, 'pristine identity changed while reading')
    version = root/'System/Library/CoreServices/SystemVersion.plist'
    if version.exists():
        build_record(root, build)
    return dict(**record, product_build=build, evidence_kind='externally pinned complete pristine family manifest')


def prepare_inputs(pristine_os, patched_system, build, output, *, pristine_identity=None, pristine_identity_sha256=None, provider_profile=None):
    """Return/write fresh run pins; no old capture/config data are consulted."""
    require(re.fullmatch(r'[0-9]{2}[A-Z][0-9]+[a-z]?', build) is not None, 'invalid build identifier')
    from .provider_profile import select
    selected, profile, additions = select(provider_profile,build)
    pristine = Path(pristine_os).resolve(strict=True); patched = Path(patched_system).resolve(strict=True)
    require(pristine.is_dir() and patched.is_dir() and pristine != patched, 'distinct source roots required')
    out = Path(output).resolve()
    require(not out.exists() and not out.is_relative_to(pristine) and not out.is_relative_to(patched),
            'output must be fresh and outside source roots')
    cache = cache_records(pristine)
    builds = dict(pristine_os=build_record(patched, build),
                  patched_system=build_record(patched, build))
    # Optional per-provider sources (pm 2026-11-14, fold-in with live_text_framework r9): {key: {path, sha256}} reads that
    # provider from a built file instead of the System view; the hash must match. Every provider's origin is recorded.
    sources = dict((profile or {}).get('sources', {}))
    require(set(sources) <= set(selected), 'provider source for an unselected provider')
    def provider_file(key, path):
        if key not in sources:
            return rooted(patched, path)
        source = Path(sources[key]['path']).resolve(strict=True)
        require(source.is_file() and pin(source)['sha256'] == sources[key]['sha256'], 'provider source hash differs: ' + key)
        return source
    providers = {key: macho_record(provider_file(key, path), path, compiler_input=additions.get(key))
                 for key, path in selected.items()}
    provider_sources = {key: dict(origin='file' if key in sources else 'system', install_path=path,
                                  path=providers[key]['path'], sha256=providers[key]['sha256'])
                        for key, path in selected.items()}
    require(len({r['path'] for r in providers.values()}) == len(selected), 'provider sources alias each other')
    dyld = macho_record(rooted(patched, '/usr/lib/dyld'), '/usr/lib/dyld', dyld=True)
    capture = dict(schema=1, build=build, **cache)
    provider_manifest = dict(schema=1, build=build, providers=selected,
                             inputs={**providers, 'cache_main':cache['files'][0]},
                             expected_install_names={k:r['install_name'] for k,r in providers.items() if r['normalization']})
    provenance = dict(schema=1, kind='dyld-cache-build/run-inputs', build=build,
                      pristine_os=str(pristine), patched_system=str(patched), build_evidence=builds,
                      provider_count=len(selected), provider_sources=provider_sources, target_dyld=dyld,
                      source_module=pin(Path(__file__)),
                      certification_complete=False, program_root_inventory_complete=False,
                      scope='input identity and provenance only; all producer/certifier gates still required')
    if profile is not None:
        provider_manifest['provider_profile'] = profile
        provenance['provider_profile'] = profile
    # Validate all bytes again before publishing pins. Intake never marks readiness.
    records = [*cache['files'], *providers.values(), dyld, *builds.values()]
    for row in records:
        actual = pin(Path(row['path']))
        require(all(actual[k] == row[k] for k in ('path', 'size', 'sha256')), 'input changed before publication')
    out.mkdir(parents=True)
    result = {}
    for name, value in [('capture-manifest.json', capture), ('provider-inputs.json', provider_manifest),
                        ('run-provenance.json', provenance)]:
        destination = out/name; destination.write_text(json.dumps(value, indent=2, sort_keys=True)+'\n')
        result[name] = pin(destination)
    return result
