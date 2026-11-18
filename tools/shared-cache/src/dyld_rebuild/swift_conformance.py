"""Rebuild conformance lookups from a final cache's Swift sections and ObjC identities.

The Apple host adapter writes hashes and exercises the runtime reader; Python
independently checks every serialized row. No target code or initializer runs.
"""
from collections import Counter
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from .cache import commands
from .exports import require
from .host_tools import compile_adapter
from .image_indexes import swift_roots
from .loader_generation import LoaderFamily
from .objc_emit import FamilyReader
from .objc_tables import family_string, objc_header, read_table as objc_table
from .objc_transfer import sections
from .swift_refs import read_table

KINDS = ('type', 'metadata', 'foreign')
ROOT = Path(__file__).resolve().parents[2]


def canonical_rows(kind, rows, read_name):
    """Rows are (key word, protocol offset, packed conformance/owner), without chain bits."""
    require(kind in KINDS, 'unknown conformance table kind')
    rows = list(rows)
    require(len(rows) <= 1_000_000, 'conformance count exceeds bound')
    names, canonical = {}, {}
    for a, b, raw in rows:
        require(all(type(v) is int and 0 <= v < 1 << 64 for v in (a, b, raw)), 'invalid conformance word')
        require(b < 1 << 47 and not raw & 1, 'protocol overflow or preexisting duplicate flag')
        if kind == 'foreign':
            offset, length = a & ((1 << 48) - 1), a >> 48
            require(offset + max(length, 1) <= 1 << 36, 'foreign name extent exceeds oracle bound')
            name = bytes(read_name(offset, length))
            require(len(name) == length, 'truncated foreign identity')
            names[a] = name
            canonical[name] = min(a, canonical.get(name, a))
        else:
            require(a < 1 << 47, 'conformance key offset overflow')
    if kind == 'foreign':
        rows = [(canonical[names[a]], b, raw) for a, b, raw in rows]
    rows.sort(key=lambda r: (r[0] & ((1 << 48) - 1), r[0] >> 48, r[1], r[2])
              if kind == 'foreign' else r)
    return rows, names


def writer(directory):
    return compile_adapter(directory, 'swift-conformance-writer', [ROOT/'tools/swift-conformance-writer.cpp'])


def emit(binary, directory, kind, rows, read_name):
    directory = Path(directory)
    rows, names = canonical_rows(kind, rows, read_name)
    data = bytearray(struct.pack('<III', 0x31435753, KINDS.index(kind), len(rows)))
    for a, b, raw in rows:
        data += struct.pack('<QQQ', a, b, raw)
        if kind == 'foreign':
            data += names[a]
    source, destination = directory/(kind+'.input'), directory/(kind+'.bin')
    require(not source.exists() and not destination.exists(), 'conformance output must be fresh')
    source.write_bytes(data)
    result = subprocess.run([str(binary), str(source), str(destination)], capture_output=True, text=True, timeout=300)
    require(result.returncode == 0, 'Apple conformance writer refused: ' + result.stderr)
    blob = destination.read_bytes()
    def read(address, size):
        require(0 <= address <= len(blob) and 0 <= size <= len(blob)-address, 'conformance output read overflow')
        return blob[address:address+size]
    table = read_table(read, 0, kind)
    require(len(table.data) == len(blob), 'trailing conformance output')
    require([(a, b, raw & ~1) for _, a, b, raw in table.rows] == rows, 'conformance roundtrip differs')
    stats = json.loads(result.stdout)
    require(stats == dict(keys=len(table.groups), values=len(rows), bytes=len(blob), misses_checked=len(table.groups)),
            'Apple conformance oracle counts differ')
    return blob, stats


def foreign_identity(read_string, read, address, import_info):
    """Swift foreign identity preserves embedded NULs and the ABI-name marker semantics."""
    start = address
    end = address + len(read_string(address))
    cursor = end
    if import_info:
        for _ in range(65536):
            component = cursor + 1
            value = read_string(component)
            cursor = component + len(value)
            require(cursor - address <= 65536, 'foreign import info exceeds bound')
            if not value:
                break
            if value[:1] == b'N':
                start, end = component + 1, cursor
            elif value[:1] in (b'S', b'R'):
                end = cursor
        else:
            raise ValueError('unterminated foreign import info')
    require(0 <= end-start < 65536, 'foreign identity length invalid')
    return start, bytes(read(start, end-start))


def collect(family):
    """Read all __TEXT,__swift5_proto entries, resolving weak and indirect references."""
    base, _ = swift_roots(family)
    reader = FamilyReader(family)
    _, _, header = objc_header(family)
    ro = base + header[2]
    count, stride = struct.unpack('<II', family.read(ro, 8))
    require(0 < count < 65536 and stride == 24, 'unsupported ObjC owner table')
    owners = {}
    for index in range(count):
        field = ro + 8 + index*stride
        mh = field + struct.unpack('<q', family.read(field, 8))[0]
        require(mh not in owners, 'duplicate ObjC owner header')
        owners[mh] = index
    require(set(owners) <= {mh for _, mh in family.images}, 'ObjC owner not in final image list')
    classes = objc_table(family.read, lambda a: family_string(family, a), base+header[5], 'class', base)
    by_name = {entry.name: [a for a, _ in entry.objects] for entry in classes.entries}
    rows = {kind: [] for kind in KINDS}
    canonical = {}
    stats = Counter()
    def relative(field, indirectable=False):
        delta = struct.unpack('<i', family.read(field, 4))[0]
        target = field + (delta & ~1 if indirectable else delta)
        return reader.ptr(target) if indirectable and delta & 1 else target
    def offset(address):
        require(base <= address < base+(1 << 47), 'conformance reference outside cache offset range')
        family.read(address, 1)
        return address-base
    for path, mh in family.images:
        for segment, name, address, size in sections(commands(family, mh)):
            if segment != '__TEXT' or name != '__swift5_proto':
                continue
            require(size % 4 == 0 and size//4 <= 1_000_000, 'invalid conformance section size')
            require(not size or mh in owners, 'Swift image has no final ObjC owner: ' + path)
            stats['images'] += 1
            for field in range(address, address+size, 4):
                descriptor = relative(field)
                protocol = relative(descriptor, True)
                stats['descriptors'] += 1
                if not protocol:
                    stats['weak_protocols'] += 1
                    continue
                b = offset(protocol)
                raw = (owners[mh] << 48) | (offset(descriptor) << 1)
                flags = struct.unpack('<I', family.read(descriptor+12, 4))[0]
                kind = (flags >> 3) & 7
                require(kind <= 3, 'unknown Swift conformance type-reference kind')
                delta = struct.unpack('<i', family.read(descriptor+4, 4))[0]
                target = descriptor+4+(delta & ~1 if kind in (1, 3) else delta)
                if kind in (1, 3):
                    target = reader.ptr(target)
                if not target:
                    stats['weak_types'] += 1
                    continue
                if kind in (0, 1):
                    a = offset(target)
                    rows['type'].append((a, b, raw))
                    flags = struct.unpack('<I', family.read(target, 4))[0] >> 16
                    if flags & 3 == 2:  # ForeignMetadataInitialization
                        name_at = relative(target+8)
                        name_at, name = foreign_identity(lambda a: family_string(family, a), family.read, name_at, flags & 4)
                        a = canonical.setdefault(name, offset(name_at)) | (len(name) << 48)
                        rows['foreign'].append((a, b, raw))
                elif kind == 2:
                    name = family_string(family, target)
                    targets = by_name.get(name, ())
                    stats['unresolved_class_names'] += not targets
                    rows['metadata'].extend((offset(a), b, raw) for a in targets)
                else:
                    rows['metadata'].append((offset(target), b, raw))
    return rows, dict(stats)


def regenerate(manifest, output, binary=None):
    """Fresh, signed family stage before loader generation; refuse table growth.

    Existing table extents are the reservations. This preserves every VM address
    and optimization root. A larger table needs a new allocation, never an
    overwrite into the next table. The caller regenerates external sidecars.
    """
    import mmap
    import shutil
    from .codesign import inspect
    from .emit_cache import sign_with_uuid
    from .loader_generation import cache_manifest, sha
    from .run_inputs import pin
    output = Path(output).resolve()
    require(not output.exists(), 'conformance family output must be fresh')
    main, count, images, pins = cache_manifest(manifest)
    original = json.loads(Path(manifest).read_text())
    family = LoaderFamily(main, expected_files=count, expected_images=images)
    try:
        # Program loader sets bind cache identities. This stage precedes their creation.
        require(original.get('stage') == 'metadata-bootstrap' or
                struct.unpack_from('<QQ', family.main.data, 336) == (0, 0),
                'conformance regeneration must precede program loader generation')
        output.mkdir(parents=True)
        tables = output/'tables'; tables.mkdir()
        binary = binary or writer(output/'writer')
        base, roots = swift_roots(family)
        rows, scan = collect(family)
        edits, reports = {}, {}
        extents = []
        reader = FamilyReader(family)
        for kind in KINDS:
            old = read_table(family.read, base+roots[kind], kind)
            extents.append((old.address, old.address+len(old.data)))
            blob, stats = emit(binary, tables, kind, rows[kind], lambda a,n: family.read(base+a,n))
            require(len(blob) <= len(old.data), 'regenerated '+kind+' table exceeds original reservation')
            replacement = blob + bytes(len(old.data)-len(blob))
            file, at = family.locate(old.address, len(old.data))
            # These hashes contain offsets, not slide pointers. Do not change slide chains.
            for mapping in file.mappings:
                if mapping.address <= old.address < mapping.address+mapping.size:
                    require(not mapping.initial & 2 and mapping.address not in reader.slides,
                            'conformance table lies in writable/slid mapping')
            if replacement != old.data:
                edits.setdefault(file.path.name, []).append((at, replacement))
            before = Counter((a,b,raw & ~1) for _,a,b,raw in old.rows)
            after = Counter(rows[kind])
            reports[kind] = dict(stats, address=old.address, original_bytes=len(old.data),
                                 added=sum((after-before).values()), removed=sum((before-after).values()),
                                 sha256=hashlib.sha256(blob).hexdigest())
        extents.sort()
        require(all(a[1] <= b[0] for a,b in zip(extents,extents[1:])), 'conformance table reservations overlap')
        other_roots = [base+roots['prespecialization'], *(base+r for r in roots['pointer_tables'])]
        require(not any(start <= root < end for start,end in extents for root in other_roots),
                'conformance reservation overlaps a prespecialization root')
        destination = output/'family'; destination.mkdir()
        for file in family.files:
            target = destination/file.path.name
            if subprocess.run(['/bin/cp','-c',str(file.path),str(target)], capture_output=True).returncode:
                shutil.copyfile(file.path, target)
            expected = next(p for p in pins if Path(p['path']) == file.path)
            require(sha(target) == expected['sha256'], 'cache input changed during conformance generation')
        signatures, identities = {}, {}
        # Sign changed subcaches first, then update the main UUID directory and sign main.
        for file in [f for f in family.files[1:] if f.path.name in edits] + [family.main]:
            with (destination/file.path.name).open('r+b') as stream, mmap.mmap(stream.fileno(),0) as data:
                for at, blob in edits.get(file.path.name, ()):
                    data[at:at+len(blob)] = blob
                if file is family.main:
                    suboff = struct.unpack_from('<I',data,392)[0]
                    for i, subcache in enumerate(family.files[1:]):
                        if subcache.path.name in identities:
                            data[suboff+56*i:suboff+56*i+16] = identities[subcache.path.name]
                identifier = inspect(data, verify_pages=False)['identifier']
                data[88:104] = bytes(16)
                signatures[file.path.name] = sign_with_uuid(data, identifier, file.mappings[0].size)
                identities[file.path.name] = bytes(data[88:104])
                data.flush()
        checked = LoaderFamily(destination/main.name, expected_files=count, expected_images=images)
        try:
            for kind in KINDS:
                table = read_table(checked.read,base+roots[kind],kind)
                require(hashlib.sha256(table.data).hexdigest() == reports[kind]['sha256'],
                        'installed conformance table differs: '+kind)
            result_uuid = bytes(checked.main.data[88:104]).hex()
        finally:
            checked.close()
        result = dict(original)
        result.pop('main', None)
        result.pop('files', None)
        result.update(stage='swift-conformance-regenerated', complete_candidate=False,
                      original_files=[dict(file=f.path.name, size=(destination/f.path.name).stat().st_size,
                                           sha256=sha(destination/f.path.name)) for f in family.files], outputs=[],
                      conformance=dict(scan=scan, tables=reports, cache_uuid=result_uuid,
                                       input_manifest=pin(manifest), writer=pin(binary), input_files=pins,
                                       native_acceptance='OPEN'), new_signatures=signatures)
        target = destination/'build-report.json'
        target.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
        return pin(target)
    finally:
        family.close()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument('--cache', type=Path, help='scan and emit table blobs only')
    inputs.add_argument('--manifest', type=Path, help='emit a signed family stage from a pinned bootstrap manifest')
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--writer', type=Path, help='reuse a compiled host adapter')
    parser.add_argument('--replay-existing', action='store_true', help='calibrate serialization against existing table records instead of scanning sections')
    args = parser.parse_args(argv)
    require(not (args.manifest and args.replay_existing), 'existing-table replay cannot produce an installed family')
    if args.manifest:
        print(json.dumps(regenerate(args.manifest, args.output, args.writer), sort_keys=True))
        return
    require(not args.output.exists(), 'conformance output directory must be fresh')
    args.output.mkdir(parents=True)
    binary = args.writer or writer(args.output/'writer')
    family = LoaderFamily(args.cache)
    try:
        base, roots = swift_roots(family)
        if args.replay_existing:
            rows = {k: [(a,b,raw & ~1) for _,a,b,raw in read_table(family.read,base+roots[k],k).rows] for k in KINDS}
            scan = {'mode': 'existing-table calibration; no section scan'}
        else:
            rows, scan = collect(family)
        report = dict(schema=1, cache_uuid=bytes(family.main.data[88:104]).hex(), scan=scan, tables={},
                      writer_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
                      scope='Final-image section scan and host lookup proof; installation and runtime acceptance are separate.')
        for kind in KINDS:
            old = read_table(family.read, base+roots[kind], kind)
            blob, stats = emit(binary, args.output, kind, rows[kind], lambda a, n: family.read(base+a, n))
            expected = Counter((a, b, raw & ~1) for _, a, b, raw in old.rows)
            actual = Counter(rows[kind])
            stats.update(address=old.address, sha256=hashlib.sha256(blob).hexdigest(),
                         original_sha256=hashlib.sha256(old.data).hexdigest(), original_bytes=len(old.data),
                         added=sum((actual-expected).values()), removed=sum((expected-actual).values()),
                         identical=blob == old.data, fits_original=len(blob) <= len(old.data))
            report['tables'][kind] = stats
        (args.output/'report.json').write_text(json.dumps(report, indent=2, sort_keys=True)+'\n')
        print(json.dumps(report, sort_keys=True))
    finally:
        family.close()
