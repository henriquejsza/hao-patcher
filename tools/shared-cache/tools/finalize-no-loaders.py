#!/usr/bin/env python3
"""Finish a bootstrap family without prebuilt loaders (fold-in v1, pm 2026-11-14).

dyld then makes a JustInTimeLoader for every cache dylib and skips program loader sets (runtime's reading of 26B131's
dyld: the program sets are only looked up when the dylibs set passes validHeader). Nothing from the source cache's sets
is carried: the dylibs set address and the program pool and trie fields in the main header are zeroed, and every ObjC
header-info row's loader field must already be 0 (the bootstrap form). OPEN: who reads that field on 27 and whether 0
is safe there (research, queue/tools/20261114-1400).
"""
import argparse
import json
import mmap
from pathlib import Path
import shutil
import struct
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'src'))
from dyld_rebuild.candidate import CandidateFamily
from dyld_rebuild.codesign import inspect
from dyld_rebuild.emit_cache import sign_with_uuid
from dyld_rebuild.exports import require
from dyld_rebuild.loader_generation import cache_manifest, sha
from dyld_rebuild.objc_tables import decode_header_info

# dyld_cache_header: dylibsPBLSetAddr, programsPBLSetPoolAddr, programsPBLSetPoolSize, programTrieAddr (Q each),
# programTrieSize (I). osVersion follows at 364 and is not touched.
LOADER_FIELDS = (328, '<4QI', 36)


def header_info(family):
    base = family.main.mappings[0].address
    address, _ = struct.unpack_from('<QQ', family.main.data, 464)
    _, _, ro, rw = struct.unpack('<IIQQ', family.read(base + address, 24))
    return decode_header_info(family.read, base + ro, base + rw, bootstrap_only=True)


def clear_loader_fields(main):
    """Zero the loader-set fields of a main cache header in place; returns the old values."""
    offset, form, size = LOADER_FIELDS
    old = struct.unpack_from(form, main, offset)
    main[offset:offset + size] = bytes(size)
    return old


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bootstrap-manifest', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    output = args.output.resolve()
    require(not output.exists(), 'output must be fresh scratch')
    main_path, count, images, _ = cache_manifest(args.bootstrap_manifest)
    source = CandidateFamily(main_path, image_count=images, subcache_count=count - 1)
    stream = data = None
    names = [f.path.name for f in source.files]
    try:
        bootstrap = json.loads(args.bootstrap_manifest.read_text())
        rows = header_info(source)   # refuses unless every loader field is 0
        output.mkdir()
        for file in source.files:
            path = output / file.path.name
            if subprocess.run(['/bin/cp', '-c', str(file.path), str(path)], capture_output=True).returncode:
                shutil.copyfile(file.path, path)
        stream = (output / source.main.path.name).open('r+b')
        data = mmap.mmap(stream.fileno(), 0)
        old = clear_loader_fields(data)
        identifier = inspect(data, verify_pages=False)['identifier']
        data[88:104] = bytes(16)
        signature = sign_with_uuid(data, identifier, source.main.mappings[0].size)
        data.flush()
    finally:
        if data is not None: data.close()
        if stream is not None: stream.close()
        source.close()
    candidate = CandidateFamily(output / main_path.name, image_count=images, subcache_count=count - 1)
    try:
        offset, form, size = LOADER_FIELDS
        require(not any(candidate.main.data[offset:offset + size]), 'loader fields not cleared')
        require(len(header_info(candidate)) == len(rows), 'header-info rows changed')
    finally:
        candidate.close()
    result = dict(bootstrap)
    result.update(classification='no prebuilt loaders; dyld JIT-loader acceptance and the header-info loader '
                                 'field on 27 are not checked here',
                  stage='no-prebuilt-loaders', complete_candidate=False, prebuilt_loaders=False,
                  cleared_header_fields=dict(zip(('dylibs_pbl_set', 'program_pool', 'program_pool_size', 'program_trie',
                                                  'program_trie_size'), (hex(v) for v in old))),
                  header_info_rows=len(rows),
                  original_files=[dict(file=n, size=(output / n).stat().st_size, sha256=sha(output / n)) for n in names],
                  outputs=[], bootstrap_manifest=dict(path=str(args.bootstrap_manifest), sha256=sha(args.bootstrap_manifest)),
                  new_signatures={main_path.name: signature})
    (output / 'build-report.json').write_text(json.dumps(result, indent=2) + '\n')
    print(json.dumps({'stage': result['stage'], 'cleared': result['cleared_header_fields']}))


if __name__ == '__main__':
    main()
