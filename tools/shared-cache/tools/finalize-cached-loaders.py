#!/usr/bin/env python3
"""Install generated cached loaders and their checked ObjC HeaderInfo links."""
import argparse
import hashlib
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
from dyld_rebuild.loader_generation import cache_manifest, read_set, sha
from dyld_rebuild.objc_tables import decode_header_info
from dyld_rebuild.graph_contract import checked_manifest,objc_inventory


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--bootstrap-manifest', type=Path, required=True)
    ap.add_argument('--header-report', type=Path, required=True)
    ap.add_argument('--pbl-report', type=Path, required=True)
    ap.add_argument('--output', type=Path, required=True)
    args = ap.parse_args()
    output = args.output.resolve()
    require(not output.exists(), 'output must be fresh scratch')
    main_path, count, images, pins = cache_manifest(args.bootstrap_manifest)
    source = CandidateFamily(main_path, image_count=images, subcache_count=count - 1)
    handles, mappings = [], {}
    try:
        bootstrap = json.loads(args.bootstrap_manifest.read_text())
        graph=checked_manifest(bootstrap,root=ROOT,images=images,files=count,family=source)
        objc=objc_inventory(source);header_count=len(objc)
        layout_path = ROOT / bootstrap['components']['allocation']['path']
        require(sha(layout_path) == bootstrap['components']['allocation']['sha256'], 'metadata allocation drift')
        layout = json.loads(layout_path.read_text())
        header = json.loads(args.header_report.read_text())
        require([(r['image'],int(r['mh'],16),r['index'],int(r['imageinfo_section'],16)) for r in header['identities']]==
                [(r['path'],r['mh'],i,r['imageinfo_section']) for i,r in enumerate(objc)],'header report image inventory differs')
        pbl = json.loads(args.pbl_report.read_text())
        require(pbl['mode'] == 'cached' and pbl['cache_inputs'] == pins,
                'cached loaders were not generated from this exact bootstrap family')
        require(header['mode'] == 'header_blobs' and not header['loader_proof']['bootstrap_only'], 'final headers required')
        blob_path = args.pbl_report.parent / pbl['cached_set']['file']
        blob = blob_path.read_bytes()
        require(sha(blob_path) == pbl['cached_set']['sha256'] == header['loader_proof']['cached_pbl_sha256'] and
                len(blob) == pbl['cached_set']['size'] <= layout['cached_pbl']['reserve'], 'generated loader bytes differ')
        loaded = read_set(blob, images, app=False)
        require([r['path'] for r in loaded['loaders']] == [p for p, _ in source.images], 'cached loader graph differs')
        header_values = {}
        for kind in ('ro', 'rw', 'imageinfo'):
            row = header['outputs'][kind]
            path = args.header_report.parent / row['file']
            value = path.read_bytes()
            address = int(row['address'], 16)
            require(len(value) == row['bytes'] <= layout[kind]['reserve'] and sha(path) == row['sha256'] and
                    address == layout[kind]['address'], 'final header blob drift')
            before = source.read(address, len(value))
            if kind == 'ro':
                require(before[:8] == value[:8] and struct.unpack_from('<II', value) == (header_count, 24), 'header-info shape differs')
                for at in range(8, len(value), 24):
                    require(before[at:at + 16] == value[at:at + 16] and before[at + 16:at + 24] == bytes(8),
                            'final header changed non-PBL fields or source was not bootstrap')
            else:
                require(before == value, 'final RW/imageinfo unexpectedly changed')
            header_values[kind] = value
        pbl_address = layout['cached_pbl']['address']
        require(source.read(pbl_address, len(blob)) == bytes(len(blob)), 'cached-loader reservation is not empty')
        output.mkdir()
        for file in source.files:
            path = output / file.path.name
            copied = subprocess.run(['/bin/cp', '-c', str(file.path), str(path)], capture_output=True)
            if copied.returncode: shutil.copyfile(file.path, path)
        affected = {source.main.path.name, source.files[-1].path.name}
        for name in affected:
            stream = (output / name).open('r+b')
            handles.append(stream)
            mappings[name] = mmap.mmap(stream.fileno(), 0)
        def put(address, value):
            file, at = source.locate(address, len(value))
            require(file.path.name in affected, 'unexpected file for final metadata')
            mappings[file.path.name][at:at + len(value)] = value
        put(layout['ro']['address'], header_values['ro'])
        put(pbl_address, blob)
        metadata = source.files[-1]
        data = mappings[metadata.path.name]
        identifier = inspect(data, verify_pages=False)['identifier']
        data[88:104] = bytes(16)
        meta_signature = sign_with_uuid(data, identifier, metadata.mappings[0].size)
        main = mappings[source.main.path.name]
        suboff, subcount = struct.unpack_from('<II', main, 392)
        require(subcount == count - 1, 'final subcache count differs')
        main[suboff + (subcount - 1) * 56:suboff + (subcount - 1) * 56 + 16] = data[88:104]
        struct.pack_into('<Q', main, 328, pbl_address)
        identifier = inspect(main, verify_pages=False)['identifier']
        main[88:104] = bytes(16)
        main_signature = sign_with_uuid(main, identifier, source.main.mappings[0].size)
        for value in mappings.values(): value.flush()
        candidate = CandidateFamily(output / main_path.name, image_count=images, subcache_count=count - 1)
        try:
            info = decode_header_info(candidate.read, layout['ro']['address'], layout['rw']['address'])
            expected = {source.images[i][1]: pbl_address + row['offset'] for i, row in enumerate(loaded['loaders'])}
            require([mh for mh,_,_ in info]==[r['mh'] for r in objc] and all(expected[mh] == pblptr for mh, _, pblptr in info),
                    'integrated HeaderInfo links differ from serialized loaders')
            require(candidate.read(pbl_address, len(blob)) == blob, 'installed cached loaders differ')
        finally: candidate.close()
        result = dict(bootstrap);result['graph_contract']=graph
        result.update(classification='integrated cached loaders and ObjC links; required program loaders/image gates not checked here',
                      stage='cached-loaders-integrated', complete_candidate=False,
                      original_files=[dict(file=f.path.name, size=(output / f.path.name).stat().st_size,
                                           sha256=sha(output / f.path.name)) for f in source.files], outputs=[],
                      bootstrap_manifest=dict(path=str(args.bootstrap_manifest), sha256=sha(args.bootstrap_manifest)),
                      cached_loaders=dict(bytes=len(blob), sha256=sha(blob_path), count=images, header_info_links=len(info)),
                      final_header_report=dict(path=str(args.header_report), sha256=sha(args.header_report)),
                      final_pbl_report=dict(path=str(args.pbl_report), sha256=sha(args.pbl_report)),
                      new_signatures={source.main.path.name: main_signature, metadata.path.name: meta_signature},
                      remaining_gates=['Regenerate every required program loader from the final filesystem.',
                                       'Retire all baked disk roots through the oclp stage and preserve required seeds/shaders.',
                                       'Update atlas/map and image integration records; produce/check the boot image.',
                                       'Probe override state and prove target acceptance without additional security relaxation.'])
        (output / 'build-report.json').write_text(json.dumps(result, indent=2) + '\n')
        print(json.dumps({'stage': result['stage'], 'cached_loaders': result['cached_loaders'], 'complete_candidate': False}))
    finally:
        for value in mappings.values(): value.close()
        for stream in handles: stream.close()
        source.close()


if __name__ == '__main__': main()
