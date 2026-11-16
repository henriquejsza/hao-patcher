"""Own-process metatype construction/export/relocation/adoption fixture.

Image headers are captured evidence, not fabricated section ranges. The fixture
starts with no installed generated keys so every object traverses the exporter
and allocator. The normal verifier then runs in another process. This does not
model an installed image or prove another runtime version's ABI.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import patch
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT/'src'))
from dyld_rebuild.metadata_graph import MetadataGraph
from dyld_rebuild.swift_graph import materialize_dependencies
from dyld_rebuild.swift_metadata import provenance, write_json
from dyld_rebuild.witness_graph import replay_prepare, replay_summary


class CapturedHeaders:
    def __init__(self, events):
        header = events[0]
        images = [r for r in events if 'image_header' in r]
        slides = {r['slide'] for r in images}
        if len(slides) != 1:
            raise ValueError('fixture cache image slides differ')
        slide = slides.pop()
        self.base = header['base']-slide
        self.end = header['end']-slide
        self.main = SimpleNamespace(data=bytes(88)+uuid.UUID(header['cache_uuid']).bytes,
                                    mappings=[SimpleNamespace(address=self.base)])
        self.images = [(r['image_header'],r['address']-slide) for r in images]
        self.headers = {r['address']-slide: bytes.fromhex(r['data']) for r in images}
        self.roots = dict(base=self.base,table=0,swift_pointer=0,dyld_offset=0)

    def read(self, address, size):
        for base, data in self.headers.items():
            if base <= address and address+size <= base+len(data):
                return data[address-base:address-base+size]
        raise ValueError('fixture reads only captured Mach-O headers')


def run(helper, toolchain, devkit, llvm, output):
    output.mkdir(parents=True, exist_ok=False)
    names = ['Sim', 'SimSg', 'Simm']
    records = [dict(name=n,owner='/usr/lib/swift/libswiftCore.dylib') for n in names]
    requests = ''.join(r['name']+'\t'+r['owner']+'\n' for r in records)
    captured = subprocess.run([str(helper)], input=requests, text=True, capture_output=True,
                              env=dict(os.environ,SWIFT_GRAPH_IMAGE_HEADERS='1'), check=True, timeout=60)
    (output/'capture.jsonl').write_text(captured.stdout)
    (output/'capture.stderr').write_text(captured.stderr)
    events = [json.loads(s) for s in captured.stdout.splitlines()]
    ordinary = next(r for r in events if r.get('abi_family') == 'metatype' and r['name'] == 'Sim')
    keys = ','.join(format(p-events[0]['base'], 'x') for p in ordinary['key'])
    exact = '@cache\t'+events[0]['cache_uuid']+'\nSim\t'+ordinary['owner']+'\t'+keys+'\n'
    repeated = subprocess.run([str(helper)], input=exact, text=True, capture_output=True,
                              check=True, timeout=60)
    (output/'exact-key.jsonl').write_text(repeated.stdout)
    repeated_events = [json.loads(s) for s in repeated.stdout.splitlines()]
    if not any(r.get('abi_family') == 'metatype' and r.get('canonical') for r in repeated_events):
        raise ValueError('exact-key metatype construction failed')
    family = CapturedHeaders(events)
    graph = MetadataGraph.from_plan([], records)
    graph.import_catalog(dict(schema=4,kind='swift-dependency-catalog',source_cache_uuid=events[0]['cache_uuid'],
                              records=[],witnesses=[],loads=[]))
    with patch('dyld_rebuild.swift_metadata.pointer_entries',return_value=({},family.roots)):
        report = graph.record_capture(family,events)
        catalog = graph.catalog()
        address = (family.end+4095)&~4095
        allocated = materialize_dependencies(catalog,family,address)
    write_json(output/'graph.json',graph.document)
    write_json(output/'catalog.json',catalog)
    write_json(output/'coverage.json',graph.coverage())
    allocation = output/'allocation'
    allocation.mkdir()
    (allocation/'payload.bin').write_bytes(allocated['data'])
    layout = dict(schema=1,installed=False,cache_uuid=events[0]['cache_uuid'],address=address,
                  roots=allocated['roots'],pointers=allocated['pointers'],records=allocated['records'])
    write_json(allocation/'allocation.json',layout)
    write_json(allocation/'build.json',provenance([output/'catalog.json',output/'capture.jsonl',Path(__file__)],
               operation='metatype-fixture-allocation',scope='Captured host image headers; empty original metadata table'))
    replay_prepare(allocation,output/'catalog.json',toolchain,devkit,output/'verification',llvm)
    completed = subprocess.run([str(output/'verification/dependency-replay'),
                               str(output/'verification/candidate.bin'),str(output/'verification/loads.txt')],
                              text=True,capture_output=True,timeout=120)
    (output/'verification.jsonl').write_text(completed.stdout)
    (output/'verification.stderr').write_text(completed.stderr)
    result = replay_summary(layout,[json.loads(s) for s in completed.stdout.splitlines()])
    write_json(output/'result.json',result)
    write_json(output/'build.json',provenance([helper,toolchain/'build.json',devkit,Path(__file__),
               output/'capture.jsonl',output/'exact-key.jsonl',output/'verification/build.json',output/'verification.jsonl'],
               operation='metatype-native-fixture',returncode=completed.returncode,
               scope='Own-process host ABI fixture, not installed or target-image acceptance'))
    if completed.returncode or not result['complete'] or report['included'] != len(names):
        raise ValueError('metatype fixture failed; see '+str(output))
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ('helper','toolchain','devkit','llvm','output'):
        parser.add_argument('--'+name,type=Path,required=True)
    args = parser.parse_args()
    print(json.dumps(run(**{k:v.resolve() for k,v in vars(args).items()}),indent=2))
