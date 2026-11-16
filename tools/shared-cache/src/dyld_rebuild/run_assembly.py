"""Current-run structural and ObjC assembly stages with independent oracles.

All target data are explicit pinned stage inputs. Tools retain their legacy
scratch ownership checks; this library never registers or installs a family.
"""
import json
from pathlib import Path
import sys

from .exports import require
from .loader_generation import cache_manifest
from .run_inputs import pin
from .run_prepare import _json, _verified
import subprocess

ROOT = Path(__file__).resolve().parents[2]


def _document(path, expected, kind=None):
    path=Path(path).resolve(strict=True)
    require(pin(path)['sha256']==expected,'stage input report pin differs: '+str(path))
    value=json.loads(path.read_text())
    require(value.get('schema')==1 and (kind is None or value.get('kind')==kind),'stage input schema/kind differs')
    return path,value


def _fresh(output):
    path=Path(output).resolve()
    require(not path.exists(),'assembly stage output must be fresh under work')
    path.mkdir(parents=True)
    return path


def _run(out,name,tool,*argv):
    print(name, flush=True)
    with (out/(name+'.log')).open('w') as log:
        subprocess.run([sys.executable,str(ROOT/tool),*map(str,argv)],stdout=log,stderr=subprocess.STDOUT,check=True)


def _record(out,kind,inputs,results):
    record=dict(schema=1,kind=kind,classification='current-run checked offline stage; final certification and target acceptance not checked here',
                inputs=inputs,results=results,certification_complete=False,
                source_modules={p.name:pin(p) for p in Path(__file__).parent.glob('*.py')})
    return dict(report=_json(out/'stage.json',record),**results)


def emit_structural(preparation_report, output, *, preparation_sha256):
    """Emit structural family and run all existing XNU/ipsw/signature checks."""
    prep_path,prep=_document(preparation_report,preparation_sha256,'dyld-cache-build/producer-preparation')
    for row in prep['artifacts'].values():_verified(row)
    for row in prep['intake_pins'].values():_verified(row)
    plan=prep['artifacts']['provider-plan.json'];source=prep['intake_pins']['capture-manifest.json']
    out=_fresh(output);family=out/'family';oracle=out/'oracle'
    explicit=['--source-manifest',source['path'],'--source-manifest-sha256',source['sha256']]
    _run(out,'emit','tools/build-cache.py','--stage','family','--plan',plan['path'],'--plan-sha256',plan['sha256'],
         '--output',family,*explicit)
    manifest=family/'build-report.json';cache_manifest(manifest)
    return _record(out,'dyld-cache-build/structural-stage',dict(preparation=pin(prep_path)),
                   dict(structural_manifest=pin(manifest)))


def prepare_global_objc(preparation_report, metadata_report, structural_manifest, output, *,
                        preparation_sha256, metadata_sha256, structural_sha256):
    """Generate global lookup/header blobs with current-source Apple roundtrips."""
    prep_path,prep=_document(preparation_report,preparation_sha256,'dyld-cache-build/producer-preparation')
    metadata_path,metadata=_document(metadata_report,metadata_sha256,'dyld-cache-build/metadata-preparation')
    manifest,_=_document(structural_manifest,structural_sha256)
    require(metadata['preparation']==pin(prep_path) and metadata['structural']==pin(manifest),'metadata stage lineage differs')
    for row in metadata['outputs'].values():_verified(row)
    source=prep['intake_pins']['capture-manifest.json'];_verified(source)
    main,files,images,_=cache_manifest(manifest)
    allocation=metadata['outputs']['metadata-layout.json'];component=metadata['outputs']['provider-objc/recipe.json']
    tables_input=metadata['outputs']['provider-objc/tables-input.json']
    out=_fresh(output);tables=out/'tables';bootstrap=out/'bootstrap';recipe=out/'recipe.json'
    explicit=['--source-manifest',source['path'],'--source-manifest-sha256',source['sha256']]
    common=['--candidate',main,'--subcache-count',str(files-1),'--metadata-plan',tables_input['path'],
            '--allocation',allocation['path'],*explicit]
    _run(out,'tables','tools/build-objc-tables.py','tables',*common,'--output-dir',tables)
    _run(out,'bootstrap','tools/build-objc-tables.py','bootstrap',*common,'--output-dir',bootstrap)
    _run(out,'package','tools/package-objc-recipe.py','--tables',tables,'--headers',bootstrap,
         '--names',Path(metadata['outputs']['canonical-additions/names.json']['path']).parent,
         '--provider-recipe',component['path'],'--allocation',allocation['path'],'--output',recipe)
    return _record(out,'dyld-cache-build/global-objc-stage',dict(preparation=pin(prep_path),metadata=pin(metadata_path),structural=pin(manifest)),
                   dict(tables_report=pin(tables/'report.json'),bootstrap_report=pin(bootstrap/'report.json'),global_recipe=pin(recipe)))


def assemble_bootstrap(preparation_report, metadata_report, global_report, structural_manifest,
                       patch_report, lookup_report, output, *, preparation_sha256, metadata_sha256,
                       global_sha256, structural_sha256, patch_sha256, lookup_sha256):
    """Assemble fresh components, then independently check every changed page."""
    prep_path,prep=_document(preparation_report,preparation_sha256,'dyld-cache-build/producer-preparation')
    metadata_path,metadata=_document(metadata_report,metadata_sha256,'dyld-cache-build/metadata-preparation')
    global_path,global_=_document(global_report,global_sha256,'dyld-cache-build/global-objc-stage')
    structural,_=_document(structural_manifest,structural_sha256)
    patch,_=_document(patch_report,patch_sha256)
    lookup,_=_document(lookup_report,lookup_sha256)
    require(global_['inputs']==dict(preparation=pin(prep_path),metadata=pin(metadata_path),structural=pin(structural)),
            'global assembly lineage differs')
    for row in metadata['outputs'].values():_verified(row)
    for row in global_['results'].values():_verified(row)
    plan=prep['artifacts']['provider-plan.json'];_verified(plan)
    out=_fresh(output);family=out/'family';oracle=out/'oracle'
    swift = metadata['outputs'].get('swift/recipe.json')
    extra = ['--swift', swift['path']] if swift else []
    _run(out,'assemble','tools/assemble-cache.py','--structural-manifest',structural,'--plan',plan['path'],
         '--allocation',metadata['outputs']['metadata-layout.json']['path'],
         '--provider-objc',metadata['outputs']['provider-objc/recipe.json']['path'],
         '--global-objc',global_['results']['global_recipe']['path'],
         '--patch-report',patch,'--lookup-report',lookup,'--output',family,*extra)
    manifest=family/'build-report.json';cache_manifest(manifest)
    return _record(out,'dyld-cache-build/assembled-bootstrap-stage',dict(preparation=pin(prep_path),metadata=pin(metadata_path),
            global_objc=pin(global_path),structural=pin(structural),patch=pin(patch),lookup=pin(lookup)),
            dict(assembled_manifest=pin(manifest)))
