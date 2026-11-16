#!/usr/bin/env python3
"""Package already checked global blobs and refuse conflicts with provider edits."""
import argparse,hashlib,json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def need(ok,why):
    if not ok:raise ValueError(why)
def number(value):return int(value,0) if isinstance(value,str) else value
def main():
    ap=argparse.ArgumentParser(description=__doc__)
    for name in ('tables','headers','names','provider-recipe','allocation','output'):
        ap.add_argument('--'+name,type=Path,required=True)
    a=ap.parse_args();out=a.output.resolve()
    need(not out.exists(),'output must be fresh work file')
    inputs={};docs={}
    for key,path in [('tables',a.tables/'report.json'),('headers',a.headers/'report.json'),('names',a.names/'names.json'),
                     ('provider',a.provider_recipe),('allocation',a.allocation)]:
        docs[key]=json.loads(path.read_text());inputs[key]={'path':str(path.resolve()),'sha256':sha(path)}
    tables,headers,names,allocation=(docs[k] for k in ('tables','headers','names','allocation'))
    need(tables['allocation']['sha256']==headers['allocation_sha256']==names['allocation_sha256']==inputs['allocation']['sha256'],
         'allocation input differs across metadata producers')
    need(tables['metadata_plan']['sha256']==headers['metadata_plan_sha256'],'provider metadata identity input differs')
    order=json.loads((a.tables/'objc-order.json').read_text())
    need([x['image'] for x in headers['identities']]==order,'header/table ObjC order differs')
    bootstrap=headers['loader_proof']['bootstrap_only']
    need(headers['mode']==('bootstrap_only_header_blobs' if bootstrap else 'header_blobs'),'header mode differs')
    blobs=[];file_edits=[];byte_edits=[]
    def blob(record,path,reservation):
        path=path.resolve();size=record.get('bytes',record.get('size'));address=number(record['address'])
        need(path.stat().st_size==size and sha(path)==record['sha256'],'blob bytes differ: '+str(path))
        slot=allocation[reservation]
        need(address==slot['address'] and size<=slot['reserve'],'blob allocation mismatch')
        blobs.append(dict(reservation=reservation,address=address,path=str(path),size=size,sha256=record['sha256']))
    for kind,row in tables['tables'].items():blob(row,a.tables/row['file'],kind)
    for kind,row in headers['outputs'].items():blob(row,a.headers/row['file'],kind)
    for kind,row in names['pools'].items():blob(row,a.names/(kind+'.bin'),{'selectors':'selector_names','classes':'class_names','protocols':'protocol_names'}[kind])
    for kind,row in headers['swift_outputs'].items():
        path=(a.headers/row['file']).resolve()
        need(path.stat().st_size==row['bytes'] and sha(path)==row['sha256'],'Swift blob differs')
        file_edits.append(dict(address=number(row['address']),path=str(path),size=row['bytes'],sha256=row['sha256'],
                               expected_sha256=row['expected_sha256'],reason='Swift owner-index remap '+kind))
    for path,expected,reason in [(a.headers/'root-edits.json',headers['root_edits_sha256'],'global ObjC root'),
                                (a.tables/'relative-list-index-edits.json',tables['relative_list_edits_sha256'],'conditional ObjC list owner index')]:
        need(sha(path)==expected,'byte-edit manifest differs');doc=json.loads(path.read_text())
        for row in doc if isinstance(doc,list) else doc['edits']:
            need(len(row['expected'])==len(row['replacement']) and len(row['expected'])%2==0,'byte edit width differs')
            byte_edits.append(dict(address=number(row['address']),before=row['expected'],after=row['replacement'],reason=reason))
    intervals=[]
    for row in blobs+file_edits:intervals.append((row['address'],row['address']+row['size'],'global blob'))
    for row in byte_edits:intervals.append((row['address'],row['address']+len(bytes.fromhex(row['before'])),'global bytes'))
    own_count=len(intervals)
    for row in docs['provider']['byte_edits']:intervals.append((row['address'],row['address']+len(bytes.fromhex(row['before'])),'provider bytes'))
    for row in docs['provider']['pointer_edits']:intervals.append((row['address'],row['address']+8,'provider pointer'))
    # Provider blob pointers intentionally lie inside provider blobs. Only compare
    # our global ranges against provider blobs; their internal checks are separate.
    own=sorted(intervals[:own_count]);all_ranges=sorted(intervals)
    need(all(x[1]<=y[0] for x,y in zip(own,own[1:])),'global edits overlap')
    for row in docs['provider']['blobs']:
        start,end=row['address'],row['address']+row['size']
        need(not any(x<end and start<y for x,y,_ in own),'global edit overlaps provider blob')
    active=[]
    for start,end,kind in all_ranges:
        active=[x for x in active if x[1]>start]
        need(not any(kind.startswith('global') or x[2].startswith('global') for x in active),'global/provider edit overlap')
        active.append((start,end,kind))
    result=dict(schema=1,mode='global_objc_bootstrap' if bootstrap else 'global_objc_final',
                bootstrap_only=bootstrap,final_publication_allowed=not bootstrap,
                blobs=blobs,file_edits=file_edits,byte_edits=sorted(byte_edits,key=lambda x:x['address']),pointer_edits=[],
                inputs=inputs,source_sha256=sha(__file__),provider_overlap_conflicts=0,
                required_final_checks=['Final cached PBL header population and cached-set regeneration identity',
                                       'Complete emitted-family ObjC/Swift rewalk and separately authorized native acceptance'])
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(dict(path=str(out),sha256=sha(out),mode=result['mode'],blobs=len(blobs),file_edits=len(file_edits),byte_edits=len(byte_edits),provider_overlap_conflicts=0)))
if __name__=='__main__':main()
