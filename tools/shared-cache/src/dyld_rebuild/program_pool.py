"""Checked, aligned program-loader pool and factory-compatible lookup trie."""
import hashlib
import struct
from .cache_exports import path_trie
from .exports import require,span,cstring
from .loader_generation import read_set
from .pbl import VERSION
from .lookup_tables import write_path_trie

MIRRORING='/System/Applications/iPhone Mirroring.app/Contents/MacOS/iPhone Mirroring'
RETIRED_HASH='86cf4ca08e839199787c93a4c0c1ff5aafe46c4d'


def main_identity(data):
    """Decode path and optional validation without requiring a CDHash flag."""
    magic,version,length,count,array=struct.unpack('<5I',span(data,0,20))
    require((magic,version)==(0x73703464,VERSION) and length==len(data) and count>0,
            'unsupported program set header')
    offset=struct.unpack_from('<I',span(data,array,4))[0]
    loader=span(data,offset,len(data)-offset)
    require(struct.unpack_from('<I',span(loader,0,8))[0]==0x6c347964 and struct.unpack_from('<H',loader,6)[0]==0x8000,
            'program main loader identity differs')
    pathoff=struct.unpack_from('<H',span(loader,32,2))[0]
    path,_=cstring(loader,pathoff)
    fvi=struct.unpack_from('<H',span(loader,42,2))[0]
    if not fvi:return dict(path=path,cdhash=None,check_cdhash=False)
    row=span(loader,fvi,56)
    require(row[52] in (0,1) and row[53] in (0,1),'program validation flags differ')
    return dict(path=path,cdhash=row[32:52].hex(),check_cdhash=bool(row[53]))


def original_inventory(family):
    pool_address,pool_size,trie_address=struct.unpack_from('<3Q',family.main.data,336)
    trie_size=struct.unpack_from('<I',family.main.data,360)[0]
    require(pool_address and pool_size and trie_address and trie_size,'original program metadata missing')
    keys=path_trie(family.read(trie_address,trie_size),pool_size)
    rows={};by_offset={}
    for offset in sorted(set(keys.values())):
        require(offset%8==0 and offset+20<=pool_size,'original program set offset/extent')
        length=struct.unpack_from('<I',family.read(pool_address+offset,20),8)[0]
        require(length>0 and offset+length<=pool_size,'original program set exceeds pool')
        identity=main_identity(family.read(pool_address+offset,length))
        require(identity['path'] not in rows,'duplicate original program main path')
        row=dict(identity,offset=offset,size=length,keys=sorted(k for k,v in keys.items() if v==offset))
        rows[identity['path']]=row;by_offset[offset]=identity['path']
    return rows,{key:by_offset[value] for key,value in keys.items()}


def validate_retirement(retired,original):
    require(len(retired)==1 and retired[0]['path']==MIRRORING,'only selected hook53a Mirroring retirement is allowed')
    row=retired[0];old=original[MIRRORING]
    require(row['original_pool_offset']==old['offset']==12005616 and
            set(row['retired_keys'])==set(old['keys'])=={MIRRORING,'/cdhash/'+RETIRED_HASH},
            'Mirroring retirement differs from original inventory')


def build_pool(programs,required,retired,entries,cached_count,*,reserve,trie_reserve):
    """Pack every required validated set; never skip a set to fit a reservation."""
    require(type(reserve) is int and 0<reserve<2**32 and type(trie_reserve) is int and trie_reserve>0,
            'invalid program reservations')
    require(len(required)==len(set(required)) and len(retired)==len(set(retired)) and set(retired)<=set(required),
            'duplicate/unknown required program retirement')
    paths=[p['path'] for p in programs]
    require(len(paths)==len(set(paths)) and set(paths)==set(required)-set(retired),'required program set missing/extra/duplicate')
    require(entries and set(entries.values())==set(paths),'program trie misses a set or targets unknown set')
    pool=bytearray();rows=[];offsets={};identities={}
    for row in sorted(programs,key=lambda r:r['path'].encode('utf-8')):
        data=row['data'];require(isinstance(data,bytes) and len(data)==row['size'] and
            hashlib.sha256(data).hexdigest()==row['sha256'],'program bytes drift')
        identity=main_identity(data)
        require(identity=={k:row[k] for k in ('path','cdhash','check_cdhash')},'program main validation differs from report')
        require(struct.unpack_from('<I',data,28)[0]==0,'UUID-bound disk program set cannot survive cache reidentification')
        parsed=read_set(data,cached_count,app=True)
        require(len(parsed['loaders'])==row['loader_count'],'program loader count differs')
        offset=len(pool);padded=(len(data)+7)&~7
        require(offset+padded<=reserve,'required program pool exceeds reserved bytes')
        offsets[row['path']]=offset;identities[row['path']]=identity
        pool+=data+bytes(padded-len(data));rows.append({k:row[k] for k in ('path','size','sha256','loader_count','cdhash','check_cdhash')})
        rows[-1]['offset']=offset
    expected_hashes={}
    for path in sorted(paths,key=lambda value:value.encode('utf-8')):
        if identities[path]['check_cdhash']:expected_hashes['/cdhash/'+identities[path]['cdhash']]=path
    require({key:path for key,path in entries.items() if key.startswith('/cdhash/')}==expected_hashes,
            'program CDHash keys differ from factory lexicographic last-wins policy')
    for key,path in entries.items():
        require(isinstance(key,str) and key.startswith('/') and path in offsets,'invalid program trie key/target')
        if key.startswith('/cdhash/'):
            require(identities[path]['check_cdhash'] and key=='/cdhash/'+identities[path]['cdhash'],
                    'stale/wrong program CDHash key')
    require(all(path in entries and entries[path]==path for path in paths),'canonical program trie key missing')
    require(all(not row['check_cdhash'] or '/cdhash/'+row['cdhash'] in entries for row in identities.values()),
            'required program CDHash key missing')
    indexed={key:offsets[path] for key,path in entries.items()}
    trie=write_path_trie(indexed,len(pool),reserve=trie_reserve)
    trie+=bytes((-len(trie))%8)
    require(len(trie)<=trie_reserve and path_trie(trie,len(pool))==indexed,'program trie alignment/roundtrip differs')
    return bytes(pool),trie,rows,indexed


def validate_current_retirement(retired,original,original_keys,source_manifest,views):
    """The retired programs are exactly those absent from the current System."""
    from .run_loaders import retirement_records
    require(retired==retirement_records(original,original_keys,views),'program retirement differs from the System')
    return {r['path'] for r in retired}


def validate_current_pool_coverage(rows,required,retired,original_keys,trie,required_count):
    """Independently require exact current main sets and every retained path alias."""
    paths=[row['path'] for row in rows]
    require(set(retired)<=set(required) and set(original_keys.values())<=set(required),'unknown current source path/retirement')
    require(required_count==len(required) and len(paths)==len(set(paths))
            and set(paths)==set(required)-set(retired),'current program pool omitted/duplicated required sets')
    offsets={row['path']:row['offset'] for row in rows}
    actual={key:offset for key,offset in trie.items() if not key.startswith('/cdhash/')}
    expected={key:offsets[path] for key,path in original_keys.items() if not key.startswith('/cdhash/') and path not in retired}
    require(actual==expected,'current program pool path/alias inventory differs')
    return dict(required=len(required),retired=len(retired),sets=len(paths),path_keys=len(expected))
