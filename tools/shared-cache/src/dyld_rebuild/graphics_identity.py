"""Hash-gated graphics input identity changes within verified header padding.

Produces unsigned cache-builder inputs only. No VA bundle conversion, signing,
file relocation, dependency-version substitution or runtime action is performed.
"""
import hashlib
import struct
from .exports import require,span,cstring
from .provider_identity import x86_slice
DYLIB_COMMANDS={0xc,0xd,0x80000018,0x8000001f,0x80000023,0x20}

def inspect_graphics(data):
    base,length,_=x86_slice(data);image=span(data,base,length)
    magic,cpu,sub,kind,count,size,flags,reserved=struct.unpack('<8I',span(image,0,32))
    require((magic,cpu,sub,kind)==(0xfeedfacf,0x1000007,3,6),'graphics normalization requires plain x86_64 MH_DYLIB')
    require(reserved==0 and 0<count<=4096,'invalid graphics Mach-O header')
    end=32+size;span(image,32,size);records=[];payload=[];ids=[];pos=32
    for _ in range(count):
        cmd,n=struct.unpack('<II',span(image,pos,8));require(n>=8 and n%8==0 and pos+n<=end,'invalid graphics command bounds')
        raw=span(image,pos,n);r={'command':cmd,'offset':pos,'size':n}
        if cmd in DYLIB_COMMANDS:
            require(n>=24,'short dylib command');nameoff,timestamp=struct.unpack_from('<II',raw,8)
            require(nameoff==24 and timestamp!=0x1a741800,'unsupported dylib name encoding')
            name,finish=cstring(raw,24);require(name and not any(raw[finish:]),'invalid dylib name/padding');r['name']=name
            if cmd==0xd:ids.append(r)
        elif cmd==0x19:
            require(n>=72,'short segment');vm,vms,off,fs=struct.unpack_from('<4Q',raw,24);sections=struct.unpack_from('<I',raw,64)[0]
            require(n==72+80*sections,'segment section count differs');span(image,off,fs)
            if fs and off:payload.append(off)
            for i in range(sections):
                at=72+80*i;addr,ss,so,align,ro,nrel,sf=struct.unpack_from('<QQIIIII',raw,at+32)
                if ss and sf&0xff not in (1,0xc,0x12):span(image,so,ss);payload.append(so)
                if nrel:span(image,ro,nrel*8);payload.append(ro)
        elif cmd==0x1d:
            require(n==16,'bad signature command');off,ss=struct.unpack_from('<II',raw,8);span(image,off,ss)
            if ss:payload.append(off)
        records.append(r);pos+=n
    require(pos==end and len(ids)==1 and payload,'missing identity/payload or command size mismatch')
    first=min(payload);require(first>=end,'header padding not bounded')
    # Unreferenced historical bytes may remain after sizeofcmds. Preserve them.
    padding_end=next((i for i in range(end,first) if image[i]),first)
    require(sum(r['command']==0x1d for r in records)<=1,'multiple signatures')
    return dict(slice_offset=base,slice_size=length,command_end=end,first_payload=first,padding_end=padding_end,records=records,identity=ids[0])

def normalize_graphics(data,expected_sha256,expected_id,canonical_path,dependency_changes=None):
    require(hashlib.sha256(data).hexdigest()==expected_sha256,'graphics source hash differs')
    changes=dependency_changes or {};before=inspect_graphics(data)
    require(before['identity']['name']==expected_id,'graphics install name differs')
    require(canonical_path.startswith('/') and '\0' not in canonical_path,'canonical graphics path must be absolute')
    for value in changes.values():require(value.startswith('/') and '\0' not in value,'dependency destination must be absolute')
    base=before['slice_offset'];rewritten=[];changed=[];seen=set()
    for r in before['records']:
        cmd=r['command'];raw=bytes(span(data,base+r['offset'],r['size']))
        if cmd==0x1d:continue
        if cmd==0x19 and raw[8:24].rstrip(b'\0')==b'dsce.bs.names':
            require(struct.unpack_from('<Q',raw,32)[0]==0 and
                    struct.unpack_from('<Q',raw,48)[0]==0 and
                    all(struct.unpack_from('<Q',raw,72+80*i+40)[0]==0 and
                        struct.unpack_from('<I',raw,72+80*i+60)[0]==0
                        for i in range(struct.unpack_from('<I',raw,64)[0])),
                    'extractor marker segment is not empty')
            # Only LINKEDIT follows this extractor marker; no loaded data moves.
            later=[x for x in before['records'] if x['command']==0x19 and x['offset']>r['offset']]
            require(len(later)==1 and data[base+later[0]['offset']+8:base+later[0]['offset']+24].rstrip(b'\0')==b'__LINKEDIT',
                    'extractor marker precedes a loaded segment')
            require(not any(x['command'] in (0x1e,0x80000034) for x in before['records']),
                    'extractor marker removal needs split/chained segment ordinal rewrite')
            first_section=1+sum(struct.unpack_from('<I',data,base+x['offset']+64)[0]
                                for x in before['records'] if x['command']==0x19 and x['offset']<r['offset'])
            for x in before['records']:
                if x['command']==2:
                    symoff,nsyms=struct.unpack_from('<II',data,base+x['offset']+8)
                    for i in range(nsyms):
                        symbol=span(data,base+symoff+16*i,16)
                        require(not (symbol[4]&0xe==0xe and symbol[5]>=first_section),
                                'symbol references removed extractor section or later section')
            changed.append({'command':cmd,'removed_empty_extractor_segment':'dsce.bs.names'})
            continue
        target=canonical_path if cmd==0xd else changes.get(r.get('name')) if cmd in DYLIB_COMMANDS else None
        if target is not None:
            if cmd!=0xd:seen.add(r['name'])
            name=target.encode()+b'\0';n=(24+len(name)+7)&~7;new=bytearray(raw[:24]);struct.pack_into('<I',new,4,n);new+=name+bytes(n-24-len(name));raw=bytes(new)
            if target!=r['name']:changed.append({'command':cmd,'from':r['name'],'to':target})
        rewritten.append(raw)
    require(seen==set(changes),'requested dependency rewrite not found')
    commands=b''.join(rewritten);end=32+len(commands);require(end<=before['padding_end'],'insufficient zero header padding')
    after=bytearray(data);clear_end=max(end,before['command_end']);after[base+32:base+clear_end]=commands+bytes(clear_end-end)
    struct.pack_into('<II',after,base+16,len(rewritten),len(commands));after=bytes(after)
    info=inspect_graphics(after)
    require(info['identity']['name']==canonical_path and not any(r['command']==0x1d for r in info['records']),'normalized identity/signature proof failed')
    require(after[:base]==data[:base] and after[base+clear_end:]==data[base+clear_end:],'non-header payload changed')
    require(after[base:base+16]==data[base:base+16] and after[base+24:base+32]==data[base+24:base+32] and len(after)==len(data),'header/layout scope changed')
    return after,dict(source_sha256=expected_sha256,sha256=hashlib.sha256(after).hexdigest(),canonical_path=canonical_path,changes=changed,header_end_before=before['command_end'],header_end_after=end,first_payload=before['first_payload'],signature_command_removed=True,payload_unchanged=True)
