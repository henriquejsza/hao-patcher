"""Append canonical name pools without changing already published identities."""
from .exports import require


def extend_pool(data, address, reserve, old_names, additions):
    require(isinstance(data,bytes) and len(data)<=reserve,'canonical name pool exceeds reservation')
    require(type(address) is int and address>=0 and type(reserve) is int and reserve>0,'invalid canonical name reservation')
    occupied=[]
    for name,location in old_names.items():
        raw=name.encode('utf-8')+b'\0';offset=location-address
        require(0<=offset and offset+len(raw)<=len(data) and data[offset:offset+len(raw)]==raw,
                'canonical old name/address differs')
        occupied.append((offset,offset+len(raw)))
    occupied.sort()
    require(all(a[1]<=b[0] for a,b in zip(occupied,occupied[1:])),'canonical old names overlap')
    names=dict(old_names);result=bytearray(data)
    require(len(additions)==len(set(additions)),'duplicate canonical additions')
    for name in sorted(additions):
        require(isinstance(name,str) and name and '\0' not in name and name not in names,'invalid new canonical name')
        names[name]=address+len(result);result+=name.encode('utf-8')+b'\0'
    require(len(result)<=reserve,'new canonical names exceed reservation')
    return bytes(result),names
