"""Prepare Swift payloads and register each ABI family's distinct lookup map."""
import struct
from .exports import require
from .image_indexes import swift_roots
from .swift_graph import materialize_dependencies
from .swift_metadata import emit_table
from .witness_runtime import recipe as runtime_recipe


def prepare(catalog,family,layout,output,toolchain):
    result=materialize_dependencies(catalog,family,layout['swift_metadata']['address'])
    roots=result['roots'];base=roots['base']
    metadata,metadata_lookup=emit_table(result['metadata_entries'],output/'metadata')
    _,tables=swift_roots(family)
    slot=len(tables['pointer_tables'])
    kinds=['witness'] + (['metatype'] if result['metatype_entries'] else [])
    if result['normalized_entries']:kinds.append('normalized')
    require(slot+len(kinds)<=8,'dyld has no free pointer-table registration slots')
    blobs=[dict(reservation=name,address=layout[name]['address'],data=data.hex()) for name,data in (
        ('swift_metadata',result['data']),('swift_table',metadata)) if data]
    reports,edits={},[]
    for index,kind in enumerate(kinds,slot):
        table,lookup=emit_table(result[kind+'_entries'],output/kind)
        reservation='swift_'+kind+'_table'
        address=layout[reservation]['address']
        registration=base+struct.unpack_from('<Q',family.main.data,376)[0]+40+index*8
        require(family.read(registration,8)==bytes(8),'dyld '+kind+' registration slot is occupied')
        blobs.append(dict(reservation=reservation,address=address,data=table.hex()))
        reports[kind]=dict(lookup=lookup,registration=registration)
        edits.append(dict(address=registration,before=bytes(8).hex(),after=struct.pack('<Q',address-base).hex()))
    runtime=runtime_recipe(family,toolchain,layout,output/'runtime',metatypes='metatype' in reports,
                           metadata_shapes=result['metadata_shapes'])
    for row in blobs:
        require(len(bytes.fromhex(row['data']))<=layout[row['reservation']]['reserve'],'Swift dependency allocation too small')
    metadata_address=layout['swift_table']['address']
    records=[r for r in result['records'] if r['kind']=='metadata' and r.get('abi_family')!='metatype']
    witnesses=[r for r in result['records'] if r['kind']=='protocol-witness']
    report=dict(schema=1,blobs=blobs+runtime['blobs'],records=records,witnesses=witnesses,
        new_pointer_fields=result['pointers']+runtime['new_pointer_fields'],
        retained_entries=[dict(key=list(k),values=v) for k,v in sorted(result['original'].items())],
        original_keys=len(result['original']),total_keys=len(result['metadata_entries']),source_lookup=metadata_lookup,
        witness_lookup=reports['witness']['lookup'],witness_registration=reports['witness']['registration'],witness_runtime=runtime,
        pointer_edits=[dict(address=roots['swift_pointer'],expected=roots['table'],target=metadata_address,
                            member_before=True,member_after=True)],
        byte_edits=[dict(address=roots['dyld_offset'],before=struct.pack('<Q',roots['table']-base).hex(),
                         after=struct.pack('<Q',metadata_address-base).hex())]+edits+runtime['byte_edits'])
    if 'metatype' in reports:
        report.update(metatypes=[r for r in result['records'] if r.get('abi_family')=='metatype'],
                      metatype_registration=reports['metatype']['registration'],metatype_lookup=reports['metatype']['lookup'])
    if 'normalized' in reports:
        report.update(normalized=[dict(key=list(k),address=base+v[0]) for k,v in sorted(result['normalized_entries'].items())],
                      normalized_registration=reports['normalized']['registration'],normalized_lookup=reports['normalized']['lookup'])
    return report
