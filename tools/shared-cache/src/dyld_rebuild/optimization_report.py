"""Read back the Swift and ObjC roots from the final signed cache family."""
import struct
from .exports import require
from .objc_emit import FamilyReader
from .objc_tables import decode_header_info, family_string, read_table
from .swift_metadata import pointer_entries


def inspect(family, layout, swift=None, *, prebuilt_loaders=True):
    base = family.main.mappings[0].address
    from .objc_tables import objc_header
    _, _, fields = objc_header(family)
    legacy = struct.unpack('<II8iq', family.read(layout['legacy_objc_root'], 48))
    require(legacy[:2] == (16, 6), 'final libobjc optimization header version/flags differ')
    for index, old_index, name in ((2, 3, 'ro'), (3, 6, 'rw'), (4, 2, 'selector'), (5, 8, 'class'), (6, 9, 'protocol')):
        expected = layout[name]['address']
        if name == 'selector' and legacy[old_index] == 0 and fields[:2] == (4, 6):
            # 27: libobjc's legacy selopt offset is 0; selectors come from dyld's header only.
            require(base + fields[index] == expected, 'final dyld selector registration differs')
            continue
        require(base + fields[index] == layout['legacy_objc_root'] + legacy[old_index] == expected,
                'final dyld/libobjc registration differs: ' + name)
    tables = {}
    for name, index in (('selector', 4), ('class', 5), ('protocol', 6)):
        table = read_table(family.read, lambda a: family_string(family, a), base + fields[index], name, base)
        tables[name] = dict(keys=len(table.entries), objects=sum(len(e.objects) for e in table.entries),
                            address=table.address, bytes=len(table.data))
    headers = decode_header_info(family.read, base + fields[2], base + fields[3], bootstrap_only=not prebuilt_loaders)
    objc = dict(tables=tables, header_infos=len(headers), cached_loader_links=len(headers) if prebuilt_loaders else 0,
                dyld_and_libobjc_roots_agree=True, native_fast_paths='OPEN')
    entries, roots = pointer_entries(family)
    result = dict(objc=objc, swift=dict(keys=len(entries), registered_table=roots['table'], native_adoption='OPEN'))
    if swift:
        require(roots['table'] == layout['swift_table']['address'], 'final Swift root did not select the generated table')
        reader = FamilyReader(family)
        for row in swift['records']:
            require(entries.get(tuple(row['key'])) == [row['address'] - base], 'final Swift catalog lookup differs')
        for field in swift['new_pointer_fields']:
            require(reader.ptr(field['address']) == field['target'], 'final Swift relocation differs')
        for row in swift['retained_entries']:
            require(entries.get(tuple(row['key'])) == row['values'], 'final Swift table changed an Apple entry')
        require(len(entries) == swift['total_keys'], 'final Swift table lost entries')
        result['swift'].update(requested=len(swift['records']), added=sum(not r['existing'] for r in swift['records']),
                               retained_keys=swift['original_keys'], relocated_pointers=len(swift['new_pointer_fields']))
        for kind,field in (('witness','witnesses'),('metatype','metatypes'),('normalized','normalized')):
            if field not in swift:continue
            from .swift_refs import read_table as read_swift
            address=layout['swift_'+kind+'_table']['address']
            require(base+struct.unpack('<Q',family.read(swift[kind+'_registration'],8))[0]==address,
                    'final '+kind+' table is not registered with dyld')
            table=read_swift(family.read,address,'pointer')
            keys=dict(table.pointer_keys)
            values={keys[row[0]]:row[3]&((1<<63)-1) for row in table.rows}
            require(len(values)==len({tuple(r['key']) for r in swift[field]}),'final '+kind+' table count differs')
            for row in swift[field]:
                require(values.get(tuple(row['key']))==row['address']-base,'final '+kind+' table lookup differs')
            runtime=swift['witness_runtime']
            for edit in runtime['byte_edits']:
                expected=bytes.fromhex(edit['after'])
                require(family.read(edit['address'],len(expected))==expected,'final Swift entry redirect differs')
            result['swift'].update({field:len(swift[field]),kind+'_keys':len(values),kind+'_table':address,
                                   kind+'_runtime':runtime.get('families',{}).get(kind,{}).get('wrapper',runtime.get('wrapper')),kind+'_native_adoption':'OPEN'})
        if swift.get('witnesses'):
            from .witness_initializers import audit_installed
            initializers=audit_installed(family,swift['witnesses'])
            require(initializers['complete'],'final Swift witness table contains stale associated witness slots')
            result['swift']['witness_initializers']=initializers
    return result
