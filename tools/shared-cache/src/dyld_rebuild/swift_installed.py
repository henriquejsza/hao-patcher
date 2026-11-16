"""Resolve catalog identities from the installed cache's registered Swift maps."""
from .exports import require
from .swift_graph import optional_records, record_id
from .swift_metadata import References, pointer_entries
from .image_indexes import swift_roots
from .objc_emit import FamilyReader
from .swift_refs import read_table


def auxiliary_entries(family, roots):
    """Read auxiliary maps; conformance descriptors and ABI function keys are disjoint."""
    base = roots['base']
    result = {}
    _, registered = swift_roots(family)
    for offset in registered['pointer_tables']:
        if base + offset == roots['table']:
            continue
        table = read_table(family.read, base + offset, 'pointer')
        keys = dict(table.pointer_keys)
        for row in table.rows:
            result.setdefault(keys[row[0]], set()).add(row[3] & ((1 << 63) - 1))
    return result


def records(catalog, family):
    """Read existing identities only; never allocate replacement metadata."""
    metadata, roots = pointer_entries(family)
    base = roots['base']
    witnesses = catalog.get('witnesses', [])
    witness_map = auxiliary_entries(family, roots) if witnesses or any(
        r.get('record_kind')=='metatype' for r in catalog['records']) else {}
    values = (catalog['records'] if catalog.get('kind') == 'swift-dependency-catalog'
              else optional_records(catalog))
    pending = {record_id(row): row for row in values + witnesses}
    require(len(pending) == len(values) + len(witnesses), 'duplicate installed Swift identity')
    witness_ids = {record_id(row) for row in witnesses}
    refs, reader = References(family), FamilyReader(family)
    resolved, result = {}, []
    while pending:
        ready = [identity for identity, row in pending.items() if all(
            'owned' not in ref or ref['owned'] in resolved for ref in row['key'])]
        require(ready, 'cyclic or missing installed Swift key dependency')
        for identity in ready:
            row = pending.pop(identity)
            key = tuple((resolved[ref['owned']] if 'owned' in ref else refs.decode(ref)) - base
                        for ref in row['key'])
            kind = 'protocol-witness' if identity in witness_ids else 'metadata'
            table = witness_map if identity in witness_ids or row.get('record_kind')=='metatype' else metadata
            addresses = set(table.get(key, []))
            require(len(addresses) == 1, f'missing or ambiguous installed Swift {kind} key: {identity}')
            address = base + addresses.pop()
            if identity in witness_ids:
                require(reader.ptr(address) == base + key[0], 'installed witness descriptor differs from its key')
            if row.get('record_kind')=='metatype':
                import struct
                require(struct.unpack('<Q',family.read(address,8))[0]==0x304 and
                        reader.ptr(address+8)==base+key[1], 'installed metatype instance differs from its key')
            resolved[identity] = address
            result.append(dict(id=identity, name=row['name'], kind=kind, key=list(key),
                               address=address, existing=True,
                               **({'abi_family':'metatype'} if row.get('record_kind')=='metatype' else {})))
    return result, roots


def verify_capture(recipe, captured, family, catalog):
    """Verify exact installed keys without serializing their dependencies again."""
    import uuid
    header, *events = captured
    cache_uuid = str(uuid.UUID(bytes=bytes(family.main.data[88:104])))
    require(header.get('schema') == 2 and header.get('cache_uuid') == recipe.get('cache_uuid') == cache_uuid,
            'installed verification capture belongs to another cache')
    require(events[-1:] == [dict(complete=True)], 'installed verification capture was interrupted')
    roots = [row for row in events if 'root' in row]
    require(len(roots) == len(recipe['records']) and all(
        row['root'] == index and row['name'] == request['name']
        for index, (row, request) in enumerate(zip(roots, recipe['records']), 1)),
        'installed verification lost or reordered roots')
    installed, tables = records(catalog, family)
    expected = {row['id']: row for row in installed if row['kind'] == 'metadata'}
    require(len(recipe['records']) == len(expected) and
            {row.get('id',row['name']) for row in recipe['records']} == set(expected),
            'installed verification recipe does not cover its catalog')
    slide = header['base'] - tables['base']
    outcomes = []
    for request, observed in zip(recipe['records'], roots):
        identity = request.get('id',request['name'])
        target = expected[identity]
        require(request['key'] == target['key'], 'installed verification recipe key differs from catalog')
        matched = not observed.get('error') and observed.get('metadata',0)-slide == target['address']
        outcomes.append(dict(name=request['name'],record_id=identity,
            status='included' if matched else 'unsupported',
            reason='installed canonical identity' if matched else observed.get('error','runtime returned another metadata identity')))
    included = sum(row['status']=='included' for row in outcomes)
    report = dict(verification=True,complete=included==len(roots),requested=len(roots),included=included,
                  added=0,retained=len(catalog['records']),retained_witnesses=len(catalog.get('witnesses',[])),entries=outcomes)
    return dict(catalog,source_cache_uuid=cache_uuid), report
