import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild import swift_inventory as inv
from dyld_rebuild.exports import Refusal
from dyld_rebuild.metadata_graph import MetadataGraph
from dyld_rebuild.swift_metadata import write_json

SECTIONS = {('/L', '__TEXT', '__const'): (0x1000, 0x2000, 'aa'),
            ('/M', '__DATA_CONST', '__const'): (0x3000, 0x4000, 'bb')}


def ref(image, offset):
    segment, section = next((k[1], k[2]) for k in SECTIONS if k[0] == image)
    return dict(image=image, image_uuid=SECTIONS[(image, segment, section)][2], segment=segment,
                section=section, offset=offset, executable=False)


def record(i, key, pointers=(), size=32, point=16, **extra):
    row = dict(key=key, data='00' * size, metadata_offset=point, name=extra.pop('name', 'S' + i.split('#')[-1]),
               pointers=[dict(offset=o, ref=r) for o, r in pointers], **extra)
    if '#' in i:                                      # legacy rows are identified by their name
        row['id'] = i
    return row


def catalog():
    return dict(schema=4, kind='swift-dependency-catalog', loads=[], source_cache_uuid='u', records=[
        record('metadata#1', [ref('/L', 0x10), ref('/M', 0x20)], [(8, ref('/M', 0x40))], type_arguments=1, owner='/L'),
        record('metadata#2', [ref('/L', 0x10), dict(owned='metadata#1')], [(0, dict(owned='metadata#1'))],
               type_arguments=1),
        record('Legacy', [ref('/L', 0x30), ref('/M', 0x50)], [(8, dict(local=0))], size=24, name='Legacy'),
        record('metadata#ex', [ref('/L', 0x60), ref('/M', 0x60)]),
        record('metadata#3', [ref('/L', 0x10), ref('/M', 0x24), ref('/M', 0x28)], type_arguments=1),
    ], witnesses=[
        record('witness#1', [ref('/L', 0x80), dict(owned='metadata#2')], [(0, ref('/L', 0x80))], size=16, point=0,
               record_kind='protocol-witness'),
    ])


class View:
    """The installed-cache interface swift_inventory.readback reads, over synthetic memory."""
    base = 0

    def __init__(self, sections=SECTIONS):
        self.sections, self.metadata, self.aux, self.memory, self.pointers = dict(sections), {}, {}, {}, {}

    def decode(self, r):
        lo, hi, uuid = self.sections[(r['image'], r['segment'], r['section'])]
        if r['image_uuid'] != uuid:
            raise Refusal('Swift runtime capture belongs to a different Mach-O build: ' + r['image'])
        return lo + r['offset']

    def in_image(self, address):
        return any(lo <= address < hi for lo, hi, _ in self.sections.values())

    def read(self, address, size):
        return bytes(self.memory.get(address + i, 0) for i in range(size))

    def ptr(self, address):
        return self.pointers.get(address, 0)


def install(cat, view):
    """Place every entry as the materializer would: allocations, relocations and table keys."""
    rows = {i: (k, r) for i, k, r, _ in inv.entries(cat)}
    resolved, start = {}, 0x10000
    view.pointers[0x3028] = 0x1090                    # witness argument -> its conformance descriptor
    for i in inv.dependency_order({i: r for i, (_, r) in rows.items()}):
        kind, row = rows[i]
        key = tuple(resolved[r['owned']] if 'owned' in r else view.decode(r) for r in row['key'])
        if i == 'metadata#ex':                        # Apple's own entry, already in an image section
            view.metadata[key] = [0x1100]
            resolved[i] = 0x1100
            continue
        address = start + row['metadata_offset']
        for n, b in enumerate(bytes.fromhex(row['data'])):
            view.memory[start + n] = b
        for p in row['pointers']:
            r = p['ref']
            view.pointers[start + p['offset']] = (resolved[r['owned']] if 'owned' in r else
                                                  start + r['local'] if 'local' in r else view.decode(r))
        (view.aux.__setitem__(key, {address}) if kind == 'witness-table' else view.metadata.__setitem__(key, [address]))
        resolved[i] = address
        start += 0x100
    view.aux[(0x1010, 0x3024, 0x1090)] = {resolved['metadata#3']}   # normalized key of metadata#3
    return resolved


class ReadbackTests(unittest.TestCase):
    def setUp(self):
        self.catalog, self.view = catalog(), View()
        self.addresses = install(self.catalog, self.view)

    def test_dependencies_come_before_dependents(self):
        rows = {i: r for i, _, r, _ in inv.entries(self.catalog)}
        order = inv.dependency_order(rows)
        self.assertLess(order.index('metadata#1'), order.index('metadata#2'))
        self.assertLess(order.index('metadata#2'), order.index('witness#1'))
        self.assertEqual(sorted(order), sorted(rows))

    def test_installed_entries_are_current_with_their_adoption(self):
        state = inv.readback(self.catalog, self.view)
        self.assertEqual({s['status'] for s in state.values()}, {'current'})
        self.assertEqual(state['metadata#ex']['adoption'], 'existing')
        self.assertEqual(state['Legacy']['adoption'], 'generated')
        self.assertEqual(state['witness#1']['address'], self.addresses['witness#1'])
        self.assertEqual(state['metadata#3']['normalized'], 'yes')
        self.assertEqual(state['metadata#1']['normalized'], '')

    def test_shared_allocation_is_an_alias(self):
        alias = copy.deepcopy(self.catalog['records'][0])
        alias.update(id='metadata#alias', key=[ref('/L', 0x10), ref('/M', 0x30)], data='11' * 32)
        self.catalog['records'].append(alias)
        self.view.metadata[(0x1010, 0x3030)] = [self.addresses['metadata#1']]
        state = inv.readback(self.catalog, self.view)
        self.assertEqual((state['metadata#alias']['status'], state['metadata#alias']['adoption']), ('current', 'alias'))
        self.assertIn('metadata#1', state['metadata#alias']['reason'])

    def test_changed_image_is_stale_with_its_dependents(self):
        self.view.sections[('/M', '__DATA_CONST', '__const')] = (0x3000, 0x4000, 'changed')
        state = inv.readback(self.catalog, self.view)
        self.assertEqual(state['metadata#1']['status'], 'stale')
        self.assertIn('different Mach-O build: /M', state['metadata#1']['reason'])
        self.assertEqual((state['metadata#2']['status'], state['witness#1']['status']), ('stale', 'stale'))
        self.assertIn('depends on metadata#1', state['metadata#2']['reason'])
        del self.view.sections[('/M', '__DATA_CONST', '__const')]
        state = inv.readback(self.catalog, self.view)
        self.assertIn('image or section absent: /M', state['metadata#1']['reason'])

    def test_absent_key_and_differing_bytes_are_unknown_not_errors(self):
        del self.view.metadata[(0x1010, self.addresses['metadata#1'])]
        start = self.addresses['Legacy'] - 16
        self.view.memory[start + 2] = 7
        state = inv.readback(self.catalog, self.view)
        self.assertEqual(state['metadata#2']['status'], 'unknown')
        self.assertIn('key absent from the installed metadata map', state['metadata#2']['reason'])
        self.assertIn('depends on metadata#2', state['witness#1']['reason'])
        self.assertEqual(state['Legacy']['status'], 'unknown')
        self.assertIn('differ', state['Legacy']['reason'])
        self.assertEqual(state['metadata#1']['status'], 'current')


class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.store = root/'store'
        art = self.store/'artifacts'
        full = catalog()
        old = dict(full, records=full['records'][:1] + full['records'][2:3], witnesses=[])
        self.old, self.new = art/'old', art/'new'
        for d in (self.old, self.new, self.store/'runs'/'session'/'01-app'):
            d.mkdir(parents=True)
        write_json(self.old/'catalog.json', old)
        write_json(self.old/'build.json', dict(date='2026-01-01', operation='capture', inputs=[]))
        write_json(self.new/'catalog.json', full)
        inventory = self.store/'runs'/'session'/'01-app'/'type-processes.json'
        write_json(inventory, {'Sm2': ['/Apps/Foo.app/Contents/MacOS/Foo']})
        reflection = self.store/'tmp'/'live-Bar'/'reflection'/'graph.json'
        reflection.parent.mkdir(parents=True)
        write_json(reflection, dict(images=[dict(path='/Apps/Bar')]))
        digest = hashlib.sha256(reflection.read_bytes()).hexdigest()
        facts = {'metadata#1': 'retained', 'Legacy': 'retained', 'metadata#2': 'generated',
                 'witness#1': 'generated', 'metadata#ex': 'retained', 'metadata#3': 'generated'}
        write_json(self.new/'graph.json', dict(
            objects={k: dict(facts=[v]) for k, v in facts.items()},
            requests=[dict(name='Sm2', object='metadata#2', source=['/Apps/Foo.app/Contents/MacOS/Foo']),
                      dict(name='w', object='witness#1', source=dict(input=digest, declaration='root-1')),
                      dict(name='never', source=['/Apps/Foo.app/Contents/MacOS/Foo'])],
            evidence=dict(frontend=dict(sources=[dict(path=str(inventory))]),
                          frontends=[dict(path=str(reflection), sha256=digest)])))
        write_json(self.new/'build.json', dict(date='2026-01-02', operation='metadata-expand', inputs=[
            dict(path=str(self.old/'catalog.json'), sha256='x'), dict(path=str(art/'gone'/'catalog.json'))]))
        self.catalog = full
        self.rows = {i: r for i, _, r, _ in inv.entries(full)}

    def tearDown(self):
        self.tmp.cleanup()

    def origins(self):
        with patch.object(inv, 'STORE', self.store):
            return inv.provenance_rows(self.new/'catalog.json', self.catalog, self.rows,
                                       inv.dependency_order(self.rows))

    def test_first_stored_catalog_generation_and_missing_bases(self):
        origins, described, read = self.origins()
        self.assertEqual((origins['metadata#1']['first_catalog'], origins['metadata#1']['how']), ('old', 'capture'))
        self.assertEqual(origins['metadata#2']['how'], 'generated')
        self.assertEqual(origins['metadata#2']['sessions'], 'live-Bar;session/01-app')   # witness#1 owns it
        self.assertEqual(origins['metadata#2']['sessions_stored'], 'partial')        # live-Bar is scratch
        self.assertEqual(origins['witness#1']['how'], 'generated')
        self.assertEqual(origins['witness#1']['sessions'], 'live-Bar')
        self.assertEqual(origins['witness#1']['sessions_stored'], 'no')        # scratch only
        self.assertEqual((origins['metadata#ex']['introduced_by'], origins['metadata#ex']['introduced_stored']),
                         ('gone', 'no'))
        self.assertEqual(origins['metadata#ex']['how'], 'retained from a missing base')
        new = next(d for d in described if d['name'] == 'new')
        self.assertEqual({b['name']: b['state'] for b in new['bases']}, {'old': 'stored', 'gone': 'missing'})
        self.assertIn(self.store/'runs'/'session'/'01-app'/'type-processes.json', read)

    def test_requesters_reach_owned_dependencies(self):
        origins = self.origins()[0]
        self.assertEqual(origins['witness#1']['requested_by'], 'Bar')
        self.assertEqual(origins['metadata#2']['requested_by'], 'Bar;Foo')
        self.assertEqual(origins['metadata#1']['requested_by'], 'Bar;Foo')     # reached through metadata#2
        self.assertEqual(origins['metadata#1']['requested_in'], 'live-Bar;session/01-app')
        self.assertEqual(origins['Legacy']['requested_by'], '')
        self.assertEqual(origins['Legacy']['bytes_from'], 'old')

    def test_deleted_base_is_recoverable_from_requests_json(self):
        base = json.loads((self.old/'catalog.json').read_text())
        graph = MetadataGraph()
        graph.import_catalog(base)
        write_json(self.new/'requests.json', graph.document)
        gone = self.old.parent/'gone'/'catalog.json'
        record = dict(date='2026-01-02', inputs=[dict(path=str(gone),
                      sha256=hashlib.sha256((self.old/'catalog.json').read_bytes()).hexdigest())])
        write_json(self.new/'build.json', record)
        for f in self.old.iterdir():
            f.unlink()
        self.old.rmdir()
        with patch.object(inv, 'STORE', self.store):
            self.assertTrue(inv.Link(self.new/'catalog.json').recoverable(str(gone)))
            origins = self.origins()[0]
        self.assertEqual((origins['metadata#1']['introduced_by'], origins['metadata#1']['introduced_stored']),
                         ('gone', 'recoverable'))
        self.assertEqual(origins['metadata#2']['introduced_stored'], 'yes')
        record['inputs'][0]['sha256'] = '0' * 64
        write_json(self.new/'build.json', record)
        self.assertFalse(inv.Link(self.new/'catalog.json').recoverable(str(gone)))
        self.assertEqual(self.origins()[0]['metadata#1']['introduced_stored'], 'no')

    def test_labels_and_moves(self):
        self.assertEqual(inv.session_label('/x/store/artifacts/a-inputs-0123/night/live-NC/reflection/graph.json'),
                         'night/live-NC')
        self.assertEqual(inv.session_label('/x/store/runs/walk/03-photos/inventory/type-processes.json'),
                         'walk/03-photos')
        moves = {'_why': 'x', '/old/exact': '/old/exact', '/old/': '/new/', '/mnt/': '/img.dmg!/'}
        self.assertEqual(inv.moved('/old/a/b', moves), '/new/a/b')
        self.assertEqual(inv.moved('/old/exact', moves), '/old/exact')
        self.assertEqual(inv.moved('/mnt/x', moves), '/img.dmg')


class RecordTests(unittest.TestCase):
    def test_build_record_revision_is_the_readme_revision(self):
        from dyld_rebuild.swift_metadata import revision
        text = (Path(__file__).resolve().parents[1]/'README.md').read_text()
        newest = text.split('## Revisions', 1)[1].split('- r', 1)[1].split(' ', 1)[0]
        self.assertEqual(revision(), int(newest))


class SelectionTests(unittest.TestCase):
    def rows(self):
        cat = catalog()
        rows = []
        for i, kind, row, _ in inv.entries(cat):
            rows.append(dict(id=i, kind=kind, owner=row.get('owner', '/L'), images='/M', status='current',
                             introduced_by='new' if i in ('metadata#2', 'witness#1') else 'old',
                             first_catalog='old', sessions='session/01-app' if i == 'metadata#2' else '',
                             requested_by='Foo' if i != 'Legacy' else ''))
        return cat, rows

    def test_exclusion_keeps_the_closure_the_materializer_needs(self):
        cat, rows = self.rows()
        result, report = inv.select(cat, rows, dict(exclude=[dict(id='metadata#1')]))
        kept = {inv.record_id(r) for r in result['records'] + result['witnesses']}
        self.assertIn('metadata#1', kept)                   # owned by metadata#2
        self.assertEqual(report['closure'], [dict(id='metadata#1', kind='metadata', required_by='metadata#2')])
        result, report = inv.select(cat, rows, dict(exclude=[dict(introduced_by='new')]))
        kept = {inv.record_id(r) for r in result['records'] + result['witnesses']}
        self.assertEqual(kept, {'metadata#1', 'Legacy', 'metadata#ex', 'metadata#3'})
        self.assertEqual((report['closure_added'], report['dropped']), (0, 2))
        self.assertEqual([inv.record_id(r) for r in result['records']], ['metadata#1', 'Legacy', 'metadata#ex',
                                                                       'metadata#3'])   # catalog order

    def test_include_rules_and_fields(self):
        cat, rows = self.rows()
        result, report = inv.select(cat, rows, dict(include=[dict(kind='witness-table')]))
        self.assertEqual(report['kept_by_kind'], {'witness-table': 1, 'metadata': 2})
        self.assertEqual(report['normalized_layouts_lost'], 0)
        result, report = inv.select(cat, rows, dict(include=[dict(id='Legacy')]))
        self.assertEqual(report['normalized_layouts_lost'], 1)
        result, report = inv.select(cat, rows, dict(include=[dict(session='session/*', image='/M')]))
        self.assertEqual(report['selected'], 1)
        with self.assertRaisesRegex(Refusal, 'unknown selection field'):
            inv.select(cat, rows, dict(include=[dict(colour='red')]))


if __name__ == '__main__':
    unittest.main()
