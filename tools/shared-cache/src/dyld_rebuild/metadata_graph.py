"""Portable Swift construction and export graph; addresses exist only at binding.

Constructor edges describe runtime operations. Object keys describe canonical
identity; relocation edges describe payload fields, including self references.
The catalog and worker protocol are projections, never alternative graph inputs
without an explicit import. Runtime observations remain evidence, not identity.
"""
from copy import deepcopy
import hashlib
import json
import uuid

from .exports import require

KIND = 'swift-metadata-graph'


def identity(kind, value):
    wire = json.dumps(value, sort_keys=True, separators=(',', ':'))
    return kind + '#' + hashlib.sha256(wire.encode()).hexdigest()


def binary_reference(ref, architecture):
    require(all(k in ref for k in ('image', 'image_uuid', 'segment', 'section', 'offset')),
            'constructor needs a stable image/section reference; renew analysis')
    require(type(ref['offset']) is int and ref['offset'] >= 0, 'invalid section offset')
    return dict(kind='binary', architecture=architecture,
                **{k: ref[k] for k in ('image', 'image_uuid', 'segment', 'section', 'offset')},
                executable=bool(ref.get('executable', False)))


class MetadataGraph:
    def __init__(self, document=None, *, architecture='x86_64'):
        self.document = deepcopy(document) if document is not None else dict(
            schema=1, kind=KIND, architecture=architecture, constructors={}, requests=[],
            objects={}, loads=[], evidence={})
        require(self.document.get('schema') == 1 and self.document.get('kind') == KIND,
                'unknown Swift metadata graph')
        self.architecture = self.document['architecture']

    def constructor(self, operation, **operands):
        node = dict(operation=operation, **operands)
        key = identity('constructor', node)
        self.document['constructors'][key] = node
        return key

    def request(self, name, owner=None, constructor=None, *, source=None, unresolved=None):
        row = dict(name=name, source=source)
        if constructor is not None:
            row.update(owner=owner, constructor=constructor)
        if unresolved is not None:
            row['unresolved'] = unresolved
        row['id'] = identity('request', row)
        row['facts'] = ['requested'] + (['unresolved'] if unresolved else [])
        self.document['requests'].append(row)
        return row['id']

    @classmethod
    def from_plan(cls, definitions, records, loads=(), *, architecture='x86_64'):
        """Frontend API. Raw cache offsets are deliberately never imported."""
        graph = cls(architecture=architecture)
        translated = {}
        for row in definitions:
            operation = row['operation']
            if operation == 'resolve':
                operands = dict(name=row['name'])
            elif operation == 'reference':
                operands = dict(metadata=binary_reference(row['metadata_reference'], architecture))
            else:
                require(operation in ('generic', 'opaque'), 'unknown constructor operation')
                operands = dict(descriptor=binary_reference(row['descriptor_reference'], architecture),
                                arguments=[translated[k] for k in row['arguments']])
                if operation == 'opaque':
                    operands.update(context=binary_reference(row['context_reference'], architecture),
                                    ordinal=row['ordinal'], key_arguments=row['key_arguments'],
                                    requirements=[dict(
                                        subject=binary_reference(r['subject_address_reference'], architecture),
                                        subject_length=r['subject_length'],
                                        protocol=binary_reference(r['protocol_reference'], architecture))
                                        for r in row['requirements']])
            translated[row['id']] = graph.constructor(operation, **operands)
        for row in records:
            require('key' not in row, 'installed exact keys are not portable constructors')
            key = translated[row['dependency']] if 'dependency' in row else graph.constructor('resolve', name=row['name'])
            graph.request(row['name'], row['owner'], key, source=row.get('id'))
        graph.document['loads'] = sorted(set(loads))
        return graph

    def frontend_evidence(self, report):
        """Keep failures and exclusions in the graph's requested denominator."""
        self.document['evidence']['frontend'] = deepcopy(report)
        requested = {r['name'] for r in self.document['requests']}
        for row in report.get('entries', []) + report.get('opaque_entries', []) + report.get('source_failures', []):
            if row['name'] not in requested:
                self.request(row['name'], source=row.get('source', row.get('sources')),
                             unresolved=dict(row))

    def reset_results(self):
        """Starting a new expansion never counts past observations as new work."""
        self.document['objects'] = {}
        self.document.pop('catalog', None)
        self.document.pop('catalog_order', None)
        self.document['evidence'] = {k: v for k, v in self.document['evidence'].items()
                                     if k in ('frontend', 'frontends')}
        for row in self.document['requests']:
            for field in ('outcome', 'object', 'compiler_object'):
                row.pop(field, None)
            row['facts'] = ['requested'] + (['unresolved'] if 'unresolved' in row else [])

    def merge_frontend(self, other, *, source):
        require(other.architecture == self.architecture, 'frontend architectures differ')
        self.document['constructors'].update(deepcopy(other.document['constructors']))
        known = {r['id'] for r in self.document['requests']}
        for row in other.document['requests']:
            row = deepcopy(row)
            row['source'] = dict(input=source, declaration=row['source'])
            row['id'] = identity('request', {k: v for k, v in row.items() if k not in ('id', 'facts')})
            if row['id'] not in known:
                self.document['requests'].append(row)
                known.add(row['id'])
        self.document['loads'] = sorted(set(self.document['loads']) | set(other.document['loads']))

    def import_catalog(self, catalog):
        """Preserve every exact-key variant, alias and original record byte-for-byte."""
        from .swift_graph import optional_records, record_id
        self.document['objects'] = {}
        dependency = catalog.get('kind') == 'swift-dependency-catalog'
        records = catalog['records'] if dependency else optional_records(catalog)
        self.document['catalog'] = {k: deepcopy(v) for k, v in catalog.items() if k not in ('records', 'witnesses')}
        self.document['catalog_order'] = dict(records=[], witnesses=[])
        for field, rows in (('records', records), ('witnesses', catalog.get('witnesses', []))):
            for row in rows:
                key = record_id(row)
                family = 'protocol-witness' if field == 'witnesses' else row.get('record_kind', 'generic-value')
                # Original IDs belong to the installation backend. Keep them even
                # when two aliases share an address or a printable type name.
                def typed(ref):
                    if 'owned' in ref:
                        return dict(kind='object', target=ref['owned'])
                    if 'local' in ref:
                        return dict(kind='local', offset=ref['local'])
                    return binary_reference(ref, self.architecture)
                self.document['objects'][key] = dict(
                    family=family, key=[typed(r) for r in row['key']],
                    payload=dict(data=row['data'], address_point=row['metadata_offset'],
                                 relocations=[dict(offset=p['offset'], target=typed(p['ref'])) for p in row['pointers']]),
                    attributes={k: deepcopy(v) for k, v in row.items()
                                if k not in ('key', 'data', 'metadata_offset', 'pointers')}, facts=['retained'])
                self.document['catalog_order'][field].append(key)
        if not dependency:
            self.document['catalog'].update(schema=3, kind='swift-value-catalog')

    def catalog(self):
        result = deepcopy(self.document['catalog'])
        for field, keys in self.document['catalog_order'].items():
            if field == 'records' or result['kind'] == 'swift-dependency-catalog':
                def exported(key):
                    node = self.document['objects'][key]
                    def ref(value):
                        if value['kind'] == 'object':
                            return dict(owned=value['target'])
                        if value['kind'] == 'local':
                            return dict(local=value['offset'])
                        return {k: v for k, v in value.items() if k not in ('kind', 'architecture')}
                    return dict(deepcopy(node['attributes']), key=[ref(r) for r in node['key']],
                                data=node['payload']['data'], metadata_offset=node['payload']['address_point'],
                                pointers=[dict(offset=p['offset'], ref=ref(p['target']))
                                          for p in node['payload']['relocations']])
                result[field] = [exported(k) for k in keys]
        return result

    def record_capture(self, family, captured):
        """Fold a worker's observations into this graph using ABI family exporters."""
        from .swift_graph import normalize_graph
        before = set(self.document['objects'])
        catalog, report = normalize_graph(self.bind(family), captured, family,
                                          self.catalog(), witness_closures=True)
        self.import_catalog(catalog)
        for key, node in self.document['objects'].items():
            node['facts'] = ['retained'] if key in before else ['generated']
        executable = [r for r in self.document['requests'] if 'constructor' in r]
        require(len(executable) == len(report['entries']), 'capture outcomes differ from graph requests')
        for request, outcome in zip(executable, report['entries']):
            request['outcome'] = deepcopy(outcome)
            state = outcome['status']
            if state == 'included':
                request['object'] = outcome['record_id']
                request['facts'] = ['requested'] + self.document['objects'][outcome['record_id']]['facts']
            elif state == 'compiler_static':
                request['facts'] = ['requested', 'compiler_provided']
                request['compiler_object'] = binary_reference(outcome['metadata'], self.architecture)
            else:
                request['facts'] = ['requested', 'unresolved']
        self.document['evidence']['capture'] = dict(
            cache_uuid=catalog['source_cache_uuid'], recovered_prefix=report['recovered_prefix'],
            scope='Matching-runtime construction and export. Installed and application adoption are unmeasured.')
        self.document['evidence']['generation'] = report
        return report

    def coverage(self):
        from collections import Counter
        requests = self.document['requests']
        objects = self.document['objects']
        return dict(
            scope='Requested frontend expressions and their runtime closures; not exhaustive application coverage.',
            requests=len(requests), constructor_requests=sum('constructor' in r for r in requests),
            request_facts=dict(Counter(f for r in requests for f in r['facts'])),
            object_families=dict(Counter(n['family'] for n in objects.values())),
            object_facts=dict(Counter(f for n in objects.values() for f in n['facts'])),
            generation=self.document['evidence'].get('generation'),
            installed=None, observed_native_use=None,
            verification=self.document['evidence'].get('isolated_replay',
                dict(executed=False, installed=False, result=None)),
            unresolved=[dict(id=r['id'], name=r['name'],
                             outcome=r.get('outcome', r.get('unresolved')))
                        for r in requests if 'unresolved' in r['facts']])

    def bind(self, family):
        """Compile portable constructors to the existing matching-runtime wire ABI."""
        from .swift_metadata import References
        require(self.architecture == 'x86_64', 'runtime worker does not support this architecture')
        refs = References(family)
        base = family.main.mappings[0].address
        def address(ref):
            require(ref['kind'] == 'binary' and ref['architecture'] == self.architecture,
                    'constructor binary architecture differs')
            return refs.decode(ref) - base
        nodes = self.document['constructors']
        bound, visiting, definitions = {}, set(), []
        def emit(key):
            if key in bound:
                return bound[key]
            require(key not in visiting, 'recursive constructor dependency')
            visiting.add(key)
            node = nodes[key]
            operation = node['operation']
            if operation == 'resolve':
                row = dict(operation=operation, name=node['name'])
            elif operation == 'reference':
                row = dict(operation=operation, metadata=address(node['metadata']))
            else:
                require(operation in ('generic', 'opaque'), 'unsupported runtime operation')
                row = dict(operation=operation, descriptor=address(node['descriptor']),
                           arguments=[emit(k) for k in node['arguments']])
                if operation == 'opaque':
                    row.update(context=address(node['context']), ordinal=node['ordinal'],
                               key_arguments=node['key_arguments'], requirements=[dict(
                                   subject_address=address(r['subject']), subject_length=r['subject_length'],
                                   protocol=address(r['protocol'])) for r in node['requirements']])
            visiting.remove(key)
            bound[key] = str(len(definitions) + 1)
            definitions.append(dict(row, id=bound[key]))
            return bound[key]
        records = [dict(id=r['id'], name=r['name'], owner=r['owner'], dependency=emit(r['constructor']))
                   for r in self.document['requests'] if 'constructor' in r]
        return dict(schema=1, kind='generic-values',
                    cache_uuid=str(uuid.UUID(bytes=bytes(family.main.data[88:104]))),
                    definitions=definitions, records=records, loads=self.document['loads'])
