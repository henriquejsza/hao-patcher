"""Provider __interpose tuples applied as cache patches (fold-in, pm/metal 2026-11-14). No Apple data."""
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild import cache_exports, run_patch  # noqa: E402
from dyld_rebuild.cache_exports import FinalGraph, trie_flags  # noqa: E402
from dyld_rebuild.exports import Export, Refusal  # noqa: E402
from dyld_rebuild.provider_layout import interpose_tuples, is_interpose  # noqa: E402


def trie(node):
    """Export trie bytes for {'terminal': bytes, 'children': {label: node}} with one-byte ulebs (small tries)."""
    order = []

    def walk(n):
        order.append(n)
        for child in n.get('children', {}).values():
            walk(child)
    walk(node)
    sizes = {id(n): 2 + len(n.get('terminal', b'')) + sum(len(l) + 2 for l in n.get('children', {})) for n in order}
    offsets, at = {}, 0
    for n in order:
        offsets[id(n)] = at
        at += sizes[id(n)]
    assert at < 128
    out = bytearray()
    for n in order:
        terminal = n.get('terminal', b'')
        out += bytes([len(terminal)]) + terminal + bytes([len(n.get('children', {}))])
        for label, child in n.get('children', {}).items():
            out += label.encode() + b'\0' + bytes([offsets[id(child)]])
    return bytes(out)


TRIE = trie({'children': {'_a': {'children': {'b': {'terminal': bytes([0, 0x10])},
                                               'c': {'terminal': bytes([8, 1, 0])}}}}})


class TrieWalk(unittest.TestCase):
    def test_flags(self):
        self.assertEqual(trie_flags(TRIE, '_ab'), 0)
        self.assertEqual(trie_flags(TRIE, '_ac'), 8)
        for absent in ('_a', '_abc', '_b', ''):
            self.assertIsNone(trie_flags(TRIE, absent), absent)
        self.assertEqual(set(cache_exports.export_trie(TRIE)), {'_ab', '_ac'})


class FlatLookup(unittest.TestCase):
    def graph(self, tries, providers=None):
        g = object.__new__(FinalGraph)
        g.providers = providers or {}
        images = [(f'/lib{i}', 0x1000 * (i + 1)) for i in range(len(tries))]
        g.family = SimpleNamespace(images=images, read=lambda address, size: tries[address // 0x1000 - 1])
        return g

    def resolve(self, g, symbol):
        with mock.patch.object(cache_exports, 'cached_trie_range', lambda family, header: (header, 0)), \
                mock.patch.object(FinalGraph, 'resolve', lambda self, path, s: {'status': 'resolved', 'provider': path}):
            return g.resolve_flat(symbol)

    def test_single_definer_not_reexporter(self):
        g = self.graph([trie({}), TRIE, trie({'children': {'_ac': {'terminal': bytes([0, 4])}}})])
        self.assertEqual(self.resolve(g, '_ab')['provider'], '/lib1')
        self.assertEqual(self.resolve(g, '_ac')['provider'], '/lib2')       # /lib1 only reexports it
        self.assertEqual(self.resolve(g, '_zz')['status'], 'missing_symbol')

    def test_several_definers_refused(self):
        g = self.graph([TRIE, TRIE])
        with self.assertRaises(Refusal):
            self.resolve(g, '_ab')

    def test_provider_counts_and_replaces_its_cache_image(self):
        provider = SimpleNamespace(exports={'_ab': Export(0, value=0x20)})
        self.assertEqual(self.resolve(self.graph([TRIE], {'/lib0': provider}), '_ab')['provider'], '/lib0')
        with self.assertRaises(Refusal):
            self.resolve(self.graph([TRIE], {'/p': provider}), '_ab')


def fake_image(rebases, binds, size=32, name='__interpose', flags=0):
    text = SimpleNamespace(name='__TEXT', initial=5, address=0, size=0x1000)
    data = SimpleNamespace(name='__DATA', initial=3, address=0x1000, size=0x1000)
    return SimpleNamespace(key='k', segments=[text, data],
                           sections=[dict(name=name, flags=flags, address=0x1000, size=size, segment=1)],
                           rebases=rebases, reader=SimpleNamespace(binds=binds),
                           segment=lambda a: text if a < 0x1000 else data)


def bind(symbol):
    return dict(symbol=symbol, provider='SPECIAL:flat-lookup', addend=0, weak_import=True)


class Tuples(unittest.TestCase):
    def test_pairs(self):
        image = fake_image({0x1000: 0x100, 0x1010: 0x200}, {0x1008: bind('_a'), 0x1018: bind('_b')})
        rows = interpose_tuples(image)
        self.assertEqual([(r['field'], r['replacement'], r['original']['symbol']) for r in rows],
                         [(0x1000, 0x100, '_a'), (0x1010, 0x200, '_b')])

    def test_by_type_and_not_other_sections(self):
        self.assertTrue(is_interpose(dict(name='__x', flags=0x0d), '__DATA_CONST'))
        self.assertTrue(is_interpose(dict(name='__interpose', flags=0), '__DATA'))
        self.assertFalse(is_interpose(dict(name='__interpose', flags=0), '__TEXT'))
        self.assertEqual(interpose_tuples(fake_image({}, {}, name='__data')), [])

    def test_refusals(self):
        for rebases, binds in (({0x1000: 0x100}, {}),                                  # no bind
                               ({0x1000: 0x1100}, {0x1008: bind('_a')}),                # replacement not code
                               ({0x1000: 0x100, 0x1010: 0x200}, {0x1008: bind('_a'), 0x1018: bind('_a')})):
            with self.assertRaises(Refusal):
                interpose_tuples(fake_image(rebases, binds, size=16 if len(rebases) == 1 else 32))
        with self.assertRaises(Refusal):
            interpose_tuples(fake_image({0x1000: 0x100}, {0x1008: bind('_a')}, size=24))


class CacheUses(unittest.TestCase):
    HOOK = dict(interposer='/hook.dylib', symbol='_e5rt_x', original_image_index=3, original=0x5000,
                replacement=0x9000, original_in_provider=False)

    def apply(self, rows, held=None, replaced=(), hook=None):
        table = SimpleNamespace(image_uses=lambda index: rows if index == 3 else [], images=[None] * 10)
        writes = []
        slide = SimpleNamespace(retarget=lambda offset, expected, value: writes.append((offset, expected, value)))
        mapping = SimpleNamespace(address=0x100000)
        def at(slides, address):
            return None, mapping, slide, {'target': held if held is not None else 0x5000}
        edits = []
        with mock.patch.object(run_patch, 'pointer_at', at):
            report = run_patch.interpose_edits([hook or self.HOOK], table, set(replaced), [], edits)
        return report, edits, writes

    def row(self, location, kind='GOT', client=None, symbol='_e5rt_x'):
        return dict(symbol=symbol, implementation=0x5000, addend=0, high8=0, kind=kind, location=location,
                    client_index=client, client=None)

    def test_every_use_holds_the_replacement(self):
        rows = [self.row(0x100010), self.row(0x100020, 'PATCH', 7), self.row(0x100030, symbol='_other')]
        report, edits, writes = self.apply(rows)
        self.assertEqual(writes, [(0x10, 0x5000, 0x9000), (0x20, 0x5000, 0x9000)])
        self.assertEqual([(e['location'], e['target_value'], e['encoding']) for e in edits],
                         [(0x100010, 0x9000, 'existing_v2_member'), (0x100020, 0x9000, 'existing_v2_member')])
        self.assertEqual(len(report[0]['cache_uses']), 2)

    def test_replaced_client_retired_and_drift_refused(self):
        _, edits, _ = self.apply([self.row(0x100010, 'PATCH', 7)], replaced=(7,))
        self.assertEqual(edits, [])
        with self.assertRaises(Refusal):
            self.apply([self.row(0x100010)], held=0x6000)


class ProviderOriginal(CacheUses):
    def test_replaced_image_uses_come_from_migration(self):
        # libLiveTextLibrary hooks Metal, itself a provider replacing Apple's Metal: the table walk is skipped
        hook = dict(self.HOOK, original_in_provider=True, migrated_cache_uses=[dict(kind='GOT', location=1, client=None)])
        report, edits, _ = self.apply([self.row(0x100010)], replaced=(3,), hook=hook)
        self.assertEqual((edits, report[0]['cache_uses']), ([], hook['migrated_cache_uses']))

    def test_unmigrated_provider_original_refused(self):
        with self.assertRaises(Refusal):
            self.apply([self.row(0x100010)], hook=dict(self.HOOK, original_in_provider=True))



class MissingUses(unittest.TestCase):
    def test_policy(self):
        row = lambda **kw: dict(dict(kind='GOT', weak_import=False, addend=0, high8=0, symbol='_f'), **kw)
        policy = run_patch.missing_use_policy
        self.assertEqual(policy(row()), 'marker')
        self.assertEqual(policy(row(weak_import=True)), 'weak-null')
        self.assertEqual(policy(row(kind='PATCH', symbol='_OBJC_CLASS_$__MTLTensorAuxiliaryPlane')), 'retained')
        self.assertEqual(policy(row(kind='PATCH', symbol='_OBJC_METACLASS_$_X')), 'retained')
        for refused in (row(kind='PATCH'), row(addend=8), row(high8=2),
                        row(kind='PATCH', symbol='_OBJC_CLASS_$_X', weak_import=True)):
            self.assertIsNone(policy(refused))


if __name__ == '__main__':
    unittest.main()
