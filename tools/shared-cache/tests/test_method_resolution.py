import sys
import struct
import json
from pathlib import Path
import unittest
from types import SimpleNamespace
from unittest.mock import Mock, patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'src'))
from dyld_rebuild.method_resolution import decision_list, resolve, differences, MethodReader, verify_report, REPORT_SOURCES
from dyld_rebuild.exports import Refusal


def method(selector, imp):
    return dict(selector=selector, imp=imp, types='@@:')


def node(lists=(), superclass=None):
    return dict(methods=decision_list(lists), superclass=superclass, unresolved_superclass=None)


class MethodResolutionTests(unittest.TestCase):

    def test_explicit_policy_requires_independent_pin_and_preserves_inventory_check(self):
        root = Path(__file__).resolve().parents[1]
        policy = root/'config/candidate-test-policy.json'
        pin = 'a'*64
        with self.assertRaisesRegex(Refusal, 'path and independent'):
            verify_report({}, [], policy_path=policy)
        with self.assertRaisesRegex(Refusal, 'path and independent'):
            verify_report({}, [], policy_sha256=pin)
        with self.assertRaisesRegex(Refusal, 'repository config'):
            verify_report({}, [], policy_path=root/'work/escape.json', policy_sha256=pin)
        with patch.object(Path, 'is_file', return_value=True), patch('dyld_rebuild.sidecars.sha', return_value=pin):
            with self.assertRaisesRegex(Refusal, 'hash differs'):
                verify_report({}, [], policy_path=policy, policy_sha256='b'*64)
            source = [dict(path='source-main', sha256=pin)]
            family = [dict(path='candidate-main', sha256=pin)]
            report = dict(schema=1, result='PASS', unexplained_differences=0, unexplained=[],
                missing_expected_differences=[], policy=dict(path=str(policy), sha256=pin),
                source_hashes={p:pin for p in REPORT_SOURCES}, source_files=source,
                family_files=family, family=dict(sha256=pin), source=dict(sha256=pin),
                all_differences=[], differences=0, explained_differences=0,
                source_inventory={}, candidate_inventory={})
            def read(path, *args, **kwargs):
                return json.dumps(dict(expected_differences={}) if path == policy else dict(files=source))
            with patch.object(Path, 'read_text', read):
                self.assertEqual(verify_report(report, family, policy_path=policy, policy_sha256=pin)['result'], 'PASS')
                report['all_differences'] = [dict(key='unexpected', before=None, after={})]
                with self.assertRaisesRegex(Refusal, 'explanation inventory'):
                    verify_report(report, family, policy_path=policy, policy_sha256=pin)
                report['policy']['path'] = str(root/'config/method-resolution-policy.json')
                with self.assertRaisesRegex(Refusal, 'policy differs'):
                    verify_report(report, family, policy_path=policy, policy_sha256=pin)

    def test_unsorted_fixed_up_methods_refuse(self):
        reader = object.__new__(MethodReader)
        reader.read = Mock(return_value=struct.pack('<II', 0xc000000f, 2))
        reader.selector_base = 0x1000
        reader.number = Mock(side_effect=[20, 10])
        with patch('dyld_rebuild.objc_transfer.CachedReader.methods', return_value={'entries': []}):
            with self.assertRaisesRegex(ValueError, 'method list'):
                reader.methods(0x2000)
        reader.methods.cache_clear()

    def test_shared_empty_method_list(self):
        reader = object.__new__(MethodReader)
        reader.read = Mock(return_value=bytes.fromhex('0300000000000000'))
        self.assertEqual(reader.methods(0x1000)['entries'], [])
        reader.methods.cache_clear()

    def test_binary_swift_mangled_name_is_lossless(self):
        raw = b'_TtC\xe8name'
        reader = object.__new__(MethodReader)
        reader.family = SimpleNamespace(locate=lambda address, size: (SimpleNamespace(data=raw+b'\0'), 0))
        self.assertEqual(reader.string(1).encode('utf-8', errors='surrogateescape'), raw)
        reader.string.cache_clear()

    def test_loaded_lists_preserve_precedence_and_skip(self):
        graph = {'child': node([('category', [method('init', '0x30')]),
                                ('child', [method('init', '0x20')])], 'base'),
                 'base': node([(None, [method('init', '0x10')])])}
        self.assertEqual(resolve(graph, 'child', 'init', {'child'})['imp'], '0x20')
        self.assertEqual(resolve(graph, 'child', 'init', {'category', 'child'})['imp'], '0x30')
        self.assertEqual(resolve(graph, 'child', 'init', set())['imp'], '0x10')

    def test_stale_owner_drops_init_despite_all_loaded_equivalence(self):
        before = {'client': node([('CopresenceCore', [method('init', '0x20')])], 'base'),
                  'base': node([(None, [method('init', '0x10')])])}
        after = dict(before, client=node([('ContextSync', [method('init', '0x20')])], 'base'))
        delta = differences(before, after)
        self.assertEqual(len(delta), 1)
        self.assertEqual(delta[0]['source_resolution']['imp'], '0x20')
        self.assertEqual(delta[0]['candidate_resolution']['imp'], '0x10')

    def test_all_selectors_and_metaclass_keys(self):
        before = {'+foo': node([(None, [method('uncommon:', '0x1')])])}
        after = {'+foo': node([(None, [method('uncommon:', '0x2')])])}
        self.assertEqual(differences(before, after)[0]['selector'], 'uncommon:')

    def test_duplicate_owner_is_first_match(self):
        result = decision_list([('x', [method('init', '0x1'), method('init', '0x2')]),
                                ('x', [method('init', '0x3')])])
        self.assertEqual([x['imp'] for x in result['init']], ['0x1'])

    def test_superclass_cycle_refuses(self):
        with self.assertRaises(Refusal):
            resolve({'a': node(superclass='b'), 'b': node(superclass='a')}, 'a', 'init', set())

    def test_superclass_change_is_not_silently_accepted(self):
        before = {'a': node(), 'b': node()}
        after = dict(before, a=node(superclass='b'))
        self.assertEqual(differences(before, after)[0]['field'], 'superclass')


if __name__ == '__main__':
    unittest.main()
