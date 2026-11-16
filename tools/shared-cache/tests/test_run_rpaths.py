"""Literal malformed Apple LC_RPATH values remain dormant until actually searched."""
import json
from pathlib import Path
import struct
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from dyld_rebuild import run_rpaths as m
from dyld_rebuild.exports import Refusal
from dyld_rebuild import run_loaders as loaders

QUOTED = '" @executable_path/Frameworks @executable_path/../../Frameworks" @executable_path/../Frameworks @executable_path/../../../../Frameworks'
ACTUAL_MAIN = '/System/Library/ExtensionKit/Extensions/BiomeSELFIngestor.appex/Contents/MacOS/BiomeSELFIngestor'


def macho(dependencies=(), rpaths=()):
    commands = []
    for path in dependencies:
        raw = path.encode() + b'\0'
        width = (24 + len(raw) + 7) & ~7
        commands.append(struct.pack('<6I', 0xc, width, 24, 0, 0, 0) + raw + b'\0' * (width - 24 - len(raw)))
    for path in rpaths:
        raw = path.encode() + b'\0'
        width = (12 + len(raw) + 7) & ~7
        commands.append(struct.pack('<3I', 0x8000001c, width, 12) + raw + b'\0' * (width - 12 - len(raw)))
    body = b''.join(commands)
    return struct.pack('<8I', 0xfeedfacf, 0x1000007, 3, 2, len(commands), len(body), 0, 0) + body


class RPathTests(unittest.TestCase):
    def test_unused_quoted_rpath_does_not_affect_absolute_dependencies(self):
        dependencies, rpaths = loaders.dependencies(macho(['/usr/lib/libSystem.B.dylib'], [QUOTED]))
        self.assertEqual(rpaths, [QUOTED])
        stack = m.rpath_stack(rpaths, ACTUAL_MAIN, ())
        self.assertEqual(list(m.dependency_candidates(dependencies[0][0], ACTUAL_MAIN, ACTUAL_MAIN, stack)),
                         ['/usr/lib/libSystem.B.dylib'])

    def test_used_literal_quoted_rpath_refuses_instead_of_tokenizing(self):
        stack = m.rpath_stack([QUOTED], ACTUAL_MAIN, ())
        with self.assertRaisesRegex(Refusal, 'unsupported reached current LC_RPATH'):
            list(m.dependency_candidates('@rpath/Required.dylib', ACTUAL_MAIN, ACTUAL_MAIN, stack))

    def test_first_resolved_path_before_unsupported_does_not_search_it(self):
        stack = m.rpath_stack(['/safe', QUOTED], ACTUAL_MAIN, ())
        candidates = m.dependency_candidates('@rpath/A.dylib', ACTUAL_MAIN, ACTUAL_MAIN, stack)
        self.assertEqual(next(candidates), '/safe/A.dylib')
        with self.assertRaisesRegex(Refusal, 'unsupported reached'):
            next(candidates)

    def test_inherited_loader_path_keeps_parent_image_context(self):
        parent = m.rpath_stack(['@loader_path/../Frameworks'], '/Parent/MacOS/main', ())
        child = m.rpath_stack(['@loader_path/Local'], '/Libraries/Child.dylib', parent)
        self.assertEqual(list(m.dependency_candidates('@rpath/A.dylib', '/Libraries/Child.dylib', '/Executable/main', child)),
                         ['/Libraries/Local/A.dylib', '/Parent/Frameworks/A.dylib'])

    def test_inherited_executable_path_uses_main_executable(self):
        stack = m.rpath_stack(['@executable_path/Frameworks'], '/Libraries/Child.dylib', ())
        self.assertEqual(list(m.dependency_candidates('@rpath/A.dylib', '/Libraries/Grandchild.dylib', '/Executable/main', stack)),
                         ['/Executable/Frameworks/A.dylib'])

    def test_absolute_space_and_quote_characters_are_preserved(self):
        stack = m.rpath_stack(['/Frameworks/Space "name"'], ACTUAL_MAIN, ())
        self.assertEqual(list(m.dependency_candidates('@rpath/A.dylib', ACTUAL_MAIN, ACTUAL_MAIN, stack)),
                         ['/Frameworks/Space "name"/A.dylib'])

    def test_relative_and_unknown_tokens_still_refuse_if_reached(self):
        for path in ('relative', '@unknown/Frameworks', '@rpath/Nested', QUOTED):
            with self.subTest(path=path), self.assertRaises(Refusal):
                list(m.dependency_candidates('@rpath/A.dylib', ACTUAL_MAIN, ACTUAL_MAIN,
                                            m.rpath_stack([path], ACTUAL_MAIN, ())))

    def test_empty_stack_remains_unresolved(self):
        with self.assertRaisesRegex(Refusal, 'unsupported/unresolved'):
            list(m.dependency_candidates('@rpath/A.dylib', ACTUAL_MAIN, ACTUAL_MAIN, ()))

    def test_duplicate_entries_do_not_grow_recursive_stack(self):
        stack = m.rpath_stack(['/safe', QUOTED], ACTUAL_MAIN, ())
        self.assertEqual(m.rpath_stack(['/safe', QUOTED], ACTUAL_MAIN, stack), stack)


class ClosureIntegrationTests(unittest.TestCase):
    def closure(self, dependency, rpaths, cached, disk=None):
        with tempfile.TemporaryDirectory(prefix='rpath-current-closure-') as name:
            base = Path(name).resolve()
            root = base / 'system'
            table = root / 'usr/share/firmlinks'
            table.parent.mkdir(parents=True)
            table.write_text('')
            inputs = {ACTUAL_MAIN: macho([dependency], rpaths)}
            inputs.update(disk or {})
            for virtual, contents in inputs.items():
                path = root / virtual.lstrip('/')
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(contents)
            views = loaders.FilesystemViews(system=root, os_root=root, app=root, data=root)
            family = SimpleNamespace(close=lambda: None)
            graph = SimpleNamespace(canonical=lambda path: path if path in cached else None)
            with patch.object(loaders, 'open_family', return_value=(family, [])), \
                 patch.object(loaders, 'original_inventory', return_value=({ACTUAL_MAIN: {}}, {})), \
                 patch.object(loaders, 'FinalGraph', return_value=graph):
                output = base / 'output'
                result = loaders.collect_program_inputs(base / 'source', base / 'candidate', views, output)
                # Return serialized closure evidence before TemporaryDirectory cleanup.
                return json.loads((output / 'closure-report.json').read_text())

    def test_actual_quoted_unused_program_retained_with_complete_absolute_edge(self):
        proof = self.closure('/usr/lib/libSystem.B.dylib', [QUOTED], {'/usr/lib/libSystem.B.dylib'})
        self.assertEqual(proof['program_count'], 1)
        self.assertEqual(proof['edges'][0]['selected'], '/usr/lib/libSystem.B.dylib')

    def test_used_quoted_value_refuses_full_closure(self):
        with self.assertRaisesRegex(Refusal, 'unsupported reached'):
            self.closure('@rpath/A.dylib', [QUOTED], set())

    def test_success_before_unused_quoted_value_is_preserved(self):
        proof = self.closure('@rpath/A.dylib', ['/safe', QUOTED], {'/safe/A.dylib'})
        self.assertEqual(proof['edges'][0]['selected'], '/safe/A.dylib')

    def test_unresolved_strong_dependency_still_refuses(self):
        with self.assertRaisesRegex(Refusal, 'required current dependency missing'):
            self.closure('@rpath/Missing.dylib', ['/safe'], set())

    def test_child_inherited_rpath_does_not_use_child_location(self):
        parent_directory = str(Path(ACTUAL_MAIN).parent)
        expected = parent_directory + '/Frameworks/A.dylib'
        proof = self.closure('/Libraries/Child.dylib', ['@loader_path/Frameworks'], {expected},
                             {'/Libraries/Child.dylib': macho(['@rpath/A.dylib'])})
        self.assertEqual(len(proof['edges']), 2)
        self.assertEqual(proof['edges'][1]['selected'], expected)


if __name__ == '__main__':
    unittest.main()
