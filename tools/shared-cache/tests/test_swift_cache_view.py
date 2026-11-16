"""Target byte transport and dependency scope, without an application fixture."""
import ctypes as C
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace as NS
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild import swift_cache_view as view
from dyld_rebuild.exports import Export, Image, Refusal
from dyld_rebuild.cache_exports import CacheDependency
from dyld_rebuild.objc_transfer import DiskReader


class ScopeTests(unittest.TestCase):
    @unittest.skipUnless(sys.platform == 'darwin', 'requires the native Swift runtime')
    def test_opaque_runtime_api_matches_swift_private_metadata(self):
        fixtures = Path(__file__).resolve().parent
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            library, probe = root/'libFixture.dylib', root/'probe'
            subprocess.run(['xcrun', 'swiftc', '-emit-library', '-module-name', 'OpaqueFixture',
                            str(fixtures/'swift-opaque-runtime.swift'), '-o', str(library)], check=True, capture_output=True)
            subprocess.run(['xcrun', 'clang', str(fixtures/'swift-opaque-runtime.c'), '-o', str(probe)], check=True, capture_output=True)
            subprocess.run(['codesign', '-s', '-', str(probe)], check=True, capture_output=True)
            symbols = subprocess.check_output(['nm', '-gU', str(library)], text=True)
            descriptor = next(line.split()[-1][1:] for line in symbols.splitlines() if line.endswith('QOMQ'))
            result = json.loads(subprocess.check_output([str(probe), str(library), descriptor], text=True))
            self.assertEqual(result, dict(same_metadata=True, state=0))

    def test_only_linked_images_supply_definitions_and_cycles_terminate(self):
        images = {
            '/root': Image('/root', [CacheDependency('/alias', 0xc),
                                    CacheDependency('/missing', 0xc)], {}),
            '/native': Image('/native', [CacheDependency('/root', 0xc)],
                             {'_$sType': Export(0, 32), '_absolute': Export(2, 7),
                              '_resolver': Export(16, 40), '_tlv': Export(1, 48)}),
            '/other-platform': Image('/other-platform', [], {'_$sType': Export(0, 64)}),
        }
        class Graph:
            def __init__(self, *args): pass
            def canonical(self, path):
                path = '/native' if path == '/alias' else path
                return path if path in images else None
            def image(self, path): return path, images[path]
        family = NS(images=[('/root', 0x1000), ('/native', 0x2000), ('/other-platform', 0x3000)])
        with patch.object(view, 'FinalGraph', Graph), patch.object(view, 'FamilyReader'):
            scoped = view.CacheView(family, ['/root'])
            self.assertEqual(scoped.symbol('$sType'), 0x2020)
            self.assertEqual(scoped.symbol('absolute'), 7)
            self.assertEqual(scoped.symbol('resolver'), 0)
            self.assertEqual(scoped.symbol('tlv'), 0)
            self.assertEqual(scoped.missing_images, ['/missing'])
            self.assertEqual({p for p, _ in scoped.images}, {'/root', '/native'})
            ambiguous = view.CacheView(family, ['/root', '/other-platform'])
            self.assertEqual(ambiguous.symbol('$sType'), 0)
            self.assertEqual(ambiguous.ambiguous_symbols['$sType'], 1)


@unittest.skipUnless(os.environ.get('SWIFT_STATIC_MIRROR_TOOLCHAIN'),
                     'set SWIFT_STATIC_MIRROR_TOOLCHAIN for the native MemoryReader bridge')
class MemoryViewTests(unittest.TestCase):
    @unittest.skipUnless(os.environ.get('SWIFT_CACHE_INVENTORY_FIXTURE'),
                         'set SWIFT_CACHE_INVENTORY_FIXTURE to a cache/image JSON input')
    def test_cached_inventory_translates_remote_relative_type_strings(self):
        script = '''
import json, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from dyld_rebuild.loader_generation import LoaderFamily
from dyld_rebuild.swift_cache_view import Bridge, CacheView, Layout
fixture=json.loads(Path(sys.argv[3]).read_text())
family=LoaderFamily(Path(fixture['cache']))
view=CacheView(family,[fixture['image']])
bridge=Bridge(Path(sys.argv[2])/'build/libSwiftMemoryView.dylib',view.reader.read,
    lambda address,value:view.reader.ptr(address),view.symbol,Layout(8,1,1,0x100000000,2**64-1))
try:
    assert bridge.add(dict(family.images)[fixture['image']])
    result=bridge.inventory()
    print(json.dumps(dict(fields=len(result['fields']),
                         properties=sum(len(f['properties']) for f in result['fields']))))
finally:
    bridge.close();family.close()
'''
        result = subprocess.run([sys.executable, '-I', '-c', script,
            str(Path(__file__).resolve().parents[1]/'src'), os.environ['SWIFT_STATIC_MIRROR_TOOLCHAIN'],
            os.environ['SWIFT_CACHE_INVENTORY_FIXTURE']], capture_output=True, text=True, check=True)
        counts = json.loads(result.stdout)
        self.assertGreater(counts['fields'], 0)
        self.assertGreater(counts['properties'], 0)

    def test_upstream_reads_opaque_descriptor_through_callbacks(self):
        library = Path(os.environ['SWIFT_STATIC_MIRROR_TOOLCHAIN']) / 'build/libSwiftMemoryView.dylib'
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, binary = root/'Provider.swift', root/'libMemoryFixture.dylib'
            source.write_text('''public protocol P {}
public struct Box<T: Hashable>: P { public var value: T }
public func make<T: Hashable>(_ value: T) -> some P { Box(value: value) }
''')
            subprocess.run(['xcrun', 'swiftc', '-emit-library', '-module-name', 'MemoryFixture',
                '-target', 'x86_64-apple-macosx13.0', str(source), '-o', str(binary)],
                check=True, capture_output=True)
            reader = DiskReader(binary.read_bytes())
            names = [n for n in reader.image.exports if n.endswith('QOMQ')]
            self.assertEqual(len(names), 1)
            symbol = names[0]
            descriptor = reader.base + reader.image.exports[symbol].value
            name = symbol.removeprefix('_$s').removesuffix('MQ')+'ySu_Qo_'
            queries = []
            def find(n):
                queries.append(n)
                return descriptor if '_'+n == symbol else 0
            def pointer(address, value):
                if reader.binds.get(address, {}).get('symbol') == '_$sSHMp':
                    return 0x100000
                return reader.ptr(address)
            bridge = view.Bridge(library, reader.read, pointer, find,
                                 view.Layout(8, 1, 1, 0, 2**64-1))
            try:
                bridge.add(reader.base)
                result = bridge.resolve(name)
                self.assertEqual(result['display'], 'MemoryFixture.Box<Swift.UInt>')
                self.assertTrue(result['concrete'])
                self.assertIn(symbol[1:], queries)
                self.assertEqual(bridge.resolve('SaySiG')['mangled'], 'SaySiG')
                self.assertEqual(bridge.resolve('\x02raw\n\0bytes')['input'], '\x02raw\n\0bytes')
                self.assertFalse(bridge.errors)
                schema = bridge.opaque(descriptor)
                self.assertEqual(schema['key_arguments'], 2)
                self.assertEqual(schema['parameters'], [dict(kind=0, key=True)])
                requirement = schema['requirements'][0]
                self.assertTrue(requirement['key'])
                self.assertEqual(requirement['subject'], 'x')
                self.assertEqual(requirement['protocol'], 0x100000)
                inventory = bridge.inventory()
                fields = {f['mangled']: f for f in inventory['fields']}
                self.assertIn('13MemoryFixture3BoxV', fields)
                self.assertEqual(fields['13MemoryFixture3BoxV']['properties'][0]['name'], 'value')
                self.assertEqual(inventory['architecture'], 'x86_64')
                # A failed read returns failure to Swift, with the reason retained.
                destination = C.create_string_buffer(8)
                self.assertEqual(bridge.callbacks[0](2**64-16, 8, destination), 0)
                self.assertEqual(sum(bridge.errors.values()), 1)
            finally:
                bridge.close()


if __name__ == '__main__':
    unittest.main()
