"""on-mac: the made-on-Mac files are checked against the row's own records, and nothing is written on a mismatch.

The full remake runs when these are set (Apple and OCLP inputs, Xcode's Metal toolchain):
  LIVE_TEXT_ON_MAC_BUILD   a tools/live-text build folder (framework/ and compiler-service/)
  LIVE_TEXT_ON_MAC_SYSTEM  the System root it was built from
  LIVE_TEXT_ON_MAC_OCLP    the oclp_hardware row folder
"""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

UNIT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('on_mac', str(UNIT/'on-mac'))
spec = importlib.util.spec_from_loader('on_mac', loader)
on_mac = importlib.util.module_from_spec(spec)
loader.exec_module(on_mac)


class Refuses(unittest.TestCase):
    def setUp(self):
        self.work = Path(tempfile.mkdtemp(prefix='on-mac-'))
        self.addCleanup(shutil.rmtree, self.work)

    def test_expect(self):
        made = self.work/'f'
        made.write_bytes(b'x')
        on_mac.expect({'f': on_mac.sha(made)}, 'f', made)
        with self.assertRaises(on_mac.Mismatch):
            on_mac.expect({'f': '0' * 64}, 'f', made)
        with self.assertRaises(on_mac.Mismatch):
            on_mac.expect({}, 'f', made)

    def test_runtime_refuses_another_system(self):
        row, system = self.work/'row', self.work/'system'
        (row/'runtime').mkdir(parents=True)
        (row/'runtime/build.json').write_text(json.dumps({
            'files': {'MPSNDArray.metallib': '1' * 64},
            'inputs': {'MPSNDArray.metallib': {'source_sha256': '2' * 64}}}))
        source = system/on_mac.runtime_tool.SOURCE_METALLIB
        source.parent.mkdir(parents=True)
        source.write_bytes(b'not the library')
        with self.assertRaises(on_mac.Mismatch):
            on_mac.runtime(row, system)
        self.assertEqual(sorted(p.name for p in (row/'runtime').iterdir()), ['build.json'])

    def test_compiler_service_refuses_another_service(self):
        row, oclp = self.work/'row', self.work/'oclp'
        row.mkdir()
        (row/'build.json').write_text(json.dumps({'inputs': {'service/MTLCompilerService': '3' * 64},
                                                 'files': {}}))
        contents = oclp/'payload/13.2.1-25'/on_mac.SERVICE_CONTENTS
        for path in ('MacOS/MTLCompilerService', 'Info.plist', '_CodeSignature/CodeResources'):
            (contents/path).parent.mkdir(parents=True, exist_ok=True)
            (contents/path).write_bytes(b'other')
        with self.assertRaises(on_mac.Mismatch):
            on_mac.compiler_service(row, oclp)
        self.assertEqual([p.name for p in row.iterdir()], ['build.json'])


ENV = ('LIVE_TEXT_ON_MAC_BUILD', 'LIVE_TEXT_ON_MAC_SYSTEM', 'LIVE_TEXT_ON_MAC_OCLP')


@unittest.skipUnless(all(os.environ.get(k) for k in ENV), 'needs ' + ', '.join(ENV))
class Remake(unittest.TestCase):
    def setUp(self):
        self.build, self.system, self.oclp = (Path(os.environ[k]) for k in ENV)
        self.work = Path(tempfile.mkdtemp(prefix='on-mac-'))
        self.addCleanup(shutil.rmtree, self.work)

    def test_compiler_service_same_bytes(self):
        row = self.work/'cs'
        shutil.copytree(self.build/'compiler-service', row)
        (row/'replace'/on_mac.cs.SERVICE).unlink()
        self.assertEqual(on_mac.compiler_service(row, self.oclp), ['replace/' + on_mac.cs.SERVICE])
        self.assertEqual(on_mac.tree(row), on_mac.tree(self.build/'compiler-service'))
        self.assertEqual(on_mac.compiler_service(row, self.oclp), [])

    def test_runtime_same_bytes(self):
        row = self.work/'fw'
        shutil.copytree(self.build/'framework', row)
        (row/'runtime/MPSNDArray.metallib').unlink()
        shutil.rmtree(row/'runtime/detector')
        self.assertEqual(sorted(on_mac.runtime(row, self.system)), ['runtime/MPSNDArray.metallib', 'runtime/detector'])
        self.assertEqual(on_mac.tree(row), on_mac.tree(self.build/'framework'))


if __name__ == '__main__':
    unittest.main()
