"""golden-gate-shared-cache on a stand-in artifact (fixture files in the generator's artifact format): the root review,
the provider bytes, the input-cache match, the cache swap, retirement and the no-overrides gate. The APFS image steps
run only in the builder VM. With the Tahoe artifact in the store, its build.json is read as a format check.
python3.14 -I -B -m unittest discover -s patches/golden-gate-shared-cache/tests"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PATCH = Path(__file__).resolve().parents[1]
TOP = PATCH.parents[1]
sys.path.insert(0, str(PATCH/'src'))
import fold  # noqa: E402

REQUIRED, COMPANIONS = fold.reviewed()
SYSTEM_AT = '/work/cache-system'
TAHOE = TOP/'store/artifacts/rebuilt-cache-photos-weather-25G332-20261102-d0adc4df8216'


def sha(data):
    return hashlib.sha256(data).hexdigest()


class StandIn(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        top = Path(self.tmp.name)
        self.system, self.artifact, self.built = top/'System', top/'artifact', top/'built-dyld'
        self.roots = sorted(REQUIRED) + sorted(COMPANIONS)[:3]
        for root in self.roots:
            path = self.system/root
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b'provider ' + root.encode())
        self.built.mkdir()
        self.inputs = {}
        for name in ('dyld_shared_cache_x86_64', 'dyld_shared_cache_x86_64.01', 'dyld_shared_cache_x86_64.map'):
            (self.built/name).write_bytes(b'installed ' + name.encode() * 50)
            self.inputs[name] = sha((self.built/name).read_bytes())
        self.make_artifact()

    def tearDown(self):
        self.tmp.cleanup()

    def make_artifact(self, roots=None, providers=None):
        a = self.artifact
        shutil.rmtree(a, ignore_errors=True)
        a.mkdir()
        roots = self.roots if roots is None else roots
        for name in ('dyld_shared_cache_x86_64', 'dyld_shared_cache_x86_64.01', 'dyld_shared_cache_x86_64.02',
                     'dyld_shared_cache_x86_64.atlas'):
            (a/name).write_bytes(b'folded ' + name.encode())
        (a/'retired-roots.txt').write_text(''.join(r + '\n' for r in roots))
        provenance = [dict(provider=Path(r).name, source='/oclp/' + r, path=f'{SYSTEM_AT}/{r}',
                           sha256=sha((self.system/r).read_bytes()) if (self.system/r).exists() else '0' * 64)
                      for r in roots] if providers is None else providers
        (a/'provider-provenance.json').write_text(json.dumps(provenance))
        inputs = [dict(path=f'/Volumes/OS/System/Library/dyld/{n}', sha256=h, size=1) for n, h in self.inputs.items()]
        inputs += [dict(path='/Volumes/OS/System/DriverKit/System/Library/dyld/dyld_shared_cache_x86_64',
                        sha256='f' * 64, size=1), dict(path='/toolchain/relocate', sha256='e' * 64, size=1)]
        (a/'build.json').write_text(json.dumps(dict(system=SYSTEM_AT, inputs=inputs, revision=82, git_commit='abc',
                                                    git_dirty=False)))
        return fold.load_artifact(a)

    # 1. roots
    def test_the_reviewed_roots_pass(self):
        art = fold.load_artifact(self.artifact)
        fold.check_roots(art['roots'], REQUIRED, COMPANIONS)
        self.assertEqual(set(art['providers']), set(self.roots))
        self.assertEqual(sorted(art['inputs']), sorted(self.inputs))      # DriverKit's cache and tools left out

    def test_an_unreviewed_or_missing_root_stops(self):
        with self.assertRaisesRegex(SystemExit, r'not reviewed: \[.usr/lib/libnew.dylib.\]'):
            fold.check_roots(self.roots + ['usr/lib/libnew.dylib'], REQUIRED, COMPANIONS)
        dropped = sorted(REQUIRED)[0]
        with self.assertRaisesRegex(SystemExit, 'required but not folded in: .*' + dropped.split('/')[-1]):
            fold.check_roots([r for r in self.roots if r != dropped], REQUIRED, COMPANIONS)
        with self.assertRaisesRegex(SystemExit, 'twice'):
            fold.check_roots(self.roots + self.roots[:1], REQUIRED, COMPANIONS)

    def test_the_required_roots_are_the_images_the_userspace_edits_count_as_overridden(self):
        data = json.loads((TOP/'patches/golden-gate-userspace/src/prespecialization-26B131.json').read_text())
        self.assertEqual(REQUIRED, {p.lstrip('/') for p in data['overridden']})
        self.assertFalse(REQUIRED & COMPANIONS)

    def test_every_library_hello_and_live_text_install_is_a_reviewed_root(self):
        # golden-gate-hello weak-loads libhelloblur from the Metal wrapper; live-text-shared hangs LiveText's dylibs off it
        for name in ('golden-gate-hello', 'golden-gate-live-text-shared'):
            pj = json.loads((TOP/'patches'/name/'patch.json').read_text())
            libs = {f['path'] for f in pj['files'] if f['path'].endswith('.dylib') or f['path'].endswith('/Metal')}
            self.assertTrue(libs)
            self.assertLessEqual(libs, REQUIRED | COMPANIONS, name)
        self.assertFalse({r for r in REQUIRED | COMPANIONS if 'MTLCompiler' in r or 'libMTLIntelCompilerPlugin' in r})

    # 2. provider bytes
    def test_a_new_hello_or_live_text_revision_is_refused_until_the_artifact_is_rebuilt(self):
        art = fold.load_artifact(self.artifact)
        wrapper = 'System/Library/Frameworks/Metal.framework/Versions/A/Metal'   # golden-gate-hello edits it
        (self.system/wrapper).write_bytes(b'hello r9: another un-skip')
        with self.assertRaisesRegex(SystemExit, 'Metal: [0-9a-f]{12} on this System, the cache holds'):
            fold.check_providers(self.system, art['roots'], art['providers'])

    def test_provider_bytes_must_be_the_folded_ones(self):
        art = fold.load_artifact(self.artifact)
        self.assertEqual(fold.check_providers(self.system, art['roots'], art['providers']), art['providers'])
        changed = self.system/self.roots[0]
        changed.write_bytes(b'rebuilt since')
        os.unlink(self.system/self.roots[1])
        with self.assertRaisesRegex(SystemExit, r'2 provider\(s\) differ.*on this System, the cache holds.*not a file'):
            fold.check_providers(self.system, art['roots'], art['providers'])

    def test_a_provider_outside_the_artifact_system_stops(self):
        bad = [dict(provider='x', path='/elsewhere/' + self.roots[0], sha256='0' * 64)]
        with self.assertRaisesRegex(SystemExit, 'not under the artifact system'):
            self.make_artifact(providers=bad)

    # 3. input cache
    def test_the_artifact_must_come_from_this_cache(self):
        art = fold.load_artifact(self.artifact)
        self.assertEqual(fold.match_input(self.built, art['inputs'], self.tmp.name, None, edits={}), 'as-built')
        (self.built/'dyld_shared_cache_x86_64.01').write_bytes(b'other repairs')
        with self.assertRaisesRegex(SystemExit, r"another cache \(differs: \['dyld_shared_cache_x86_64.01'\]"):
            fold.match_input(self.built, art['inputs'], self.tmp.name, None, edits={})
        (self.built/'dyld_shared_cache_x86_64.map').unlink()
        with self.assertRaisesRegex(SystemExit, 'made from cache files'):
            fold.match_input(self.built, art['inputs'], self.tmp.name, None, edits={})

    def test_an_artifact_from_the_image_before_the_prespecialization_edits_matches(self):
        main = self.built/'dyld_shared_cache_x86_64'
        data = bytearray(main.read_bytes())
        before = bytes(data[10:13])
        data[10:13] = b'\x31\xc0\x90'                          # the edit, as golden-gate-userspace applied it
        main.write_bytes(bytes(data))
        edits = {main.name: [(10, before, b'\x31\xc0\x90', 'switch')]}
        signed = []
        art = fold.load_artifact(self.artifact)
        self.assertEqual(fold.match_input(self.built, art['inputs'], self.tmp.name,
                                          lambda p, force: signed.append(force), edits=edits),
                         'without-prespecialization')
        self.assertEqual(signed, [True])
        self.assertEqual(sorted(p.name for p in Path(self.tmp.name).iterdir()),
                         ['System', 'artifact', 'built-dyld'])  # the scratch copy is gone
        data[20] ^= 1                                          # and anything else still stops
        main.write_bytes(bytes(data))
        with self.assertRaisesRegex(SystemExit, 'another cache'):
            fold.match_input(self.built, art['inputs'], self.tmp.name, lambda p, force: None, edits=edits)

    def test_the_userspace_prespecialization_data_reads_as_edits(self):
        names = ('dyld_shared_cache_x86_64', 'dyld_shared_cache_x86_64.06')
        for n in names:
            (self.built/n).write_bytes(b'')
        edits = fold.prespecialization_edits(self.built)
        self.assertEqual(sorted(edits), list(names))
        self.assertEqual(sum(len(e) for e in edits.values()), 115)     # 2 switch reads + 113 descriptor slots
        for offset, before, after, _ in edits['dyld_shared_cache_x86_64']:
            self.assertEqual(len(before), len(after))

    # 4. cache swap
    def test_the_x86_64_family_is_replaced_whole(self):
        dyld = self.tmp.name + '/dyld'
        os.mkdir(dyld)
        for n in ('dyld_shared_cache_x86_64', 'dyld_shared_cache_x86_64.01', 'dyld_shared_cache_x86_64.03',
                  'dyld_shared_cache_x86_64.map', 'dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64e.01'):
            Path(dyld, n).write_bytes(b'apple')
        os.chmod(Path(dyld, 'dyld_shared_cache_x86_64'), 0o755)
        art = fold.load_artifact(self.artifact)
        removed, installed = fold.replace_cache(dyld, self.artifact, art['files'])
        self.assertEqual(removed, ['dyld_shared_cache_x86_64', 'dyld_shared_cache_x86_64.01',
                                   'dyld_shared_cache_x86_64.03', 'dyld_shared_cache_x86_64.map'])
        self.assertEqual(sorted(os.listdir(dyld)), sorted(['dyld_shared_cache_arm64e', 'dyld_shared_cache_arm64e.01']
                                                          + art['files']))
        for n in art['files']:
            self.assertEqual(Path(dyld, n).read_bytes(), (self.artifact/n).read_bytes())
            self.assertEqual(os.stat(Path(dyld, n)).st_mode & 0o7777, 0o755)
        self.assertEqual(Path(dyld, 'dyld_shared_cache_arm64e').read_bytes(), b'apple')

    # 5. retirement and gate
    def test_after_retirement_no_cache_image_is_on_disk(self):
        images = ['/' + r for r in self.roots if r in REQUIRED] + ['/usr/lib/dyld', '/usr/lib/libz.1.dylib']
        (self.system/'usr/lib/dyld').write_bytes(b'dyld')
        with self.assertRaisesRegex(SystemExit, r'10 cache image\(s\) still on disk'):
            fold.gate(self.system, images)
        fold.retire(self.system, self.roots)
        self.assertEqual(fold.gate(self.system, images), 0)
        for r in self.roots:
            self.assertFalse((self.system/r).exists())
        self.assertTrue((self.system/'usr/lib/dyld').exists())       # dyld is never loaded from the cache

    def test_check_command_is_read_only(self):
        out = subprocess.run([sys.executable, '-I', str(PATCH/'src/fold.py'), 'check', str(self.system),
                              str(self.artifact)], check=True, capture_output=True, text=True)
        self.assertEqual(set(json.loads(out.stdout)), set(self.roots))
        self.assertTrue(all((self.system/r).exists() for r in self.roots))


class Format(unittest.TestCase):
    @unittest.skipUnless(TAHOE.is_dir(), 'Tahoe artifact not in the store')
    def test_the_generator_artifact_format_reads(self):
        art = fold.load_artifact(TAHOE)
        self.assertEqual(len(art['roots']), 19)
        self.assertEqual(set(art['roots']), set(art['providers']))
        self.assertIn('dyld_shared_cache_x86_64.map', art['inputs'])
        self.assertEqual(len(art['files']), 29)


class Recipe(unittest.TestCase):
    def test_hook_and_staging(self):
        hook = (PATCH/'src/kc-hook.sh').read_text()
        self.assertIn('fold.py" install "$S" "$H/inputs/rebuilt_cache"', hook)
        pj = json.loads((PATCH/'patch.json').read_text())
        self.assertEqual(pj['inputs'], ['rebuilt_cache'])
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(['sh', str(PATCH/'make.sh'), d + '/build'], check=True)
            for module in ('cryptex.py', 'cache_pages.py', 'install.py', 'prespecialization.py', 'swift_refs.py',
                           'prespecialization-26B131.json'):
                self.assertTrue(Path(d, 'build/userspace', module).is_file(), module)

    def test_only_in_the_b_set_before_native_identities(self):
        sets = {p.name: [l.split()[0] for l in p.read_text().splitlines() if l.strip() and not l.startswith('#')]
                for p in (TOP/'pipeline/sets').glob('*.txt')}
        self.assertEqual([n for n, s in sets.items() if 'golden-gate-shared-cache' in s], ['dev-bs-test-fold.txt'])
        b = sets['dev-bs-test-fold.txt']
        self.assertEqual(b.index('golden-gate-shared-cache') + 1, b.index('golden-gate-native-identities'))
        self.assertEqual([n for n in b if n != 'golden-gate-shared-cache'], sets['dev-bs-test.txt'])


if __name__ == '__main__':
    unittest.main()
