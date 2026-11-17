"""The generic image: target generic (no board id, no GPU, no OCLP patch sets) and its profile, generated and planned.

Until packs/generic.json and pipeline/profiles/generic.json land (the model pack is another change), the profile is
pipeline/tests/fixtures/generic/profile.json and the pack a stand-in with one stand-in recipe; once both are in the
tree the same tests run on the real ones.
python3.14 -I -B -m unittest discover -s pipeline/tests -k generic"""
import contextlib
import io
import json
import os
from pathlib import Path
import runpy
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
FIX = Path(__file__).resolve().parent / 'fixtures' / 'generic'
P = runpy.run_path(str(TOP / 'pipeline' / 'patches.py'))
TARGET = TOP / 'pipeline' / 'targets' / 'generic.json'
REAL_PROFILE = TOP / 'pipeline' / 'profiles' / 'generic.json'
REAL_PACK = TOP / 'packs' / 'generic.json'
PLATFORM_KINDS = ('gpu', 'wifi', 'audio')


class Tree:
    """The real profile, packs and recipes when the generic pack is in the tree; else a temporary tree: every real
    recipe linked, plus the stand-in pack generic with one stand-in recipe at the end of order.txt."""

    def __enter__(self):
        if REAL_PROFILE.is_file() and REAL_PACK.is_file():
            self.real = True
            self.profile, self.root, self.order = REAL_PROFILE, str(TOP / 'patches'), P['ORDER']
            self.packs = P['load_packs']()
            return self
        self.real = False
        self.tmp = tempfile.TemporaryDirectory()
        d = Path(self.tmp.name)
        root, packs_dir = d / 'patches', d / 'packs'
        root.mkdir()
        packs_dir.mkdir()
        for name in P['patch_names'](str(TOP / 'patches')):
            os.symlink(TOP / 'patches' / name, root / name)
        (root / 'generic-standin').mkdir()
        (root / 'generic-standin' / 'patch.json').write_text(json.dumps(
            {'revision': 1, 'stage': 'oclp-hook', 'applies': 'any', 'inputs': [], 'pack': 'generic',
             'status': 'product', 'validated': False}))
        for f in (TOP / 'packs').glob('*.json'):
            os.symlink(f, packs_dir / f.name)
        os.symlink(FIX / 'pack.json', packs_dir / 'generic.json')
        self.order = str(d / 'order.txt')
        Path(self.order).write_text((TOP / 'pipeline' / 'order.txt').read_text() + '\ngeneric-standin\n')
        self.profile, self.root = FIX / 'profile.json', str(root)
        self.packs = P['load_packs'](str(packs_dir), str(root))
        return self

    def __exit__(self, *exc):
        if not self.real:
            self.tmp.cleanup()

    def generate(self):
        return P['generate'](str(self.profile), self.root, self.packs, self.order)


class GenericTarget(unittest.TestCase):
    def test_no_board_id_no_gpu_no_patch_sets(self):
        t = json.loads(TARGET.read_text())
        self.assertNotIn('board_id', t)
        self.assertTrue(t['generic'])
        self.assertEqual((t['facts']['gpu'], t['facts']['firmware']), ([], 'none'))
        for flag in ('SSE4.2', 'POPCNT', 'AVX1.0'):
            self.assertIn(flag, t['facts']['cpu']['flags'])
        self.assertNotIn('AVX2', t['facts']['cpu']['flags'])
        self.assertEqual(P['oclp_patchsets'](TARGET), set())       # an explicit empty list, not a missing profile

    def test_detects_only_the_os_layer(self):
        packs = P['load_packs']()
        found = P['detect_packs'](TARGET, packs)
        self.assertEqual(found, ['base'])
        self.assertEqual([n for n in found if packs[n].get('layer') != 'os'], [])


class GenericProfile(unittest.TestCase):
    def test_generates_the_os_layer_and_the_model_pack_only(self):
        with Tree() as t:
            got = t.generate()
            owner = {r: n for n, p in t.packs.items() for r in p.get('recipes', [])}
            self.assertTrue(set(t.packs['generic']['recipes']) <= set(got))
            self.assertTrue(t.packs['generic'].get('opt_in'), 'the generic pack is selected by name only')
            for name in got:
                pack = t.packs[owner[name]]
                self.assertFalse(pack.get('layer') == 'platform' and pack.get('kind') in PLATFORM_KINDS, name)
                self.assertFalse(pack.get('kind') == 'model' and owner[name] != 'generic', name)
            # the OS layer exactly as the 9,2 alpha image has it
            alpha = P['generate'](str(TOP / 'pipeline' / 'profiles' / 'alpha-v0.1.0.json'))
            os_layer = [n for n in alpha if t.packs[owner[n]].get('layer') == 'os']
            self.assertEqual([n for n in got if owner[n] != 'generic'], os_layer)

    def test_plans_for_the_donor_build(self):
        with Tree() as t, tempfile.TemporaryDirectory() as d:
            setfile = Path(d) / 'generic.txt'
            setfile.write_text(''.join(n + '\n' for n in t.generate()))
            for build in ('25G342',):
                with contextlib.redirect_stderr(io.StringIO()):
                    rows = P['plan'](str(setfile), str(TARGET), build, root=t.root, locks=None,
                                     packs=P['detect_packs'](TARGET, t.packs), pack_defs=t.packs)
                names = [n for _, n, _ in rows]
                self.assertIn('darwin27-kernel', names)
                self.assertTrue(set(t.packs['generic']['recipes']) <= set(names))   # opt-in: named by the set

    def test_the_profile_without_its_pack_fails_clearly(self):
        if REAL_PACK.is_file():
            self.skipTest('packs/generic.json is in the tree')
        with self.assertRaises(ValueError) as e:
            P['generate'](str(FIX / 'profile.json'))
        self.assertIn('unknown packs: generic', str(e.exception))

    def test_the_9_2_profiles_do_not_change(self):
        for prof in sorted((TOP / 'pipeline' / 'profiles').glob('*.json')):
            if json.loads(prof.read_text())['target'] != 'mbp92':
                continue
            self.assertEqual(P['generate'](str(prof)), P['names'](str(TOP / 'pipeline' / 'sets' / (prof.stem + '.txt'))),
                             prof.stem)


if __name__ == '__main__':
    unittest.main()
