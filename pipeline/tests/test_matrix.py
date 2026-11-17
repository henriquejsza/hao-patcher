"""patches.py matrix: plan-only cells over profiles x targets x build pairs; --check refuses a release profile that
does not plan cleanly."""
import json
from pathlib import Path
import runpy
import subprocess
import sys
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
P = runpy.run_path(str(TOP / 'pipeline' / 'patches.py'))

ANY = dict.fromkeys(P['REQUIRES'], 'any')
MODEL = 'MacBookPro9,2'
FX = {'model': MODEL, 'facts': {'gpu': ['intel-ivb'], 'firmware': 'none'},
      'oclp_hardware_profile': {'cpu': {'flags': ['AVX1.0'], 'leafs': []}}}


def proven(rev, os_build='26B131'):
    return [{'model': MODEL, 'os': os_build, 'donor': '25G342', 'revision': rev, 'evidence': 'laptop boot'}]


class Matrix(unittest.TestCase):
    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        r = self.root = Path(self.d.name)
        for sub in ('patches', 'packs', 'profiles', 'targets', 'assemblies'):
            (r / sub).mkdir()
        recipes = {
            'proven': dict(revision=1, requires=dict(ANY, os=['26B131', '26A428']), proven_on=proven(1)),
            'gpu-hsw': dict(revision=1, requires=dict(ANY, gpu=['intel-hsw'])),
            'fresh': dict(revision=1, requires=ANY),
            'stale': dict(revision=2, requires=ANY, proven_on=proven(1)),
        }
        for name, p in recipes.items():
            (r / 'patches' / name).mkdir()
            (r / 'patches' / name / 'patch.json').write_text(json.dumps(dict(p, stage='post', pack='base')))
        (r / 'packs' / 'base.json').write_text(json.dumps({'format': 1, 'phase': 'installer', 'layer': 'os',
                                                           'detect': {'any_intel': True}}))
        (r / 'order.txt').write_text(''.join(n + '\n' for n in recipes))
        (r / 'targets' / 'fx.json').write_text(json.dumps(FX))
        (r / 'oclp').mkdir()
        (r / 'oclp' / 'fx.json').write_text(json.dumps({'patchset_order': []}))
        g = P['oclp_patchsets'].__globals__
        self.addCleanup(g.__setitem__, 'OCLP_PROFILES', g['OCLP_PROFILES'])
        g['OCLP_PROFILES'] = str(r / 'oclp')
        (r / 'profiles' / 'rel.json').write_text(json.dumps({'target': 'fx', 'release': True}))
        (r / 'profiles' / 'dev.json').write_text(json.dumps({'target': 'fx'}))
        for name, a in (('rel', ('26B131', '25G342', 'rel')), ('old', ('26A428', '25G342', 'dev')),
                        ('tahoe', (None, None, 'tahoe'))):
            body = {'patch_set': a[2]}
            if a[0]:
                body.update(golden_build=a[0], donor_build=a[1])
            (r / 'assemblies' / (name + '.json')).write_text(json.dumps(body))

    def tearDown(self):
        self.d.cleanup()

    def cells(self):
        r = self.root
        packs = P['load_packs'](str(r / 'packs'), str(r / 'patches'))
        return P['matrix'](str(r / 'profiles'), str(r / 'targets'), str(r / 'assemblies'), str(r / 'patches'), packs,
                           str(r / 'order.txt'))

    def cell(self, cells, profile, os_build):
        return next(c for c in cells if c['profile'] == profile and c['os'] == os_build)

    def test_pairs_need_both_builds(self):
        self.assertEqual(sorted(P['build_pairs'](str(self.root / 'assemblies'))),
                         [('26A428', '25G342'), ('26B131', '25G342')])

    def test_cells(self):
        cells = self.cells()
        self.assertEqual(len(cells), 4)                          # 2 profiles x 1 target x 2 pairs
        c = self.cell(cells, 'rel', '26B131')
        self.assertTrue(c['own'] and c['release'])
        self.assertEqual(list(c['refused']), ['gpu-hsw'])        # a refused recipe, with unmet()'s reason
        self.assertIn('gpu intel-ivb is not one of intel-hsw', c['refused']['gpu-hsw'][0])
        self.assertEqual(c['run'], ['proven', 'fresh', 'stale'])
        self.assertEqual(c['unproven'], ['fresh', 'stale'])      # proven: proof for this model, os and revision
        self.assertEqual(c['stale'], {'stale': 'proven r1, now r2'})
        self.assertEqual(c['host'], 'unrecorded')
        old = self.cell(cells, 'rel', '26A428')
        self.assertFalse(old['own'])
        self.assertIn('proven', old['unproven'])                 # proof on 26B131 is not proof on 26A428
        self.assertEqual(old['stale'], {})
        self.assertTrue(self.cell(cells, 'dev', '26A428')['own'])
        text = P['matrix_text'](cells)
        self.assertIn('rel (release)', text)
        self.assertIn('    refused gpu-hsw: gpu intel-ivb', text)

    def test_check(self):
        bad = P['matrix_problems'](self.cells())
        self.assertEqual(len(bad), 1)
        self.assertIn('release rel on fx 26B131/25G342: gpu-hsw refused', bad[0])
        f = self.root / 'patches' / 'gpu-hsw' / 'patch.json'
        f.write_text(json.dumps(dict(json.loads(f.read_text()), requires=ANY)))
        self.assertEqual(P['matrix_problems'](self.cells()), [])
        (self.root / 'assemblies' / 'rel.json').unlink()         # a release profile no assembly builds
        self.assertIn('no assembly', P['matrix_problems'](self.cells())[0])

    def test_dev_profile_refusal_is_not_a_problem(self):
        (self.root / 'profiles' / 'rel.json').unlink()
        self.assertEqual(P['matrix_problems'](self.cells()), [])


class RealTree(unittest.TestCase):
    def test_matrix_check_runs(self):
        p = subprocess.run([sys.executable, '-I', str(TOP / 'pipeline' / 'patches.py'), 'matrix', '--check'],
                           capture_output=True, text=True)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn('host unrecorded', p.stdout)


if __name__ == '__main__':
    unittest.main()
