"""docs/requires.md: requires and proven_on are checked, and plan stops on an unmet requirement."""
import json
from pathlib import Path
import runpy
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
P = runpy.run_path(str(TOP / 'pipeline' / 'patches.py'))

GOOD = {'os': ['26B131'], 'donor': ['25G342'], 'cpu': ['avx1.0', '!avx2'], 'gpu': ['intel-ivb'], 'firmware': ['none']}
MBP92 = {'model': 'MacBookPro9,2', 'facts': {'gpu': ['intel-ivb'], 'firmware': 'none'},
         'oclp_hardware_profile': {'cpu': {'flags': ['SSE4.2', 'AVX1.0'], 'leafs': []}}}


class Format(unittest.TestCase):
    def test_good_and_any(self):
        self.assertEqual(P['requires_problems'](GOOD), [])
        self.assertEqual(P['requires_problems'](dict.fromkeys(P['REQUIRES'], 'any')), [])

    def test_bad(self):
        self.assertTrue(P['requires_problems'](dict(GOOD, os=[])))
        self.assertTrue(P['requires_problems']({k: v for k, v in GOOD.items() if k != 'cpu'}))
        self.assertIn('intel-ivb', P['requires_problems'](dict(GOOD, gpu=['hd4000']))[0])
        self.assertTrue(P['requires_problems'](dict(GOOD, os=['27.2.1'])))
        self.assertTrue(P['requires_problems'](dict(GOOD, firmware=['T2'])))

    def test_proven_on(self):
        ok = {'model': 'MacBookPro9,2', 'os': '26B131', 'donor': '25G342', 'revision': 3, 'evidence': 'bench X'}
        self.assertEqual(P['proven_problems']([ok], 3), [])
        self.assertTrue(P['proven_problems']([dict(ok, revision=4)], 3))
        self.assertTrue(P['proven_problems']([dict(ok, evidence='')], 3))
        self.assertTrue(P['proven_problems']([dict(ok, works=True)], 3))


class Unmet(unittest.TestCase):
    def facts(self, **t):
        return P['target_facts'](dict(MBP92, **t))

    def test_met(self):
        self.assertEqual(P['unmet'](GOOD, self.facts(), '26B131', '25G342'), [])

    def test_each_key(self):
        f = self.facts()
        self.assertEqual(len(P['unmet'](GOOD, f, '26A428', '25G342')), 1)
        self.assertEqual(len(P['unmet'](GOOD, f, None, '25G342')), 1)          # os not given: not met
        self.assertEqual(len(P['unmet'](GOOD, f, '26B131', '25G332')), 1)
        self.assertIn('gpu', P['unmet'](GOOD, self.facts(facts={'gpu': ['intel-hsw'], 'firmware': 'none'}),
                                        '26B131', '25G342')[0])
        self.assertIn('firmware', P['unmet'](GOOD, self.facts(facts={'gpu': ['intel-ivb'], 'firmware': 't2'}),
                                             '26B131', '25G342')[0])
        avx2 = self.facts(oclp_hardware_profile={'cpu': {'flags': ['AVX1.0'], 'leafs': ['AVX2']}})
        self.assertEqual(P['unmet'](GOOD, avx2, '26B131', '25G342'), ['cpu avx2 is present'])
        self.assertEqual(P['unmet'](GOOD, self.facts(oclp_hardware_profile={}), '26B131', '25G342'),
                         ['cpu avx1.0 is missing'])

    def test_unknown_facts_never_meet(self):
        self.assertEqual(len(P['unmet'](GOOD, P['target_facts']({'model': 'X'}), '26B131', '25G342')), 3)


class Tree(unittest.TestCase):
    """A two-recipe tree: plan stops on an unmet requirement; check keeps the pending list honest."""

    def setUp(self):
        self.d = tempfile.TemporaryDirectory()
        r = self.root = Path(self.d.name)
        for name in ('a', 'b'):
            (r / 'patches' / name).mkdir(parents=True)
            (r / 'patches' / name / 'patch.json').write_text(json.dumps({'revision': 1, 'stage': 'post', 'applies': 'any'}))
        (r / 'set.txt').write_text('a\nb\n')
        (r / 'order.txt').write_text('a  # 26B131 only\nb\n')
        (r / 'pending.txt').write_text('b\n')
        (r / 'target.json').write_text(json.dumps(MBP92))

    def tearDown(self):
        self.d.cleanup()

    def give(self, name, **p):
        f = self.root / 'patches' / name / 'patch.json'
        old = {k: v for k, v in json.loads(f.read_text()).items() if k != 'applies'}   # requires replaces applies
        f.write_text(json.dumps(dict(old, **p)))

    def plan(self, build):
        return [n for _, n, _ in P['plan'](str(self.root / 'set.txt'), str(self.root / 'target.json'), build,
                                           root=str(self.root / 'patches'))]

    def tree(self):
        return P['requires_tree_problems'](str(self.root / 'patches'), str(self.root / 'pending.txt'),
                                           str(self.root / 'order.txt'))

    def test_plan_runs_when_met_and_stops_when_not(self):
        self.give('a', requires=GOOD)
        self.assertEqual(self.plan('26B131/25G342'), ['a', 'b'])
        with self.assertRaises(ValueError) as e:
            self.plan('26A428/25G342')
        self.assertIn('a: requires not met', str(e.exception))
        with self.assertRaises(ValueError):
            self.plan('25G342')                                                 # no macOS 27 build given

    def test_pending_list_and_comments(self):
        self.assertEqual(self.tree(), ['a: needs "requires" (docs/requires.md)'])
        self.give('a', requires=GOOD)
        self.assertEqual(self.tree(), [])
        self.give('b', requires=GOOD)
        self.assertEqual(self.tree(), ['b: has "requires": remove it from pipeline/requires-pending.txt'])
        (self.root / 'pending.txt').write_text('')
        (self.root / 'order.txt').write_text('a  # built for 26A428\nb\n')
        self.assertEqual(self.tree(), ['order.txt: a: the comment names 26A428, its requires does not'])


class RealTree(unittest.TestCase):
    def test_target_has_facts(self):
        f = P['target_facts'](str(TOP / 'pipeline/targets/mbp92.json'))
        self.assertEqual((f['gpu'], f['firmware']), ({'intel-ivb'}, 'none'))
        self.assertIn('avx1.0', f['cpu'])
        self.assertNotIn('avx2', f['cpu'])

    def test_tree_is_clean(self):
        self.assertEqual(P['requires_tree_problems'](), [])


if __name__ == '__main__':
    unittest.main()
