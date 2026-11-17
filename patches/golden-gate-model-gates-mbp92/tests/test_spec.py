"""The declared gate edits: one spec, only on targets with model_gates, sites equal to userspace's planner for mbp92."""
import json
import os
from pathlib import Path
import sys
import unittest

PATCH = Path(__file__).resolve().parents[1]
TOP = PATCH.parents[1]
sys.path.insert(0, str(TOP/'patches/golden-gate-userspace/src'))
import model_gates  # noqa: E402

SPEC = json.loads((PATCH/'edits/cache-01.json').read_text())
TARGET = json.loads((TOP/'pipeline/targets/mbp92.json').read_text())


class Spec(unittest.TestCase):
    def test_only_on_targets_with_model_gates(self):
        self.assertEqual(SPEC['when_target'], 'model_gates')
        self.assertIn('model_gates', TARGET['platform_data'])
        self.assertEqual([e['id'] for e in SPEC['edits']], ['model-gates'])

    def test_userspace_no_longer_declares_it(self):
        userspace = json.loads((TOP/'patches/golden-gate-userspace/edits/cache-01.json').read_text())
        self.assertNotIn('model-gates', [e['id'] for e in userspace['edits']])

    def test_hook_does_nothing(self):
        lines = [l for l in (PATCH/'src/kc-hook.sh').read_text().splitlines() if l and not l.startswith('#')]
        self.assertEqual(lines, ['exit 0'])

    @unittest.skipUnless(os.environ.get('USERSPACE_X86_CACHE'), 'set USERSPACE_X86_CACHE (a 26B131 x86_64 cache folder)')
    def test_sites_equal_the_planner_for_this_target(self):
        import hashlib
        cache = Path(os.environ['USERSPACE_X86_CACHE'])
        gates = model_gates.target_gates(TARGET['model'], TARGET['platform_data'])
        planned = model_gates.plan_cache_family(cache, gates=gates)
        (fname, changes), = planned.items()
        key = hashlib.sha256((cache/Path(fname).name).read_bytes()).hexdigest()
        declared = [(s['at'], s['before'], s['after'], s['reason']) for s in SPEC['edits'][0]['resolved'][key]]
        self.assertEqual(declared, [(o, b.hex(), a.hex(), r) for o, b, a, r in changes])


if __name__ == '__main__':
    unittest.main()
