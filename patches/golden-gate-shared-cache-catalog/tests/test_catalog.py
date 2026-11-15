"""golden-gate-shared-cache-catalog: the B recipe's fold, staged whole, on the B+catalog row."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

PATCH = Path(__file__).resolve().parents[1]
BASE = PATCH.parent/'golden-gate-shared-cache'


class Recipe(unittest.TestCase):
    def test_hook_runs_the_staged_fold_on_its_own_row(self):
        hook = (PATCH/'src/kc-hook.sh').read_text()
        self.assertIn('"$H/build/fold/fold.py" install "$S" "$H/inputs/rebuilt_cache_catalog"', hook)
        pj, base = (json.loads((p/'patch.json').read_text()) for p in (PATCH, BASE))
        self.assertEqual(pj['inputs'], ['rebuilt_cache_catalog'])
        self.assertEqual((pj['stage'], pj['applies']), (base['stage'], base['applies']))

    def test_staging_is_the_b_recipe_byte_for_byte(self):
        # the hook stages src/ as the hook folder and make.sh's output as build/ (pipeline/stages/inputs.sh)
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(['sh', str(PATCH/'make.sh'), d + '/build'], check=True)
            fold = Path(d, 'build/fold')
            for name in ('fold.py', 'providers.txt'):
                self.assertEqual((fold/name).read_bytes(), (BASE/'src'/name).read_bytes(), name)
            self.assertFalse((fold/'kc-hook.sh').exists())
            for module in ('cryptex.py', 'model_gates.py', 'prespecialization.py', 'swift_refs.py'):
                self.assertTrue((fold/'build/userspace'/module).is_file(), module)
            # fold.py finds that staged userspace (not the checkout's) when run from the staged folder
            out = subprocess.run(['python3.14', '-I', '-c', 'import sys; sys.argv = ["fold"]; '
                                  f'sys.path.insert(0, "{fold}"); import fold; print(fold.USERSPACE)'],
                                 check=True, capture_output=True, text=True)
            self.assertEqual(out.stdout.strip(), str((fold/'build/userspace').resolve()))


if __name__ == '__main__':
    unittest.main()
