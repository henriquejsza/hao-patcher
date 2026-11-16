import json, os, runpy, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

TOP = Path(__file__).resolve().parents[3]
TOOL = TOP/'tools/asset-build/asset-build'
AB = runpy.run_path(str(TOOL))


class Table(unittest.TestCase):
    def test_every_asset_is_an_ours_row_with_a_row_file(self):
        classes = json.loads((TOP/'pipeline/release-classes.json').read_text())['rows']
        for row in AB['ASSETS']:
            self.assertEqual(classes[row]['class'], 'ours', row)
            self.assertTrue(any((TOP/lock/row).is_file() for lock in AB['LOCKS']), row)

    def test_list_and_refusals(self):
        r = subprocess.run([sys.executable, '-I', str(TOOL), 'list'], capture_output=True, text=True)
        self.assertEqual(r.stdout.split(), list(AB['ASSETS']))
        r = subprocess.run([sys.executable, '-I', str(TOOL), 'nope', '/nonexistent/x'], capture_output=True, text=True)
        self.assertNotEqual(r.returncode, 0); self.assertIn('ROW is one of', r.stderr)
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, '-I', str(TOOL), 'display_state_shim', d], capture_output=True, text=True)
            self.assertNotEqual(r.returncode, 0); self.assertIn('exists', r.stderr)


@unittest.skipUnless(shutil.which('xcrun') and os.environ.get('ASSET_BUILD_COMPILE'), 'set ASSET_BUILD_COMPILE=1 (Xcode)')
class Compile(unittest.TestCase):
    def test_windowserver_filter_matches_its_row(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, '-I', str(TOOL), 'windowserver_filter_shim', Path(d)/'o'],
                               capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
