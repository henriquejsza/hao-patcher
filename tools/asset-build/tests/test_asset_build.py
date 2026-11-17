import json, os, runpy, shutil, subprocess, sys, tempfile, unittest
from pathlib import Path

TOP = Path(__file__).resolve().parents[3]
TOOL = TOP/'tools/asset-build/asset-build'
AB = runpy.run_path(str(TOOL))
BT = runpy.run_path(str(TOP/'pipeline/unpack/build-tools'))


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


@unittest.skipUnless(shutil.which('git'), 'needs git')
class PaxComment(unittest.TestCase):
    def test_two_commits_of_one_tree_and_time_differ_only_in_the_named_commit(self):
        with tempfile.TemporaryDirectory() as d:
            env = dict(os.environ, GIT_CONFIG_GLOBAL='/dev/null', GIT_CONFIG_NOSYSTEM='1', GIT_AUTHOR_NAME='a',
                       GIT_AUTHOR_EMAIL='a@invalid', GIT_COMMITTER_NAME='a', GIT_COMMITTER_EMAIL='a@invalid',
                       GIT_AUTHOR_DATE='1793389707 -0400', GIT_COMMITTER_DATE='1793389707 -0400')
            git = lambda *a: subprocess.run(['git', '-C', d, *a], check=True, capture_output=True, env=env).stdout
            git('init', '-q')
            Path(d, 'f').write_text('x\n')
            git('add', 'f')
            tree = git('write-tree').decode().strip()
            one, two = (git('commit-tree', tree, '-m', m).decode().strip() for m in ('one', 'two'))
            a, b = (git('archive', '--format=tar', c) for c in (one, two))
            self.assertNotEqual(a, b)
            self.assertEqual(BT['name_commit'](a, one, two), b)
            with self.assertRaises(SystemExit):
                BT['name_commit'](a, two, one)


@unittest.skipUnless(shutil.which('xcrun') and os.environ.get('ASSET_BUILD_COMPILE'), 'set ASSET_BUILD_COMPILE=1 (Xcode)')
class Compile(unittest.TestCase):
    def test_windowserver_filter_fl_and_ripatch_match_their_rows(self):
        for row in ('windowserver_filter_shim', 'fl', 'ripatch'):
            with tempfile.TemporaryDirectory() as d:
                r = subprocess.run([sys.executable, '-I', str(TOOL), row, Path(d)/'o'], capture_output=True, text=True)
                self.assertEqual(r.returncode, 0, row + r.stderr)


@unittest.skipUnless(os.environ.get('ASSET_BUILD_OCLP'), 'set ASSET_BUILD_OCLP to an OCLP clone or URL (850 MB clone)')
class OclpSource(unittest.TestCase):
    def test_upstream_plus_target_patch_matches_the_row(self):
        with tempfile.TemporaryDirectory() as d:
            r = subprocess.run([sys.executable, '-I', str(TOOL), 'oclp_source', Path(d)/'o', '--oclp-upstream',
                                os.environ['ASSET_BUILD_OCLP']], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
