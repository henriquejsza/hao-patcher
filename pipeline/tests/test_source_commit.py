"""pipeline/source_commit.py: a producer records its commit in a checkout and in a release archive (no .git)."""
from pathlib import Path
import runpy
import subprocess
import tempfile
import unittest

TOP = Path(__file__).resolve().parents[2]
S = runpy.run_path(str(TOP / 'pipeline' / 'source_commit.py'))


class SourceCommit(unittest.TestCase):
    def test_archive_folder_reads_the_stamped_commit_and_is_clean(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'pipeline').mkdir()
            (Path(d) / 'pipeline/SOURCE_COMMIT').write_text('a' * 40 + '\n')
            self.assertEqual(S['commit'](d), 'a' * 40)
            self.assertFalse(S['dirty'](d, 'pipeline'))

    def test_unsubstituted_stamp_is_no_commit(self):
        with tempfile.TemporaryDirectory() as d:
            (Path(d) / 'pipeline').mkdir()
            (Path(d) / 'pipeline/SOURCE_COMMIT').write_text('$' 'Format:%H$\n')
            self.assertEqual(S['commit'](d), '')

    def test_git_archive_stamps_the_commit(self):
        if not (TOP / '.git').exists():
            self.skipTest('not a checkout')
        out = subprocess.run(['git', '-C', str(TOP), 'archive', 'HEAD', 'pipeline/SOURCE_COMMIT'], capture_output=True)
        if out.returncode:
            self.skipTest('SOURCE_COMMIT not committed yet')
        text = subprocess.run(['tar', 'xO'], input=out.stdout, capture_output=True).stdout.decode().strip()
        head = subprocess.run(['git', '-C', str(TOP), 'rev-parse', 'HEAD'], capture_output=True, text=True).stdout.strip()
        self.assertEqual(text, head)
