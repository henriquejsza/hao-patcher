"""disk_guard: a producer run refuses to start without room and removes its intermediates afterwards."""
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from dyld_rebuild import disk_guard
from dyld_rebuild.exports import Refusal


class DiskGuard(unittest.TestCase):
    def setUp(self):
        self.top = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.work, self.output = self.top / 'new-work', self.top / 'new-family'

    def test_one_volume_needs_work_and_family_together(self):
        disk_guard.check(self.work, self.output, 'x', free=lambda p: 38, command='')
        with self.assertRaisesRegex(Refusal, 'needs 38 GB'):
            disk_guard.check(self.work, self.output, 'x', free=lambda p: 37, command='')

    def test_a_site_check_command_can_refuse(self):
        calls = []
        def run(argv):
            calls.append(argv)
            return subprocess.CompletedProcess(argv, 3)
        with self.assertRaisesRegex(Refusal, 'refused the run'):
            disk_guard.check(self.work, self.output, 'fold F', free=lambda p: 1000, run=run, command='site-disk')
        self.assertEqual([['site-disk', 'check', '--need', '38', '--who', 'shared-cache', '--what', 'fold F']], calls)

    def test_intermediates_go_and_the_selection_stays(self):
        (self.work / 'build/prepare').mkdir(parents=True)
        (self.work / 'build/prepare/big').write_bytes(b'x')
        (self.work / 'selection.json').write_text('{}')
        (self.work / 'source.img').write_bytes(b'img')
        disk_guard.remove_intermediates(self.work)
        self.assertEqual(['selection.json'], sorted(p.name for p in self.work.iterdir()))


if __name__ == '__main__':
    unittest.main()
