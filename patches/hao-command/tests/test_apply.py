"""apply.sh into a scratch Data root: the launcher, the CPython and tools/hao land where /usr/local/bin/hao expects."""
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
RECIPE = HERE.parent


class Apply(unittest.TestCase):
    def test_lays_out_the_command(self):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            p = d / 'recipe'
            (p / 'inputs').mkdir(parents=True)
            (p / 'build').mkdir()
            py = d / 'python' / 'bin'
            py.mkdir(parents=True)
            (py / 'python3.12').write_text('#!/bin/sh\n')
            (py / 'python3.12').chmod(0o755)
            with tarfile.open(p / 'inputs' / 'python_x86_64', 'w:gz') as t:
                t.add(d / 'python', arcname='python')
            subprocess.run(['sh', str(RECIPE / 'make.sh'), str(p / 'build')], check=True)
            data = d / 'data'
            data.mkdir()
            env = dict(os.environ, P=str(p), DATA=str(data))
            script = (RECIPE / 'apply.sh').read_text().replace('chown -R root:wheel', ': chown -R root:wheel') \
                .replace('install -d -o root -g wheel', 'install -d')
            r = subprocess.run(['sh', '-eu', '-c', script], env=env, capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
            launcher = (data / 'usr/local/bin/hao').read_text()
            self.assertIn('/usr/local/lib/hao/python/bin/python3.12 -I /usr/local/lib/hao/hao/tools/hao/hao', launcher)
            self.assertTrue((data / 'usr/local/lib/hao/python/bin/python3.12').is_file())
            self.assertTrue((data / 'usr/local/lib/hao/hao/tools/hao/hao').is_file())
            self.assertTrue((data / 'usr/local/lib/hao/hao/tools/hao/vendor/rich/LICENSE').is_file())
            self.assertFalse((data / 'usr/local/lib/hao/hao/tools/hao/tests').exists())


if __name__ == '__main__':
    unittest.main()
