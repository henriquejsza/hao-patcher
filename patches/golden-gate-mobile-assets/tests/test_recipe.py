"""golden-gate-mobile-assets: apply.sh refuses a pack for another build or with a changed tar, and extracts a good one.
python3.14 -I -B -m unittest discover -s patches/golden-gate-mobile-assets/tests"""
import hashlib
import io
import json
import os
import plistlib
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

PATCH = Path(__file__).resolve().parents[1]
PJ = json.loads((PATCH / 'patch.json').read_text())


class Recipe(unittest.TestCase):
    def run_apply(self, build='26B131', system='26B131', tamper=False):
        with tempfile.TemporaryDirectory() as d:
            d = Path(d)
            pack = d / 'p/inputs/mobile_assets'
            pack.mkdir(parents=True)
            with tarfile.open(pack / 'mobile-assets.tar', 'w', format=tarfile.PAX_FORMAT) as t:
                info = tarfile.TarInfo('System/Library/AssetsV2/com_apple_MobileAsset_Font8/a')
                info.size = 1
                t.addfile(info, io.BytesIO(b'x'))
            (pack / 'INFO').write_text('build %s\n' % build)
            sums = ''.join('%s  %s\n' % (hashlib.sha256((pack / n).read_bytes()).hexdigest(), n)
                           for n in ('mobile-assets.tar', 'INFO'))
            (pack / 'SHA256SUMS').write_text(sums)
            if tamper:
                (pack / 'mobile-assets.tar').write_bytes(b'changed')
            sv = d / 'sys/System/Library/CoreServices'
            sv.mkdir(parents=True)
            (sv / 'SystemVersion.plist').write_bytes(plistlib.dumps({'ProductBuildVersion': system}))
            data = d / 'data'
            data.mkdir()
            text = (PATCH / 'apply.sh').read_text().replace('chflags -R restricted', 'true')
            r = subprocess.run(['/bin/sh', '-eu', '-c', text], capture_output=True, text=True,
                               env=dict(os.environ, P=str(d / 'p'), SYS=str(d / 'sys'), DATA=str(data)))
            return r, (data / 'System/Library/AssetsV2/com_apple_MobileAsset_Font8/a').exists()

    def test_extracts_a_matching_pack(self):
        r, placed = self.run_apply()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertTrue(placed)

    def test_refuses_another_build(self):
        r, placed = self.run_apply(build='26B999')
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(placed)

    def test_refuses_a_changed_tar(self):
        r, placed = self.run_apply(tamper=True)
        self.assertNotEqual(r.returncode, 0)
        self.assertFalse(placed)

    def test_declares_the_tree_from_its_row(self):
        self.assertEqual(PJ['inputs'], ['mobile_assets'])
        self.assertEqual([(f['path'], f['origin']['row']) for f in PJ['files']], [('System/Library/AssetsV2', 'mobile_assets')])


if __name__ == '__main__':
    unittest.main()
