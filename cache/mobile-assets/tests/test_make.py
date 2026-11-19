"""cache/mobile-assets/make keeps the assets and mobileassetd's state, and drops what is not the image's.
python3.14 -I -B -m unittest discover -s cache/mobile-assets/tests"""
import io
import runpy
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parents[1]
A = 'System/Library/AssetsV2/'


def add(tar, name, data=b'x', pax=None):
    info = tarfile.TarInfo(name)
    if name.endswith('/'):
        info.type = tarfile.DIRTYPE
        tar.addfile(info)
        return
    info.size = len(data)
    if pax:
        info.pax_headers = pax
    tar.addfile(info, io.BytesIO(data))


class Make(unittest.TestCase):
    def run_make(self, members, exclude=''):
        with tempfile.TemporaryDirectory() as d:
            tool = Path(d) / 'tool'
            tool.mkdir()
            (tool / 'make').write_text((HERE / 'make').read_text())
            (tool / 'exclude.txt').write_text(exclude)
            raw = Path(d) / 'artifacts' / 'mobile-assets-26B131-raw-test'
            raw.mkdir(parents=True)
            with tarfile.open(raw / 'mobile-assets.tar', 'w', format=tarfile.PAX_FORMAT) as t:
                for m in members:
                    add(t, *m) if isinstance(m, tuple) else add(t, m)
            (raw / 'INFO').write_text('build 26B131\n')
            out = subprocess.run([sys.executable, '-I', str(tool / 'make'), str(raw)], capture_output=True, text=True)
            self.assertEqual(out.returncode, 0, out.stderr)
            final = next(p for p in (Path(d) / 'artifacts').iterdir() if p.name.startswith('mobile-assets-26B131-')
                         and 'raw' not in p.name)
            with tarfile.open(final / 'mobile-assets.tar') as t:
                return {m.name: m.pax_headers for m in t}, (final / 'INFO').read_text(), out.stdout

    def test_drops_appledouble_purged_health_lookup_and_provenance(self):
        names, info, _ = self.run_make([
            A + 'com_apple_MobileAsset_DictionaryServices/a.asset/x',
            A + 'com_apple_MobileAsset_DictionaryServices/._a.asset',
            A + 'com_apple_MobileAsset_DictionaryServices/c.xml.purged',
            A + 'persisted/HealthReport/state',
            A + 'persisted/AutoStagerTargetLookupResults/r',
            A + 'persisted/AutoAssetSets/s',
            A + 'PreinstalledAssetsV2/InstallWithOs/x', A + 'history/h', A + 'staging/s', A + 'downloadDir/d',
            (A + 'locks/l', b'x', {'SCHILY.xattr.com.apple.provenance': 'p', 'SCHILY.xattr.szmodtime': 't'})])
        self.assertEqual(sorted(names), sorted([A + 'com_apple_MobileAsset_DictionaryServices/a.asset/x',
                                                A + 'persisted/AutoAssetSets/s', A + 'locks/l']))
        self.assertEqual(names[A + 'locks/l'], {'SCHILY.xattr.szmodtime': 't'})
        self.assertIn('assets 1\ncom_apple_MobileAsset_DictionaryServices', info)

    def test_excluded_asset_types_are_dropped(self):
        names, _, _ = self.run_make([A + 'com_apple_MobileAsset_DictionaryServices/a',
                                     A + 'com_apple_MobileAsset_UAF_Example/b'],
                                    exclude='# reason\ncom_apple_MobileAsset_UAF_Example  # its service is disabled\n')
        self.assertEqual(list(names), [A + 'com_apple_MobileAsset_DictionaryServices/a'])

    def test_prints_the_row(self):
        _, _, out = self.run_make([A + 'com_apple_MobileAsset_DictionaryServices/a'])
        self.assertRegex(out, r'row pipeline/inputs/golden/26B131/mobile_assets:\n-  store/artifacts/'
                              r'mobile-assets-26B131-[0-9a-f]{12}$')


if __name__ == '__main__':
    unittest.main()
