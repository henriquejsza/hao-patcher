"""src/arm64_only.py writes what edit-engine's plist.set writes for edits/av1-encoder-info.json, on a plist laid out as
AV1EncoderSW's (synthetic: no Apple bytes here), and refuses a plist that is not the x86_64 AV1 software encoder.
AV1_INFO_PLIST=FILE also checks the 26B131 file against the spec's expect.
python3.14 -I -B -m unittest discover -s patches/golden-gate-av1-encoder-x86/tests"""
import hashlib, json, os, plistlib, subprocess, sys, tempfile, unittest
from pathlib import Path

RECIPE = Path(__file__).resolve().parents[1]
TOP = RECIPE.parents[1]
SPEC = RECIPE / 'edits/av1-encoder-info.json'
sys.path.insert(0, str(RECIPE / 'src'))
import arm64_only  # noqa: E402

FIXTURE = {'CFBundleIdentifier': 'com.apple.AV1EncoderSW', 'CMClassImplementations': [{
    'CMClassID': 'com.apple.videotoolbox.videoencoder',
    'CMClassImplementationID': 'com.apple.videotoolbox.videoencoder.av1.sw',
    'CMExecutableArchitectures': ['x86_64', 'arm64'], 'CMFactoryFunction': 'AV1Encoder_CreateInstance',
    'CMMatchingInfo': {'VTCodecType': 'av01'}}], 'LSMinimumSystemVersion': '27.2'}


def engine(spec, data):
    with tempfile.TemporaryDirectory() as d:
        src, out, s = Path(d) / 'in', Path(d) / 'out', Path(d) / 'spec.json'
        src.write_bytes(data)
        s.write_text(json.dumps(spec))
        subprocess.run([sys.executable, '-I', str(TOP / 'tools/edit-engine/edit-engine'), 'apply', '--quiet', str(s),
                        str(src), str(out)], check=True)
        return out.read_bytes()


class Edit(unittest.TestCase):
    def test_the_hook_writes_what_the_spec_declares(self):
        spec = json.loads(SPEC.read_text())
        spec.pop('expect')
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            data = plistlib.dumps(FIXTURE, fmt=fmt, sort_keys=False)
            out = arm64_only.arm64_only(data)
            self.assertEqual(out, engine(spec, data))
            impl = plistlib.loads(out)['CMClassImplementations'][0]
            self.assertEqual(impl['CMExecutableArchitectures'], ['arm64'])
            self.assertEqual(impl['CMFactoryFunction'], 'AV1Encoder_CreateInstance')

    def test_another_plist_stops_the_build(self):
        other = dict(FIXTURE, CMClassImplementations=[dict(FIXTURE['CMClassImplementations'][0],
                                                           CMExecutableArchitectures=['arm64'])])
        with self.assertRaises(SystemExit):
            arm64_only.arm64_only(plistlib.dumps(other))

    @unittest.skipUnless(os.environ.get('AV1_INFO_PLIST'), 'set AV1_INFO_PLIST to the 26B131 Info.plist')
    def test_the_26B131_file(self):
        data = Path(os.environ['AV1_INFO_PLIST']).read_bytes()
        (before, after), = json.loads(SPEC.read_text())['expect'].items()
        self.assertEqual(hashlib.sha256(data).hexdigest(), before)
        self.assertEqual(hashlib.sha256(arm64_only.arm64_only(data)).hexdigest(), after)


if __name__ == '__main__':
    unittest.main()
