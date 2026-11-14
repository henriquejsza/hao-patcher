"""The kc-hook's driver edit: src/add_weak_dylib.py adds exactly one LC_LOAD_WEAK_DYLIB /usr/lib/libhd4000-planes.dylib,
after the three weak libraries the earlier recipes add.

python3.14 -I -B -m unittest discover -s patches/golden-gate-hd4000-planes/tests

With HD4000_PLANES_DRIVER_INPUT=PATH (the driver as golden-gate-metal-argbuf leaves it; laptop 1's is 68c198ea...)
it runs the edit and the hook's `codesign` on the real file. With HD4000_PLANES_DRIVER_EXPECT=SHA256 it also compares
the result (1a9763f5... is what ran on laptop 1, signed on the host; the builder VM's codesign may sign differently).
"""
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

PATCH = Path(__file__).resolve().parents[1]
LIB = '/usr/lib/libhd4000-planes.dylib'
EARLIER = ['/usr/lib/libmetalold-selectors.dylib', '/usr/lib/libmetal-framebuffer.dylib',
           '/System/Library/Extensions/AppleIntelHD4000GraphicsMTLDriver.bundle/Contents/MacOS/libargbuf.dylib']


def weak_dylibs(path):
    out = subprocess.run(['otool', '-l', str(path)], capture_output=True, text=True, check=True).stdout.splitlines()
    names = []
    for i, line in enumerate(out):
        if line.strip() == 'cmd LC_LOAD_WEAK_DYLIB':
            names.append(next(l.split()[1] for l in out[i:i + 4] if l.strip().startswith('name ')))
    return names


class Hook(unittest.TestCase):
    def test_hook_names_the_library_and_the_row(self):
        hook = (PATCH / 'src/kc-hook.sh').read_text()
        self.assertIn(f'LIB={LIB}', hook)
        self.assertIn('inputs/hd4000_planes', hook)
        self.assertIn('codesign -f -s - -i AppleIntelHD4000GraphicsMTLDriver', hook)

    @unittest.skipUnless(os.environ.get('HD4000_PLANES_DRIVER_INPUT'), 'set HD4000_PLANES_DRIVER_INPUT to the driver after metal-argbuf')
    def test_real_driver(self):
        d = Path(tempfile.mkdtemp()); src = d / 'in'
        shutil.copy(os.environ['HD4000_PLANES_DRIVER_INPUT'], src)
        self.assertEqual(weak_dylibs(src), EARLIER)
        subprocess.run([sys.executable, '-I', str(PATCH / 'src/add_weak_dylib.py'), str(src), str(d / 'out'), LIB], check=True, capture_output=True)
        subprocess.run(['codesign', '-f', '-s', '-', '-i', 'AppleIntelHD4000GraphicsMTLDriver', str(d / 'out')], check=True, capture_output=True)
        self.assertEqual(weak_dylibs(d / 'out'), EARLIER + [LIB])
        subprocess.run(['codesign', '-v', str(d / 'out')], check=True)
        if os.environ.get('HD4000_PLANES_DRIVER_EXPECT'):
            import hashlib
            self.assertEqual(hashlib.sha256((d / 'out').read_bytes()).hexdigest(), os.environ['HD4000_PLANES_DRIVER_EXPECT'])


if __name__ == '__main__':
    unittest.main()
