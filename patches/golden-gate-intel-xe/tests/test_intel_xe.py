import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest

HOOK = Path(__file__).resolve().parents[1] / 'src' / 'kc-hook.sh'


class IntelXeHookTests(unittest.TestCase):
    def test_noop_without_bundle(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = dict(os.environ)
            env.pop('VOSTROXE_BUNDLE', None)
            r = subprocess.run(['sh', str(HOOK), tmp], env=env, capture_output=True, text=True, check=True)
            self.assertIn('no VOSTROXE_BUNDLE supplied', r.stdout)

    def test_installs_kexts_into_sle_and_bundles_into_library(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sys_root = tmp / 'sys'
            sys_root.mkdir()
            bundle = tmp / 'bundle'
            (bundle / 'GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle').mkdir(parents=True)
            (bundle / 'GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/bin').write_text('mtl')
            (bundle / 'Extensions/AppleIntelTGLGraphics.kext').mkdir(parents=True)
            (bundle / 'Extensions/AppleIntelTGLGraphicsFramebuffer.kext').mkdir(parents=True)
            (bundle / 'Extensions/HookCase.kext').mkdir(parents=True)
            (bundle / 'Extensions/AppleIntelTGLGraphicsGLDriver.bundle').mkdir(parents=True)
            (bundle / 'xe.bundle').mkdir(parents=True)
            (bundle / 'xe.bundle/igc').write_text('xe')

            # Portable stubs for macOS ditto and root chown during host unit tests
            bin_dir = tmp / 'bin'
            bin_dir.mkdir()
            ditto = bin_dir / 'ditto'
            ditto.write_text('#!/bin/sh\ncp -R "$1" "$2"\n')
            ditto.chmod(0o755)
            chown = bin_dir / 'chown'
            chown.write_text('#!/bin/sh\nexit 0\n')
            chown.chmod(0o755)

            env = dict(os.environ, VOSTROXE_BUNDLE=str(bundle), PATH=f'{bin_dir}:{os.environ.get("PATH", "")}')
            r = subprocess.run(['sh', str(HOOK), str(sys_root)], env=env, capture_output=True, text=True, check=True)
            self.assertIn('TGL 16.0.32 + HookCase into S/L/E', r.stdout)
            self.assertTrue((sys_root / 'System/Library/Extensions/AppleIntelTGLGraphics.kext').is_dir())
            self.assertTrue((sys_root / 'System/Library/Extensions/AppleIntelTGLGraphicsFramebuffer.kext').is_dir())
            self.assertTrue((sys_root / 'System/Library/Extensions/HookCase.kext').is_dir())
            self.assertTrue((sys_root / 'Library/GPUBundles/AppleIntelTGLGraphicsMTLDriver.bundle/bin').is_file())
            self.assertTrue((sys_root / 'Library/Extensions/AppleIntelTGLGraphicsGLDriver.bundle').is_dir())
            self.assertTrue((sys_root / 'System/Library/Caches/xe.bundle/igc').is_file())

    def test_relinks_system_kc_without_touching_boot_kc(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            sys_root = tmp / 'sys'
            kc_dir = sys_root / 'System/Library/KernelCollections'
            kc_dir.mkdir(parents=True)
            (sys_root / 'System/Library/Kernels').mkdir(parents=True)
            (sys_root / 'System/Library/Kernels/kernel').write_bytes(b'kern')
            boot_kc = kc_dir / 'BootKernelExtensions.kc'
            boot_kc.write_bytes(b'BOOT_KC_BYTES')
            (kc_dir / 'BootKernelExtensions.kc.elides').write_text('com.apple.driver.A\n')
            (kc_dir / 'SystemKernelExtensions.kc').write_bytes(b'OLD_SYS_KC')

            bundle = tmp / 'bundle'
            (bundle / 'Extensions/AppleIntelTGLGraphics.kext').mkdir(parents=True)
            (bundle / 'Extensions/HookCase.kext').mkdir(parents=True)

            bin_dir = tmp / 'bin'
            bin_dir.mkdir()
            for name, body in {
                'ditto': '#!/bin/sh\ncp -R "$1" "$2"\n',
                'chown': '#!/bin/sh\nexit 0\n',
                'codesign': '#!/bin/sh\nexit 0\n',
                'install': '#!/bin/sh\nwhile [ $# -gt 2 ]; do shift; done\ncp "$1" "$2"\n',
                'uname': '#!/bin/sh\necho arm64\n',
            }.items():
                p = bin_dir / name
                p.write_text(body)
                p.chmod(0o755)

            fake_kmutil = tmp / 'fake_kmutil'
            fake_kmutil.write_text(
                '#!/bin/sh\n'
                'out=\nroot=\n'
                'while [ $# -gt 0 ]; do\n'
                '  case "$1" in\n'
                '    -R) root=$2; shift 2;;\n'
                '    -S) out=$2; shift 2;;\n'
                '    *) shift;;\n'
                '  esac\n'
                'done\n'
                'printf "NEW_SYS_KC" > "$root$out"\n'
            )
            fake_kmutil.chmod(0o755)

            env = dict(
                os.environ,
                VOSTROXE_BUNDLE=str(bundle),
                TAHOE_KMUTIL=str(fake_kmutil),
                PATH=f'{bin_dir}:{os.environ.get("PATH", "")}',
            )
            r = subprocess.run(['sh', str(HOOK), str(sys_root)], env=env, capture_output=True, text=True, check=True)
            self.assertIn('re-linked SystemKernelExtensions.kc', r.stdout)
            self.assertEqual(boot_kc.read_bytes(), b'BOOT_KC_BYTES')
            self.assertEqual((kc_dir / 'SystemKernelExtensions.kc').read_bytes(), b'NEW_SYS_KC')


if __name__ == '__main__':
    unittest.main()
