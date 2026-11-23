import plistlib
from pathlib import Path
import runpy
import tempfile
import unittest

SRC = Path(__file__).resolve().parents[1] / 'src' / 'vostro3520.py'
MOD = runpy.run_path(str(SRC))


class Vostro3520Tests(unittest.TestCase):
    def test_ensure_cryptexfixup_and_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            vxe = tmp / 'vxe/EFI/OC'
            (vxe / 'ACPI').mkdir(parents=True)
            (vxe / 'Kexts/Lilu.kext').mkdir(parents=True)
            (vxe / 'ACPI/SSDT-EC.aml').write_bytes(b'ACPI')
            base_cfg = {
                'Kernel': {
                    'Add': [
                        {'BundlePath': 'Lilu.kext', 'Enabled': True},
                        {'BundlePath': 'VirtualSMC.kext', 'Enabled': True},
                    ]
                },
                'NVRAM': {'Add': {MOD['APPLE_NVRAM']: {'boot-args': '-v'}}},
                'PlatformInfo': {'Generic': {'SystemProductName': 'MacBookPro16,2'}},
            }
            (vxe / 'config.plist').write_bytes(plistlib.dumps(base_cfg))
            (vxe / 'config-install.plist').write_bytes(plistlib.dumps(base_cfg))

            esp = tmp / 'esp'
            MOD['apply_vostroxe'](esp, tmp / 'vxe/EFI')
            for name in ('config.plist', 'config-safe.plist', 'config-accel.plist'):
                cfg = plistlib.loads((esp / 'EFI/OC' / name).read_bytes())
                kexts = [k['BundlePath'] for k in cfg['Kernel']['Add']]
                self.assertEqual(kexts[:2], ['Lilu.kext', 'CryptexFixup.kext'])
                args = cfg['NVRAM']['Add'][MOD['APPLE_NVRAM']]['boot-args'].split()
                self.assertIn('-crypt_force_avx', args)
                self.assertIn('-lilubetaall', args)
                self.assertEqual(cfg['PlatformInfo']['UpdateSMBIOSMode'], 'Create')


if __name__ == '__main__':
    unittest.main()
