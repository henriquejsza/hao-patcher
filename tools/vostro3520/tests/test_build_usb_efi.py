import plistlib
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / 'build-usb-efi.py'
APPLE_NVRAM = '7C436110-AB2A-4BBB-A880-FE41995C9F82'


class BuildUsbEfiTests(unittest.TestCase):
    def _make_vostroxe_efi(self, root: Path):
        oc = root / 'OC'
        (oc / 'ACPI').mkdir(parents=True)
        (oc / 'Drivers').mkdir(parents=True)
        (oc / 'Kexts/Lilu.kext').mkdir(parents=True)
        (oc / 'Kexts/NootedGreen.kext').mkdir(parents=True)
        (oc / 'ACPI/SSDT-PLUG-ALT.aml').write_bytes(b'ACPI')
        base = {
            'Kernel': {
                'Add': [
                    {'BundlePath': 'Lilu.kext', 'Enabled': True},
                    {'BundlePath': 'VirtualSMC.kext', 'Enabled': True},
                    {'BundlePath': 'NootedGreen.kext', 'Enabled': True},
                ],
                'Patch': [],
            },
            'NVRAM': {'Add': {APPLE_NVRAM: {'boot-args': '-ngreentglwithgfx'}}},
            'PlatformInfo': {'Generic': {'SystemProductName': 'MacBookPro16,2'}},
            'Misc': {'Boot': {'ShowPicker': False}},
            'UEFI': {'Drivers': [], 'APFS': {'MinDate': 0, 'MinVersion': 0}},
        }
        install = {
            'Kernel': {
                'Add': [
                    {'BundlePath': 'Lilu.kext', 'Enabled': True},
                    {'BundlePath': 'VirtualSMC.kext', 'Enabled': True},
                    {'BundlePath': 'NootedGreen.kext', 'Enabled': False},
                ],
                'Patch': [],
            },
            'NVRAM': {'Add': {APPLE_NVRAM: {'boot-args': 'keepsyms=1 -v'}}},
            'PlatformInfo': {'Generic': {'SystemProductName': 'MacBookPro16,2'}},
            'Misc': {'Boot': {'ShowPicker': False}},
            'UEFI': {'Drivers': [], 'APFS': {'MinDate': 0, 'MinVersion': 0}},
        }
        (oc / 'config.plist').write_bytes(plistlib.dumps(base))
        (oc / 'config-install.plist').write_bytes(plistlib.dumps(install))

    def _make_hao_esp(self, root: Path):
        oc = root / 'EFI/OC'
        (oc / 'Kexts/IntelCommpage.kext').mkdir(parents=True)
        (oc / 'Kexts/HaoExec.kext').mkdir(parents=True)
        (oc / 'Kexts/IntelCommpage.kext/marker').write_text('ic')
        (oc / 'Kexts/HaoExec.kext/marker').write_text('he')
        hao_cfg = {
            'Kernel': {
                'Add': [
                    {'BundlePath': 'IntelCommpage.kext', 'Enabled': True, 'MinKernel': '27.0.0', 'MaxKernel': '27.99.99'},
                    {'BundlePath': 'HaoExec.kext', 'Enabled': True, 'MinKernel': '27.0.0', 'MaxKernel': '27.99.99'},
                ],
                'Patch': [
                    {'Comment': 'early-vm-test', 'Enabled': True, 'Find': b'\x90', 'Replace': b'\xc3', 'MinKernel': '', 'MaxKernel': ''},
                    {'Comment': 'disabled-patch', 'Enabled': False, 'Find': b'\x00', 'Replace': b'\x01'},
                ],
            }
        }
        (oc / 'config.plist').write_bytes(plistlib.dumps(hao_cfg))

    def test_merge_safe_accel_and_recovery_configs(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            vxe = tmp / 'vxe-efi'
            hao = tmp / 'hao-esp'
            out = tmp / 'out-efi'
            dummy_apfs = tmp / 'apfs.efi'
            dummy_apfs.write_bytes(b'DUMMY_APFS_EFI')
            self._make_vostroxe_efi(vxe)
            self._make_hao_esp(hao)

            subprocess.run(
                [
                    sys.executable, '-I', str(SCRIPT),
                    '--vostroxe-efi', str(vxe),
                    '--hao-esp', str(hao),
                    '--out', str(out),
                    '--apfs', str(dummy_apfs),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            self.assertTrue((out / 'OC/Kexts/IntelCommpage.kext/marker').is_file())
            self.assertTrue((out / 'OC/Kexts/HaoExec.kext/marker').is_file())
            self.assertTrue((out / 'OC/Drivers/apfs.efi').is_file())

            safe = plistlib.loads((out / 'OC/config-safe.plist').read_bytes())
            accel = plistlib.loads((out / 'OC/config-accel.plist').read_bytes())
            rec = plistlib.loads((out / 'OC/config-recovery.plist').read_bytes())
            active = plistlib.loads((out / 'OC/config.plist').read_bytes())

            self.assertEqual(active, safe)

            # Recovery stays clean of Darwin 27 patches/kexts
            self.assertEqual(rec['Kernel']['Patch'], [])
            self.assertNotIn('HaoExec.kext', [k['BundlePath'] for k in rec['Kernel']['Add']])
            self.assertTrue(rec['UEFI']['APFS']['GlobalConnect'])
            self.assertTrue(any(d.get('Path') == 'apfs.efi' and d.get('Enabled') for d in rec['UEFI']['Drivers']))

            # Safe & accel carry CryptexFixup after Lilu, IntelCommpage, HaoExec, and Darwin 27 scoped patches
            for cfg, want_ng in ((safe, False), (accel, True)):
                kexts = {k['BundlePath']: k for k in cfg['Kernel']['Add']}
                order = [k['BundlePath'] for k in cfg['Kernel']['Add']]
                self.assertEqual(order[:3], ['Lilu.kext', 'CryptexFixup.kext', 'IntelCommpage.kext'])
                self.assertIn('HaoExec.kext', kexts)
                self.assertEqual(kexts['NootedGreen.kext']['Enabled'], want_ng)
                self.assertEqual(len(cfg['Kernel']['Patch']), 1)
                self.assertEqual(cfg['Kernel']['Patch'][0]['Comment'], 'early-vm-test')
                self.assertEqual(cfg['Kernel']['Patch'][0]['MinKernel'], '27.0.0')
                self.assertEqual(cfg['Kernel']['Patch'][0]['MaxKernel'], '27.99.99')
                args = cfg['NVRAM']['Add'][APPLE_NVRAM]['boot-args'].split()
                for flag in ('-lilubetaall', '-crypt_force_avx', 'amfi_get_out_of_my_way=1',
                             'amfi_force_policy=8', 'auxKCAtBoot=false'):
                    self.assertIn(flag, args)
                self.assertEqual(cfg['UEFI']['APFS']['MinDate'], -1)
                self.assertEqual(cfg['UEFI']['APFS']['MinVersion'], -1)
                self.assertTrue(cfg['UEFI']['APFS']['GlobalConnect'])
                self.assertTrue(any(d.get('Path') == 'apfs.efi' and d.get('Enabled') for d in cfg['UEFI']['Drivers']))
                self.assertEqual(cfg['Misc']['Debug']['Target'], 65)
                if want_ng:
                    self.assertNotIn('-igfxvesa', args)
                    self.assertIn('agdpmod=ignore', args)
                    self.assertIn('ngreenhdmiaux=1', args)
                    self.assertEqual(cfg['PlatformInfo']['Generic']['SystemProductName'], 'MacBookPro16,2')
                else:
                    self.assertIn('-igfxvesa', args)
                    self.assertEqual(cfg['PlatformInfo']['Generic']['SystemProductName'], 'iMac20,1')

    def test_tgl_prelink_kexts_only_in_accel(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            vxe = tmp / 'vxe-efi'
            hao = tmp / 'hao-esp'
            tgl = tmp / 'tgl-kexts'
            out = tmp / 'out-efi'
            self._make_vostroxe_efi(vxe)
            self._make_hao_esp(hao)
            expected_tgl = [
                'IOGraphicsFamily.kext',
                'IOAcceleratorFamily2.kext',
                'AppleGraphicsDeviceControl.kext',
                'HookCase.kext',
                'AppleIntelTGLGraphicsFramebuffer.kext',
                'AppleIntelTGLGraphics.kext',
            ]
            for name in expected_tgl:
                (tgl / name).mkdir(parents=True)
                (tgl / name / 'marker').write_text(name)

            subprocess.run(
                [
                    sys.executable, '-I', str(SCRIPT),
                    '--vostroxe-efi', str(vxe),
                    '--hao-esp', str(hao),
                    '--tgl-kexts', str(tgl),
                    '--default-accel',
                    '--out', str(out),
                ],
                check=True,
                capture_output=True,
                text=True,
            )

            for name in expected_tgl:
                self.assertTrue((out / 'OC/Kexts' / name / 'marker').is_file())

            safe = plistlib.loads((out / 'OC/config-safe.plist').read_bytes())
            accel = plistlib.loads((out / 'OC/config-accel.plist').read_bytes())
            rec = plistlib.loads((out / 'OC/config-recovery.plist').read_bytes())
            active = plistlib.loads((out / 'OC/config.plist').read_bytes())

            self.assertEqual(active, accel)
            accel_order = [k['BundlePath'] for k in accel['Kernel']['Add']]
            ng_idx = accel_order.index('NootedGreen.kext')
            self.assertEqual(accel_order[ng_idx + 1:ng_idx + 1 + len(expected_tgl)], expected_tgl)
            for k in accel['Kernel']['Add'][ng_idx + 1:ng_idx + 1 + len(expected_tgl)]:
                self.assertTrue(k['Enabled'])
                self.assertEqual((k['MinKernel'], k['MaxKernel']), ('27.0.0', '27.99.99'))
            for cfg in (safe, rec):
                names = [k['BundlePath'] for k in cfg['Kernel']['Add']]
                for name in expected_tgl:
                    self.assertNotIn(name, names)


if __name__ == '__main__':
    unittest.main()
