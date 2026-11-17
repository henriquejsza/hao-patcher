"""src/generic.py on a fixture ESP and the real qemu_reference_efi row when the store has it."""
from pathlib import Path
import os
import plistlib
import runpy
import shutil
import tempfile
import unittest

PATCH = Path(__file__).resolve().parents[1]
TOP = PATCH.parents[1]
G = runpy.run_path(str(PATCH/'src/generic.py'))
CR = runpy.run_path(str(TOP/'patches/hao-opencore/src/config_reasons.py'))


def reference(root):
    """A reference tree like the row: config with quirks and a VirtualSMC entry, and the kext."""
    (root/'EFI/OC/Kexts/VirtualSMC.kext/Contents/MacOS').mkdir(parents=True)
    (root/'EFI/OC/Kexts/VirtualSMC.kext/Contents/MacOS/VirtualSMC').write_bytes(b'smc')
    (root/'EFI/OC/config.plist').write_bytes(plistlib.dumps({
        'Booter': {'Quirks': {'SetupVirtualMap': True, 'ProvideMaxSlide': 0, 'OnlyInReference': True}},
        'Kernel': {'Add': [{'BundlePath': 'VirtualSMC.kext', 'Enabled': True, 'Arch': 'x86_64',
                            'ExecutablePath': 'Contents/MacOS/VirtualSMC', 'PlistPath': 'Contents/Info.plist'}],
                   'Quirks': {'DisableIoMapper': True, 'SetApfsTrimTimeout': -1}},
        'UEFI': {'Quirks': {'RequestBootVarRouting': True}}}))


def esp(root, lilu=True):
    (root/'EFI/OC/Kexts').mkdir(parents=True)
    add = [{'BundlePath': 'Lilu.kext', 'Enabled': True}] if lilu else []
    add.append({'BundlePath': 'RestrictEvents.kext', 'Enabled': True})
    (root/'EFI/OC/config.plist').write_bytes(plistlib.dumps({
        'Booter': {'Quirks': {'SetupVirtualMap': False, 'ProvideMaxSlide': 0}},
        'Kernel': {'Add': add, 'Quirks': {'DisableIoMapper': False, 'SetApfsTrimTimeout': -1}},
        'UEFI': {'Quirks': {'RequestBootVarRouting': True}},
        'PlatformInfo': {'Generic': {'SystemProductName': 'MacBookPro9,2'}}}))


class Generic(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, self.tmp)
        reference(self.tmp/'ref'); esp(self.tmp/'esp')

    def run_it(self):
        G['main'](['generic.py', str(self.tmp/'esp'), str(self.tmp/'ref')])
        return plistlib.loads((self.tmp/'esp/EFI/OC/config.plist').read_bytes())

    def test_quirks_smc_and_smbios(self):
        c = self.run_it()
        self.assertTrue(c['Booter']['Quirks']['SetupVirtualMap'])
        self.assertTrue(c['Kernel']['Quirks']['DisableIoMapper'])
        self.assertNotIn('OnlyInReference', c['Booter']['Quirks'])         # only quirks this config knows
        self.assertEqual([k['BundlePath'] for k in c['Kernel']['Add']], ['Lilu.kext', 'VirtualSMC.kext', 'RestrictEvents.kext'])
        self.assertTrue((self.tmp/'esp/EFI/OC/Kexts/VirtualSMC.kext/Contents/MacOS/VirtualSMC').is_file())
        g = c['PlatformInfo']['Generic']
        self.assertEqual((g['SystemProductName'], c['PlatformInfo']['UpdateSMBIOSMode']), ('iMac20,1', 'Create'))
        self.assertEqual((len(g['SystemSerialNumber']), len(g['MLB']), len(g['ROM'])), (12, 17, 6))
        self.assertTrue(CR['is_generic'](c))

    def test_identity_is_generated_once_and_kept(self):
        first = self.run_it()['PlatformInfo']['Generic']
        again = self.run_it()['PlatformInfo']['Generic']
        self.assertEqual(first, again)
        other = Path(tempfile.mkdtemp()); self.addCleanup(shutil.rmtree, other)
        esp(other/'esp')
        G['main'](['generic.py', str(other/'esp'), str(self.tmp/'ref')])
        third = plistlib.loads((other/'esp/EFI/OC/config.plist').read_bytes())['PlatformInfo']['Generic']
        self.assertNotEqual(first['SystemSerialNumber'], third['SystemSerialNumber'])   # one per image

    def test_refuses_without_lilu(self):
        shutil.rmtree(self.tmp/'esp'); esp(self.tmp/'esp', lilu=False)
        with self.assertRaises(SystemExit):
            self.run_it()

    def test_every_element_it_adds_has_a_generic_reason(self):
        before = set(CR['elements'](plistlib.loads((self.tmp/'esp/EFI/OC/config.plist').read_bytes())))
        reasons = CR['load_reasons']()
        real = Path(TOP/'store/inputs/qemu-reference-20261022')
        if real.is_dir():                                                    # the row's real quirk set
            shutil.rmtree(self.tmp/'ref'); shutil.copytree(real, self.tmp/'ref')
            ref = plistlib.loads((real/'EFI/OC/config.plist').read_bytes())
            config = plistlib.loads((self.tmp/'esp/EFI/OC/config.plist').read_bytes())
            for s in G['SECTIONS']:
                config[s]['Quirks'] = {k: (False if isinstance(v, bool) else v) for k, v in ref[s]['Quirks'].items()}
            (self.tmp/'esp/EFI/OC/config.plist').write_bytes(plistlib.dumps(config))
        added = set(CR['elements'](self.run_it())) - before
        self.assertIn('kext:VirtualSMC.kext', added)
        for e in sorted(added):
            self.assertIn(e, reasons, e)

    def test_apply_runs_before_hao_opencore(self):
        order = [l.split('#')[0].strip() for l in (TOP/'pipeline/order.txt').read_text().splitlines()]
        self.assertLess(order.index('opencore-generic'), order.index('hao-opencore'))


if __name__ == '__main__':
    unittest.main()
