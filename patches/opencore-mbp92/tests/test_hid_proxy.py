import importlib.util
from pathlib import Path
import plistlib
import tempfile
import unittest

HERE = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('hid_proxy', HERE/'src/hid_proxy.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
PLIST = HERE/'src/HIDProxyKernelMatch-Info.plist'


def winner(personalities, interface):
    """The personality IOKit picks for an interface: every key present must match, the highest IOProbeScore wins."""
    keys = ('idVendor', 'idProduct', 'bConfigurationValue', 'bInterfaceNumber', 'bInterfaceClass',
            'bInterfaceSubClass', 'bInterfaceProtocol')
    fits = [p for p in personalities if all(p[k] == interface[k] for k in keys if k in p)]
    return max(fits, key=lambda p: p.get('IOProbeScore', 0))


class HIDProxy(unittest.TestCase):
    def test_proxies_go_to_the_kernel_driver_not_the_dext(self):
        # AppleUserHIDDrivers.dext's generic keyboard personality (IOProbeScore 1) won both on every recorded boot;
        # the proxies' termination then never completed (laptop ioreg: inactive, busy 2) and EHCI's power-off waited.
        dext = dict(IOClass='AppleUserHIDDevice', IOProbeScore=1, bInterfaceClass=3, bInterfaceSubClass=1,
                    bInterfaceProtocol=1)
        kernel = dict(IOClass='IOUSBHostHIDDevice', bInterfaceClass=3, bInterfaceSubClass=1, bInterfaceProtocol=1)
        ours = list(plistlib.loads(PLIST.read_bytes())['IOKitPersonalities'].values())
        for product in (0x820a, 0x820b):
            proxy = dict(idVendor=0x05ac, idProduct=product, bConfigurationValue=1, bInterfaceNumber=0,
                         bInterfaceClass=3, bInterfaceSubClass=1, bInterfaceProtocol=1)
            self.assertEqual(winner([dext, kernel], proxy)['IOClass'], 'AppleUserHIDDevice')   # without the kext
            self.assertEqual(winner([dext, kernel] + ours, proxy)['IOClass'], 'IOUSBHostHIDDevice')
        # The top case (05ac:0253) and any other keyboard keep their drivers.
        other = dict(idVendor=0x05ac, idProduct=0x0253, bConfigurationValue=1, bInterfaceNumber=0,
                     bInterfaceClass=3, bInterfaceSubClass=1, bInterfaceProtocol=1)
        self.assertEqual(winner([dext, kernel] + ours, other)['IOClass'], 'AppleUserHIDDevice')

    def test_kext_is_codeless_and_checked(self):
        module.check(PLIST)
        with tempfile.TemporaryDirectory() as directory:
            bad = Path(directory)/'Info.plist'
            info = plistlib.loads(PLIST.read_bytes())
            next(iter(info['IOKitPersonalities'].values()))['IOProbeScore'] = 1
            bad.write_bytes(plistlib.dumps(info))
            with self.assertRaises(ValueError):
                module.check(bad)
            info = plistlib.loads(PLIST.read_bytes())
            info['CFBundleExecutable'] = 'Code'
            bad.write_bytes(plistlib.dumps(info))
            with self.assertRaises(ValueError):
                module.check(bad)

    def test_apply_adds_one_entry_and_the_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            esp = Path(directory)
            (esp/'EFI/OC/Kexts').mkdir(parents=True)
            config = esp/'EFI/OC/config.plist'
            config.write_bytes(plistlib.dumps({'Kernel': {'Add': [dict(BundlePath='Lilu.kext', Enabled=True)]}}))
            module.apply(esp, PLIST)
            module.apply(esp, PLIST)   # a re-run keeps one entry
            added = plistlib.loads(config.read_bytes())['Kernel']['Add']
            self.assertEqual([x['BundlePath'] for x in added], ['Lilu.kext', module.NAME])
            self.assertEqual(added[1]['ExecutablePath'], '')
            self.assertTrue(added[1]['Enabled'])
            self.assertEqual((esp/'EFI/OC/Kexts'/module.NAME/'Contents/Info.plist').read_bytes(),
                             PLIST.read_bytes())
            self.assertEqual([p.name for p in (esp/'EFI/OC/Kexts'/module.NAME).rglob('*') if p.is_file()],
                             ['Info.plist'])


if __name__ == '__main__':
    unittest.main()
