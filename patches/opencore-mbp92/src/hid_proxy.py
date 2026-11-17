"""Put the Bluetooth HID-proxy devices on the in-kernel USB HID driver (fixes #79).

  hid_proxy.py ESP INFO_PLIST

Writes the codeless HIDProxyKernelMatch.kext (INFO_PLIST, src/HIDProxyKernelMatch-Info.plist, is its only file) to
ESP/EFI/OC/Kexts and adds its Kernel.Add entry once.
At boot the BCM20702's HID-proxy functions (05ac:820a keyboard, 05ac:820b mouse) leave when Bluetooth switches to
HCI mode. Matched by the AppleUserHIDDrivers dext, their termination never completes, and the EHCI controller's
next change to power state Off waits for them for good (the wake panic). The kext's personalities outscore the
dext's (IOProbeScore 1) so the kernel's IOUSBHostHIDDevice takes them instead.
"""
from pathlib import Path
import plistlib
import shutil
import sys

NAME = 'HIDProxyKernelMatch.kext'
DEXT_SCORE = 1   # AppleUserHIDDrivers.dext: every USB HID personality has IOProbeScore 1
PROXIES = {0x820a, 0x820b}


def check(plist):
    """The kext is codeless and routes exactly the two HID-proxy interfaces to the kernel HID driver."""
    info = plistlib.loads(plist.read_bytes())
    if 'CFBundleExecutable' in info:
        raise ValueError(f'{NAME}: must be codeless')
    seen = set()
    for name, p in info['IOKitPersonalities'].items():
        if (p.get('IOClass'), p.get('CFBundleIdentifier'), p.get('IOProviderClass')) != (
                'IOUSBHostHIDDevice', 'com.apple.driver.usb.IOUSBHostHIDDevice', 'IOUSBHostInterface'):
            raise ValueError(f'{name}: not the kernel IOUSBHostHIDDevice on IOUSBHostInterface')
        if p.get('idVendor') != 0x05ac or p.get('IOProbeScore', 0) <= DEXT_SCORE:
            raise ValueError(f'{name}: Apple vendor and a probe score above the dext\'s required')
        seen.add(p.get('idProduct'))
    if seen != PROXIES:
        raise ValueError(f'{NAME}: matches {sorted(map(hex, seen))}, want {sorted(map(hex, PROXIES))}')
    return info


def apply(esp, plist):
    check(plist)
    config_path = esp/'EFI/OC/config.plist'
    config = plistlib.loads(config_path.read_bytes())
    destination = esp/'EFI/OC/Kexts'/NAME
    shutil.rmtree(destination, ignore_errors=True)
    (destination/'Contents').mkdir(parents=True)
    shutil.copyfile(plist, destination/'Contents/Info.plist')   # FAT: bytes only
    config['Kernel']['Add'] = [x for x in config['Kernel']['Add'] if x.get('BundlePath') != NAME]
    config['Kernel']['Add'].append(dict(
        Arch='x86_64', BundlePath=NAME, Comment='hao: Bluetooth HID-proxy devices on the kernel HID driver (#79)',
        Enabled=True, ExecutablePath='', PlistPath='Contents/Info.plist', MinKernel='27.0.0', MaxKernel='27.99.99'))
    config_path.write_bytes(plistlib.dumps(config))
    print(f'HID proxy: {NAME} in Kernel.Add (05ac:820a, 05ac:820b on IOUSBHostHIDDevice)')


if __name__ == '__main__':
    apply(Path(sys.argv[1]), Path(sys.argv[2]))
