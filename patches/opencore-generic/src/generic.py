"""The generic model's part of an image's OpenCore: virtual machines and non-Apple PCs, graphics in software.

  generic.py ESP REFERENCE

ESP is the image's EFI partition (EFI/OC/config.plist as pipeline/stages/build-efi.py made it for the generic target).
REFERENCE is the row qemu_reference_efi: the OpenCore tree tested on OVMF (QEMU's UEFI), the base of
tools/kernel-foundation vm_esp.py. This sets, in place:

- PlatformInfo: SMBIOS iMac20,1 (a model Tahoe supports natively, so its donors and OCLP's base config fit it), created
  on firmware that has none (UpdateSMBIOSMode Create). Serial, board serial (MLB), system UUID and ROM are generated for
  this image the first time and kept after; they are random, not Apple-issued, so Apple services that check them
  (iMessage, FaceTime) need the user's own valid values.
- VirtualSMC.kext (Acidanthera 1.3.8, from the reference): non-Apple firmware has no SMC, and macOS needs one. It
  conflicts with a real Mac's SMC: this pack is never for Mac hardware.
- The reference's Booter, Kernel and UEFI quirks: each quirk the reference turns on is set to its value (only quirks
  this OpenCore's config knows).

hao-opencore runs next: the Darwin 27 kernel repairs, IntelCommpage, HaoExec and boot-args, and the check that every
element of the finished config has a recorded reason (src/config-reasons.json there).
"""
import plistlib
import secrets
import shutil
import sys
import uuid
from pathlib import Path

PRODUCT = 'iMac20,1'
SECTIONS = ('Booter', 'Kernel', 'UEFI')
SMC = 'VirtualSMC.kext'
ALNUM = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ'      # serial characters (no I, no O)


def on(value):
    return value is True or (isinstance(value, int) and not isinstance(value, bool) and value > 0)


def quirks(config, reference):
    """{section: [quirk, ...]} set from the reference: every quirk it turns on that this config also has."""
    changed = {}
    for section in SECTIONS:
        have, ref = config[section]['Quirks'], reference[section]['Quirks']
        for name, value in sorted(ref.items()):
            if on(value) and name in have and have[name] != value:
                have[name] = value
                changed.setdefault(section, []).append(name)
    return changed


def add_smc(config, esp, reference_root):
    """Copy VirtualSMC.kext from the reference into the ESP and load it right after Lilu."""
    add = config['Kernel']['Add']
    names = [k['BundlePath'] for k in add]
    if 'Lilu.kext' not in names:
        raise SystemExit('opencore-generic: the config loads no Lilu.kext; VirtualSMC needs it')
    entry, = [k for k in plistlib.loads((reference_root/'EFI/OC/config.plist').read_bytes())['Kernel']['Add']
              if k['BundlePath'] == SMC]
    dest = esp/'EFI/OC/Kexts'/SMC
    if dest.exists():
        shutil.rmtree(dest)
    shutil.copytree(reference_root/'EFI/OC/Kexts'/SMC, dest)
    add[:] = [k for k in add if k['BundlePath'] != SMC]
    add.insert([k['BundlePath'] for k in add].index('Lilu.kext') + 1, dict(entry, Enabled=True))


def serial(length):
    return ''.join(secrets.choice(ALNUM) for _ in range(length))


def platform(config):
    """SMBIOS iMac20,1, created; identity values generated once per image and kept after."""
    info = config.setdefault('PlatformInfo', {})
    generic = info.setdefault('Generic', {})
    fresh = generic.get('SystemProductName') != PRODUCT or not generic.get('SystemSerialNumber')
    info.update(Automatic=True, UpdateDataHub=True, UpdateNVRAM=True, UpdateSMBIOS=True, UpdateSMBIOSMode='Create')
    generic.update(SystemProductName=PRODUCT, SpoofVendor=True)
    if fresh:
        generic.update(SystemSerialNumber=serial(12), MLB=serial(17),
                       SystemUUID=str(uuid.uuid4()).upper(), ROM=secrets.token_bytes(6))
    return fresh


def main(argv):
    esp, reference_root = Path(argv[1]), Path(argv[2])
    path = esp/'EFI/OC/config.plist'
    config = plistlib.loads(path.read_bytes())
    reference = plistlib.loads((reference_root/'EFI/OC/config.plist').read_bytes())
    changed = quirks(config, reference)
    add_smc(config, esp, reference_root)
    fresh = platform(config)
    path.write_bytes(plistlib.dumps(config))
    print('opencore-generic: SMBIOS %s (%s), VirtualSMC after Lilu, quirks set: %s' % (
        PRODUCT, 'new identity' if fresh else 'identity kept',
        '; '.join('%s %s' % (s, ', '.join(n)) for s, n in changed.items()) or 'none needed'))
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
