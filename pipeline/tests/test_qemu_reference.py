"""pipeline/unpack/qemu-reference (row qemu_reference_efi) on fixture zips and a fixture OCLP source (no network); the
tracked config carries no machine identity; with the store's rows, the made tree is the pinned row."""
import io
import json
import os
from pathlib import Path
import plistlib
import runpy
import stat
import tarfile
import tempfile
import unittest
import zipfile

TOP = Path(__file__).resolve().parents[2]
Q = runpy.run_path(str(TOP/'pipeline/unpack/qemu-reference'))
LOCK = runpy.run_path(str(TOP/'pipeline/lock.py'))
INPUTS = ('opencore_release', 'oclp_source', 'ocbinarydata_hfsplus', 'virtualsmc_release')


def zip_bytes(members):
    b = io.BytesIO()
    with zipfile.ZipFile(b, 'w') as z:
        for name, data in members.items():
            z.writestr(name, data)
    return b.getvalue()


def fixtures(root):
    opencore = root/'OpenCore-RELEASE.zip'
    opencore.write_bytes(zip_bytes({'X64/EFI/BOOT/BOOTx64.efi': b'boot', 'X64/EFI/BOOT/.contentVisibility': b'Disabled',
                                    'X64/EFI/BOOT/.contentFlavour': b'OpenCore', 'X64/EFI/OC/OpenCore.efi': b'core',
                                    'X64/EFI/OC/Drivers/OpenRuntime.efi': b'runtime',
                                    'X64/EFI/OC/Drivers/OpenCanopy.efi': b'not in the tree'}))
    oclp = root/'oclp-source.tar'
    kext = lambda name, extra={}: zip_bytes(dict({
        '%s/Contents/Info.plist' % name: b'info ' + name.encode(),
        '%s/Contents/MacOS/%s' % (name, name[:-5]): b'bin ' + name.encode(),
        '__MACOSX/%s/Contents/._Info.plist' % name: b'fork'}, **extra))
    members = {'payloads/Drivers/apfs_aligned.efi': b'apfs',
               'payloads/Kexts/Misc/AppleIntelCPUPowerManagement-v1.0.0.zip': kext('AppleIntelCPUPowerManagement.kext'),
               'payloads/Kexts/Misc/AppleIntelCPUPowerManagementClient-v1.0.0.zip':
                   kext('AppleIntelCPUPowerManagementClient.kext'),
               'payloads/Kexts/Acidanthera/Lilu-v1.7.2-RELEASE.zip':
                   kext('Lilu.kext', {'Lilu.kext.dSYM/Contents/Info.plist': b'dsym'})}
    with tarfile.open(oclp, 'w') as t:
        for name, data in members.items():
            info = tarfile.TarInfo(name); info.size = len(data)
            t.addfile(info, io.BytesIO(data))
    hfs = root/'HfsPlus.efi'
    hfs.write_bytes(b'hfs')
    smc = root/'VirtualSMC-RELEASE.zip'
    smc.write_bytes(zip_bytes({'Kexts/VirtualSMC.kext/Contents/Info.plist': b'smc info',
                               'Kexts/VirtualSMC.kext/Contents/MacOS/VirtualSMC': b'smc',
                               'Kexts/SMCBatteryManager.kext/Contents/Info.plist': b'other',
                               'dSYM/VirtualSMC.kext.dSYM/Contents/Info.plist': b'dsym'}))
    return opencore, oclp, hfs, smc


class Make(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.inputs = fixtures(self.tmp)

    def make(self, out, **kw):
        return Q['make'](self.tmp/out, *self.inputs, **kw)

    def test_layout_and_sources(self):
        record = self.make('out')
        out = self.tmp/'out'
        files = sorted(str(p.relative_to(out)) for p in out.rglob('*') if p.is_file())
        self.assertEqual(files, sorted(['build.json', 'EFI/BOOT/BOOTx64.efi', 'EFI/BOOT/.contentVisibility',
            'EFI/OC/OpenCore.efi', 'EFI/OC/config.plist', 'EFI/OC/Drivers/OpenRuntime.efi',
            'EFI/OC/Drivers/HfsPlus.efi', 'EFI/OC/Drivers/apfs_aligned.efi',
            'EFI/OC/Kexts/AppleIntelCPUPowerManagement.kext/Contents/Info.plist',
            'EFI/OC/Kexts/AppleIntelCPUPowerManagement.kext/Contents/MacOS/AppleIntelCPUPowerManagement',
            'EFI/OC/Kexts/AppleIntelCPUPowerManagementClient.kext/Contents/Info.plist',
            'EFI/OC/Kexts/AppleIntelCPUPowerManagementClient.kext/Contents/MacOS/AppleIntelCPUPowerManagementClient',
            'EFI/OC/Kexts/Lilu.kext/Contents/Info.plist', 'EFI/OC/Kexts/Lilu.kext/Contents/MacOS/Lilu',
            'EFI/OC/Kexts/VirtualSMC.kext/Contents/Info.plist', 'EFI/OC/Kexts/VirtualSMC.kext/Contents/MacOS/VirtualSMC']))
        self.assertEqual((out/'EFI/BOOT/BOOTx64.efi').read_bytes(), b'boot')
        self.assertEqual((out/'EFI/OC/Drivers/HfsPlus.efi').read_bytes(), b'hfs')
        self.assertEqual((out/'EFI/OC/Kexts/Lilu.kext/Contents/MacOS/Lilu').read_bytes(), b'bin Lilu.kext')
        self.assertEqual((out/'EFI/OC/Kexts/VirtualSMC.kext/Contents/MacOS/VirtualSMC').read_bytes(), b'smc')
        self.assertEqual((out/'EFI/OC/config.plist').read_bytes(), Q['CONFIG'].read_bytes())
        self.assertEqual(set(record['files']), set(files) - {'build.json'})
        self.assertEqual(json.loads((out/'build.json').read_text()), record)
        for p in [out, *out.rglob('*')]:
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o755 if p.is_dir() else 0o644, p)

    def test_deterministic(self):
        self.make('a')
        self.make('b')
        os.utime(self.tmp/'b/EFI/OC/OpenCore.efi', (0, 0))
        self.assertEqual(LOCK['content_sha256'](str(self.tmp/'a')), LOCK['content_sha256'](str(self.tmp/'b')))

    def test_refuses_existing_output_and_missing_member(self):
        (self.tmp/'out').mkdir()
        with self.assertRaises(Q['Failed']):
            self.make('out')
        bad = self.tmp/'empty.zip'
        bad.write_bytes(zip_bytes({'X64/EFI/BOOT/BOOTx64.efi': b'boot'}))
        self.inputs = (bad,) + self.inputs[1:]
        self.assertEqual(Q['main']([str(self.tmp/'other'), '--opencore', str(bad), '--oclp-source', str(self.inputs[1]),
                                    '--hfsplus', str(self.inputs[2]), '--virtualsmc', str(self.inputs[3])]), 1)
        self.assertFalse((self.tmp/'other').exists())

    def test_refuses_a_config_with_an_identity(self):
        config = plistlib.loads(Q['CONFIG'].read_bytes())
        config['PlatformInfo']['Generic']['SystemSerialNumber'] = 'C02ABCDEFGHJ'
        (self.tmp/'config.plist').write_bytes(plistlib.dumps(config))
        with self.assertRaisesRegex(Q['Failed'], 'SystemSerialNumber'):
            self.make('out', config=self.tmp/'config.plist')


class TrackedConfig(unittest.TestCase):
    def test_no_identity(self):
        config = plistlib.loads(Q['CONFIG'].read_bytes())
        generic = config['PlatformInfo']['Generic']
        self.assertEqual(Q['identity'](Q['CONFIG'].read_bytes()), [])
        for key in ('SystemSerialNumber', 'MLB', 'SystemUUID'):
            self.assertEqual(generic[key], '', key)
        self.assertFalse(any(generic['ROM']))

    def test_is_what_build_efi_and_opencore_generic_read(self):
        config = plistlib.loads(Q['CONFIG'].read_bytes())
        for section in ('Booter', 'Kernel', 'UEFI'):
            self.assertIn('Quirks', config[section])
        self.assertIn('VirtualSMC.kext', [k['BundlePath'] for k in config['Kernel']['Add']])
        self.assertIn('APFS', config['UEFI'])
        self.assertIn('Drivers', config['UEFI'])


class Row(unittest.TestCase):
    def test_classified_made_on_mac_from_its_downloads(self):
        rows = json.loads((TOP/'pipeline/release-classes.json').read_text())['rows']
        entry = rows['qemu_reference_efi']
        self.assertEqual((entry['class'], entry['producer']), ('made-on-mac', 'pipeline/unpack/qemu-reference'))
        self.assertEqual(sorted(entry['inputs']), sorted(INPUTS))
        for name in ('ocbinarydata_hfsplus', 'virtualsmc_release'):
            self.assertEqual(rows[name]['class'], 'download')
        text = (TOP/'pipeline/make-on-mac').read_text()
        self.assertIn("(['qemu_reference_efi'], qemu_reference)", text)
        for name in INPUTS:
            self.assertIn("I('%s')" % name, text)   # each read from a checked private copy (Run.input)

    def test_store_rows_make_the_pinned_row(self):
        lock = str(TOP/'pipeline/inputs/25G342')
        table = {**LOCK['rows'](str(TOP/'pipeline/inputs/common')), **LOCK['rows'](lock)}
        paths = [table[name][1] for name in INPUTS]
        if not all(os.path.exists(p) for p in paths):
            self.skipTest('needs the rows %s in the store' % ', '.join(INPUTS))
        out = Path(tempfile.mkdtemp())/'tree'
        Q['make'](out, *paths)
        self.assertEqual(LOCK['row_hash'](lock, 'qemu_reference_efi', str(out)), table['qemu_reference_efi'][0])


if __name__ == '__main__':
    unittest.main()
