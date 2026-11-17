"""stages/build-efi.py, base qemu_reference, on a fake OpenCore release zip and a fake reference tree (no OCLP)."""
import hashlib
import json
from pathlib import Path
import plistlib
import runpy
import subprocess
import sys
import tempfile
import unittest
import zipfile

TOP = Path(__file__).resolve().parents[2]
SCRIPT = TOP/'pipeline/stages/build-efi.py'
BUILD = runpy.run_path(str(SCRIPT))
LOCK = runpy.run_path(str(TOP/'pipeline/lock.py'))


def fixtures(root):
    """A reference tree as qemu_reference_efi has it, an OpenCore release zip and a qemu_reference target."""
    ref = root/'reference'
    for name, data in {'EFI/BOOT/BOOTx64.efi': b'ref boot', 'EFI/BOOT/.contentVisibility': b'Disabled',
                       'EFI/OC/OpenCore.efi': b'ref core', 'EFI/OC/Drivers/OpenRuntime.efi': b'ref runtime',
                       'EFI/OC/Drivers/HfsPlus.efi': b'ref hfs', 'EFI/OC/Drivers/apfs_aligned.efi': b'ref apfs',
                       'EFI/OC/Kexts/Lilu.kext/Contents/Info.plist': b'lilu'}.items():
        (ref/name).parent.mkdir(parents=True, exist_ok=True)
        (ref/name).write_bytes(data)
    (ref/'EFI/OC/config.plist').write_bytes(plistlib.dumps({
        'Kernel': {'Add': [dict(BundlePath='Lilu.kext', Enabled=True)]},
        'UEFI': {'Drivers': [dict(Arguments='', Comment='OpenRuntime.efi', Enabled=True, LoadEarly=False,
                                  Path='OpenRuntime.efi')],
                 'APFS': {'EnableJumpstart': True, 'GlobalConnect': False}}}))
    (ref/'build.json').write_text('{"not": "copied"}')
    archive = root/'OpenCore-1.0.5-DEBUG.zip'
    with zipfile.ZipFile(archive, 'w') as z:
        z.writestr('X64/EFI/BOOT/BOOTx64.efi', b'release boot')
        z.writestr('X64/EFI/OC/OpenCore.efi', b'release core')
        z.writestr('X64/EFI/OC/Drivers/OpenRuntime.efi', b'release runtime')
        z.writestr('X64/EFI/OC/Drivers/OpenCanopy.efi', b'not in the reference')
        z.writestr('X64/EFI/OC/Tools/OpenShell.efi', b'not in the reference')
    target = root/'generic.json'
    target.write_text(json.dumps(dict(model='iMac20,1', efi_build=dict(base='qemu_reference'))))
    return ref, archive, target


class QemuReference(unittest.TestCase):
    def test_layout_and_record(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ref, archive, target = fixtures(root)
            before = LOCK['content_sha256'](str(ref))
            record = BUILD['build'](None, None, target, 'unused', archive, root/'out/esp', reference=ref)
            out = root/'out/esp'
            self.assertEqual(sorted(str(p.relative_to(out)) for p in out.rglob('*') if p.is_file()), [
                'EFI/BOOT/.contentVisibility', 'EFI/BOOT/BOOTx64.efi', 'EFI/OC/Drivers/HfsPlus.efi',
                'EFI/OC/Drivers/OpenRuntime.efi', 'EFI/OC/Drivers/apfs_aligned.efi', 'EFI/OC/Kexts/Lilu.kext/Contents/Info.plist',
                'EFI/OC/OpenCore.efi', 'EFI/OC/config.plist'])
            # the release's binaries where the reference has the same path; the reference's own drivers kept
            self.assertEqual((out/'EFI/BOOT/BOOTx64.efi').read_bytes(), b'release boot')
            self.assertEqual((out/'EFI/OC/OpenCore.efi').read_bytes(), b'release core')
            self.assertEqual((out/'EFI/OC/Drivers/OpenRuntime.efi').read_bytes(), b'release runtime')
            self.assertEqual((out/'EFI/OC/Drivers/HfsPlus.efi').read_bytes(), b'ref hfs')
            config = plistlib.loads((out/'EFI/OC/config.plist').read_bytes())
            self.assertEqual([d['Path'] for d in config['UEFI']['Drivers']], ['OpenRuntime.efi', 'apfs_aligned.efi'])
            self.assertTrue(config['UEFI']['APFS']['GlobalConnect'])
            self.assertEqual(config['Kernel']['Add'], [dict(BundlePath='Lilu.kext', Enabled=True)])
            self.assertEqual(LOCK['content_sha256'](str(ref)), before)     # the row is read, never changed
            self.assertEqual([p.name for p in (root/'out').iterdir()], ['esp'])  # no temporary left
            self.assertEqual(record['base'], 'qemu_reference')
            self.assertEqual(record['operation'], 'qemu-reference-base-efi')
            self.assertEqual((record['model'], record['opencore_version'], record['opencore_variant']),
                             ('iMac20,1', '1.0.5', 'DEBUG'))
            self.assertEqual(record['opencore_archive_sha256'], hashlib.sha256(archive.read_bytes()).hexdigest())
            self.assertEqual(record['reference_sha256'], before)
            self.assertEqual(record['target_sha256'], hashlib.sha256(target.read_bytes()).hexdigest())
            self.assertEqual(record['builder_sha256'], hashlib.sha256(SCRIPT.read_bytes()).hexdigest())
            self.assertEqual(list(record['shared_sha256']), ['tools/kernel-foundation/vm_esp.py'])
            self.assertEqual(record['opencore_replaced'], ['EFI/BOOT/BOOTx64.efi', 'EFI/OC/Drivers/OpenRuntime.efi',
                                                           'EFI/OC/OpenCore.efi'])
            self.assertEqual(record['files']['EFI/OC/OpenCore.efi'], hashlib.sha256(b'release core').hexdigest())
            self.assertNotIn('settings', record)

    def test_command_line_writes_the_record(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ref, archive, target = fixtures(root)
            result = subprocess.run([sys.executable, '-I', '-B', str(SCRIPT), '--source', root/'no-oclp',
                                     '--target', target, '--revision', 'fd83bda09', '--opencore', archive,
                                     '--reference', ref, '--out', root/'esp', '--record', root/'base-efi.json'],
                                    capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            record = json.loads((root/'base-efi.json').read_text())
            self.assertEqual(record['base'], 'qemu_reference')
            self.assertTrue((root/'esp/EFI/BOOT/BOOTx64.efi').is_file())

    def test_refusals(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            ref, archive, target = fixtures(root)
            def build(recipe, reference=ref, out='esp'):
                target.write_text(json.dumps(recipe))
                return BUILD['build'](None, None, target, 'r', archive, root/out, reference=reference)
            with self.assertRaisesRegex(ValueError, "generic: unknown \"efi_build\" base 'harvested'"):
                build(dict(model='iMac20,1', efi_build=dict(base='harvested')))
            with self.assertRaisesRegex(ValueError, 'base qemu_reference takes no settings'):
                build(dict(model='iMac20,1', efi_build=dict(base='qemu_reference', settings={})))
            with self.assertRaisesRegex(ValueError, 'needs --reference'):
                build(dict(model='iMac20,1', efi_build=dict(base='qemu_reference')), reference=None)
            with self.assertRaisesRegex(ValueError, '--reference is for "efi_build" base qemu_reference only'):
                build(dict(model='MacBookPro9,2', efi_build=dict(settings={})))
            (ref/'EFI/BOOT/BOOTx64.efi').unlink()
            with self.assertRaisesRegex(ValueError, 'has no EFI/BOOT/BOOTx64.efi'):
                build(dict(model='iMac20,1', efi_build=dict(base='qemu_reference')))
            self.assertFalse((root/'esp').exists())

    def test_real_rows(self):
        """With the store: the generic target's ESP from the real qemu_reference_efi and opencore_release rows."""
        common = TOP/'pipeline/inputs/25G342'
        try:
            ref = Path(LOCK['path'](str(common), 'qemu_reference_efi'))
            archive = Path(LOCK['path'](str(common), 'opencore_release'))
        except SystemExit:
            self.skipTest('store rows qemu_reference_efi/opencore_release not present')
        with tempfile.TemporaryDirectory() as folder:
            BUILD['build'](None, None, TOP/'pipeline/targets/generic.json', 'r', archive, Path(folder)/'esp',
                           reference=ref)
            esp = Path(folder)/'esp'
            for name in ('EFI/BOOT/BOOTx64.efi', 'EFI/OC/OpenCore.efi', 'EFI/OC/config.plist',
                         'EFI/OC/Kexts/Lilu.kext', 'EFI/OC/Kexts/VirtualSMC.kext'):
                self.assertTrue((esp/name).exists(), name)
            self.assertFalse((esp/'System').exists())


if __name__ == '__main__':
    unittest.main()
