"""stick.py with a fake diskutil: partitioning makes two folders as the stick's mounted volumes; no real disk."""
import io
import os
from pathlib import Path
import plistlib
import re
import subprocess
import sys
import tarfile
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
TOOL = HERE.parent
sys.path.insert(0, str(TOOL / 'src'))
import stick as STICK      # noqa: E402

REPO = TOOL.parents[1]
NV = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
IAS = '4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14'


def oclp_config():
    return {'Misc': {'Security': {'DmgLoading': 'Signed', 'ScanPolicy': 0x10F0103}, 'Boot': {'LauncherOption': 'Full',
                                                                                            'HideAuxiliary': True}},
            'UEFI': {'Quirks': {'RequestBootVarRouting': True}},
            'Kernel': {'Add': [{'BundlePath': 'Lilu.kext', 'Enabled': True},
                               {'BundlePath': 'AutoPkgInstaller.kext', 'Enabled': True}], 'Patch': []},
            'NVRAM': {'Add': {NV: {'boot-args': 'keepsyms=1 -lilubetaall'},
                              '4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102': {'revpatch': 'sbvmm,asset'},
                              IAS: {'IASInstallPhaseList': b'x', 'DefaultBackgroundColor': b'\0\0\0\0'}},
                      'Delete': {IAS: ['IASInstallPhaseList', 'DefaultBackgroundColor']}}}


def esp_tar(path, config=None):
    with tarfile.open(path, 'w') as t:
        for name, data in (('EFI/OC/OpenCore.efi', b'MZ opencore'), ('EFI/OC/.contentFlavour', b'OCLP'),
                           ('EFI/OC/Kexts/Lilu.kext/Contents/Info.plist', b'<plist/>'),
                           ('EFI/OC/config.plist', plistlib.dumps(config or oclp_config())),
                           ('System/Library/CoreServices/boot.efi', b'boot')):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            t.addfile(info, io.BytesIO(data))


class FakeHost:
    """diskutil partitionDisk makes ROOT/HAOBOOT and ROOT/HAO; list/info describe them as mounted there."""

    def __init__(self, root):
        self.root, self.calls, self.partitioned = Path(root), [], False

    def run(self, argv, check=True, timeout=120):
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        out = b''
        if argv[:2] == ['diskutil', 'partitionDisk']:
            for name in ('HAOBOOT', 'HAO'):
                (self.root / name).mkdir()
            self.partitioned = True
        elif argv[:3] == ['diskutil', 'list', '-plist']:
            parts = [{'DeviceIdentifier': 'disk4s1', 'VolumeName': 'EFI'}]
            if self.partitioned:
                parts += [{'DeviceIdentifier': 'disk4s2', 'VolumeName': 'HAOBOOT'},
                          {'DeviceIdentifier': 'disk4s3', 'VolumeName': 'HAO'}]
            out = plistlib.dumps({'AllDisksAndPartitions': [{'DeviceIdentifier': 'disk4', 'Partitions': parts}]})
        elif argv[:3] == ['diskutil', 'info', '-plist']:
            name = {'disk4s2': 'HAOBOOT', 'disk4s3': 'HAO'}[argv[3]]
            out = plistlib.dumps({'MountPoint': str(self.root / name)})
        elif argv[:2] == ['hdiutil', 'attach']:
            out = plistlib.dumps({'system-entities': [{'dev-entry': '/dev/disk7s1'}, {'dev-entry': '/dev/disk7'}]})
        return subprocess.CompletedProcess(argv, 0, out, b'')


class StickTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = Path(self.tmp.name)
        self.bs = self.d / 'BaseSystem-x86_64.dmg'
        self.bs.write_bytes(b'koly' * 1000)
        self.esp = self.d / 'esp.tar'
        esp_tar(self.esp)
        kit = self.kit = self.d / 'kit'
        for rel, data in (('kit.json', b'{"schema": 1}'), ('py-x86_64/bin/python3.12', b'#!py'),
                          ('hooks/02-userspace/inputs/u/filesystem.dmg', b'U' * 2048),
                          ('hooks/15-identities/inputs/u/filesystem.dmg', b'U' * 2048),
                          ('hooks/15-identities/inputs/u/other.dmg', b'V' * 2048)):
            (kit / rel).parent.mkdir(parents=True, exist_ok=True)
            (kit / rel).write_bytes(data)
        os.symlink('python3.12', kit / 'py-x86_64/bin/python3')
        top = self.top = self.d / 'hao-builder'
        for rel in ('tools/hao/hao', 'pipeline/lock.py', 'store/inputs/huge', 'tools/hao/src/__pycache__/x.pyc',
                    'CLAUDE.md', '.gitignore'):
            (top / rel).parent.mkdir(parents=True, exist_ok=True)
            (top / rel).write_text(rel)
        (top / '.gitignore').write_text('store\nCLAUDE.md\n__pycache__\n')
        git = ['git', '-C', str(top), '-c', 'user.name=t', '-c', 'user.email=t@example.invalid']
        subprocess.run(git + ['init', '-q'], check=True)
        subprocess.run(git + ['add', '.'], check=True)
        self.mnt = self.d / 'Volumes'
        self.mnt.mkdir()
        self.dedupe, STICK.DEDUPE_BYTES = STICK.DEDUPE_BYTES, 1024

    def tearDown(self):
        STICK.DEDUPE_BYTES = self.dedupe
        self.tmp.cleanup()

    def test_writes_both_partitions(self):
        host = FakeHost(self.mnt)
        steps = []
        rec = STICK.write(host, 'disk4', self.bs, self.esp, self.kit, self.top, record={'model': 'MacBookPro9,2'},
                          on_step=steps.append)
        self.assertEqual(host.calls[1][:3], ['diskutil', 'partitionDisk', '/dev/disk4'])
        self.assertEqual(host.calls[1][3:], ['GPT', 'MS-DOS', 'HAOBOOT', '%dM' % STICK.SLACK_MB, 'JHFS+', 'HAO', 'R'])
        self.assertEqual(host.calls[-1], ['diskutil', 'unmountDisk', '/dev/disk4'])
        boot, kit = self.mnt / 'HAOBOOT', self.mnt / 'HAO'
        self.assertEqual((boot / 'EFI/BOOT/BOOTX64.EFI').read_bytes(), b'MZ opencore')
        self.assertFalse((boot / 'EFI/BOOT/OpenCore.efi').exists())
        self.assertFalse((boot / 'EFI/BOOT/.contentFlavour').exists())
        self.assertTrue((boot / 'EFI/BOOT/Kexts/Lilu.kext/Contents/Info.plist').is_file())
        self.assertFalse((boot / 'System').exists())
        self.assertEqual((boot / 'com.apple.recovery.boot/BaseSystem.dmg').read_bytes(), self.bs.read_bytes())
        c = plistlib.loads((boot / 'EFI/BOOT/config.plist').read_bytes())
        self.assertEqual(c['Misc']['Security']['DmgLoading'], 'Any')
        self.assertEqual(c['NVRAM']['Add'][NV]['boot-args'], 'keepsyms=1 -lilubetaall amfi=0x80')
        self.assertEqual(rec['boot_args'], 'keepsyms=1 -lilubetaall amfi=0x80')
        self.assertEqual(rec['model'], 'MacBookPro9,2')
        # hao without its store, git and caches; the kit, symlinks kept, the userspace twin a hard link
        self.assertTrue((kit / 'hao/tools/hao/hao').is_file())
        self.assertTrue((kit / 'hao/pipeline/lock.py').is_file())
        for gone in ('store', '.git', 'tools/hao/src/__pycache__', 'CLAUDE.md'):
            self.assertFalse((kit / 'hao' / gone).exists(), gone)
        self.assertEqual(os.readlink(kit / 'kit/py-x86_64/bin/python3'), 'python3.12')
        a, b = kit / 'kit/hooks/02-userspace/inputs/u/filesystem.dmg', kit / 'kit/hooks/15-identities/inputs/u/filesystem.dmg'
        self.assertEqual(a.stat().st_ino, b.stat().st_ino)
        self.assertNotEqual((kit / 'kit/hooks/15-identities/inputs/u/other.dmg').stat().st_ino, a.stat().st_ino)
        self.assertEqual(rec['hard_links'], [['kit/hooks/15-identities/inputs/u/filesystem.dmg',
                                              'kit/hooks/02-userspace/inputs/u/filesystem.dmg']])
        self.assertEqual(rec['kit_bytes'], sum(p.stat().st_size for p in self.kit.rglob('*')
                                               if p.is_file() and not p.is_symlink()) - 2048)
        # the launchers run hao with the kit's CPython
        for name, cmd in (('install', 'install --kit "$D/kit"'), ('report', 'report --output "$D/reports/')):
            text = (kit / name).read_text()
            self.assertTrue(os.access(kit / name, os.X_OK))
            self.assertIn('"$PY/bin/python3.12" -I "$D/hao/tools/hao/hao" ' + cmd, text)
        self.assertTrue((kit / 'reports').is_dir())
        self.assertIn('erase /dev/disk4', steps[0])

    def test_launcher_runs_hao_with_the_kits_python(self):
        host = FakeHost(self.mnt)
        STICK.write(host, 'disk4', self.bs, self.esp, self.kit, self.top)
        kit = self.mnt / 'HAO'
        machine = subprocess.run(['uname', '-m'], capture_output=True, text=True).stdout.strip()
        py = kit / 'kit' / ('py-x86_64' if machine == 'x86_64' else 'py') / 'bin'
        py.mkdir(parents=True, exist_ok=True)
        (py / 'python3.12').write_text('#!/bin/sh\necho "$@"\n')
        (py / 'python3.12').chmod(0o755)
        out = subprocess.run([str(kit / 'install'), '/dev/disk0'], capture_output=True, text=True, check=True).stdout
        self.assertEqual(out.split(), ['-I', str(kit / 'hao/tools/hao/hao'), 'install', '--kit', str(kit / 'kit'),
                                       '/dev/disk0'])

    def test_release_archive_without_git(self):
        import shutil
        shutil.rmtree(self.top / '.git')
        files = STICK.hao_files(self.top)
        self.assertIn('tools/hao/hao', files)
        self.assertIn('CLAUDE.md', files)            # an archive has none; what it holds is copied
        self.assertFalse([f for f in files if f.startswith(('store/', '.git/')) or '__pycache__' in f])

    def test_refuses_a_folder_that_is_no_kit(self):
        (self.kit / 'kit.json').unlink()
        with self.assertRaises(STICK.StickError):
            STICK.write(FakeHost(self.mnt), 'disk4', self.bs, self.esp, self.kit, self.top)

    def test_boot_size_is_netrecs_formula(self):
        self.assertEqual(STICK.boot_mb(1462025716, 40 * STICK.MB), 1394 * 102 // 100 + 40 + 256)

    def test_attach_image_makes_a_sparse_raw_disk(self):
        host = FakeHost(self.mnt)
        img = self.d / 'out' / 'stick.img'
        self.assertEqual(STICK.attach_image(host, img, 64 * 10 ** 9), 'disk7')
        self.assertEqual(img.stat().st_size, 64 * 10 ** 9)
        self.assertLess(img.stat().st_blocks * 512, 10 ** 6)
        self.assertIn('diskimage-class=CRawDiskImage', host.calls[0])
        with self.assertRaises(STICK.StickError):
            STICK.attach_image(host, img, 10)

    def test_config_change_is_netrecs(self):
        """The stick's OpenCore change and pipeline/stages/netrec.sh's must not drift apart: run netrec's own
        Python (its heredoc) and ours on the same config."""
        text = (REPO / 'pipeline/stages/netrec.sh').read_text()
        script = re.search(r"python3 -I - \$W/mnt/EFI/BOOT/config.plist <<'EOF'\n(.*?)\nEOF\n", text, re.S).group(1)
        a, b = self.d / 'a.plist', self.d / 'b.plist'
        a.write_bytes(plistlib.dumps(oclp_config()))
        subprocess.run([sys.executable, '-I', '-', str(a)], input=script.encode(), check=True, capture_output=True)
        b.write_bytes(plistlib.dumps(STICK.opencore_config(oclp_config())))
        self.assertEqual(plistlib.loads(a.read_bytes()), plistlib.loads(b.read_bytes()))


if __name__ == '__main__':
    unittest.main()
