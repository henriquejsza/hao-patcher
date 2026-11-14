"""Writing the USB stick (hao create-installer, step 3 "Write the USB stick"; workflow plan step 17).

The stick has the layout of the NetBoot Recovery (pipeline/stages/netrec.sh), on a USB disk, plus the kit:

  EFI        the EFI system partition diskutil makes on every GPT disk; left empty
  HAOBOOT    FAT32 (Microsoft Basic Data): EFI/BOOT/ = the target's OpenCore (the ESP row of targets/<model>.json, as
             OCLP installs it) with OpenCore.efi as BOOTX64.EFI, so the firmware's Option menu lists the stick, and the
             config changed as netrec.sh changes it (DmgLoading Any, BlessOverride to the Recovery folder, amfi=0x80,
             RequestBootVarRouting off, ...); com.apple.recovery.boot/BaseSystem.dmg = the Recovery OpenCore loads
  HAO        Mac OS Extended (Journaled): `hao/` (this hao folder without its store), `kit/` (golden-run --stage-kit),
             `install` and `report` (launchers for the Recovery's Terminal, run with the kit's own CPython),
             `release.json` when there is one, `stick.json` (what was written, with sha256s), `reports/`

The Recovery is the Tahoe BaseSystem, as DIRECTION's "Recovery on a stick" says until the Golden Gate Recovery is
proven; which BaseSystem.dmg (stock, or the end-user Recovery `pipeline/recovery` builds) is the caller's choice.
Nothing here formats APFS. A dev host writes a stick image file (`--image FILE`): a raw disk attached with hdiutil,
written exactly as a stick, then detached.

    python3 stick.py opencore-config IN.plist OUT.plist      the config change alone (tests compare it with netrec.sh)
"""
import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import subprocess
import sys
import tarfile

BOOT_NAME, KIT_NAME = 'HAOBOOT', 'HAO'
MB = 1024 * 1024
# FAT32 tables, clusters and GPT on top of the BaseSystem and OpenCore (netrec.sh: 2 % + 256 MB; less was too tight)
SLACK_MB = 256
SCAN_POLICY = 0x00000801            # FILE_SYSTEM_LOCK | FS_NTFS (Basic Data partitions), no DEVICE_LOCK
LAUNCHER = '''#!/bin/sh
# %(what)s, from the stick: hao %(cmd)s with the kit's own CPython (the Recovery has no Python).
D=$(cd "$(dirname "$0")" && pwd)
case $(uname -m) in x86_64) PY=$D/kit/py-x86_64 ;; *) PY=$D/kit/py ;; esac
exec "$PY/bin/python3.12" -I "$D/hao/tools/hao/hao" %(cmd)s %(args)s"$@"
'''
LAUNCHERS = {
    'install': dict(what='Install macOS 27', cmd='install', args='--kit "$D/kit" '),
    'report': dict(what='A report for a GitHub issue', cmd='report', args='--output "$D/reports/hao-report-$(date +%Y%m%d-%H%M%S).txt" '),
}
SKIP = {'store', '.git', '__pycache__', '.DS_Store', '.claude'}


class StickError(Exception):
    pass


def opencore_config(c):
    """The stick's OpenCore config from the target's (a plist dict, changed in place and returned): netrec.sh's
    changes, so the stick boots the unsigned BaseSystem.dmg the way the NetBoot Recovery does."""
    sec, boot = c['Misc']['Security'], c['Misc']['Boot']
    sec['DmgLoading'] = 'Any'
    sec['ScanPolicy'] = SCAN_POLICY
    c['Misc']['BlessOverride'] = ['\\com.apple.recovery.boot\\']
    boot['LauncherOption'] = 'Disabled'
    boot['HideAuxiliary'] = False
    c['UEFI']['Quirks']['RequestBootVarRouting'] = False
    for k in c['Kernel']['Add']:
        if k['BundlePath'] == 'AutoPkgInstaller.kext':
            k['Enabled'] = False
    nv = c['NVRAM']['Add']['7C436110-AB2A-4BBB-A880-FE41995C9F82']
    args = nv['boot-args'].split()
    nv['boot-args'] = ' '.join(args + [a for a in ['amfi=0x80'] if a not in args])
    rev = c['NVRAM']['Add'].get('4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102', {})
    if 'revpatch' in rev:
        rev['revpatch'] = ','.join(x for x in rev['revpatch'].split(',') if x != 'sbvmm')
    ias = '4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14'
    for k in ('IASInstallPhaseList', 'IASCurrentInstallPhase', 'DefaultBackgroundColor'):
        c['NVRAM']['Add'].get(ias, {}).pop(k, None)
        if k in c['NVRAM'].get('Delete', {}).get(ias, []) and k != 'DefaultBackgroundColor':
            c['NVRAM']['Delete'][ias].remove(k)
    c['Kernel']['Patch'].append({
        'Arch': 'x86_64', 'Base': '', 'Comment': 'netrec: even boot progress bar (vc_progressmeter_task incr[])',
        'Count': 1, 'Enabled': True, 'Identifier': 'kernel', 'Limit': 0, 'Mask': b'', 'ReplaceMask': b'',
        'MinKernel': '25.0.0', 'MaxKernel': '25.99.99', 'Skip': 0,
        'Find': bytes.fromhex('10271027002000100008800180014000'), 'Replace': (65535).to_bytes(2, 'little') * 8})
    return c


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(8 * MB), b''):
            h.update(block)
    return h.hexdigest()


def tree_bytes(path):
    path = Path(path)
    if path.is_file():
        return path.stat().st_size
    return sum(p.lstat().st_size for p in path.rglob('*') if p.is_file() and not p.is_symlink())


def kit_bytes(path):
    """Bytes a tree takes, each hard-linked file once."""
    seen, total = set(), 0
    for p in Path(path).rglob('*'):
        st = p.lstat()
        if p.is_file() and not p.is_symlink() and (st.st_dev, st.st_ino) not in seen:
            seen.add((st.st_dev, st.st_ino))
            total += st.st_size
    return total


def boot_mb(basesystem_bytes, opencore_bytes):
    """HAOBOOT's size in MB: netrec.sh's formula."""
    return basesystem_bytes // MB * 102 // 100 + opencore_bytes // MB + SLACK_MB


def opencore_files(tar_path, dest):
    """Unpack the ESP row's EFI/OC into DEST (= HAOBOOT/EFI/BOOT), OpenCore.efi as BOOTX64.EFI, the config changed."""
    dest = Path(dest)
    with tarfile.open(tar_path) as t:
        members = [m for m in t.getmembers() if m.name.lstrip('./').startswith('EFI/OC/') and
                   not os.path.isabs(m.name) and '..' not in Path(m.name).parts]
        if not members:
            raise StickError('%s has no EFI/OC' % tar_path)
        for m in members:
            rel = Path(m.name.lstrip('./')).relative_to('EFI/OC')
            out = dest / rel
            if m.isdir():
                out.mkdir(parents=True, exist_ok=True)
            elif m.isfile():
                out.parent.mkdir(parents=True, exist_ok=True)
                with t.extractfile(m) as src, open(out, 'wb') as f:
                    shutil.copyfileobj(src, f)
    if not (dest / 'OpenCore.efi').is_file() or not (dest / 'config.plist').is_file():
        raise StickError('%s: EFI/OC has no OpenCore.efi or config.plist' % tar_path)
    (dest / 'OpenCore.efi').rename(dest / 'BOOTX64.EFI')
    for p in dest.glob('.content*'):          # OCLP's picker flags for its ESP
        p.unlink()
    p = dest / 'config.plist'
    c = opencore_config(plistlib.loads(p.read_bytes()))
    p.write_bytes(plistlib.dumps(c))
    return c


DEDUPE_BYTES = 64 * MB


def hao_files(top):
    """The hao folder's files, relative: in a git checkout the tracked ones (so nothing git ignores, such as local
    notes, reaches a stick), in a release archive every file but the store and caches."""
    top = Path(top)
    if (top / '.git').exists():
        r = subprocess.run(['git', '-C', str(top), 'ls-files', '-z'], stdout=subprocess.PIPE, check=True)
        return sorted(f for f in r.stdout.decode().split('\0') if f and ((top / f).exists() or (top / f).is_symlink()))
    out = []
    for root, dirs, files in os.walk(top):
        dirs[:] = sorted(d for d in dirs if d not in SKIP)
        out += [str((Path(root) / f).relative_to(top)) for f in sorted(files) if f not in SKIP and not f.startswith('._')]
    return out


def copy_hao(top, dest):
    top, dest = Path(top), Path(dest)
    for rel in hao_files(top):
        src, out = top / rel, dest / rel
        if not rel or rel.split('/', 1)[0] in SKIP:
            continue
        out.parent.mkdir(parents=True, exist_ok=True)
        if src.is_symlink():
            os.symlink(os.readlink(src), out)
        elif src.is_file():
            shutil.copy2(src, out)


def copy_tree(src, dest, skip=SKIP, linked=None):
    """SRC into DEST, without the store, git and caches; symlinks kept as links. A file of DEDUPE_BYTES or more whose
    bytes equal one already copied (same size and name, then same sha256) becomes a hard link to it: the kit carries
    the Golden Gate userspace payload in two hooks, APFS clones in the store, 22 GB twice on the stick otherwise.
    LINKED (a list) gets (copy, linked to) for each."""
    src, dest = Path(src), Path(dest)
    seen = {}
    for root, dirs, files in os.walk(src):
        dirs[:] = sorted(d for d in dirs if d not in skip)
        r = Path(root)
        out = dest / r.relative_to(src)
        out.mkdir(parents=True, exist_ok=True)
        for d in list(dirs):
            if (r / d).is_symlink():
                dirs.remove(d)
                os.symlink(os.readlink(r / d), out / d)
        for f in sorted(files):
            if f in skip or f.startswith('._'):
                continue
            if (r / f).is_symlink():
                os.symlink(os.readlink(r / f), out / f)
                continue
            size = (r / f).stat().st_size
            if size >= DEDUPE_BYTES:
                twins = seen.setdefault((size, f), [])
                digest = None
                for first, first_digest in twins:
                    digest = digest or sha256(r / f)
                    if digest == first_digest:
                        os.link(first, out / f)
                        if linked is not None:
                            linked.append((out / f, first))
                        break
                else:
                    shutil.copy2(r / f, out / f)
                    twins.append((out / f, digest or sha256(out / f)))
                continue
            shutil.copy2(r / f, out / f)


def write_boot(mount, basesystem, opencore_tar):
    """HAOBOOT's files. Returns what stick.json records of them."""
    mount = Path(mount)
    c = opencore_files(opencore_tar, mount / 'EFI' / 'BOOT')
    rec = mount / 'com.apple.recovery.boot'
    rec.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(basesystem, rec / 'BaseSystem.dmg')
    for p in mount.rglob('._*'):
        p.unlink()
    want, got = sha256(basesystem), sha256(rec / 'BaseSystem.dmg')
    if want != got:
        raise StickError('BaseSystem.dmg on the stick has sha256 %s, not %s' % (got, want))
    nv = c['NVRAM']['Add']['7C436110-AB2A-4BBB-A880-FE41995C9F82']
    return dict(basesystem_sha256=want, basesystem_bytes=Path(basesystem).stat().st_size,
                opencore_sha256=sha256(opencore_tar), boot_args=nv['boot-args'],
                config_sha256=sha256(mount / 'EFI' / 'BOOT' / 'config.plist'))


def write_kit(mount, kit, hao_top, release=None, record=None):
    """HAO's files: hao, the kit, the launchers, release.json and stick.json."""
    mount, kit = Path(mount), Path(kit)
    if not (kit / 'kit.json').is_file():
        raise StickError('%s is no kit (no kit.json)' % kit)
    copy_hao(hao_top, mount / 'hao')
    linked = []
    copy_tree(kit, mount / 'kit', skip={'.DS_Store', '__pycache__'}, linked=linked)
    for name, fill in LAUNCHERS.items():
        p = mount / name
        p.write_text(LAUNCHER % fill)
        p.chmod(0o755)
    (mount / 'reports').mkdir(exist_ok=True)
    if release:
        shutil.copyfile(release, mount / 'release.json')
    rec = dict(record or {})
    rec.update(schema=1, kit_json_sha256=sha256(kit / 'kit.json'), kit_bytes=kit_bytes(mount / 'kit'),
               hard_links=[[str(Path(a).relative_to(mount)), str(Path(b).relative_to(mount))] for a, b in linked],
               release_sha256=sha256(release) if release else None)
    (mount / 'stick.json').write_text(json.dumps(rec, indent=1, sort_keys=True) + '\n')
    return rec


# -- the disk

def _plist(host, *argv):
    return plistlib.loads(host.run(list(argv), timeout=600).stdout)


def partition(host, disk, boot_size_mb):
    """Erase DISK (a whole disk the caller checked and the user confirmed) into EFI + HAOBOOT (FAT32) + HAO (JHFS+).
    Returns {name: (device, mount point)}."""
    host.run(['diskutil', 'unmountDisk', 'force', '/dev/' + disk], check=False)
    host.run(['diskutil', 'partitionDisk', '/dev/' + disk, 'GPT',
              'MS-DOS', BOOT_NAME, '%dM' % boot_size_mb, 'JHFS+', KIT_NAME, 'R'], timeout=1200)
    found = {}
    for part in _plist(host, 'diskutil', 'list', '-plist', disk).get('AllDisksAndPartitions', [{}])[0].get('Partitions', []):
        name = part.get('VolumeName')
        if name in (BOOT_NAME, KIT_NAME):
            info = _plist(host, 'diskutil', 'info', '-plist', part['DeviceIdentifier'])
            if not info.get('MountPoint'):
                host.run(['diskutil', 'mount', part['DeviceIdentifier']])
                info = _plist(host, 'diskutil', 'info', '-plist', part['DeviceIdentifier'])
            found[name] = (part['DeviceIdentifier'], info.get('MountPoint'))
    missing = [n for n in (BOOT_NAME, KIT_NAME) if not (found.get(n) or (None, None))[1]]
    if missing:
        raise StickError('after partitioning %s, %s is not mounted' % (disk, ', '.join(missing)))
    return found


def attach_image(host, image, size_bytes):
    """A new raw stick image IMAGE of SIZE_BYTES (sparse), attached without mounting. Returns its diskN."""
    image = Path(image)
    if image.exists():
        raise StickError('%s exists' % image)
    image.parent.mkdir(parents=True, exist_ok=True)
    with open(image, 'wb') as f:
        f.truncate(size_bytes)
    r = host.run(['hdiutil', 'attach', '-imagekey', 'diskimage-class=CRawDiskImage', '-nomount', '-plist', str(image)],
                 timeout=300)
    for e in plistlib.loads(r.stdout).get('system-entities', []):
        dev = e.get('dev-entry', '')
        if dev.startswith('/dev/disk') and 's' not in dev[len('/dev/disk'):]:
            return dev[len('/dev/'):]
    raise StickError('hdiutil attached %s as no whole disk' % image)


def write(host, disk, basesystem, opencore_tar, kit, hao_top, release=None, record=None, on_step=None):
    """The whole stick on DISK. ON_STEP(text) is told each part as it starts. Returns stick.json's content."""
    step = on_step or (lambda text: None)
    mb = boot_mb(Path(basesystem).stat().st_size, Path(opencore_tar).stat().st_size)
    step('erase /dev/%s: EFI, %s (FAT32, %d MB), %s (Mac OS Extended, the rest)' % (disk, BOOT_NAME, mb, KIT_NAME))
    parts = partition(host, disk, mb)
    step('%s: OpenCore and the Recovery (%s)' % (BOOT_NAME, Path(basesystem).name))
    rec = dict(record or {})
    rec.update(write_boot(parts[BOOT_NAME][1], basesystem, opencore_tar))
    step('%s: hao, the kit, the install and report commands' % KIT_NAME)
    rec = write_kit(parts[KIT_NAME][1], kit, hao_top, release, rec)
    host.run(['diskutil', 'unmountDisk', '/dev/' + disk], check=False, timeout=300)
    return rec


def main(argv):
    if len(argv) == 3 and argv[0] == 'opencore-config':
        c = opencore_config(plistlib.loads(Path(argv[1]).read_bytes()))
        Path(argv[2]).write_bytes(plistlib.dumps(c))
        return 0
    print(__doc__.rsplit('\n\n', 1)[-1], file=sys.stderr)
    return 2


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
