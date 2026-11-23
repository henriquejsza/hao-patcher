"""Dell Vostro 3520 (Alder Lake i5-1235U, Intel Iris Xe 8086:46a8) OpenCore overlay.

  vostro3520.py ESP VOSTROXE_EFI OCLP_SOURCE [--smbios FILE] [--keep-opencore-bin]

Overlays the VostroXe OpenCore ACPI tables, kexts, quirks, Alder Lake CPUID emulation, and
MacBookPro16,2 SMBIOS onto ESP while adding CryptexFixup.kext (1.0.5) right after Lilu.kext and
appending -crypt_force_avx (required on AVX2 CPUs so Golden Gate's modified OS cryptex grafts).

Writes three configs into ESP/EFI/OC:
  - config-safe.plist:  Darwin 27 bare-metal safe boot (no Iris Xe spoof, NootedGreen disabled, verbose)
  - config-accel.plist: Darwin 27 + Intel Iris Xe Metal 2 acceleration (NootedGreen enabled, 9A49 spoof)
  - config.plist:       active config (defaults to config-safe.plist until Iris Xe stack is validated on 27)
"""
import io
import plistlib
import secrets
import shutil
import sys
import tarfile
import tempfile
import uuid
import zipfile
from pathlib import Path

APPLE_NVRAM = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
FORCE_AVX = '-crypt_force_avx'
CRYPTEXFIXUP_ZIP = 'payloads/Kexts/Acidanthera/CryptexFixup-v1.0.5-RELEASE.zip'
LILU_ZIP = 'payloads/Kexts/Acidanthera/Lilu-v1.7.2-RELEASE.zip'
CRYPTEXFIXUP_ENTRY = dict(
    Arch='x86_64',
    BundlePath='CryptexFixup.kext',
    Comment='CryptexFixup (Golden Gate modified OS cryptex graft on AVX2)',
    Enabled=True,
    ExecutablePath='Contents/MacOS/CryptexFixup',
    MaxKernel='',
    MinKernel='20.0.0',
    PlistPath='Contents/Info.plist',
)
ALNUM = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ'


def oclp_kext(esp, oclp_tar, zip_path, bundle):
    """Extract BUNDLE from pinned OCLP tarball into ESP/EFI/OC/Kexts."""
    if not oclp_tar or not Path(oclp_tar).is_file():
        return False
    with tarfile.open(oclp_tar) as tar:
        member = tar.extractfile(zip_path)
        if member is None:
            raise SystemExit(f'opencore-vostro3520: {zip_path} is not in {oclp_tar}')
        data = member.read()
    dest = esp / 'EFI/OC/Kexts' / bundle
    if dest.exists():
        shutil.rmtree(dest)
    with tempfile.TemporaryDirectory() as tmp, zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(tmp)
        found = [p for p in Path(tmp).rglob(bundle) if p.is_dir() and 'dSYM' not in str(p)]
        if len(found) != 1:
            raise SystemExit(f'opencore-vostro3520: expected one {bundle}, found {len(found)}')
        shutil.copytree(found[0], dest)
    return True


def ensure_cryptexfixup(config):
    """Insert CryptexFixup.kext right after Lilu.kext and append -crypt_force_avx."""
    add = config.setdefault('Kernel', {}).setdefault('Add', [])
    names = [k.get('BundlePath') for k in add]
    if 'Lilu.kext' not in names:
        raise SystemExit('opencore-vostro3520: config loads no Lilu.kext')
    add[:] = [k for k in add if k.get('BundlePath') != 'CryptexFixup.kext']
    lilu_idx = [k.get('BundlePath') for k in add].index('Lilu.kext')
    add.insert(lilu_idx + 1, dict(CRYPTEXFIXUP_ENTRY))

    nvram = config.setdefault('NVRAM', {}).setdefault('Add', {}).setdefault(APPLE_NVRAM, {})
    args = nvram.get('boot-args', '').split()
    for arg in ('-lilubetaall', FORCE_AVX):
        if arg not in args:
            args.append(arg)
    nvram['boot-args'] = ' '.join(args)
    return config


def load_smbios_local(path):
    if not path or not Path(path).is_file():
        return None
    vals = {}
    for line in Path(path).read_text(encoding='utf-8').splitlines():
        line = line.strip()
        if line and not line.startswith('#') and '=' in line:
            k, v = line.split('=', 1)
            vals[k.strip()] = v.strip()
    if 'ROM' in vals:
        vals['ROM'] = bytes.fromhex(vals['ROM'])
    return vals


def apply_smbios(config, smbios=None):
    info = config.setdefault('PlatformInfo', {})
    generic = info.setdefault('Generic', {})
    info.update(Automatic=True, UpdateDataHub=True, UpdateNVRAM=True, UpdateSMBIOS=True, UpdateSMBIOSMode='Create')
    if smbios:
        for k in ('SystemProductName', 'SystemSerialNumber', 'MLB', 'SystemUUID', 'ROM'):
            if k in smbios:
                generic[k] = smbios[k]
    elif not generic.get('SystemSerialNumber') or 'CHANGE' in str(generic.get('SystemSerialNumber', '')):
        generic['SystemProductName'] = generic.get('SystemProductName') or 'MacBookPro16,2'
        generic['SystemSerialNumber'] = ''.join(secrets.choice(ALNUM) for _ in range(12))
        generic['MLB'] = ''.join(secrets.choice(ALNUM) for _ in range(17))
        generic['SystemUUID'] = str(uuid.uuid4()).upper()
        generic['ROM'] = secrets.token_bytes(6)
    return config


def copy_tree_contents(src_dir, dst_dir):
    dst_dir.mkdir(parents=True, exist_ok=True)
    for item in sorted(src_dir.iterdir()):
        dst = dst_dir / item.name
        if item.is_dir():
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(item, dst)
        else:
            shutil.copy2(item, dst)


def apply_vostroxe(esp, vostroxe_efi, oclp_tar=None, smbios_file=None, accel_default=False):
    esp = Path(esp)
    vostroxe_efi = Path(vostroxe_efi)
    oc_src = vostroxe_efi / 'OC' if (vostroxe_efi / 'OC').is_dir() else vostroxe_efi / 'EFI/OC'
    if not oc_src.is_dir():
        raise SystemExit(f'opencore-vostro3520: missing EFI/OC in {vostroxe_efi}')

    oc_dst = esp / 'EFI/OC'
    oc_dst.mkdir(parents=True, exist_ok=True)
    for sub in ('ACPI', 'Kexts', 'Resources'):
        if (oc_src / sub).is_dir():
            copy_tree_contents(oc_src / sub, oc_dst / sub)

    if oclp_tar and Path(oclp_tar).is_file():
        oclp_kext(esp, oclp_tar, LILU_ZIP, 'Lilu.kext')
        oclp_kext(esp, oclp_tar, CRYPTEXFIXUP_ZIP, 'CryptexFixup.kext')

    smbios = load_smbios_local(smbios_file)
    safe_src = oc_src / 'config-install.plist'
    accel_src = oc_src / 'config.plist'

    safe_cfg = plistlib.loads((safe_src if safe_src.is_file() else accel_src).read_bytes())
    accel_cfg = plistlib.loads(accel_src.read_bytes())

    for cfg in (safe_cfg, accel_cfg):
        ensure_cryptexfixup(cfg)
        apply_smbios(cfg, smbios)

    (oc_dst / 'config-safe.plist').write_bytes(plistlib.dumps(safe_cfg))
    (oc_dst / 'config-accel.plist').write_bytes(plistlib.dumps(accel_cfg))
    active = accel_cfg if accel_default else safe_cfg
    (oc_dst / 'config.plist').write_bytes(plistlib.dumps(active))
    return dict(safe=len(safe_cfg['Kernel']['Add']), accel=len(accel_cfg['Kernel']['Add']))


def main(argv):
    if len(argv) < 3:
        raise SystemExit('usage: vostro3520.py ESP VOSTROXE_EFI [OCLP_SOURCE] [SMBIOS_LOCAL]')
    esp, vostroxe_efi = Path(argv[1]), Path(argv[2])
    oclp_tar = Path(argv[3]) if len(argv) > 3 and argv[3] else None
    smbios_file = Path(argv[4]) if len(argv) > 4 and argv[4] else None
    info = apply_vostroxe(esp, vostroxe_efi, oclp_tar=oclp_tar, smbios_file=smbios_file)
    print(f'opencore-vostro3520: installed Vostro 3520 EFI (safe={info["safe"]} kexts, accel={info["accel"]} kexts, CryptexFixup + {FORCE_AVX})')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
