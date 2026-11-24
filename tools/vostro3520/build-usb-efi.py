#!/usr/bin/env python3
"""Merge a VostroXe OpenCore EFI with hao-opencore's Darwin 27 kernel repairs for bare-metal boot.

Usage:
  python3 tools/vostro3520/build-usb-efi.py \
      --vostroxe-efi /path/to/VostroXe/EFI \
      --hao-esp /path/to/bound-hao-esp \
      --out /path/to/output-EFI \
      [--smbios /path/to/smbios.local] \
      [--cryptexfixup /path/to/CryptexFixup.kext] \
      [--lilu /path/to/Lilu.kext] \
      [--opencore-zip /path/to/OpenCore-1.0.5-RELEASE.zip] \
      [--hfsplus /path/to/HfsPlus.efi] \
      [--apfs /path/to/apfs.efi]

Produces on --out (EFI/):
  EFI/OC/config-safe.plist      Darwin 27 bare-metal safe boot (verbose, NootedGreen OFF, no GPU spoof)
  EFI/OC/config-accel.plist     Darwin 27 + Intel Iris Xe Metal 2 (NootedGreen ON, 9A49 spoof)
  EFI/OC/config-recovery.plist  Tahoe Recovery safe boot (no Darwin 27 kexts/patches)
  EFI/OC/config.plist           Copy of config-safe.plist (or config-accel.plist with --default-accel)
"""
import argparse
import copy
import plistlib
import shutil
import sys
import zipfile
from pathlib import Path

APPLE_NVRAM = '7C436110-AB2A-4BBB-A880-FE41995C9F82'
DARWIN27_ARGS = (
    '-lilubetaall',
    '-crypt_force_avx',
    'amfi_get_out_of_my_way=1',
    'amfi_force_policy=8',
    'auxKCAtBoot=false',
    'ipc_control_port_options=0',
)
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
HAOEXEC_ENTRY = dict(
    Arch='x86_64',
    BundlePath='HaoExec.kext',
    Comment='hao: route unprepared arm64-only executables, UUID-bound',
    Enabled=True,
    ExecutablePath='Contents/MacOS/HaoExec',
    MaxKernel='27.99.99',
    MinKernel='27.0.0',
    PlistPath='Contents/Info.plist',
)
COMMPAGE_ENTRY = dict(
    Arch='x86_64',
    BundlePath='IntelCommpage.kext',
    Comment='hao: Darwin 27 x86_64 commpage, Sandbox, AMFI and IOSurface compatibility',
    Enabled=True,
    ExecutablePath='Contents/MacOS/IntelCommpage',
    MaxKernel='27.99.99',
    MinKernel='27.0.0',
    PlistPath='Contents/Info.plist',
)


def load_smbios(path):
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


def apply_smbios(cfg, smbios):
    if not smbios:
        return
    gen = cfg.setdefault('PlatformInfo', {}).setdefault('Generic', {})
    for k in ('SystemProductName', 'SystemSerialNumber', 'MLB', 'SystemUUID', 'ROM'):
        if k in smbios:
            gen[k] = smbios[k]


def add_kext_after(add_list, after_bundle, entry):
    add_list[:] = [k for k in add_list if k.get('BundlePath') != entry['BundlePath']]
    names = [k.get('BundlePath') for k in add_list]
    if after_bundle in names:
        add_list.insert(names.index(after_bundle) + 1, dict(entry))
    else:
        add_list.append(dict(entry))


def merge_darwin27(base_cfg, hao_cfg, verbose=False, accel=False):
    cfg = copy.deepcopy(base_cfg)
    add = cfg.setdefault('Kernel', {}).setdefault('Add', [])

    # Ensure CryptexFixup immediately after Lilu
    add_kext_after(add, 'Lilu.kext', CRYPTEXFIXUP_ENTRY)

    # Pull IntelCommpage and HaoExec entries from hao_cfg if present, else defaults
    hao_adds = {k.get('BundlePath'): k for k in hao_cfg.get('Kernel', {}).get('Add', [])} if hao_cfg else {}
    commpage = copy.deepcopy(hao_adds.get('IntelCommpage.kext', COMMPAGE_ENTRY))
    commpage['Enabled'] = True
    commpage['MinKernel'] = commpage.get('MinKernel') or '27.0.0'
    commpage['MaxKernel'] = commpage.get('MaxKernel') or '27.99.99'
    haoexec = copy.deepcopy(hao_adds.get('HaoExec.kext', HAOEXEC_ENTRY))
    haoexec['Enabled'] = True
    haoexec['MinKernel'] = '27.0.0'
    haoexec['MaxKernel'] = '27.99.99'

    add_kext_after(add, 'CryptexFixup.kext', commpage)
    add[:] = [k for k in add if k.get('BundlePath') != 'HaoExec.kext']
    add.append(haoexec)

    # Toggle GPU/backlight kexts and SSDT-PNLF depending on safe (pure GOP) vs accel (Iris Xe)
    for k in add:
        bp = k.get('BundlePath')
        if bp == 'NootedGreen.kext':
            k['Enabled'] = bool(accel)
        elif not accel and bp in ('WhateverGreen.kext', 'BrightnessKeys.kext'):
            k['Enabled'] = False
    if not accel:
        for a in cfg.get('ACPI', {}).get('Add', []):
            if a.get('Path') == 'SSDT-PNLF.aml':
                a['Enabled'] = False

    # Merge Darwin 27 Kernel.Patch entries (scoped to Darwin 27 so Tahoe Recovery stays untouched)
    patches = cfg.setdefault('Kernel', {}).setdefault('Patch', [])
    if hao_cfg:
        existing_comments = {p.get('Comment') for p in patches}
        for p in hao_cfg.get('Kernel', {}).get('Patch', []):
            if not p.get('Enabled'):
                continue
            p2 = copy.deepcopy(p)
            if not p2.get('MinKernel'):
                p2['MinKernel'] = '27.0.0'
            if not p2.get('MaxKernel'):
                p2['MaxKernel'] = '27.99.99'
            if p2.get('Comment') not in existing_comments:
                patches.append(p2)

    # Ensure boot-args carry Darwin 27 required flags
    nvram = cfg.setdefault('NVRAM', {}).setdefault('Add', {}).setdefault(APPLE_NVRAM, {})
    args = [a for a in nvram.get('boot-args', '').split() if a not in ('-nokcmismatchpanic', '-pmap_pcid_disable', 'ic_csr_internal=1')]
    for arg in DARWIN27_ARGS:
        if arg not in args:
            args.append(arg)
    if verbose:
        for arg in ('-v', 'keepsyms=1'):
            if arg not in args:
                args.append(arg)
    if not accel and '-igfxvesa' not in args:
        args.append('-igfxvesa')
    nvram['boot-args'] = ' '.join(args)

    # Ensure SIP allows unsigned kexts + unrestricted FS + unauthenticated root (0x0A13 >= 0x0803)
    if 'csr-active-config' not in nvram:
        nvram['csr-active-config'] = bytes.fromhex('03080000')

    # Keep ShowPicker on for bare-metal testing so user can choose Golden Gate or Recovery
    cfg.setdefault('Misc', {}).setdefault('Boot', {})['ShowPicker'] = True
    cfg['Misc']['Boot']['Timeout'] = 10
    # Ensure APFS scanning sees all partitions on NVMe (MinDate/MinVersion = -1)
    apfs = cfg.setdefault('UEFI', {}).setdefault('APFS', {})
    apfs['EnableJumpstart'] = True
    apfs['GlobalConnect'] = True
    apfs['MinDate'] = -1
    apfs['MinVersion'] = -1
    return cfg


def copy_bundle(src, dst):
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(src, dst)


def replace_oc_binaries(efi_root, oc_zip):
    with zipfile.ZipFile(oc_zip) as zf:
        by_lower = {m.lower(): m for m in zf.namelist()}
        for path in sorted(efi_root.rglob('*.efi')):
            rel = str(path.relative_to(efi_root)).replace('\\', '/')
            for prefix in ('X64/', 'X64/EFI/'):
                member = by_lower.get((prefix + rel).lower())
                if member:
                    path.write_bytes(zf.read(member))
                    break


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument('--vostroxe-efi', type=Path, required=True)
    ap.add_argument('--hao-esp', type=Path, help='ESP directory produced by hao-opencore (has IntelCommpage, HaoExec, bound Kernel.Patch)')
    ap.add_argument('--out', type=Path, required=True)
    ap.add_argument('--smbios', type=Path)
    ap.add_argument('--cryptexfixup', type=Path)
    ap.add_argument('--lilu', type=Path)
    ap.add_argument('--opencore-zip', type=Path)
    ap.add_argument('--hfsplus', type=Path)
    ap.add_argument('--apfs', type=Path, help='Apple APFS standalone EFI driver (e.g. apfs.efi)')
    ap.add_argument('--default-accel', action='store_true')
    args = ap.parse_args()

    out = args.out
    if out.exists():
        shutil.rmtree(out)
    shutil.copytree(args.vostroxe_efi, out)

    oc = out / 'OC'
    kexts = oc / 'Kexts'
    drivers = oc / 'Drivers'

    if args.hfsplus and args.hfsplus.is_file():
        shutil.copy2(args.hfsplus, drivers / 'HfsPlus.efi')
    if args.apfs and args.apfs.is_file():
        shutil.copy2(args.apfs, drivers / 'apfs.efi')
    if args.opencore_zip and args.opencore_zip.is_file():
        replace_oc_binaries(out, args.opencore_zip)
    if args.lilu and args.lilu.is_dir():
        copy_bundle(args.lilu, kexts / 'Lilu.kext')
    if args.cryptexfixup and args.cryptexfixup.is_dir():
        copy_bundle(args.cryptexfixup, kexts / 'CryptexFixup.kext')

    hao_cfg = None
    if args.hao_esp and args.hao_esp.is_dir():
        hao_oc = args.hao_esp / 'EFI/OC' if (args.hao_esp / 'EFI/OC').is_dir() else args.hao_esp / 'OC'
        hao_plist = hao_oc / 'config.plist'
        if hao_plist.is_file():
            hao_cfg = plistlib.loads(hao_plist.read_bytes())
        for bundle in ('IntelCommpage.kext', 'HaoExec.kext', 'CryptexFixup.kext', 'Lilu.kext'):
            src = hao_oc / 'Kexts' / bundle
            if src.is_dir() and (bundle in ('IntelCommpage.kext', 'HaoExec.kext') or not (kexts / bundle).is_dir()):
                copy_bundle(src, kexts / bundle)

    smbios = load_smbios(args.smbios)
    safe_base = plistlib.loads((oc / 'config-install.plist').read_bytes())
    accel_base = plistlib.loads((oc / 'config.plist').read_bytes())

    # Ensure HfsPlus.efi and apfs.efi are enabled in UEFI.Drivers if present
    for base in (safe_base, accel_base):
        apply_smbios(base, smbios)
        drv_list = base.setdefault('UEFI', {}).setdefault('Drivers', [])
        if (drivers / 'HfsPlus.efi').is_file():
            for d in drv_list:
                if d.get('Path') == 'HfsPlus.efi':
                    d['Enabled'] = True
                    break
            else:
                drv_list.append(dict(Arguments='', Comment='HfsPlus', Enabled=True, HideVerbose=False, LoadEarly=False, Path='HfsPlus.efi'))
        if (drivers / 'apfs.efi').is_file():
            for d in drv_list:
                if d.get('Path') == 'apfs.efi':
                    d['Enabled'] = True
                    break
            else:
                drv_list.append(dict(Arguments='', Comment='Apple APFS', Enabled=True, HideVerbose=False, LoadEarly=False, Path='apfs.efi'))

    recovery_cfg = copy.deepcopy(safe_base)
    apfs_rec = recovery_cfg.setdefault('UEFI', {}).setdefault('APFS', {})
    apfs_rec['EnableJumpstart'] = True
    apfs_rec['GlobalConnect'] = True
    apfs_rec['MinDate'] = -1
    apfs_rec['MinVersion'] = -1
    recovery_cfg.setdefault('Misc', {}).setdefault('Boot', {})['ShowPicker'] = True
    recovery_cfg['Misc']['Boot']['Timeout'] = 10

    safe_cfg = merge_darwin27(safe_base, hao_cfg, verbose=True, accel=False)
    accel_cfg = merge_darwin27(accel_base, hao_cfg, verbose=True, accel=True)

    for c in (safe_cfg, accel_cfg, recovery_cfg):
        dbg = c.setdefault('Misc', {}).setdefault('Debug', {})
        dbg['Target'] = 65  # enable (1) + file (64); omit serial (2) which stalls ~284 ms/line on laptops without COM1

    (oc / 'config-recovery.plist').write_bytes(plistlib.dumps(recovery_cfg))
    (oc / 'config-safe.plist').write_bytes(plistlib.dumps(safe_cfg))
    (oc / 'config-accel.plist').write_bytes(plistlib.dumps(accel_cfg))
    (oc / 'config.plist').write_bytes(plistlib.dumps(accel_cfg if args.default_accel else safe_cfg))

    n_patches = len(safe_cfg['Kernel']['Patch'])
    print(f'build-usb-efi: wrote {out} (safe={len(safe_cfg["Kernel"]["Add"])} kexts, {n_patches} kernel patches; accel={len(accel_cfg["Kernel"]["Add"])} kexts)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
