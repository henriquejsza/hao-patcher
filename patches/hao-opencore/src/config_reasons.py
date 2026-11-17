"""Every enabled part of an image's OpenCore config.plist has a recorded reason (PROTOCOL S18).

  config_reasons.py check CONFIG [--reasons FILE] [--kexts DIR]
        exit 1 and name each element without a reason; with --kexts (the ESP's EFI/OC/Kexts), also each enabled
        kext whose files are not exactly the ones kext-provenance.json pins
  config_reasons.py list CONFIG                       print the config's elements, one per line

An element is one setting someone chose: an enabled kext, Kernel Patch or Block entry, ACPI or DeviceProperties
entry, a Kernel/Booter/UEFI quirk that is on (with its value when it is a number), a Misc.Security value, an NVRAM
Add key (with its value for the keys that weaken security: csr-active-config, revblock, revpatch), an NVRAM Delete key,
and WriteFlash. Boot-args' arguments have their reasons in edits/config.json (arg_reasons). config-reasons.json maps
each element to its reason; a reason that starts with "UNTRACED:" says what is not known yet and which test settles it.
"""
import argparse
import hashlib
import json
from pathlib import Path
import plistlib
import sys

REASONS = Path(__file__).resolve().parent / 'config-reasons.json'
PROVENANCE = Path(__file__).resolve().parent / 'kext-provenance.json'
VALUE_KEYS = {'csr-active-config', 'revblock', 'revpatch'}


def _value(v):
    return v.hex() if isinstance(v, bytes) else str(v)


def elements(config):
    """The sorted element strings of a parsed config.plist."""
    out = set()
    kernel = config.get('Kernel', {})
    out |= {'kext:' + k['BundlePath'] for k in kernel.get('Add', []) if k.get('Enabled')}
    out |= {'kernel-patch:' + p.get('Comment', '?') for p in kernel.get('Patch', []) if p.get('Enabled')}
    out |= {'kernel-block:' + b.get('Identifier', '?') for b in kernel.get('Block', []) if b.get('Enabled')}
    out |= {'acpi:' + a.get('Path', '?') for a in config.get('ACPI', {}).get('Add', []) if a.get('Enabled')}
    out |= {'device:' + d for d in config.get('DeviceProperties', {}).get('Add', {})}
    for section, quirks in (('kernel', kernel.get('Quirks', {})), ('booter', config.get('Booter', {}).get('Quirks', {})),
                            ('uefi', config.get('UEFI', {}).get('Quirks', {}))):
        for name, v in quirks.items():
            if v is True:
                out.add(f'{section}-quirk:{name}')
            elif isinstance(v, int) and not isinstance(v, bool) and v > 0:      # -1 and 0: not set
                out.add(f'{section}-quirk:{name}={v}')
    out |= {f'security:{k}={_value(v)}' for k, v in config.get('Misc', {}).get('Security', {}).items()
            if k not in ('PasswordHash', 'PasswordSalt')}
    nvram = config.get('NVRAM', {})
    for guid, keys in nvram.get('Add', {}).items():
        for k, v in keys.items():
            out.add(f'nvram-add:{guid}:{k}' + (f'={_value(v)}' if k in VALUE_KEYS else ''))
    for guid, keys in nvram.get('Delete', {}).items():
        out |= {f'nvram-delete:{guid}:{k}' for k in keys}
    out.add(f'nvram:WriteFlash={nvram.get("WriteFlash")}')
    return sorted(out)


def load_reasons(path=REASONS):
    reasons = json.loads(Path(path).read_text())
    bad = [k for k, v in reasons.items() if not isinstance(v, str) or not v.strip()]
    if bad:
        raise ValueError('empty reasons: ' + ', '.join(bad))
    return reasons


def missing(config, reasons):
    return [e for e in elements(config) if e not in reasons]


def provenance_problems(config, kexts, provenance):
    """Why an enabled kext's bundle is not the one kext-provenance.json pins: every enabled top-level bundle must be
    listed; a third-party one ("oclp-payload", "oclp-generated") must hold exactly the pinned files with the pinned
    sha256 (traced to upstream OCLP 3.0.0-rc.5 and, where one exists, the Acidanthera release). hao's own kexts
    ("hao") are bound or stamped per image and checked by kc_bind.py and repairs.py instead."""
    bad = []
    bundles = sorted({k['BundlePath'].split('/Contents/')[0] for k in config.get('Kernel', {}).get('Add', [])
                      if k.get('Enabled')})
    for name in bundles:
        entry = provenance.get(name)
        if entry is None:
            bad.append(f'{name}: no provenance (kext-provenance.json); not loaded from an unknown source')
            continue
        if entry['kind'] == 'hao':
            continue
        folder = Path(kexts) / name
        have = {str(f.relative_to(folder)): hashlib.sha256(f.read_bytes()).hexdigest()
                for f in sorted(folder.rglob('*')) if f.is_file()} if folder.is_dir() else {}
        if have != entry['files']:
            changed = sorted(k for k in set(have) | set(entry['files']) if have.get(k) != entry['files'].get(k))
            bad.append(f'{name}: files differ from {entry["source"]}: {", ".join(changed[:5])}')
    return bad


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('check', 'list'))
    parser.add_argument('config', type=Path)
    parser.add_argument('--reasons', type=Path, default=REASONS)
    parser.add_argument('--kexts', type=Path, help="the ESP's EFI/OC/Kexts: also check each enabled kext's provenance")
    parser.add_argument('--provenance', type=Path, default=PROVENANCE)
    args = parser.parse_args()
    with open(args.config, 'rb') as f:
        config = plistlib.load(f)
    if args.command == 'list':
        print('\n'.join(elements(config)))
        return 0
    lacking = missing(config, load_reasons(args.reasons))
    if lacking:
        print('config-reasons: no recorded reason (patches/hao-opencore/src/config-reasons.json) for:', file=sys.stderr)
        print('\n'.join('  ' + e for e in lacking), file=sys.stderr)
        return 1
    if args.kexts:
        bad = provenance_problems(config, args.kexts, json.loads(args.provenance.read_text()))
        if bad:
            print('config-reasons: kexts whose source is not the pinned upstream one:', file=sys.stderr)
            print('\n'.join('  ' + b for b in bad), file=sys.stderr)
            return 1
    untraced = sum(1 for e in elements(config) if load_reasons(args.reasons)[e].startswith('UNTRACED:'))
    print(f'config-reasons: every element of {args.config.name} has a reason ({untraced} untraced, under test)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
