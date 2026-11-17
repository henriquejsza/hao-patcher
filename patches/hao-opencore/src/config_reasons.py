"""Every enabled part of an image's OpenCore config.plist has a recorded reason (PROTOCOL S18).

  config_reasons.py check CONFIG [--reasons FILE]     exit 1 and name each element without a reason
  config_reasons.py list CONFIG                       print the config's elements, one per line

An element is one setting someone chose: an enabled kext, Kernel Patch or Block entry, ACPI or DeviceProperties
entry, a Kernel/Booter/UEFI quirk that is on (with its value when it is a number), a Misc.Security value, an NVRAM
Add key (with its value for the keys that weaken security: csr-active-config, revblock, revpatch), an NVRAM Delete key,
and WriteFlash. Boot-args' arguments have their reasons in edits/config.json (arg_reasons). config-reasons.json maps
each element to its reason; a reason that starts with "UNTRACED:" says what is not known yet and which test settles it.
"""
import argparse
import json
from pathlib import Path
import plistlib
import sys

REASONS = Path(__file__).resolve().parent / 'config-reasons.json'
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


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('command', choices=('check', 'list'))
    parser.add_argument('config', type=Path)
    parser.add_argument('--reasons', type=Path, default=REASONS)
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
    untraced = sum(1 for e in elements(config) if load_reasons(args.reasons)[e].startswith('UNTRACED:'))
    print(f'config-reasons: every element of {args.config.name} has a reason ({untraced} untraced, under test)')
    return 0


if __name__ == '__main__':
    sys.exit(main())
