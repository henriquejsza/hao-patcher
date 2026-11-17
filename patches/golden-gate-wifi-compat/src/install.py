"""Put the IO80211 and WiFiPeerToPeer compat libraries in front of OCLP's Modern Wireless wrappers (run by
src/kc-hook.sh, right after golden-gate-userspace).

Each wrapper is renamed LEAF + OCLP.dylib (install name and file, signed again ad hoc with its own identifier) and the
compat library, which re-exports it, is installed under the framework's own name with the wrapper's file flags.
install_wrapper_compat and set_install_name are golden-gate-userspace's (its CoreWiFi step uses them);
tests/test_install.py checks the two give the same bytes."""
import os
from pathlib import Path
import shutil
import struct
import subprocess
import sys
import tempfile

# airportd SIGBUS without this: OCLP's Modern Wireless wrapper (PatcherSupportPkg 13.7.2-25 IO80211, kept as
# an OCLP path) exports 7 functions 27.0's callers use as 8-byte data (a pointer to a CFString of the name), so a call
# from WiFiPolicy (-[WiFiUsageLinkSession eventDictionary:] -> apple80211_authtype_uppertoStr) runs the wrapper's
# __DATA, and it lacks Apple80211Get20MhzChannelIndexBitmap, which WiFiAnalytics binds. The compat library (row
# io80211_compat, made and checked against the build's clients by golden-gate-userspace's src/io80211/make) defines
# the 8 as the build's x86_64 IO80211 does and re-exports the wrapper, renamed IO80211OCLP.dylib, so every other name
# resolves as before and the wrapper's initializers still run (it re-exports IO80211Old.dylib itself).
IO80211 = 'System/Library/PrivateFrameworks/IO80211.framework/Versions/A/'
# coreaudiod, AirPlayXPCHelper, ControlCenter and sharingd abort in libobjc without this: OCLP's Modern Wireless
# WiFiPeerToPeer wrapper (13.7.2-25) lacks 36 Wi-Fi Aware classes 27.x's x86_64 cache binds, so dyld sets them to
# 0xbad4007 and loading APTransport's category on WiFiAwareDatapathInfo is fatal. The compat library (row
# wifip2p_compat, made and checked by golden-gate-userspace's src/wifip2p/make) defines them and re-exports the
# wrapper, renamed WiFiPeerToPeerOCLP.dylib, in the same way.
WIFIP2P = 'System/Library/PrivateFrameworks/WiFiPeerToPeer.framework/Versions/A/'


def run(*args):
    subprocess.run([str(arg) for arg in args], check=True)


def set_install_name(data, old, new):
    """Change a thin x86_64 dylib's LC_ID_DYLIB from OLD to NEW (bytes) in place, growing the command into the zero
    padding after the load commands when NEW is longer; the later commands move down (no load command holds an
    offset into the header). Stands in for install_name_tool -id, which the builder VM lacks; the caller re-signs."""
    magic, cpu, _, kind, ncmds, sizeofcmds = struct.unpack_from('<6I', data, 0)
    if magic != 0xfeedfacf or cpu != 0x1000007 or kind != 6:
        raise ValueError('not a thin x86_64 dylib')
    first, found, at = None, None, 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<II', data, at)
        if cmd == 0x19:
            nsects, = struct.unpack_from('<I', data, at+64)
            for i in range(nsects):
                offset, = struct.unpack_from('<I', data, at+72+i*80+48)
                if offset and (first is None or offset < first):
                    first = offset
        if cmd == 0xd:
            found = at, size
        at += size
    if found is None:
        raise ValueError('no LC_ID_DYLIB')
    at, size = found
    name_at, = struct.unpack_from('<I', data, at+8)
    current = bytes(data[at+name_at:at+size]).split(b'\0', 1)[0]
    if current != old:
        raise ValueError('install name is %s, expected %s' % (current.decode(), old.decode()))
    grown = max(size, (name_at+len(new)+1+7)//8*8)
    end = 32+sizeofcmds
    if first is None or end+grown-size > first or any(data[end:end+grown-size]):
        raise ValueError('no room for the longer install name')
    data[at:end+grown-size] = bytes(data[at:at+name_at])+new.ljust(grown-name_at, b'\0')+bytes(data[at+size:end])
    struct.pack_into('<I', data, at+4, grown)
    struct.pack_into('<I', data, 20, sizeofcmds+grown-size)


def install_file(source, target):
    target.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, target)
    os.chown(target, 0, 0)
    os.chmod(target, 0o755)


def install_wrapper_compat(system, compat, workspace, folder, leaf, suffix='OCLP'):
    """Rename the library SYSTEM/FOLDER/LEAF (OCLP's wrapper) to LEAF+SUFFIX.dylib (install name and file, re-signed
    with its identifier) and install COMPAT, which re-exports it, as LEAF."""
    wrapper, renamed = system/folder/leaf, system/folder/f'{leaf}{suffix}.dylib'
    if not wrapper.is_file() or wrapper.is_symlink():
        raise SystemExit(f'{wrapper}: no {leaf} library to put the compat library in front of')
    data = bytearray(wrapper.read_bytes())
    set_install_name(data, ('/'+folder+leaf).encode(), ('/'+folder+renamed.name).encode())
    details = subprocess.run(['codesign', '-dv', str(wrapper)], check=True, capture_output=True, text=True).stderr
    identifier = next(l.split('=', 1)[1] for l in details.splitlines() if l.startswith('Identifier='))
    staged = workspace/renamed.name
    staged.write_bytes(data)
    run('codesign', '-f', '-s', '-', '-i', identifier, '--preserve-metadata=entitlements,flags,runtime', staged)
    flags = wrapper.stat().st_flags
    run('chflags', 'noschg,nouchg,norestricted', wrapper)
    for source, target in ((staged, renamed), (compat, wrapper)):
        install_file(source, target)
        os.chflags(target, flags)
    print(f'{leaf}: compat library re-exports the original as', renamed.name, 'identifier', identifier, flush=True)


def main(argv=None):
    system, io80211, wifip2p = (Path(a) for a in (sys.argv[1:] if argv is None else argv))
    workspace = Path(tempfile.mkdtemp(prefix='golden-gate-wifi-'))
    install_wrapper_compat(system, io80211, workspace, IO80211, 'IO80211')
    install_wrapper_compat(system, wifip2p, workspace, WIFIP2P, 'WiFiPeerToPeer')
    shutil.rmtree(workspace)


if __name__ == '__main__':
    main()
