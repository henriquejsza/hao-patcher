"""AV1EncoderSW's VideoToolbox registration with x86_64 taken out of CMExecutableArchitectures.

  arm64_only.py SYSTEM OUT

Writes OUT from SYSTEM/PLIST with CMClassImplementations[0].CMExecutableArchitectures = ["arm64"], in the file's own
format and key order, as tools/edit-engine's plist.set writes it (edits/av1-encoder-info.json). The implementation must
be the AV1 software encoder that lists x86_64, or the build stops."""
import plistlib
import sys
from pathlib import Path

PLIST = 'System/Library/Video/Plug-Ins/AV1EncoderSW.bundle/Contents/Info.plist'
IMPLEMENTATION = 'com.apple.videotoolbox.videoencoder.av1.sw'


def arm64_only(data):
    root = plistlib.loads(data)
    impl = root['CMClassImplementations'][0]
    if impl.get('CMClassImplementationID') != IMPLEMENTATION or 'x86_64' not in impl.get('CMExecutableArchitectures', ()):
        raise SystemExit('av1-encoder-x86: %s is not the x86_64 AV1 software encoder' % PLIST)
    impl['CMExecutableArchitectures'] = ['arm64']
    fmt = plistlib.FMT_BINARY if data.startswith(b'bplist00') else plistlib.FMT_XML
    return plistlib.dumps(root, fmt=fmt, sort_keys=False)


if __name__ == '__main__':
    system, out = map(Path, sys.argv[1:3])
    out.write_bytes(arm64_only((system / PLIST).read_bytes()))
