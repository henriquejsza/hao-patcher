"""The Tahoe kernel donors IntelCommpage and the kernel profiles read, from Apple's Kernel Debug Kit.

  kernel-fixes kdk-donors KDK_ROOT OUT --build BUILD

KDK_ROOT is the root of a mounted or unpacked Kernel Debug Kit (Apple's, as KdkSupportPkg mirrors it; row `kdk`), so
KDK_ROOT/System/Library/Extensions holds the kexts. OUT (a new folder) gets the x86_64 slice of each donor's executable,
exactly as `lipo -thin x86_64` writes it, and build.json naming each source (relative to KDK_ROOT) and both sha256.
build.json holds no date and no host path, so the same KDK always gives the same folder.
"""
import hashlib
import json
from pathlib import Path
import struct

DONORS = ('AppleMobileFileIntegrity', 'Sandbox', 'EndpointSecurity', 'IOSurface')
CPU_X86_64 = 0x01000007
FAT_MAGIC, FAT_MAGIC_64 = 0xcafebabe, 0xcafebabf
MH_MAGIC_64 = 0xfeedfacf


def x86_64_slice(data):
    """The x86_64 slice of a universal Mach-O, or the file itself when it is a thin x86_64 Mach-O."""
    magic, = struct.unpack_from('>I', data, 0)
    if magic in (FAT_MAGIC, FAT_MAGIC_64):
        count, = struct.unpack_from('>I', data, 4)
        size = 32 if magic == FAT_MAGIC_64 else 20
        for i in range(count):
            at = 8 + i * size
            if magic == FAT_MAGIC_64:
                cpu, _, offset, length = struct.unpack_from('>iiQQ', data, at)
            else:
                cpu, _, offset, length = struct.unpack_from('>iiII', data, at)
            if cpu & 0xffffffff == CPU_X86_64:
                return data[offset:offset + length]
        raise ValueError('no x86_64 slice')
    if struct.unpack_from('<I', data, 0)[0] == MH_MAGIC_64 and struct.unpack_from('<i', data, 4)[0] == CPU_X86_64:
        return data
    raise ValueError('not an x86_64 or universal Mach-O')


def make(kdk_root, out, build):
    kdk_root, out = Path(kdk_root), Path(out)
    out.mkdir(parents=True, exist_ok=False)
    files = {}
    for name in DONORS:
        rel = f'System/Library/Extensions/{name}.kext/Contents/MacOS/{name}'
        source = (kdk_root / rel).read_bytes()
        thin = x86_64_slice(source)
        (out / name).write_bytes(thin)
        files[name] = dict(source='kdk/' + rel, source_sha256=hashlib.sha256(source).hexdigest(),
                           sha256=hashlib.sha256(thin).hexdigest())
    record = dict(operation='thin-kdk-intel-donors', build=build, producer='tools/kernel-fixes kdk-donors', files=files)
    (out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
    return record
