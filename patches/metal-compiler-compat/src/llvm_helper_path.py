#!/usr/bin/env python3
"""llvm_helper_path.py IN OUT: copy OCLP's GPUCompiler 31001 libLLVM.dylib with its libLLVM_helper load path made
absolute. OCLP links the helper by the relative path System/Library/...; dyld refuses relative paths in a hardened
process, and MTLCompilerService runs hardened, so its dlopen of the 31001 MTLCompiler failed and the service called a
null pointer on every 31001 request. The name is rewritten in place (same load command, same size: the leading "/"
takes one of the NUL padding bytes). Refuses unless the relative name occurs exactly once, in an LC_LOAD_DYLIB, with
room. The old signature stays for `codesign -f -s -` to replace."""
import struct, sys
OLD = b'System/Library/PrivateFrameworks/GPUCompiler.framework/Versions/31001/Libraries/libLLVM_helper.dylib'
LC_LOAD_DYLIB = 0xc


def edit(data):
    b = bytearray(data)
    magic, cpu, _, _, ncmds = struct.unpack_from('<5I', b, 0)
    assert magic == 0xfeedfacf and cpu == 0x01000007, 'not a thin x86_64 Mach-O'
    assert b.count(OLD) == 1, 'helper path not found exactly once (edited before, or another libLLVM)'
    off = 32
    for _ in range(ncmds):
        cmd, size = struct.unpack_from('<2I', b, off)
        name_at = off + struct.unpack_from('<I', b, off + 8)[0] if cmd == LC_LOAD_DYLIB else None
        if name_at is not None and b[name_at:name_at + len(OLD)] == OLD:
            room = off + size - name_at
            assert room >= len(OLD) + 2, 'no padding for the leading /'
            b[name_at:off + size] = (b'/' + OLD).ljust(room, b'\0')
            return bytes(b), name_at
        off += size
    raise AssertionError('helper path is not an LC_LOAD_DYLIB name')


def main(src, dst):
    out, at = edit(open(src, 'rb').read())
    open(dst, 'wb').write(out)
    print(f'{dst}: libLLVM_helper load path made absolute at {at:#x}')


if __name__ == '__main__':
    main(*sys.argv[1:3])
