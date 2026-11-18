#!/bin/sh
# metal-compiler-compat (kc-hook, after the OCLP overlay installed the legacy 3802 Metal stack): OCLP's
# MTLCompilerService loads cache/metallib's compat.dylib at startup (inputs/metal_compiler_compat, tools/live-text),
# and OCLP's GPUCompiler 31001 libLLVM.dylib names libLLVM_helper by an absolute path (edits/libllvm-31001.json):
# the service runs hardened, where dyld refuses the relative one.
set -eu
S=${1:?System mount}; H=$(cd "$(dirname "$0")" && pwd)
"${OCLP_PYTHON:?}" -I "$H/install.py" "$S" "$H/inputs/metal_compiler_compat"
LLVM=$S/System/Library/PrivateFrameworks/GPUCompiler.framework/Versions/31001/Libraries/libLLVM.dylib
W=$(mktemp -d /private/var/tmp/compiler-compat.XXXXXX)
"${OCLP_PYTHON:?}" -I "$H/llvm_helper_path.py" "$LLVM" "$W/libLLVM.dylib"
codesign -f -s - -i libLLVM "$W/libLLVM.dylib"
chflags noschg,nouchg,norestricted "$LLVM"
rm -f "$LLVM"; install -o root -g wheel -m 755 "$W/libLLVM.dylib" "$LLVM"; chflags restricted "$LLVM"
rm -rf "$W"
shasum -a 256 "$LLVM"
