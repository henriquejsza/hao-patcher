#!/bin/sh
# make.sh OUTDIR: build libhelloblur.dylib (row libhelloblur) from src/hello_blurcache.m on the host, as the user.
#   x86_64, macOS 13 minimum, Xcode's macOS SDK, MRC (-fno-objc-arc), -O2, install name /usr/lib/libhelloblur.dylib,
#   links only Foundation, libobjc and libSystem; ad hoc signed with identifier local.libhelloblur.
# The bytes depend on the toolchain: the linker and SDK versions are written into the load commands, and the UUID and
# the signature follow from them. With the Xcode the row names, the result is the row's file byte for byte;
# compare.py tells another toolchain's rebuild from a real difference. HELLOBLUR_SDK overrides the SDK.
set -eu
H=$(cd "$(dirname "$0")" && pwd); OUT=${1:?output dir}
SDK=${HELLOBLUR_SDK:-$(xcrun --sdk macosx --show-sdk-path)}
[ -d "$SDK" ] || { echo "make.sh: no SDK at $SDK (set HELLOBLUR_SDK)" >&2; exit 1; }
mkdir -p "$OUT"
xcrun clang -arch x86_64 -mmacosx-version-min=13.0 -isysroot "$SDK" -dynamiclib -fno-objc-arc -O2 -Wall -Werror \
    -Wl,-no_warn_inits -install_name /usr/lib/libhelloblur.dylib -framework Foundation -lobjc \
    -o "$OUT/libhelloblur.dylib" "$H/src/hello_blurcache.m"
codesign -f -s - -i local.libhelloblur "$OUT/libhelloblur.dylib"
shasum -a 256 "$OUT/libhelloblur.dylib"
