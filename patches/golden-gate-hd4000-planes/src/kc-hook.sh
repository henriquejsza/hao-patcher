#!/bin/sh
# golden-gate-hd4000-planes (kc-hook): plane textures of planar IOSurfaces read and written with the surface's own
# row pitch on the HD 4000 (diag#0025 Photos zoom, diag#0024 lock-screen bands). Runs in set order after
# golden-gate-metal-argbuf (the previous weak dylib in the same driver binary).
#   usr/lib/libhd4000-planes.dylib  <- inputs/hd4000_planes/libhd4000-planes.dylib
#   AppleIntelHD4000GraphicsMTLDriver.bundle/Contents/MacOS/AppleIntelHD4000GraphicsMTLDriver
#       + one LC_LOAD_WEAK_DYLIB /usr/lib/libhd4000-planes.dylib in the zero padding after its load commands,
#         re-signed ad hoc
#   kc-hook.sh SYSTEM_MOUNT     env OCLP_PYTHON
set -eu
S=${1:?System mount}; H=$(cd "$(dirname "$0")" && pwd); IN=$H/inputs/hd4000_planes
DRIVER=$S/System/Library/Extensions/AppleIntelHD4000GraphicsMTLDriver.bundle/Contents/MacOS/AppleIntelHD4000GraphicsMTLDriver
LIB=/usr/lib/libhd4000-planes.dylib

W=$(mktemp -d /private/var/tmp/hd4000-planes.XXXXXX)
"${OCLP_PYTHON:?}" -I "$H/add_weak_dylib.py" "$DRIVER" "$W/driver" "$LIB"
codesign -f -s - -i AppleIntelHD4000GraphicsMTLDriver "$W/driver"
put() { rm -f "$3"; install -o root -g wheel -m "$1" "$2" "$3"; chflags restricted "$3"; }   # put MODE SRC DEST, as Apple's
install -d -m 755 "$S/usr/lib"
put 755 "$IN/libhd4000-planes.dylib" "$S$LIB"
chflags noschg,nouchg,norestricted "$DRIVER"
put 755 "$W/driver" "$DRIVER"
rm -rf "$W"
shasum -a 256 "$S$LIB" "$DRIVER"
