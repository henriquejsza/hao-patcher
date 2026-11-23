#!/bin/sh
# golden-gate-intel-xe (oclp-hook, pack intel-xe): installs the Intel Iris Xe Metal 2 acceleration stack
# (Tiger Lake 16.0.32 bundles, HookCase.kext, patched AppleIntelTGLGraphicsMTLDriver, libxedrv and shader
# compiler built by VostroXe) into the Golden Gate 27 System/Library volumes when VOSTROXE_BUNDLE is supplied.
# Without VOSTROXE_BUNDLE the image boots cleanly in safe software graphics first, and the stack can be
# deployed after bare-metal Darwin 27 boot is confirmed.
set -eu
SYS=$1
BUNDLE=${VOSTROXE_BUNDLE:-}
if [ -z "$BUNDLE" ] || [ ! -d "$BUNDLE" ]; then
    echo "golden-gate-intel-xe: no VOSTROXE_BUNDLE supplied; leaving safe graphics (deploy VostroXe stack after first bare-metal boot)"
    exit 0
fi

mkdir -p "$SYS/Library/GPUBundles" "$SYS/Library/Extensions" "$SYS/System/Library/Extensions"
for item in AppleIntelTGLGraphicsMTLDriver.bundle AppleIntelGraphicsShared.bundle; do
    if [ -d "$BUNDLE/GPUBundles/$item" ]; then
        rm -rf "$SYS/Library/GPUBundles/$item"
        ditto "$BUNDLE/GPUBundles/$item" "$SYS/Library/GPUBundles/$item"
    fi
done
# macOS 27's kmutil cannot build an x86_64 Auxiliary Kernel Collection (auxKCAtBoot=false), so the
# Tiger Lake accelerator/framebuffer kexts and HookCase.kext must live in /System/Library/Extensions
# and be linked into SystemKernelExtensions.kc using Tahoe's kmutil (not /Library/Extensions AuxKC).
for item in AppleIntelTGLGraphics.kext AppleIntelTGLGraphicsFramebuffer.kext HookCase.kext; do
    if [ -d "$BUNDLE/Extensions/$item" ]; then
        rm -rf "$SYS/System/Library/Extensions/$item"
        ditto "$BUNDLE/Extensions/$item" "$SYS/System/Library/Extensions/$item"
        chown -R 0:0 "$SYS/System/Library/Extensions/$item"
    fi
done
for item in AppleIntelTGLGraphicsGLDriver.bundle AppleIntelTGLGraphicsVADriver.bundle \
            AppleIntelTGLGraphicsVAME.bundle; do
    if [ -d "$BUNDLE/Extensions/$item" ]; then
        rm -rf "$SYS/Library/Extensions/$item"
        ditto "$BUNDLE/Extensions/$item" "$SYS/Library/Extensions/$item"
    fi
done
if [ -d "$BUNDLE/xe.bundle" ]; then
    mkdir -p "$SYS/System/Library/Caches"
    rm -rf "$SYS/System/Library/Caches/xe.bundle"
    ditto "$BUNDLE/xe.bundle" "$SYS/System/Library/Caches/xe.bundle"
fi
echo "golden-gate-intel-xe: installed Intel Iris Xe (TGL 16.0.32 + HookCase into S/L/E + xe.bundle) into $SYS"
