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

# When Tahoe's kmutil is provided and BootKernelExtensions.kc is already present (from darwin27-kernel),
# re-link ONLY SystemKernelExtensions.kc so AppleIntelTGLGraphics*, HookCase.kext are actually linked into
# the Darwin 27 System KC while keeping BootKernelExtensions.kc byte-identical for kernel-fixes/kc-binder.
KC=System/Library/KernelCollections
if [ -n "${TAHOE_KMUTIL:-}" ] && [ -f "$TAHOE_KMUTIL" ] \
    && [ -f "$SYS/$KC/BootKernelExtensions.kc" ] \
    && [ -f "$SYS/$KC/BootKernelExtensions.kc.elides" ]; then
    W=$(mktemp -d)
    B=/.darwin27-kc-build
    trap 'rm -rf "$SYS$B" "$W"' EXIT
    cp "$TAHOE_KMUTIL" "$W/kmutil"
    chmod 755 "$W/kmutil"
    if [ "$(uname -m)" = x86_64 ] && [ -n "${TAHOE_KC_BUILDER:-}" ] && [ -f "$TAHOE_KC_BUILDER" ]; then
        install -m 644 "$TAHOE_KC_BUILDER" "$W/kcbuilder.dylib"
        codesign -s - -f "$W/kcbuilder.dylib"
        "${OCLP_PYTHON:-python3}" -I "${KMUTIL_BUILDER_PY:?set KMUTIL_BUILDER_PY with TAHOE_KC_BUILDER}" \
            "$W/kmutil" @executable_path/kcbuilder.dylib
    fi
    codesign -s - -f "$W/kmutil"
    rm -rf "$SYS$B"
    mkdir -p "$SYS$B"
    cp "$SYS/$KC/BootKernelExtensions.kc" "$SYS$B/BootKernelExtensions.kc"
    cp "$SYS/$KC/BootKernelExtensions.kc.elides" "$SYS$B/BootKernelExtensions.kc.elides"
    # shellcheck disable=SC2046
    "$W/kmutil" create -n sys -a x86_64 --allow-missing-kdk -R "$SYS" \
        -k "$SYS/System/Library/Kernels/kernel" -V release \
        -B "$B/BootKernelExtensions.kc" -S "$B/SystemKernelExtensions.kc" \
        $(sed 's/^/--elide-identifier /' "$SYS$B/BootKernelExtensions.kc.elides")
    install -o root -g wheel -m 644 "$SYS$B/SystemKernelExtensions.kc" "$SYS/$KC/SystemKernelExtensions.kc"
    rm -rf "$SYS$B" "$W"
    trap - EXIT
    echo "golden-gate-intel-xe: re-linked SystemKernelExtensions.kc with TGL + HookCase (BootKC unchanged)"
fi

echo "golden-gate-intel-xe: installed Intel Iris Xe (TGL 16.0.32 + HookCase into S/L/E + xe.bundle) into $SYS"
