#!/bin/sh
# Relink macOS 27 (Golden Gate, 26B131) SystemKernelExtensions.kc on a booted Vostro 3520
# to include HookCase.kext, AppleIntelTGLGraphicsFramebuffer.kext, and AppleIntelTGLGraphics.kext,
# seal a new APFS boot snapshot, and switch the USB ESP to config-accel.plist.
#
# Usage (from Terminal inside macOS 27):
#   sudo sh /Volumes/OPENCORE/xe-kit/enable-xe-macos27.sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "Run with sudo: sudo sh $0" >&2
    exit 1
fi

KIT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
USB_VOL=$(dirname "$KIT_DIR")

for f in "$KIT_DIR/kmutil" "$KIT_DIR/kcbuilder.dylib"; do
    if [ ! -f "$f" ]; then
        echo "Missing $f" >&2
        exit 1
    fi
done

# Detect live APFS root snapshot device (e.g. /dev/disk1s2s1 -> /dev/disk1s2)
ROOT_DEV=$(mount | awk '$3 == "/" {print $1; exit}')
SYS_DEV=$(echo "$ROOT_DEV" | sed -E 's/s[0-9]+$//')
if [ -z "$SYS_DEV" ] || [ ! -b "$SYS_DEV" ]; then
    echo "Could not resolve APFS System device from root '$ROOT_DEV'" >&2
    exit 1
fi
echo "Root snapshot: $ROOT_DEV -> System device: $SYS_DEV"

WORK=$(mktemp -d /private/tmp/xe-kc-work.XXXXXX)
# MUST be a canonical real path (NOT /tmp symlink -> /private/tmp), otherwise kmutil fails to strip
# the volume-root prefix and embeds /private/tmp/xe-sys-rw/System/Library/Extensions/... in SystemKC!
SYS=/private/tmp/xe-sys-rw
BUILD_REL=/.xe-kc-build
cleanup() {
    rm -rf "$SYS$BUILD_REL" "$WORK" 2>/dev/null || true
    if mount | grep -q " on $SYS "; then
        umount "$SYS" 2>/dev/null || diskutil unmount force "$SYS" 2>/dev/null || true
    fi
}
trap cleanup EXIT

# Copy Tahoe kmutil + kcbuilder.dylib without xattrs/resource forks (codesign rejects Finder detritus) and ad-hoc sign locally
cat "$KIT_DIR/kmutil" > "$WORK/kmutil"
cat "$KIT_DIR/kcbuilder.dylib" > "$WORK/kcbuilder.dylib"
xattr -c "$WORK/kmutil" "$WORK/kcbuilder.dylib" 2>/dev/null || true
chmod 755 "$WORK/kmutil"
chmod 644 "$WORK/kcbuilder.dylib"
codesign -s - -f "$WORK/kcbuilder.dylib"
codesign -s - -f "$WORK/kmutil"

# Mount APFS System volume writable
mkdir -p "$SYS"
if mount | grep -q " on $SYS "; then
    umount "$SYS" || diskutil unmount force "$SYS"
fi
mount -o nobrowse -t apfs "$SYS_DEV" "$SYS"

SLE="$SYS/System/Library/Extensions"
KC="$SYS/System/Library/KernelCollections"

for k in HookCase.kext AppleIntelTGLGraphicsFramebuffer.kext AppleIntelTGLGraphics.kext; do
    if [ ! -d "$SLE/$k" ]; then
        echo "ERROR: $SLE/$k is missing!" >&2
        exit 1
    fi
    chown -R root:wheel "$SLE/$k"
done

if [ ! -f "$KC/BootKernelExtensions.kc" ] || [ ! -f "$KC/BootKernelExtensions.kc.elides" ]; then
    echo "ERROR: BootKernelExtensions.kc or .elides missing in $KC" >&2
    exit 1
fi

rm -rf "$SYS$BUILD_REL"
mkdir -p "$SYS$BUILD_REL"
cp "$KC/BootKernelExtensions.kc" "$SYS$BUILD_REL/BootKernelExtensions.kc"
cp "$KC/BootKernelExtensions.kc.elides" "$SYS$BUILD_REL/BootKernelExtensions.kc.elides"

echo "Linking SystemKernelExtensions.kc with Tahoe kmutil + HookCase + AppleIntelTGLGraphics*..."
# shellcheck disable=SC2046
"$WORK/kmutil" create -n sys -a x86_64 --allow-missing-kdk -R "$SYS" \
    -k "$SYS/System/Library/Kernels/kernel" -V release \
    -B "$BUILD_REL/BootKernelExtensions.kc" \
    -S "$BUILD_REL/SystemKernelExtensions.kc" \
    --bundle-identifier org.smichaud.HookCase \
    --bundle-identifier com.xxxxx.driver.AppleIntelTGLGraphicsFramebuffer \
    --bundle-identifier com.xxxxx.driver.AppleIntelTGLGraphics \
    $(sed 's/^/--elide-identifier /' "$SYS$BUILD_REL/BootKernelExtensions.kc.elides")

NEW_KC="$SYS$BUILD_REL/SystemKernelExtensions.kc"
echo "Verifying TGL kexts inside new SystemKernelExtensions.kc..."
MISSING=0
for id in org.smichaud.HookCase com.xxxxx.driver.AppleIntelTGLGraphicsFramebuffer com.xxxxx.driver.AppleIntelTGLGraphics; do
    if LC_ALL=C grep -a -q "$id" "$NEW_KC"; then
        echo "  OK: $id"
    else
        echo "  MISSING: $id" >&2
        MISSING=1
    fi
done
if [ "$MISSING" -ne 0 ]; then
    echo "ERROR: One or more TGL kexts were not linked into SystemKernelExtensions.kc. Aborting without modifying snapshot." >&2
    exit 1
fi
if LC_ALL=C grep -a -q "xe-sys-rw" "$NEW_KC"; then
    echo "ERROR: Mount prefix 'xe-sys-rw' leaked into SystemKernelExtensions.kc! Aborting." >&2
    exit 1
fi
echo "  OK: Clean /System/Library/Extensions paths (no mount prefix leak)"

echo "Installing new SystemKernelExtensions.kc (BootKernelExtensions.kc untouched)..."
install -o root -g wheel -m 644 "$NEW_KC" "$KC/SystemKernelExtensions.kc"
rm -rf "$SYS$BUILD_REL"

echo "Creating new APFS boot snapshot..."
bless --mount "$SYS" --bootefi --create-snapshot

# Only swap config-accel.plist if OPENCORE is already mounted (avoid diskutil mount on FAT32 FSKit which hangs on macOS 27)
if [ -f "/Volumes/OPENCORE/EFI/OC/config-accel.plist" ]; then
    echo "Switching /Volumes/OPENCORE/EFI/OC/config.plist -> config-accel.plist..."
    cp "/Volumes/OPENCORE/EFI/OC/config-accel.plist" "/Volumes/OPENCORE/EFI/OC/config.plist"
    sync
else
    echo "INFO: SystemKernelExtensions.kc + snapshot prontos! Volte ao Linux para ativar config-accel.plist no pendrive."
fi

echo ""
echo "DONE! Reboot now (F12 -> OPENCORE -> macOS Golden Gate) to boot with Intel Iris Xe Metal 2!"
echo "If anything hangs, swap config-safe.plist -> config.plist from Linux."
