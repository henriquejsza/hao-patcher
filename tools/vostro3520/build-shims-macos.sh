#!/usr/bin/env bash
# Compile all open-source hao-patcher tools and x86_64 userspace shims on an x86_64 macOS builder
# (macOS 15+ with Xcode Command Line Tools; no Apple Silicon or Xcode 27 required).
set -euo pipefail

REPO=${1:-/Volumes/HAO_WORK/hao-patcher}
OUT=${2:-/Volumes/HAO_WORK/built-shims}
HAO_RT=${3:-$REPO/store/src/hao-runtime}
MIN_OS=${MIN_OS:-15.0}

mkdir -p "$OUT"/{tools,codeid_carrier,display_state_shim,corewifi_compat,corespotlight_compat,windowserver_filter}

echo "== [1/9] fl (firmlink helper with com.apple.private.apfs.set-firmlink)"
cc -O2 -Wall -arch x86_64 -mmacosx-version-min="$MIN_OS" \
   -o "$OUT/tools/fl" "$REPO/pipeline/unpack/pristine-tools/fl.c"
codesign -f -s - --entitlements "$REPO/pipeline/unpack/pristine-tools/ent.plist" "$OUT/tools/fl"

echo "== [2/9] hmeta & autool"
cc -O2 -Wall -arch x86_64 -mmacosx-version-min="$MIN_OS" \
   -o "$OUT/tools/hmeta" "$REPO/pipeline/unpack/pristine-tools/hmeta.c"
codesign -f -s - "$OUT/tools/hmeta"
cc -O2 -Wall -arch x86_64 -mmacosx-version-min="$MIN_OS" \
   -o "$OUT/tools/autool" "$REPO/pipeline/unpack/pristine-tools/autool.c"
codesign -f -s - "$OUT/tools/autool"

echo "== [3/9] ripatch"
cc -O2 -Wall -arch x86_64 -mmacosx-version-min=12.0 \
   -o "$OUT/tools/ripatch" "$REPO/pipeline/unpack/ripatch.c"
codesign -f -s - "$OUT/tools/ripatch"

echo "== [4/9] codeid_carrier (carrier.o + libhao_codeid.a + build.json)"
make -C "$HAO_RT" build/libhao_codeid.a
clang -arch x86_64 -O2 -Wall -Wextra -Werror -fno-common \
   -I "$HAO_RT/include" \
   -c "$REPO/patches/golden-gate-userspace/src/codeid/carrier.c" \
   -o "$OUT/codeid_carrier/carrier.o"
cp "$HAO_RT/build/libhao_codeid.a" "$OUT/codeid_carrier/libhao_codeid.a"
python3 - "$OUT/codeid_carrier" <<'PYCID'
import hashlib, json, pathlib, sys
d = pathlib.Path(sys.argv[1])
(d / 'build.json').write_text(json.dumps({
    'carrier_o': hashlib.sha256((d / 'carrier.o').read_bytes()).hexdigest(),
    'hao_runtime': {'libhao_codeid_a': hashlib.sha256((d / 'libhao_codeid.a').read_bytes()).hexdigest()},
}, indent=2) + '\n')
PYCID

echo "== [5/9] display_state_shim (dss_shim.dylib)"
xcrun clang -arch x86_64 -mmacosx-version-min="$MIN_OS" \
   -O2 -Wall -Wextra -dynamiclib \
   -install_name /usr/local/lib/dss_shim.dylib \
   -o "$OUT/display_state_shim/dss_shim.dylib" \
   "$REPO/tools/display-state-shim/src/dss_shim.c" \
   "$REPO/tools/display-state-shim/src/dss_convert.c" \
   "$REPO/tools/display-state-shim/stubs/CoreDisplay.tbd"
codesign -f -s - "$OUT/display_state_shim/dss_shim.dylib"

echo "== [6/9] corewifi_compat (corewifi_compat.dylib)"
xcrun clang -arch x86_64 -mmacosx-version-min="$MIN_OS" \
   -O2 -Wall -Wextra -Werror -fobjc-arc -dynamiclib -fvisibility=hidden \
   -Wl,-not_for_dyld_shared_cache \
   -install_name /System/Library/PrivateFrameworks/CoreWiFi.framework/Versions/A/CoreWiFi \
   -compatibility_version 1.0.0 -current_version 1006.2.0 \
   -Wl,-reexport_library,"$REPO/patches/golden-gate-userspace/src/corewifi/CoreWiFiTahoe.tbd" \
   -framework Foundation \
   -o "$OUT/corewifi_compat/corewifi_compat.dylib" \
   "$REPO/patches/golden-gate-userspace/src/corewifi/corewifi_compat.m"
codesign -f -s - "$OUT/corewifi_compat/corewifi_compat.dylib"

echo "== [7/9] corespotlight_compat (corespotlight_compat.dylib)"
xcrun clang -arch x86_64 -mmacosx-version-min="$MIN_OS" \
   -O2 -Wall -Wextra -Werror -dynamiclib -fobjc-arc \
   -framework Foundation -framework CoreSpotlight \
   -Wl,-not_for_dyld_shared_cache \
   -install_name /usr/lib/corespotlight_compat.dylib \
   -o "$OUT/corespotlight_compat/corespotlight_compat.dylib" \
   "$REPO/patches/golden-gate-corespotlight-compat/src/corespotlight_compat.m"
codesign -f -s - "$OUT/corespotlight_compat/corespotlight_compat.dylib"

echo "== [8/9] windowserver_filter (windowserver_filter.dylib)"
xcrun clang -arch x86_64 -mmacosx-version-min="$MIN_OS" \
   -O2 -Wall -Wextra -Werror -dynamiclib -framework QuartzCore \
   -Wl,-not_for_dyld_shared_cache \
   -install_name /usr/lib/windowserver_filter.dylib \
   -o "$OUT/windowserver_filter/windowserver_filter.dylib" \
   "$REPO/patches/golden-gate-windowserver-filter/src/filter_shim.c"
codesign -f -s - "$OUT/windowserver_filter/windowserver_filter.dylib"

echo "== [9/9] Done! Built artifacts:"
find "$OUT" -maxdepth 2 -type f -ls
