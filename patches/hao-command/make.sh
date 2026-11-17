#!/bin/sh
# Stage the hao command for the post: tools/hao (not its tests) and NOTICE.md under OUT/hao, and release.json when the
# release has one, so the installed Mac runs the same hao as the USB installer. Repository source. In a checkout the
# tracked files; in a release archive (no .git) the files on disk, without tests and __pycache__.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
OUT=${1:?output}
rm -rf "$OUT/hao"
mkdir -p "$OUT/hao"
if [ -e "$TOP/.git" ]; then
    # the committed bytes, not the working tree (an uncommitted change is never staged into an image)
    git -C "$TOP" archive HEAD tools/hao NOTICE.md | (cd "$OUT/hao" && tar -xf -)
    rm -rf "$OUT/hao/tools/hao/tests"
    VERSION=$(git -C "$TOP" describe --always --abbrev=12)
else
    (cd "$TOP" && find tools/hao NOTICE.md -type f ! -path 'tools/hao/tests/*' ! -path '*/__pycache__/*' ! -name '*.pyc' \
        ! -name '.DS_Store' | tar -cf - -T -) | (cd "$OUT/hao" && tar -xf -)
    VERSION=$(cat "$TOP/pipeline/SOURCE_COMMIT" 2>/dev/null || true)
    case $VERSION in ''|*Format*) VERSION=unknown ;; esac
fi
[ ! -f "$TOP/tools/hao/release.json" ] || cp "$TOP/tools/hao/release.json" "$OUT/hao/tools/hao/release.json"
# the commit staged, for hao's version where there is no checkout and no release.json (a dev image)
printf '%s\n' "$VERSION" > "$OUT/hao/tools/hao/VERSION"
