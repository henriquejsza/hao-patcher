#!/bin/sh
# Stage the hao command for the post: tools/hao's tracked files (not its tests) and release.json when the release has
# one, under OUT/hao/tools/hao, so the installed Mac runs the same hao as the USB installer. Repository source.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TOP=$(cd "$HERE/../.." && pwd)
OUT=${1:?output}
mkdir -p "$OUT/hao"
(cd "$TOP" && git ls-files tools/hao NOTICE.md | grep -v '^tools/hao/tests/' | tar -cf - -T -) | (cd "$OUT/hao" && tar -xf -)
[ ! -f "$TOP/tools/hao/release.json" ] || cp "$TOP/tools/hao/release.json" "$OUT/hao/tools/hao/release.json"
