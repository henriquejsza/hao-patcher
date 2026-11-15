#!/bin/sh
# Stage golden-gate-shared-cache's code (fold.py and its reviewed providers.txt) as build/fold, with that recipe's own
# staging of golden-gate-userspace under it, so this recipe runs the B recipe unchanged on its own row.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:?output}
BASE="$HERE/../golden-gate-shared-cache"
mkdir -p "$OUT"
ditto "$BASE/src" "$OUT/fold"
rm -rf "$OUT/fold/__pycache__" "$OUT/fold/kc-hook.sh"
sh "$BASE/make.sh" "$OUT/fold/build"
