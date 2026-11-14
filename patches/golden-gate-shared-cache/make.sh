#!/bin/sh
# Stage golden-gate-userspace's cryptex code (image build, seal, 4 KiB re-sign, Swift reference check) as build/userspace,
# so this recipe rebuilds the OS cryptex the same way that recipe built it.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
OUT=${1:?output}
mkdir -p "$OUT"
ditto "$HERE/../golden-gate-userspace/src" "$OUT/userspace"
rm -rf "$OUT/userspace/__pycache__" "$OUT/userspace/inputs"
