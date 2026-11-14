#!/bin/sh
# golden-gate-shared-cache (kc-hook, B images only, last before golden-gate-native-identities): the OS cryptex's x86_64
# cache becomes the rebuilt family in inputs/rebuilt_cache, which holds the on-disk providers, and those files leave
# System, so dyld loads nothing at a cache install path from disk.
#   kc-hook.sh SYSTEM_MOUNT     env OCLP_PYTHON GRP PBU
set -eu
S=${1:?System mount}; H=$(cd "$(dirname "$0")" && pwd)
"${OCLP_PYTHON:?}" -I "$H/fold.py" install "$S" "$H/inputs/rebuilt_cache"
