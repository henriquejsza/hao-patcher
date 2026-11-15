#!/bin/sh
# golden-gate-shared-cache-catalog (kc-hook, B+catalog images only, last before golden-gate-native-identities):
# golden-gate-shared-cache's fold (staged as build/fold by make.sh) with the B+catalog family in
# inputs/rebuilt_cache_catalog.
#   kc-hook.sh SYSTEM_MOUNT     env OCLP_PYTHON GRP PBU
set -eu
S=${1:?System mount}; H=$(cd "$(dirname "$0")" && pwd)
"${OCLP_PYTHON:?}" -I "$H/build/fold/fold.py" install "$S" "$H/inputs/rebuilt_cache_catalog"
