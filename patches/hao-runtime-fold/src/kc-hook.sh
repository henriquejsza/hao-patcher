#!/bin/sh
# hao-runtime-fold (fold-in sets only, in hao-runtime's place): hao-runtime's installation with the payload built for
# the rebuilt cache family (row hao_runtime_fold), whose generated data names that family's cache UUID.
set -eu
H=$(cd "$(dirname "$0")" && pwd)
"$OCLP_PYTHON" -I "$H/inputs/hao_runtime_fold/hao-install.py" "$1" "$H/inputs/hao_runtime_fold"
