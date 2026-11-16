#!/bin/sh
set -eu
S=$1; H=$(cd "$(dirname "$0")" && pwd)
E=$H/inputs/edit_engine/stub-edit
[ -f "$S/usr/lib/hao/stub-identities" ]
rm -f "$S/usr/lib/hao/libhao-appstore-policy.dylib"
install -o root -g wheel -m 755 "$H/inputs/store_service/libhao-appstore-policy.dylib" "$S/usr/lib/hao/libhao-appstore-policy.dylib"
for f in appstored appstoreagent app-store-ui; do
    "${OCLP_PYTHON:?}" -I "$E" "$S" "$H/build/$f.json"
done
