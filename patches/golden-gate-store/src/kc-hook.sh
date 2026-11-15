#!/bin/sh
set -eu
S=$1; H=$(cd "$(dirname "$0")" && pwd); IN=$H/inputs/store_service
D=System/Library/PrivateFrameworks/AppStoreDaemon.framework/Support
U="System/Applications/App Store.app/Contents/MacOS/App Store"
M=$S/usr/lib/hao/stub-identities
chk() { [ "$(shasum -a 256 "$1" | cut -d' ' -f1)" = "$2" ] || { echo "$0: unexpected $1" >&2; exit 1; }; }
chk "$S/$D/appstoreagent" 99c826aab3b02b21fa9aa925d4e3303e86377376889f00cd79d5f7dcf3242cd8
chk "$S/$D/appstored" 3432336f72e8d0819498dc972435fc7bae50326b66f2609c0dbc0becb1a22c35
chk "$S/$U" 0d62bbd00661dd507263610861a266ab2794bd055442fb0ecba74ca87891f50e
[ -f "$M" ]
put() { rm -f "$3"; install -o root -g wheel -m "$1" "$2" "$3"; }
sys() { put 755 "$1" "$2"; chflags restricted "$2"; }
put 644 "$S/$D/appstoreagent" "$S/usr/lib/hao/store-policy-original-appstoreagent"
put 644 "$S/$D/appstored" "$S/usr/lib/hao/store-policy-original-appstored"
put 755 "$IN/libhao-appstore-policy.dylib" "$S/usr/lib/hao/libhao-appstore-policy.dylib"
sys "$IN/appstoreagent" "$S/$D/appstoreagent"
sys "$IN/appstored" "$S/$D/appstored"
sys "$IN/app-store-ui" "$S/$U"
"${OCLP_PYTHON:?}" -I - "$M" "$IN/stub-identities.ui" "$IN/stub-identities.add" <<'PY'
import sys
m, ui, add = sys.argv[1:]
lines = open(m).read().splitlines()
new = open(ui).read().strip('\n')
path = new.split(None, 3)[3]
hits = [i for i, l in enumerate(lines) if len(l.split(None, 3)) == 4 and l.split(None, 3)[3] == path]
if len(hits) != 1:
    sys.exit('stub-identities: %d lines for %s' % (len(hits), path))
lines[hits[0]] = new
for l in open(add).read().splitlines():
    if l and l not in lines:
        lines.append(l)
open(m, 'w').write('\n'.join(lines) + '\n')
PY
