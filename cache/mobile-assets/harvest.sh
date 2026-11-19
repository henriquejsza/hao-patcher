#!/bin/sh
# harvest.sh SSH OUT: copy a booted test Mac's MobileAssets (System/Library/AssetsV2 on its Data volume) after an
# online first login, as the raw input of ./make. SSH is the command that runs a root shell on that Mac (for
# example "ssh root@HOST"); OUT is a new folder under store/artifacts/. mobileassetd is left running: run this once
# the login has settled and no download is in progress (`log stream --process mobileassetd` quiet).
set -eu
[ $# -eq 2 ] || { echo "usage: harvest.sh SSH OUT" >&2; exit 2; }
SSH=$1; OUT=$2
[ ! -e "$OUT" ] || { echo "harvest.sh: $OUT exists" >&2; exit 1; }
mkdir -p "$OUT"
build=$($SSH sw_vers -buildVersion)
$SSH "tar -c -f - --numeric-owner -C /System/Volumes/Data System/Library/AssetsV2" > "$OUT/mobile-assets.tar"
tar -tf "$OUT/mobile-assets.tar" > /dev/null
printf 'build %s\nharvested %s\n' "$build" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" > "$OUT/INFO"
echo "harvest.sh: $(tar -tf "$OUT/mobile-assets.tar" | wc -l | tr -d ' ') entries from $build -> $OUT"
