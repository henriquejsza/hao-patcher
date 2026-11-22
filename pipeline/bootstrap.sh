#!/bin/sh
# Generated for one immutable release. No branch or latest lookup is performed.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
umask 077
fail() { echo "hao: $*" >&2; exit 4; }
release='@RELEASE@'
candidate='@CANDIDATE@'
# true only for a release cut while tools/hao/data/unsigned-releases.json names its version
unsigned='@UNSIGNED@'
base='https://github.com/lythka/hao-assets/releases/download/@RELEASE@'
[ "$(id -u)" != 0 ] || fail 'run hao as your normal account; it asks for a password when needed'
case "$(uname -m)" in arm64) arch=arm64;; x86_64) arch=x86_64;; *) fail 'unsupported host architecture';; esac
work="$PWD/hao-$release"
[ ! -L "$work" ] || fail 'work folder is a symbolic link'
mkdir -p "$work"
[ "$(stat -f %u "$work")" = "$(id -u)" ] || fail 'work folder belongs to another account'
chmod 700 "$work"
cd "$work"
for managed in kit runtime metal downloads store; do
    [ ! -L "$managed" ] || fail "managed folder is a symbolic link: $managed"
done
lock="$work/.lock"
mkdir "$lock" 2>/dev/null || fail "another hao run owns $lock; after an interrupted run remove that empty folder"
mkdir -p downloads
scratch=$(mktemp -d "$work/.verify.XXXXXXXX") || fail 'cannot create verification folder'
trap 'rm -rf "$scratch"; rmdir "$lock"' EXIT
trap 'exit 4' HUP INT TERM
cat > "$scratch/allowed" <<'KEY'
hao-release @KEY@
KEY
# fetch URL DESTINATION [FILE]: FILE is the name in a candidate's staged release (default: the URL's last part).
fetch() {
    if [ "$candidate" = true ]; then
        [ -n "${HAO_BOOTSTRAP_FILES:-}" ] || fail 'candidate requires HAO_BOOTSTRAP_FILES pointing to the staged release'
        staged=${3:-${1##*/}}
        [ -f "$HAO_BOOTSTRAP_FILES/$staged" ] || staged="external/$staged"
        cp "$HAO_BOOTSTRAP_FILES/$staged" "$2" || fail "local mirror miss: $1"
        return
    fi
    curl --fail --location --proto '=https' --tlsv1.2 --retry 3 "$1" -o "$2" || fail "download interrupted: $1; run the same command again"
}
[ "$unsigned" != true ] || echo 'hao: this release is not signed; its files are checked against SHA256SUMS and release.json only' >&2
for name in release.json SHA256SUMS; do
    fetch "$base/$name" "$scratch/$name"
    [ "$unsigned" != true ] || continue
    fetch "$base/$name.sig" "$scratch/$name.sig"
    ssh-keygen -Y verify -f "$scratch/allowed" -I hao-release -n hao-release -s "$scratch/$name.sig" < "$scratch/$name" >/dev/null 2>&1 || fail "bad signature: $name"
done
hash() { shasum -a 256 "$1" | cut -d ' ' -f 1; }
# Read only authenticated JSON, with macOS's JSON parser (no Python needed yet).
field() { plutil -extract "$1" raw -o - "$scratch/release.json" 2>/dev/null || fail "missing release field: $1"; }
[ "$(field release)" = "$release" ] || fail 'wrong release'
expected=$(awk '$2 == "release.json" {print $1}' "$scratch/SHA256SUMS")
[ "$(hash "$scratch/release.json")" = "$expected" ] || fail 'release.json checksum mismatch'
plain_name() {
    case "$1" in ''|.*|-*|*/*|*[!A-Za-z0-9._+-]*) fail "invalid file name in release.json: $1";; esac
}
# pinned LABEL URL SIZE SHA256 [FILE]: the file in downloads/SHA256, fetched unless already there and intact.
pinned() {
    case "$3" in *[!0-9]*|'') fail 'invalid asset size';; esac
    case "$4" in *[!0-9a-f]*|'') fail 'invalid SHA256';; esac
    [ "${#4}" = 64 ] || fail 'invalid SHA256 length'
    case "$2" in https://*) ;; *) fail 'asset URL must be HTTPS';; esac
    asset="$work/downloads/$4"
    [ ! -L "$asset" ] || fail 'download is a symbolic link'
    if [ ! -f "$asset" ] || [ "$(hash "$asset")" != "$4" ]; then
        fetch "$2" "$scratch/download" "${5:-}"
        [ "$(hash "$scratch/download")" = "$4" ] || fail "SHA256 mismatch: $1"
        [ "$(stat -f %z "$scratch/download")" = "$3" ] || fail "size mismatch: $1"
        mv "$scratch/download" "$asset"
    fi
}
optional() { plutil -extract "$1" raw -o - "$scratch/release.json" 2>/dev/null || true; }
get_asset() {
    file=$(optional "bootstrap.$1.file")
    [ -z "$file" ] || plain_name "$file"
    pinned "$1" "$(field "bootstrap.$1.url")" "$(field "bootstrap.$1.size")" "$(field "bootstrap.$1.sha256")" "$file"
}
# One archive holds every file of ours. It is checked whole, then each member taken from it is checked again
# against its own SHA256 in the signed release.json.
bundle=
if plutil -extract bundle json -o /dev/null "$scratch/release.json" 2>/dev/null; then
    file=$(field bundle.file)
    plain_name "$file"
    pinned bundle "$(field bundle.url)" "$(field bundle.size)" "$(field bundle.sha256)" "$file"
    bundle=$asset
    mkdir "$scratch/members"
fi
member() {
    file=$(field "bootstrap.$1.file")
    plain_name "$file"
    digest=$(field "bootstrap.$1.sha256")
    tar -xf "$bundle" -C "$scratch/members" "$file" || fail "the release archive lacks $file"
    asset="$scratch/members/$file"
    [ -f "$asset" ] && [ ! -L "$asset" ] || fail "not a file in the release archive: $file"
    [ "$(hash "$asset")" = "$digest" ] || fail "SHA256 mismatch: $1"
}
if [ -n "$bundle" ]; then member kit; else get_asset kit; fi
kit_asset=$asset
metal_asset=
if plutil -extract bootstrap.metal json -o /dev/null "$scratch/release.json" 2>/dev/null; then
    if [ -n "$bundle" ]; then member metal; else get_asset metal; fi
    metal_asset=$asset
fi
get_asset "python_$arch"
python_asset=$asset
# Re-extract verified archives; an interrupted or locally edited tree is never reused.
mkdir "$scratch/kit" "$scratch/runtime" "$scratch/metal"
tar -xzf "$kit_asset" -C "$scratch/kit" || fail 'cannot unpack builder kit'
tar -xzf "$python_asset" -C "$scratch/runtime" || fail 'cannot unpack pinned Python'
if [ -n "$metal_asset" ]; then
    tar -xf "$metal_asset" -C "$scratch/metal" || fail 'cannot unpack pinned LLVM'
fi
py="$scratch/runtime/python/bin/python3.12"
[ -x "$py" ] || fail 'pinned Python archive has no interpreter'
"$py" -I -S -c 'import platform,sys; sys.exit(platform.machine()!=sys.argv[1])' "$arch" || fail 'wrong Python architecture'
# The store lives outside both the replaceable kit and disposable scratch folder.
# Migrate an earlier kit only to this persistent location; never delete it on failure.
if [ -L kit/store ]; then
    [ "$(readlink kit/store)" = ../store ] || fail 'kit store has an unexpected symbolic link'
elif [ -e kit/store ]; then
    [ ! -e store ] || fail 'both old and new stores exist; preserve them before retrying'
    mv kit/store store || fail 'cannot preserve existing store'
fi
mkdir -p store
ln -s ../store "$scratch/kit/store"
rm -rf kit runtime metal
mv "$scratch/kit" kit
mv "$scratch/runtime" runtime
mv "$scratch/metal" metal
if [ -n "$metal_asset" ]; then
    HAO_METAL_LLVM="$work/metal"
    export HAO_METAL_LLVM
fi
if [ -n "$bundle" ]; then
    # hao takes the release's other files from the archive already checked here
    HAO_BUNDLE="$bundle"
    export HAO_BUNDLE
fi
cp "$scratch/release.json" "$scratch/SHA256SUMS" kit/tools/hao/
[ "$unsigned" = true ] || cp "$scratch/release.json.sig" "$scratch/SHA256SUMS.sig" kit/tools/hao/
PATH="$work/runtime/python/bin:$PATH"
export PATH
[ "$#" -gt 0 ] || set -- create-installer
"$work/runtime/python/bin/python3.12" -I -B "$work/kit/tools/hao/hao" "$@"
