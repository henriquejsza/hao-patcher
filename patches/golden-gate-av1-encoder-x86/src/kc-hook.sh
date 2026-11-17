#!/bin/sh
# golden-gate-av1-encoder-x86 (kc-hook): VideoToolbox does not offer the AV1 software encoder to x86_64 programs.
# Its once-only table setup is AVX2 code without a CPU check, so the first AV1 encode on a CPU without AVX2 dies with
# SIGILL (diag#0053: osascript "clipboard info" with an image). The plist is put back root:wheel 0644 restricted.
set -eu
S=${1:?System mount}; H=$(cd "$(dirname "$0")" && pwd)
F=$S/System/Library/Video/Plug-Ins/AV1EncoderSW.bundle/Contents/Info.plist
W=$(mktemp /private/var/tmp/av1-encoder-x86.XXXXXX)
"${OCLP_PYTHON:?}" -I "$H/arm64_only.py" "$S" "$W"
chflags noschg,nouchg,norestricted "$F"
rm -f "$F"
install -o root -g wheel -m 644 "$W" "$F"
chflags restricted "$F"
rm -f "$W"
echo "golden-gate-av1-encoder-x86: $(shasum -a 256 "$F" | cut -c1-16) $F"
